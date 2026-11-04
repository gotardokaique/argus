//! Upstreams DNS-over-HTTPS (RFC 8484) com fallback ordenado.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use argus_core::config::{DohServer, UpstreamConfig};
use hickory_proto::op::{Message, MessageType};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use tracing::{debug, warn};

const DNS_MESSAGE: &str = "application/dns-message";
const MAX_DNS_MESSAGE: usize = 65_535;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("{0}")]
    Transport(String),
    #[error("tempo esgotado")]
    Timeout,
    #[error("resposta inválida: {0}")]
    BadResponse(String),
    #[error("todos os upstreams falharam")]
    AllFailed,
}

/// Troca de uma mensagem DNS (formato wire) com um servidor.
pub trait Exchange: Send + Sync {
    fn exchange<'a>(&'a self, query: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, UpstreamError>>;
}

pub struct DohClient {
    url: reqwest::Url,
    http: reqwest::Client,
}

impl DohClient {
    pub fn new(server: &DohServer, timeout: Duration) -> Result<Self, String> {
        let url = reqwest::Url::parse(&server.url).map_err(|e| e.to_string())?;
        let port = url.port_or_known_default().unwrap_or(443);
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .connect_timeout(timeout)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(30))
            .user_agent(concat!("argus-dns/", env!("CARGO_PKG_VERSION")))
            // Qualquer nome fora do bootstrap falha: nunca recorre ao DNS do sistema.
            .dns_resolver(Arc::new(crate::http::NoResolve));
        if let Some(host) = url.host_str().filter(|_| !server.bootstrap.is_empty()) {
            let addrs: Vec<SocketAddr> = server
                .bootstrap
                .iter()
                .map(|ip| SocketAddr::new(*ip, port))
                .collect();
            builder = builder.resolve_to_addrs(host, &addrs);
        }
        let http = builder.build().map_err(|e| e.to_string())?;
        Ok(Self { url, http })
    }
}

impl Exchange for DohClient {
    fn exchange<'a>(&'a self, query: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, UpstreamError>> {
        Box::pin(async move {
            let resp = self
                .http
                .post(self.url.clone())
                .header(CONTENT_TYPE, DNS_MESSAGE)
                .header(ACCEPT, DNS_MESSAGE)
                .body(query.to_vec())
                .send()
                .await
                .map_err(|e| UpstreamError::Transport(error_chain(&e)))?;
            let status = resp.status();
            if !status.is_success() {
                return Err(UpstreamError::BadResponse(format!("HTTP {status}")));
            }
            let ctype = resp
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !ctype.starts_with(DNS_MESSAGE) {
                return Err(UpstreamError::BadResponse(format!(
                    "content-type {ctype:?}"
                )));
            }
            let body = resp
                .bytes()
                .await
                .map_err(|e| UpstreamError::Transport(error_chain(&e)))?;
            if body.len() > MAX_DNS_MESSAGE {
                return Err(UpstreamError::BadResponse("mensagem grande demais".into()));
            }
            Ok(body.to_vec())
        })
    }
}

/// Mensagem de erro com as causas (reqwest esconde a causa real em `source()`).
pub(crate) fn error_chain(e: &dyn std::error::Error) -> String {
    let mut msg = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        src = s.source();
    }
    msg
}

struct Member {
    name: String,
    client: Box<dyn Exchange>,
    /// Milissegundos (desde `UpstreamPool::epoch`) até quando o servidor fica no fim da fila.
    down_until: AtomicU64,
}

pub struct UpstreamPool {
    members: Vec<Member>,
    timeout: Duration,
    backoff: Duration,
    epoch: Instant,
}

impl UpstreamPool {
    pub fn from_config(cfg: &UpstreamConfig) -> Result<Self, String> {
        let mut members = Vec::new();
        for s in &cfg.servers {
            let client =
                DohClient::new(s, cfg.timeout).map_err(|e| format!("upstream {}: {e}", s.name))?;
            members.push((s.name.clone(), Box::new(client) as Box<dyn Exchange>));
        }
        Ok(Self::new(members, cfg.timeout, cfg.failure_backoff))
    }

    pub fn new(
        members: Vec<(String, Box<dyn Exchange>)>,
        timeout: Duration,
        backoff: Duration,
    ) -> Self {
        Self {
            members: members
                .into_iter()
                .map(|(name, client)| Member {
                    name,
                    client,
                    down_until: AtomicU64::new(0),
                })
                .collect(),
            timeout,
            backoff,
            epoch: Instant::now(),
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Envia a consulta ao primeiro upstream saudável; em falha, tenta os demais.
    /// Servidores em backoff só são usados quando nenhum saudável responde.
    /// Retorna a resposta e o nome do upstream que respondeu.
    pub async fn resolve(&self, query: &Message) -> Result<(Message, &str), UpstreamError> {
        // RFC 8484 §4.1: ID 0 melhora o cache HTTP; o ID real é restaurado pelo chamador.
        let mut q = query.clone();
        q.metadata.id = 0;
        let wire = q
            .to_vec()
            .map_err(|e| UpstreamError::BadResponse(e.to_string()))?;

        let now = self.now_ms();
        let (healthy, down): (Vec<&Member>, Vec<&Member>) = self
            .members
            .iter()
            .partition(|m| m.down_until.load(Ordering::Relaxed) <= now);

        for m in healthy.into_iter().chain(down) {
            let result = match tokio::time::timeout(self.timeout, m.client.exchange(&wire)).await {
                Ok(r) => r.and_then(|bytes| validate(&bytes, query)),
                Err(_) => Err(UpstreamError::Timeout),
            };
            match result {
                Ok(msg) => {
                    m.down_until.store(0, Ordering::Relaxed);
                    return Ok((msg, &m.name));
                }
                Err(e) => {
                    let backoff = u64::try_from(self.backoff.as_millis()).unwrap_or(u64::MAX);
                    m.down_until
                        .store(self.now_ms().saturating_add(backoff), Ordering::Relaxed);
                    warn!(upstream = %m.name, error = %e, "falha no upstream, tentando o próximo");
                }
            }
        }
        debug!("nenhum upstream respondeu");
        Err(UpstreamError::AllFailed)
    }
}

/// Confere que a resposta corresponde à pergunta feita.
fn validate(bytes: &[u8], query: &Message) -> Result<Message, UpstreamError> {
    let msg = Message::from_vec(bytes).map_err(|e| UpstreamError::BadResponse(e.to_string()))?;
    if msg.message_type != MessageType::Response {
        return Err(UpstreamError::BadResponse("não é uma resposta".into()));
    }
    let same_question = match (msg.queries.first(), query.queries.first()) {
        (Some(a), Some(b)) => {
            a.query_type == b.query_type
                && a.query_class == b.query_class
                && a.name.to_lowercase() == b.name.to_lowercase()
        }
        _ => false,
    };
    if !same_question {
        return Err(UpstreamError::BadResponse(
            "pergunta da resposta não confere".into(),
        ));
    }
    Ok(msg)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use hickory_proto::op::{OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::sync::atomic::AtomicUsize;

    /// Upstream falso para testes: responde, falha ou demora.
    pub struct Fake {
        pub behavior: Behavior,
        pub calls: Arc<AtomicUsize>,
    }

    #[derive(Clone, Copy)]
    pub enum Behavior {
        Answer,
        Fail,
        Hang,
    }

    impl Exchange for Fake {
        fn exchange<'a>(
            &'a self,
            query: &'a [u8],
        ) -> BoxFuture<'a, Result<Vec<u8>, UpstreamError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                match self.behavior {
                    Behavior::Fail => Err(UpstreamError::Transport("falso".into())),
                    Behavior::Hang => {
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        unreachable!()
                    }
                    Behavior::Answer => {
                        let q = Message::from_vec(query).unwrap();
                        let mut r = Message::response(q.id, OpCode::Query);
                        r.add_queries(q.queries.clone());
                        Ok(r.to_vec().unwrap())
                    }
                }
            })
        }
    }

    fn fake(b: Behavior) -> (Box<dyn Exchange>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Box::new(Fake {
                behavior: b,
                calls: calls.clone(),
            }),
            calls,
        )
    }

    fn query() -> Message {
        let mut m = Message::query();
        m.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        m
    }

    #[tokio::test]
    async fn falls_back_and_backs_off() {
        let (a, a_calls) = fake(Behavior::Fail);
        let (b, b_calls) = fake(Behavior::Answer);
        let pool = UpstreamPool::new(
            vec![("a".into(), a), ("b".into(), b)],
            Duration::from_millis(200),
            Duration::from_secs(60),
        );
        let (_, used) = pool.resolve(&query()).await.unwrap();
        assert_eq!(used, "b");
        // "a" está em backoff: a próxima consulta vai direto para "b".
        let (_, used) = pool.resolve(&query()).await.unwrap();
        assert_eq!(used, "b");
        assert_eq!(a_calls.load(Ordering::SeqCst), 1);
        assert_eq!(b_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn timeout_moves_to_next() {
        let (a, _) = fake(Behavior::Hang);
        let (b, _) = fake(Behavior::Answer);
        let pool = UpstreamPool::new(
            vec![("a".into(), a), ("b".into(), b)],
            Duration::from_millis(50),
            Duration::from_secs(1),
        );
        assert_eq!(pool.resolve(&query()).await.unwrap().1, "b");
    }

    #[tokio::test]
    async fn all_failed() {
        let (a, _) = fake(Behavior::Fail);
        let pool = UpstreamPool::new(
            vec![("a".into(), a)],
            Duration::from_millis(50),
            Duration::from_secs(1),
        );
        assert!(matches!(
            pool.resolve(&query()).await,
            Err(UpstreamError::AllFailed)
        ));
    }
}
