//! Decisão por consulta: nomes especiais → política → cache → upstream.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use argus_core::config::{BlockedResponse, DnsConfig};
use argus_core::event::{DnsQueryEvent, Event, Transport};
use argus_core::verdict::Verdict;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::RData;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::blocklist::{Decision, Policy};
use crate::cache::{Cache, CacheKey};
use crate::domain::query_name;
use crate::forward::Forwarders;
use crate::message::{self, adapt, encode, reply_to};
use crate::upstream::UpstreamPool;

/// Canário do Firefox: NXDOMAIN aqui desliga o DoH automático do navegador,
/// que contornaria o filtro.
const FIREFOX_CANARY: &str = "use-application-dns.net";

#[derive(Debug, Default)]
pub struct Stats {
    pub queries: AtomicU64,
    pub blocked: AtomicU64,
    pub cache_hits: AtomicU64,
    pub failures: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    Blocked,
    Cache,
    Upstream(String),
    Forward,
    Local,
    Failed,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::Blocked => f.write_str("blocked"),
            Source::Cache => f.write_str("cache"),
            Source::Upstream(name) => write!(f, "upstream:{name}"),
            Source::Forward => f.write_str("forward"),
            Source::Local => f.write_str("local"),
            Source::Failed => f.write_str("failed"),
        }
    }
}

struct Outcome {
    message: Message,
    verdict: Verdict,
    source: Source,
}

pub struct Resolver {
    policy: Arc<Policy>,
    cache: Cache,
    upstreams: Arc<UpstreamPool>,
    forwarders: Forwarders,
    blocked_response: BlockedResponse,
    blocked_ttl: u32,
    query_timeout: Duration,
    forward_timeout: Duration,
    forward_single_label: bool,
    events: broadcast::Sender<Event>,
    pub stats: Stats,
}

impl Resolver {
    pub fn new(cfg: &DnsConfig, policy: Arc<Policy>, upstreams: Arc<UpstreamPool>) -> Self {
        Self {
            policy,
            cache: Cache::new(cfg.cache.clone()),
            upstreams,
            forwarders: Forwarders::new(&cfg.forward_zones),
            blocked_response: cfg.blocked_response,
            blocked_ttl: cfg.blocked_ttl,
            query_timeout: cfg.query_timeout,
            forward_timeout: cfg.upstream.timeout,
            forward_single_label: cfg.forward_single_label,
            events: broadcast::channel(1024).0,
            stats: Stats::default(),
        }
    }

    /// Eventos de cada consulta respondida (para o serviço/UI).
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub fn policy(&self) -> &Arc<Policy> {
        &self.policy
    }

    /// Processa um pacote DNS e devolve a resposta serializada (`None` = descartar).
    pub async fn handle(
        &self,
        packet: &[u8],
        client: SocketAddr,
        transport: Transport,
    ) -> Option<Vec<u8>> {
        let start = Instant::now();
        let Ok(query) = Message::from_vec(packet) else {
            debug!(%client, len = packet.len(), "pacote DNS malformado");
            return message::formerr_raw(packet);
        };
        if query.message_type != MessageType::Query {
            return None;
        }
        if query.op_code != OpCode::Query {
            return encode(reply_to(&query, ResponseCode::NotImp), &query, transport);
        }
        if query.queries.len() != 1 {
            return encode(reply_to(&query, ResponseCode::FormErr), &query, transport);
        }
        self.stats.queries.fetch_add(1, Ordering::Relaxed);
        let name = query_name(&query.queries[0].name);

        let outcome =
            match tokio::time::timeout(self.query_timeout, self.answer(&query, &name)).await {
                Ok(outcome) => outcome,
                Err(_) => {
                    warn!(%client, name, "tempo esgotado ao resolver");
                    self.failed(&query, Verdict::Clean)
                }
            };
        self.record(&query, &name, client, transport, &outcome, start.elapsed());
        encode(outcome.message, &query, transport)
    }

    async fn answer(&self, query: &Message, name: &str) -> Outcome {
        let q = &query.queries[0];

        if name == "localhost" || name.ends_with(".localhost") {
            return self.local(message::localhost(query));
        }
        if name == FIREFOX_CANARY {
            return self.local(reply_to(query, ResponseCode::NXDomain));
        }

        let verdict = match self.policy.check(name) {
            Decision::Blocked { matched, list } => return self.block(query, list, matched),
            Decision::Allowed { rule, overridden } => Verdict::Allowed { rule, overridden },
            Decision::Pass => Verdict::Clean,
        };

        let zone_servers = self.forwarders.find(name);
        if zone_servers.is_none()
            && !name.is_empty()
            && !name.contains('.')
            && !self.forward_single_label
        {
            return Outcome {
                message: reply_to(query, ResponseCode::NXDomain),
                verdict,
                source: Source::Local,
            };
        }

        let key = CacheKey {
            name: name.to_owned(),
            qtype: q.query_type,
            qclass: q.query_class,
            dnssec_ok: query.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok),
            checking_disabled: query.checking_disabled,
        };
        if let Some(cached) = self.cache.get(&key, Instant::now()) {
            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            return self.finish(query, cached, verdict, Source::Cache);
        }

        let (resp, source) = match zone_servers {
            Some(servers) => match self
                .forwarders
                .exchange(servers, query, self.forward_timeout)
                .await
            {
                Some(resp) => (resp, Source::Forward),
                None => return self.failed(query, verdict),
            },
            None => match self.upstreams.resolve(query).await {
                Ok((resp, upstream)) => (resp, Source::Upstream(upstream.to_owned())),
                Err(_) => return self.failed(query, verdict),
            },
        };
        self.cache.insert(key, &resp, Instant::now());
        self.finish(query, resp, verdict, source)
    }

    /// Antes de entregar uma resposta, confere os alvos de CNAME: um domínio
    /// liberado pode apontar para um domínio bloqueado (CNAME cloaking).
    fn finish(&self, query: &Message, resp: Message, verdict: Verdict, source: Source) -> Outcome {
        if !matches!(verdict, Verdict::Allowed { .. }) {
            for record in &resp.answers {
                let RData::CNAME(cname) = &record.data else {
                    continue;
                };
                let target = query_name(&cname.0);
                if let Decision::Blocked { matched, list } = self.policy.check(&target) {
                    return self.block(query, list, format!("{matched} (via CNAME {target})"));
                }
            }
        }
        Outcome {
            message: adapt(resp, query),
            verdict,
            source,
        }
    }

    fn block(&self, query: &Message, list: String, detail: String) -> Outcome {
        self.stats.blocked.fetch_add(1, Ordering::Relaxed);
        Outcome {
            message: message::blocked(query, self.blocked_response, self.blocked_ttl),
            verdict: Verdict::Malicious {
                source: list,
                detail,
            },
            source: Source::Blocked,
        }
    }

    fn local(&self, message: Message) -> Outcome {
        Outcome {
            message,
            verdict: Verdict::Clean,
            source: Source::Local,
        }
    }

    fn failed(&self, query: &Message, verdict: Verdict) -> Outcome {
        self.stats.failures.fetch_add(1, Ordering::Relaxed);
        Outcome {
            message: reply_to(query, ResponseCode::ServFail),
            verdict,
            source: Source::Failed,
        }
    }

    fn record(
        &self,
        query: &Message,
        name: &str,
        client: SocketAddr,
        transport: Transport,
        o: &Outcome,
        took: Duration,
    ) {
        let qtype = query.queries[0].query_type;
        let rcode = format!("{:?}", o.message.response_code);
        let duration_us = u64::try_from(took.as_micros()).unwrap_or(u64::MAX);
        match &o.verdict {
            Verdict::Malicious { source, detail } => warn!(
                target: "argus_dns::blocked",
                %client, %transport, name, %qtype, list = %source, matched = %detail,
                "consulta bloqueada"
            ),
            Verdict::Allowed {
                rule,
                overridden: Some(overridden),
            } => info!(
                target: "argus_dns::allowed",
                %client, name, %qtype, rule = %rule, overridden = %overridden,
                "bloqueio ignorado pela allowlist"
            ),
            _ => debug!(
                target: "argus_dns::query",
                %client, %transport, name, %qtype, rcode = %rcode, source = %o.source, duration_us,
                "consulta"
            ),
        }

        if self.events.receiver_count() > 0 {
            let timestamp_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            let _ = self.events.send(Event::DnsQuery(DnsQueryEvent {
                timestamp_ms,
                client,
                transport,
                name: name.to_owned(),
                qtype: qtype.to_string(),
                verdict: o.verdict.clone(),
                rcode,
                source: o.source.to_string(),
                duration_us,
            }));
        }
    }
}
