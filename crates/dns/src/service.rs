//! Montagem e ciclo de vida do filtro DNS. Usado pelo binário de console e,
//! na Fase 3, pelo Windows Service.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, bail};
use argus_core::config::{Config, DnsConfig};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::blocklist::Policy;
use crate::blocklist::updater::Updater;
use crate::http::PoolResolver;
use crate::resolver::Resolver;
use crate::server;
use crate::upstream::UpstreamPool;

const STATS_INTERVAL: Duration = Duration::from_secs(300);

pub struct DnsService {
    resolver: Arc<Resolver>,
    local_addrs: Vec<SocketAddr>,
    tasks: JoinSet<()>,
}

impl DnsService {
    /// Inicia com os upstreams DoH da configuração.
    pub async fn start(cfg: &Config) -> anyhow::Result<Self> {
        let upstreams = UpstreamPool::from_config(&cfg.dns.upstream).map_err(anyhow::Error::msg)?;
        Self::start_with(cfg, Arc::new(upstreams)).await
    }

    /// Inicia com um conjunto de upstreams arbitrário (testes, transportes futuros).
    pub async fn start_with(cfg: &Config, upstreams: Arc<UpstreamPool>) -> anyhow::Result<Self> {
        let dns = &cfg.dns;
        let infra = infra_hosts(dns);
        let policy = Arc::new(Policy::new(
            dns.allowlist.iter().map(String::as_str),
            infra.iter().map(String::as_str),
        ));

        let updater = Updater::new(
            policy.clone(),
            download_client(upstreams.clone())?,
            dns.blocklists.clone(),
            cfg.data_dir.join("blocklists"),
        );
        // Listas do cache em disco valem antes de abrir as portas.
        updater.rebuild().await;

        let resolver = Arc::new(Resolver::new(dns, policy, upstreams));
        let permits = Arc::new(Semaphore::new(dns.max_concurrent_queries));
        let mut tasks = JoinSet::new();
        let mut local_addrs = Vec::new();

        for addr in &dns.listen {
            if !addr.ip().is_loopback() {
                warn!(%addr, "escutando fora do loopback: o resolver fica acessível pela rede");
            }
            let udp = match UdpSocket::bind(addr).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(%addr, error = %e, "não foi possível abrir UDP; endereço ignorado");
                    continue;
                }
            };
            let bound = udp.local_addr()?;
            // Mesma porta no TCP (importa quando a configuração usa porta 0).
            let tcp = match TcpListener::bind(bound).await {
                Ok(l) => l,
                Err(e) => {
                    warn!(addr = %bound, error = %e, "não foi possível abrir TCP; endereço ignorado");
                    continue;
                }
            };
            tasks.spawn(server::run_udp(
                Arc::new(udp),
                resolver.clone(),
                permits.clone(),
            ));
            tasks.spawn(server::run_tcp(tcp, resolver.clone(), permits.clone()));
            info!(addr = %bound, "escutando (UDP e TCP)");
            local_addrs.push(bound);
        }
        if local_addrs.is_empty() {
            bail!(
                "nenhum endereço de escuta disponível em {:?}. A porta 53 pode estar em uso \
                 (verifique com `Get-NetUDPEndpoint -LocalPort 53`)",
                dns.listen
            );
        }

        tasks.spawn(updater.run());
        tasks.spawn(log_stats(resolver.clone()));

        Ok(Self {
            resolver,
            local_addrs,
            tasks,
        })
    }

    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.local_addrs
    }

    pub fn resolver(&self) -> &Arc<Resolver> {
        &self.resolver
    }

    /// Aguarda até alguma tarefa interna terminar (o que indica falha).
    pub async fn wait(&mut self) -> anyhow::Result<()> {
        match self.tasks.join_next().await {
            Some(Err(e)) if e.is_panic() => bail!("tarefa interna do DNS entrou em pânico: {e}"),
            Some(_) => bail!("tarefa interna do DNS terminou inesperadamente"),
            None => Ok(()),
        }
    }

    pub async fn shutdown(mut self) {
        self.tasks.shutdown().await;
    }
}

/// Hosts dos quais o próprio filtro depende. Nunca são bloqueados, para que uma
/// lista errada não impeça o Argus de se atualizar.
fn infra_hosts(dns: &DnsConfig) -> Vec<String> {
    let urls = dns.upstream.servers.iter().map(|s| s.url.as_str()).chain(
        dns.blocklists
            .sources
            .iter()
            .flat_map(|s| s.urls.iter().map(String::as_str)),
    );
    urls.filter_map(|u| url::Url::parse(u).ok()?.host_str().map(str::to_owned))
        .collect()
}

/// Cliente HTTP dos downloads: resolve nomes direto nos upstreams DoH.
fn download_client(upstreams: Arc<UpstreamPool>) -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .dns_resolver(Arc::new(PoolResolver(upstreams)))
        .https_only(true)
        .no_proxy()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(120))
        .user_agent(concat!(
            "argus-dns/",
            env!("CARGO_PKG_VERSION"),
            " (+blocklist updater)"
        ))
        .build()
        .context("falha ao criar o cliente HTTP")
}

async fn log_stats(resolver: Arc<Resolver>) {
    let mut last = 0;
    loop {
        tokio::time::sleep(STATS_INTERVAL).await;
        let s = &resolver.stats;
        let queries = s.queries.load(Ordering::Relaxed);
        if queries == last {
            continue;
        }
        last = queries;
        info!(
            target: "argus_dns::stats",
            queries,
            blocked = s.blocked.load(Ordering::Relaxed),
            cache_hits = s.cache_hits.load(Ordering::Relaxed),
            failures = s.failures.load(Ordering::Relaxed),
            blocklist_domains = resolver.policy().blocked_domains(),
            "estatísticas"
        );
    }
}
