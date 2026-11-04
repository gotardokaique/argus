use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::verdict::Verdict;

/// Evento emitido por um componente, consumido pelo serviço (Fase 3) e pela UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    DnsQuery(DnsQueryEvent),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Udp,
    Tcp,
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        })
    }
}

/// Uma consulta DNS respondida pelo filtro local.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryEvent {
    /// Milissegundos desde a época Unix.
    pub timestamp_ms: u64,
    pub client: SocketAddr,
    pub transport: Transport,
    pub name: String,
    pub qtype: String,
    pub verdict: Verdict,
    /// Código de resposta enviado ao cliente (NoError, NXDomain, ServFail...).
    pub rcode: String,
    /// Como a resposta foi obtida: "blocked", "cache", "upstream:<nome>", "forward", "local".
    pub source: String,
    pub duration_us: u64,
}
