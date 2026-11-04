//! Filtro DNS local do Argus.
//!
//! Escuta em loopback (UDP e TCP), bloqueia domínios presentes em blocklists
//! públicas, respeita uma allowlist com prioridade e encaminha o resto para
//! upstreams DNS-over-HTTPS com fallback. Respostas são cacheadas pelo TTL.
//!
//! O formato wire é tratado pelo `hickory-proto`; os laços de servidor, a
//! política e o cache são próprios, para controlar o comportamento no Windows
//! e o ponto exato onde cada decisão é tomada e registrada.

#![forbid(unsafe_code)]

pub mod blocklist;
pub mod cache;
pub mod domain;
pub mod forward;
pub mod http;
pub mod message;
pub mod resolver;
pub mod server;
pub mod service;
pub mod upstream;

pub use service::DnsService;
