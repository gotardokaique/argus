//! Resolução de nomes para o tráfego HTTP do próprio Argus.
//!
//! O DNS do sistema aponta para o Argus; se ele resolvesse seus próprios
//! downloads pelo sistema, dependeria de si mesmo (e das próprias blocklists).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use reqwest::dns::{Addrs, Name as HttpName, Resolve, Resolving};

use crate::upstream::UpstreamPool;

/// Recusa toda resolução. Usado nos clientes DoH, que só conectam por bootstrap.
pub struct NoResolve;

impl Resolve for NoResolve {
    fn resolve(&self, name: HttpName) -> Resolving {
        let msg = format!("{} não está no bootstrap do upstream", name.as_str());
        Box::pin(async move { Err(msg.into()) })
    }
}

/// Resolve direto pelos upstreams DoH, sem cache e sem blocklists.
pub struct PoolResolver(pub Arc<UpstreamPool>);

impl Resolve for PoolResolver {
    fn resolve(&self, name: HttpName) -> Resolving {
        let pool = self.0.clone();
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let fqdn = Name::from_ascii(format!("{host}."))?;
            let (v4, v6) = tokio::join!(
                lookup(&pool, &fqdn, RecordType::A),
                lookup(&pool, &fqdn, RecordType::AAAA)
            );
            let mut ips = v4.unwrap_or_default();
            ips.extend(v6.unwrap_or_default());
            if ips.is_empty() {
                return Err(format!("{host}: sem endereços").into());
            }
            let addrs: Addrs = Box::new(ips.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

async fn lookup(pool: &UpstreamPool, name: &Name, rtype: RecordType) -> Option<Vec<IpAddr>> {
    let mut q = Message::query();
    q.metadata.recursion_desired = true;
    q.add_query(Query::query(name.clone(), rtype));
    let (resp, _) = pool.resolve(&q).await.ok()?;
    if resp.response_code != ResponseCode::NoError {
        return None;
    }
    Some(
        resp.answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(IpAddr::V4(a.0)),
                RData::AAAA(a) => Some(IpAddr::V6(a.0)),
                _ => None,
            })
            .collect(),
    )
}
