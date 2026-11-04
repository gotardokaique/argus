//! Política de bloqueio: allowlist fixa + blocklists trocadas atomicamente.

pub mod parse;
pub mod updater;

use arc_swap::ArcSwap;
use tracing::warn;

use crate::domain::{DomainSet, normalize_entry};

/// Conjunto imutável de blocklists. Substituído inteiro a cada atualização,
/// sem bloquear consultas em andamento.
#[derive(Debug, Default)]
pub struct Snapshot {
    set: DomainSet,
    sources: Vec<String>,
}

impl Snapshot {
    pub fn builder() -> SnapshotBuilder {
        SnapshotBuilder::default()
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    fn source_name(&self, idx: u16) -> &str {
        self.sources.get(idx as usize).map_or("?", String::as_str)
    }
}

#[derive(Debug, Default)]
pub struct SnapshotBuilder {
    snap: Snapshot,
}

impl SnapshotBuilder {
    /// Registra uma fonte e devolve o índice a usar em [`SnapshotBuilder::insert`].
    pub fn add_source(&mut self, name: &str) -> u16 {
        self.snap.sources.push(name.to_owned());
        u16::try_from(self.snap.sources.len() - 1).expect("menos de 65536 fontes")
    }

    pub fn insert(&mut self, domain: &str, source: u16, subdomains: bool) -> bool {
        self.snap.set.insert(domain, source, subdomains)
    }

    pub fn build(self) -> Snapshot {
        self.snap
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Pass,
    /// Liberado pela allowlist; `overridden` descreve o bloqueio que foi ignorado.
    Allowed {
        rule: String,
        overridden: Option<String>,
    },
    Blocked {
        matched: String,
        list: String,
    },
}

pub struct Policy {
    allow: DomainSet,
    block: ArcSwap<Snapshot>,
}

impl Policy {
    /// `allowlist`: entradas do usuário (liberam também subdomínios).
    /// `infra`: hosts dos quais o próprio Argus depende (liberados só no nome exato).
    pub fn new<'a>(
        allowlist: impl IntoIterator<Item = &'a str>,
        infra: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        let mut allow = DomainSet::new();
        for entry in allowlist {
            match normalize_entry(entry) {
                Some(d) => {
                    allow.insert(&d, 0, true);
                }
                None => warn!(entry, "entrada inválida na allowlist ignorada"),
            }
        }
        for host in infra {
            if let Some(d) = normalize_entry(host) {
                allow.insert(&d, 1, false);
            }
        }
        Self {
            allow,
            block: ArcSwap::from_pointee(Snapshot::default()),
        }
    }

    pub fn check(&self, name: &str) -> Decision {
        let snap = self.block.load();
        let blocked = snap.set.lookup(name);
        match (self.allow.lookup(name), blocked) {
            (Some(a), b) => Decision::Allowed {
                rule: a.matched.to_owned(),
                overridden: b.map(|m| format!("{} ({})", m.matched, snap.source_name(m.source))),
            },
            (None, Some(m)) => Decision::Blocked {
                matched: m.matched.to_owned(),
                list: snap.source_name(m.source).to_owned(),
            },
            (None, None) => Decision::Pass,
        }
    }

    pub fn replace(&self, snapshot: Snapshot) {
        self.block.store(snapshot.into());
    }

    pub fn blocked_domains(&self) -> usize {
        self.block.load().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(allow: &[&str]) -> Policy {
        let p = Policy::new(allow.iter().copied(), ["dns.quad9.net"]);
        let mut b = Snapshot::builder();
        let s = b.add_source("lista-a");
        b.insert("evil.com", s, true);
        b.insert("quad9.net", s, true);
        b.insert("cdn.shared.net", s, true);
        p.replace(b.build());
        p
    }

    #[test]
    fn blocks_and_passes() {
        let p = policy(&[]);
        assert_eq!(
            p.check("x.evil.com"),
            Decision::Blocked {
                matched: "evil.com".into(),
                list: "lista-a".into()
            }
        );
        assert_eq!(p.check("good.com"), Decision::Pass);
    }

    #[test]
    fn allowlist_wins() {
        let p = policy(&["Shared.net"]);
        assert_eq!(
            p.check("cdn.shared.net"),
            Decision::Allowed {
                rule: "shared.net".into(),
                overridden: Some("cdn.shared.net (lista-a)".into())
            }
        );
    }

    #[test]
    fn infra_hosts_are_exact_only() {
        let p = policy(&[]);
        assert!(matches!(p.check("dns.quad9.net"), Decision::Allowed { .. }));
        assert!(matches!(
            p.check("x.dns.quad9.net"),
            Decision::Blocked { .. }
        ));
        assert!(matches!(
            p.check("other.quad9.net"),
            Decision::Blocked { .. }
        ));
    }
}
