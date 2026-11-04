//! Normalização de nomes e conjunto de domínios com match por sufixo.

use std::collections::HashMap;
use std::net::IpAddr;

use hickory_proto::rr::Name;

/// Nomes que aparecem em arquivos hosts mas nunca devem virar regra.
const IGNORED: &[&str] = &[
    "localhost.localdomain",
    "local",
    "localhost",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
];

/// Normaliza uma entrada de lista (blocklist/allowlist): minúsculas, sem ponto
/// final nem `*.` inicial. Rejeita IPs, nomes sem ponto e rótulos inválidos.
pub fn normalize_entry(input: &str) -> Option<String> {
    let s = input.trim().trim_end_matches('.');
    let s = s.strip_prefix("*.").unwrap_or(s);
    if s.is_empty() || s.len() > 253 || !s.contains('.') || s.parse::<IpAddr>().is_ok() {
        return None;
    }
    let s = s.to_ascii_lowercase();
    if IGNORED.contains(&s.as_str()) {
        return None;
    }
    let labels_ok = s.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    labels_ok.then_some(s)
}

/// Nome de consulta em forma canônica para lookup: minúsculas, ASCII (punycode), sem ponto final.
pub fn query_name(name: &Name) -> String {
    let mut s = name.to_lowercase().to_ascii();
    if s.ends_with('.') {
        s.pop();
    }
    s
}

/// Itera o nome e seus sufixos, do mais específico ao menos: `a.b.c`, `b.c`, `c`.
pub fn suffixes(name: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(name), |s| s.split_once('.').map(|(_, rest)| rest))
        .filter(|s| !s.is_empty())
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    source: u16,
    subdomains: bool,
}

/// Conjunto de domínios. Lookup em O(rótulos): um acesso ao hash por sufixo.
#[derive(Debug, Default)]
pub struct DomainSet {
    map: HashMap<Box<str>, Entry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match<'a> {
    /// Entrada da lista que casou (o próprio nome ou um domínio pai).
    pub matched: &'a str,
    pub source: u16,
}

impl DomainSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insere uma entrada já normalizada. Duplicatas são unidas: vale a primeira
    /// fonte, e o match de subdomínio é ativado se qualquer fonte o pedir.
    /// Retorna `true` se a entrada era nova.
    pub fn insert(&mut self, domain: &str, source: u16, subdomains: bool) -> bool {
        match self.map.get_mut(domain) {
            Some(e) => {
                e.subdomains |= subdomains;
                false
            }
            None => {
                self.map.insert(domain.into(), Entry { source, subdomains });
                true
            }
        }
    }

    /// Procura `name` (já normalizado) e seus domínios pai.
    pub fn lookup(&self, name: &str) -> Option<Match<'_>> {
        suffixes(name).enumerate().find_map(|(i, suffix)| {
            let (key, e) = self.map.get_key_value(suffix)?;
            (i == 0 || e.subdomains).then_some(Match {
                matched: key,
                source: e.source,
            })
        })
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_entries() {
        assert_eq!(normalize_entry(" Evil.COM. ").as_deref(), Some("evil.com"));
        assert_eq!(normalize_entry("*.evil.com").as_deref(), Some("evil.com"));
        assert_eq!(
            normalize_entry("xn--bcher-kva.example").as_deref(),
            Some("xn--bcher-kva.example")
        );
        assert_eq!(
            normalize_entry("_dmarc.example.com").as_deref(),
            Some("_dmarc.example.com")
        );
        for bad in [
            "",
            "com",
            "localhost",
            "0.0.0.0",
            "::1",
            "a..b",
            "bad domain.com",
            "ex@mple.com",
            "bücher.de",
        ] {
            assert_eq!(normalize_entry(bad), None, "{bad:?}");
        }
        assert_eq!(normalize_entry(&format!("{}.com", "a".repeat(64))), None);
    }

    #[test]
    fn query_names_are_canonical() {
        let n = Name::from_ascii("WWW.Example.COM.").unwrap();
        assert_eq!(query_name(&n), "www.example.com");
        assert_eq!(query_name(&Name::root()), "");
    }

    #[test]
    fn suffix_iteration() {
        assert_eq!(suffixes("a.b.c").collect::<Vec<_>>(), ["a.b.c", "b.c", "c"]);
        assert_eq!(suffixes("").count(), 0);
    }

    #[test]
    fn subdomain_matching() {
        let mut set = DomainSet::new();
        set.insert("evil.com", 0, true);
        set.insert("exact.net", 1, false);

        assert_eq!(set.lookup("evil.com").unwrap().matched, "evil.com");
        assert_eq!(set.lookup("a.b.evil.com").unwrap().matched, "evil.com");
        assert!(set.lookup("notevil.com").is_none());
        assert!(set.lookup("evil.com.br").is_none());

        assert_eq!(set.lookup("exact.net").unwrap().source, 1);
        assert!(set.lookup("www.exact.net").is_none());
    }

    #[test]
    fn duplicates_merge() {
        let mut set = DomainSet::new();
        assert!(set.insert("x.com", 0, false));
        assert!(!set.insert("x.com", 1, true));
        assert_eq!(set.len(), 1);
        let m = set.lookup("sub.x.com").unwrap();
        assert_eq!(m.source, 0);
    }
}
