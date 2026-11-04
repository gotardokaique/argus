//! Cache de respostas respeitando TTL (RFC 1035 §3.2.1, RFC 2308 para negativas).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use argus_core::config::CacheConfig;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{DNSClass, RData, RecordType};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: String,
    pub qtype: RecordType,
    pub qclass: DNSClass,
    /// Respostas com e sem registros DNSSEC (bit DO) e com validação
    /// desligada (bit CD) não são intercambiáveis.
    pub dnssec_ok: bool,
    pub checking_disabled: bool,
}

struct Entry {
    message: Message,
    stored: Instant,
    expires: Instant,
}

pub struct Cache {
    entries: Mutex<HashMap<CacheKey, Entry>>,
    cfg: CacheConfig,
}

impl Cache {
    pub fn new(cfg: CacheConfig) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            cfg,
        }
    }

    /// Devolve a resposta com os TTLs decrementados pelo tempo em cache.
    pub fn get(&self, key: &CacheKey, now: Instant) -> Option<Message> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries.get(key)?;
        if entry.expires <= now {
            entries.remove(key);
            return None;
        }
        let elapsed = u32::try_from(now.duration_since(entry.stored).as_secs()).unwrap_or(u32::MAX);
        let mut msg = entry.message.clone();
        for r in msg
            .answers
            .iter_mut()
            .chain(&mut msg.authorities)
            .chain(&mut msg.additionals)
        {
            r.decrement_ttl(elapsed);
        }
        Some(msg)
    }

    /// Armazena a resposta se ela for cacheável. Retorna o TTL usado.
    pub fn insert(&self, key: CacheKey, msg: &Message, now: Instant) -> Option<u32> {
        let ttl = self.ttl_for(msg)?;
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= self.cfg.max_entries && !entries.contains_key(&key) {
            evict(&mut entries, self.cfg.max_entries, now);
        }
        let mut stored = msg.clone();
        stored.edns = None;
        entries.insert(
            key,
            Entry {
                message: stored,
                stored: now,
                expires: now + Duration::from_secs(ttl.into()),
            },
        );
        Some(ttl)
    }

    fn ttl_for(&self, msg: &Message) -> Option<u32> {
        if !self.cfg.enabled || self.cfg.max_entries == 0 || msg.truncation {
            return None;
        }
        let ttl = match msg.response_code {
            ResponseCode::NoError if !msg.answers.is_empty() => {
                let min = msg
                    .answers
                    .iter()
                    .chain(&msg.authorities)
                    .map(|r| r.ttl)
                    .min()?;
                min.clamp(self.cfg.min_ttl, self.cfg.max_ttl)
            }
            // Negativa (NXDOMAIN ou NODATA): TTL = min(TTL do SOA, SOA.minimum).
            ResponseCode::NoError | ResponseCode::NXDomain => {
                let soa_ttl = msg.authorities.iter().find_map(|r| match &r.data {
                    RData::SOA(soa) => Some(r.ttl.min(soa.minimum)),
                    _ => None,
                })?;
                soa_ttl.min(self.cfg.negative_max_ttl)
            }
            _ => return None,
        };
        (ttl > 0).then_some(ttl)
    }

    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Remove expirados; se ainda cheio, remove os ~10% que expiram primeiro.
fn evict(entries: &mut HashMap<CacheKey, Entry>, max: usize, now: Instant) {
    entries.retain(|_, e| e.expires > now);
    if entries.len() < max {
        return;
    }
    let excess = entries.len() + 1 - max;
    let target = excess.max(max / 10).min(entries.len());
    let mut by_expiry: Vec<(Instant, CacheKey)> = entries
        .iter()
        .map(|(k, e)| (e.expires, k.clone()))
        .collect();
    by_expiry.select_nth_unstable_by_key(target - 1, |(exp, _)| *exp);
    for (_, k) in by_expiry.into_iter().take(target) {
        entries.remove(&k);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{OpCode, Query};
    use hickory_proto::rr::rdata::{A, SOA};
    use hickory_proto::rr::{Name, Record};

    fn key(name: &str) -> CacheKey {
        CacheKey {
            name: name.into(),
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            dnssec_ok: false,
            checking_disabled: false,
        }
    }

    fn answer(name: &str, ttls: &[u32]) -> Message {
        let n = Name::from_ascii(name).unwrap();
        let mut m = Message::response(0, OpCode::Query);
        m.add_query(Query::query(n.clone(), RecordType::A));
        for (i, ttl) in ttls.iter().enumerate() {
            m.add_answer(Record::from_rdata(
                n.clone(),
                *ttl,
                RData::A(A::new(192, 0, 2, i as u8)),
            ));
        }
        m
    }

    fn cache(max_entries: usize) -> Cache {
        Cache::new(CacheConfig {
            max_entries,
            ..CacheConfig::default()
        })
    }

    #[test]
    fn respects_and_decrements_ttl() {
        let c = cache(100);
        let t0 = Instant::now();
        assert_eq!(
            c.insert(key("a.test"), &answer("a.test.", &[300, 120]), t0),
            Some(120)
        );

        let hit = c.get(&key("a.test"), t0 + Duration::from_secs(20)).unwrap();
        assert_eq!(
            hit.answers.iter().map(|r| r.ttl).collect::<Vec<_>>(),
            [280, 100]
        );

        assert!(
            c.get(&key("a.test"), t0 + Duration::from_secs(120))
                .is_none()
        );
        assert!(c.is_empty());
    }

    #[test]
    fn negative_uses_soa_minimum() {
        let c = cache(100);
        let mut m = Message::error_msg(0, OpCode::Query, ResponseCode::NXDomain);
        let zone = Name::from_ascii("test.").unwrap();
        let soa = SOA::new(zone.clone(), zone.clone(), 1, 7200, 900, 86400, 300);
        m.add_authority(Record::from_rdata(zone, 3600, RData::SOA(soa)));
        assert_eq!(c.insert(key("nx.test"), &m, Instant::now()), Some(300));

        let no_soa = Message::error_msg(0, OpCode::Query, ResponseCode::NXDomain);
        assert_eq!(c.insert(key("nx2.test"), &no_soa, Instant::now()), None);
    }

    #[test]
    fn never_caches_failures_or_zero_ttl() {
        let c = cache(100);
        let now = Instant::now();
        assert_eq!(
            c.insert(
                key("s"),
                &Message::error_msg(0, OpCode::Query, ResponseCode::ServFail),
                now
            ),
            None
        );
        assert_eq!(c.insert(key("z"), &answer("z.", &[0]), now), None);
        let mut tc = answer("t.", &[60]);
        tc.metadata.truncation = true;
        assert_eq!(c.insert(key("t"), &tc, now), None);
    }

    #[test]
    fn evicts_when_full() {
        let c = cache(20);
        let now = Instant::now();
        for i in 0..50u32 {
            c.insert(key(&format!("n{i}")), &answer("n.", &[100 + i]), now);
        }
        assert!(c.len() <= 20);
        // As entradas mais longas sobrevivem.
        assert!(c.get(&key("n49"), now).is_some());
    }
}
