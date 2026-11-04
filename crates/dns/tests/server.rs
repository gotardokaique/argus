//! Teste ponta a ponta: servidor real em 127.0.0.1:<porta efêmera>, upstream falso.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use argus_core::config::{BlocklistSource, Config, ListFormat};
use argus_dns::DnsService;
use argus_dns::upstream::{BoxFuture, Exchange, UpstreamError, UpstreamPool};
use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Responde A 192.0.2.1 (TTL 300) para tudo; `cloaked.test` vira CNAME para um domínio bloqueado.
struct FakeUpstream {
    calls: Arc<AtomicUsize>,
}

impl Exchange for FakeUpstream {
    fn exchange<'a>(&'a self, query: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, UpstreamError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let q = Message::from_vec(query).unwrap();
            assert_eq!(q.id, 0, "DoH deve usar ID 0");
            let mut r = Message::response(q.id, OpCode::Query);
            r.add_queries(q.queries.clone());
            let name = q.queries[0].name.clone();
            if name.to_ascii().eq_ignore_ascii_case("cloaked.test.") {
                let target = Name::from_ascii("tracker.evil.test.").unwrap();
                r.add_answer(Record::from_rdata(
                    name,
                    300,
                    RData::CNAME(CNAME(target.clone())),
                ));
                r.add_answer(Record::from_rdata(
                    target,
                    300,
                    RData::A(A::new(192, 0, 2, 66)),
                ));
            } else {
                r.add_answer(Record::from_rdata(
                    name,
                    300,
                    RData::A(A::new(192, 0, 2, 1)),
                ));
            }
            Ok(r.to_vec().unwrap())
        })
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    service: DnsService,
    calls: Arc<AtomicUsize>,
}

async fn start() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let list = dir.path().join("local.txt");
    std::fs::write(&list, "evil.test\n# comentário\nbad.example\n").unwrap();

    let mut cfg = Config {
        data_dir: dir.path().join("data"),
        ..Config::default()
    };
    cfg.dns.listen = vec!["127.0.0.1:0".parse().unwrap()];
    cfg.dns.allowlist = vec!["ok.evil.test".into()];
    cfg.dns.blocklists.sources = vec![BlocklistSource {
        name: "local".into(),
        enabled: true,
        urls: vec![],
        path: Some(list),
        format: ListFormat::Domains,
        match_subdomains: true,
    }];

    let calls = Arc::new(AtomicUsize::new(0));
    let fake: Box<dyn Exchange> = Box::new(FakeUpstream {
        calls: calls.clone(),
    });
    let pool = UpstreamPool::new(
        vec![("fake".into(), fake)],
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    let service = DnsService::start_with(&cfg, Arc::new(pool)).await.unwrap();
    Harness {
        _dir: dir,
        service,
        calls,
    }
}

impl Harness {
    fn addr(&self) -> SocketAddr {
        self.service.local_addrs()[0]
    }
}

fn query(name: &str, rtype: RecordType) -> Message {
    let mut m = Message::query();
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
    m
}

async fn udp(server: SocketAddr, q: &Message) -> Message {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&q.to_vec().unwrap(), server).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("sem resposta UDP")
        .unwrap();
    let r = Message::from_vec(&buf[..n]).unwrap();
    assert_eq!(r.id, q.id);
    r
}

async fn tcp(server: SocketAddr, q: &Message) -> Message {
    let mut s = TcpStream::connect(server).await.unwrap();
    let wire = q.to_vec().unwrap();
    s.write_all(&(wire.len() as u16).to_be_bytes())
        .await
        .unwrap();
    s.write_all(&wire).await.unwrap();
    let len = s.read_u16().await.unwrap() as usize;
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await.unwrap();
    Message::from_vec(&buf).unwrap()
}

fn first_a(r: &Message) -> Option<Ipv4Addr> {
    r.answers.iter().find_map(|rec| match &rec.data {
        RData::A(a) => Some(a.0),
        _ => None,
    })
}

#[tokio::test]
async fn blocks_listed_domains_and_subdomains() {
    let h = start().await;
    for name in ["evil.test.", "deep.sub.EVIL.test.", "bad.example."] {
        let r = udp(h.addr(), &query(name, RecordType::A)).await;
        assert_eq!(r.response_code, ResponseCode::NoError, "{name}");
        assert_eq!(first_a(&r), Some(Ipv4Addr::UNSPECIFIED), "{name}");
    }
    assert_eq!(
        h.calls.load(Ordering::SeqCst),
        0,
        "bloqueados não chegam ao upstream"
    );
}

#[tokio::test]
async fn allowlist_overrides_blocklist() {
    let h = start().await;
    let r = udp(h.addr(), &query("www.ok.evil.test.", RecordType::A)).await;
    assert_eq!(first_a(&r), Some(Ipv4Addr::new(192, 0, 2, 1)));
}

#[tokio::test]
async fn forwards_and_caches() {
    let h = start().await;
    let r1 = udp(h.addr(), &query("example.org.", RecordType::A)).await;
    assert_eq!(first_a(&r1), Some(Ipv4Addr::new(192, 0, 2, 1)));
    assert!(r1.recursion_available);

    let r2 = tcp(h.addr(), &query("EXAMPLE.org.", RecordType::A)).await;
    assert_eq!(first_a(&r2), Some(Ipv4Addr::new(192, 0, 2, 1)));
    assert!(r2.answers[0].ttl <= 300);
    // A pergunta volta como o cliente escreveu.
    assert_eq!(r2.queries[0].name.to_ascii(), "EXAMPLE.org.");
    assert_eq!(
        h.calls.load(Ordering::SeqCst),
        1,
        "segunda consulta veio do cache"
    );
}

#[tokio::test]
async fn blocks_cname_to_blocked_domain() {
    let h = start().await;
    let r = udp(h.addr(), &query("cloaked.test.", RecordType::A)).await;
    assert_eq!(first_a(&r), Some(Ipv4Addr::UNSPECIFIED));
}

#[tokio::test]
async fn local_names() {
    let h = start().await;
    let r = udp(h.addr(), &query("localhost.", RecordType::A)).await;
    assert_eq!(first_a(&r), Some(Ipv4Addr::LOCALHOST));

    let r = udp(h.addr(), &query("impressora.", RecordType::A)).await;
    assert_eq!(r.response_code, ResponseCode::NXDomain);

    let r = udp(h.addr(), &query("use-application-dns.net.", RecordType::A)).await;
    assert_eq!(r.response_code, ResponseCode::NXDomain);
    assert_eq!(h.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn survives_garbage() {
    let h = start().await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&[0xde, 0xad, 0x01, 0x00, 0xff], h.addr())
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let r = Message::from_vec(&buf[..n]).unwrap();
    assert_eq!(r.id, 0xdead);
    assert_eq!(r.response_code, ResponseCode::FormErr);

    // O servidor continua respondendo depois do lixo.
    let r = udp(h.addr(), &query("example.net.", RecordType::A)).await;
    assert_eq!(r.response_code, ResponseCode::NoError);
}
