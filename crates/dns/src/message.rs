//! Construção e serialização de respostas.

use std::net::{Ipv4Addr, Ipv6Addr};

use argus_core::config::BlockedResponse;
use argus_core::event::Transport;
use hickory_proto::op::{Edns, Message, Metadata, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};

/// Payload UDP máximo anunciado (DNS Flag Day 2020: evita fragmentação IP).
pub const UDP_MAX_PAYLOAD: u16 = 1232;

/// Resposta sem registros espelhando a consulta (ID, opcode, RD, CD e pergunta).
pub fn reply_to(query: &Message, rcode: ResponseCode) -> Message {
    let mut m = Message::response(query.id, query.op_code);
    m.metadata = Metadata::response_from_request(&query.metadata);
    m.metadata.recursion_available = true;
    m.metadata.response_code = rcode;
    m.add_queries(query.queries.iter().cloned());
    m
}

pub fn blocked(query: &Message, mode: BlockedResponse, ttl: u32) -> Message {
    match mode {
        BlockedResponse::Nxdomain => reply_to(query, ResponseCode::NXDomain),
        BlockedResponse::NullIp => {
            fixed_address(query, Ipv4Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED, ttl)
        }
    }
}

/// `localhost` e `*.localhost` resolvem para loopback (RFC 6761 §6.3).
pub fn localhost(query: &Message) -> Message {
    fixed_address(query, Ipv4Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 300)
}

/// A/AAAA com o endereço dado; demais tipos recebem NOERROR sem respostas (NODATA).
fn fixed_address(query: &Message, v4: Ipv4Addr, v6: Ipv6Addr, ttl: u32) -> Message {
    let mut m = reply_to(query, ResponseCode::NoError);
    if let Some(q) = query.queries.first() {
        let rdata = match q.query_type {
            RecordType::A => Some(RData::A(A(v4))),
            RecordType::AAAA => Some(RData::AAAA(AAAA(v6))),
            _ => None,
        };
        if let Some(rdata) = rdata {
            m.add_answer(Record::from_rdata(q.name.clone(), ttl, rdata));
        }
    }
    m
}

/// Ajusta uma resposta obtida de terceiros (upstream/cache) para este cliente.
pub fn adapt(mut resp: Message, query: &Message) -> Message {
    resp.metadata.id = query.id;
    resp.metadata.recursion_desired = query.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.checking_disabled = query.checking_disabled;
    resp.metadata.authoritative = false;
    // RFC 6840 §5.8: só sinalizar AD a quem pediu DO ou AD.
    let dnssec_ok = query.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok);
    resp.metadata.authentic_data &= dnssec_ok || query.authentic_data;
    // Devolve a pergunta como o cliente a escreveu (preserva maiúsculas/0x20).
    resp.queries = query.queries.clone();
    resp
}

/// Serializa para o transporte; em UDP, trunca (TC=1) o que não couber.
pub fn encode(mut resp: Message, query: &Message, transport: Transport) -> Option<Vec<u8>> {
    resp.edns = query.edns.as_ref().map(|client| {
        let mut e = Edns::new();
        e.set_max_payload(UDP_MAX_PAYLOAD);
        e.set_dnssec_ok(client.flags().dnssec_ok);
        e
    });
    let limit = match transport {
        Transport::Udp => usize::from(query.max_payload().min(UDP_MAX_PAYLOAD)),
        Transport::Tcp => usize::from(u16::MAX),
    };
    let bytes = resp.to_vec().ok()?;
    if bytes.len() <= limit {
        return Some(bytes);
    }
    resp.truncate().to_vec().ok()
}

/// FORMERR para pacotes que nem chegam a ser parseados (usa apenas o ID bruto).
pub fn formerr_raw(packet: &[u8]) -> Option<Vec<u8>> {
    let id = u16::from_be_bytes([*packet.first()?, *packet.get(1)?]);
    // Se o próprio bit QR indica resposta, não responder (evita loops).
    if packet.get(2).is_some_and(|flags| flags & 0x80 != 0) {
        return None;
    }
    Message::error_msg(id, hickory_proto::op::OpCode::Query, ResponseCode::FormErr)
        .to_vec()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;

    fn query(name: &str, rtype: RecordType, edns: Option<u16>) -> Message {
        let mut m = Message::query();
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
        if let Some(size) = edns {
            let mut e = Edns::new();
            e.set_max_payload(size);
            m.set_edns(e);
        }
        m
    }

    #[test]
    fn null_ip_and_nxdomain() {
        let q = query("evil.com.", RecordType::A, None);
        let r = blocked(&q, BlockedResponse::NullIp, 60);
        assert_eq!(r.id, q.id);
        assert!(r.recursion_desired && r.recursion_available);
        assert_eq!(r.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
        assert_eq!(r.answers[0].ttl, 60);

        let r = blocked(
            &query("evil.com.", RecordType::AAAA, None),
            BlockedResponse::NullIp,
            60,
        );
        assert_eq!(r.answers[0].data, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));

        let r = blocked(
            &query("evil.com.", RecordType::HTTPS, None),
            BlockedResponse::NullIp,
            60,
        );
        assert_eq!(r.response_code, ResponseCode::NoError);
        assert!(r.answers.is_empty());

        let r = blocked(&q, BlockedResponse::Nxdomain, 60);
        assert_eq!(r.response_code, ResponseCode::NXDomain);
    }

    #[test]
    fn truncates_large_udp_responses() {
        let q = query("big.test.", RecordType::A, None);
        let mut r = reply_to(&q, ResponseCode::NoError);
        for i in 0..60u8 {
            r.add_answer(Record::from_rdata(
                q.queries[0].name.clone(),
                60,
                RData::A(A::new(10, 0, 0, i)),
            ));
        }
        let udp = Message::from_vec(&encode(r.clone(), &q, Transport::Udp).unwrap()).unwrap();
        assert!(udp.truncation);
        assert!(udp.answers.is_empty());

        let tcp = Message::from_vec(&encode(r.clone(), &q, Transport::Tcp).unwrap()).unwrap();
        assert!(!tcp.truncation);
        assert_eq!(tcp.answers.len(), 60);

        // Com EDNS anunciando 4096, o limite efetivo é 1232: 60 registros A (~1 KB) cabem.
        let q = query("big.test.", RecordType::A, Some(4096));
        let udp = Message::from_vec(&encode(r, &q, Transport::Udp).unwrap()).unwrap();
        assert!(!udp.truncation);
        assert_eq!(udp.edns.unwrap().max_payload(), UDP_MAX_PAYLOAD);
    }

    #[test]
    fn formerr_for_garbage() {
        let r = Message::from_vec(&formerr_raw(&[0x12, 0x34, 0x01]).unwrap()).unwrap();
        assert_eq!(r.id, 0x1234);
        assert_eq!(r.response_code, ResponseCode::FormErr);
        assert!(formerr_raw(&[0x12]).is_none());
        assert!(formerr_raw(&[0x12, 0x34, 0x80]).is_none());
    }
}
