//! Encaminhamento de zonas locais (ex.: `lan`) para servidores DNS comuns.

use std::net::SocketAddr;
use std::time::Duration;

use argus_core::config::ForwardZone;
use hickory_proto::op::{Message, MessageType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::warn;

use crate::domain::suffixes;

pub struct Forwarders {
    /// (zona normalizada, servidores)
    zones: Vec<(String, Vec<SocketAddr>)>,
}

impl Forwarders {
    pub fn new(cfg: &[ForwardZone]) -> Self {
        Self {
            zones: cfg
                .iter()
                .map(|z| {
                    (
                        z.zone.trim_matches('.').to_ascii_lowercase(),
                        z.servers.clone(),
                    )
                })
                .collect(),
        }
    }

    /// Servidores da zona mais específica que contém `name`.
    pub fn find(&self, name: &str) -> Option<&[SocketAddr]> {
        suffixes(name).find_map(|s| {
            self.zones
                .iter()
                .find(|(z, _)| z == s)
                .map(|(_, srv)| srv.as_slice())
        })
    }

    /// Envia a consulta aos servidores da zona, em ordem. Usa um ID aleatório
    /// novo (o ID do cliente é restaurado pelo chamador).
    pub async fn exchange(
        &self,
        servers: &[SocketAddr],
        query: &Message,
        timeout: Duration,
    ) -> Option<Message> {
        let mut q = query.clone();
        q.metadata.id = rand::random();
        let wire = q.to_vec().ok()?;
        for server in servers {
            match tokio::time::timeout(timeout, exchange_one(*server, &wire, q.id)).await {
                Ok(Ok(msg)) => return Some(msg),
                Ok(Err(e)) => warn!(%server, error = %e, "falha no servidor da zona local"),
                Err(_) => warn!(%server, "tempo esgotado no servidor da zona local"),
            }
        }
        None
    }
}

async fn exchange_one(server: SocketAddr, wire: &[u8], id: u16) -> std::io::Result<Message> {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .expect("endereço fixo");
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(server).await?;
    sock.send(wire).await?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = sock.recv(&mut buf).await?;
        // Descarta respostas com ID diferente (atrasadas ou forjadas).
        let Ok(msg) = Message::from_vec(&buf[..n]) else {
            continue;
        };
        if msg.id != id || msg.message_type != MessageType::Response {
            continue;
        }
        if msg.truncation {
            return exchange_tcp(server, wire).await;
        }
        return Ok(msg);
    }
}

async fn exchange_tcp(server: SocketAddr, wire: &[u8]) -> std::io::Result<Message> {
    let mut stream = TcpStream::connect(server).await?;
    let len = u16::try_from(wire.len()).map_err(|_| std::io::ErrorKind::InvalidInput)?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(wire).await?;
    let len = stream.read_u16().await? as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Message::from_vec(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn most_specific_zone_wins() {
        let a: SocketAddr = "192.168.1.1:53".parse().unwrap();
        let b: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let f = Forwarders::new(&[
            ForwardZone {
                zone: "LAN.".into(),
                servers: vec![a],
            },
            ForwardZone {
                zone: "office.lan".into(),
                servers: vec![b],
            },
        ]);
        assert_eq!(f.find("printer.lan"), Some(&[a][..]));
        assert_eq!(f.find("pc.office.lan"), Some(&[b][..]));
        assert_eq!(f.find("lan"), Some(&[a][..]));
        assert_eq!(f.find("example.com"), None);
        assert_eq!(f.find("evillan"), None);
    }
}
