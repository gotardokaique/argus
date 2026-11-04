//! Laços de escuta UDP e TCP (RFC 1035 §4.2, RFC 7766).

use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;

use argus_core::event::Transport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tracing::{debug, error, warn};

use crate::resolver::Resolver;

const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_TCP_CONNECTIONS: usize = 128;

pub async fn run_udp(socket: Arc<UdpSocket>, resolver: Arc<Resolver>, permits: Arc<Semaphore>) {
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            // Windows entrega o ICMP "port unreachable" de um envio anterior
            // como WSAECONNRESET no próximo recv. Não é erro do socket.
            Err(e) if e.kind() == ErrorKind::ConnectionReset => continue,
            Err(e) => {
                error!(error = %e, "erro no socket UDP");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            debug!(%peer, "sobrecarga: consulta UDP descartada");
            continue;
        };
        let packet = buf[..len].to_vec();
        let (socket, resolver) = (socket.clone(), resolver.clone());
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(resp) = resolver.handle(&packet, peer, Transport::Udp).await
                && let Err(e) = socket.send_to(&resp, peer).await
            {
                debug!(%peer, error = %e, "falha ao enviar resposta UDP");
            }
        });
    }
}

pub async fn run_tcp(listener: TcpListener, resolver: Arc<Resolver>, permits: Arc<Semaphore>) {
    let connections = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "erro ao aceitar conexão TCP");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(conn) = connections.clone().try_acquire_owned() else {
            debug!(%peer, "limite de conexões TCP atingido");
            continue;
        };
        let (resolver, permits) = (resolver.clone(), permits.clone());
        tokio::spawn(async move {
            let _conn = conn;
            if let Err(e) = serve_connection(stream, peer, &resolver, &permits).await {
                debug!(%peer, error = %e, "conexão TCP encerrada");
            }
        });
    }
}

async fn serve_connection(
    mut stream: TcpStream,
    peer: std::net::SocketAddr,
    resolver: &Resolver,
    permits: &Semaphore,
) -> std::io::Result<()> {
    loop {
        let len = match tokio::time::timeout(TCP_IDLE_TIMEOUT, stream.read_u16()).await {
            Ok(Ok(len)) => usize::from(len),
            Ok(Err(e)) if e.kind() == ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(()), // ocioso
        };
        let mut packet = vec![0u8; len];
        tokio::time::timeout(TCP_IDLE_TIMEOUT, stream.read_exact(&mut packet))
            .await
            .map_err(|_| ErrorKind::TimedOut)??;

        let _permit = permits.acquire().await.map_err(|_| ErrorKind::BrokenPipe)?;
        let Some(resp) = resolver.handle(&packet, peer, Transport::Tcp).await else {
            return Ok(());
        };
        let resp_len = u16::try_from(resp.len()).map_err(|_| ErrorKind::InvalidData)?;
        let mut frame = Vec::with_capacity(resp.len() + 2);
        frame.extend_from_slice(&resp_len.to_be_bytes());
        frame.extend_from_slice(&resp);
        stream.write_all(&frame).await?;
    }
}
