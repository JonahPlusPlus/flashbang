use std::{io, net::{SocketAddr, IpAddr, Ipv6Addr}, sync::{Arc, atomic::{AtomicBool, Ordering}}, pin::Pin};

use bytes::{Bytes, BytesMut};
use futures::{FutureExt, future::poll_fn};
use tokio::{net::{TcpListener, TcpStream, TcpSocket, UdpSocket}, time::{timeout, Duration}, io::{AsyncReadExt, AsyncWriteExt}};


use super::*;

const MAX_PACKET_SIZE: usize = 65535;

pub struct TokioServerRuntime;

impl TokioServerRuntime {
    async fn serve_tcp(runner: ServerRunner) -> io::Result<()> {
        // TODO: Make addr const when Rust 1.69 releases
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), INSECURE_PORT);
    
        let listener = TcpListener::bind(addr).await?;
    
        log::debug!("Started `tcp/{INSECURE_PORT}`");
    
        while runner.running.load(Ordering::Relaxed) {
            let Ok(result) = timeout(Duration::from_millis(200), listener.accept()).await else {
                continue;
            };
    
            let (stream, remote) = match result {
                Ok(r) => r,
                Err(err) => {
                    log::warn!("`tcp/{INSECURE_PORT}` failed to connect to remote: {err}");
                    continue;
                }
            };

            let conn = TcpConn {
                stream,
                remote,
            };
    
            tokio::spawn(async move {
                let processor = ServerProcessor::new(conn);

                processor.process();
            });
        }
    
        Ok(())
    }
    
    async fn serve_udp(runner: ServerRunner) -> io::Result<()> {
        // TODO: make const
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), INSECURE_PORT);
    
        let socket = UdpSocket::bind(addr).await?;
    
        log::debug!("Started `udp/{INSECURE_PORT}`");

        let conn = UdpConn {
            socket,
        };
        
        let processor = ServerProcessor::new(conn);

        processor.process();
    
        Ok(())
    }
}

#[async_trait::async_trait]
impl ServerRuntime for TokioServerRuntime {
    async fn run(runner: ServerRunner) {
        let mut tcp = tokio::spawn(Self::serve_tcp(runner.clone()));
        let mut udp = tokio::spawn(Self::serve_udp(runner.clone()));

        poll_fn(|cx| {
            if runner.running.load(Ordering::Relaxed) {
                let tcp_status = tcp.poll_unpin(cx);

                if let Poll::Ready(Ok(Err(e))) = tcp_status {
                    log::error!("{e}");

                    tcp = tokio::spawn(Self::serve_tcp(runner.clone()));
                }

                let udp_status = udp.poll_unpin(cx);

                if let Poll::Ready(Ok(Err(e))) = udp_status {
                    log::error!("{e}");

                    udp = tokio::spawn(Self::serve_udp(runner.clone()));
                }

                Poll::Pending
            } else {
                tcp.abort();
                udp.abort();

                Poll::Ready(())
            }
        }).await;
    }
}

struct TcpConn {
    stream: TcpStream,
    remote: SocketAddr,
}

#[async_trait::async_trait]
impl ServerConn for TcpConn {
    async fn send(&mut self, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        self.stream.write_all(&buf).await?;
        Ok(())
    }

    async fn recv(&mut self) -> io::Result<(Bytes, SocketAddr)> {
        let mut buf = [0u8; MAX_PACKET_SIZE];

        let size = self.stream.read(&mut buf).await?;

        let bytes = Bytes::from(buf[0..size].to_vec());

        Ok((bytes, self.remote))
    }
}

struct UdpConn {
    socket: UdpSocket,
}

#[async_trait::async_trait]
impl ServerConn for UdpConn {
    async fn send(&mut self, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        let size = self.socket.send_to(buf, addr).await?;
        return if size != buf.len() {
            Err(io::Error::new(io::ErrorKind::Other, "Failed to write full message"))
        } else {
            Ok(())
        };
    }

    async fn recv(&mut self) -> io::Result<(Bytes, SocketAddr)> {
        let mut buf = [0u8; MAX_PACKET_SIZE];

        let (size, addr) = self.socket.recv_from(&mut buf).await?;

        let bytes = Bytes::from(buf[0..size].to_vec());

        Ok((bytes, addr))
    }
}
