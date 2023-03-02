use std::{io, sync::{Arc, Mutex, atomic::AtomicBool}, task::{Poll, Waker}, time::{Instant, Duration}, net::SocketAddr};

use std::future::Future;

use bytes::Bytes;

use super::config::ServerConfig;

pub mod tokio_server;

/// Port number for unsecured TCP/UDP ("stun" scheme).
pub const INSECURE_PORT: u16 = 3478;

/// Port number for secured TLS/DTLS ("stuns" scheme).
pub const SECURE_PORT: u16 = 5349;

#[derive(Clone)]
pub struct ServerRunner {
    pub running: Arc<AtomicBool>,
    pub config: ServerConfig,
}

#[async_trait::async_trait]
pub trait ServerRuntime: Send + Sync {
    async fn run(runner: ServerRunner);
}

#[async_trait::async_trait]
pub trait ServerConn {
    async fn send(&mut self, buf: &[u8], addr: SocketAddr) -> io::Result<()>;

    async fn recv(&mut self) -> io::Result<(Bytes, SocketAddr)>;
}

pub struct ServerProcessor<T: ServerConn> {
    conn: T,
}

impl<T: ServerConn> ServerProcessor<T> {
    pub fn new(conn: T) -> Self {
        Self {
            conn
        }
    }

    pub fn process(&self) {
        
    }
}