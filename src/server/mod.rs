use std::marker::PhantomData;
use std::sync::{Arc, atomic::AtomicBool};

use self::config::ServerConfig;
use self::runtime::{ServerRuntime, ServerRunner};

pub mod config;
pub mod runtime;

/// The STUN server.
/// 
/// Runs on ports 3478 (stun) and 5349 (stuns).
#[derive(Default)]
pub struct Server<R: ServerRuntime> {
    running: Arc<AtomicBool>,
    config: ServerConfig,
    _marker: PhantomData<R>,
}

impl<R: ServerRuntime> Server<R> {
    pub fn new(running: Arc<AtomicBool>, config: ServerConfig) -> Self {
        Self {
            running,
            config,
            _marker: PhantomData,
        }
    }

    pub async fn run(&mut self) {
        let runner = ServerRunner {
            running: self.running.clone(),
            config: self.config,
        };

        R::run(runner).await;
    }
}
