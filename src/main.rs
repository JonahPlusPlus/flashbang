use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use argh::FromArgs;
use flashbang::server::{Server, config::ServerConfig, runtime::tokio_server::TokioServerRuntime};

#[derive(FromArgs)]
/// A STUN/TURN server.
struct ServerArgs {
    
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    let server_args: ServerArgs = argh::from_env();

    let running = Arc::new(AtomicBool::new(true));
    let running_handler = running.clone();

    ctrlc::set_handler(move || {
        running_handler.store(false, Ordering::Relaxed);
    }).expect("Error setting Ctrl-C handler");

    let config = ServerConfig {

    };

    let mut server: Server<TokioServerRuntime> = Server::new(running, config);
    
    server.run().await;

    log::info!("Shutdown gracefully");
}
