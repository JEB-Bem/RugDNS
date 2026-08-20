mod rug_dns_handler;
mod rug_dns_resolver;
mod dnstamp;
mod config;

use hickory_server::ServerFuture;
use tokio::net::UdpSocket;
use rug_dns_handler::RugDnsHandler;
use rug_dns_resolver::RugDnsResolver;
use tracing::{info};
use tracing_subscriber::EnvFilter;

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_test_writer()
        .try_init();
}

#[tokio::main]
async fn main() {
    init_tracing();
    info!("Running RugDns Server v{} (hickory server {})", env!("CARGO_PKG_VERSION"), hickory_server::version());

    let config = config::init_config(None).await;

    let host_port = {
        let config_guard = config.read().await;
        format!("{}:{}", config_guard.bind, config_guard.port)
    };
    let socket  = UdpSocket::bind(&host_port).await.expect(&format!("binding listener to {}", host_port));
    info!("Bind on {}", host_port);

    let resolver = RugDnsResolver::init(config.clone()).await;
    let handler = RugDnsHandler::new(config.clone(), resolver);
    let mut server  = ServerFuture::new(handler);

    server.register_socket(socket);
    server.block_until_done().await.expect("running error");
}
