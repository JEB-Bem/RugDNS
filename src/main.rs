mod rug_dns_handler;
mod rug_dns_resolver;
mod dnstamp;
mod config;

use hickory_server::{Server};
use tokio::net::UdpSocket;
use rug_dns_handler::RugDnsHandler;
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

    let handler = RugDnsHandler::new(&config);
    let mut server  = Server::new(handler);
    let socket  = UdpSocket::bind("127.0.0.1:8553").await.expect("binding listener to 127.0.0.1:8553");
    dbg!(&socket);
    info!("Bind on 127.0.0.1:8553");

    server.register_socket(socket);

    server.block_until_done().await.expect("running error");
}
