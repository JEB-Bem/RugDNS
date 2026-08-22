use hickory_server::ServerFuture;
use rugdns::handler::RugDnsHandler;
use rugdns::resolver::RugDnsResolver;
use rugdns::config;
use tokio::net::UdpSocket;
use tracing::{info};

#[tokio::main]
async fn main() {
    rugdns::init_tracing();
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
