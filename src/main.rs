use hickory_server::ServerFuture;
use rugdns::{config, handler::RugDnsHandler, resolver::RugDnsResolver};
use tokio::net::UdpSocket;
use tracing::info;

#[tokio::main]
async fn main() {
    rugdns::init_tracing();
    info!(
        "Running RugDns Server v{} (hickory server {})",
        env!("CARGO_PKG_VERSION"),
        hickory_server::version()
    );

    let config = config::init_config(None).await;

    let host_port = format!("{}:{}", config.bind, config.port);
    let socket =
        UdpSocket::bind(&host_port).await.expect(&format!("binding listener to {}", host_port));
    info!("Bind on {}", host_port);

    let resolver = RugDnsResolver::init(&config).await;
    let handler = RugDnsHandler::new(config, resolver);
    let mut server = ServerFuture::new(handler);

    server.register_socket(socket);
    server.block_until_done().await.expect("running error");
}
