use rugdns::{config::{self, Config, Sources}, dnstamp::{DNScryptResolver, DnsResolver, DoHResolver, StampConvert}, resolver::RugDnsResolver};
use hickory_proto::{op::Query, rr::RecordType};
use tokio::sync::RwLock;
use std::{collections::HashMap, sync::Arc};
use tracing::debug;

fn build_ip_query(domain: &str) -> Query {
    Query::query(domain.parse().unwrap(), RecordType::A)
}

fn test_config() -> Config {
    let mut servers = HashMap::new();
    servers.insert(
        String::from("alidns"),
        vec![String::from("sdns://AgAAAAAAAAAACTIyMy41LjUuNSCY49XlNq8pWM0vfxT3BO9KJ20l4zzWXy5l9eTycnwTMAkyMjMuNS41LjUKL2Rucy1xdWVyeQ")]
    );
    let sources = Sources {
        minisign_key: "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3".into(),
        public_resolvers: vec![
            "https://download.dnscrypt.info/dnscrypt-resolvers/v3/public-resolvers.md".into(),
            "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/refs/heads/master/v3/public-resolvers.md".into(),
            "https://cdn.jsdelivr.net/gh/DNSCrypt/dnscrypt-resolvers@master/v3/public-resolvers.md".into(),
        ],
        servers: Some(servers),
    };

    Config {
        bind: "127.0.0.1".parse().unwrap(),
        port: 8553,    // 这个端口才多个测试并行时可能被占用
        timeout_s: 5,
        sources,
        ..Default::default()
    }
}

#[tokio::test]
async fn with_bad_dnssec_resovler_and_config() {
    rugdns::init_tracing();

    let bad_doamin = "dnssec-failed.org";
    // alidns-doh do not support DNSSEC, so the following config is broken.
    // Resolving should fallback.
    let server = DoHResolver::build(
        0x1,  // DNSSEC
        Some("223.5.5.5".parse().unwrap()),
        Vec::new(),
        "223.5.5.5:443",
        "/dns-query",
        Vec::new()
    ).unwrap();

    let name = "alidns-doh".to_owned();
    let stamp = server.encode();
    let mut config = test_config();

    let servers = config.sources.servers.as_mut().unwrap();
    if let Some(v) = servers.get_mut(&name) {
        v.clear();
        v.push(stamp);
    } else {
        servers.insert(name, vec![stamp]);
    }

    let resolver = RugDnsResolver::init(Arc::new(RwLock::new(config))).await;
    let query = build_ip_query(bad_doamin);
    match resolver.resolve(query).await {
        _ => debug!("Test end.")
    };
}