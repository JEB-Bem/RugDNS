use minisign_verify::{PublicKey, Signature};
use anyhow::Result;
use std::{collections::HashMap, fs, net::IpAddr};
use tracing::{info, debug, warn};
use serde::{Deserialize, Serialize};
use tokio::{task::JoinSet, sync::RwLock};
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub bind: IpAddr,
    pub port: u16,
    pub sources: Sources,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Sources {
    pub minisign_key: String,
    pub public_resolvers: Vec<String>,
    pub servers: Option<HashMap<String, Vec<String>>>,
}

/// Download file from the specified url. (System proxies will be set from
/// environment variables.)
async fn download_file(url: &str) -> Result<String> {
    Ok(reqwest::get(url).await?.error_for_status()?.text().await?)
}

async fn fetch_file(url: &str, pk: &str) -> String {
    let content = download_file(url).await.unwrap();
    let public_key = PublicKey::from_base64(pk).unwrap();
    let sign = Signature::decode(
        &download_file(&format!("{url}.minisig")
    ).await.unwrap()).unwrap();
    let bytes = content.into_bytes();
    debug!("Verifying {url}");
    public_key.verify(&bytes, &sign, true).unwrap();
    debug!("{url} verified");
    String::from_utf8(bytes).unwrap()
}

async fn fetch_resolvers(
    urls: Vec<String>,
    pk: String,
    servers: &mut HashMap<String, Vec<String>>
) -> Result<()> {
    let mut set = JoinSet::new();

    for url in urls {
        let pk_clone = pk.clone();
        set.spawn(async move {
            fetch_file(&url, &pk_clone).await
        });
    }

    let content = loop {
        match set.join_next().await {
            Some(Ok(value)) => break value,
            Some(Err(err)) => {
                warn!("task failed: {err}");
            }
            None => {
                anyhow::bail!("all tasks failed");
            }
        }
    };

    let mut server_name = String::new();
    for line in content.lines() {
        if let Some(name) = line.strip_prefix("## ") {
            server_name = name.trim().to_owned();
        } else if line.starts_with("sdns://") {
            if server_name.is_empty() {
                panic!("found 'sdns://' before `server_name`");
            }
            servers
                .entry(server_name.clone())
                .or_default()
                .push(line.trim().to_owned())
        }
    }

    set.abort_all();

    Ok(())
}

fn find_config() -> Option<&'static str> {
    const PATHES: [&str; 3] = [
        "./config.toml", "~/.config/rugdns/config.toml", "/etc/rugdns/config.toml"
    ];
    for path in PATHES {
        if fs::exists(path).unwrap() {
            return Some(path);
        }
    }
    None
}

/// Read Configuration File, then initialize the public resolvers configurations
pub async fn init_config(path: Option<&str>) -> Arc<RwLock<Config>> {
    // Read Configuration
    let path =
        if let Some(path) = path { path }
        else if let Some(path) = find_config(){ path }
        else { panic!("no `config.toml` found."); };

    debug!("Reading configurations from '{path}.'");
    let content = fs::read_to_string(path).expect("read config");

    debug!("Parsing configurations...");
    let mut config: Config = toml::from_str(&content).expect("parse config from toml");

    debug!("Parsing DNS Servers...");

    let servers = config.sources.servers.get_or_insert_with(HashMap::new);
    let urls = config.sources.public_resolvers.clone();
    let pk = config.sources.minisign_key.clone();
    if let Err(e) = fetch_resolvers(urls, pk, servers).await {
        warn!("{}", e.to_string());
    }

    if servers.is_empty() {
        panic!("no resolver servers configurations found");
    }

    Arc::new(RwLock::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_file() {
        crate::init_tracing();
        fetch_file(
            "https://download.dnscrypt.info/dnscrypt-resolvers/v3/public-resolvers.md",
            "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"
        ).await;
    }

    #[tokio::test]
    async fn test_init_config() {
        crate::init_tracing();
        let mut config = init_config(None).await;
    }

}
