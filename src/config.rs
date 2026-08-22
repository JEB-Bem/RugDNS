use minisign_verify::{PublicKey, Signature};
use anyhow::Result;
use std::{collections::HashMap, net::IpAddr};
use tracing::{info, debug, warn, error};
use serde::{Deserialize, Serialize};
use tokio::{fs, task::JoinSet, sync::RwLock};
use std::sync::Arc;
use std::{env, path::PathBuf, ffi::OsString};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub bind: IpAddr,
    pub port: u16,
    pub timeout_s: u8,
    pub sources: Sources,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Sources {
    pub minisign_key: String,
    pub public_resolvers: Vec<String>,
    pub servers: Option<HashMap<String, Vec<String>>>,
}

fn cache_dir() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("CACHE_DIRECTORY") {
        return Some(PathBuf::from(path));
    }

    dirs::cache_dir().map(|p| p.join("rugdns"))
}

/// Download file from the specified url. (System proxies will be set from
/// environment variables.)
async fn download_file(url: &str) -> Result<String> {
    Ok(reqwest::get(url).await?.error_for_status()?.text().await?)
}

async fn fetch_file(url: &str, pk: &str) -> (String, String) {
    let content = download_file(url).await.unwrap();
    let content_sig = download_file(&format!("{url}.minisig")).await.unwrap();

    let public_key = PublicKey::from_base64(pk).unwrap();
    let sign = Signature::decode(&content_sig).unwrap();
    let bytes = content.into_bytes();

    debug!("Verifying {url}");
    public_key.verify(&bytes, &sign, true).unwrap();
    debug!("{url} verified");
    (String::from_utf8(bytes).unwrap(), content_sig)
}

async fn load_file(mut path: OsString, pk: &str) -> (String, String) {
    debug!("load resolvers: {path:?}");
    let content = fs::read_to_string(&path).await.unwrap();

    path.push(".minisig");
    debug!("load resolvers sign: {path:?}");
    let content_sig = fs::read_to_string(PathBuf::from(&path)).await.unwrap();

    let public_key = PublicKey::from_base64(pk).unwrap();
    let sign = Signature::decode(&content_sig).unwrap();
    let bytes = content.into_bytes();

    debug!("Verifying {path:?}");
    public_key.verify(&bytes, &sign, true).unwrap();
    debug!("{path:?} verified");
    (String::from_utf8(bytes).unwrap(), content_sig)
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

    let cache_dir = cache_dir().unwrap();
    let (content, content_sig) = loop {
        match set.join_next().await {
            Some(Ok(value)) => break value,
            Some(Err(err)) => {
                warn!("Task failed: {err}");
            }
            None => {
                error!("All downloading tasks failed");
                info!("Try load cached files.");
                break load_file(
                    cache_dir.join("resolvers.md").as_os_str().to_os_string(),
                    &pk
                ).await
            }
        }
    };
    
    fs::create_dir_all(&cache_dir).await.expect(&format!("create cache dir: {cache_dir:?}"));
    fs::write(cache_dir.join("resolvers.md"), &content).await.expect(
        "write resolvers"
    );
    fs::write(&cache_dir.join("resolvers.md.minisig"), &content_sig).await.expect(
        "write resolvers' minisig"
    );

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
        if std::fs::exists(path).unwrap() {
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
    let content = fs::read_to_string(path).await.expect("read config");

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
    async fn test_cache_file() {
        crate::init_tracing();
        unsafe { env::set_var("CACHE_DIRECTORY", "/tmp/rugdns") };
        let cache_dir = cache_dir().unwrap();
        assert_eq!(cache_dir, PathBuf::from("/tmp/rugdns"));
        let _ = fs::remove_dir_all(&cache_dir).await;
        fetch_resolvers(
            vec!["https://download.dnscrypt.info/dnscrypt-resolvers/v3/public-resolvers.md".into()],
            "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3".into(),
            &mut HashMap::<String, Vec<String>>::new()
        ).await.expect("fetch resolvers");
        
        assert!(std::fs::exists(cache_dir).unwrap());

        let mut map = HashMap::<String, Vec<String>>::new();
        fetch_resolvers(
            vec![],
            "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3".into(),
            &mut map,
        ).await.expect("fetch resolvers");
        assert!(map.get("alidns-doh").is_some());
    }
}
