use crate::config::Config;
use hickory_client::client::DnssecClient;
use hickory_proto::{
    h2::{HttpsClientStream, HttpsClientStreamBuilder},
    op::Query,
    runtime::TokioRuntimeProvider,
    rustls as hickory_rustls,
    xfer::{DnsHandle, DnsRequestOptions, DnsResponse, FirstAnswer},
};
use rustls::ClientConfig;
use tokio::sync::RwLock;
use std::sync::Arc;
use tracing::{debug, info};
use anyhow::Result;

pub struct RugDnsResolver {
    config: Arc<RwLock<Config>>,
    client: DnssecClient,
    options: DnsRequestOptions,
}

impl RugDnsResolver {
    /// Constructs a new DNS Resolver
    pub async fn init(config: Arc<RwLock<Config>>) -> Self {
        let mut options = DnsRequestOptions::default();
        options.use_edns = true;
        options.edns_set_dnssec_ok = true;
        options.max_request_depth = 26;
        options.recursion_desired = true;
        // options.case_randomization = true;
        let provider = TokioRuntimeProvider::default();
        let stream_builder = HttpsClientStreamBuilder::with_client_config(
            Arc::new(hickory_rustls::client_config()),
            provider
        );
        let conn = stream_builder.build(
            "223.5.5.5:443".parse().unwrap(),
            "223.5.5.5".into(),
            "/dns-query".into()
        );
        let (client, bg) = DnssecClient::connect(conn).await.expect("connect with 223.5.5.5:443");
        info!("Client built with target: 233.5.5.5");
        tokio::spawn(bg);

        Self {
            config,
            client,
            options,
        }
    }
    
    /// A *classic* DNS query
    pub async fn lookup(&self, query: Query) -> Result<DnsResponse> {
        // TODO: implement proxy.
        // TODO: add dns cache feature.
        debug!("Received query: {query:?}");
        Ok(self.client.lookup(query, self.options).first_answer().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use std::str::FromStr;
    use tokio::process::Command;
    use hickory_proto::{op::Message, rr::{Name, RecordType, RData}};

    async fn fetch_simple_case_data() -> (&'static str, String, String){
        let domain = "fanyi.baidu.com.";
        let mut dig = Command::new("dig");
        dig.args(&["@223.5.5.5", "+https", "+short", domain]);
        let output = dig.output().await.unwrap().stdout;
        let mut lines = str::from_utf8(&output).unwrap().lines();

        (domain, lines.next().unwrap().into(), lines.next().unwrap().into())
    }
    
    #[tokio::test]
    async fn test_lookup_a() {
        crate::init_tracing();
        let config = config::init_config(None).await;
        let resolver = RugDnsResolver::init(config).await;
        let (domain, cname, ip) = fetch_simple_case_data().await;
        debug!("Result of `{domain}` - cname: {cname}, ip:{ip}");

        let query = Query::query(Name::from_str(domain).unwrap(), RecordType::A);
        let msg = resolver.lookup(query).await.unwrap().into_message();
        assert_eq!(msg.answer_count(), 2);
        let answers = msg.answers();
        dbg!(answers);
        assert_eq!(answers[1].name().to_lowercase(), Name::from_str(&cname).unwrap());
        assert_eq!(answers[1].data(), &RData::A(ip.parse().unwrap()));
    }
    
    // TODO: 通过修改头里面的是否进行 DNSSEC 验证和是否在失败后仍然传输数据等选项，
    // 验证 Rug DNS 会正确的处理这些 flags
}