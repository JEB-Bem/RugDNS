use crate::{config::Config, dnstamp::{self, DnsResolver}};
use hickory_client::client::{DnssecClient, Client};
use hickory_proto::{
    h2::{HttpsClientStream, HttpsClientStreamBuilder},
    op::Query,
    runtime::TokioRuntimeProvider,
    rustls as hickory_rustls,
    xfer::{DnsHandle, DnsRequest, DnsRequestOptions, DnsResponse, FirstAnswer},
    ProtoError,
    ProtoErrorKind,
};
use tokio::{
    sync::RwLock,
    task::JoinHandle,
    time::{self, Duration},
};
use futures_util::stream::Stream;
use std::{collections::HashMap, ops::Deref, pin::Pin, sync::Arc};
use std::net::SocketAddr;
use tracing::{debug, info, warn, error};
use anyhow::{Result, anyhow};

#[derive(Clone)]
enum RugClient {
    Client(Client),
    SecClient(DnssecClient),
}

struct State {
    client: RugClient,
    bg_handle: JoinHandle<Result<(), ProtoError>>,
    resolver: DnsResolver,
    score: u32,
}

pub struct RugDnsResolver {
    config: Arc<RwLock<Config>>,
    state: RwLock<State>,
    options: DnsRequestOptions,
}

impl DnsHandle for RugClient {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send + 'static>>;
    fn is_verifying_dnssec(&self) -> bool {
        match self {
            RugClient::Client(client)    => client.is_verifying_dnssec(),
            RugClient::SecClient(client) => client.is_verifying_dnssec(),
        }
    }
    
    fn is_using_edns(&self) -> bool {
        match self {
            RugClient::Client(client)    => client.is_using_edns(),
            RugClient::SecClient(client) => client.is_using_edns(),
        }
    }
    
    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&self, request: R) -> Self::Response {
        let request = request.into();

        match self {
            RugClient::Client(client)    => Box::pin(client.send(request)),
            RugClient::SecClient(client) => client.send(request),
        }
    }
}

impl RugDnsResolver {
    /// Constructs a new DNS Resolver
    pub async fn init(config: Arc<RwLock<Config>>) -> Self {
        // Options Initialization
        let mut options = DnsRequestOptions::default();
        options.use_edns = true;
        options.edns_set_dnssec_ok = true;
        options.max_request_depth = 26;
        options.recursion_desired = true;
        // options.case_randomization = true;

        // Client Initialization
        let state = RwLock::new(Self::new_doh_stream(
            &config.read().await.sources.servers, "alidns-doh"
        ).await);

        Self {
            config,
            state,
            options,
        }
    }
    
    async fn new_doh_stream(servers: &Option<HashMap<String, Vec<String>>>, name: &str) -> State {
        let info = &servers
            .as_ref()
            .unwrap()
            .get(name)
            .expect("server {name} not found")[0];
        warn!("Temporary implementation.");
        let resolver = match dnstamp::parse_stamp(info).expect("create a doh stream") {
            DnsResolver::DNScrypt(_) => {
                panic!("Unexpected dnstamp: {info}");
            },
            DnsResolver::DoH(t) => t,
        };
        let host = match resolver.host() {
            dnstamp::Host::Ip(ip) => ip.to_string(),
            dnstamp::Host::Domain(domain) => domain.to_owned(),
        };

        let provider = TokioRuntimeProvider::default();
        let stream_builder = HttpsClientStreamBuilder::with_client_config(
            Arc::new(hickory_rustls::client_config()),
            provider
        );

        let stream = stream_builder.build(
            SocketAddr::new(
                resolver.addr().expect("unimplemented"), resolver.port()
            ),
            host,
            resolver.path().into()
        );
        if resolver.props() & 0x1 == 0x1 {
            // The resolver support DNSSEC
            let (client, bg) = DnssecClient::connect(stream).await.expect(&format!("connect with {:?}", resolver.host()));
            info!("Client built with target: {}", resolver.host());

            let bg_handle = tokio::spawn(bg);
            State {
                client: RugClient::SecClient(client),
                bg_handle,
                resolver: DnsResolver::DoH(resolver),
                score: 1000,
            }
        } else {
            // The resovler do not support DNSSEC
            let (client, bg) = Client::connect(stream).await.expect(&format!("connect with {:?}", resolver.host()));
            info!("Client built with target: {}", resolver.host());

            let bg_handle = tokio::spawn(bg);
            State {
                client: RugClient::Client(client),
                bg_handle,
                resolver: DnsResolver::DoH(resolver),
                score: 1000,
            }
        }
    }
    
    pub async fn reconn_doh(&self) {
        warn!("http2 connection dead, need a new one.");
        let mut state = self.state.write().await;
        let resolver = match &state.resolver {
            DnsResolver::DNScrypt(_) => {
                unimplemented!();
            },
            DnsResolver::DoH(t) => t,
        };
        let host = match resolver.host() {
            dnstamp::Host::Ip(ip) => ip.to_string(),
            dnstamp::Host::Domain(domain) => domain.to_owned(),
        };

        let provider = TokioRuntimeProvider::default();
        let stream_builder = HttpsClientStreamBuilder::with_client_config(
            Arc::new(hickory_rustls::client_config()),
            provider
        );
        let stream = stream_builder.build(
            SocketAddr::new(
                resolver.addr().expect("unimplemented"), resolver.port()
            ),
            host,
            resolver.path().into()
        );
        if resolver.props() & 0x1 == 0x1 {
            // Support DNSSEC
            let (client, bg) = DnssecClient::connect(stream).await.expect(&format!("connect with {:?}", resolver.host()));
            let bg_handle = tokio::spawn(bg);
            state.client = RugClient::SecClient(client);
            state.bg_handle = bg_handle;
        } else {
            // DO NOT support DNSSEC
            let (client, bg) = Client::connect(stream).await.expect(&format!("connect with {:?}", resolver.host()));
            let bg_handle = tokio::spawn(bg);
            state.client = RugClient::Client(client);
            state.bg_handle = bg_handle;
        }
    }
    
    pub async fn reconn_if_unhealthy(&self) {
        if self.state.read().await.bg_handle.is_finished() {
            self.reconn_doh().await;
        }
    }
    
    async fn lookup(&self, query: Query) -> Result<DnsResponse, ProtoError> {
        debug!("Received query: {query:?}");
        self.reconn_if_unhealthy().await;
        self.state.read().await.client.lookup(query, self.options).first_answer().await
    }
    
    /// A *classic* DNS query
    pub async fn resolve(&self, query: Query) -> Result<DnsResponse, ProtoError> {
        let seconds = self.config.read().await.timeout_s / 5 * 3;
            
        // TODO: Retry with customed times
        for _ in 0..3 {
            match if seconds == 0 {
                self.lookup(query.clone()).await
            } else {
                let t = Duration::from_secs(seconds as u64);
                time::timeout(t, self.lookup(query.clone())).await.expect("lookup")
            } {
                Ok(resp) => return Ok(resp),
                Err(err) => self.handle_err(err).await?,
            };
        }
        unimplemented!()
    }
    
    async fn handle_err(&self, err: ProtoError) -> Result<(), ProtoError> {
        match err.kind.deref() {
            ProtoErrorKind::BadQueryCount(_) => return Err(err.into()),
            _ => self.reconn_doh().await,
        };
        Ok(())
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
        let msg = resolver.resolve(query).await.unwrap().into_message();
        assert_eq!(msg.answer_count(), 2);
        let answers = msg.answers();
        dbg!(answers);
        // assert_eq!(answers[1].name().to_lowercase(), Name::from_str(&cname).unwrap());
        // assert_eq!(answers[1].data(), &RData::A(ip.parse().unwrap()));
    }
    
    // TODO: 通过修改头里面的是否进行 DNSSEC 验证和是否在失败后仍然传输数据等选项，
    // 验证 Rug DNS 会正确的处理这些 flags
}