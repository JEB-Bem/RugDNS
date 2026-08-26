use std::{
    collections::{BTreeSet, HashMap},
    io::ErrorKind::AddrNotAvailable,
    net::SocketAddr,
    ops::Deref,
    pin::Pin,
    sync::Arc,
};

use anyhow::{Result, bail};
use futures::future::join_all;
use futures_util::stream::Stream;
use hickory_client::client::{Client, DnssecClient};
use hickory_proto::{
    ProtoError, ProtoErrorKind,
    h2::HttpsClientStreamBuilder,
    op::Query,
    runtime::TokioRuntimeProvider,
    rustls as hickory_rustls,
    udp::UdpClientStream,
    xfer::{DnsHandle, DnsRequest, DnsRequestOptions, DnsRequestSender, DnsResponse, FirstAnswer},
};
use rand;
use tokio::{
    sync::RwLock,
    task::JoinHandle,
    time::{self, Duration},
};
use tracing::{debug, error, info, warn};

use crate::{
    config::Config,
    dnstamp::{self, DNScryptResolver, DnsResolver, DoHResolver, Host, PlainResolver},
};

#[derive(Clone)]
enum RugClient {
    Client(Client),
    SecClient(DnssecClient),
}

/// Track a Resolver's state, including connection health and the information
/// needed to rebuild the network connection.
struct State {
    client:    RugClient,
    // It may be used in the future.
    bg_handle: JoinHandle<Result<(), ProtoError>>,
    resolver:  DnsResolver,
    health:    bool,
    // to locate the Item
    score:     u32,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
struct Item {
    score: u32,
    ind:   usize,
}

#[derive(Debug, Default)]
struct Rank {
    clients:     RwLock<BTreeSet<Item>>,
    dnseclients: RwLock<BTreeSet<Item>>,
}

struct Resolvers {
    rank:    Rank,
    states:  Vec<RwLock<State>>,
    is_dhcp: bool,
}

pub struct RugDnsResolver {
    // config: Arc<Config>,
    proxy_resolvers:   Resolvers,
    direct_resolvers:  Resolvers,
    default_resolvers: Resolvers,
    dhcp_resolvers:    Resolvers,
    timeout:           Duration,
    para_num:          u8,
}

impl DnsHandle for RugClient {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send + 'static>>;

    fn is_verifying_dnssec(&self) -> bool {
        match self {
            RugClient::Client(client) => client.is_verifying_dnssec(),
            RugClient::SecClient(client) => client.is_verifying_dnssec(),
        }
    }

    fn is_using_edns(&self) -> bool {
        match self {
            RugClient::Client(client) => client.is_using_edns(),
            RugClient::SecClient(client) => client.is_using_edns(),
        }
    }

    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&self, request: R) -> Self::Response {
        let request = request.into();

        match self {
            RugClient::Client(client) => Box::pin(client.send(request)),
            RugClient::SecClient(client) => client.send(request),
        }
    }
}

impl State {
    pub async fn lookup(&self, query: Query) -> Result<DnsResponse, ProtoError> {
        debug!("Received query: {query:?}");
        let mut options = DnsRequestOptions::default();
        options.use_edns = true;
        options.edns_set_dnssec_ok = true;
        options.max_request_depth = 26;
        options.recursion_desired = true;
        // options.case_randomization = true;

        self.client.lookup(query, options).first_answer().await
    }
}

impl Resolvers {
    /// Construct a Resolvers use giving server names and servers sources list.
    /// The `is_dhcp` field will be defaultly set to false.
    pub async fn init(
        server_names: &Vec<String>,
        servers: &Option<HashMap<String, Vec<String>>>,
        mut timeout: Duration,
    ) -> Self {
        // - A item in `server_names` can be either an IP such us '223.5.5.5' or a server name
        //   defined in the server souces list, such as 'google'.
        // - There is a simple sketch below. 'timeout' means this task would be executed by
        //   `time::timeout` with argument `timeout`
        //
        //                   ┌───►223.5.5.5
        //                   │   timeout     ┌──────►dns_stamp1(timeout)
        //                   │               │
        // server_names──────┼───►google─────┼──────►dns_stamp2(timeout)
        //                   │   timeout     │
        //                   │               └──────►dns_stamp3(timeout)
        //                   └───►alidns-doh─────┐
        //                       timeout         │
        //                                       └────► ...
        //
        // Add a lock so we can initialize all DNS stamps concurrently.
        let states = Arc::new(RwLock::new(Vec::new()));
        let rank = Arc::new(Rank::default());
        if timeout.is_zero() {
            timeout = Duration::from_secs(60);
        }

        // Concurrently initialize server names on a single thread.
        join_all(server_names.into_iter().map(|name| {
            time::timeout(
                timeout,
                Self::add_server_states(name, servers, states.clone(), rank.clone(), timeout),
            )
        }))
        .await;

        // Remove the lock.
        let rwlock = Arc::into_inner(states).unwrap();
        let states = rwlock.into_inner();
        let rank = Arc::into_inner(rank).unwrap();

        Self { states, rank, is_dhcp: false }
    }

    pub async fn dhcp_init() -> Self {
        unimplemented!();
    }

    pub async fn resolve(
        &self,
        query: Query,
        timeout: Duration,
        para_num: u8,
    ) -> Result<Result<DnsResponse, ProtoError>> {
        // TODO: do more about the result
        debug!("Resolving {:?}", query);
        let (sec_res, res) = tokio::join!(
            self.clients_resolve(query.clone(), timeout, para_num, &self.rank.dnseclients),
            self.clients_resolve(query.clone(), timeout, para_num, &self.rank.clients),
        );

        if let Ok(res) = sec_res {
            Ok(res)
        } else if let Ok(res) = res {
            // TODO: need more argument to handle the DNSSEC options.
            Ok(res)
        } else {
            bail!("all resoling tasks failed");
        }
    }

    pub async fn clients_resolve(
        &self,
        query: Query,
        timeout: Duration,
        para_num: u8,
        clients: &RwLock<BTreeSet<Item>>,
    ) -> Result<Result<DnsResponse, ProtoError>> {
        assert!(para_num > 0);

        if self.states.len() == 0 {
            info!("No resolver in the Resolvers, skipping...");
            bail!("No resolver in the Resolvers");
        }
        let availables = Arc::new(RwLock::new(Self::get_available(clients, para_num).await));
        let results = join_all((0..para_num).map(|task_id| {
            let availables = availables.clone();
            let query = query.clone();
            async move {
                debug!("#{task_id} task begin");
                let ind = if let Some(ind) = self.take_healthy_available(availables).await {
                    ind
                } else {
                    bail!("no available resolver");
                };
                let state = self.states[ind].write().await;
                let dnssec_tag =
                    if state.resolver.props() & 0x01 == 0x01 { "DNSSEC" } else { "NON-DNSSEC" };

                debug!("#{dnssec_tag}{task_id} Resovling with {:?}", state.resolver);
                match if timeout.is_zero() {
                    // No limit.
                    let resp = state.lookup(query.clone()).await;
                    drop(state); // release the write lock.
                    resp
                } else {
                    let resp = if let Ok(value) =
                        time::timeout(timeout, state.lookup(query.clone())).await
                    {
                        value
                    } else {
                        // Time out.
                        debug!(
                            "#{dnssec_tag}{task_id} Timeout while resolving with {:?}",
                            state.resolver
                        );
                        bail!("resolver lookup timed out.");
                    };
                    drop(state); // release the write lock.
                    resp
                } {
                    Ok(resp) => {
                        debug!("#{dnssec_tag}{task_id} Result: {resp:?}");
                        self.update_score(ind, true).await;
                        debug!("#{dnssec_tag}{task_id} Score updated.");
                        return Ok(Ok(resp));
                    }
                    Err(err) => {
                        // TODO: If DO flag didn't set, Nsec Error could be
                        // ignored.
                        debug!("#{dnssec_tag}{task_id} Got Error: {err}");
                        match self.handle_err(err, ind, timeout).await {
                            Ok(err) => Ok(Err(err)),
                            Err(err) => Err(err),
                        }
                    }
                }
            }
        }))
        .await;

        for res in results {
            if let Ok(resp) = res {
                debug!("One group got result: {resp:?}");
                return Ok(resp);
            }
        }

        bail!("all lookuping tasks are failed or skipped");
    }

    async fn get_available(clients: &RwLock<BTreeSet<Item>>, para_num: u8) -> Vec<usize> {
        let clients = clients.read().await;
        let mut inds = Vec::with_capacity(para_num as usize);
        for item in clients.iter().rev() {
            if item.score < 1000 && inds.len() >= para_num as usize {
                break;
            }
            inds.push(item.ind);
        }
        inds
    }

    async fn take_healthy_available(&self, availables: Arc<RwLock<Vec<usize>>>) -> Option<usize> {
        loop {
            let ind = {
                let mut availables = availables.write().await;
                let len = availables.len();
                if len == 0 {
                    return None;
                }
                let i = rand::random_range(0..len);
                availables.swap_remove(i)
            };
            if let Some(state) = self.states.get(ind) {
                if state.read().await.health {
                    return Some(ind);
                } else {
                    continue;
                }
            } else {
                error!("Unexpected `index out of boundary` error.");
                return None;
            }
        }
    }

    async fn add_server_states(
        name: &String,
        servers: &Option<HashMap<String, Vec<String>>>,
        states: Arc<RwLock<Vec<RwLock<State>>>>,
        rank: Arc<Rank>,
        timeout: Duration,
    ) {
        // If `name` is a simple ip such as `223.5.5.5`.
        if let Some((host, port)) = dnstamp::split_hostname(name) {
            debug!("A simple ip server: {name}");
            match host {
                Host::Domain(_) => {
                    warn!("Found wrong config of Resovler-Server-Names: {name}");
                }
                Host::Ip(ip) => {
                    let resolver = DnsResolver::Plain(PlainResolver::build(0, ip, port).unwrap());
                    Self::add_state_with_resolver(resolver, states, rank).await;
                }
            }
            return;
        } // Or a DNS Stamp.

        debug!("Parsing a set of dnstamps for {name}");

        // Concurrently initialize server names on a single thread.
        let stamps = servers.as_ref().unwrap().get(name).expect("server {name} not found");
        join_all(stamps.into_iter().map(|stamp| {
            debug!("Parsing {stamp}");
            let states = states.clone();
            let rank = rank.clone();
            time::timeout(timeout, async move {
                let resolver = if let Some(v) = dnstamp::parse_stamp(stamp) {
                    v
                } else {
                    warn!("Dnstamp: '{stamp}' is invalid");
                    return;
                };
                Self::add_state_with_resolver(resolver, states, rank).await
            })
        }))
        .await;
    }

    async fn add_state_with_resolver(
        resolver: DnsResolver,
        states: Arc<RwLock<Vec<RwLock<State>>>>,
        rank: Arc<Rank>,
    ) {
        let score = 1000;
        let state = match Self::new_state(resolver, score).await {
            Ok(v) => v,
            Err(err) => {
                warn!("Create a resolver: {err}");
                return;
            }
        };

        let mut clients = match state.client {
            RugClient::Client(_) => rank.clients.write().await,
            RugClient::SecClient(_) => rank.dnseclients.write().await,
        };
        let mut states = states.write().await;
        let ind = states.len();
        clients.insert(Item { score, ind });
        // FIXME: If time out at this line?
        states.push(RwLock::new(state));
    }

    async fn handle_err(
        &self,
        err: ProtoError,
        ind: usize,
        timeout: Duration,
    ) -> Result<ProtoError> {
        warn!("Client Lookup Error: {err}");
        match err.kind.deref() {
            ProtoErrorKind::Busy => {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                self.reconn(ind, timeout).await;
                bail!("Network busy, task failed");
            }
            ProtoErrorKind::DnsKeyProtocolNot3(_) | ProtoErrorKind::RustlsError(_) => {
                self.update_score(ind, false).await;
                bail!("Unexpected errors, task failed");
            }
            // Try handle these errors by reconnecting to upstream. => Reconn
            ProtoErrorKind::Canceled(_)
            | ProtoErrorKind::Message(_)
            | ProtoErrorKind::Msg(_)
            | ProtoErrorKind::NoConnections
            | ProtoErrorKind::Io(_)
            | ProtoErrorKind::RequestRefused => {
                self.reconn(ind, timeout).await;
                bail!("Upstream Error, task failed.");
            }
            // Errors caused by external callers should be propagated unchanged.
            _ => {
                self.update_score(ind, true).await;
                return Ok(err);
            }
        };
    }

    async fn reconn(&self, ind: usize, timeout: Duration) {
        let state = &self.states[ind];
        // Prevent other tasks from blocking?
        let (resolver, score, new_score) = {
            let mut state = state.write().await;
            state.health = false;
            let score = state.score;
            let new_score = if score < 100 { 0 } else { score - 100 };
            state.score = new_score;
            (state.resolver.clone(), score, new_score)
        };
        let resolver_debug = format!("{:?}", resolver);
        debug!("Reconnect with {resolver_debug}");

        let mut clients_rank = match state.read().await.client {
            RugClient::Client(_) => self.rank.clients.write().await,
            RugClient::SecClient(_) => self.rank.dnseclients.write().await,
        };
        clients_rank.remove(&Item { score, ind });
        clients_rank.insert(Item { score: new_score, ind });

        match time::timeout(timeout, Self::new_state(resolver, score)).await {
            Ok(v) => match v {
                Ok(v) => {
                    let State { client, bg_handle, .. } = v;
                    let mut state = state.write().await;
                    state.client = client;
                    state.bg_handle = bg_handle;
                    state.health = true;
                }
                Err(err) => {
                    error!("Reconnect with {resolver_debug}: {err}");
                }
            },
            Err(err) => error!("Reconnect with {resolver_debug}: {err}"),
        };
    }

    // Note: The score is also updated in `reconn`.
    async fn update_score(&self, ind: usize, success: bool) {
        let state = &self.states[ind];
        let (score, new_score) = if success {
            debug!("Success! Updating score...");
            debug!("Acquiring write lock of states[{ind}]");
            let mut state = state.write().await;
            let score = state.score;
            let new_score = if score < 1000 { 1000 } else { score + 100 };
            state.score = new_score;
            (score, new_score)
        } else {
            debug!("Failed. Updating score...");
            debug!("Acquiring write lock of states[{ind}]");
            let mut state = state.write().await;
            let score = state.score;
            let new_score = if score < 100 { 0 } else { score - 100 };
            state.score = new_score;
            (score, new_score)
        };

        // Acquire locks in the same order as in `add_state_with_resolver()`.
        debug!("Acquiring read lock of clients_rank({score}, {ind})");
        let mut clients_rank = match state.read().await.client {
            RugClient::Client(_) => self.rank.clients.write().await,
            RugClient::SecClient(_) => self.rank.dnseclients.write().await,
        };
        clients_rank.remove(&Item { score, ind });
        clients_rank.insert(Item { score: new_score, ind });
        debug!("Updated score.");
    }

    async fn new_state(resolver: DnsResolver, score: u32) -> Result<State> {
        match resolver {
            DnsResolver::Plain(r) => Self::new_plain_state(r, score).await,
            DnsResolver::DNScrypt(r) => Self::new_dnscrypt_state(r, score).await,
            DnsResolver::DoH(r) => Self::new_doh_state(r, score).await,
        }
    }

    async fn new_dnscrypt_state(resolver: DNScryptResolver, score: u32) -> Result<State> {
        unimplemented!();
    }

    async fn new_plain_state(resolver: PlainResolver, score: u32) -> Result<State> {
        debug!("Creating a state with PlainResolver config");
        let name_server = SocketAddr::new(resolver.addr().to_owned(), resolver.port());

        let provider = TokioRuntimeProvider::default();
        let stream = UdpClientStream::builder(name_server, provider).build();
        Self::create_state(DnsResolver::Plain(resolver), stream, score).await
    }

    async fn new_doh_state(resolver: DoHResolver, score: u32) -> Result<State> {
        debug!("Creating a state with DoHResolver config");
        let host = match resolver.host() {
            Host::Ip(ip) => ip.to_string(),
            Host::Domain(domain) => domain.to_owned(),
        };
        let name_server = SocketAddr::new(resolver.addr().expect("unimplemented"), resolver.port());

        let provider = TokioRuntimeProvider::default();
        let stream_builder = HttpsClientStreamBuilder::with_client_config(
            Arc::new(hickory_rustls::client_config()),
            provider,
        );

        let stream = stream_builder.build(name_server, host, resolver.path().into());
        Self::create_state(DnsResolver::DoH(resolver), stream, score).await
    }

    async fn create_state<F, S>(resolver: DnsResolver, stream: F, score: u32) -> Result<State>
    where
        S: DnsRequestSender,
        F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    {
        debug!("Creating a state with config: {resolver:?}");
        if resolver.props() & 0x1 == 0x1 {
            // The resolver support DNSSEC
            let (client, bg) = DnssecClient::connect(stream).await?;
            debug!("Client built with target: {:?}", resolver);

            let bg_handle = tokio::spawn(bg);
            Ok(State {
                client: RugClient::SecClient(client),
                bg_handle,
                resolver,
                health: true,
                score,
            })
        } else {
            // The resovler do not support DNSSEC
            let (client, bg) = Client::connect(stream).await?;
            debug!("Client built with target: {:?}", resolver);

            let bg_handle = tokio::spawn(bg);
            Ok(State {
                client: RugClient::Client(client),
                bg_handle,
                resolver,
                health: true,
                score,
            })
        }
    }
}

impl RugDnsResolver {
    /// Constructs a new DNS Resolver
    pub async fn init(config: &Config) -> Self {
        debug!("Intializing RugDnsResolver");
        debug!("Intializing Proxy Resolvers");
        let timeout = Duration::from_secs(config.timeout_s as u64);
        let proxy_resolvers =
            Resolvers::init(&config.proxy_servers, &config.sources.servers, timeout).await;
        debug!("Intializing Direct Resolvers");
        let direct_resolvers =
            Resolvers::init(&config.direct_servers, &config.sources.servers, timeout).await;
        debug!("Intializing Default Resolvers");
        let default_resolvers =
            Resolvers::init(&config.default_servers, &config.sources.servers, timeout).await;
        // FIXME: Temporary implementation.
        debug!("Intializing DHCP Resolvers");
        let dhcp_resolvers =
            Resolvers::init(&config.direct_servers, &config.sources.servers, timeout).await;
        if (proxy_resolvers.states.len()
            + direct_resolvers.states.len()
            + default_resolvers.states.len()
            + dhcp_resolvers.states.len())
            == 0
        {
            panic!("no valid resolver to use, check the network and the configuration file.");
        }
        Self {
            proxy_resolvers,
            direct_resolvers,
            default_resolvers,
            dhcp_resolvers,
            timeout,
            para_num: config.para_num,
        }
    }

    /// A *classic* DNS query
    // TODO?: If we need to modify the client, we may need a larger critical
    // section protected by the RwLock.
    pub async fn resolve(&self, query: Query) -> Result<DnsResponse, ProtoError> {
        // TODO: Disable with non-proxy mode.
        // Try proxy servers
        match self.proxy_resolvers.resolve(query.clone(), self.timeout, self.para_num).await {
            Ok(value) => return value,
            Err(err) => error!("Proxy resolvers: {err}"),
        }
        // TODO?: A separate DNSCrypt resolvers to resolver a oversea domain without proxy
        // Try direct servers
        match self.direct_resolvers.resolve(query.clone(), self.timeout, self.para_num).await {
            Ok(value) => return value,
            Err(err) => error!("Direct resolvers: {err}"),
        }
        // Try default servers
        match self.default_resolvers.resolve(query.clone(), self.timeout, self.para_num).await {
            Ok(value) => return value,
            Err(err) => error!("Default resolvers: {err}"),
        }

        // Try DHCP servers
        match self.dhcp_resolvers.resolve(query, self.timeout, self.para_num).await {
            Ok(value) => return value,
            Err(err) => error!("DHCP resolvers: {err}"),
        }

        Err(ProtoError::from("Resolve finally went wrong"))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hickory_proto::{
        op::Message,
        rr::{Name, RData, RecordType},
    };
    use tokio::process::Command;

    use super::*;
    use crate::config;

    async fn fetch_simple_case_data() -> (&'static str, String, String) {
        let domain = "fanyi.baidu.com.";
        let mut dig = Command::new("dig");
        dig.args(&["@223.5.5.5", "+https", "+short", domain]);
        let output = dig.output().await.unwrap().stdout;
        let mut lines = str::from_utf8(&output).unwrap().lines();

        (domain, lines.next().unwrap().into(), lines.next().unwrap().into())
    }

    #[tokio::test]
    async fn test_lookup_a() {
        // /*
        crate::init_tracing();
        let config = config::init_config(None).await;
        let resolver = RugDnsResolver::init(&config).await;
        let domain = "blog.chrjeb.cn.";
        let ip = "47.104.90.193";
        debug!("Query `{domain}`- ip:{ip}");

        let query = Query::query(Name::from_str(domain).unwrap(), RecordType::A);
        let msg = resolver.resolve(query).await.unwrap().into_message();
        assert_eq!(msg.answer_count(), 1);
        let answers = msg.answers();
        dbg!(answers);
        assert_eq!(answers[0].name().to_lowercase(), Name::from_str(domain).unwrap());
        assert_eq!(answers[0].data(), &RData::A(ip.parse().unwrap()));
        // */
    }

    // TODO: 通过修改头里面的是否进行 DNSSEC
    // 验证和是否在失败后仍然传输数据等选项， 验证 Rug DNS 会正确的处理这些
    // flags
}
