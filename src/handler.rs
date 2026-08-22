use crate::config::Config;
use crate::resolver::RugDnsResolver;
use hickory_server::{
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    authority::MessageResponseBuilder
};
use hickory_proto::{
    op::ResponseCode,
    rr::RecordType,
};
use tracing::{info, debug, warn, error};
use std::sync::Arc;
use tokio::{sync::RwLock, time::{self, Duration}};

pub struct RugDnsHandler {
    config: Arc<RwLock<Config>>,
    resolver: RugDnsResolver,
}

impl RugDnsHandler {
    pub fn new(config: Arc<RwLock<Config>>, resolver: RugDnsResolver) -> Self {
        Self {
            config, 
            resolver,
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for RugDnsHandler {
    async fn handle_request<R: ResponseHandler> (
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        debug!("Received request: {request:?}");
        // 这里使用了 Deref trait，实际上 request: Request 被转换为了 MessageRequest
        debug!("Building MessageResponseBuilder...");
        let mut builder = MessageResponseBuilder::from_message_request(request);
        if let Some(edns) = request.edns() { builder.edns(edns.to_owned()); }
        let query = {
            if request.queries().len() > 1 {
                // RCODE reference: https://www.iana.org/assignments/dns-parameters#dns-parameters-6
                warn!("There is not exactly one query entry in the request.");
                debug!("Sending err msg with RCODE: NotImp.");
                let response = builder.error_msg(request.header(), ResponseCode::NotImp);
                return response_handle.send_response(response).await.unwrap();
            }
            request.queries()[0].original().to_owned()
        };
        
        debug!("Send lookup query {query:?} to rug resolver");
        let seconds = self.config.read().await.timeout_s as u64;
        match if seconds == 0 {
            // 0 seconds means no limit
            self.resolver.resolve(query).await
        } else {
            // Set a timeout
            time::timeout(
                Duration::from_secs(seconds),
                self.resolver.resolve(query)
            ).await.expect("resolve query")
        } {
            Ok(mut resp) => {
                // Set response `id` with the request `id`.
                resp.set_id(request.id());
                
                // Split resp.name_servers into SOA and non-SOA entries.
                let name_servers = resp
                    .name_servers()
                    .iter()
                    .filter(|record| record.record_type() != RecordType::SOA);

                let soa = resp
                    .name_servers()
                    .iter()
                    .filter(|record| record.record_type() == RecordType::SOA);

                let response = builder.build(
                    resp.header().to_owned(),
                    resp.answers(),
                    name_servers,
                    soa,
                    resp.additionals()
                );
                debug!("Built response: {response:?}");
                response_handle.send_response(response).await.unwrap()
            },
            Err(err) => {
                let response = builder.error_msg(request.header(), ResponseCode::ServFail);
                warn!("resolver lookup error: {err}");
                debug!("Send response with RCODE: ServFail.");
                response_handle.send_response(response).await.unwrap()
            }
        }
    }
}
