use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::net::runtime::Time;
use crate::config::Config;
use tracing::{info, debug, warn, error};
use data_encoding::HEXLOWER;

pub struct RugDnsHandler {
}

impl RugDnsHandler {
    pub fn new(config: &Config) -> Self {
        RugDnsHandler {  }
    }
}

#[async_trait::async_trait]
impl RequestHandler for RugDnsHandler {
    async fn handle_request<R: ResponseHandler, T: Time> (
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        debug!("Received request: {:?}", HEXLOWER.encode(request.as_slice()));
        unimplemented!();
    }
}
