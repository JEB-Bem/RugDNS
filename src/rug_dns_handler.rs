use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::net::runtime::Time;

pub struct RugDnsHandler {
    bar: u8,
}

impl RugDnsHandler {
    pub fn new(bar: u8) -> Self {
        RugDnsHandler { bar }
    }
}

#[async_trait::async_trait]
impl RequestHandler for RugDnsHandler {
    async fn handle_request<R: ResponseHandler, T: Time> (
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        unimplemented!();
    }
}
