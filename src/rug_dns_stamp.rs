use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use regex::regex;
use tracing::{debug, info};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtocolIdentifier {
    DNScrypt = 0x01,
    DoH      = 0x02,
}

#[derive(Debug, PartialEq)]
pub enum DnsResolver {
    DoH(DoHResolver),
    DNScrypt(DNScryptResolver),
}

#[derive(Debug, PartialEq, Clone)]
pub enum Host {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug, PartialEq, Clone)]
pub struct DoHResolver {
    props: u64,
    addr: Option<IpAddr>,
    hashi: Vec<Vec<u8>>,
    host: Host,
    port: u16,
    path: String,
    bootstraps: Vec<IpAddr>,
}

#[derive(Debug, PartialEq)]
pub struct DNScryptResolver {
    props: u64,
    addr: Option<IpAddr>,
    port: u16,
    pk: Vec<u8>,
    provider_name: String,
}

pub trait StampConvert {
    /// Parse bytes without a protocol identifier into a DnsResolver.
    fn parse_from_bytes(bytes: &[u8]) -> Option<DnsResolver>;
}

/// Check whether the domain is valid under RFC 1034, except that a trailing
/// dot is not allowed.
pub fn validate_domain(domain: &str) -> bool {
    regex!(
        r"^((?:([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]{0,61}[A-Za-z0-9])\.)+)([A-Za-z0-9]|(?:[A-Za-z0-9][A-Za-z0-9\-]{0,61}[A-Za-z0-9]))$"
    ).is_match(domain)
}

pub fn validate_path(path: &str) -> bool {
    regex!(r"^\/(([A-z0-9\-\%]+\/)*[A-z0-9\-\%]+$)?$").is_match(path)
}

pub fn parse_stamp(mut b64_str: &str) -> Option<DnsResolver> {
    b64_str = b64_str.get((b64_str.trim_matches('=').find("sdns://")? + 7)..)?;
    dbg!(b64_str);
    let bytes = URL_SAFE_NO_PAD.decode(b64_str).expect("parse dns stamp");
    match bytes[0] {
        v if v == ProtocolIdentifier::DNScrypt as u8 =>
            DNScryptResolver::parse_from_bytes(&bytes[1..]),
        v if v == ProtocolIdentifier::DoH as u8 =>
            DoHResolver::parse_from_bytes(&bytes[1..]),
        _ => panic!("unexpected protocol identifier"),
    }
}

impl DoHResolver {
    pub fn build(
        props: u64,
        addr: Option<IpAddr>,
        hashi: Vec<Vec<u8>>,
        hostname: &str,
        mut path: &str,
        bootstraps: Vec<IpAddr>
    ) -> Option<Self> {
        let (host, port) = Self::split_hostname(hostname)?;
        if props > 7 { return None; }
        if path.is_empty() { path = "/dns-query"; }
        else if !validate_path(path) { return None; }

        Some(Self {
            props,
            hashi,
            addr,
            host,
            port: port.into(),
            path: path.into(),
            bootstraps,
        })
    }

    fn split_hostname<'a>(hostname: &'a str) -> Option<(Host, u16)> {
        let host: &str;
        let port: u16;
        match hostname.find(':') {
            Some(ind) => {
                host = &hostname[..ind];
                port = hostname[ind+1..].parse::<u16>().ok()?;
            },
            None => {
                host = hostname;
                port = 443;
            }
        }

        if validate_domain(host) {
            return Some((Host::Domain(host.into()),port));
        }
        if let Ok(host) = host.parse::<IpAddr>() {
            return Some((Host::Ip(host), port));
        }

        None
    }

    pub fn set_props(&mut self, props: u64) -> bool {
        if props > 7 { false }
        else { self.props = props; true }
    }
    pub fn set_addr(&mut self, ip: IpAddr) { self.addr = Some(ip); }
    pub fn set_host(&mut self, host: Host) { self.host = host; }
    pub fn set_port(&mut self, port: u16) { self.port = port; }
    pub fn set_path(&mut self, path: &str) -> bool {
        if validate_path(path) { self.path = path.into(); true }
        else { false }
    }
    pub fn hashi_as_mut<'a>(&'a mut self) -> &'a mut Vec<Vec<u8>> {
        return self.hashi.as_mut()
    }
    pub fn bootstraps_as_mut<'a>(&'a mut self) -> &'a mut Vec<IpAddr> {
        return self.bootstraps.as_mut()
    }
}

impl StampConvert for DoHResolver {
    fn parse_from_bytes(mut bytes: &[u8]) -> Option<DnsResolver> {
        // props
        let props    = u64::from_be_bytes(bytes.get(..8)?.try_into().ok()?);
        bytes = bytes.get(8..)?;
        dbg!(&props);

        // addr
        let addr_len = u8::from_be_bytes(bytes.get(..1)?.try_into().ok()?) as usize;
        bytes = bytes.get(1..)?;
        let mut addr = "";
        if addr_len != 0 {
            addr = str::from_utf8(bytes.get(..addr_len)?).ok()?;
            bytes = bytes.get(addr_len..)?;
            dbg!(addr);
        }

        // hashi
        let mut hashi = Vec::new();
        loop {
            let hash_len = u8::from_be_bytes(bytes.get(..1)?.try_into().ok()?);
            dbg!(hash_len);
            bytes = bytes.get(1..)?;
            if hash_len == 0 { break }
            let flag = (hash_len & 0x80) == 0;
            let hash_len = (hash_len & 0x7f) as usize;
            let hash = bytes.get(..hash_len)?;
            bytes = bytes.get(hash_len..)?;
            // &[u8] -> Vec<u8>
            hashi.push(hash.to_vec());
            if flag { break };
        }

        // hostname
        let hostname_len = u8::from_be_bytes(bytes.get(..1)?.try_into().ok()?) as usize;
        bytes = bytes.get(1..)?;
        let mut hostname = "";
        if hostname_len != 0 {
            hostname = str::from_utf8(bytes.get(..hostname_len)?).ok()?;
            bytes = bytes.get(hostname_len..)?;
            dbg!(hostname);
        }

        // path
        let path_len = u8::from_be_bytes(bytes.get(..1)?.try_into().ok()?) as usize;
        let mut path = "";
        if path_len != 0 {
            path = str::from_utf8(bytes.get(1..(path_len + 1))?).ok()?;
            dbg!(path);
        }

        // bootstraps
        let mut bootstraps = Vec::<IpAddr>::new();
        if bytes.len() > path_len + 1 {
            bytes.get((path_len + 1)..)?;
            loop {
                let bs_len = u8::from_be_bytes(bytes.get(..1)?.try_into().ok()?);
                bytes = bytes.get(1..)?;
                if bs_len == 0 { break }
                let flag = (bs_len & 0x80) != 0;
                let bs_len = (bs_len & 0x7f) as usize;
                let bs = bytes.get(..bs_len)?;
                bytes = bytes.get(..bs_len)?;
                // &[u8] -> Vec<u8> -> String
                bootstraps.push(dbg!(str::from_utf8(bs).ok()?.parse().ok()?));
                if flag { break };
            }
        }

        Some(DnsResolver::DoH(Self::build(
            props,
            addr.parse().ok(),
            hashi,
            hostname,
            path,
            bootstraps
        )?))
    }
}

impl DNScryptResolver {
    pub fn build() -> Self {
        unimplemented!();
    }
}

impl StampConvert for DNScryptResolver {
    fn parse_from_bytes(bytes: &[u8]) -> Option<DnsResolver> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_domain() {
        crate::init_tracing();
        assert!(validate_domain("ex-e.com"));
        assert!(validate_domain("a.com"));
        assert!(validate_domain("A.a.com"));
        assert!(validate_domain("a.A.com"));
        assert!(validate_domain("1.com"));
        assert!(validate_domain("a-1.com"));
        assert!(validate_domain("a.aAb.co"));
    }

    #[test]
    fn test_invalid_domain() {
        crate::init_tracing();
        assert!(!validate_domain("example.com."));
        assert!(!validate_domain("-a.example.com."));
        assert!(!validate_domain("blog-.example.com."));
        assert!(!validate_domain("blog-.ex-b.com."));
    }

    #[test]
    fn test_valid_path() {
        crate::init_tracing();
        assert!(validate_path("/"));
        assert!(validate_path("/query"));
        assert!(validate_path("/query/a"));
    }

    #[test]
    fn test_invalid_path() {
        crate::init_tracing();
        assert!(!validate_path("//"));
        assert!(!validate_path("/query/"));
        assert!(!validate_path("/query/a/"));
    }

    #[test]
    #[should_panic]
    fn test_parse_invalid_stamp() {
        crate::init_tracing();
        parse_stamp("sdns://Agf*AAAGCD");
    }

    #[test]
    fn test_parse_doh_stamp() {
        crate::init_tracing();
        let mut doh_resolver = DoHResolver::build(
            /* props= */ 0b000,
            /* addr= */ Some("223.5.5.5".parse().unwrap()),
            /* hashi= */
            vec![b"\x98\xe3\xd5\xe56\xaf)X\xcd/\x7f\x14\xf7\x04\xefJ'm%\xe3<\xd6_.e\xf5\xe4\xf2r|\x130".into()],
            /* hostname= */ "223.5.5.5",
            /* path= */ "/dns-query",
            /* bootstraps= */ Vec::new(),
        ).unwrap();

        assert_eq!(
            parse_stamp("sdns://AgAAAAAAAAAACTIyMy41LjUuNSCY49XlNq8pWM0vfxT3BO9KJ20l4zzWXy5l9eTycnwTMAkyMjMuNS41LjUKL2Rucy1xdWVyeQ"),
            Some(DnsResolver::DoH(doh_resolver.clone()))
        );

        doh_resolver.hashi_as_mut().clear();
        assert_eq!(
            parse_stamp("sdns://AgAAAAAAAAAACTIyMy41LjUuNQAJMjIzLjUuNS41Ci9kbnMtcXVlcnk"),
            Some(DnsResolver::DoH(doh_resolver.clone()))
        )
    }
}
