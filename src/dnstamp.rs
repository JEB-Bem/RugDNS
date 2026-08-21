use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use regex::regex;
use tracing::{debug, info};
use data_encoding::HEXLOWER;
use anyhow::Result;

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

#[derive(Debug, PartialEq)]
pub struct DNScryptResolver {
    props: u64,
    addr: IpAddr,
    port: u16,
    pk: String,
    provider_name: String,
}

#[derive(Debug, PartialEq, Clone)]
pub struct DoHResolver {
    props: u64,
    addr: Option<IpAddr>,
    hashi: Vec<String>,
    host: Host,
    port: u16,
    path: String,
    bootstraps: Vec<IpAddr>,
}

pub trait StampConvert {
    /// Parse bytes without a protocol identifier into a DnsResolver.
    fn parse_from_bytes(bytes: &[u8]) -> Option<DnsResolver>;
}

/// Check whether the domain is valid under RFC 1034, except that a trailing
/// dot is not allowed.
pub fn validate_domain(domain: &str) -> bool {
    if let Ok(_) = domain.parse::<IpAddr>() {
        return false;
    }
    regex!(
        r"^((?:([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]{0,61}[A-Za-z0-9])\.)+)([A-Za-z0-9]|(?:[A-Za-z0-9][A-Za-z0-9\-]{0,61}[A-Za-z0-9]))$"
    ).is_match(domain)
}

pub fn validate_path(path: &str) -> bool {
    regex!(r"^\/(([A-z0-9\-\%]+\/)*[A-z0-9\-\%]+$)?$").is_match(path)
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
        debug!("Valide domain: {host:?}.");
        return Some((Host::Domain(host.into()),port));
    }

    Some((Host::Ip(host.parse::<IpAddr>().ok()?), port))
}

fn from_hex(s: &str) -> Result<Vec<u8>> {
    Ok(HEXLOWER.decode(s.as_bytes())?)
}

fn to_hex(s: &[u8]) -> String {
    HEXLOWER.encode(s)
}

impl DNScryptResolver {
    pub fn build(
        props: u64,
        hostname: &str,
        pk: &str,
        provider_name: &str,
    ) -> Option<Self> {
        let (host, port) = split_hostname(hostname)?;
        let addr = if let Host::Ip(ip) = host {
            ip
        } else { return None; };
        if props > 7 { return None; }
        if pk.len() != 64 || from_hex(pk).is_err() { return None; }
        if !validate_domain(provider_name) { return None; }

        Some(Self {
            props,
            addr,
            port,
            pk: pk.into(),
            provider_name: provider_name.into(),
        })
    }

    pub fn props(&self) -> u64 { self.props }
    pub fn addr(&self) -> &IpAddr { &self.addr }
    pub fn port(&self) -> u16 { self.port }
    pub fn pk(&self) -> &str { &self.pk }
    pub fn provider_name(&self) -> &str { &self.provider_name }
}

impl StampConvert for DNScryptResolver {
    fn parse_from_bytes(mut bytes: &[u8]) -> Option<DnsResolver> {
        let props = u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?);
        bytes = bytes.get(8..)?;

        // addr: LP(addr [:port])
        let addr_len =
            u8::from_be_bytes(bytes.get(..1)?.try_into().ok()?) as usize;
        bytes = bytes.get(1..)?;
        if addr_len == 0 { return None; }
        let addr = str::from_utf8(bytes.get(..addr_len)?).ok()?;
        bytes = bytes.get(addr_len..)?;

        // pk: LP(pk)
        let pk_len =
            u8::from_be_bytes(bytes.get(..1)?.try_into().ok()?) as usize;
        bytes = bytes.get(1..)?;
        if pk_len == 0 { return None; }
        let pk = to_hex(bytes.get(..pk_len)?);
        bytes = bytes.get(pk_len..)?;

        // providerName: LP(providerName)
        let provider_name_len =
            u8::from_be_bytes(bytes.get(..1)?.try_into().ok()?) as usize;
        bytes = bytes.get(1..)?;
        if provider_name_len == 0 { return None; }
        let provider_name =
            str::from_utf8(bytes.get(..provider_name_len)?).ok()?;

        Some(DnsResolver::DNScrypt(Self::build(props, addr, &pk, provider_name)?))
    }
}

pub fn parse_stamp(mut b64_str: &str) -> Option<DnsResolver> {
    b64_str = b64_str.get((b64_str.trim_matches('=').find("sdns://")? + 7)..)?;
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
        hashi: Vec<String>,
        hostname: &str,
        mut path: &str,
        bootstraps: Vec<IpAddr>
    ) -> Option<Self> {
        let (host, port) = split_hostname(hostname)?;
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
    pub fn hashi_as_mut<'a>(&'a mut self) -> &'a mut Vec<String> {
        return self.hashi.as_mut()
    }
    pub fn bootstraps_as_mut<'a>(&'a mut self) -> &'a mut Vec<IpAddr> {
        return self.bootstraps.as_mut()
    }
    
    pub fn props(&self) -> u64 { self.props }
    pub fn addr(&self) -> &Option<IpAddr> { &self.addr }
    pub fn hashi(&self) -> &Vec<String> { &self.hashi }
    pub fn host(&self) -> &Host { &self.host }
    pub fn port(&self) -> u16 { self.port }
    pub fn path(&self) -> &str { &self.path }
    pub fn bootstraps(&self) -> &Vec<IpAddr> { &self.bootstraps }
}

impl StampConvert for DoHResolver {
    fn parse_from_bytes(mut bytes: &[u8]) -> Option<DnsResolver> {
        // props: little-endian u64
        let props = u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?);
        bytes = bytes.get(8..)?;

        // addr: LP(string), may be empty
        let addr_len = u8::from_be_bytes(bytes.get(..1)?.try_into().ok()?) as usize;
        bytes = bytes.get(1..)?;
        let mut addr = "";
        if addr_len != 0 {
            addr = str::from_utf8(bytes.get(..addr_len)?).ok()?;
            bytes = bytes.get(addr_len..)?;
        }

        // hashi: VLP of raw hash bytes; high bit (0x80) = more elements follow
        let mut hashi = Vec::new();
        loop {
            let vlen = u8::from_be_bytes(bytes.get(..1)?.try_into().ok()?);
            bytes = bytes.get(1..)?;
            if vlen == 0 { break }
            let more = (vlen & 0x80) != 0;
            let len = (vlen & 0x7f) as usize;
            hashi.push(to_hex(bytes.get(..len)?));
            bytes = bytes.get(len..)?;
            if !more { break }
        }

        // hostname: LP(string), may be empty
        let hostname_len = u8::from_be_bytes(bytes.get(..1)?.try_into().ok()?) as usize;
        bytes = bytes.get(1..)?;
        let mut hostname = "";
        if hostname_len != 0 {
            hostname = str::from_utf8(bytes.get(..hostname_len)?).ok()?;
            bytes = bytes.get(hostname_len..)?;
        }

        // path: LP(string), may be empty
        let path_len = u8::from_be_bytes(bytes.get(..1)?.try_into().ok()?) as usize;
        bytes = bytes.get(1..)?;
        let mut path = "";
        if path_len != 0 {
            path = str::from_utf8(bytes.get(..path_len)?).ok()?;
            bytes = bytes.get(path_len..)?;
        }

        // bootstraps: optional VLP of IPs; absent when bytes are exhausted
        let mut bootstraps = Vec::<IpAddr>::new();
        while !bytes.is_empty() {
            let vlen = u8::from_be_bytes(bytes.get(..1)?.try_into().ok()?);
            bytes = bytes.get(1..)?;
            if vlen == 0 { break }
            let more = (vlen & 0x80) != 0;
            let len = (vlen & 0x7f) as usize;
            let ip = str::from_utf8(bytes.get(..len)?).ok()?.parse().ok()?;
            bytes = bytes.get(len..)?;
            bootstraps.push(ip);
            if !more { break }
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
        // single label (no dot) and empty string are rejected
        assert!(!validate_domain("com"));
        assert!(!validate_domain("121.123.235.117"));
        assert!(!validate_domain(""));
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
        assert!(!validate_path(""));
    }

    #[test]
    #[should_panic]
    fn test_parse_invalid_stamp_base64() {
        crate::init_tracing();
        // '*' is not a base64url character -> decode panics
        parse_stamp("sdns://Agf*AAAGCD");
    }

    #[test]
    #[should_panic]
    fn test_parse_invalid_stamp_protocol() {
        crate::init_tracing();
        // decodes to [0x03, ...], an unknown protocol identifier
        parse_stamp("sdns://Aw");
    }

    #[test]
    fn test_parse_stamp_no_prefix() {
        crate::init_tracing();
        assert!(parse_stamp("not-a-stamp").is_none());
        assert!(parse_stamp("").is_none());
    }

    #[test]
    fn test_parse_doh_stamp_basic() {
        crate::init_tracing();
        let expect = DoHResolver::build(
            /* props= */ 0,
            /* addr= */ Some("223.5.5.5".parse().unwrap()),
            /* hashi= */
            vec!["98e3d5e536af2958cd2f7f14f704ef4a276d25e33cd65f2e65f5e4f2727c1330".into()],
            /* hostname= */ "223.5.5.5",
            /* path= */ "/dns-query",
            /* bootstraps= */ Vec::new(),
        ).unwrap();

        assert_eq!(
            parse_stamp("sdns://AgAAAAAAAAAACTIyMy41LjUuNSCY49XlNq8pWM0vfxT3BO9KJ20l4zzWXy5l9eTycnwTMAkyMjMuNS41LjUKL2Rucy1xdWVyeQA"),
            Some(DnsResolver::DoH(expect))
        );
    }

    #[test]
    fn test_parse_doh_stamp_no_hash() {
        crate::init_tracing();
        let expect = DoHResolver::build(
            0,
            Some("223.5.5.5".parse().unwrap()),
            Vec::new(),
            "223.5.5.5",
            "/dns-query",
            Vec::new(),
        ).unwrap();

        assert_eq!(
            parse_stamp("sdns://AgAAAAAAAAAACTIyMy41LjUuNQAJMjIzLjUuNS41Ci9kbnMtcXVlcnkA"),
            Some(DnsResolver::DoH(expect))
        );
    }

    #[test]
    fn test_parse_doh_stamp_props_little_endian() {
        crate::init_tracing();
        // props=1 (DNSSEC), encoded little-endian: 01 00 00 00 00 00 00 00
        let expect = DoHResolver::build(
            1,
            None,
            vec![to_hex(&vec![0xab; 32])],
            "dns.example.com:8443",
            "/dns-query",
            Vec::new(),
        ).unwrap();

        assert_eq!(
            parse_stamp("sdns://AgEAAAAAAAAAACCrq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urqxRkbnMuZXhhbXBsZS5jb206ODQ0MwovZG5zLXF1ZXJ5AA"),
            Some(DnsResolver::DoH(expect))
        );
    }

    #[test]
    fn test_parse_doh_stamp_domain_host_port() {
        crate::init_tracing();
        // empty addr, empty hashi, domain host, no bootstraps field at all
        let expect = DoHResolver::build(
            0,
            None,
            Vec::new(),
            "dns.example.com",
            "/dns-query",
            Vec::new(),
        ).unwrap();

        assert_eq!(
            parse_stamp("sdns://AgAAAAAAAAAAAAAPZG5zLmV4YW1wbGUuY29tCi9kbnMtcXVlcnk"),
            Some(DnsResolver::DoH(expect))
        );
    }

    #[test]
    fn test_parse_doh_stamp_multi_hash() {
        crate::init_tracing();
        let expect = DoHResolver::build(
            0,
            None,
            vec![to_hex(&vec![0x11; 32]), to_hex(&vec![0x22; 32])],
            "dns.example.com",
            "/dns-query",
            Vec::new(),
        ).unwrap();

        assert_eq!(
            parse_stamp("sdns://AgAAAAAAAAAAAKARERERERERERERERERERERERERERERERERERERERERESAiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg9kbnMuZXhhbXBsZS5jb20KL2Rucy1xdWVyeQA"),
            Some(DnsResolver::DoH(expect))
        );
    }

    #[test]
    fn test_parse_doh_stamp_bootstraps() {
        crate::init_tracing();
        let expect = DoHResolver::build(
            0,
            None,
            Vec::new(),
            "dns.example.com",
            "/dns-query",
            vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
        ).unwrap();

        assert_eq!(
            parse_stamp("sdns://AgAAAAAAAAAAAAAPZG5zLmV4YW1wbGUuY29tCi9kbnMtcXVlcnmHMS4xLjEuMQc4LjguOC44"),
            Some(DnsResolver::DoH(expect))
        );
    }

    #[test]
    fn test_parse_dnscrypt_stamp_basic() {
        crate::init_tracing();
        let expect = DNScryptResolver::build(
            /* props= */ 0b111,
            /* hostname= */ "175.45.182.179",
            /* pk= */ "daea841aedb59a3533482fcde8a63f4f22fdd80beaa981c5ee4478ff2527ed72",
            /* provider_name= */ "2.dnscrypt-cert.dnscry.pt",
        ).unwrap();

        assert_eq!(
            parse_stamp("sdns://AQcAAAAAAAAADjE3NS40NS4xODIuMTc5INrqhBrttZo1M0gvzeimP08i_dgL6qmBxe5EeP8lJ-1yGTIuZG5zY3J5cHQtY2VydC5kbnNjcnkucHQ"),
            Some(DnsResolver::DNScrypt(expect))
        );
    }

    #[test]
    fn test_parse_dnscrypt_stamp_invalid_pk() {
        crate::init_tracing();

        assert_eq!(
            parse_stamp("sdns://AQcAAAAAAAAAEjE3NS40NS4xODIuMTc5OjQ0Mx_a6oQa7bWaM0gvzeimP08i_dgL6qmBxe5EeP8lJ-1yGTIuZG5zY3J5cHQtY2VydC5kbnNjcnkucHQ"),
            None
        );
    }

    #[test]
    fn test_parse_dnscrypt_stamp_props_little_endian() {
        crate::init_tracing();
        // props=1 (DNSSEC), encoded little-endian: 01 00 00 00 00 00 00 00
        let expect = DNScryptResolver::build(
            /* props= */ 0b001,
            /* hostname= */ "175.45.182.179",
            /* pk= */ "daea841aedb59a3533482fcde8a63f4f22fdd80beaa981c5ee4478ff2527ed72",
            /* provider_name= */ "2.dnscrypt-cert.dnscry.pt",
        ).unwrap();

        assert_eq!(
            parse_stamp("sdns://AQEAAAAAAAAADjE3NS40NS4xODIuMTc5INrqhBrttZo1M0gvzeimP08i_dgL6qmBxe5EeP8lJ-1yGTIuZG5zY3J5cHQtY2VydC5kbnNjcnkucHQ"),
            Some(DnsResolver::DNScrypt(expect))
        );
    }

    #[test]
    fn test_parse_dnscrypt_stamp_port() {
        crate::init_tracing();
        let expect = DNScryptResolver::build(
            /* props= */ 0b111,    // 07 00 00 00 00 00 00 00
            /* hostname= */ "175.45.182.179:443",
            /* pk= */ "daea841aedb59a3533482fcde8a63f4f22fdd80beaa981c5ee4478ff2527ed72",
            /* provider_name= */ "2.dnscrypt-cert.dnscry.pt",
        ).unwrap();

        assert_eq!(
            parse_stamp("sdns://AQcAAAAAAAAAEjE3NS40NS4xODIuMTc5OjQ0MyDa6oQa7bWaNTNIL83opj9PIv3YC-qpgcXuRHj_JSftchkyLmRuc2NyeXB0LWNlcnQuZG5zY3J5LnB0"),
            Some(DnsResolver::DNScrypt(expect))
        );
    }
}
