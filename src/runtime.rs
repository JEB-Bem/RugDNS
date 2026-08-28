use std::{io, net::SocketAddr, pin::Pin};

use hickory_proto::runtime::{
    RuntimeProvider, TokioHandle, TokioRuntimeProvider, TokioTime, iocompat::AsyncIoTokioAsStd,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, Error, ErrorKind},
    net::{TcpSocket, TcpStream, UdpSocket as TokioUdpSocket},
    time,
    time::Duration,
};
use tracing::{debug, info};

#[derive(Clone)]
pub struct HttpProxyRuntimeProvider {
    inner:      TokioRuntimeProvider,
    proxy_addr: SocketAddr,
}

impl HttpProxyRuntimeProvider {
    /// Create a Tokio Proxy runtime
    pub fn new(proxy_addr: SocketAddr) -> Self {
        Self { inner: TokioRuntimeProvider::new(), proxy_addr }
    }
}

async fn read_header(stream: &mut TcpStream, buf: &mut [u8]) -> io::Result<usize> {
    for i in 0..buf.len() {
        let byte = &mut buf[i..i + 1];
        if stream.read(byte).await? == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "proxy closed before CONNECT response completed",
            ));
        }
        if buf[..i + 1].ends_with(b"\r\n\r\n") {
            return Ok(i + 1);
        }
    }
    Err(Error::new(
        ErrorKind::InvalidData,
        format!("CONNECT response header too large: exceeds {}", buf.len()),
    ))
}

async fn create_tunnel(
    proxy_addr: SocketAddr,
    server_addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
) -> io::Result<TcpStream> {
    let socket = match proxy_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }?;
    if let Some(bind_addr) = bind_addr {
        socket.bind(bind_addr)?;
    }
    socket.set_nodelay(true)?;

    let mut stream = socket.connect(proxy_addr).await?;
    let content = format!(
        "CONNECT {server_addr} HTTP/1.1\r\n\
         Host: {server_addr}\r\n\
         \r\n"
    );
    debug!("Write content: {content:?}");
    stream.write_all(content.as_bytes()).await?;

    let mut buf = [0u8; 256];
    let len = read_header(&mut stream, &mut buf).await?;
    let header = match str::from_utf8(&buf[..len]) {
        Ok(content) => content,
        Err(err) => {
            return Err(Error::new(
                ErrorKind::HostUnreachable,
                format!("parse CONNECT response: {err}"),
            ));
        }
    };
    debug!("Proxy response header: {header}");
    let mut resp = header.split(" ");

    let parse_err = Error::new(
        ErrorKind::HostUnreachable,
        "missing or invalid parameter in HTTP response start-line",
    );

    if resp.next().ok_or(Error::new(parse_err.kind(), parse_err.to_string()))? != "HTTP/1.1" {
        return Err(Error::new(ErrorKind::HostUnreachable, "HTTP protocol unmatched"));
    }
    // Assumes the HTTP/1.1 version has already been checked.
    let info = header.trim().split_once("HTTP/1.1").unwrap().1;

    match resp.next().ok_or(Error::new(parse_err.kind(), parse_err.to_string()))?.parse::<u16>() {
        Ok(code) => match code {
            x if x / 100 == 2 => Ok(stream),
            400 => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("<{info}> invalid server addr: {server_addr}"),
            )),
            407 => Err(Error::new(ErrorKind::ConnectionRefused, format!("<{info}> unimplemented"))),
            x if x / 100 == 4 => Err(Error::new(ErrorKind::ConnectionRefused, format!("<{info}>"))),
            _ => Err(Error::new(ErrorKind::HostUnreachable, format!("<{info}>"))),
        },
        Err(err) => {
            Err(Error::new(ErrorKind::InvalidData, format!("invalid HTTP status code: {err}")))
        }
    }
}

impl RuntimeProvider for HttpProxyRuntimeProvider {
    type Handle = TokioHandle;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;
    type Timer = TokioTime;
    type Udp = TokioUdpSocket;

    fn create_handle(&self) -> Self::Handle { self.inner.create_handle() }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        wait_for: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        let proxy_addr = self.proxy_addr.clone();
        Box::pin(async move {
            let future = create_tunnel(proxy_addr, server_addr, bind_addr);
            let wait_for = wait_for.unwrap_or(Duration::from_secs(5));
            match time::timeout(wait_for, future).await {
                Ok(Ok(socket)) => {
                    let local_addr = socket.local_addr()?;
                    info!(
                        "Proxy established from {local_addr} to {server_addr} through {proxy_addr}"
                    );
                    Ok(AsyncIoTokioAsStd(socket))
                }
                Ok(Err(e)) => Err(e),
                Err(_) => Err(Error::new(
                    ErrorKind::TimedOut,
                    format!(
                        "connection to {server_addr:?} with {:?} timed out after {wait_for:?}",
                        proxy_addr
                    ),
                )),
            }
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        self.inner.bind_udp(local_addr, server_addr)
    }
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tracing::debug;

    use super::*;

    #[tokio::test]
    async fn test_proxy_tcp() {
        crate::init_tracing();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        debug!("Listener bound on {listener_addr}");
        // /*
        let provider = HttpProxyRuntimeProvider::new("127.0.0.1:10808".parse().unwrap());
        // */
        // let provider = TokioRuntimeProvider::new();
        debug!("provider initialized");

        let mut stream = provider.connect_tcp(listener_addr, None, None).await.unwrap().0;
        let rug_addr = stream.local_addr().unwrap();
        debug!("rugdns stream established: {rug_addr} -> 127.0.0.1:10808");

        let (mut lstream, proxy_addr) = listener.accept().await.unwrap();
        debug!("proxy stream established: {proxy_addr} -> {listener_addr}");

        // Test sending
        let mut buf = [0u8; 10];
        assert_eq!(stream.write(b"hello").await.unwrap(), 5);
        debug!("{rug_addr} -> 127.0.0.1:10808 Send: b\"hello\"");
        debug!("{proxy_addr} -> {listener_addr} Send: b\"hello\"");
        let len = lstream.read(&mut buf).await.unwrap();
        dbg!(str::from_utf8(&buf).unwrap());
        debug!("{rug_addr:?} -> {listener_addr:?} Received");
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(len, 5);

        // Test receiving
        let mut buf = [0u8; 10];
        assert_eq!(lstream.write(b"world").await.unwrap(), 5);
        debug!("{listener_addr} -> {proxy_addr} Send: b\"world\"");
        debug!("127.0.0.1:10808 -> {rug_addr} Send: b\"world\"");
        let len = stream.read(&mut buf).await.unwrap();
        dbg!(str::from_utf8(&buf).unwrap());
        debug!("{listener_addr} -> {rug_addr} Received");
        assert_eq!(&buf[..5], b"world");
        assert_eq!(len, 5);
    }
}
