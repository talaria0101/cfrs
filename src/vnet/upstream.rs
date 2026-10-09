//! Shared upstream logic: proxy specs, routing rules, SOCKS5/HTTP handshakes,
//! UDP association, and chaining.
//!
//! Both `pod-netns` backends and any other caller use one implementation, so a
//! new transport is added once rather than per backend.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, Context, Result};

/// An upstream that never answers must not stall the supervisor and the child's
/// `connect` forever.
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn within_timeout<F, T>(what: &str, future: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    match tokio::time::timeout(UPSTREAM_TIMEOUT, future).await {
        Ok(result) => result,
        Err(_) => bail!("{what} timed out after {:?}", UPSTREAM_TIMEOUT),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyKind {
    Socks5,
    Http,
    /// Not a proxy at all: dial the target through a running `tailscaled`'s
    /// LocalAPI `ts-dial` endpoint, so the tailnet is the transport.
    Tailscale,
}

#[derive(Clone, Debug)]
pub struct Proxy {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub pass: Option<String>,
    /// When set, the proxy is reached over an `AF_UNIX` socket instead of TCP.
    /// A sealed host may permit unix connects and deny every TCP one.
    pub unix_path: Option<String>,
}

impl Proxy {
    pub fn parse(spec: &str) -> Result<Self> {
        // unix:/path or socks5+unix:/path — a SOCKS5 proxy on a unix socket.
        if let Some(path) = spec
            .strip_prefix("unix:")
            .or_else(|| spec.strip_prefix("socks5+unix:"))
            .or_else(|| spec.strip_prefix("socks5+unix://"))
        {
            if path.is_empty() {
                bail!("unix proxy {spec:?} has no path");
            }
            return Ok(Self {
                kind: ProxyKind::Socks5,
                host: String::new(),
                port: 0,
                user: None,
                pass: None,
                unix_path: Some(path.to_string()),
            });
        }
        if let Some(path) = spec
            .strip_prefix("tailscale:")
            .or_else(|| spec.strip_prefix("tailscale://"))
        {
            if path.is_empty() {
                bail!("tailscale proxy {spec:?} has no socket path");
            }
            return Ok(Self {
                kind: ProxyKind::Tailscale,
                host: String::new(),
                port: 0,
                user: None,
                pass: None,
                unix_path: Some(path.to_string()),
            });
        }
        let (scheme, rest) = match spec.split_once("://") {
            Some((s, r)) => (s, r),
            None => ("socks5", spec),
        };
        // socks5://unix:/path — a SOCKS5 proxy reached over a unix socket.
        if let Some(path) = rest.strip_prefix("unix:") {
            if !path.is_empty() && (scheme == "socks5" || scheme == "socks5h" || scheme == "socks")
            {
                return Ok(Self {
                    kind: ProxyKind::Socks5,
                    host: String::new(),
                    port: 0,
                    user: None,
                    pass: None,
                    unix_path: Some(path.to_string()),
                });
            }
        }
        let kind = match scheme {
            "socks5" | "socks5h" | "socks" => ProxyKind::Socks5,
            "http" | "https" => ProxyKind::Http,
            other => bail!("unknown proxy scheme {other:?} (socks5:// or http://)"),
        };
        // user:pass@host:port
        let (creds, hostport) = match rest.rsplit_once('@') {
            Some((c, h)) => (Some(c), h),
            None => (None, rest),
        };
        let (user, pass) = match creds {
            Some(c) => match c.split_once(':') {
                Some((u, p)) => (Some(u.to_string()), Some(p.to_string())),
                None => (Some(c.to_string()), None),
            },
            None => (None, None),
        };
        let (host, port) = hostport
            .rsplit_once(':')
            .with_context(|| format!("proxy {spec:?} needs host:port"))?;
        Ok(Self {
            kind,
            host: host.to_string(),
            port: port.parse().context("proxy port")?,
            user,
            pass,
            unix_path: None,
        })
    }

    pub fn endpoint(&self) -> String {
        match &self.unix_path {
            Some(p) => format!("unix:{p}"),
            None => format!("{}:{}", self.host, self.port),
        }
    }

    /// How the previous hop should address this one when chaining. A unix
    /// socket has no `host:port`, so it is named `unix:<path>` and the hop in
    /// front resolves it (the same convention the tests' proxy uses).
    pub fn chain_addr(&self) -> String {
        self.endpoint()
    }
}

// ── per-destination routing ─────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum RuleMatch {
    Domain(String),
    Cidr(Ipv4Addr, u8),
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub matcher: RuleMatch,
    pub proxy: Proxy,
}

pub fn in_cidr(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - prefix as u32);
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

/// First matching rule wins; otherwise the default `-x` chain. A rule is a
/// single hop; the default is a chain.
pub fn select_chain<'a>(rules: &'a [Rule], default: &'a [Proxy], target: &str) -> &'a [Proxy] {
    let host = target.rsplit_once(':').map_or(target, |(h, _)| h);
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let ip: Option<IpAddr> = bare.parse().ok();
    for rule in rules {
        match &rule.matcher {
            RuleMatch::Domain(d) => {
                if d.eq_ignore_ascii_case(host) {
                    return std::slice::from_ref(&rule.proxy);
                }
            }
            RuleMatch::Cidr(net, prefix) => {
                if let Some(IpAddr::V4(v4)) = ip {
                    if in_cidr(v4, *net, *prefix) {
                        return std::slice::from_ref(&rule.proxy);
                    }
                }
            }
        }
    }
    default
}


pub async fn connect_upstream(proxy: &Proxy, target: &str) -> Result<tokio::net::TcpStream> {
    let stream = tokio::net::TcpStream::connect(proxy.endpoint())
        .await
        .with_context(|| format!("connect to proxy {}", proxy.endpoint()))?;
    match proxy.kind {
        ProxyKind::Socks5 => socks5_connect(stream, proxy, target).await,
        ProxyKind::Http => http_connect(stream, proxy, target).await,
        ProxyKind::Tailscale => bail!("the tailscale hop is only available on the seccomp backend"),
    }
}

/// A connected upstream: TCP, or a unix socket where TCP is denied.
pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncStream for T {}
pub type Upstream = Box<dyn AsyncStream>;

/// Dial the proxy and run its handshake. With more than one `-x`, the hops
/// are **chained**: dial the first, then ask each hop to CONNECT to the next,
/// and finally ask the last for the target. Each intermediate hop sees only the
/// address of the next one.
pub async fn connect_upstream_async(chain: &[Proxy], target: &str) -> Result<Upstream> {
    let (first, rest) = chain.split_first().context("no proxy configured")?;
    if first.kind == ProxyKind::Tailscale {
        if !rest.is_empty() {
            bail!("a tailscale hop cannot be chained with a proxy hop");
        }
        let path = first
            .unix_path
            .as_deref()
            .context("tailscale hop has no socket")?;
        let (host, port) = split_target(target)?;
        let conn = crate::vnet::tailscale::Dialer::new(path)
            .dial(&host, port)
            .await
            .with_context(|| format!("tailnet dial {target}"))?;
        return Ok(Box::new(conn));
    }
    let mut stream: Upstream = dial_proxy(first).await?;
    if rest.is_empty() {
        return match first.kind {
            ProxyKind::Socks5 => socks5_connect(stream, first, target).await,
            ProxyKind::Http => http_connect(stream, first, target).await,
            ProxyKind::Tailscale => unreachable!("handled above"),
        };
    }
    for (i, hop) in chain.iter().enumerate().take(chain.len() - 1) {
        if hop.kind != ProxyKind::Socks5 {
            bail!(
                "chaining needs SOCKS5 hops; {} is {:?}",
                hop.endpoint(),
                hop.kind
            );
        }
        let next = &chain[i + 1];
        stream = socks5_connect(stream, hop, &next.chain_addr()).await?;
    }
    let last = chain.last().unwrap();
    match last.kind {
        ProxyKind::Socks5 => socks5_connect(stream, last, target).await,
        ProxyKind::Http => http_connect(stream, last, target).await,
        ProxyKind::Tailscale => bail!("a tailscale hop must be the only hop"),
    }
}

async fn socks5_handshake<S>(mut stream: S, proxy: &Proxy) -> Result<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let methods: &[u8] = if proxy.user.is_some() {
        &[0x00, 0x02]
    } else {
        &[0x00]
    };
    stream.write_all(&[0x05, methods.len() as u8]).await?;
    stream.write_all(methods).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] == 0xff {
        bail!("proxy refused SOCKS5 methods");
    }
    if resp[1] == 0x02 {
        let user = proxy.user.as_deref().unwrap_or("");
        let pass = proxy.pass.as_deref().unwrap_or("");
        stream.write_all(&[0x01, user.len() as u8]).await?;
        stream.write_all(user.as_bytes()).await?;
        stream.write_all(&[pass.len() as u8]).await?;
        stream.write_all(pass.as_bytes()).await?;
        let mut auth = [0u8; 2];
        stream.read_exact(&mut auth).await?;
        if auth[1] != 0x00 {
            bail!("SOCKS5 authentication failed");
        }
    }
    Ok(stream)
}

/// Read an `ATYP`-prefixed address and port from a SOCKS5 reply.
async fn read_socks_addr<S>(stream: &mut S, atyp: u8) -> Result<SocketAddr>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt;
    match atyp {
        0x01 => {
            let mut b = [0u8; 6];
            stream.read_exact(&mut b).await?;
            Ok(SocketAddr::from((
                Ipv4Addr::new(b[0], b[1], b[2], b[3]),
                u16::from_be_bytes([b[4], b[5]]),
            )))
        }
        0x04 => {
            let mut b = [0u8; 18];
            stream.read_exact(&mut b).await?;
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[..16]);
            Ok(SocketAddr::from((
                std::net::Ipv6Addr::from(o),
                u16::from_be_bytes([b[16], b[17]]),
            )))
        }
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            let mut host = vec![0u8; l[0] as usize];
            stream.read_exact(&mut host).await?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            let host = String::from_utf8_lossy(&host).to_string();
            let ip: IpAddr = host
                .parse()
                .context("relay returned a name, not an address")?;
            Ok(SocketAddr::new(ip, u16::from_be_bytes(p)))
        }
        other => bail!("bad SOCKS5 address type {other}"),
    }
}

async fn socks5_connect<S>(stream: S, proxy: &Proxy, target: &str) -> Result<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let mut stream = socks5_handshake(stream, proxy).await?;
    // A chained hop is addressed as `unix:<path>`; there is no host:port, so
    // the whole string goes as a domain and the port is 0. The hop resolves it.
    let (host, port) = if target.starts_with("unix:") {
        (target.to_string(), 0u16)
    } else {
        split_target(target)?
    };
    let mut req = vec![0x05, 0x01, 0x00];
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = bare.parse::<std::net::Ipv6Addr>() {
        req.push(0x04);
        req.extend_from_slice(&ip.octets());
    } else {
        req.push(0x03);
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
    }
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;
    let mut head = [0u8; 4];
    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut head).await?;
    if head[1] != 0x00 {
        bail!("SOCKS5 connect to {target} failed: code {}", head[1]);
    }
    read_socks_addr(&mut stream, head[3]).await?;
    Ok(stream)
}

/// `UDP ASSOCIATE`: keep the TCP control connection and learn the relay address.
pub async fn socks5_udp_associate<S>(stream: S, proxy: &Proxy) -> Result<(S, SocketAddr)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = socks5_handshake(stream, proxy).await?;
    // DST.ADDR/DST.PORT are the client's expected source; 0.0.0.0:0 means any.
    stream
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        bail!("SOCKS5 UDP ASSOCIATE failed: code {}", head[1]);
    }
    let relay = read_socks_addr(&mut stream, head[3]).await?;
    Ok((stream, relay))
}

async fn http_connect<S>(mut stream: S, proxy: &Proxy, target: &str) -> Result<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let (Some(u), Some(p)) = (&proxy.user, &proxy.pass) {
        let creds = base64(format!("{u}:{p}").as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {creds}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            bail!("proxy closed during CONNECT");
        }
        buf.push(byte[0]);
        if buf.len() > 8192 {
            bail!("proxy CONNECT response too large");
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok());
    if status != Some(200) {
        bail!(
            "proxy CONNECT to {target} failed: {}",
            text.lines().next().unwrap_or("")
        );
    }
    Ok(stream)
}

pub fn split_target(target: &str) -> Result<(String, u16)> {
    let (host, port) = target
        .rsplit_once(':')
        .with_context(|| format!("target {target:?} has no port"))?;
    Ok((host.to_string(), port.parse().context("target port")?))
}

pub fn base64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Dial the proxy without sending a request; the caller speaks next.
pub async fn dial_proxy(proxy: &Proxy) -> Result<Upstream> {
    match &proxy.unix_path {
        Some(path) => Ok(Box::new(
            tokio::net::UnixStream::connect(path)
                .await
                .with_context(|| format!("connect to unix proxy {path}"))?,
        )),
        None => Ok(Box::new(
            tokio::net::TcpStream::connect(proxy.endpoint())
                .await
                .with_context(|| format!("connect to proxy {}", proxy.endpoint()))?,
        )),
    }
}

/// Wrap a datagram in a SOCKS5 UDP request header.
pub fn wrap_udp(payload: &[u8], ip: IpAddr, port: u16) -> Vec<u8> {
    let mut out = vec![0u8, 0, 0];
    match ip {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(payload);
    out
}


#[cfg(test)]
mod tests {
    use super::*;

        #[test]
        fn parses_proxy_specs() {
            let p = Proxy::parse("socks5://user:pass@127.0.0.1:1080").unwrap();
            assert_eq!(p.kind, ProxyKind::Socks5);
            assert_eq!(p.host, "127.0.0.1");
            assert_eq!(p.port, 1080);
            assert_eq!(p.user.as_deref(), Some("user"));
            assert_eq!(p.pass.as_deref(), Some("pass"));

            let p = Proxy::parse("http://proxy.example:8080").unwrap();
            assert_eq!(p.kind, ProxyKind::Http);
            assert_eq!(p.endpoint(), "proxy.example:8080");

            assert!(Proxy::parse("ftp://x:1").is_err());
            assert!(Proxy::parse("socks5://nohostport").is_err());
        }
        #[test]
        fn base64_matches_known_vectors() {
            assert_eq!(base64(b""), "");
            assert_eq!(base64(b"f"), "Zg==");
            assert_eq!(base64(b"fo"), "Zm8=");
            assert_eq!(base64(b"foo"), "Zm9v");
            assert_eq!(base64(b"foobar"), "Zm9vYmFy");
            assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
        }
        #[test]
        fn split_target_keeps_ipv4_and_names() {
            assert_eq!(
                split_target("example.com:443").unwrap(),
                ("example.com".into(), 443)
            );
            assert_eq!(split_target("1.2.3.4:80").unwrap(), ("1.2.3.4".into(), 80));
            assert!(split_target("noport").is_err());
        }
        #[test]
        fn rules_select_chains_in_order() {
            let default = vec![Proxy::parse("socks5://127.0.0.1:1").unwrap()];
            let rules = vec![
                Rule {
                    matcher: RuleMatch::Domain("example.com".into()),
                    proxy: Proxy::parse("socks5://127.0.0.1:2").unwrap(),
                },
                Rule {
                    matcher: RuleMatch::Cidr("10.0.0.0".parse().unwrap(), 8),
                    proxy: Proxy::parse("socks5://127.0.0.1:3").unwrap(),
                },
            ];
            assert_eq!(select_chain(&rules, &default, "example.com:80")[0].port, 2);
            assert_eq!(select_chain(&rules, &default, "EXAMPLE.com:443")[0].port, 2);
            assert_eq!(select_chain(&rules, &default, "10.1.2.3:443")[0].port, 3);
            assert_eq!(select_chain(&rules, &default, "1.2.3.4:80")[0].port, 1);
        }
        #[test]
        fn cidr_matching_is_exact() {
            let net: Ipv4Addr = "10.0.0.0".parse().unwrap();
            assert!(in_cidr("10.0.0.1".parse().unwrap(), net, 8));
            assert!(in_cidr("10.255.255.255".parse().unwrap(), net, 8));
            assert!(!in_cidr("11.0.0.1".parse().unwrap(), net, 8));
            assert!(in_cidr("1.2.3.4".parse().unwrap(), net, 0));
        }
}
