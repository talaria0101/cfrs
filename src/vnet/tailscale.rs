//! Reach a tailnet through an **unmodified** `tailscaled`.
//!
//! `tailscaled` already runs a userspace network stack in
//! `--tun=userspace-networking` mode: no TUN device, no `CAP_NET_ADMIN`, no
//! `AF_INET` bind. What it does not offer is a way in for a program whose host
//! forbids TCP binds and restricts TCP connects to a handful of ports. The
//! daemon's own `--socks5-server` is an `AF_INET` listener and is therefore
//! unreachable from such a program, and the daemon is a static Go binary, so
//! `LD_PRELOAD` cannot interpose it either.
//!
//! The one door that is always open is the daemon's **LocalAPI unix socket**.
//! `/localapi/v0/dial` upgrades the request to the `ts-dial` protocol and then
//! carries the connection over the tailnet, running the same `UserDial` path
//! the built-in SOCKS5 server uses. This module speaks that protocol and puts
//! a SOCKS5 / HTTP `CONNECT` front door in front of it, on an `AF_UNIX`
//! socket. `shim/cfrssocks.c` then redirects the `connect(2)` calls of an
//! unmodified program to that front door.
//!
//! Nothing here patches, recompiles or re-links Tailscale. It is the daemon's
//! documented local API and its userspace netstack.
//!
//! ```text
//! tailscaled --tun=userspace-networking --socket /run/tailscale/tailscaled.sock
//! cfrs net tailscale --socket /run/tailscale/tailscaled.sock \
//!                    --listen unix:/run/cfrssocks.sock
//! LD_PRELOAD=libcfrssocks.so CFRSSOCKS_PROXY=/run/cfrssocks.sock \
//!     curl http://100.x.y.z:8080/
//! ```

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf,
};
use tokio::net::{TcpStream, UnixStream};
use tokio::task::JoinHandle;

use crate::vnet::proxy::ProxyListen;
use crate::vnet::socks;

/// The path `tailscaled` uses when `--socket` is not given and the process is
/// running as root. A per-user install should pass `--socket` explicitly.
pub const DEFAULT_SOCKET: &str = "/var/run/tailscale/tailscaled.sock";

/// How long one proxied client connection may take, end to end.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(300);

/// Dials `host:port` through a running `tailscaled`'s userspace netstack.
#[derive(Clone, Debug)]
pub struct Dialer {
    socket: PathBuf,
}

impl Dialer {
    /// Use the LocalAPI socket at `socket`.
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    /// The LocalAPI socket this dialer talks to.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Dial `host:port` over the tailnet.
    ///
    /// `host` may be an IP literal, a MagicDNS name (without the trailing dot),
    /// or an FQDN. When the daemon reports that the address is *not* routed
    /// through the tailnet it returns `Dial-Self` and the resolved address; the
    /// connection is then dialled directly, which preserves the daemon's rule
    /// that it will not open a non-tailnet connection on the caller's behalf.
    pub async fn dial(&self, host: &str, port: u16) -> io::Result<Conn> {
        let mut stream = UnixStream::connect(&self.socket).await?;
        let request = format!(
            "POST /localapi/v0/dial HTTP/1.1\r\n\
             Host: local-tailscaled.sock\r\n\
             Connection: upgrade\r\n\
             Upgrade: ts-dial\r\n\
             Dial-Host: {host}\r\n\
             Dial-Port: {port}\r\n\
             Dial-Network: tcp\r\n\
             Content-Length: 0\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        let head = read_http_head(&mut stream).await?;
        let (status, headers) = parse_http_head(&head)?;
        if status == 101 {
            return Ok(Conn::Tailnet(stream));
        }
        if status == 200 && headers.get("dial-self").map(String::as_str) == Some("true") {
            let addr = headers.get("dial-addr").ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Dial-Self without Dial-Addr")
            })?;
            let addr: SocketAddr = addr.parse().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Dial-Addr {addr:?} is not an address"),
                )
            })?;
            return Ok(Conn::Direct(TcpStream::connect(addr).await?));
        }
        Err(io::Error::other(format!(
            "tailscaled refused the dial (status {status})"
        )))
    }
}

/// A connection established by [`Dialer::dial`].
pub enum Conn {
    /// The connection is carried by `tailscaled` over the tailnet.
    Tailnet(UnixStream),
    /// The address was not on the tailnet and was dialled directly.
    Direct(TcpStream),
}

impl AsyncRead for Conn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tailnet(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Direct(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tailnet(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Direct(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tailnet(stream) => Pin::new(stream).poll_flush(cx),
            Self::Direct(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tailnet(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Direct(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Read the HTTP response head, stopping *exactly* at the blank line so the
/// bytes of a `101` handover that follow are not consumed.
async fn read_http_head(stream: &mut UnixStream) -> io::Result<String> {
    const MAX_HEAD: usize = 64 * 1024;
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "tailscaled closed the local API connection before responding",
            ));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > MAX_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "local API response head is too large",
            ));
        }
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

fn parse_http_head(head: &str) -> io::Result<(u16, HashMap<String, String>)> {
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad status line {status_line:?}"),
            )
        })?;
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    Ok((status, headers))
}

/// A running front door. Dropping or [`abort`](Self::abort)ing it stops the
/// accept loop.
pub struct TailscaleProxy {
    pub listen: ProxyListen,
    accepts: JoinHandle<()>,
}

impl TailscaleProxy {
    /// Stop accepting.
    pub fn abort(self) {
        self.accepts.abort();
    }
}

/// Bind `listen` and serve SOCKS5 / HTTP `CONNECT` clients, dialling each
/// request through `dialer`.
pub async fn serve(
    dialer: Dialer,
    listen: ProxyListen,
    default_port: u16,
) -> Result<TailscaleProxy> {
    let accepts = match listen.clone() {
        ProxyListen::Tcp(bind) => {
            let listener = tokio::net::TcpListener::bind(bind)
                .await
                .with_context(|| format!("binding {bind}"))?;
            let dialer = dialer.clone();
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(handle_client(stream, dialer.clone(), default_port));
                }
            })
        }
        ProxyListen::Unix(path) => {
            #[cfg(unix)]
            {
                let listener = bind_unix(&path)?;
                let dialer = dialer.clone();
                tokio::spawn(async move {
                    while let Ok((stream, _)) = listener.accept().await {
                        tokio::spawn(handle_client(stream, dialer.clone(), default_port));
                    }
                })
            }
            #[cfg(not(unix))]
            {
                let _ = (dialer, path, default_port);
                anyhow::bail!("unix sockets are not supported on this platform");
            }
        }
    };
    Ok(TailscaleProxy { listen, accepts })
}

#[cfg(unix)]
fn bind_unix(path: &Path) -> Result<tokio::net::UnixListener> {
    let _ = std::fs::remove_file(path);
    tokio::net::UnixListener::bind(path).with_context(|| format!("binding unix:{}", path.display()))
}

async fn handle_client<S>(stream: S, dialer: Dialer, default_port: u16)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);
    let first = match reader.fill_buf().await {
        Ok(buffer) if !buffer.is_empty() => buffer[0],
        _ => return,
    };
    let is_socks = socks::looks_like_socks5(first);
    let request = if is_socks {
        match socks::socks5_read_request(&mut reader).await {
            Ok(request) => request,
            Err(_) => return,
        }
    } else if let Ok(request) = socks::http_read_connect(&mut reader).await {
        request
    } else {
        return;
    };

    let port = if request.port == 0 {
        default_port
    } else {
        request.port
    };
    let host = request.host.to_string();
    match dialer.dial(&host, port).await {
        Ok(mut remote) => {
            let reply = if is_socks {
                socks::socks5_reply(&mut reader, 0x00, None).await
            } else {
                socks::http_connect_ok(&mut reader).await
            };
            if reply.is_err() {
                return;
            }
            let _ = tokio::time::timeout(
                CLIENT_TIMEOUT,
                tokio::io::copy_bidirectional(&mut reader, &mut remote),
            )
            .await;
        }
        Err(err) => {
            let message = err.to_string();
            if is_socks {
                let _ =
                    socks::socks5_reply(&mut reader, socks::socks5_code_for_error(&message), None)
                        .await;
            } else {
                let _ = socks::http_connect_reply(&mut reader, 502, "Bad Gateway").await;
            }
        }
    }
}

/// The Tailscale IPv4 range, `100.64.0.0/10` (CGNAT).
pub fn is_tailnet_v4(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..128).contains(&octets[1])
}

/// The Tailscale IPv6 range, `fd7a:115c:a1e0::/48`.
pub fn is_tailnet_v6(ip: std::net::Ipv6Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 0xfd
        && octets[1] == 0x7a
        && octets[2] == 0x11
        && octets[3] == 0x5c
        && octets[4] == 0xa1
        && octets[5] == 0xe0
}

/// Whether `ip` is a Tailscale address (used by the shim's filter, and
/// available to callers that want the same rule).
pub fn is_tailnet(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_tailnet_v4(v4),
        IpAddr::V6(v6) => is_tailnet_v6(v6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A fake `tailscaled` LocalAPI: it answers `/localapi/v0/dial` with a
    /// `101`, then echoes everything after the handover. It records the
    /// `Dial-Host` it was asked for.
    async fn fake_tailscaled(
        listener: tokio::net::UnixListener,
        seen: std::sync::Arc<tokio::sync::Mutex<Vec<String>>>,
    ) {
        if let Ok((mut stream, _)) = listener.accept().await {
            let head = read_head(&mut stream).await;
            if let Some(host) = header_value(&head, "dial-host") {
                seen.lock().await.push(host);
            }
            stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: ts-dial\r\nConnection: upgrade\r\n\r\n")
                .await
                .unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }

    async fn read_head(stream: &mut UnixStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while stream.read(&mut byte).await.unwrap_or(0) == 1 {
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&head).into_owned()
    }

    fn header_value(head: &str, name: &str) -> Option<String> {
        head.split("\r\n").find_map(|line| {
            let (n, v) = line.split_once(':')?;
            if n.trim().eq_ignore_ascii_case(name) {
                Some(v.trim().to_string())
            } else {
                None
            }
        })
    }

    #[test]
    fn recognises_tailnet_addresses() {
        assert!(is_tailnet("100.119.211.25".parse().unwrap()));
        assert!(is_tailnet("100.64.0.0".parse().unwrap()));
        assert!(is_tailnet("100.127.255.255".parse().unwrap()));
        assert!(!is_tailnet("100.63.255.255".parse().unwrap()));
        assert!(!is_tailnet("100.128.0.0".parse().unwrap()));
        assert!(!is_tailnet("192.168.1.1".parse().unwrap()));
        assert!(is_tailnet("fd7a:115c:a1e0::1b38:d31c".parse().unwrap()));
        assert!(!is_tailnet("fd00::1".parse().unwrap()));
    }

    #[tokio::test]
    async fn dialer_performs_the_ts_dial_upgrade() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tailscaled.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let seen = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        tokio::spawn(fake_tailscaled(listener, seen.clone()));

        let dialer = Dialer::new(&path);
        let mut conn = dialer.dial("100.82.22.3", 8080).await.expect("dial");
        conn.write_all(b"hello tailnet").await.unwrap();
        let mut echo = [0u8; 13];
        conn.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"hello tailnet");
        assert_eq!(seen.lock().await.as_slice(), &["100.82.22.3".to_string()]);
    }

    #[tokio::test]
    async fn socks5_client_is_spliced_through_the_bridge() {
        let dir = tempfile::tempdir().unwrap();
        let api = dir.path().join("tailscaled.sock");
        let api_listener = tokio::net::UnixListener::bind(&api).unwrap();
        let seen = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        tokio::spawn(fake_tailscaled(api_listener, seen.clone()));

        let front = dir.path().join("front.sock");
        let proxy = serve(Dialer::new(&api), ProxyListen::Unix(front.clone()), 80)
            .await
            .expect("serve");

        let mut client = UnixStream::connect(&front).await.unwrap();
        // SOCKS5 greeting, then CONNECT 100.82.22.3:8080.
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        client
            .write_all(&[5, 1, 0, 1, 100, 82, 22, 3, 0x1f, 0x90])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 5);
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
        assert_eq!(seen.lock().await.as_slice(), &["100.82.22.3".to_string()]);
        proxy.abort();
    }
}
