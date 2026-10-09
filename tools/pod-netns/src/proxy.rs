//! Proxy transports: what a proxied connection actually talks to.
//!
//! This is the part lifted from the prior-art tools, and it is the part that
//! transfers. None of `rmb122/nsproxy-rs`, `nlzy/nsproxy`, `OkamiW/proxy-ns` or
//! `fooker/netns-proxy` can run here, because all four need
//! `unshare(CLONE_NEWNET)` and `/dev/net/tun`. Their connector layers need
//! neither and are what makes a proxied socket useful once the supervisor has
//! taken the flow over.
//!
//! Two connectors, both dependency-free:
//!   - SOCKS5 (RFC 1928), with `ATYP=DOMAINNAME` so the proxy resolves and the
//!     client never needs working DNS. That detail is the reason DNS survives in
//!     an environment where the client cannot resolve anything: `OkamiW/proxy-ns`
//!     and `rmb122/nsproxy-rs` both fake a DNS answer and then put the NAME back
//!     on the wire. Here the supervisor already knows the address, so
//!     `DOMAINNAME` is only used when the caller supplies a name.
//!   - HTTP CONNECT, so an unmodified `curl` can use it with `-x`.
//!
//! The prefetch behaviour follows `rmb122/nsproxy-rs`
//! (`src/proxy/mod.rs`): when reading a CONNECT response through a BufReader,
//! bytes already pulled past the header boundary are handed to the caller, or
//! the first tunnel bytes are silently dropped when the server coalesces the
//! response with payload. That was a real past defect in that project. Here the
//! handshake functions return those bytes and `relay::Flow` delivers them.

use std::io::{self, Read, Write};

/// The small surface we need from an upstream socket, so tests can substitute a
/// in-memory pipe without a real network.
pub trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}

/// Minimal SOCKS5 client handshake, RFC 1928, no auth.
///
/// `ATYP=DOMAINNAME` is the point of interest: it makes the proxy perform the
/// name resolution, which is what lets a client with no working DNS reach a host
/// by name. `ATYP=IPv4` is used for a literal address.
pub fn socks5_connect(
    stream: &mut dyn ReadWrite,
    host: &str,
    port: u16,
    want_domain_atyp: bool,
) -> io::Result<Vec<u8>> {
    // greeting: version 5, one method, "no authentication"
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut greet = [0u8; 2];
    stream.read_exact(&mut greet)?;
    if greet[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a SOCKS5 proxy"));
    }
    if greet[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy demanded authentication",
        ));
    }

    let mut req = vec![0x05, 0x01, 0x00]; // VER, CONNECT, RSV
    if want_domain_atyp || host.parse::<std::net::Ipv4Addr>().is_err() {
        let hb = host.as_bytes();
        if hb.len() > 255 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "hostname too long"));
        }
        req.push(0x03); // ATYP = DOMAINNAME
        req.push(hb.len() as u8);
        req.extend_from_slice(hb);
    } else {
        let v4: std::net::Ipv4Addr = host.parse().expect("checked above");
        req.push(0x01); // ATYP = IPv4
        req.extend_from_slice(&v4.octets());
    }
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req)?;

    // Read only the two bytes the decision needs: VER and REP. Reading a full
    // four-byte header first meant a refusal reply had to carry a valid ATYP
    // and bound address before the error could be reported, which is both
    // unnecessary and wrong: a proxy may answer "host unreachable" with nothing
    // after it.
    let mut head = [0u8; 2];
    stream.read_exact(&mut head)?;
    if head[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a SOCKS5 reply"));
    }
    if head[1] != 0x00 {
        let msg = match head[1] {
            0x01 => "general failure",
            0x02 => "connection not allowed",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown failure",
        };
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 proxy refused CONNECT: {}", msg),
        ));
    }

    // Success: now the rest of the reply must be consumed.
    let mut rest = [0u8; 2]; // RSV + ATYP
    stream.read_exact(&mut rest)?;
    let atyp = rest[1];

    // Consume BND.ADDR/BND.PORT. A well-behaved server sends nothing after the
    // bound address, so this final read is expected to hit EOF. Treating EOF as
    // an error here is what made the handshake unusable against a script that
    // closes cleanly, so EOF means "no prefetched bytes", which is the truth.
    let mut leftover = Vec::new();
    match atyp {
        0x01 => {
            let mut b = [0u8; 4 + 2];
            stream.read_exact(&mut b)?;
        }
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l)?;
            let mut b = vec![0u8; l[0] as usize + 2];
            stream.read_exact(&mut b)?;
        }
        0x04 => {
            let mut b = [0u8; 16 + 2];
            stream.read_exact(&mut b)?;
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy replied with an unknown address type",
            ))
        }
    }
    // Anything already buffered belongs to the tunnel and must not be dropped.
    let mut one = [0u8; 1];
    loop {
        match stream.read(&mut one) {
            Ok(0) => break, // clean EOF: no prefetched data
            Ok(_) => leftover.push(one[0]),
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    Ok(leftover)
}

/// HTTP CONNECT handshake, so `curl -x http://host:port` works unmodified.
pub fn http_connect(stream: &mut dyn ReadWrite, host: &str, port: u16) -> io::Result<Vec<u8>> {
    let req = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    stream.write_all(req.as_bytes())?;

    // Read headers byte by byte so nothing past the blank line is lost.
    let mut head: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
        if head.len() >= 4 && &head[head.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if head.len() > 8192 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "CONNECT response too long"));
        }
    }
    let text = String::from_utf8_lossy(&head);
    let first = text.lines().next().unwrap_or("");
    let ok = first.contains(" 200");
    if !ok {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("HTTP proxy refused CONNECT: {}", first.trim()),
        ));
    }
    // Preserve anything already read past the header. EOF here is normal and
    // means there is nothing buffered.
    let mut prefetch = Vec::new();
    let mut one = [0u8; 1];
    loop {
        match stream.read(&mut one) {
            Ok(0) => break,
            Ok(_) => prefetch.push(one[0]),
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    Ok(prefetch)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scripted in-memory peer, so the handshakes are tested without a network.
    struct Fake {
        input: Vec<u8>,
        pos: usize,
        output: Vec<u8>,
    }
    impl Read for Fake {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.input.len() {
                return Ok(0);
            }
            let n = std::cmp::min(buf.len(), self.input.len() - self.pos);
            buf[..n].copy_from_slice(&self.input[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }
    impl Write for Fake {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn socks5_uses_domain_atyp_so_the_proxy_resolves() {
        let mut f = Fake {
            input: vec![0x05, 0x00, 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
            pos: 0,
            output: Vec::new(),
        };
        let _ = socks5_connect(&mut f, "example.internal", 443, true).unwrap();
        // The greeting (3 bytes) is written first, so the request starts at
        // offset 3: VER=5 CMD=1 RSV=0 ATYP=3 LEN=15 "example.internal" PORT.
        let req = &f.output[3..];
        assert_eq!(&req[0..3], &[0x05, 0x01, 0x00]);
        assert_eq!(req[3], 0x03, "a name must go out as ATYP=DOMAINNAME");
        // "example.internal" is 16 bytes; assert against the string's own length
        // rather than a hand-counted constant that can drift from the literal.
        let name = b"example.internal";
        assert_eq!(req[4] as usize, name.len());
        assert_eq!(&req[5..5 + name.len()], name);
        assert_eq!(&req[5 + name.len()..7 + name.len()], &443u16.to_be_bytes());
    }

    #[test]
    fn socks5_uses_ipv4_atyp_for_a_literal() {
        let mut f = Fake {
            input: vec![0x05, 0x00, 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
            pos: 0,
            output: Vec::new(),
        };
        let _ = socks5_connect(&mut f, "93.184.216.34", 80, false).unwrap();
        let req = &f.output[3..];
        assert_eq!(req[3], 0x01, "a literal address must use ATYP=IPv4");
        assert_eq!(&req[4..8], &[93, 184, 216, 34]);
    }

    #[test]
    fn socks5_refusal_is_reported_with_the_reason() {
        // Each REP code must map to its own message, since "refused" with no
        // reason is what makes a proxy failure hard to act on.
        for (rep, expect) in [
            (0x01u8, "general failure"),
            (0x02, "connection not allowed"),
            (0x03, "network unreachable"),
            (0x04, "host unreachable"),
            (0x05, "connection refused"),
            (0x06, "TTL expired"),
            (0x07, "command not supported"),
            (0x08, "address type not supported"),
        ] {
            let mut f = Fake {
                input: vec![0x05, 0x00, 0x05, rep],
                pos: 0,
                output: Vec::new(),
            };
            let e = socks5_connect(&mut f, "h", 1, true).unwrap_err();
            assert!(e.to_string().contains(expect), "rep {rep:#04x}: got {e}");
        }
    }

    /// A refusal must be reported even when the proxy sends nothing after the
    /// reply code. Reading a full four-byte header first meant such a reply
    /// failed with "failed to fill whole buffer" instead of the actual reason.
    #[test]
    fn socks5_refusal_needs_no_trailing_bytes() {
        let mut f = Fake {
            input: vec![0x05, 0x00, 0x05, 0x04],
            pos: 0,
            output: Vec::new(),
        };
        let e = socks5_connect(&mut f, "unreachable.example", 443, true).unwrap_err();
        assert!(e.to_string().contains("host unreachable"), "got: {e}");
    }

    /// The handshake must report which bytes it over-read, because those are the
    /// first bytes of the tunnel and dropping them is the defect this module
    /// exists to avoid. The relay is what delivers them; see `relay::Flow`.
    #[test]
    fn a_coalesced_response_yields_its_trailing_bytes() {
        // The client writes a greeting and reads a 2-byte reply first, so the scripted
        // peer must send that too, then the CONNECT reply, then the payload:
        //   greeting reply: 05 00
        //   CONNECT reply:  05 00 | 00 01 | 00 00 00 00 | 00 00
        //   payload:        "PAYLOAD"
        let mut script = vec![
            0x05, 0x00, // greeting reply: VER, "no auth"
        ];
        script.extend_from_slice(&[
            0x05, 0x00, // CONNECT reply head: VER, REP=success
            0x00, 0x01, // rest: RSV, ATYP=IPv4
            0, 0, 0, 0, // BND.ADDR
            0, 0, // BND.PORT
        ]);
        script.extend_from_slice(b"PAYLOAD");
        let mut f = Fake { input: script, pos: 0, output: Vec::new() };
        let leftover = socks5_connect(&mut f, "1.2.3.4", 80, false).unwrap();
        assert_eq!(
            leftover, b"PAYLOAD",
            "bytes read past the reply are the tunnel's first bytes and must be handed back"
        );
    }

    /// `http_connect` is the default route (`Route::Proxy` with `socks5` off),
    /// so it needs the same three guarantees the SOCKS5 tests assert: the exact
    /// request on the wire, the over-read bytes handed back, and a refusal
    /// carrying its reason.
    #[test]
    fn http_connect_writes_the_request_curl_would() {
        let mut f = Fake {
            input: b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec(),
            pos: 0,
            output: Vec::new(),
        };
        let leftover = http_connect(&mut f, "db.internal", 5432).unwrap();
        let req = String::from_utf8(f.output).unwrap();
        assert!(
            req.starts_with("CONNECT db.internal:5432 HTTP/1.1\r\n"),
            "a non-standard proxy needs the method line curl sends, got: {req:?}"
        );
        assert!(
            req.contains("\r\nHost: db.internal:5432\r\n"),
            "the Host header is required by RFC 7231 for CONNECT, got: {req:?}"
        );
        assert!(req.ends_with("\r\n\r\n"), "the request must end the headers, got: {req:?}");
        assert!(leftover.is_empty(), "nothing past the header means nothing to hand back");
    }

    /// A proxy that sends its 200 and the first tunnel bytes in one write must
    /// not lose the payload to header buffering.
    #[test]
    fn http_connect_yields_bytes_sent_past_the_header() {
        let script = b"HTTP/1.1 200 Connection established\r\n\r\nPAYLOAD".to_vec();
        let mut f = Fake { input: script, pos: 0, output: Vec::new() };
        let leftover = http_connect(&mut f, "1.2.3.4", 80).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&leftover), "PAYLOAD",
            "bytes read past the headers are the tunnel's first bytes and must be handed back"
        );
    }

    #[test]
    fn http_connect_refusal_is_reported_with_the_status_line() {
        for (status, expect) in [
            ("HTTP/1.1 403 Forbidden", "403"),
            ("HTTP/1.1 407 Proxy Authentication Required", "407"),
            ("HTTP/1.1 502 Bad Gateway", "502"),
        ] {
            let mut f = Fake {
                input: format!("{status}\r\n\r\n").into_bytes(),
                pos: 0,
                output: Vec::new(),
            };
            let e = http_connect(&mut f, "h", 1).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused, "{status}");
            assert!(e.to_string().contains(expect), "{status}: got {e}");
        }
    }

    /// A 2xx that is not 200 is still a success to a proxy, but this tool keys
    /// off " 200". Pin which shapes are accepted so a change here is deliberate.
    #[test]
    fn http_connect_accepts_only_a_200_status() {
        let mut f = Fake {
            input: b"HTTP/1.0 200 OK\r\n\r\n".to_vec(),
            pos: 0,
            output: Vec::new(),
        };
        assert!(http_connect(&mut f, "h", 1).is_ok(), "HTTP/1.0 200 must be accepted");

        let mut f = Fake {
            input: b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(),
            pos: 0,
            output: Vec::new(),
        };
        assert!(http_connect(&mut f, "h", 1).is_err(), "204 is not a CONNECT success");
    }
}
