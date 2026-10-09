//! Carrying a flow the supervisor has taken over.
//!
//! The interception side lives in `main.rs`; this module is the other half: once
//! the child's fd has been claimed from the pre-inherited pool, the bytes on it
//! have to go somewhere real. `proxy.rs` speaks the upstream protocols, and
//! this dials them and then relays in both directions.
//!
//! ## Why a pool rather than SECCOMP_IOCTL_NOTIF_ADDFD
//!
//! ADDFD IS the obvious way to hand a child a fresh fd, and it WORKS here: all
//! four (flags, newfd_flags) combinations inject a descriptor, including
//! `newfd_flags=0`. This comment previously said the opposite, on the strength of
//! a probe that issued four ADDFD calls against one notification, so the first
//! success consumed it and the rest reported ENOENT. See
//! `probe/addfd_clean.c`.
//!
//! The pool is still what this tool uses, because ADDFD is not a drop-in swap:
//! it hands over a descriptor without resolving the pending syscall, so the
//! supervisor must answer the notification as well, and the fd numbering stops
//! being under our control. That is a migration to do deliberately, not a
//! limitation to route around.
//!
//! Given that, the fds are created BEFORE `exec` and inherited. That constrains
//! the design in one specific way, which is the whole trick here:
//!
//!   The child's `socket()` call is intercepted, and we answer it with the fd
//!   NUMBER of a pool entry we are holding. The child then uses that number, and
//!   the number happens to refer to a real connected socketpair we own the other
//!   end of. No new fd is ever created after exec.
//!
//! That only works because the pool fds are real and known, which is why
//! `main::Pool` hands back the actual descriptor rather than a slot index.
//!
//! ## The filter must not apply to the supervisor
//!
//! The filter notifies on `socket`, `bind` and `connect`, and the tool makes
//! those calls itself when it dials an upstream. A notifying syscall blocks its
//! thread until someone services the listener, and the only listener is the
//! supervisor thread that is itself blocked, so a filtered supervisor deadlocks
//! on its own dial: measured in `probe/selfdl.c`, where a process whose own
//! `connect` notifies never returns from that `connect` (exit 124 under
//! `timeout 10`).
//!
//! The fix is structural rather than clever. The filter is installed into the
//! CHILD by a pre-exec hook, so the supervisor's threads are never filtered and
//! can dial freely. `Notifier::install` is called from inside `pre_exec`, which
//! runs in the forked child before `exec`, and never in the parent.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use crate::proxy::{http_connect, socks5_connect};

/// Where a proxied flow should actually go.
#[derive(Debug, Clone)]
pub enum Route {
    /// Straight TCP to a host and port.
    Tcp { host: String, port: u16 },
    /// An AF_UNIX socket on this machine.
    Unix { path: String },
    /// Through a proxy, which is asked to open the connection to the destination.
    Proxy {
        dest_host: String,
        dest_port: u16,
        proxy_host: String,
        proxy_port: u16,
        socks5: bool,
    },
}

/// How to reach the far end of a proxied flow.
#[derive(Debug, Clone)]
pub struct Dial {
    pub route: Route,
}

impl Dial {
    pub fn describe(&self) -> String {
        match &self.route {
            Route::Tcp { host, port } => format!("{host}:{port} (direct TCP)"),
            Route::Unix { path } => format!("{path} (AF_UNIX)"),
            Route::Proxy { dest_host, dest_port, proxy_host, socks5, .. } => format!(
                "{dest_host}:{dest_port} via {} {proxy_host}",
                if *socks5 { "SOCKS5" } else { "HTTP CONNECT" }
            ),
        }
    }
}

/// A connected flow, ready to be relayed.
///
/// Holds the read side and a duplicate for the write side, because the two relay
/// directions run on separate threads and a single socket cannot be shared
/// between them as a trait object. `dial` captures the duplicate while the
/// socket is still a concrete `TcpStream`, which is the only point at which
/// `try_clone` is available.
pub struct Flow {
    read: Box<dyn crate::proxy::ReadWrite>,
    write: Box<dyn crate::proxy::ReadWrite>,
    /// Bytes already over-read while parsing the proxy's response, which belong
    /// to the read direction.
    prefetched: Vec<u8>,
}

/// Establish the flow and block until the child can be told whether it worked.
///
/// THIS RUNS OFF THE SUPERVISOR THREAD, and that is not an optimisation.
///
/// A seccomp user-notification listener only receives notifications raised by
/// tasks whose filter is in scope, and the supervisor's own syscalls are in
/// scope: the filter is installed before any threads exist, so every thread the
/// tool creates is filtered too. If the supervisor dials the upstream itself,
/// that dial raises a notification, and the only listener is the very thread
/// now blocked inside the dial. Nothing can answer it, so the tool deadlocks
/// with the child frozen inside its own `connect`.
///
/// Measured directly: a process whose own `connect` notifies, with no one
/// servicing the listener, never returns from that `connect`
/// (`probe/selfdl.c`, which times out). Passing the notification through from
/// the same thread does not help, because the thread cannot reach its own
/// listener while it is blocked.
///
/// So the dial happens on a worker thread while the supervisor keeps servicing
/// notifications. The child's `connect` is answered once the dial result is
/// known, which is the behaviour a caller expects: a refused upstream must
/// surface as a failed `connect`, not as a success that delivers nothing.
pub fn dial_async(
    dial: Dial,
    timeout: Duration,
) -> std::sync::mpsc::Receiver<std::io::Result<Flow>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(dial_blocking(&dial, timeout));
    });
    rx
}

fn dial_blocking(dial: &Dial, connect_timeout: Duration) -> std::io::Result<Flow> {
    match &dial.route {
        Route::Unix { path } => {
            let sock = UnixStream::connect(path)?;
            Ok(Flow::from_unix(sock))
        }
        Route::Tcp { host, port } => {
            let sock = TcpStream::connect_timeout(&resolve(host, *port)?, connect_timeout)?;
            let _ = sock.set_nodelay(true);
            Ok(Flow::from_socket(sock))
        }
        Route::Proxy { dest_host, dest_port, proxy_host, proxy_port, socks5 } => {
            let mut sock =
                TcpStream::connect_timeout(&resolve(proxy_host, *proxy_port)?, connect_timeout)?;
            let _ = sock.set_nodelay(true);
            // The destination goes to the PROXY as a name when it is not a
            // literal address, so the proxy resolves it. That is what lets a
            // child with no working DNS reach a host by name, and it is why the
            // name is not resolved here even when this process could resolve it.
            let prefetched = if *socks5 {
                let want_domain = dest_host.parse::<std::net::Ipv4Addr>().is_err();
                socks5_connect(&mut sock, dest_host, *dest_port, want_domain)?
            } else {
                http_connect(&mut sock, dest_host, *dest_port)?
            };
            Ok(Flow::from_socket_with(sock, prefetched))
        }
    }
}

impl Flow {
    fn from_socket(sock: TcpStream) -> Flow {
        Flow::from_socket_with(sock, Vec::new())
    }

    fn from_unix(sock: UnixStream) -> Flow {
        let write = sock.try_clone().expect("cloning the unix origin socket");
        Flow {
            read: Box::new(sock),
            write: Box::new(write),
            prefetched: Vec::new(),
        }
    }

    fn from_socket_with(sock: TcpStream, prefetched: Vec<u8>) -> Flow {
        // Cloned while the socket is still a concrete type. Without this the two
        // relay directions could not each own a handle, and one of them would
        // have to be dropped rather than served.
        let write = sock.try_clone().expect("cloning the upstream socket");
        Flow {
            read: Box::new(sock),
            write: Box::new(write),
            prefetched,
        }
    }
}

fn resolve(host: &str, port: u16) -> std::io::Result<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;
    (host, port).to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{host} resolved to no addresses"),
        )
    })
}

/// Wrap a single stream as a `Flow` with no prefetched bytes, for the accept
/// direction where the far side is an already-connected unix socket rather than
/// a proxied one.
pub fn one_shot(sock: UnixStream) -> Flow {
    Flow::from_unix(sock)
}

/// Bytes moved in each direction, for the end-of-flow log line.
#[derive(Debug, Default, Clone, Copy)]
pub struct Counted {
    pub to_far: u64,
    pub to_child: u64,
}

impl std::fmt::Display for Counted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{},{}", self.to_far, self.to_child)
    }
}

/// Relay bytes both ways until both directions finish.
///
/// Two threads rather than a select loop: each direction has an unambiguous end
/// condition here, so this stays readable and needs no extra dependency. Both
/// halves are joined, so the function returns only when the flow is really over
/// and the caller can log the totals.
///
/// The bytes buffered from the proxy handshake go to the read direction and are
/// written out before the socket is touched, or the first bytes of the tunnel
/// are dropped when the server coalesces its response with the start of the
/// payload.
pub fn relay(child_side: UnixStream, flow: Flow) -> Counted {
    let Flow { read: mut far_read, write: mut far_write, prefetched } = flow;
    // One clone feeds the read direction; the original feeds the write direction.
    let read_end = child_side.try_clone().expect("cloning a unix stream for the relay");

    // Far -> child.
    let up = std::thread::spawn(move || {
        let mut to_child = read_end;
        let mut buf = [0u8; 65536];
        let mut n = 0u64;
        let mut pos = 0usize;
        while pos < prefetched.len() {
            let take = std::cmp::min(buf.len(), prefetched.len() - pos);
            if to_child.write_all(&prefetched[pos..pos + take]).is_err() {
                return n;
            }
            pos += take;
            n += take as u64;
        }
        loop {
            match far_read.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(k) => {
                    if to_child.write_all(&buf[..k]).is_err() {
                        break;
                    }
                    n += k as u64;
                }
            }
        }
        n
    });

    // Child -> far.
    let down = std::thread::spawn(move || {
        let mut from_child = child_side;
        let mut buf = [0u8; 65536];
        let mut n = 0u64;
        loop {
            match from_child.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(k) => {
                    // The far side may accept a partial write, so this must be
                    // write_all rather than write.
                    if far_write.write_all(&buf[..k]).is_err() {
                        break;
                    }
                    n += k as u64;
                }
            }
        }
        let _ = far_write.flush();
        n
    });

    // `up` carries far -> child and `down` carries child -> far, so each join is
    // assigned to the direction its thread actually pumps. Crossing these two
    // is invisible in the totals, since both counts still get printed, and it
    // makes the log line say the opposite of what happened: a child that wrote
    // 32 bytes and read 62 was logged as 62,32 "each way", which reads as if
    // the two were equal.
    let to_child = up.join().unwrap_or(0);
    let to_far = down.join().unwrap_or(0);
    Counted { to_far, to_child }
}
#[cfg(test)]
mod tests {
    use super::*;

    /// A pair of in-memory byte queues standing in for the two sockets, so the
    /// relay's ordering behaviour is testable without a network.
    struct Pipe {
        rx: std::io::Cursor<Vec<u8>>,
        tx: Vec<u8>,
    }
    impl Pipe {
        fn new(input: &[u8]) -> Pipe {
            Pipe { rx: std::io::Cursor::new(input.to_vec()), tx: Vec::new() }
        }
    }
    impl Read for Pipe {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = std::io::Read::read(&mut self.rx, buf)?;
            Ok(n)
        }
    }
    impl Write for Pipe {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.tx.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The regression the prefetch logic exists for: bytes over-read while
    /// parsing the proxy's reply are the tunnel's first bytes. If the relay drops
    /// them, a stream that begins with server output silently loses its first
    /// bytes, which looks like a protocol bug in whatever is on the other end.
    #[test]
    fn handshake_leftovers_reach_the_child_first() {
        let (a, mut b) = UnixStream::pair().unwrap();
        // The far side will contribute "PAYLOAD" as prefetched bytes, then EOF.
        let far = Flow {
            read: Box::new(Pipe::new(b"")),
            write: Box::new(Pipe::new(b"")),
            prefetched: b"PAYLOAD".to_vec(),
        };
        std::thread::spawn(move || {
            let _ = relay(a, far);
        });
        let mut got = Vec::new();
        b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 7];
        // Read exactly the prefetched length so the assertion is about those
        // bytes and not about how much happened to arrive.
        let _ = b.read(&mut buf);
        got.extend_from_slice(&buf);
        assert_eq!(&got, b"PAYLOAD");
    }

    /// The two counts are what the end-of-flow log line prints, so they have to
    /// be in the direction their names claim. A child that writes 4 bytes and
    /// reads 10 must log `to_child=10, to_far=4`. Assigning the two join results
    /// the wrong way round still prints two plausible numbers, which is why this
    /// was shipped and stayed shipped: nothing failed, the totals just quietly
    /// described the opposite of what happened.
    #[test]
    fn the_counts_name_the_direction_they_pumped() {
        // Both halves of the pair must be closed for both relay threads to see
        // EOF: `child_peer` stands in for the child process, and dropping it
        // after writing is what ends the far -> child direction.
        let (child_side, mut child_peer) = UnixStream::pair().unwrap();

        // Distinct lengths per direction, so a swap cannot be mistaken for
        // symmetry: the far side delivers 10 bytes and EOFs, the child writes 4.
        let far = Flow {
            read: Box::new(Pipe::new(b"0123456789")),
            write: Box::new(Pipe::new(b"")),
            prefetched: Vec::new(),
        };

        // Stand in for the child: read what the far side sends, write 4 bytes back,
        // then close. Reading first is what keeps the far -> child direction
        // alive: if the socket closes before relay writes to it, the write
        // fails with EPIPE and the count comes back as 0.
        let reader = std::thread::spawn(move || {
            use std::io::Read as _;
            use std::io::Write as _;
            let mut got = [0u8; 10];
            child_peer.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"0123456789", "the far side's bytes must arrive in order");
            child_peer.write_all(b"abcd").unwrap();
            child_peer.flush().unwrap();
        });

        let counted = relay(child_side, far);
        reader.join().unwrap();

        assert_eq!(counted.to_child, 10, "the 10 far bytes went TO THE CHILD");
        assert_eq!(counted.to_far, 4, "the 4 child bytes went TO THE FAR SIDE");
        // And the order the end-of-flow log line prints them in.
        assert_eq!(counted.to_string(), "4,10");
    }

    #[test]
    fn describe_says_where_the_flow_goes() {
        let proxied = Dial {
            route: Route::Proxy {
                dest_host: "db.internal".into(),
                dest_port: 5432,
                proxy_host: "proxy.corp".into(),
                proxy_port: 3128,
                socks5: false,
            },
        };
        let d = proxied.describe();
        assert!(d.contains("db.internal:5432"), "{d}");
        assert!(d.contains("HTTP CONNECT"), "{d}");

        let socks = Dial {
            route: match proxied.route {
                Route::Proxy {
                    dest_host,
                    dest_port,
                    proxy_host,
                    proxy_port,
                    ..
                } => Route::Proxy {
                    dest_host,
                    dest_port,
                    proxy_host,
                    proxy_port,
                    socks5: true,
                },
                other => other,
            },
        };
        assert!(socks.describe().contains("SOCKS5"));

        let direct = Dial { route: Route::Tcp { host: "h".into(), port: 1 } };
        assert!(direct.describe().contains("direct TCP"));
        let unix = Dial { route: Route::Unix { path: "/tmp/x".into() } };
        assert!(unix.describe().contains("/tmp/x"));
    }
}
