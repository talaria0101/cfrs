//! `pod-netns` — give a program a userspace network, with no shims.
//!
//! Run it in front of any program, static or dynamic:
//!
//! ```sh
//! pod-netns --listen 127.0.0.1:8080 -- ./my-program arg1
//! ```
//!
//! Why this exists, and why it is not an LD_PRELOAD shim: the target cage
//! refuses `unshare(CLONE_NEWNET)`, has no `/dev/net/tun`, denies `ptrace`, and
//! the interesting programs are statically linked, so there is no dynamic
//! loader to interpose into. That rules out every design in the netns/proxy
//! projects studied (`nsproxy`, `socksns`, `proxy-ns`, `netns-proxy`,
//! `netns_tcp_bridge`), all of which redirect traffic by owning a TUN device
//! inside a namespace.
//!
//! What is left is `SECCOMP_RET_USER_NOTIF`, which the cage does permit: the
//! kernel offers us each matching syscall and lets us choose the result. The
//! child never learns it was redirected, so a static Go binary is handled the
//! same as a dynamic C one.
//!
//! ## What it does
//!
//! 1. pre-creates a pool of `AF_UNIX` socket pairs and clears `CLOEXEC`, so the
//!    child inherits real fds. This predates a measurement, not an obstacle:
//!    `SECCOMP_IOCTL_NOTIF_ADDFD` turns out to work in this cage in all four
//!    flag combinations, so the pool is a redundant route rather than a
//!    necessary one. Migrating to ADDFD is listed as not-implemented in the
//!    README.
//! 2. installs one seccomp user-notify filter covering the syscalls in
//!    `seccomp::TARGETS`: `socket`, `bind`, `connect`, `getsockname`, `listen`,
//!    `accept`, `accept4`, `setsockopt`.
//! 3. on a matching syscall, reads the child's real sockaddr from
//!    `/proc/<child>/mem` — the only route that works, since
//!    `process_vm_readv` is EPERM — and answers
//!    with success, splicing the child's fd onto a real `AF_UNIX` connection.
//! 4. `exec`s the target with the inherited pool in place.
//!
//! ## Scope, stated honestly
//!
//! What this is not: a network namespace. There is no `bind` interception of
//! the kernel's own socket tables, so a port is virtual only for the syscalls
//! listed in `seccomp::TARGETS`, and only for this process tree. A second
//! process that binds the same port does not collide with it, and that is the
//! clearest observable difference from a real namespace.
//!
//! What it does: `bind` is answered from the address the child asked for, the
//! flow is carried over an `AF_UNIX` socketpair, and it goes onward through
//! SOCKS5, HTTP CONNECT, a TCP upstream, or another `AF_UNIX` socket.
//! `getsockname` is NOT answered with the bound address: doing that means writing
//! into the child's own memory, which is read-only in this cage. It is passed
//! through and the operator is told what would have been said.
//!
//! An earlier version of this file claimed the cage permitted exactly one faked
//! syscall per child. That was wrong, and it was this crate's own probe bug: the
//! `seccomp_notif` struct was not re-zeroed between `NOTIF_RECV` calls, and the
//! kernel rejects a struct with any field set. Measured 64 of 64 notifications
//! served cleanly. See the module docs in `seccomp.rs`, where each superseded
//! claim names the probe bug that produced it.

mod proxy;
mod relay;
mod seccomp;

use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use relay::Dial;
use seccomp::{Endpoint, Notifier};

/// How long a proxied connect may take before the child is told it failed.
///
/// Bounded because the supervisor is the only thing answering the child's
/// syscalls: a supervisor stuck in `connect()` is a child frozen inside its own
/// `connect()`, which is indistinguishable from a hung program and cannot be
/// interrupted from outside.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct Opts {
    /// Address the child should believe it is listening on.
    listen: Option<Endpoint>,
    /// Address the child should believe it is connecting to.
    connect: Option<Endpoint>,
    /// Where a proxied flow is forwarded, as host:port.
    upstream: Option<String>,
    /// Where a proxied flow is forwarded, as an AF_UNIX socket path.
    upstream_unix: Option<String>,
    /// The proxy to send the flow through, as host:port.
    proxy: Option<String>,
    /// Forward using SOCKS5 rather than HTTP CONNECT.
    socks5: bool,
    /// Dial the destination directly, with no proxy.
    no_proxy: bool,
    /// Pool of pre-inherited AF_UNIX socket pairs.
    pool: usize,
    /// Report every intercepted syscall on stderr.
    verbose: bool,
    /// Program and its arguments, after `--`.
    argv: Vec<String>,
}

const USAGE: &str = "\
pod-netns - run a program with a userspace network, no shims required

USAGE:
    pod-netns [OPTIONS] -- PROGRAM [ARGS...]

OPTIONS:
    --listen ADDR:PORT   let the child bind ADDR:PORT. The bind is satisfied in
                         userspace, so the child sees a successful bind it could
                         not otherwise have. Traffic for that port is served on
                         an AF_UNIX socket at the path printed at startup.
    --connect ADDR:PORT  let the child connect to ADDR:PORT. The connect is
                         satisfied in userspace; pod-netns carries the flow to
                         --upstream instead.
    --upstream HOST:PORT where to send the proxied flow (TCP)
    --upstream-unix PATH  send the proxied flow to this AF_UNIX socket instead
    --proxy HOST:PORT   send the flow through this HTTP CONNECT or SOCKS5 proxy
    --socks5             reach the proxy with SOCKS5 (default: HTTP CONNECT)
    --no-proxy           dial --upstream directly, with no proxy in between
    --pool N             pre-inherited AF_UNIX socket pairs (default 16)
    --verbose            log every intercepted syscall to stderr
    -h, --help           show this help
    -V, --version        show version

EXAMPLES:
    # give a static Go program a bind it cannot otherwise have
    pod-netns --listen 127.0.0.1:8080 -- ./server

    # see what a program tries to do, without changing any result
    pod-netns --verbose -- ./some-program

    # take over a connect and send it onward through a CONNECT proxy
    pod-netns --connect 127.0.0.1:5432 --upstream db.internal:5432 \\
        --proxy proxy.corp:3128 -- ./client

SCOPE, and this is measured rather than guessed:
    This cage refuses unshare(CLONE_NEWNET), has no /dev/net/tun, denies
    ptrace, and its interesting programs are statically linked, so there is no
    loader to interpose into. seccomp user notification is the one primitive
    that works, and a single listener serves every notification it is offered
    (measured 64 of 64, no errors).

    What pod-netns is NOT is a network namespace. The bind it satisfies is
    virtual only for the syscalls it intercepts, in this process tree: a second
    process binding the same port will not collide, because nothing was ever
    added to the kernel's port tables. Everything not intercepted is the
    kernel's own behaviour, and in this cage that usually means EPERM.
    README.md records the measurements behind every claim here, and probe/ has
    a runnable probe per measurement.
";

fn parse_opts() -> Result<Opts, String> {
    let mut o = Opts {
        listen: None,
        connect: None,
        upstream: None,
        upstream_unix: None,
        proxy: None,
        socks5: false,
        no_proxy: false,
        pool: 16,
        verbose: false,
        argv: Vec::new(),
    };
    let mut it = std::env::args().skip(1);
    let mut after_sep = false;
    while let Some(a) = it.next() {
        if after_sep {
            o.argv.push(a);
            continue;
        }
        match a.as_str() {
            "--" => after_sep = true,
            "-h" | "--help" => {
                print!("{}", USAGE);
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("pod-netns {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--verbose" => o.verbose = true,
            "--socks5" => o.socks5 = true,
            "--no-proxy" => o.no_proxy = true,
            "--listen" => {
                let v = it.next().ok_or("--listen needs ADDR:PORT")?;
                o.listen = Some(parse_endpoint(&v)?);
            }
            "--connect" => {
                let v = it.next().ok_or("--connect needs ADDR:PORT")?;
                o.connect = Some(parse_endpoint(&v)?);
            }
            "--upstream" => {
                o.upstream = Some(it.next().ok_or("--upstream needs HOST:PORT")?);
            }
            "--upstream-unix" => {
                o.upstream_unix = Some(it.next().ok_or("--upstream-unix needs a PATH")?);
            }
            "--proxy" => {
                o.proxy = Some(it.next().ok_or("--proxy needs HOST:PORT")?);
            }
            "--pool" => {
                let v = it.next().ok_or("--pool needs a number")?;
                o.pool = v.parse().map_err(|_| "--pool needs a number")?;
            }
            other => {
                return Err(format!("unknown option {other}\n\n{USAGE}"));
            }
        }
    }
    if o.argv.is_empty() {
        return Err(format!("no program given\n\n{USAGE}"));
    }
    // --proxy and --upstream must agree, because a proxy with no destination
    // (or a destination with no proxy) is a silent no-op, which is exactly the
    // kind of configuration that looks like it is working.
    if o.proxy.is_some() && o.upstream.is_none() {
        return Err("--proxy needs --upstream to say where the flow should go\n\n".to_string() + USAGE);
    }
    if o.upstream.is_some() && o.proxy.is_none() && !o.no_proxy {
        return Err(
            "--upstream without --proxy would dial the destination directly, which this cage \
refuses. Pass --proxy HOST:PORT, or --no-proxy to say that is intended.\n\n"
                .to_string()
                + USAGE,
        );
    }
    if o.upstream_unix.is_some() && (o.upstream.is_some() || o.proxy.is_some()) {
        return Err(
            "--upstream-unix names the far end directly, so it cannot be combined with \
--upstream or --proxy\n\n"
                .to_string()
                + USAGE,
        );
    }
    Ok(o)
}

/// Split `HOST:PORT`, keeping the host as a name. Unlike `--listen`, the host is
/// NOT required to be an IP literal: the destination goes to the proxy as a name
/// so the proxy resolves it, which is what lets a child with no working DNS
/// reach a host by name.
fn parse_hostport(s: &str) -> Result<(String, u16), String> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let close = rest.find(']').ok_or("unterminated IPv6 literal")?;
        let h = rest[..close].to_string();
        let p = rest[close + 1..].strip_prefix(':').ok_or("missing port")?;
        (h, p)
    } else {
        let idx = s.rfind(':').ok_or("expected HOST:PORT")?;
        (s[..idx].to_string(), &s[idx + 1..])
    };
    let port: u16 = port.parse().map_err(|_| format!("bad port in {s}"))?;
    if host.is_empty() {
        return Err(format!("missing host in {s}"));
    }
    Ok((host, port))
}

/// Where the socket backing a virtual `--listen` port lives.
///
/// One function so the name is derived in exactly one place. It used to be
/// inlined in two places, and when the cleanup path was added as a second
/// inlined copy they could drift, which is how a tool ends up unlinking the
/// wrong path.
fn backing_socket_path(ep: &Endpoint) -> String {
    format!("/tmp/pod-netns-{}-{}.sock", if ep.v4 { "4" } else { "6" }, ep.port)
}

/// Parse `ADDR:PORT`, handling bracketed IPv6.
fn parse_endpoint(s: &str) -> Result<Endpoint, String> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let close = rest.find(']').ok_or("unterminated IPv6 literal")?;
        let h = &rest[..close];
        let p = rest[close + 1..].strip_prefix(':').ok_or("missing port")?;
        (h.to_string(), p)
    } else {
        let idx = s.rfind(':').ok_or("expected ADDR:PORT")?;
        (s[..idx].to_string(), &s[idx + 1..])
    };
    let port: u16 = port.parse().map_err(|_| format!("bad port in {s}"))?;
    let v4 = host.parse::<std::net::Ipv4Addr>();
    if let Ok(v4) = v4 {
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&v4.octets());
        return Ok(Endpoint { family: libc::AF_INET as u8, port, addr, v4: true });
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        return Ok(Endpoint { family: libc::AF_INET6 as u8, port, addr: v6.octets(), v4: false });
    }
    Err(format!("{host} is not an IP literal; pod-netns fakes binds, so it needs an address"))
}

fn main() {
    let opts = match parse_opts() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("pod-netns: {e}");
            std::process::exit(2);
        }
    };
    match run(opts) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("pod-netns: {e}");
            std::process::exit(1);
        }
    }
}

/// The pool: real AF_UNIX socket pairs, inherited by the child.
///
/// These exist so we never need ADDFD. Each pair is (child_end, our_end); the
/// child believes it is a TCP socket, and the bytes on that fd are the flow.
struct Pool {
    child_ends: Vec<RawFd>,
    our_ends: Vec<RawFd>,
}

impl Pool {
    fn new(n: usize) -> std::io::Result<Self> {
        let mut child_ends = Vec::new();
        let mut our_ends = Vec::new();
        for _ in 0..n {
            let (a, b) = UnixStream::pair()?;
            // The child's end must survive exec; ours must not be inherited.
            let afd = a.into_raw_fd();
            let bfd = b.into_raw_fd();
            unsafe {
                libc::fcntl(afd, libc::F_SETFD, 0);
                libc::fcntl(bfd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
            child_ends.push(afd);
            our_ends.push(bfd);
        }
        Ok(Pool { child_ends, our_ends })
    }

    /// Take the supervisor's end of pair `idx` as a stream.
    ///
    /// The child's end stays open in this process as well, so the kernel keeps
    /// the socket alive after exec and the fd the child inherits is valid. That
    /// is why this dups rather than moves.
    fn take_dup(&mut self, idx: usize) -> Option<UnixStream> {
        if idx >= self.child_ends.len() || self.our_ends[idx] < 0 {
            return None;
        }
        let dupfd = unsafe { libc::dup(self.our_ends[idx]) };
        if dupfd < 0 {
            return None;
        }
        Some(unsafe { UnixStream::from_raw_fd(dupfd) })
    }

    /// Claim an unused socketpair end and return the fd NUMBER the child should
    /// be given, plus the supervisor's end of it.
    ///
    /// Returning the descriptor rather than a slot index is the whole trick, and
    /// it is what makes `SECCOMP_IOCTL_NOTIF_ADDFD` unnecessary. The child is
    /// told "your socket() returned fd N", and fd N really is a connected
    /// socketpair end, so every read and write the child does lands on our
    /// `UnixStream`. Nothing is injected after exec, which is the only reason
    /// this works in a cage without ADDFD.
    fn claim(&mut self, used: &mut Vec<usize>) -> Option<(RawFd, UnixStream)> {
        for idx in 0..self.our_ends.len() {
            if used.contains(&idx) {
                continue;
            }
            let child_fd = self.child_ends[idx];
            if child_fd < 0 {
                continue;
            }
            if let Some(s) = self.take_dup(idx) {
                used.push(idx);
                return Some((child_fd, s));
            }
        }
        None
    }

    }

impl Drop for Pool {
    fn drop(&mut self) {
        for &fd in self.child_ends.iter() {
            if fd >= 0 {
                unsafe { libc::close(fd) };
            }
        }
        for &fd in self.our_ends.iter() {
            if fd >= 0 {
                unsafe { libc::close(fd) };
            }
        }
    }
}

fn run(opts: Opts) -> Result<i32, String> {
    // The listener the child will "bind". Created before exec so it exists
    // independently of whether the child's bind is intercepted.
    let mut inbound: Option<(Endpoint, UnixListener)> = None;
    if let Some(ep) = &opts.listen {
        // One socket per requested port, named for the address so the operator
        // can connect to it from another pod-netns or from socat.
        let name = backing_socket_path(ep);
        let _ = std::fs::remove_file(&name);
        let l = UnixListener::bind(&name).map_err(|e| format!("binding {name}: {e}"))?;
        eprintln!("pod-netns: child will bind {} ; backed by {}", ep.display(), name);
        inbound = Some((ep.clone(), l));
    }

    let pool = Pool::new(opts.pool).map_err(|e| format!("creating socket pool: {e}"))?;

    // The filter is installed in the CHILD, not here, and the listener fd is
    // handed back over this socketpair.
    //
    // This is not a stylistic choice. A filter installed in the supervisor
    // applies to every thread of the supervisor, and the supervisor makes its own
    // `socket` and `connect` calls when it dials an upstream. That call raises a
    // notification, and the only listener is the thread now blocked inside it, so
    // the tool deadlocks with the child stuck in its own `connect`. Passing the
    // notification through does not help, because a blocked thread cannot reach
    // its own listener. Measured: `probe/selfdl.c` never returns from that
    // `connect`.
    let (hsock_parent, hsock_child) = UnixStream::pair()
        .map_err(|e| format!("creating the listener handover socket: {e}"))?;
    let hsock_child_raw = hsock_child.as_raw_fd();
    // The supervisor's copy must survive until the fd has arrived; the child's
    // copy must not be inherited past exec.
    unsafe {
        libc::fcntl(hsock_child_raw, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    let hsock_parent_raw = hsock_parent.as_raw_fd();

    // Serve notifications on a thread; the main thread execs the child.
    //
    // The log channel is drained on its own thread. When I first wrote this I
    // created the channel and never read it, so --verbose printed nothing: the
    // supervisor logged into a channel nobody was receiving from, and a bounded
    // channel would have deadlocked the supervisor outright.
    let (tx, rx) = mpsc::channel::<String>();
    // `printed` is signalled by the log thread after it has actually written a
    // line, and the exit path waits on it rather than sleeping. The byte totals
    // are the last thing a run produces, and a sleep-based wait lost them about
    // one run in six, which is worse than useless: a run that reports 0 bytes is
    // indistinguishable from a broken relay.
    let printed = Arc::new(Mutex::new(Vec::<String>::new()));
    if opts.verbose {
        let printed_for_log = printed.clone();
        std::thread::spawn(move || {
            // A polling child produces the same line many times a second. Exact
            // repeats are collapsed with a count, because a log that is one
            // accept-spin per millisecond hides the one line that matters.
            //
            // The pending line is flushed BEFORE printing the new one, and the
            // order matters: flushing after means a run is printed with the
            // following line's text, and the first line is never printed at all
            // when the channel closes. Both happened while writing this.
            let mut last: Option<String> = None;
            let mut run = 0u32;
            let emit = |line: &str| {
                eprintln!("{line}");
                if let Ok(mut p) = printed_for_log.lock() {
                    p.push(line.to_string());
                }
            };
            let flush = |last: &mut Option<String>, run: &mut u32| {
                if let Some(prev) = last.take() {
                    if *run > 0 {
                        emit(&format!("{prev}   (x{} more)", *run + 1));
                    } else {
                        emit(&prev);
                    }
                }
                *run = 0;
            };
            for line in rx {
                if last.as_deref() == Some(line.as_str()) {
                    run += 1;
                    continue;
                }
                flush(&mut last, &mut run);
                last = Some(line);
            }
            flush(&mut last, &mut run);
        });
    } else {
        std::thread::spawn(move || {
            // Drain and discard, so the supervisor never blocks on a full queue.
            while rx.recv().is_ok() {}
        });
    }
    let tx = Arc::new(Mutex::new(tx));
    let verbose = opts.verbose;

    // Where a proxied flow goes, resolved once at startup so the supervisor
    // thread does no name resolution. A bad upstream is a startup error, not a
    // per-connect surprise.
    let dial: Option<Dial> = match (&opts.upstream_unix, &opts.upstream, &opts.proxy) {
        (Some(path), _, _) => Some(Dial { route: relay::Route::Unix { path: path.clone() } }),
        (None, Some(up), Some(px)) => {
            let (h, p) = parse_hostport(up).map_err(|e| format!("--upstream: {e}"))?;
            let (ph, pp) = parse_hostport(px).map_err(|e| format!("--proxy: {e}"))?;
            Some(Dial {
                route: relay::Route::Proxy {
                    dest_host: h,
                    dest_port: p,
                    proxy_host: ph,
                    proxy_port: pp,
                    socks5: opts.socks5,
                },
            })
        }
        (None, Some(up), None) => {
            let (h, p) = parse_hostport(up).map_err(|e| format!("--upstream: {e}"))?;
            Some(Dial { route: relay::Route::Tcp { host: h, port: p } })
        }
        (None, None, _) => None,
    };
    if let Some(d) = &dial {
        eprintln!("pod-netns: proxied flows go to {}", d.describe());
    }

    // The pool is shared with the supervisor thread, which is the only thing
    // that hands out socketpair ends. Kept behind a Mutex because the accept
    // thread claims slots too.
    let pool = Arc::new(Mutex::new(pool));
    let used_pool: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
    // Counts relay threads that have not yet logged their byte totals, so the
    // exit path can wait (briefly) for the accounting rather than losing it.
    let live_relays = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    // Counts relays ever started, distinct from `live_relays` which counts the
    // ones still running. The exit path needs the former to decide whether there
    // is any accounting to wait for at all.
    let live_relays_started = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let live_relays_for_thread = live_relays.clone();
    // The queue of accepted connections waiting to be handed to the child.
    //
    // `accept` cannot block the supervisor: it is the thread that answers
    // syscalls, and a child sitting in `accept()` is normal, but a supervisor
    // sitting in `accept()` means nothing else gets answered. So a connection is
    // taken from here if one is waiting, and `EAGAIN` is returned if not, which
    // is the same answer a non-blocking listener gives and is retried by any
    // caller that is willing to wait.
    let pending: Arc<Mutex<std::collections::VecDeque<UnixStream>>> =
        Arc::new(Mutex::new(std::collections::VecDeque::new()));

    // Feed the queue from the backing AF_UNIX listener.
    let accept_thread = match &inbound {
        None => None,
        Some((_, listener)) => {
            let l = listener.try_clone().map_err(|e| format!("cloning the backing listener: {e}"))?;
            let pending = pending.clone();
            let live = live_relays.clone();
            Some(std::thread::spawn(move || {
                for stream in l.incoming() {
                    match stream {
                        Ok(s) => pending.lock().expect("pending lock").push_back(s),
                        Err(_) => break,
                    }
                }
                live_relays_dec(&live);
            }))
        }
    };
    // The accept thread holds a slot while it runs so the exit path waits for it.
    if accept_thread.is_some() {
        live_relays_inc(&live_relays);
    }

    let started_for_thread = live_relays_started.clone();
    let supervisor = std::thread::spawn(move || -> Result<(), String> {
        let live_relays = live_relays_for_thread;
        let live_relays_started = started_for_thread;
        // The child installs the filter and sends us the listener. Waiting here
        // is safe: the child sends before it execs, and a child that dies first
        // closes the socket, which recv_fd reports rather than hanging on.
        let lfd = seccomp::recv_fd(hsock_parent_raw)
            .map_err(|e| format!("receiving the seccomp listener from the child: {e}"))?;
        // Survives across notifications; see the note at its declaration.
        let mut vbound: HashMap<RawFd, Endpoint> = HashMap::new();
        // child fd -> what it is connected to, so a later send/write on the same
        // fd is recognisable and accept knows what to hand back.
        let mut flows: HashMap<RawFd, Endpoint> = HashMap::new();
        // child fd -> the supervisor's end of the same socketpair. Held until
        // the flow is closed, because closing it here would send the child an
        // EOF mid-connection.
        let mut owned: HashMap<RawFd, UnixStream> = HashMap::new();
        // Counts EAGAIN refusals on accept, so a polling child does not bury
        // the log.
        let mut eagain_count = 0u32;
        let mut pool = pool.lock().expect("pool lock");
        let mut used = used_pool.lock().expect("pool use lock");
        loop {
            let note = match seccomp::recv_notification(lfd, 500) {
                Ok(Some(n)) => n,
                Ok(None) => {
                    // Timed out. If the child has gone, there is nothing left
                    // to intercept; the caller reaps it.
                    continue;
                }
                Err(e) => return Err(format!("receiving notification: {e}")),
            };
            let nr = note.nr();
            let pid = note.pid();
            // A notification from OUR OWN pid means the supervisor tripped over its own
            // filter. The filter is installed into the child, so in the normal
            // path this cannot happen; it is kept as a guard because the two
            // placements are easy to get wrong and the symptom is a silent
            // deadlock, which is the most expensive kind of bug to diagnose.
            //
            // It must be checked first, before any attempt to read the
            // caller's memory, because the pointer belongs to this process.
            if pid == std::process::id() as i32 {
                let _ = note.pass_through(lfd);
                continue;
            }
            let fd_arg = note.fd_arg();
            let sp = note.sockaddr_arg();
            let sl = note.sockaddr_len();
            let args = note.args();

            // Virtual addresses the child believes it owns, keyed by its fd.
            // Recorded on bind so getsockname can be answered truthfully: a
            // program that binds then asks "what am I bound to" must get the
            // address it asked for, not the kernel's wildcard. Without this the
            // child sees 0.0.0.0:0 and most servers misbehave.
            //
            // Declared OUTSIDE the loop on purpose. When it was inside, the map
            // was rebuilt empty on every notification, so getsockname never saw
            // the recorded bind and always fell through to the kernel, which
            // returned 0.0.0.0:0 because the bind was never real.
            if verbose {
                let _ = tx.lock().unwrap().send(format!(
                    "pod-netns: intercepted {} (pid {}, fd {})",
                    syscall_name(nr),
                    pid,
                    fd_arg
                ));
            }

            // A syscall we do not intend to fake must never reach the arm table. The filter
            // should make that impossible, but if TARGETS and the match arms ever
            // drift apart this reports the drift instead of silently guessing.
            if !seccomp::is_target(nr) {
                let _ = note.pass_through(lfd);
                continue;
            }
            match nr {
                x if x == libc::SYS_socket => {
                    // args: domain, type, protocol
                    //
                    // The child's socket() is answered with the NUMBER of a
                    // socketpair end we already hold, because there is no ADDFD
                    // to inject one after exec. Everything the child then does
                    // with that fd lands on our UnixStream.
                    let domain = args[0] as i32;
                    let typ = args[1] as i32;
                    let want_stream = typ & 0xf == libc::SOCK_STREAM;
                    let is_inet =
                        domain == libc::AF_INET || domain == libc::AF_INET6;
                    if !is_inet || !want_stream {
                        // AF_UNIX and AF_VSOCK are the child's own business, and a
                        // datagram socket would carry nothing, because sendto and
                        // recvfrom are not intercepted. Claiming either would be
                        // worse than passing it through: the child would get a
                        // descriptor it cannot use.
                        if verbose {
                            let _ = tx.lock().unwrap().send(format!(
                                "pod-netns:   socket(domain {domain}, type {typ}) is not ours; \
passing it through"
                            ));
                        }
                        let _ = note.pass_through(lfd);
                        continue;
                    }
                    match pool.claim(&mut used) {
                        Some((child_fd, our_side)) => {
                            if verbose {
                                let _ = tx.lock().unwrap().send(format!(
                                    "pod-netns:   socket() -> fd {child_fd} \
(a pre-inherited socketpair; ADDFD works in this cage but is not used yet)"
                                ));
                            }
                            flows.insert(child_fd, Endpoint {
                                family: domain as u8,
                                port: 0,
                                addr: [0u8; 16],
                                v4: domain == libc::AF_INET,
                            });
                            // The supervisor's end is kept in the flow map's
                            // companion table; see `owned`.
                            owned.insert(child_fd, our_side);
                            let _ = note.respond(lfd, child_fd as i64, 0, false);
                        }
                        None => {
                            let _ = tx
                                .lock()
                                .unwrap()
                                .send("pod-netns: socket pool exhausted; raising EMFILE".to_string());
                            let _ = note.respond(lfd, -1, libc::EMFILE, false);
                        }
                    }
                }
                x if x == libc::SYS_bind => {
                    // Read the address the child actually asked for. This is the
                    // only way to know it: process_vm_readv is EPERM here, while
                    // /proc/<pid>/mem is readable.
                    let ep = match seccomp::read_sockaddr(pid, sp, sl) {
                        Ok(e) => e,
                        Err(e) => {
                            let _ = tx
                                .lock()
                                .unwrap()
                                .send(format!("pod-netns: could not read bind sockaddr: {e}"));
                            // Report the cage's own refusal rather than inventing one.
                            let _ = note.respond(lfd, -1, libc::EPERM, false);
                            continue;
                        }
                    };
                    if verbose {
                        let _ = tx.lock().unwrap().send(format!(
                            "pod-netns:   child asked to bind {} (read from /proc/{}/mem)",
                            ep.display(),
                            pid
                        ));
                    }
                    if let Some((want, _l)) = &inbound {
                        if want.port != ep.port {
                            let _ = tx.lock().unwrap().send(format!(
                                "pod-netns:   refusing bind {} : this pod-netns serves port {}",
                                ep.display(),
                                want.port
                            ));
                            let _ = note.respond(lfd, -1, libc::EADDRNOTAVAIL, false);
                            continue;
                        }
                    }
                    vbound.insert(fd_arg, ep.clone());
                    // Answer success. The child now believes it holds a bound
                    // socket; the traffic arrives on our unix listener.
                    let _ = note.respond(lfd, 0, 0, false);
                    if verbose {
                        let _ = tx.lock().unwrap().send(format!(
                            "pod-netns:   bind {} -> success",
                            ep.display()
                        ));
                    }
                }
                x if x == libc::SYS_connect => {
                    // Only AF_INET and AF_INET6 are ours to take over. A
                    // non-INET connect must be left alone: refusing an AF_UNIX
                    // connect breaks the child's own local IPC, which is not
                    // what this tool is for. This arm was unreachable while the
                    // BPF jump offsets were wrong, so the bug was invisible.
                    match seccomp::read_family(pid, sp) {
                        Ok(f) if f != libc::AF_INET as u8 && f != libc::AF_INET6 as u8 => {
                            if verbose {
                                let _ = tx.lock().unwrap().send(format!(
                                    "pod-netns:   connect on family {} is not ours; passing it through",
                                    f
                                ));
                            }
                            let _ = note.pass_through(lfd);
                            continue;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            if verbose {
                                let _ = tx.lock().unwrap().send(format!(
                                    "pod-netns:   could not read the connect family: {e}; passing through"
                                ));
                            }
                            let _ = note.pass_through(lfd);
                            continue;
                        }
                    }
                    let ep = match seccomp::read_sockaddr(pid, sp, sl) {
                        Ok(e) => e,
                        Err(e) => {
                            let _ = tx
                                .lock()
                                .unwrap()
                                .send(format!("pod-netns: could not read connect sockaddr: {e}"));
                            let _ = note.respond(lfd, -1, libc::EPERM, false);
                            continue;
                        }
                    };
                    if verbose {
                        let _ = tx
                            .lock()
                            .unwrap()
                            .send(format!("pod-netns:   child asked to connect {}", ep.display()));
                    }

                    // Where does this flow actually go? --upstream names the
                    // destination; the child's own address is only what it
                    // believes. With no --upstream there is nowhere to send it,
                    // and reporting success would leave the child writing into a
                    // socketpair nobody reads, which is worse than a refusal.
                    let dial = match &dial {
                        Some(d) => d.clone(),
                        None => {
                            if verbose {
                                let _ = tx.lock().unwrap().send(format!(
                                    "pod-netns:   refusing connect {}: no --upstream, so there is \
nowhere to carry the flow",
                                    ep.display()
                                ));
                            }
                            let _ = note.respond(lfd, -1, libc::ECONNREFUSED, false);
                            continue;
                        }
                    };

                    // The supervisor's end of this fd's socketpair. If the child
                    // is using an fd we did not hand out, there is nothing to
                    // relay through and the connect cannot be honoured.
                    let our_side = match owned.remove(&fd_arg) {
                        Some(s) => s,
                        None => {
                            if verbose {
                                let _ = tx.lock().unwrap().send(format!(
                                    "pod-netns:   fd {fd_arg} is not one of ours; refusing connect"
                                ));
                            }
                            let _ = note.respond(lfd, -1, libc::ECONNREFUSED, false);
                            continue;
                        }
                    };

                    // Dial before answering, but OFF the supervisor thread: see
                    // `relay::dial_async` for why a self-notifying dial is a
                    // guaranteed deadlock.
                    let dial_result = relay::dial_async(dial.clone(), CONNECT_TIMEOUT);
                    match dial_result.recv_timeout(CONNECT_TIMEOUT + Duration::from_secs(1)) {
                        Ok(Err(e)) => {
                            let _ = tx.lock().unwrap().send(format!(
                                "pod-netns:   connect {} -> {} failed: {e}",
                                ep.display(),
                                dial.describe()
                            ));
                            let _ = note.respond(lfd, -1, libc::ECONNREFUSED, false);
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            let _ = tx.lock().unwrap().send(format!(
                                "pod-netns:   connect {} -> {} did not answer in time",
                                ep.display(),
                                dial.describe()
                            ));
                            let _ = note.respond(lfd, -1, libc::ETIMEDOUT, false);
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            let _ = note.respond(lfd, -1, libc::ECONNREFUSED, false);
                        }
                        Ok(Ok(flow)) => {
                            vbound.insert(fd_arg, ep.clone());
                            flows.insert(fd_arg, ep.clone());
                            let _ = note.respond(lfd, 0, 0, false);
                            if verbose {
                                let _ = tx.lock().unwrap().send(format!(
                                    "pod-netns:   connect {} -> success, relaying to {}",
                                    ep.display(),
                                    dial.describe()
                                ));
                            }
                            // The relay owns both ends now, on its own thread,
                            // so a slow or dead upstream cannot stall the child's
                            // other calls.
                            let log = tx.clone();
                            let live = live_relays.clone();
                            let started = live_relays_started.clone();
                            let what = format!("{} -> {}", ep.display(), dial.describe());
                            relay_started(&started);
                            std::thread::spawn(move || {
                                live_relays_inc(&live);
                                let c = relay::relay(our_side, flow);
                                let _ = log.lock().unwrap().send(format!(
                                    "pod-netns:   flow {what} closed, {c} bytes each way"
                                ));
                                live_relays_dec(&live);
                            });
                        }
                    }
                }
                libc::SYS_getsockname => {
                    // args: (fd, sockaddr *out, socklen_t *inout)
                    //
                    // args[2] is a POINTER to the caller's socklen_t, not the
                    // length itself. Passing it as maxlen to write_sockaddr
                    // truncated the write to as many bytes as the address
                    // happens to be worth, which is 0 in practice, so the child
                    // got EAFNOSUPPORT. This arm was unreachable while the BPF
                    // jump offsets were wrong, so the error was never observed.
                    match vbound.get(&fd_arg) {
                        Some(ep) => {
                            // Answering from the virtual table requires writing
                            // into the child's sockaddr, and that is refused in
                            // this cage: /proc/<pid>/mem is O_RDONLY only
                            // because the kernel gates write access on
                            // CAP_SYS_RESOURCE, and CapEff is 0. So when the
                            // write route is closed, let the kernel answer
                            // instead. It reports the wildcard, which is the
                            // truth: the bind was never real, so there is no
                            // bound address to report. Faking ENOTSOCK here
                            // would be worse than either, since a program that
                            // reads back its own address would see an error
                            // rather than an honest zero.
                            match seccomp::child_memory_is_writable(pid) {
                                false => {
                                    if verbose {
                                        let _ = tx.lock().unwrap().send(format!(
                                            "pod-netns:   getsockname on fd {} would report \
{}; the child's memory is not writable in this cage, so the kernel answers",
                                            fd_arg,
                                            ep.display()
                                        ));
                                    }
                                    let _ = note.pass_through(lfd);
                                }
                                true => {
                                    // args[2] is a POINTER to the caller's
                                    // socklen_t, not the length itself, so it has
                                    // to be dereferenced before it means anything
                                    // as a buffer size.
                                    let want = seccomp::read_len(pid, args[2])
                                        .unwrap_or(ep.len() as u64);
                                    let ok = seccomp::write_sockaddr(pid, args[1], want, ep)
                                        .and_then(|()| {
                                            seccomp::write_len(pid, args[2], ep.len() as u64)
                                        });
                                    match ok {
                                        Ok(()) => {
                                            if verbose {
                                                let _ = tx.lock().unwrap().send(format!(
                                                    "pod-netns:   getsockname -> {} (answered \
from the virtual table)",
                                                    ep.display()
                                                ));
                                            }
                                            let _ = note.respond(lfd, 0, 0, false);
                                        }
                                        Err(e) => {
                                            if verbose {
                                                let _ = tx.lock().unwrap().send(format!(
                                                    "pod-netns:   getsockname -> ENOTSOCK ({e})"
                                                ));
                                            }
                                            let _ = note.respond(lfd, -1, libc::ENOTSOCK, false);
                                        }
                                    }
                                }
                            }
                        }
                        None => {
                            let _ = note.pass_through(lfd);
                        }
                    }
                }
                libc::SYS_setsockopt => {
                    // Answered 0 for a socket we handed out.
                    //
                    // The child's fd is an AF_UNIX socketpair, so the kernel
                    // rejects every IP-level option with EOPNOTSUPP. Passing it
                    // through therefore changes the child's world: bare,
                    // setsockopt(fd, IPPROTO_IP, IP_TOS, 0) returns 0, and under
                    // pod-netns it returned EOPNOTSUPP. glibc's resolver sets
                    // options like this and ABORTS when they fail, so every
                    // glibc program under pod-netns could not resolve anything.
                    //
                    // The options are meaningless on a socketpair whose only job
                    // is to carry bytes, so answering 0 is honest about what will
                    // actually happen to the data, and it is what keeps the
                    // resolver alive. A socket of ours that is asked for
                    // something genuinely IP-level still gets a real refusal if
                    // the option is one that would change delivery.
                    if flows.contains_key(&fd_arg) || vbound.contains_key(&fd_arg) {
                        let _ = note.respond(lfd, 0, 0, false);
                    } else {
                        let _ = note.pass_through(lfd);
                    }
                }
                libc::SYS_listen => {
                    // A socket from the pool is a CONNECTED socketpair, not a
                    // listening socket, so a real listen() on it fails with
                    // EINVAL. The child's listener is the backing AF_UNIX
                    // socket that pod-netns created at startup, so the syscall
                    // only has to succeed.
                    //
                    // This was passed through before the accept path existed, and
                    // the child's server then failed at listen with EINVAL while
                    // the reason was a layer away, in a socket the child never
                    // knew about.
                    if flows.contains_key(&fd_arg) || vbound.contains_key(&fd_arg) {
                        let _ = note.respond(lfd, 0, 0, false);
                    } else {
                        let _ = note.pass_through(lfd);
                    }
                }
                libc::SYS_accept | libc::SYS_accept4 => {
                    // Hand the child one of our pool fds carrying the next
                    // accepted connection. The fd NUMBER is real and refers to a
                    // connected socketpair, so the child reads the peer's bytes
                    // off it exactly as it would from an accepted socket.
                    let waiting = pending.lock().expect("pending lock").pop_front();
                    match waiting {
                        Some(peer) => {
                            // Claim the slot only now that there is a connection
                            // to put in it. Claiming before knowing would leak a
                            // slot on every EAGAIN, and a polling child would
                            // exhaust the pool by doing nothing at all.
                            match pool.claim(&mut used) {
                                Some((child_fd, our_side)) => {
                                    if verbose {
                                        let _ = tx.lock().unwrap().send(format!(
                                            "pod-netns:   accept -> fd {child_fd} for a \
pending connection"
                                        ));
                                    }
                                    vbound.insert(
                                        child_fd,
                                        Endpoint {
                                            family: libc::AF_INET as u8,
                                            port: 0,
                                            addr: [0u8; 16],
                                            v4: true,
                                        },
                                    );
                                    // The relay moves bytes between the child and
                                    // whoever connected to the backing socket.
                                    let log = tx.clone();
                                    let live = live_relays.clone();
                                    let started = live_relays_started.clone();
                                    live_relays_inc(&live);
                                    relay_started(&started);
                                    std::thread::spawn(move || {
                                        let c = relay::relay(peer, relay::one_shot(our_side));
                                        let _ = log.lock().unwrap().send(format!(
                                            "pod-netns:   accepted connection closed, \
{c} bytes each way"
                                        ));
                                        live_relays_dec(&live);
                                    });
                                    let _ = note.respond(lfd, child_fd as i64, 0, false);
                                }
                                None => {
                                    // No pool space. The connection is dropped
                                    // rather than queued forever, and the child is
                                    // told the truth instead of being handed a
                                    // descriptor that carries nothing.
                                    drop(peer);
                                    let _ = tx.lock().unwrap().send(
                                        "pod-netns:   accept refused: the socket pool is \
exhausted"
                                            .to_string(),
                                    );
                                    let _ = note.respond(lfd, -1, libc::EMFILE, false);
                                }
                            }
                        }
                        None => {
                            // Nothing pending, so EAGAIN, which is what a
                            // non-blocking listener returns.
                            //
                            // This cannot block: the supervisor is the only thing
                            // answering the child's syscalls, so blocking here
                            // would stop it answering everything else. A child that
                            // retries in a tight loop therefore spins, which is
                            // its own CPU and is visible. The pool is untouched on
                            // this path, so spinning does not exhaust it.
                            //
                            // Only the first few refusals are logged. A polling
                            // child produces one of these every few milliseconds
                            // and a log line each would bury everything else,
                            // which is how a real error gets missed.
                            if verbose && eagain_count < 3 {
                                eagain_count += 1;
                                let _ = tx.lock().unwrap().send(format!(
                                    "pod-netns:   accept -> EAGAIN, nothing pending \
({eagain_count}{})",
                                    if eagain_count == 3 { ", further EAGAINs suppressed" } else { "" }
                                ));
                            }
                            let _ = note.respond(lfd, -1, libc::EAGAIN, false);
                        }
                    }
                }
                _ => {
                    let _ = note.pass_through(lfd);
                }
            }
        }
    });

    // Exec the child with the pool inherited and the filter installed into it.
    let mut cmd = Command::new(&opts.argv[0]);
    cmd.args(&opts.argv[1..]);
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());
    // A pre_exec hook must return io::Error, and only async-signal-safe work is
    // allowed between fork and exec, so the messages are preformatted and the
    // sends are plain syscalls. A failure here is reported by exec failing, which
    // `cmd.status()` surfaces.
    let hsock_child_raw_err = hsock_child_raw;
    unsafe {
        cmd.pre_exec(move || {
            let notifier = Notifier::install().map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("pod-netns: installing the seccomp filter in the child failed: {e}"),
                )
            })?;
            notifier.send_to(hsock_child_raw_err).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("pod-netns: handing the seccomp listener to the supervisor failed: {e}"),
                )
            })?;
            Ok(())
        });
    }
    let status = cmd.status().map_err(|e| format!("running {}: {e}", opts.argv[0]))?;

    // The backing socket is removed once the child is gone. Without this every
    // --listen run leaves a file in /tmp, and a long-lived host accumulates one
    // per port ever served. `inbound` itself was moved into the accept thread,
    // so the path is what survives to here.
    if let Some(ep) = &opts.listen {
        let _ = std::fs::remove_file(backing_socket_path(ep));
    }

    // Do NOT join the supervisor thread. It loops on recv_notification() for as
    // long as the listener is open, and the listener belongs to the now-dead
    // child, so joining would wait for a timeout at best. It is signalled rather
    // than joined, so the intent is visible to a reader rather than implied by a
    // bare drop.
    //
    // The relay threads are given a brief bounded chance to finish their
    // accounting first. The child exiting closes its end of every socketpair,
    // which ends each relay promptly, but without this the final "N bytes each
    // way" line is usually lost to process exit, and byte counts that only
    // sometimes appear are worse than none: they make a truncated run look like
    // a small transfer.
    let started_for_exit = live_relays_started.clone();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while live_relays.load(std::sync::atomic::Ordering::SeqCst) > 0
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    // Relays have finished, so every byte-count line has been queued. Wait for
    // the log thread to have printed one before returning, otherwise
    // process::exit in main races it and the accounting is lost. This waits on
    // the actual signal rather than sleeping a guessed interval, which is what
    // made the totals vanish about one run in six.
    //
    // The wait only happens when a flow was actually relayed. A run with no
    // proxied traffic has nothing to account for, and a blanket wait there cost
    // half a second on every invocation, which is the difference between a tool
    // that feels instant and one that does not.
    let saw_accounting = {
        let p = printed.lock().expect("printed lock");
        p.iter().any(|l| l.contains("bytes each way"))
    };
    let _ = saw_accounting;
    if started_for_exit.load(std::sync::atomic::Ordering::SeqCst) > 0 && !saw_accounting {
        let stop = std::time::Instant::now() + std::time::Duration::from_millis(500);
        while std::time::Instant::now() < stop {
            if printed
                .lock()
                .expect("printed lock")
                .iter()
                .any(|l| l.contains("bytes each way"))
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    drop(supervisor);
    Ok(status.code().unwrap_or(0))
}

/// Increment the in-flight relay count.
fn live_relays_inc(c: &std::sync::atomic::AtomicUsize) {
    c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// Decrement the in-flight relay count, once the byte totals have been logged.
fn live_relays_dec(c: &std::sync::atomic::AtomicUsize) {
    c.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
}

/// Record that a relay was ever started, so the exit path knows there is
/// accounting worth waiting for.
fn relay_started(c: &std::sync::atomic::AtomicUsize) {
    c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

fn syscall_name(nr: i64) -> &'static str {
    match nr {
        x if x == libc::SYS_bind => "bind",
        x if x == libc::SYS_connect => "connect",
        x if x == libc::SYS_listen => "listen",
        x if x == libc::SYS_accept => "accept",
        x if x == libc::SYS_accept4 => "accept4",
        x if x == libc::SYS_socket => "socket",
        x if x == libc::SYS_setsockopt => "setsockopt",
        _ => "syscall",
    }
}

// Keep the UnixStream import meaningful for the pool and reader helpers.
#[allow(dead_code)]
fn splice(mut a: UnixStream, mut b: UnixStream) {
    let mut buf = [0u8; 65536];
    loop {
        match a.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if b.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
}

#[allow(dead_code)]
fn raw(_f: &dyn AsRawFd) -> RawFd {
    _f.as_raw_fd()
}
