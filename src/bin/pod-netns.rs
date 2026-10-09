//! pod-netns — run a program in a network namespace with all egress through a
//! SOCKS5 or HTTP proxy, with no `LD_PRELOAD` and no interposers.
//!
//! A shim can only reach a dynamic binary. A network namespace is enforced by
//! the kernel, so a static binary, a Go binary, and a program that never calls
//! libc's `connect(3)` are all treated the same. This is the practical use of
//! the userspace virtual network in `cfrs::vnet`: a TUN device is the only
//! interface inside the namespace, the host side of it is a `smoltcp` stack,
//! and every flow is handed to an upstream proxy.
//!
//! ```text
//!   pod-netns [opts] -- PROGRAM
//!     │
//!     ├─ child: unshare(NEWUSER|NEWNET), lo up, TUN eth0, exec PROGRAM
//!     │
//!     └─ parent: smoltcp over the TUN, fake-IP DNS, SOCKS5/HTTP upstream
//! ```
//!
//! Requires unprivileged user namespaces and `/dev/net/tun`. `pod-netns
//! doctor` measures both before anything is attempted; where the host denies
//! them (a sealed sandbox can), it says so with the errno and exits non-zero.

use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use cfrs::vnet::upstream::{
    connect_upstream, connect_upstream_async, dial_proxy, select_chain, socks5_udp_associate,
    within_timeout, wrap_udp, Proxy, ProxyKind, Rule, RuleMatch, Upstream,
};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::socket::udp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, Ipv4Address};

/// A std `Ipv4Addr` as smoltcp's wire type.
fn smol_v4(addr: Ipv4Addr) -> Ipv4Address {
    Ipv4Address::from_bytes(&addr.octets())
}

// ── tunables ────────────────────────────────────────────────────────────────

/// Address on the TUN inside the namespace (the guest side of the /31).
const TUN_ADDR: Ipv4Addr = Ipv4Addr::new(10, 66, 255, 255);
/// The gateway the stack impersonates, and the DNS server handed to the guest.
const TUN_GW: Ipv4Addr = Ipv4Addr::new(10, 66, 255, 254);
const TUN_PREFIX: u8 = 31;
const TUN_MTU: usize = 1500;
const TCP_BUF: usize = 64 * 1024;
const DNS_PORT: u16 = 53;
/// RFC 2544 benchmarking range, used by proxychains and friends for fake IPs.
const FAKE_IP_BASE: u32 = 0xC612_0000; // 198.18.0.0
const FAKE_IP_COUNT: u32 = 1 << 17; // 198.18.0.0/15

const TUNSETIFF: libc::c_ulong = 0x4004_54CA;
const IFF_TUN: libc::c_int = 0x0001;
const IFF_NO_PI: libc::c_int = 0x1000;

// ── errors ──────────────────────────────────────────────────────────────────

/// Exit code for "this host cannot run any backend", distinct from a failure
/// of the program itself.
const EXIT_NO_BACKEND: i32 = 3;

// ── command line ────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum BackendKind {
    Auto,
    Netns,
    Seccomp,
}

struct Args {
    proxies: Vec<Proxy>,
    rules: Vec<Rule>,
    maps: Vec<(String, IpAddr)>,
    program: Vec<String>,
    doctor: bool,
    doctor_json: bool,
    verbose: bool,
    inbound_dir: std::path::PathBuf,
    serve: Option<cfrs::vnet::proxy::ProxyListen>,
    backend: BackendKind,
}

fn usage() -> String {
    "\
pod-netns — run a program with all egress through a proxy, without shims

USAGE:
    pod-netns [OPTIONS] -- PROGRAM [ARGS...]
    pod-netns doctor [--json]
    pod-netns --serve LISTEN -x PROXY

OPTIONS:
    -x, --proxy SPEC       Upstream proxy, repeatable; more than one chains:
                             socks5://[user:pass@]host:port
                             http://[user:pass@]host:port
                             socks5://unix:/path     (unix-socket proxy)
                             tailscale:/path/to/tailscaled.sock
                           Default: $ALL_PROXY, $HTTPS_PROXY or $HTTP_PROXY
    -r, --rule SPEC        Per-destination route; first match wins:
                             domain:NAME=socks5://host:port
                             cidr:10.0.0.0/8=socks5://host:port
        --map NAME=ADDR    Resolve NAME to ADDR locally, repeatable
        --backend NAME     auto (default), netns or seccomp
        --inbound-dir DIR  Where a bound port is exposed as a unix socket
                           [default: /tmp/pod-netns-inbound]
        --serve LISTEN     Serve SOCKS5, HTTP CONNECT and UDP ASSOCIATE on
                           unix:/path or tcp://host:port, forwarding through
                           the -x chain
    -v, --verbose          Log each flow
    -V, --version          Print the version and exit
    -h, --help             This text

doctor measures what the host permits and exits 3 when no backend can run.
"
    .to_string()
}

fn parse_args(argv: &[String]) -> Result<Args> {
    let mut proxies = Vec::new();
    let mut rules = Vec::new();
    let mut program = Vec::new();
    let mut doctor = false;
    let mut doctor_json = false;
    let mut verbose = false;
    let mut maps: Vec<(String, IpAddr)> = Vec::new();
    let mut backend = BackendKind::Auto;
    let mut inbound_dir = std::path::PathBuf::from("/tmp/pod-netns-inbound");
    let mut serve: Option<cfrs::vnet::proxy::ProxyListen> = None;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--" => {
                program = argv[i + 1..].to_vec();
                break;
            }
            "doctor" if i == 0 => {
                doctor = true;
                i += 1;
                if argv.get(i).map(String::as_str) == Some("--json") {
                    doctor_json = true;
                    i += 1;
                }
            }
            "-V" | "--version" => {
                println!("pod-netns {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--map" => {
                let spec = argv.get(i + 1).context("--map needs NAME=ADDR")?;
                let (name, addr) = spec.split_once('=').context("--map needs NAME=ADDR")?;
                if name.is_empty() {
                    bail!("--map has an empty name");
                }
                maps.push((name.to_string(), addr.parse().context("--map address")?));
                i += 2;
            }
            "-h" | "--help" => {
                print!("{}", usage());
                std::process::exit(0);
            }
            "-v" | "--verbose" => {
                verbose = true;
                i += 1;
            }
            "-x" | "--proxy" => {
                let spec = argv.get(i + 1).context("--proxy needs a value")?;
                proxies.push(Proxy::parse(spec)?);
                i += 2;
            }
            "-r" | "--rule" => {
                let spec = argv.get(i + 1).context("--rule needs a value")?;
                let (lhs, rhs) = spec
                    .split_once('=')
                    .context("--rule needs KIND:VALUE=PROXY")?;
                let (kind, value) = lhs.split_once(':').context("--rule needs KIND:VALUE")?;
                let matcher = match kind {
                    "domain" => RuleMatch::Domain(value.to_string()),
                    "cidr" => {
                        let (net, prefix) = value
                            .split_once('/')
                            .context("cidr rule needs ADDR/PREFIX")?;
                        RuleMatch::Cidr(
                            net.parse().context("cidr address")?,
                            prefix.parse().context("cidr prefix")?,
                        )
                    }
                    other => bail!("unknown rule kind {other:?} (domain, cidr)"),
                };
                rules.push(Rule {
                    matcher,
                    proxy: Proxy::parse(rhs)?,
                });
                i += 2;
            }
            "--serve" => {
                let spec = argv.get(i + 1).context("--serve needs a listen spec")?;
                serve = Some(
                    cfrs::vnet::proxy::ProxyListen::parse(spec)
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                );
                i += 2;
            }
            "--inbound-dir" => {
                inbound_dir = std::path::PathBuf::from(
                    argv.get(i + 1).context("--inbound-dir needs a value")?,
                );
                i += 2;
            }
            "--backend" => {
                let value = argv.get(i + 1).context("--backend needs a value")?;
                backend = match value.as_str() {
                    "auto" => BackendKind::Auto,
                    "netns" => BackendKind::Netns,
                    "seccomp" => BackendKind::Seccomp,
                    other => bail!("unknown backend {other:?} (auto, netns, seccomp)"),
                };
                i += 2;
            }
            other => bail!("unexpected argument {other:?}; see --help"),
        }
    }
    // An ambient proxy is used when no -x is given, so the tool composes with
    // whatever the environment already names.
    if proxies.is_empty() {
        for var in [
            "ALL_PROXY",
            "all_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
        ] {
            if let Ok(value) = std::env::var(var) {
                if !value.is_empty() {
                    if let Ok(proxy) = Proxy::parse(&value) {
                        proxies.push(proxy);
                        break;
                    }
                }
            }
        }
    }
    if !doctor && serve.is_none() && program.is_empty() {
        bail!("nothing to run; usage: pod-netns [OPTIONS] -- PROGRAM");
    }
    Ok(Args {
        proxies,
        rules,
        maps,
        program,
        doctor,
        doctor_json,
        verbose,
        inbound_dir,
        serve,
        backend,
    })
}

// ── capability probes ───────────────────────────────────────────────────────

struct Probe {
    name: &'static str,
    ok: bool,
    detail: String,
}

fn probe_unshare(flags: libc::c_int) -> Probe {
    // Probe in a forked child: a successful unshare would otherwise take the
    // probe process out of the host's network namespace permanently.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let r = unsafe { libc::unshare(flags) };
        let code = if r == 0 {
            0
        } else {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(1)
        };
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    let name = if flags == libc::CLONE_NEWNET {
        "unshare(CLONE_NEWNET)"
    } else {
        "unshare(NEWUSER|NEWNET)"
    };
    if code == 0 {
        Probe {
            name,
            ok: true,
            detail: "ok".into(),
        }
    } else {
        let errno = std::io::Error::from_raw_os_error(code);
        Probe {
            name,
            ok: false,
            detail: format!("{errno}"),
        }
    }
}

fn probe_tun() -> Probe {
    let path = c"/dev/net/tun";
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        return Probe {
            name: "open(/dev/net/tun)",
            ok: false,
            detail: format!("{e}"),
        };
    }
    unsafe { libc::close(fd) };
    Probe {
        name: "open(/dev/net/tun)",
        ok: true,
        detail: "ok".into(),
    }
}

fn probe_ptrace() -> Probe {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let r = unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) };
        if r != 0 {
            unsafe { libc::_exit(1) };
        }
        unsafe { libc::raise(libc::SIGSTOP) };
        unsafe { libc::_exit(0) };
    }
    // The child is our tracer's child, so its SIGSTOP is a ptrace-stop; use
    // WUNTRACED so a plain stop is still reported if TRACEME failed silently.
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
    let stopped = libc::WIFSTOPPED(status);
    let detail = if stopped {
        "descendant ptrace allowed".to_string()
    } else {
        "ptrace not permitted".to_string()
    };
    unsafe {
        libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0);
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, &mut status, 0);
    }
    Probe {
        name: "PTRACE_TRACEME (fallback backend)",
        ok: stopped,
        detail,
    }
}

/// Can a seccomp filter that returns `SECCOMP_RET_USER_NOTIF` be installed and
/// handed a listener fd? That is the only `LD_PRELOAD`-free interception left
/// when namespaces and ptrace are both denied.
fn probe_seccomp_notif() -> Probe {
    const BPF_LD_ABS_W: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const BPF_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K
    const RET_USER_NOTIF: u32 = 0x7fc0_0000;
    const RET_ALLOW: u32 = 0x7fff_0000;
    const SET_MODE_FILTER: libc::c_uint = 1;
    const FLAG_NEW_LISTENER: libc::c_uint = 8;

    let filter = [
        libc::sock_filter {
            code: BPF_LD_ABS_W,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: BPF_JEQ_K,
            jt: 0,
            jf: 1,
            k: libc::SYS_getpid as u32,
        },
        libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: RET_USER_NOTIF,
        },
        libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: RET_ALLOW,
        },
    ];
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut _,
    };
    let r = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SET_MODE_FILTER,
            FLAG_NEW_LISTENER,
            &prog as *const libc::sock_fprog,
        )
    };
    if r < 0 {
        return Probe {
            name: "seccomp(SECCOMP_RET_USER_NOTIF)",
            ok: false,
            detail: format!("{}", std::io::Error::last_os_error()),
        };
    }
    let fd = r as RawFd;
    unsafe { libc::close(fd) };
    Probe {
        name: "seccomp(SECCOMP_RET_USER_NOTIF)",
        ok: true,
        detail: "listener installed".into(),
    }
}

/// Can the supervisor write a child's memory? That is what faking
/// `getsockname`/`getpeername`/`accept` addresses needs.
fn probe_mem_write() -> Probe {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let mut b = [0u8; 1];
        unsafe { libc::read(0, b.as_mut_ptr() as *mut _, 0) };
        unsafe { libc::_exit(0) };
    }
    let path = CString::new(format!("/proc/{pid}/mem")).unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    let (ok, detail) = if fd >= 0 {
        unsafe { libc::close(fd) };
        (true, "O_RDWR on /proc/<pid>/mem".to_string())
    } else {
        (false, format!("{}", std::io::Error::last_os_error()))
    };
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, std::ptr::null_mut(), 0);
    }
    Probe {
        name: "write /proc/<pid>/mem",
        ok,
        detail,
    }
}

fn doctor(json: bool) -> i32 {
    let probes = [
        probe_unshare(libc::CLONE_NEWNET),
        probe_unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET),
        probe_tun(),
        probe_ptrace(),
        probe_seccomp_notif(),
        probe_mem_write(),
    ];
    let netns_available = (probes[0].ok || probes[1].ok) && probes[2].ok;
    let seccomp_available = probes[4].ok;
    let any = netns_available || seccomp_available;

    if json {
        let mut root = serde_json::Map::new();
        let capabilities: serde_json::Map<String, serde_json::Value> = probes
            .iter()
            .map(|p| {
                (
                    p.name.to_string(),
                    serde_json::json!({ "ok": p.ok, "detail": p.detail }),
                )
            })
            .collect();
        root.insert("capabilities".into(), capabilities.into());
        root.insert("backend_netns".into(), netns_available.into());
        root.insert("backend_seccomp".into(), seccomp_available.into());
        root.insert("backend_available".into(), any.into());
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::Value::Object(root))
                .unwrap_or_else(|_| "{}".to_string())
        );
        return if any { 0 } else { EXIT_NO_BACKEND };
    }

    println!("pod-netns: capability report");
    for p in &probes {
        println!(
            "  {:<34} {:<5} {}",
            p.name,
            if p.ok { "ok" } else { "no" },
            p.detail
        );
    }
    println!(
        "pod-netns: backend netns:   {}",
        if netns_available { "available" } else { "unavailable" }
    );
    println!(
        "pod-netns: backend seccomp: {}",
        if seccomp_available { "available" } else { "unavailable" }
    );
    if probes[3].ok && !any {
        println!("pod-netns: note: descendant ptrace works, so a ptrace backend could run here");
    }
    if any {
        0
    } else {
        EXIT_NO_BACKEND
    }
}

// ── namespace + TUN setup (child side) ──────────────────────────────────────

fn write_proc(path: &str, data: &str) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("open {path}"))?;
    f.write_all(data.as_bytes())
        .with_context(|| format!("write {path}"))
}

fn write_id_maps(pid: u32) -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    write_proc(&format!("/proc/{pid}/setgroups"), "deny")?;
    write_proc(&format!("/proc/{pid}/uid_map"), &format!("{uid} {uid} 1\n"))?;
    write_proc(&format!("/proc/{pid}/gid_map"), &format!("{gid} {gid} 1\n"))?;
    Ok(())
}

fn ifreq_for(name: &str) -> libc::ifreq {
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in name.bytes().enumerate().take(libc::IF_NAMESIZE - 1) {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    ifr
}

fn bringup_loopback() -> Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        bail!("socket() for lo: {}", std::io::Error::last_os_error());
    }
    let mut ifr = ifreq_for("lo");
    let r = unsafe {
        ifr.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as i16;
        libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr as *const _)
    };
    unsafe { libc::close(sock) };
    if r < 0 {
        bail!("ioctl SIOCSIFFLAGS lo: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

/// Create and configure the TUN device inside the namespace. Returns its fd.
fn create_tun(name: &str) -> Result<OwnedFd> {
    if name.len() >= libc::IF_NAMESIZE {
        bail!("TUN name {name:?} is too long");
    }
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("open /dev/net/tun");
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut ifr = ifreq_for(name);
    let r = unsafe {
        ifr.ifr_ifru.ifru_flags = (IFF_TUN | IFF_NO_PI) as libc::c_short;
        libc::ioctl(
            owned.as_raw_fd(),
            TUNSETIFF as _,
            &mut ifr as *mut libc::ifreq,
        )
    };
    if r < 0 {
        return Err(std::io::Error::last_os_error()).context("ioctl TUNSETIFF");
    }

    // Configure with ioctls rather than `ip`: RTNETLINK can fail inside a user
    // namespace even when the ioctls succeed.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        bail!(
            "socket() for tun config: {}",
            std::io::Error::last_os_error()
        );
    }
    let guard = FdGuard(sock);
    let set_addr = |cmd: libc::c_ulong, addr: Ipv4Addr| -> Result<()> {
        let mut ifr = ifreq_for(name);
        let r = unsafe {
            let sin = &mut ifr.ifr_ifru.ifru_addr as *mut libc::sockaddr as *mut libc::sockaddr_in;
            (*sin).sin_family = libc::AF_INET as u16;
            (*sin).sin_addr.s_addr = u32::from_ne_bytes(addr.octets());
            libc::ioctl(guard.0, cmd as _, &ifr as *const _)
        };
        if r < 0 {
            bail!("ioctl {cmd:#x}: {}", std::io::Error::last_os_error());
        }
        Ok(())
    };

    let mut mtu_ifr = ifreq_for(name);
    let mtu_r = unsafe {
        mtu_ifr.ifr_ifru.ifru_mtu = TUN_MTU as libc::c_int;
        libc::ioctl(guard.0, libc::SIOCSIFMTU as _, &mtu_ifr as *const _)
    };
    if mtu_r < 0 {
        bail!("ioctl SIOCSIFMTU: {}", std::io::Error::last_os_error());
    }
    set_addr(libc::SIOCSIFADDR, TUN_ADDR)?;
    let netmask = u32::MAX << (32 - TUN_PREFIX as u32);
    set_addr(libc::SIOCSIFNETMASK, Ipv4Addr::from(netmask.to_be_bytes()))?;

    let mut up = ifreq_for(name);
    let up_r = unsafe {
        up.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as i16;
        libc::ioctl(guard.0, libc::SIOCSIFFLAGS as _, &up as *const _)
    };
    if up_r < 0 {
        bail!("ioctl SIOCSIFFLAGS up: {}", std::io::Error::last_os_error());
    }

    // Default route via the gateway the userspace stack impersonates.
    let mut route: libc::rtentry = unsafe { std::mem::zeroed() };
    let dst = &mut route.rt_dst as *mut libc::sockaddr as *mut libc::sockaddr_in;
    let gw = &mut route.rt_gateway as *mut libc::sockaddr as *mut libc::sockaddr_in;
    let mask = &mut route.rt_genmask as *mut libc::sockaddr as *mut libc::sockaddr_in;
    unsafe {
        (*dst).sin_family = libc::AF_INET as u16;
        (*gw).sin_family = libc::AF_INET as u16;
        (*gw).sin_addr.s_addr = u32::from_ne_bytes(TUN_GW.octets());
        (*mask).sin_family = libc::AF_INET as u16;
    }
    route.rt_flags = libc::RTF_UP | libc::RTF_GATEWAY;
    let name_c = CString::new(name)?;
    route.rt_dev = name_c.as_ptr() as *mut libc::c_char;
    if unsafe { libc::ioctl(guard.0, libc::SIOCADDRT as _, &route as *const _) } < 0 {
        bail!("ioctl SIOCADDRT: {}", std::io::Error::last_os_error());
    }
    Ok(owned)
}

struct FdGuard(RawFd);
impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

// ── fd passing (child → parent) ─────────────────────────────────────────────

/// Send one fd over a unix socketpair with SCM_RIGHTS.
fn send_fd(sock: RawFd, fd: RawFd) -> Result<()> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr() as *mut _,
        iov_len: 1,
    };
    let mut cmsg = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg.len();
    unsafe {
        let hdr = CMSG_FIRSTHDR(&msg);
        (*hdr).cmsg_level = libc::SOL_SOCKET;
        (*hdr).cmsg_type = libc::SCM_RIGHTS;
        (*hdr).cmsg_len = CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            &fd as *const RawFd as *const u8,
            CMSG_DATA(hdr),
            std::mem::size_of::<RawFd>(),
        );
        msg.msg_controllen = (*hdr).cmsg_len as _;
        if libc::sendmsg(sock, &msg, 0) < 0 {
            bail!("sendmsg(SCM_RIGHTS): {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[allow(non_snake_case)]
unsafe fn CMSG_FIRSTHDR(msg: *const libc::msghdr) -> *mut libc::cmsghdr {
    if (*msg).msg_controllen >= std::mem::size_of::<libc::cmsghdr>() as _ {
        (*msg).msg_control as *mut libc::cmsghdr
    } else {
        std::ptr::null_mut()
    }
}

#[allow(non_snake_case)]
unsafe fn CMSG_DATA(hdr: *mut libc::cmsghdr) -> *mut u8 {
    (hdr as *mut u8).add(std::mem::size_of::<libc::cmsghdr>())
}

#[allow(non_snake_case)]
fn CMSG_LEN(len: u32) -> u32 {
    (std::mem::size_of::<libc::cmsghdr>() as u32 + len + 7) & !7
}

/// Receive one fd over a unix socketpair.
fn recv_fd(sock: RawFd) -> Result<RawFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr() as *mut _,
        iov_len: 1,
    };
    let mut cmsg = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg.len();
    let n = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if n <= 0 {
        bail!("recvmsg(SCM_RIGHTS): {}", std::io::Error::last_os_error());
    }
    let hdr = unsafe { CMSG_FIRSTHDR(&msg) };
    if hdr.is_null() {
        bail!("no fd in the received message");
    }
    let mut fd: RawFd = -1;
    // Copy bytes, not elements: with `*mut RawFd` a count of
    // `size_of::<RawFd>()` would write four fds' worth into one.
    unsafe {
        std::ptr::copy_nonoverlapping(
            CMSG_DATA(hdr) as *const u8,
            (&mut fd as *mut RawFd).cast::<u8>(),
            std::mem::size_of::<RawFd>(),
        );
    }
    Ok(fd)
}

// ── TUN as a smoltcp device ─────────────────────────────────────────────────

struct Tun {
    fd: RawFd,
    mtu: usize,
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

impl Tun {
    fn new(fd: RawFd, mtu: usize) -> Self {
        // The read loop drains until EAGAIN, so the fd must not block.
        unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
        Self {
            fd,
            mtu,
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        }
    }

    /// Read whatever the kernel has queued into `rx`.
    fn read_ready(&mut self) {
        loop {
            let mut buf = vec![0u8; self.mtu];
            let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut _, self.mtu) };
            if n <= 0 {
                break;
            }
            buf.truncate(n as usize);
            self.rx.push_back(buf);
        }
    }

    fn flush(&mut self) {
        while let Some(pkt) = self.tx.pop_front() {
            let mut off = 0;
            while off < pkt.len() {
                let n = unsafe {
                    libc::write(self.fd, pkt[off..].as_ptr() as *const _, pkt.len() - off)
                };
                if n <= 0 {
                    return;
                }
                off += n as usize;
            }
        }
    }
}

impl Device for Tun {
    type RxToken<'a> = TunRx;
    type TxToken<'a> = TunTx<'a>;
    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((TunRx(pkt), TunTx { out: &mut self.tx }))
    }
    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TunTx { out: &mut self.tx })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.checksum = ChecksumCapabilities::default();
        caps
    }
}

struct TunRx(Vec<u8>);
impl RxToken for TunRx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, f: F) -> R {
        f(&mut self.0)
    }
}
struct TunTx<'a> {
    out: &'a mut VecDeque<Vec<u8>>,
}
impl TxToken for TunTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.out.push_back(buf);
        r
    }
}

// ── fake-IP DNS ─────────────────────────────────────────────────────────────

struct FakeDns {
    by_ip: HashMap<Ipv4Addr, String>,
    by_name: HashMap<String, Ipv4Addr>,
    next: u32,
}

impl FakeDns {
    /// Pin a name to a real address, so it resolves locally with no fake IP.
    fn pin(&mut self, name: &str, ip: IpAddr) {
        if let IpAddr::V4(v4) = ip {
            self.by_name.insert(name.to_string(), v4);
        }
    }

    fn new() -> Self {
        Self {
            by_ip: HashMap::new(),
            by_name: HashMap::new(),
            next: 0,
        }
    }

    fn address_for(&mut self, name: &str) -> Ipv4Addr {
        if let Some(ip) = self.by_name.get(name) {
            return *ip;
        }
        let ip = Ipv4Addr::from((FAKE_IP_BASE + (self.next % FAKE_IP_COUNT)).to_be_bytes());
        self.next += 1;
        self.by_name.insert(name.to_string(), ip);
        self.by_ip.insert(ip, name.to_string());
        ip
    }

    fn name_for(&self, ip: Ipv4Addr) -> Option<&str> {
        self.by_ip.get(&ip).map(String::as_str)
    }
}

// ── the stack loop ──────────────────────────────────────────────────────────

/// One outbound flow: a smoltcp TCP socket and the upstream proxy connection.
struct Flow {
    upstream: tokio::net::TcpStream,
    to_upstream: Vec<u8>,
    to_app: Vec<u8>,
    up_eof: bool,
}

struct Backend {
    device: Tun,
    interface: Interface,
    sockets: SocketSet<'static>,
    dns_socket: SocketHandle,
    dns: FakeDns,
    /// destination port → listener handle created for it
    listeners: HashMap<u16, SocketHandle>,
    flows: HashMap<SocketHandle, Flow>,
    proxies: Vec<Proxy>,
    rules: Vec<Rule>,
    verbose: bool,
}

impl Backend {
    fn new(
        fd: RawFd,
        proxies: Vec<Proxy>,
        rules: Vec<Rule>,
        maps: Vec<(String, IpAddr)>,
        verbose: bool,
    ) -> Result<Self> {
        let mut device = Tun::new(fd, TUN_MTU);
        let mut config = IfaceConfig::new(HardwareAddress::Ip);
        config.random_seed = seed();
        let mut interface = Interface::new(config, &mut device, SmolInstant::now());
        interface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv4(smol_v4(TUN_GW)), TUN_PREFIX))
                .unwrap();
        });
        interface
            .routes_mut()
            .add_default_ipv4_route(smol_v4(TUN_GW))
            .unwrap();
        // Accept packets addressed to any destination: the guest connects to
        // real addresses, and we impersonate all of them.
        interface.set_any_ip(true);

        let mut sockets = SocketSet::new(Vec::new());
        let dns_socket = add_udp(&mut sockets, DNS_PORT);
        let mut dns = FakeDns::new();
        for (name, ip) in &maps {
            dns.pin(name, *ip);
        }
        Ok(Self {
            device,
            interface,
            sockets,
            dns_socket,
            dns,
            listeners: HashMap::new(),
            flows: HashMap::new(),
            proxies,
            rules,
            verbose,
        })
    }

    /// A SYN to a new destination port needs a listen socket before smoltcp
    /// processes the packet.
    fn observe_syns(&mut self) {
        let mut new_ports = Vec::new();
        for pkt in &self.device.rx {
            if let Some((_src, _sport, _dst, dport)) = parse_tcp_syn(pkt) {
                if !self.listeners.contains_key(&dport) && !new_ports.contains(&dport) {
                    new_ports.push(dport);
                }
            }
        }
        for port in new_ports {
            // Bound the table: a program that sweeps ports must not grow it
            // without limit.
            if self.listeners.len() >= MAX_TRACKED_FDS {
                break;
            }
            let mut socket = tcp_socket();
            let endpoint = IpListenEndpoint { addr: None, port };
            if socket.listen(endpoint).is_ok() {
                let handle = self.sockets.add(socket);
                self.listeners.insert(port, handle);
                if self.verbose {
                    eprintln!("pod-netns: listening for outbound port {port}");
                }
            }
        }
    }

    async fn tick(&mut self) -> Result<()> {
        self.observe_syns();
        self.answer_dns();
        self.interface
            .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
        self.accept_flows().await;
        self.shuttle().await;
        self.device.flush();
        Ok(())
    }

    fn answer_dns(&mut self) {
        let socket = self.sockets.get_mut::<udp::Socket>(self.dns_socket);
        while socket.can_recv() {
            let Ok((data, meta)) = socket.recv() else {
                break;
            };
            let Ok(query) = cfrs::vnet::dns::ParsedQuery::parse(data) else {
                continue;
            };
            let ip = self.dns.address_for(&query.name);
            let answers = vec![IpAddr::V4(ip)];
            let reply = cfrs::vnet::dns::build_response(&query, &answers, 0);
            let _ = socket.send_slice(&reply, meta.endpoint);
        }
    }

    async fn accept_flows(&mut self) {
        let handles: Vec<SocketHandle> = self.listeners.values().copied().collect();
        for handle in handles {
            if self.flows.contains_key(&handle) {
                continue;
            }
            // The destination is the socket's local endpoint; the source is
            // the guest's. Read it under an immutable borrow, then release it
            // before touching the map again.
            let target = {
                let socket = self.sockets.get::<tcp::Socket>(handle);
                if !matches!(socket.state(), tcp::State::Established) {
                    continue;
                }
                let Some(local) = socket.local_endpoint() else {
                    continue;
                };
                let IpAddress::Ipv4(dst_ip) = local.addr else {
                    continue;
                };
                let b = dst_ip.as_bytes();
                let dst_ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
                match self.dns.name_for(dst_ip) {
                    Some(name) => format!("{name}:{}", local.port),
                    None => format!("{dst_ip}:{}", local.port),
                }
            };
            let proxy = select_chain(&self.rules, &self.proxies, &target)[0].clone();
            if self.verbose {
                eprintln!("pod-netns: {target} via {}", proxy.endpoint());
            }
            match connect_upstream(&proxy, &target).await {
                Ok(stream) => {
                    self.flows.insert(
                        handle,
                        Flow {
                            upstream: stream,
                            to_upstream: Vec::new(),
                            to_app: Vec::new(),
                            up_eof: false,
                        },
                    );
                }
                Err(e) => {
                    if self.verbose {
                        eprintln!("pod-netns: upstream for {target} failed: {e:#}");
                    }
                    self.sockets.get_mut::<tcp::Socket>(handle).abort();
                }
            }
        }
    }

    async fn shuttle(&mut self) {
        let handles: Vec<SocketHandle> = self.flows.keys().copied().collect();
        for handle in handles {
            let mut flow = self.flows.remove(&handle).unwrap();
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            let mut close = false;

            // app → upstream
            while socket.can_recv() {
                match socket.recv(|buf| {
                    let n = buf.len().min(64 * 1024);
                    flow.to_upstream.extend_from_slice(&buf[..n]);
                    (n, ())
                }) {
                    Ok(()) => {}
                    Err(_) => break,
                }
            }
            while !flow.to_upstream.is_empty() {
                match flow.upstream.try_write(&flow.to_upstream) {
                    Ok(0) => break,
                    Ok(n) => {
                        flow.to_upstream.drain(..n);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        close = true;
                        break;
                    }
                }
            }

            // upstream → app
            let mut buf = [0u8; 16 * 1024];
            loop {
                match flow.upstream.try_read(&mut buf) {
                    Ok(0) => {
                        flow.up_eof = true;
                        break;
                    }
                    Ok(n) => flow.to_app.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        close = true;
                        break;
                    }
                }
            }
            while !flow.to_app.is_empty() && socket.can_send() {
                match socket.send_slice(&flow.to_app) {
                    Ok(n) => {
                        flow.to_app.drain(..n);
                    }
                    Err(_) => break,
                }
            }

            if (flow.up_eof && flow.to_app.is_empty()) || close || !socket.may_send() {
                socket.close();
                self.flows.remove(&handle);
                continue;
            }
            self.flows.insert(handle, flow);
        }
    }
}

fn tcp_socket() -> tcp::Socket<'static> {
    let rx = tcp::SocketBuffer::new(vec![0u8; TCP_BUF]);
    let tx = tcp::SocketBuffer::new(vec![0u8; TCP_BUF]);
    let mut socket = tcp::Socket::new(rx, tx);
    socket.set_nagle_enabled(false);
    socket
}

fn add_udp(sockets: &mut SocketSet<'static>, port: u16) -> SocketHandle {
    let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 8 * 1024]);
    let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 8 * 1024]);
    let mut socket = udp::Socket::new(rx, tx);
    socket.bind(IpListenEndpoint { addr: None, port }).unwrap();
    sockets.add(socket)
}

fn seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15)
}

/// Parse a bare TCP SYN and return (src ip, src port, dst ip, dst port).
fn parse_tcp_syn(pkt: &[u8]) -> Option<(Ipv4Addr, u16, Ipv4Addr, u16)> {
    if pkt.len() < 40 || (pkt[0] >> 4) != 4 {
        return None;
    }
    if pkt[9] != 6 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if pkt.len() < ihl + 20 {
        return None;
    }
    let flags = pkt[ihl + 13];
    if flags & 0x02 == 0 || flags & 0x10 != 0 {
        return None; // SYN set, ACK clear
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
    let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    Some((src, sport, dst, dport))
}



// ── process orchestration ───────────────────────────────────────────────────

fn run(args: Args) -> Result<i32> {
    let (parent, child) = socketpair()?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork: {}", std::io::Error::last_os_error());
    }
    if pid == 0 {
        // Child: new namespace, TUN, then the program.
        unsafe { libc::close(parent) };
        let result = child_setup(child, &args);
        // child_setup only returns on error; it execs on success.
        if let Err(e) = result {
            eprintln!("pod-netns: {e:#}");
            unsafe { libc::_exit(EXIT_NO_BACKEND) };
        }
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::close(child) };

    // Parent: the child reports whether it made a user namespace; if so, write
    // its id maps before it continues, then take the TUN fd.
    let mut kind = [0u8; 1];
    if read_exact_fd(parent, &mut kind)? == 0 {
        bail!("child died before reporting its namespace");
    }
    if kind[0] == b'u' {
        write_id_maps(pid as u32).context("write uid/gid maps")?;
        write_all_fd(parent, b"a")?;
    }
    let tun_fd = recv_fd(parent).context("receive TUN fd")?;
    unsafe { libc::close(parent) };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let proxies = args.proxies.clone();
    let rules = args.rules.clone();
    let maps = args.maps.clone();
    let verbose = args.verbose;
    let result = runtime.block_on(async move {
        let mut backend = Backend::new(tun_fd, proxies, rules, maps, verbose)?;
        let fd = backend.device.fd;
        let async_fd = tokio::io::unix::AsyncFd::with_interest(
            unsafe { OwnedFd::from_raw_fd(libc::dup(fd)) },
            tokio::io::Interest::READABLE,
        )?;
        loop {
            backend.device.read_ready();
            backend.tick().await?;
            // Wake on TUN input or a short timer, whichever comes first.
            let _ = tokio::time::timeout(Duration::from_millis(20), async_fd.readable()).await;
            let mut status = 0;
            let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if r == pid {
                return Ok::<i32, anyhow::Error>(if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    128 + libc::WTERMSIG(status)
                });
            }
        }
    });
    // Reap if the loop exited without seeing it.
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    result
}

fn child_setup(sock: RawFd, args: &Args) -> Result<()> {
    // A network namespace alone needs CAP_SYS_ADMIN; the user-namespace pair
    // works unprivileged and the parent writes the maps.
    let userns = if unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0 {
        false
    } else {
        let e = std::io::Error::last_os_error();
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
            bail!(
                "unshare(CLONE_NEWNET) failed ({e}) and unshare(CLONE_NEWUSER|CLONE_NEWNET) failed ({})",
                std::io::Error::last_os_error()
            );
        }
        true
    };
    // Tell the parent, and wait for the id maps before using the namespace.
    write_all_fd(sock, if userns { b"u" } else { b"n" })?;
    if userns {
        let mut ack = [0u8; 1];
        if read_exact_fd(sock, &mut ack)? == 0 {
            bail!("parent died before writing the id maps");
        }
    }
    bringup_loopback()?;
    let tun = create_tun("eth0")?;
    send_fd(sock, tun.as_raw_fd())?;
    unsafe { libc::close(sock) };
    std::mem::forget(tun); // the parent owns its own handle; keep ours open too

    let program = &args.program;
    let path = CString::new(program[0].as_bytes())?;
    let mut argv: Vec<CString> = Vec::with_capacity(program.len() + 1);
    for a in program {
        argv.push(CString::new(a.as_bytes())?);
    }
    let ptrs: Vec<*const libc::c_char> = argv
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    unsafe {
        libc::execvp(path.as_ptr(), ptrs.as_ptr());
    }
    bail!("execvp {}: {}", program[0], std::io::Error::last_os_error())
}

fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> Result<()> {
    while !buf.is_empty() {
        let n = unsafe { libc::write(fd, buf.as_ptr() as *const _, buf.len()) };
        if n <= 0 {
            bail!("write: {}", std::io::Error::last_os_error());
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

fn read_exact_fd(fd: RawFd, buf: &mut [u8]) -> Result<usize> {
    let mut off = 0;
    while off < buf.len() {
        let n = unsafe { libc::read(fd, buf[off..].as_mut_ptr() as *mut _, buf.len() - off) };
        if n < 0 {
            bail!("read: {}", std::io::Error::last_os_error());
        }
        if n == 0 {
            return Ok(off);
        }
        off += n as usize;
    }
    Ok(off)
}

fn socketpair() -> Result<(RawFd, RawFd)> {
    let mut fds = [0 as RawFd; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        bail!("socketpair: {}", std::io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn fake_dns_is_stable_and_reversible() {
        let mut dns = FakeDns::new();
        let a = dns.address_for("example.com");
        let b = dns.address_for("example.com");
        assert_eq!(a, b, "the same name must map to the same fake ip");
        assert_eq!(dns.name_for(a), Some("example.com"));
        let other = dns.address_for("example.org");
        assert_ne!(a, other);
        assert!(a.octets()[0] == 198 && a.octets()[1] == 18);
    }



    #[test]
    fn the_filter_covers_the_bypass_surfaces() {
        let syscalls = intercepted_syscalls();
        for required in [
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_sendto,
            libc::SYS_sendmsg,
            libc::SYS_sendmmsg,
            libc::SYS_setsockopt,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ] {
            assert!(
                syscalls.contains(&required),
                "syscall {required} is not intercepted"
            );
        }
    }



    #[test]
    fn parses_a_tcp_syn() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // IPv4, IHL 5
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
        pkt[16..20].copy_from_slice(&[93, 184, 216, 34]);
        pkt[20..22].copy_from_slice(&40000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[33] = 0x02; // SYN
        assert_eq!(
            parse_tcp_syn(&pkt),
            Some((
                Ipv4Addr::new(10, 0, 0, 2),
                40000,
                Ipv4Addr::new(93, 184, 216, 34),
                443
            ))
        );

        // An ACK is not a SYN.
        pkt[33] = 0x10;
        assert_eq!(parse_tcp_syn(&pkt), None);
        // UDP is not TCP.
        pkt[9] = 17;
        pkt[33] = 0x02;
        assert_eq!(parse_tcp_syn(&pkt), None);
        // Too short.
        assert_eq!(parse_tcp_syn(&pkt[..20]), None);
    }
}

// ── front door: pod-netns as a proxy for others ─────────────────────────────

enum FrontListener {
    Unix(tokio::net::UnixListener),
    Tcp(tokio::net::TcpListener),
}

impl FrontListener {
    async fn accept(&self) -> std::io::Result<Upstream> {
        match self {
            FrontListener::Unix(l) => Ok(Box::new(l.accept().await?.0)),
            FrontListener::Tcp(l) => Ok(Box::new(l.accept().await?.0)),
        }
    }
}

/// Serve SOCKS5 and HTTP `CONNECT`, forwarding each request through the
/// configured upstream chain. This makes an instance a hop for another, and a
/// drop-in replacement for a shim's front door.
async fn serve_front_door(
    listen: cfrs::vnet::proxy::ProxyListen,
    chain: Vec<Proxy>,
    rules: Vec<Rule>,
    verbose: bool,
) -> Result<()> {
    use cfrs::vnet::proxy::ProxyListen;
    let listener = match &listen {
        ProxyListen::Unix(path) => {
            let _ = std::fs::remove_file(path);
            FrontListener::Unix(tokio::net::UnixListener::bind(path)?)
        }
        ProxyListen::Tcp(addr) => FrontListener::Tcp(tokio::net::TcpListener::bind(addr).await?),
    };
    eprintln!(
        "pod-netns: serving {} ({} upstream)",
        listen_str(&listen),
        chain.len()
    );
    loop {
        let conn = listener.accept().await?;
        let chain = chain.clone();
        let rules = rules.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_one(conn, &chain, &rules, verbose).await {
                if verbose {
                    eprintln!("pod-netns: front door: {e:#}");
                }
            }
        });
    }
}

fn listen_str(listen: &cfrs::vnet::proxy::ProxyListen) -> String {
    match listen {
        cfrs::vnet::proxy::ProxyListen::Unix(p) => format!("unix:{}", p.display()),
        cfrs::vnet::proxy::ProxyListen::Tcp(a) => format!("tcp://{a}"),
    }
}

async fn serve_one(conn: Upstream, chain: &[Proxy], rules: &[Rule], verbose: bool) -> Result<()> {
    use cfrs::vnet::socks;
    use tokio::io::AsyncBufReadExt;
    let mut reader = tokio::io::BufReader::new(conn);
    let first = {
        let buf = reader.fill_buf().await?;
        buf.first().copied()
    };
    match first {
        Some(5) => {
            let (cmd, request) = read_socks5_command(&mut reader).await?;
            if cmd == 0x03 {
                return serve_udp_associate(reader, chain, verbose).await;
            }
            let target = format!("{}:{}", request.host, request.port);
            let selected = select_chain(rules, chain, &target);
            if verbose {
                eprintln!(
                    "pod-netns: front door {target} via {}",
                    selected[0].endpoint()
                );
            }
            let mut upstream = match within_timeout(
                "front door connect",
                connect_upstream_async(selected, &target),
            )
            .await
            {
                Ok(u) => u,
                Err(e) => {
                    let _ = socks::socks5_reply(
                        &mut reader,
                        socks::socks5_code_for_error(&e.to_string()),
                        None,
                    )
                    .await;
                    return Err(e);
                }
            };
            socks::socks5_reply(&mut reader, 0x00, None).await?;
            let _ = tokio::io::copy_bidirectional(&mut reader, &mut upstream).await;
            Ok(())
        }
        Some(_) => {
            let request = socks::http_read_connect(&mut reader).await?;
            let target = format!("{}:{}", request.host, request.port);
            let selected = select_chain(rules, chain, &target);
            let mut upstream = match within_timeout(
                "front door connect",
                connect_upstream_async(selected, &target),
            )
            .await
            {
                Ok(u) => u,
                Err(e) => {
                    let _ = socks::http_connect_reply(&mut reader, 502, "Bad Gateway").await;
                    return Err(e);
                }
            };
            socks::http_connect_ok(&mut reader).await?;
            let _ = tokio::io::copy_bidirectional(&mut reader, &mut upstream).await;
            Ok(())
        }
        None => Ok(()),
    }
}

/// Read a SOCKS5 greeting and request, accepting any command so
/// `UDP ASSOCIATE` is not rejected before it can be served.
async fn read_socks5_command<S>(stream: &mut S) -> Result<(u8, cfrs::vnet::socks::ProxyRequest)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use cfrs::vnet::socks::ProxyHost;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut intro = [0u8; 2];
    stream
        .read_exact(&mut intro)
        .await
        .context("SOCKS5 greeting")?;
    if intro[0] != 0x05 {
        bail!("SOCKS5 version {} is not 5", intro[0]);
    }
    let mut methods = vec![0u8; intro[1] as usize];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[0x05, 0x00]).await?;
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .context("SOCKS5 request")?;
    if header[0] != 0x05 {
        bail!("SOCKS5 request version {} is not 5", header[0]);
    }
    let host = match header[3] {
        0x01 => {
            let mut a = [0u8; 4];
            stream.read_exact(&mut a).await?;
            ProxyHost::Ip(IpAddr::V4(Ipv4Addr::from(a)))
        }
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            let mut h = vec![0u8; l[0] as usize];
            stream.read_exact(&mut h).await?;
            ProxyHost::Domain(String::from_utf8_lossy(&h).to_string())
        }
        0x04 => {
            let mut a = [0u8; 16];
            stream.read_exact(&mut a).await?;
            ProxyHost::Ip(IpAddr::V6(std::net::Ipv6Addr::from(a)))
        }
        other => bail!("SOCKS5 address type {other} is not supported"),
    };
    let mut p = [0u8; 2];
    stream.read_exact(&mut p).await?;
    Ok((
        header[1],
        cfrs::vnet::socks::ProxyRequest {
            host,
            port: u16::from_be_bytes(p),
        },
    ))
}

/// Answer `UDP ASSOCIATE` by relaying through the first upstream proxy's own
/// association, so a UDP relay can chain through this instance.
async fn serve_udp_associate(
    mut control: tokio::io::BufReader<Upstream>,
    chain: &[Proxy],
    verbose: bool,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let proxy = chain.first().context("no upstream for UDP ASSOCIATE")?;
    if proxy.kind != ProxyKind::Socks5 {
        let _ = control
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        bail!("UDP ASSOCIATE needs a SOCKS5 upstream");
    }
    // Our own relay socket, advertised to the client.
    let relay = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
    let addr = relay.local_addr()?;
    let mut bnd = vec![0x05u8, 0x00, 0x00];
    match addr {
        SocketAddr::V4(a) => {
            bnd.push(0x01);
            bnd.extend_from_slice(&a.ip().octets());
            bnd.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            bnd.push(0x04);
            bnd.extend_from_slice(&a.ip().octets());
            bnd.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    control.write_all(&bnd).await?;
    control.flush().await?;

    // The upstream's relay, reached over its own association.
    let up_control = dial_proxy(proxy).await?;
    let (_up_control, up_addr) = socks5_udp_associate(up_control, proxy).await?;
    let up = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
    if verbose {
        eprintln!("pod-netns: front door UDP relay {addr} -> {up_addr}");
    }

    let client: Arc<tokio::sync::Mutex<Option<SocketAddr>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    // client -> upstream
    let to_upstream = {
        let relay = relay.clone();
        let up = up.clone();
        let client = client.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            while let Ok((n, from)) = relay.recv_from(&mut buf).await {
                *client.lock().await = Some(from);
                if n < 4 {
                    continue;
                }
                let _ = up.send_to(&buf[..n], up_addr).await;
            }
        })
    };
    // upstream -> client
    let to_client = {
        let relay = relay.clone();
        let up = up.clone();
        let client = client.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            while let Ok((n, _)) = up.recv_from(&mut buf).await {
                if let Some(to) = *client.lock().await {
                    let _ = relay.send_to(&buf[..n], to).await;
                }
            }
        })
    };
    // Hold the control connection until the client closes it, then stop the
    // relay tasks rather than leaving them holding the sockets.
    let mut byte = [0u8; 1];
    while control.read(&mut byte).await.unwrap_or(0) == 1 {}
    to_upstream.abort();
    to_client.abort();
    Ok(())
}

// ── seccomp user-notification backend ─// ── seccomp user-notification backend ───────────────────────────────────────
//
// Where a network namespace is denied, a seccomp filter that returns
// `SECCOMP_RET_USER_NOTIF` still lets a supervisor mediate syscalls without any
// `LD_PRELOAD`. This backend intercepts `socket(2)` and hands the child a
// socketpair end with `SECCOMP_IOCTL_NOTIF_ADDFD`; the child's own `connect(2)`
// is then answered by the supervisor, which dials the proxy and splices. Only
// `socket` and `connect` need emulating for TCP, because the socketpair carries
// the bytes natively. UDP port 53 is answered from the fake-IP pool.

const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_uint = 8;
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
const SECCOMP_IOCTL_NOTIF_ADDFD: libc::c_ulong = 0x4018_2103;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
const SECCOMP_ADDFD_FLAG_SEND: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

#[repr(C)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

#[repr(C)]
struct SeccompNotifAddfd {
    id: u64,
    flags: u32,
    srcfd: u32,
    newfd: u32,
    newfd_flags: u32,
}

/// The syscalls the filter stops. Everything else is allowed untouched.
fn intercepted_syscalls() -> [libc::c_long; 17] {
    [
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_bind,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_io_uring_setup,
        libc::SYS_close,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ]
}

fn install_notif_filter() -> Result<RawFd> {
    const BPF_LD_ABS_W: u16 = 0x20;
    const BPF_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const RET_USER_NOTIF: u32 = 0x7fc0_0000;
    const RET_ALLOW: u32 = 0x7fff_0000;

    let mut filter = vec![libc::sock_filter {
        code: BPF_LD_ABS_W,
        jt: 0,
        jf: 0,
        k: 0,
    }];
    for syscall in intercepted_syscalls() {
        filter.push(libc::sock_filter {
            code: BPF_JEQ_K,
            jt: 0,
            jf: 1,
            k: syscall as u32,
        });
        filter.push(libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: RET_USER_NOTIF,
        });
    }
    filter.push(libc::sock_filter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: RET_ALLOW,
    });

    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut _,
    };
    let r = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const libc::sock_fprog,
        )
    };
    if r < 0 {
        return Err(std::io::Error::last_os_error()).context("seccomp(NEW_LISTENER)");
    }
    Ok(r as RawFd)
}

/// Read `len` bytes from the child at `addr`.
fn read_mem(mem: RawFd, addr: u64, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut off = 0;
    while off < len {
        let n = unsafe {
            libc::pread(
                mem,
                buf[off..].as_mut_ptr() as *mut _,
                len - off,
                (addr as i64) + off as i64,
            )
        };
        if n <= 0 {
            bail!("pread(/proc/pid/mem): {}", std::io::Error::last_os_error());
        }
        off += n as usize;
    }
    Ok(buf)
}

/// Write `data` into the child at `addr`.
fn write_mem(mem: RawFd, addr: u64, data: &[u8]) -> Result<()> {
    let mut off = 0;
    while off < data.len() {
        let n = unsafe {
            libc::pwrite(
                mem,
                data[off..].as_ptr() as *const _,
                data.len() - off,
                (addr as i64) + off as i64,
            )
        };
        if n <= 0 {
            bail!("pwrite(/proc/pid/mem): {}", std::io::Error::last_os_error());
        }
        off += n as usize;
    }
    Ok(())
}

fn sockaddr_in(family: u16, ip: IpAddr, port: u16) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => {
            let mut b = vec![0u8; 16];
            b[0..2].copy_from_slice(&family.to_ne_bytes());
            b[2..4].copy_from_slice(&port.to_be_bytes());
            b[4..8].copy_from_slice(&v4.octets());
            b
        }
        IpAddr::V6(v6) => {
            let mut b = vec![0u8; 28];
            b[0..2].copy_from_slice(&family.to_ne_bytes());
            b[2..4].copy_from_slice(&port.to_be_bytes());
            b[8..24].copy_from_slice(&v6.octets());
            b
        }
    }
}

fn parse_sockaddr(bytes: &[u8]) -> Option<(u16, IpAddr, u16)> {
    if bytes.len() < 4 {
        return None;
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    match family as i32 {
        libc::AF_INET if bytes.len() >= 8 => Some((
            family,
            IpAddr::V4(Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7])),
            port,
        )),
        libc::AF_INET6 if bytes.len() >= 24 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&bytes[8..24]);
            Some((family, IpAddr::V6(o.into()), port))
        }
        _ => None,
    }
}

fn set_nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        bail!("fcntl(F_GETFL): {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        bail!("fcntl(F_SETFL): {}", std::io::Error::last_os_error());
    }
    Ok(())
}

fn notif_addfd_send(lfd: RawFd, id: u64, srcfd: RawFd, newfd_flags: u32) -> Result<i32> {
    let req = SeccompNotifAddfd {
        id,
        flags: SECCOMP_ADDFD_FLAG_SEND,
        srcfd: srcfd as u32,
        newfd: 0,
        newfd_flags,
    };
    let r = unsafe { libc::ioctl(lfd, SECCOMP_IOCTL_NOTIF_ADDFD, &req) };
    if r < 0 {
        return Err(std::io::Error::last_os_error()).context("NOTIF_ADDFD");
    }
    Ok(r)
}

fn notif_respond(lfd: RawFd, id: u64, val: i64, error: i32) -> Result<()> {
    let resp = SeccompNotifResp {
        id,
        val,
        error,
        flags: 0,
    };
    let r = unsafe { libc::ioctl(lfd, SECCOMP_IOCTL_NOTIF_SEND, &resp) };
    if r < 0 {
        let e = std::io::Error::last_os_error();
        // ENOENT means the target died or the syscall was interrupted.
        if e.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(e).context("NOTIF_SEND");
    }
    Ok(())
}

fn notif_continue(lfd: RawFd, id: u64) -> Result<()> {
    let resp = SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };
    let r = unsafe { libc::ioctl(lfd, SECCOMP_IOCTL_NOTIF_SEND, &resp) };
    if r < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(e).context("NOTIF_SEND(CONTINUE)");
    }
    Ok(())
}

/// A live SOCKS5 UDP association: the relay socket, its address, and the TCP
/// control connection that must stay open for the association to live.
struct UdpRelay {
    udp: Arc<tokio::net::UdpSocket>,
    relay_addr: SocketAddr,
    _control: Upstream,
}

/// A listening socket inside the sandbox. Connections arrive on a unix
/// listener (the only bind a sealed host permits) and are handed to the child's
/// `accept` as injected socketpair ends.
struct Inbound {
    rx: tokio::sync::mpsc::UnboundedReceiver<tokio::net::UnixStream>,
}

enum Sock {
    Stream {
        pair: tokio::net::UnixStream,
        bound: Option<(IpAddr, u16)>,
        inbound: Option<Inbound>,
    },
    Datagram {
        pair: Arc<tokio::net::UnixDatagram>,
        dest: Option<(IpAddr, u16)>,
        relay: Option<UdpRelay>,
    },
}

fn run_seccomp(args: Args) -> Result<i32> {
    if args.proxies.is_empty() {
        bail!("the seccomp backend needs -x (there is no direct mode)");
    }
    // A seccomp filter is per-thread unless TSYNC is used. Install it on a
    // helper thread and fork there: the child inherits the filter, and the
    // listener fd stays in this process's fd table, so no SCM_RIGHTS handshake
    // is needed (the child's own sendmsg is itself intercepted).
    let program = args.program.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("pod-netns-filter".into())
        .spawn(move || {
            // Built before fork so the child allocates nothing.
            let path = match CString::new(program[0].as_bytes()) {
                Ok(p) => p,
                Err(e) => {
                    let _ = tx.send(Err(anyhow::anyhow!("program path: {e}")));
                    return;
                }
            };
            let argv: Vec<CString> = match program
                .iter()
                .map(|a| CString::new(a.as_bytes()))
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(v) => v,
                Err(e) => {
                    let _ = tx.send(Err(anyhow::anyhow!("argv: {e}")));
                    return;
                }
            };
            let ptrs: Vec<*const libc::c_char> = argv
                .iter()
                .map(|c| c.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect();

            let lfd = match install_notif_filter() {
                Ok(fd) => fd,
                Err(e) => {
                    let _ = tx.send(Err(e));
                    return;
                }
            };
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                let _ = tx.send(Err(anyhow::anyhow!(
                    "fork: {}",
                    std::io::Error::last_os_error()
                )));
                return;
            }
            if pid == 0 {
                // Child: the filter is inherited. execv with no allocation.
                unsafe { libc::execv(path.as_ptr(), ptrs.as_ptr()) };
                unsafe { libc::_exit(127) };
            }
            let _ = tx.send(Ok((lfd, pid)));
        })?;
    let (lfd, pid) = rx.recv().context("filter thread died")??;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(supervise_seccomp(
        lfd,
        pid,
        args.proxies,
        args.rules,
        args.maps,
        args.verbose,
        args.inbound_dir,
    ))
}

async fn supervise_seccomp(
    lfd: RawFd,
    pid: i32,
    proxies: Vec<Proxy>,
    rules: Vec<Rule>,
    maps: Vec<(String, IpAddr)>,
    verbose: bool,
    inbound_dir: std::path::PathBuf,
) -> Result<i32> {
    // NOTIF_RECV is non-blocking so the shutdown flag is observed; the fd is
    // also pollable, so the loop sleeps on readiness rather than spinning.
    unsafe { libc::fcntl(lfd, libc::F_SETFL, libc::O_NONBLOCK) };
    let dup = unsafe { OwnedFd::from_raw_fd(libc::dup(lfd)) };
    let async_fd = tokio::io::unix::AsyncFd::with_interest(dup, tokio::io::Interest::READABLE)?;

    let mem_path = CString::new(format!("/proc/{pid}/mem"))?;
    // Read access to a child's /proc/pid/mem is granted; write access is a
    // stronger check and can be denied, so fall back to read-only.
    let mut mem_writable = true;
    let mut mem = unsafe { libc::open(mem_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if mem < 0 {
        mem_writable = false;
        mem = unsafe { libc::open(mem_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    }
    if mem < 0 {
        // The child may have exited already; that is not a supervisor failure.
        mem_writable = false;
        if verbose {
            eprintln!(
                "pod-netns: /proc/{pid}/mem unavailable: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let stop = shutdown.clone();
        tokio::spawn(async move {
            loop {
                let mut status = 0;
                let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if r == pid {
                    stop.store(true, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
    }

    let mut map: HashMap<i32, Sock> = HashMap::new();
    let mut dns = FakeDns::new();
    for (name, ip) in &maps {
        dns.pin(name, *ip);
    }

    while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        let mut req: SeccompNotif = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::ioctl(lfd, SECCOMP_IOCTL_NOTIF_RECV, &mut req) };
        if r < 0 {
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => {
                    tokio::select! {
                        _ = async_fd.readable() => {}
                        _ = tokio::time::sleep(Duration::from_millis(20)) => {}
                    }
                    continue;
                }
                _ => break,
            }
        }
        let id = req.id;
        let nr = req.data.nr;
        let a = req.data.args;

        let outcome = if nr == libc::SYS_socket as i32 {
            handle_socket(lfd, id, a, &mut map)
        } else if nr == libc::SYS_connect as i32 {
            handle_connect(
                lfd, id, a, mem, &mut map, &mut dns, &proxies, &rules, verbose,
            )
            .await
        } else if nr == libc::SYS_sendto as i32 {
            handle_sendto(lfd, id, a, mem, &mut map, &mut dns, &proxies).await
        } else if nr == libc::SYS_sendmsg as i32 {
            handle_sendmsg(lfd, id, a, mem, &mut map, &mut dns, &proxies).await
        } else if nr == libc::SYS_sendmmsg as i32 {
            handle_sendmmsg(lfd, id, a, mem, &mut map, &mut dns, &proxies).await
        } else if nr == libc::SYS_setsockopt as i32 {
            // An AF_UNIX socketpair rejects IP-level options, which makes
            // glibc's resolver give up before it ever sends. Pretend.
            if map.contains_key(&(a[0] as i32)) {
                notif_respond(lfd, id, 0, 0)
            } else {
                notif_continue(lfd, id)
            }
        } else if nr == libc::SYS_getsockopt as i32 {
            handle_getsockopt(lfd, id, a, mem, mem_writable, &mut map)
        } else if nr == libc::SYS_close as i32 {
            // Drop the supervisor's end when the child closes an injected fd,
            // or the table and its socketpairs grow for the process lifetime.
            map.remove(&(a[0] as i32));
            notif_continue(lfd, id)
        } else if nr == libc::SYS_io_uring_setup as i32 {
            // io_uring submits network operations without the intercepted
            // syscalls, which would bypass this filter entirely. Refuse it.
            notif_respond(lfd, id, -1, libc::EPERM)
        } else if nr == libc::SYS_bind as i32 {
            handle_bind(lfd, id, a, mem, &mut map)
        } else if nr == libc::SYS_listen as i32 {
            handle_listen(lfd, id, a, &mut map, &inbound_dir).await
        } else if nr == libc::SYS_accept as i32 || nr == libc::SYS_accept4 as i32 {
            handle_accept(lfd, id, a, &mut map, nr == libc::SYS_accept4 as i32).await
        } else if nr == libc::SYS_getsockname as i32 || nr == libc::SYS_getpeername as i32 {
            handle_sockname(lfd, id, a, mem, mem_writable, &mut map)
        } else {
            notif_continue(lfd, id)
        };
        if let Err(e) = outcome {
            if verbose {
                eprintln!("pod-netns: notif {nr}: {e:#}");
            }
        }
    }
    unsafe { libc::close(mem) };

    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    Ok(if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        128 + libc::WTERMSIG(status)
    })
}

/// Above this many tracked descriptors the child is refused more, so a program
/// that leaks sockets cannot grow the supervisor without bound.
const MAX_TRACKED_FDS: usize = 4096;

fn handle_socket(lfd: RawFd, id: u64, a: [u64; 6], map: &mut HashMap<i32, Sock>) -> Result<()> {
    if map.len() >= MAX_TRACKED_FDS {
        return notif_respond(lfd, id, -1, libc::EMFILE);
    }
    let domain = a[0] as i32;
    let ty = a[1] as i32;
    let kind = ty & 0xf; // SOCK_STREAM=1, SOCK_DGRAM=2
    let inet = domain == libc::AF_INET || domain == libc::AF_INET6;
    if !inet || (kind != libc::SOCK_STREAM && kind != libc::SOCK_DGRAM) {
        return notif_continue(lfd, id);
    }
    // ADDFD only accepts O_CLOEXEC in newfd_flags on older kernels, so
    // SOCK_NONBLOCK is applied to the shared description instead: the child's
    // fd is a dup of `theirs`, so the flag is inherited.
    let mut newfd_flags = 0u32;
    if ty & libc::SOCK_CLOEXEC != 0 {
        newfd_flags |= libc::O_CLOEXEC as u32;
    }
    let nonblocking = ty & libc::SOCK_NONBLOCK != 0;
    if kind == libc::SOCK_STREAM {
        // A std pair is blocking on both ends; only the supervisor's end is
        // made non-blocking, so the child gets a blocking socket unless it
        // asked for SOCK_NONBLOCK.
        let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
        set_nonblocking(ours.as_raw_fd())?;
        if nonblocking {
            set_nonblocking(theirs.as_raw_fd())?;
        }
        let child_fd = notif_addfd_send(lfd, id, theirs.as_raw_fd(), newfd_flags)?;
        drop(theirs);
        map.insert(
            child_fd,
            Sock::Stream {
                pair: tokio::net::UnixStream::from_std(ours)?,
                bound: None,
                inbound: None,
            },
        );
    } else {
        let (ours, theirs) = std::os::unix::net::UnixDatagram::pair()?;
        set_nonblocking(ours.as_raw_fd())?;
        if nonblocking {
            set_nonblocking(theirs.as_raw_fd())?;
        }
        let child_fd = notif_addfd_send(lfd, id, theirs.as_raw_fd(), newfd_flags)?;
        drop(theirs);
        map.insert(
            child_fd,
            Sock::Datagram {
                pair: Arc::new(tokio::net::UnixDatagram::from_std(ours)?),
                dest: None,
                relay: None,
            },
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_connect(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    map: &mut HashMap<i32, Sock>,
    dns: &mut FakeDns,
    proxies: &[Proxy],
    rules: &[Rule],
    verbose: bool,
) -> Result<()> {
    let fd = a[0] as i32;
    let is_datagram = matches!(map.get(&fd), Some(Sock::Datagram { .. }));
    if !map.contains_key(&fd) {
        return notif_continue(lfd, id);
    }
    let addr = read_mem(mem, a[1], (a[2] as usize).min(128))?;
    let Some((_family, ip, port)) = parse_sockaddr(&addr) else {
        return notif_respond(lfd, id, -1, libc::EAFNOSUPPORT);
    };
    if is_datagram {
        if let Some(Sock::Datagram { dest, .. }) = map.get_mut(&fd) {
            *dest = Some((ip, port));
        }
        return notif_respond(lfd, id, 0, 0);
    }
    let target = match ip {
        IpAddr::V4(v4) => match dns.name_for(v4) {
            Some(name) => format!("{name}:{port}"),
            None => format!("{v4}:{port}"),
        },
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    };
    let chain = select_chain(rules, proxies, &target);
    if verbose {
        eprintln!("pod-netns: connect {target} via {}", chain[0].endpoint());
    }
    match within_timeout("upstream connect", connect_upstream_async(chain, &target)).await {
        Ok(mut upstream) => {
            notif_respond(lfd, id, 0, 0)?;
            if let Some(Sock::Stream { mut pair, .. }) = map.remove(&fd) {
                tokio::spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut pair, &mut upstream).await;
                });
            }
        }
        Err(e) => {
            if verbose {
                eprintln!("pod-netns: upstream for {target} failed: {e:#}");
            }
            notif_respond(lfd, id, -1, libc::ECONNREFUSED)?;
        }
    }
    Ok(())
}

async fn handle_sendto(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    map: &mut HashMap<i32, Sock>,
    dns: &mut FakeDns,
    proxies: &[Proxy],
) -> Result<()> {
    let fd = a[0] as i32;
    let buf = a[1];
    let len = a[2] as usize;
    let name = a[4];
    let namelen = a[5] as usize;
    let (recorded, pair) = match map.get(&fd) {
        Some(Sock::Datagram { dest, pair, .. }) => (*dest, pair.clone()),
        _ => return notif_continue(lfd, id),
    };
    let target = if name != 0 && namelen >= 4 {
        parse_sockaddr(&read_mem(mem, name, namelen.min(128))?)
            .map(|(_, ip, port)| (ip, port))
            .or(recorded)
    } else {
        recorded
    };
    let Some((ip, port)) = target else {
        return notif_respond(lfd, id, -1, libc::EDESTADDRREQ);
    };
    if port == DNS_PORT {
        let query = read_mem(mem, buf, len)?;
        let Ok(parsed) = cfrs::vnet::dns::ParsedQuery::parse(&query) else {
            return notif_respond(lfd, id, -1, libc::EINVAL);
        };
        let fake = dns.address_for(&parsed.name);
        let reply = cfrs::vnet::dns::build_response(&parsed, &[IpAddr::V4(fake)], 0);
        let _ = pair.send(&reply).await;
        return notif_respond(lfd, id, len as i64, 0);
    }
    let payload = read_mem(mem, buf, len)?;
    match relay_datagram(map, fd, &proxies[0], pair, &payload, ip, port).await {
        Ok(()) => notif_respond(lfd, id, len as i64, 0),
        Err(e) => {
            let _ = notif_respond(lfd, id, -1, libc::ENETUNREACH);
            Err(e)
        }
    }
}

/// `sendmmsg` is what glibc's resolver uses: a vector of `mmsghdr`. Only the
/// first message is answered.
async fn handle_sendmmsg(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    map: &mut HashMap<i32, Sock>,
    dns: &mut FakeDns,
    proxies: &[Proxy],
) -> Result<()> {
    let fd = a[0] as i32;
    let msgvec = a[1];
    let vlen = a[2] as usize;
    if vlen == 0 {
        return notif_respond(lfd, id, 0, 0);
    }
    // struct mmsghdr = struct msghdr (56 bytes) + u32 msg_len + padding.
    handle_sendmsg(
        lfd,
        id,
        [fd as u64, msgvec, 0, 0, 0, 0],
        mem,
        map,
        dns,
        proxies,
    )
    .await
}

async fn handle_sendmsg(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    map: &mut HashMap<i32, Sock>,
    dns: &mut FakeDns,
    proxies: &[Proxy],
) -> Result<()> {
    let fd = a[0] as i32;
    let msg_ptr = a[1];
    let (recorded, pair) = match map.get(&fd) {
        Some(Sock::Datagram { dest, pair, .. }) => (*dest, pair.clone()),
        _ => return notif_continue(lfd, id),
    };
    // struct msghdr on x86_64: name, namelen, iov, iovlen, control, controllen, flags.
    let hdr = read_mem(mem, msg_ptr, 56)?;
    let name_ptr = u64::from_ne_bytes(hdr[0..8].try_into().unwrap());
    let name_len = u32::from_ne_bytes(hdr[8..12].try_into().unwrap()) as usize;
    let iov_ptr = u64::from_ne_bytes(hdr[16..24].try_into().unwrap());
    let iov_len = u64::from_ne_bytes(hdr[24..32].try_into().unwrap()) as usize;
    let target = if name_ptr != 0 && name_len >= 4 {
        parse_sockaddr(&read_mem(mem, name_ptr, name_len.min(128))?)
            .map(|(_, ip, port)| (ip, port))
            .or(recorded)
    } else {
        recorded
    };
    let Some((ip, port)) = target else {
        return notif_respond(lfd, id, -1, libc::EDESTADDRREQ);
    };
    let mut payload = Vec::new();
    for i in 0..iov_len.min(8) {
        let iov = read_mem(mem, iov_ptr + (i as u64) * 16, 16)?;
        let base = u64::from_ne_bytes(iov[0..8].try_into().unwrap());
        let len = u64::from_ne_bytes(iov[8..16].try_into().unwrap()) as usize;
        if len == 0 {
            continue;
        }
        payload.extend_from_slice(&read_mem(mem, base, len.min(65536))?);
    }
    if port == DNS_PORT {
        let Ok(parsed) = cfrs::vnet::dns::ParsedQuery::parse(&payload) else {
            return notif_respond(lfd, id, -1, libc::EINVAL);
        };
        let fake = dns.address_for(&parsed.name);
        let reply = cfrs::vnet::dns::build_response(&parsed, &[IpAddr::V4(fake)], 0);
        let _ = pair.send(&reply).await;
        return notif_respond(lfd, id, payload.len() as i64, 0);
    }
    match relay_datagram(map, fd, &proxies[0], pair, &payload, ip, port).await {
        Ok(()) => notif_respond(lfd, id, payload.len() as i64, 0),
        Err(e) => {
            let _ = notif_respond(lfd, id, -1, libc::ENETUNREACH);
            Err(e)
        }
    }
}

async fn ensure_udp_relay(
    map: &mut HashMap<i32, Sock>,
    fd: i32,
    proxy: &Proxy,
    pair: Arc<tokio::net::UnixDatagram>,
) -> Result<()> {
    if matches!(map.get(&fd), Some(Sock::Datagram { relay: Some(_), .. })) {
        return Ok(());
    }
    if proxy.kind != ProxyKind::Socks5 {
        bail!("UDP relay needs a SOCKS5 proxy");
    }
    let control = within_timeout("udp associate dial", dial_proxy(proxy)).await?;
    let (control, relay_addr) =
        within_timeout("udp associate", socks5_udp_associate(control, proxy)).await?;
    let udp = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
    let reader = udp.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((n, _)) = reader.recv_from(&mut buf).await else {
                break;
            };
            if n < 4 {
                continue;
            }
            let off = match buf[3] {
                0x01 => 10,
                0x03 => 4 + 1 + buf[4] as usize + 2,
                0x04 => 22,
                _ => continue,
            };
            if n < off {
                continue;
            }
            let _ = pair.send(&buf[off..n]).await;
        }
    });
    if let Some(Sock::Datagram { relay, .. }) = map.get_mut(&fd) {
        *relay = Some(UdpRelay {
            udp,
            relay_addr,
            _control: control,
        });
    }
    Ok(())
}

/// Wrap a datagram in a SOCKS5 UDP request header and send it to the relay.
async fn relay_datagram(
    map: &mut HashMap<i32, Sock>,
    fd: i32,
    proxy: &Proxy,
    pair: Arc<tokio::net::UnixDatagram>,
    payload: &[u8],
    ip: IpAddr,
    port: u16,
) -> Result<()> {
    ensure_udp_relay(map, fd, proxy, pair).await?;
    let wrapped = wrap_udp(payload, ip, port);
    if let Some(Sock::Datagram { relay: Some(r), .. }) = map.get(&fd) {
        r.udp.send_to(&wrapped, r.relay_addr).await?;
    }
    Ok(())
}

fn handle_bind(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    map: &mut HashMap<i32, Sock>,
) -> Result<()> {
    let fd = a[0] as i32;
    match map.get_mut(&fd) {
        Some(Sock::Stream { bound, .. }) => {
            if a[1] != 0 && a[2] >= 4 {
                if let Some((_, ip, port)) =
                    parse_sockaddr(&read_mem(mem, a[1], (a[2] as usize).min(128))?)
                {
                    *bound = Some((ip, port));
                }
            }
            notif_respond(lfd, id, 0, 0)
        }
        // A datagram socket that binds a local port is a socketpair here.
        Some(Sock::Datagram { .. }) => notif_respond(lfd, id, 0, 0),
        None => notif_continue(lfd, id),
    }
}

/// `listen` creates the real listener the sandbox can have: a unix socket named
/// after the port. A reader task turns accepted connections into a queue that
/// `accept` draws from.
async fn handle_listen(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    map: &mut HashMap<i32, Sock>,
    inbound_dir: &std::path::Path,
) -> Result<()> {
    let fd = a[0] as i32;
    let Some(Sock::Stream {
        bound: Some((_, port)),
        ..
    }) = map.get(&fd)
    else {
        return notif_continue(lfd, id);
    };
    let port = *port;
    std::fs::create_dir_all(inbound_dir)?;
    let path = inbound_dir.join(format!("{port}.sock"));
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path)
        .with_context(|| format!("bind inbound listener {}", path.display()))?;
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((conn, _)) = listener.accept().await {
            if tx.send(conn).is_err() {
                break;
            }
        }
    });
    if let Some(Sock::Stream { inbound, .. }) = map.get_mut(&fd) {
        *inbound = Some(Inbound { rx });
    }
    notif_respond(lfd, id, 0, 0)?;
    // The listener is a real unix socket; say where it is.
    eprintln!("pod-netns: listening on unix:{} (port {port})", path.display());
    Ok(())
}

async fn handle_accept(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    map: &mut HashMap<i32, Sock>,
    accept4: bool,
) -> Result<()> {
    let fd = a[0] as i32;
    // The caller's flags are on accept4 only; ADDFD takes just O_CLOEXEC.
    let flags = if accept4 { a[3] as i32 } else { 0 };
    let mut newfd_flags = 0u32;
    if flags & libc::SOCK_CLOEXEC != 0 {
        newfd_flags |= libc::O_CLOEXEC as u32;
    }
    let conn = {
        let Some(Sock::Stream {
            inbound: Some(inc), ..
        }) = map.get_mut(&fd)
        else {
            return notif_continue(lfd, id);
        };
        match inc.rx.recv().await {
            Some(c) => c,
            None => return notif_respond(lfd, id, -1, libc::EINVAL),
        }
    };
    let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
    set_nonblocking(ours.as_raw_fd())?;
    if flags & libc::SOCK_NONBLOCK != 0 {
        set_nonblocking(theirs.as_raw_fd())?;
    }
    // ADDFD with SEND already answers the syscall with the installed fd.
    notif_addfd_send(lfd, id, theirs.as_raw_fd(), newfd_flags)?;
    drop(theirs);
    let mut ours = tokio::net::UnixStream::from_std(ours)?;
    let mut conn = conn;
    tokio::spawn(async move {
        let _ = tokio::io::copy_bidirectional(&mut ours, &mut conn).await;
    });
    Ok(())
}

fn handle_getsockopt(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    writable: bool,
    map: &mut HashMap<i32, Sock>,
) -> Result<()> {
    let fd = a[0] as i32;
    let level = a[1] as i32;
    let optname = a[2] as i32;
    let optval = a[3];
    let optlen_ptr = a[4];
    let Some(entry) = map.get(&fd) else {
        return notif_continue(lfd, id);
    };
    if !writable || optval == 0 || optlen_ptr == 0 {
        return notif_continue(lfd, id);
    }
    let len = read_mem(mem, optlen_ptr, 4)?;
    let len = u32::from_ne_bytes(len[..4].try_into().unwrap()) as usize;
    if len == 0 || len > 256 {
        return notif_continue(lfd, id);
    }
    let mut val = vec![0u8; len];
    if level == libc::SOL_SOCKET && optname == libc::SO_TYPE {
        let ty = match entry {
            Sock::Stream { .. } => libc::SOCK_STREAM,
            Sock::Datagram { .. } => libc::SOCK_DGRAM,
        };
        let b = (ty as u32).to_ne_bytes();
        val[..4].copy_from_slice(&b);
    }
    write_mem(mem, optval, &val)?;
    notif_respond(lfd, id, 0, 0)
}

fn handle_sockname(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    writable: bool,
    map: &mut HashMap<i32, Sock>,
) -> Result<()> {
    let fd = a[0] as i32;
    let Some(entry) = map.get(&fd) else {
        return notif_continue(lfd, id);
    };
    if !writable {
        // Cannot rewrite the caller's sockaddr; let the kernel answer (it will
        // report the AF_UNIX socketpair).
        return notif_continue(lfd, id);
    }
    // Answer with a plausible INET address so a program that checks it does not
    // see an AF_UNIX socketpair.
    let (ip, port) = match entry {
        Sock::Stream { bound, .. } => bound.unwrap_or((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
        Sock::Datagram { dest, .. } => dest.unwrap_or((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
    };
    let family = if ip.is_ipv4() {
        libc::AF_INET as u16
    } else {
        libc::AF_INET6 as u16
    };
    let bytes = sockaddr_in(family, ip, port);
    let out_len = (bytes.len() as u64).to_ne_bytes();
    write_mem(mem, a[2], &out_len)?;
    if a[1] != 0 {
        write_mem(mem, a[1], &bytes)?;
    }
    notif_respond(lfd, id, 0, 0)
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("pod-netns: {e:#}");
            std::process::exit(2);
        }
    };
    if args.doctor {
        std::process::exit(doctor(args.doctor_json));
    }
    if args.serve.is_some() {
        if args.proxies.is_empty() {
            eprintln!("pod-netns: --serve needs at least one -x upstream");
            std::process::exit(2);
        }
        let listen = args.serve.clone().unwrap();
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("pod-netns: {e:#}");
                std::process::exit(EXIT_NO_BACKEND);
            }
        };
        let outcome = runtime.block_on(serve_front_door(
            listen,
            args.proxies.clone(),
            args.rules.clone(),
            args.verbose,
        ));
        match outcome {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("pod-netns: {e:#}");
                std::process::exit(EXIT_NO_BACKEND);
            }
        }
    }
    let result = match args.backend {
        BackendKind::Netns => run(args),
        BackendKind::Seccomp => run_seccomp(args),
        BackendKind::Auto => {
            // The netns backend needs unshare and a TUN; without them the
            // seccomp backend is the only thing that can work.
            if probe_unshare(libc::CLONE_NEWNET).ok
                || probe_unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET).ok
            {
                run(args)
            } else {
                run_seccomp(args)
            }
        }
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("pod-netns: {e:#}");
            std::process::exit(EXIT_NO_BACKEND);
        }
    }
}
