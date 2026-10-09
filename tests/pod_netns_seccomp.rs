//! End-to-end tests for `pod-netns`'s seccomp backend.
//!
//! A SOCKS5 proxy listens on a unix socket (the only bind a sealed host
//! permits). A compiled C program calls `socket(AF_INET)`/`connect(AF_INET)`
//! normally; the filter stops both and the supervisor hands it a socketpair
//! and dials the proxy. No `LD_PRELOAD` is involved, so a **static** build is
//! exercised too — that is the whole point of the backend.
//!
//! Three tests: a single proxy, two chained hops, and UDP relayed through
//! `UDP ASSOCIATE`. If the host does not offer `SECCOMP_RET_USER_NOTIF` they
//! report that and pass, as the other shim tests do without a compiler.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use cfrs::vnet::shim;

fn have_compiler() -> bool {
    shim::compiler().is_ok()
}

fn build_program(dir: &std::path::Path, name: &str, source: &str, static_link: bool) -> PathBuf {
    let source_path = dir.join(format!("{name}.c"));
    std::fs::write(&source_path, source).unwrap();
    let output = dir.join(name);
    let cc = shim::compiler().unwrap();
    let mut cmd = Command::new(cc);
    cmd.arg("-O2");
    if static_link {
        cmd.arg("-static");
    }
    let status = cmd
        .arg("-o")
        .arg(&output)
        .arg(&source_path)
        .status()
        .unwrap();
    assert!(status.success(), "compiling {name} failed");
    output
}

/// Read a SOCKS5 request after the method handshake; returns (cmd, host, port).
fn read_request(c: &mut UnixStream) -> Option<(u8, String, u16)> {
    let mut hdr = [0u8; 2];
    c.read_exact(&mut hdr).ok()?;
    let mut methods = vec![0u8; hdr[1] as usize];
    c.read_exact(&mut methods).ok()?;
    c.write_all(&[5, 0]).ok()?;
    let mut req = [0u8; 4];
    c.read_exact(&mut req).ok()?;
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            c.read_exact(&mut a).ok()?;
            Ipv4Addr::from(a).to_string()
        }
        3 => {
            let mut l = [0u8; 1];
            c.read_exact(&mut l).ok()?;
            let mut h = vec![0u8; l[0] as usize];
            c.read_exact(&mut h).ok()?;
            String::from_utf8_lossy(&h).to_string()
        }
        4 => {
            let mut a = [0u8; 16];
            c.read_exact(&mut a).ok()?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => return None,
    };
    let mut p = [0u8; 2];
    c.read_exact(&mut p).ok()?;
    Some((req[1], host, u16::from_be_bytes(p)))
}

/// A SOCKS5 CONNECT proxy on a unix socket. With `hop`, a target named
/// `unix:<path>` is forwarded to that socket; otherwise it greets and echoes.
fn socks5_proxy(listener: UnixListener, targets: mpsc::Sender<String>, hop: bool) {
    for conn in listener.incoming() {
        let mut c = match conn {
            Ok(c) => c,
            Err(_) => break,
        };
        let targets = targets.clone();
        let _ = std::thread::spawn(move || {
            let Some((cmd, host, port)) = read_request(&mut c) else {
                return;
            };
            if cmd != 1 {
                return;
            }
            let _ = targets.send(format!("{host}:{port}"));
            if hop && host.starts_with("unix:") {
                let Ok(mut up) = UnixStream::connect(&host[5..]) else {
                    return;
                };
                let _ = c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
                let mut up2 = up.try_clone().unwrap();
                let mut c2 = c.try_clone().unwrap();
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut up2, &mut c2);
                    let _ = c2.shutdown(std::net::Shutdown::Write);
                });
                let _ = std::io::copy(&mut c, &mut up);
            } else {
                let _ = c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
                let _ = c.write_all(b"HELLO-FROM-TARGET\n");
                let mut buf = [0u8; 4096];
                while let Ok(n) = c.read(&mut buf) {
                    if n == 0 || c.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        });
    }
}

fn seccomp_available() -> bool {
    let out = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .arg("doctor")
        .output()
        .expect("run pod-netns doctor");
    String::from_utf8_lossy(&out.stdout).contains("SECCOMP_RET_USER_NOTIF    ok")
}

fn run(dir: &std::path::Path, proxies: &[&std::path::Path], program: &std::path::Path) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pod-netns"));
    cmd.args(["--backend", "seccomp"]);
    for p in proxies {
        cmd.arg("-x").arg(format!("unix:{}", p.display()));
    }
    let output = cmd.arg("--").arg(program).output().expect("run pod-netns");
    assert!(
        output.status.success(),
        "pod-netns failed: stderr={:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

const CLIENT: &str = r#"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(80);
    inet_pton(AF_INET, "93.184.216.34", &a.sin_addr);
    if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) { perror("connect"); return 1; }
    write(s, "PING\n", 5);
    char b[64] = {0};
    int n = read(s, b, sizeof b - 1);
    printf("READ:%d:%s", n, b);
    return 0;
}
"#;

const SERVER: &str = r#"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(8080);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) { perror("bind"); return 1; }
    if (listen(s, 4) < 0) { perror("listen"); return 1; }
    int c = accept(s, NULL, NULL);
    if (c < 0) { perror("accept"); return 1; }
    char b[64] = {0};
    int n = read(c, b, sizeof b - 1);
    if (n <= 0) return 1;
    write(c, "PONG\n", 5);
    return 0;
}
"#;

const DNS_CLIENT: &str = r#"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(void) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    int r = getaddrinfo("example.com", "80", &hints, &res);
    if (r != 0) { printf("GAI:%d\n", r); return 1; }
    char ip[64] = {0};
    inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, ip, sizeof ip);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(s, res->ai_addr, res->ai_addrlen) < 0) { perror("connect"); return 1; }
    char b[64] = {0};
    int n = read(s, b, sizeof b - 1);
    printf("DNS:%s:%d:%s", ip, n, b);
    return 0;
}
"#;

const IPV6_CLIENT: &str = r#"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(void) {
    int s = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 a; memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6; a.sin6_port = htons(80);
    inet_pton(AF_INET6, "2001:db8::1", &a.sin6_addr);
    if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) { perror("connect"); return 1; }
    write(s, "PING\n", 5);
    char b[64] = {0};
    int n = read(s, b, sizeof b - 1);
    printf("READ6:%d:%s", n, b);
    return 0;
}
"#;

const UDP_CLIENT: &str = r#"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in d; memset(&d, 0, sizeof d);
    d.sin_family = AF_INET; d.sin_port = htons(9999);
    inet_pton(AF_INET, "127.0.0.1", &d.sin_addr);
    if (sendto(s, "PING", 4, 0, (struct sockaddr *)&d, sizeof d) < 0) { perror("sendto"); return 1; }
    char b[128] = {0};
    int n = recvfrom(s, b, sizeof b - 1, 0, NULL, NULL);
    printf("UDP:%d:%s", n, n > 0 ? b : "");
    return 0;
}
"#;

#[test]
fn seccomp_backend_proxies_a_static_and_a_dynamic_binary() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("socks.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || socks5_proxy(listener, tx, false));

    let dynamic = build_program(&dir, "client-dynamic", CLIENT, false);
    let statically = build_program(&dir, "client-static", CLIENT, true);
    for program in [&dynamic, &statically] {
        let stdout = run(&dir, &[&sock], program);
        assert!(stdout.contains("READ:18:HELLO-FROM-TARGET"), "{stdout:?}");
    }
    assert_eq!(rx.recv().unwrap(), "93.184.216.34:80");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seccomp_backend_chains_two_proxies() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-chain-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p1 = dir.join("p1.sock");
    let p2 = dir.join("p2.sock");
    let (tx1, rx1) = mpsc::channel();
    let (tx2, rx2) = mpsc::channel();
    let l2 = UnixListener::bind(&p2).unwrap();
    let l1 = UnixListener::bind(&p1).unwrap();
    std::thread::spawn(move || socks5_proxy(l2, tx2, false));
    std::thread::spawn(move || socks5_proxy(l1, tx1, true));

    let program = build_program(&dir, "client-chain", CLIENT, false);
    let stdout = run(&dir, &[&p1, &p2], &program);
    assert!(stdout.contains("READ:18:HELLO-FROM-TARGET"), "{stdout:?}");
    // The first hop was asked for the second, not for the target.
    assert_eq!(rx1.recv().unwrap(), format!("unix:{}:0", p2.display()));
    assert_eq!(rx2.recv().unwrap(), "93.184.216.34:80");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seccomp_backend_relays_udp() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-udp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("socks.sock");

    // A UDP echo, the thing the client believes it is talking to.
    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 65535];
        while let Ok((n, from)) = echo.recv_from(&mut buf) {
            let mut reply = b"ECHO:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            let _ = echo.send_to(&reply, from);
        }
    });

    // A SOCKS5 proxy with UDP ASSOCIATE on a unix control socket.
    let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let listener = UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let mut c = match conn {
                Ok(c) => c,
                Err(_) => break,
            };
            let Some((cmd, _host, _port)) = read_request(&mut c) else {
                continue;
            };
            if cmd != 3 {
                continue;
            }
            let mut bnd = vec![5u8, 0, 0, 1];
            bnd.extend_from_slice(
                &relay_addr
                    .ip()
                    .to_string()
                    .parse::<Ipv4Addr>()
                    .unwrap()
                    .octets(),
            );
            bnd.extend_from_slice(&relay_addr.port().to_be_bytes());
            let _ = c.write_all(&bnd);
            // Hold the control connection open for the life of the test.
            let mut buf = [0u8; 1];
            while c.read(&mut buf).unwrap_or(0) == 1 {}
        }
    });
    // The relay: unwrap a SOCKS5 UDP header, forward, wrap the reply.
    {
        let echo_addr = echo_addr;
        std::thread::spawn(move || {
            let mut buf = [0u8; 65535];
            while let Ok((n, from)) = relay.recv_from(&mut buf) {
                if n < 4 {
                    continue;
                }
                let off = match buf[3] {
                    1 => 10,
                    3 => 4 + 1 + buf[4] as usize + 2,
                    4 => 22,
                    _ => continue,
                };
                if n < off {
                    continue;
                }
                let up = UdpSocket::bind("127.0.0.1:0").unwrap();
                up.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let _ = up.send_to(&buf[off..n], echo_addr);
                let mut reply = [0u8; 65535];
                if let Ok((rn, _)) = up.recv_from(&mut reply) {
                    let mut out = vec![0u8, 0, 0, 1, 127, 0, 0, 1];
                    out.extend_from_slice(&echo_addr.port().to_be_bytes());
                    out.extend_from_slice(&reply[..rn]);
                    let _ = relay.send_to(&out, from);
                }
            }
        });
    }

    let program = build_program(&dir, "udp-client", UDP_CLIENT, false);
    let stdout = run(&dir, &[&sock], &program);
    assert!(stdout.contains("UDP:9:ECHO:PING"), "{stdout:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seccomp_backend_routes_by_rule() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-route-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p1 = dir.join("p1.sock");
    let p2 = dir.join("p2.sock");
    let l1 = UnixListener::bind(&p1).unwrap();
    let l2 = UnixListener::bind(&p2).unwrap();
    let (tx1, rx1) = mpsc::channel();
    let (tx2, rx2) = mpsc::channel();
    std::thread::spawn(move || socks5_proxy(l1, tx1, false));
    std::thread::spawn(move || socks5_proxy(l2, tx2, false));

    let program = build_program(&dir, "client-route", CLIENT, false);
    let output = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--backend", "seccomp", "-x"])
        .arg(format!("unix:{}", p1.display()))
        .args(["-r"])
        .arg(format!("cidr:93.184.0.0/16=unix:{}", p2.display()))
        .arg("--")
        .arg(&program)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("READ:18:HELLO-FROM-TARGET"));
    // The rule proxy saw it; the default did not.
    assert_eq!(rx2.recv().unwrap(), "93.184.216.34:80");
    assert!(
        rx1.try_recv().is_err(),
        "the default proxy must not be used"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seccomp_backend_accepts_inbound() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-inbound-{}", std::process::id()));
    let inbound = dir.join("in");
    std::fs::create_dir_all(&inbound).unwrap();
    let proxy = dir.join("socks.sock");
    let listener = UnixListener::bind(&proxy).unwrap();
    let (tx, _rx) = mpsc::channel();
    std::thread::spawn(move || socks5_proxy(listener, tx, false));

    let server = build_program(&dir, "server", SERVER, false);
    let mut child = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--backend", "seccomp", "--inbound-dir"])
        .arg(&inbound)
        .args(["-x"])
        .arg(format!("unix:{}", proxy.display()))
        .arg("--")
        .arg(&server)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // The listener is a unix socket named after the bound port.
    let sockpath = inbound.join("8080.sock");
    let mut conn = None;
    for _ in 0..100 {
        if let Ok(c) = UnixStream::connect(&sockpath) {
            conn = Some(c);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut c = conn.expect("the inbound listener did not appear");
    c.write_all(b"PING\n").unwrap();
    let mut buf = [0u8; 16];
    let n = c.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"PONG\n");
    drop(c);
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pod_netns_serves_a_front_door_and_chains_with_itself() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-serve-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let echo = dir.join("echo.sock");
    let front = dir.join("front.sock");
    let listener = UnixListener::bind(&echo).unwrap();
    let (tx, _rx) = mpsc::channel();
    std::thread::spawn(move || socks5_proxy(listener, tx, false));

    // One instance serves SOCKS5 and forwards through the echo proxy.
    let mut server = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--serve"])
        .arg(format!("unix:{}", front.display()))
        .args(["-x"])
        .arg(format!("unix:{}", echo.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if front.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // A second instance runs a client through the first one's front door.
    let program = build_program(&dir, "client-serve", CLIENT, false);
    let stdout = run(&dir, &[&front], &program);
    assert!(stdout.contains("READ:18:HELLO-FROM-TARGET"), "{stdout:?}");

    let _ = server.kill();
    let _ = server.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seccomp_backend_dials_the_tailnet_with_no_shim() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-ts-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let api = dir.join("tailscaled.sock");
    let listener = UnixListener::bind(&api).unwrap();
    // A stand-in for tailscaled's LocalAPI: accept the ts-dial upgrade, greet,
    // then echo.
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let mut c = match conn {
                Ok(c) => c,
                Err(_) => break,
            };
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while c.read(&mut b).unwrap_or(0) == 1 {
                    head.push(b[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                if !String::from_utf8_lossy(&head).contains("Upgrade: ts-dial") {
                    return;
                }
                let _ = c.write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: ts-dial\r\nConnection: upgrade\r\n\r\n",
                );
                let _ = c.write_all(b"HELLO-FROM-TAILNET\n");
                let mut buf = [0u8; 4096];
                while let Ok(n) = c.read(&mut buf) {
                    if n == 0 || c.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });

    let program = build_program(&dir, "client-ts", CLIENT, false);
    let output = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--backend", "seccomp", "-x"])
        .arg(format!("tailscale:{}", api.display()))
        .arg("--")
        .arg(&program)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("READ:19:HELLO-FROM-TAILNET"),
        "{:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pod_netns_serves_a_udp_front_door() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-udpfront-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 65535];
        while let Ok((n, from)) = echo.recv_from(&mut buf) {
            let mut reply = b"ECHO:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            let _ = echo.send_to(&reply, from);
        }
    });

    // A UDP ASSOCIATE proxy for the front door to forward through.
    let socks = dir.join("udp.sock");
    let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let listener = UnixListener::bind(&socks).unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let mut c = match conn {
                Ok(c) => c,
                Err(_) => break,
            };
            let Some((cmd, _, _)) = read_request(&mut c) else {
                continue;
            };
            if cmd != 3 {
                continue;
            }
            let mut bnd = vec![5u8, 0, 0, 1];
            bnd.extend_from_slice(
                &relay_addr
                    .ip()
                    .to_string()
                    .parse::<Ipv4Addr>()
                    .unwrap()
                    .octets(),
            );
            bnd.extend_from_slice(&relay_addr.port().to_be_bytes());
            let _ = c.write_all(&bnd);
            let mut buf = [0u8; 1];
            while c.read(&mut buf).unwrap_or(0) == 1 {}
        }
    });
    {
        std::thread::spawn(move || {
            let mut buf = [0u8; 65535];
            while let Ok((n, from)) = relay.recv_from(&mut buf) {
                if n < 4 {
                    continue;
                }
                let off = match buf[3] {
                    1 => 10,
                    3 => 4 + 1 + buf[4] as usize + 2,
                    4 => 22,
                    _ => continue,
                };
                if n < off {
                    continue;
                }
                let up = UdpSocket::bind("127.0.0.1:0").unwrap();
                up.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let _ = up.send_to(&buf[off..n], echo_addr);
                let mut reply = [0u8; 65535];
                if let Ok((rn, _)) = up.recv_from(&mut reply) {
                    let mut out = vec![0u8, 0, 0, 1, 127, 0, 0, 1];
                    out.extend_from_slice(&echo_addr.port().to_be_bytes());
                    out.extend_from_slice(&reply[..rn]);
                    let _ = relay.send_to(&out, from);
                }
            }
        });
    }

    let front = dir.join("front.sock");
    let mut server = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--serve"])
        .arg(format!("unix:{}", front.display()))
        .args(["-x"])
        .arg(format!("unix:{}", socks.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if front.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let program = build_program(&dir, "udp-client-front", UDP_CLIENT, false);
    let output = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--backend", "seccomp", "-x"])
        .arg(format!("unix:{}", front.display()))
        .arg("--")
        .arg(&program)
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("UDP:9:ECHO:PING"),
        "{:?}",
        String::from_utf8_lossy(&output.stdout)
    );

    let _ = server.kill();
    let _ = server.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seccomp_backend_proxies_ipv6_targets() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-v6-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("socks.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || socks5_proxy(listener, tx, false));

    let program = build_program(&dir, "client6", IPV6_CLIENT, false);
    let stdout = run(&dir, &[&sock], &program);
    assert!(stdout.contains("READ6:18:HELLO-FROM-TARGET"), "{stdout:?}");
    // The address reaches the proxy as an IPv6 target, not as a name.
    assert_eq!(rx.recv().unwrap(), "2001:db8::1:80");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seccomp_backend_uses_an_ambient_proxy() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-env-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("socks.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let (tx, _rx) = mpsc::channel();
    std::thread::spawn(move || socks5_proxy(listener, tx, false));

    let program = build_program(&dir, "client-env", CLIENT, false);
    // No -x: the proxy comes from the environment.
    let output = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--backend", "seccomp", "--"])
        .arg(&program)
        .env("ALL_PROXY", format!("socks5://unix:{}", sock.display()))
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("READ:18:HELLO-FROM-TARGET"),
        "{:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seccomp_backend_pins_names_with_map() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-map-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("socks.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || socks5_proxy(listener, tx, false));

    let program = build_program(&dir, "client-map", DNS_CLIENT, false);
    let output = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--backend", "seccomp", "--map", "example.com=1.2.3.4", "-x"])
        .arg(format!("unix:{}", sock.display()))
        .arg("--")
        .arg(&program)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DNS:1.2.3.4:18:HELLO-FROM-TARGET"), "{stdout:?}");
    // The pinned address reaches the proxy, not a fake IP.
    assert_eq!(rx.recv().unwrap(), "1.2.3.4:80");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn doctor_json_is_machine_readable() {
    let out = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).expect("doctor --json is JSON");
    assert!(value["capabilities"].is_object());
    assert!(value["backend_seccomp"].is_boolean());
    assert!(value["backend_available"].is_boolean());
    // The exit code must agree with the report.
    let any = value["backend_available"].as_bool().unwrap();
    assert_eq!(out.status.success(), any);
}
