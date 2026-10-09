//! Integration tests for pod-netns.
//!
//! Every test that asserts a capability has a matching control: the same
//! program run WITHOUT pod-netns, to show the cage would have refused it. A
//! test that cannot fail on an unfixed cage is not a test, and the two I
//! drafted that only exercised their own scaffolding were deleted rather than
//! kept as decoration.
//!
//! The child is `testdata/sg`, a statically linked Go binary, chosen
//! deliberately: it is the case an LD_PRELOAD shim cannot reach, so passing
//! here is evidence the approach needs no loader.

use std::process::{Command, Stdio};

fn bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().expect("test exe path");
    p.pop(); // deps
    p.pop(); // <profile dir>
    p.join("pod-netns")
}

fn child() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/sg/sg")
}

/// Skipping is reported loudly, because a silent skip reads as a pass.
/// Every fixture this suite needs, with the command that builds it.
///
/// The list exists so one test can assert that all of them are present, rather
/// than each test quietly skipping when its own fixture is missing. That matters
/// because `cargo test` captures stderr and discards it on success, so a test that
/// prints SKIPPED and returns still reports `ok`: a fresh clone where the fixtures
/// were never built looks identical to a green run, which is exactly the reading
/// this suite must not permit. Compiled fixtures are not committed, so a clean
/// checkout genuinely does need this run.
const FIXTURES: &[(&str, &str)] = &[
    ("testdata/sg/sg", "(cd testdata/sg && CGO_ENABLED=0 go build -o sg .)"),
    ("testdata/gs/gs", "(cd testdata/gs && CGO_ENABLED=0 go build -o gs .)"),
    ("testdata/cdyn/cdyn", "mkdir -p testdata/cdyn && cc -O1 -o testdata/cdyn/cdyn testdata/cdyn.c"),
    ("testdata/relayer", "cc -O1 -o testdata/relayer testdata/relayer.c"),
    ("testdata/srv", "cc -O1 -o testdata/srv testdata/srv.c"),
    ("testdata/ucli", "cc -O1 -o testdata/ucli testdata/ucli.c"),
    ("testdata/iclient", "cc -O1 -o testdata/iclient testdata/iclient.c"),
    ("testdata/dnsfix", "cc -O1 -o testdata/dnsfix testdata/dnsfix.c"),
];

/// The gate. Without it a missing fixture silently removes coverage, so this
/// fails loudly and prints every command needed to restore it.
#[test]
fn every_fixture_is_built() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // The fixture paths are relative to the crate, so the printed commands are
    // only correct if run from there, and creating the one directory that has no
    // committed member means the printed command works verbatim on a fresh
    // checkout rather than failing on a missing directory.
    let _ = std::fs::create_dir_all(root.join("testdata/cdyn"));
    let missing: Vec<String> = FIXTURES
        .iter()
        .filter(|(path, _)| !root.join(path).exists())
        .map(|(path, cmd)| format!("{path}   (build with: {cmd})"))
        .collect();
    assert!(
        missing.is_empty(),
        "these fixtures are missing, so the tests that use them are skipping \
rather than running, and cargo test would report a green run anyway. Run these \
from the crate directory:\n  {}",
        missing.join("\n  ")
    );
}

/// Skipping is reported loudly, because a silent skip reads as a pass.
macro_rules! require_child {
    () => {
        if !child().exists() {
            eprintln!(
                "SKIPPED: build the fixture first: (cd testdata/sg && CGO_ENABLED=0 go build -o sg .)"
            );
            return;
        }
    };
}

fn run_under(args: &[&str], child_port: &str, env: &[(&str, &str)]) -> String {
    let mut c = Command::new(bin());
    c.args(args).arg("--").arg(child()).arg(child_port);
    for (k, v) in env {
        c.env(k, v);
    }
    c.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let out = c.output().expect("spawn pod-netns");
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    s
}

fn run_bare(child_port: &str) -> String {
    let out = Command::new(child())
        .arg(child_port)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn child");
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    s
}

#[test]
fn usage_error_without_a_program() {
    let out = Command::new(bin()).output().expect("run");
    assert_eq!(out.status.code(), Some(2), "no program must be a usage error");
    assert!(String::from_utf8_lossy(&out.stderr).contains("no program given"));
}

/// The help text must not understate what pod-netns does, and must not repeat
/// the false claim that the cage permits only one faked syscall. That claim
/// came from a probe bug (the `seccomp_notif` struct was not re-zeroed between
/// RECV calls) and 64 of 64 notifications now serve cleanly, so asserting it
/// here would lock a known-wrong statement into the test suite.
#[test]
fn help_states_the_scope_without_claiming_a_one_syscall_limit() {
    let out = Command::new(bin()).arg("--help").output().expect("run");
    assert_eq!(out.status.code(), Some(0));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("not a network namespace") || s.contains("is NOT is a network namespace")
            || s.contains("What pod-netns is NOT"),
        "help must state the scope; got: {s}"
    );
    for wrong in ["ONE faked syscall", "one faked syscall per child", "fake 1 of 1"] {
        assert!(
            !s.contains(wrong),
            "help repeats the disproved one-faked-syscall claim {wrong:?}; got: {s}"
        );
    }
}

#[test]
fn unknown_option_is_rejected() {
    let out = Command::new(bin())
        .arg("--nope")
        .arg("--")
        .arg("/bin/true")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown option"));
}

#[test]
fn malformed_endpoints_are_rejected_before_spawning() {
    for bad in ["127.0.0.1", "notanip:80", "127.0.0.1:notaport"] {
        let out = Command::new(bin())
            .arg("--listen")
            .arg(bad)
            .arg("--")
            .arg("/bin/true")
            .output()
            .expect("run");
        assert_eq!(out.status.code(), Some(2), "{bad} must be rejected");
    }
}

/// The core claim: a statically linked program that the cage refuses to bind
/// can bind under pod-netns.
#[test]
fn static_child_binds_only_under_pod_netns() {
    require_child!();

    // CONTROL. If this stops failing, the cage changed and the test below is
    // no longer evidence of anything.
    let bare = run_bare("26001");
    assert!(
        bare.contains("permission denied"),
        "control must show the cage refusing the bind; got: {bare}"
    );

    let under = run_under(&["--listen", "127.0.0.1:26001"], "26001", &[]);
    assert!(
        under.contains("bind &{26001 [127 0 0 1]") && under.contains("-> <nil>"),
        "the bind must succeed under pod-netns; got: {under}"
    );
    assert!(
        !under.contains("permission denied"),
        "no refusal expected under pod-netns; got: {under}"
    );
}

#[test]
fn supervisor_reads_and_reports_the_requested_address() {
    require_child!();
    let out = run_under(&["--verbose", "--listen", "127.0.0.1:26002"], "26002", &[]);
    assert!(
        out.contains("child asked to bind 127.0.0.1:26002"),
        "supervisor must report the sockaddr it read; got: {out}"
    );
    assert!(
        out.contains("/mem"),
        "must attribute the sockaddr to the child's memory; got: {out}"
    );
}

/// A port the tool was not asked to serve must be refused, not silently allowed.
#[test]
fn unserved_port_is_refused() {
    require_child!();
    let out = run_under(&["--verbose", "--listen", "127.0.0.1:26004"], "26005", &[]);
    assert!(
        out.contains("refusing bind"),
        "a port outside --listen must be refused; got: {out}"
    );
}

/// getsockname cannot report the address the child asked for, and the reason is
/// a capability, not an oversight: answering it means writing the sockaddr into
/// the child's own buffer, and `/proc/<pid>/mem` is O_RDONLY-only here because
/// the kernel gates write access on CAP_SYS_RESOURCE (measured: O_WRONLY and
/// O_RDWR both return EACCES with CapEff = 0; process_vm_writev and ptrace are
/// both EPERM).
///
/// So the contract is not "getsockname returns the bound address" but "getsockname
/// is never silently faked": the kernel's wildcard is passed through, and the
/// operator is told what would have been said. A test that asserted the bound
/// address would be asserting something this cage cannot deliver.
#[test]
fn getsockname_is_honest_rather_than_faked() {
    require_child!();

    let bare = run_bare("26006");
    assert!(
        bare.contains("getsockname(same fd") && bare.contains("&{0 [0 0 0 0]"),
        "control should show a wildcard, since the bind never happened; got: {bare}"
    );

    let under = run_under(&["--verbose", "--listen", "127.0.0.1:26006"], "26006", &[]);
    assert!(
        under.contains("getsockname on fd") && under.contains("26006"),
        "the operator must be told which address would have been reported; got: {under}"
    );
    // The kernel's answer is passed through, so the child sees its own wildcard
    // rather than a fabricated address. The exact rendering is the child's own
    // and differs by family, so the assertion is that the served port does NOT
    // appear in the getsockname result and that no virtual-table answer was
    // claimed.
    let gs_line = under
        .lines()
        .find(|l| l.contains("getsockname(same fd"))
        .unwrap_or_else(|| panic!("getsockname never reached the child; got: {under}"));
    assert!(
        !gs_line.contains("26006"),
        "getsockname must not report the served port, since the bind was never real; got: {gs_line}"
    );
    assert!(
        !under.contains("answered from the virtual table"),
        "the virtual table is unreachable without a write route; got: {under}"
    );
}

/// The data path, end to end, with a control.
///
/// This is the only test that proves bytes actually move. Every other test can
/// pass with a relay that carries nothing at all, because a connect that
/// returns 0 and a bind that returns 0 look identical whether or not anything
/// was delivered.
///
/// The origin is an AF_UNIX socket rather than a TCP one because this cage
/// refuses `bind` on loopback outright (`Permission denied`, measured), so there
/// is no way to stand up a local TCP origin to talk to. AF_UNIX still exercises
/// the whole relay: the child's socket is a pre-inherited socketpair, the
/// supervisor splices it to the origin, and the reply has to come back the same
/// way.
///
/// The control is the same fixture with no pod-netns, where `connect` to loopback
/// BLOCKS in this cage rather than being refused, so the control asserts the
/// fixture does not complete on its own.
#[test]
fn the_relay_carries_bytes_in_both_directions() {
    let relayer = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/relayer");
    if !relayer.exists() {
        eprintln!("SKIPPED: build the fixture (cc -O1 -o testdata/relayer testdata/relayer.c)");
        return;
    }

    // The origin: a one-shot AF_UNIX server that answers with a known token, so
    // the assertion is on bytes the fixture could not have invented.
    let sock_path = format!("/tmp/pod-netns-test-origin-{}.sock", std::process::id());
    let _ = std::fs::remove_file(&sock_path);
    let server = std::os::unix::net::UnixListener::bind(&sock_path)
        .expect("bind the AF_UNIX test origin");
    let origin = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut c, _) = server.accept().expect("accept on the test origin");
        c.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();
        let mut buf = [0u8; 4096];
        let n = c.read(&mut buf).unwrap_or(0);
        let _ = c.write_all(
            b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO",
        );
        String::from_utf8_lossy(&buf[..n]).to_string()
    });

    let out = Command::new(bin())
        .args(["--verbose", "--connect", "127.0.0.1:28099"])
        .arg("--upstream-unix")
        .arg(&sock_path)
        .arg("--")
        .arg(&relayer)
        .arg("28099")
        .stdin(Stdio::null())
        .output()
        .expect("spawn pod-netns");
    let s = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let got_request = origin.join().unwrap_or_default();
    let _ = std::fs::remove_file(&sock_path);

    assert!(
        s.contains("connect -> 0"),
        "the faked connect must succeed under pod-netns; got: {s}"
    );
    assert!(
        got_request.contains("GET /"),
        "the origin must receive the child's actual bytes, not an empty read; got: {got_request:?}"
    );
    assert!(
        s.contains("got reply with HELLO"),
        "the reply must travel back through the relay to the child; got: {s}"
    );
    assert!(
        s.contains("bytes each way"),
        "the flow must be accounted for in both directions; got: {s}"
    );
}

/// A refusal upstream must reach the child as a failed `connect`, not as a
/// success that then delivers nothing. A proxy that reports success and hangs is
/// the single most confusing failure mode a caller can be handed.
#[test]
fn an_unreachable_origin_fails_the_childs_connect() {
    let relayer = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/relayer");
    if !relayer.exists() {
        eprintln!("SKIPPED: build the fixture (cc -O1 -o testdata/relayer testdata/relayer.c)");
        return;
    }
    // Nothing is listening on this path, so the dial must fail.
    let dead = "/tmp/pod-netns-dead-origin.sock";
    let _ = std::fs::remove_file(dead);

    let out = Command::new(bin())
        .args(["--connect", "127.0.0.1:28098", "--upstream-unix", dead])
        .arg("--")
        .arg(&relayer)
        .arg("28098")
        .stdin(Stdio::null())
        .output()
        .expect("spawn pod-netns");
    let s = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        s.contains("connect -> -1"),
        "an unreachable origin must fail the child's connect; got: {s}"
    );
    assert!(
        !s.contains("got reply"),
        "nothing may be reported as delivered when the upstream is unreachable; got: {s}"
    );
}

/// The inbound path, end to end: bind, listen, accept, and the bytes arriving.
///
/// This is the other half of the relay and it is a different code path from
/// `--connect`: the connection arrives on a backing AF_UNIX socket, is queued,
/// and `accept` hands the child a pool fd. A test that only checks `bind` returns
/// 0 passes with a broken accept path, because the child never gets as far as
/// calling it.
#[test]
fn an_inbound_connection_reaches_the_childs_accept() {
    let srv = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/srv");
    if !srv.exists() {
        eprintln!("SKIPPED: build the fixture (cc -O1 -o testdata/srv testdata/srv.c)");
        return;
    }
    let port = 28095u16;
    let sock = format!("/tmp/pod-netns-4-{port}.sock");
    let _ = std::fs::remove_file(&sock);

    let mut child = Command::new(bin());
    child
        .args(["--verbose", "--listen", &format!("127.0.0.1:{port}")])
        .arg("--")
        .arg(&srv)
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = child.spawn().expect("spawn pod-netns with the server fixture");

    // Wait for the backing socket to appear, bounded: an unbounded wait here is a
    // hung test rather than a failed one.
    let mut peer: Option<std::os::unix::net::UnixStream> = None;
    for _ in 0..100 {
        if std::path::Path::new(&sock).exists() {
            if let Ok(s) = std::os::unix::net::UnixStream::connect(&sock) {
                peer = Some(s);
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let mut peer = match peer {
        Some(p) => p,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the backing socket {sock} never became connectable");
        }
    };
    use std::io::Write;
    peer.write_all(b"GET /inbound HTTP/1.0\r\nHost: x\r\n\r\n")
        .expect("write to the backing socket");

    let out = child.wait_with_output().expect("wait for the server fixture");
    let s = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_file(&sock);

    assert!(s.contains("listen ok"), "the faked listen must succeed: {s}");
    assert!(
        s.contains("accept ok"),
        "accept must hand the child a real descriptor: {s}"
    );
    assert!(
        s.contains("peer said: GET /inbound"),
        "the child's accepted socket must carry the client's actual bytes: {s}"
    );
}
/// through exactly what it cannot.
///
/// The fixture here makes an `AF_INET`/`SOCK_STREAM` socket, which pod-netns
/// must claim, and the assertion is that it did. The other half, that an
/// `AF_UNIX` or datagram socket is passed through, is asserted separately by
/// `unix_sockets_are_not_claimed`, because a socket that is claimed and then
/// carries nothing is worse than one that was never touched.
#[test]
fn inet_stream_sockets_are_claimed_from_the_pool() {
    let relayer = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/relayer");
    if !relayer.exists() {
        return;
    }
    let out = Command::new(bin())
        .args(["--verbose", "--connect", "127.0.0.1:28097", "--upstream-unix", "/tmp/x.sock"])
        .arg("--")
        .arg(&relayer)
        .arg("28097")
        .stdin(Stdio::null())
        .output()
        .expect("spawn");
    let s = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        s.contains("socket() -> fd"),
        "an AF_INET STREAM socket must be answered with a pool fd: {s}"
    );
    assert!(
        s.contains("pre-inherited socketpair"),
        "the claim must say where the fd came from: {s}"
    );
    // The log must not repeat the disproved claim that ADDFD is unavailable. It
    // works; the pool is a deliberate choice pending a migration, not a
    // workaround for a missing kernel feature.
    assert!(
        !s.contains("ADDFD is unavailable"),
        "the log repeats the disproved ADDFD claim: {s}"
    );
}

/// A socket the relay cannot carry must be passed through untouched.
///
/// Claiming an `AF_UNIX` socket would leave the child holding a socketpair end
/// where it expected a filesystem socket, so its own local IPC would break, and
/// it would break with no message anywhere. The fixture connects to a real unix
/// path, so a pass-through is observable as a successful connect.
#[test]
fn unix_sockets_are_not_claimed() {
    let ucli = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ucli");
    if !ucli.exists() {
        eprintln!("SKIPPED: build the fixture (cc -O1 -o testdata/ucli testdata/ucli.c)");
        return;
    }
    let path = format!("/tmp/pod-netns-unix-{}.sock", std::process::id());
    let _ = std::fs::remove_file(&path);
    let server = std::os::unix::net::UnixListener::bind(&path).expect("bind");
    let accept = std::thread::spawn(move || {
        use std::io::{Read, Write};
        match server.accept() {
            Ok((mut c, _)) => {
                c.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
                let mut buf = [0u8; 256];
                let n = c.read(&mut buf).unwrap_or(0);
                let _ = c.write_all(b"pong");
                n
            }
            Err(_) => 0,
        }
    });

    let out = Command::new(bin())
        .args(["--verbose"])
        .arg("--")
        .arg(&ucli)
        .arg(&path)
        .stdin(Stdio::null())
        .output()
        .expect("spawn");
    let s = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let got = accept.join().unwrap_or(0);
    let _ = std::fs::remove_file(&path);

    // The pass-through is asserted three ways: the child's own connect succeeds,
    // the bytes arrive at the server, and the reply comes back. Any of those
    // failing means the socket was mangled.
    assert!(
        s.contains("connect -> 0"),
        "an AF_UNIX socket must connect normally; got: {s}"
    );
    assert_eq!(got, 4, "the server must receive the child's bytes; got: {s}");
    assert!(
        s.contains("reply: pong"),
        "the reply must come back untouched; got: {s}"
    );
    assert!(
        s.contains("is not ours; passing it through"),
        "an AF_UNIX socket must be passed through, not claimed: {s}"
    );
    assert!(
        !s.contains("socket() -> fd"),
        "an AF_UNIX socket must never be answered with a pool fd: {s}"
    );
}

/// The backing socket must not outlive the run.
///
/// Every `--listen` invocation creates a file in /tmp, and without an explicit
/// unlink a long-lived host accumulates one per port ever served. That is not
/// cosmetic: it fills /tmp with unbounded entries nobody knows are stale, and a
/// later run on the same port has to unlink someone else's leftover to bind at
/// all.
#[test]
fn the_backing_socket_is_cleaned_up() {
    let port = 28093u16;
    let sock = format!("/tmp/pod-netns-4-{port}.sock");
    let _ = std::fs::remove_file(&sock);

    let out = Command::new(bin())
        .args(["--listen", &format!("127.0.0.1:{port}")])
        .arg("--")
        .arg("/bin/true")
        .stdin(Stdio::null())
        .output()
        .expect("spawn");

    assert!(
        out.status.success(),
        "the run itself must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !std::path::Path::new(&sock).exists(),
        "the backing socket {sock} must be removed once the child exits"
    );
}

/// A socket we handed the child must not break the child's resolver.
///
/// The child's fd is an AF_UNIX socketpair, so the kernel returns `EOPNOTSUPP`
/// for every IP-level `setsockopt`. Passing those through looks harmless and is
/// not: glibc's resolver sets options like `IPV6_V6ONLY` and **aborts** when one
/// fails, so every glibc program under pod-netns would fail to resolve anything,
/// with the failure surfacing as a name-resolution error rather than as anything
/// to do with a proxy.
///
/// This is the defect that made a DNS fix necessary, so it is asserted directly
/// rather than through `getaddrinfo`, whose result here depends on the cage's
/// resolver and not on this tool.
#[test]
fn setsockopt_on_a_claimed_socket_succeeds() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/dnsfix");
    if !fixture.exists() {
        eprintln!("SKIPPED: build the fixture (cc -O1 -o testdata/dnsfix testdata/dnsfix.c)");
        return;
    }

    // CONTROL: what the options return with no interception. If these change, the
    // comparison below is meaningless.
    let bare = String::from_utf8_lossy(
        &Command::new(&fixture).output().expect("run the fixture bare").stdout,
    )
    .to_string();
    assert!(
        bare.contains("setsockopt(IPPROTO_IP, IP_TOS, 0)        -> 0"),
        "control: IP_TOS must succeed on a real socket; got: {bare}"
    );

    let out = Command::new(bin())
        .args(["--connect", "127.0.0.1:80", "--upstream-unix", "/tmp/pod-netns-none.sock"])
        .arg("--")
        .arg(&fixture)
        .stdin(Stdio::null())
        .output()
        .expect("spawn");
    let s = String::from_utf8_lossy(&out.stdout).to_string();

    for opt in [
        "setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)",
        "setsockopt(IPPROTO_IP, IP_TOS, 0)",
    ] {
        let line = s
            .lines()
            .find(|l| l.starts_with(opt))
            .unwrap_or_else(|| panic!("{opt} was not reported; got: {s}"));
        assert!(
            line.ends_with("-> 0 (ok)"),
            "a claimed socket must answer {opt} with 0 so the resolver does not \
abort, but it got: {line}"
        );
    }
}

/// Option validation must reject combinations that would silently do nothing.
#[test]
fn contradictory_upstream_options_are_rejected() {
    for args in [
        vec!["--proxy", "p:1", "--connect", "127.0.0.1:1"],
        vec!["--upstream", "h:1", "--connect", "127.0.0.1:1"],
        vec!["--upstream-unix", "/tmp/x", "--upstream", "h:1"],
        vec!["--upstream-unix", "/tmp/x", "--proxy", "p:1"],
    ] {
        let mut c = Command::new(bin());
        c.args(&args).arg("--").arg("/bin/true");
        let out = c.output().expect("run");
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?} must be a usage error, got {:?}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// The listener must not leak state between runs.
#[test]
fn runs_are_independent() {
    require_child!();
    let first = run_under(&["--verbose", "--listen", "127.0.0.1:26008"], "26008", &[]);
    let second = run_under(&["--verbose", "--listen", "127.0.0.1:26009"], "26009", &[]);
    assert!(first.contains("26008"), "first run: {first}");
    assert!(second.contains("26009"), "second run: {second}");
    assert!(
        !second.contains("child asked to bind 127.0.0.1:26008"),
        "state leaked between runs: {second}"
    );
}

/// A dynamic (non-Go, libc-linked) program must work identically, since the
/// claim is that no shim is needed for either kind of binary.
#[test]
fn dynamic_child_binds_under_pod_netns() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/cdyn/cdyn");
    if !path.exists() {
        eprintln!("SKIPPED: build the fixture (cc -o testdata/cdyn/cdyn testdata/cdyn.c)");
        return;
    }
    let bare = Command::new(&path)
        .arg("26011")
        .output()
        .expect("spawn");
    // The control is the whole point of this test, so it must actually fail
    // when the cage stops refusing. Matching is case-insensitive because the
    // two fixtures report it differently: Go's runtime renders "permission
    // denied" and glibc renders "Permission denied". Asserting one spelling
    // made this control pass vacuously on the other fixture.
    let bare = String::from_utf8_lossy(&bare.stdout).to_lowercase();
    assert!(
        bare.contains("permission denied"),
        "control must be refused by the cage; got: {bare}"
    );
    let out = Command::new(bin())
        .args(["--verbose", "--listen", "127.0.0.1:26011"])
        .arg("--")
        .arg(&path)
        .arg("26011")
        .output()
        .expect("spawn");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("bind OK"), "a dynamic child must also bind: {s}");
}
