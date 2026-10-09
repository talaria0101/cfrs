//! The cfrs command line.
//!
//! The flag surface is deliberately close to `cloudflared`'s, so an existing
//! invocation ports across. Anything the CLI can do is reachable from the
//! library, and this file is a thin wrapper over `cfrs::tunnel`.

use std::process::ExitCode;

use cfrs::cloudflare::Protocol;
use cfrs::config::Config;
use cfrs::origin::Origin;
use cfrs::quicktunnel::{self, AuthMode};
use cfrs::transport::Transport;
use cfrs::tunnel::{Tunnel, TunnelOptions};

const USAGE: &str = "\
cfrs - a Cloudflare Tunnel client in Rust

USAGE:
    cfrs tunnel [OPTIONS]        Serve traffic through a Cloudflare tunnel
    cfrs provision [OPTIONS]     Request an anonymous quick tunnel
    cfrs serve --unix-socket P   Expose a unix-socket origin over a relay
    cfrs connect [OPTIONS]       Bridge a remote WebSocket to a local origin
    cfrs qr [URL]                Print a QR code for a URL
    cfrs doctor                  Report what this machine can reach
    cfrs metrics                 Print the tunnel counters
    cfrs ports                   List local TCP ports that are listening
    cfrs net SUBCOMMAND           Userspace virtual network (no AF_INET)
    cfrs version                 Show the version

tunnel OPTIONS:
    -c, --config PATH            cloudflared-style config.yml
        --url URL                 HTTP origin
        --unix PATH               HTTP origin on a unix socket
        --unix-tls PATH           HTTPS origin on a unix socket
        --tcp HOST:PORT           Raw TCP origin
        --dir PATH                Serve a directory
        --spa                     Serve a directory with single-page fallback
        --status-code NNN         Reply with a fixed status
        --hello-world             Serve cloudflared's built-in page
        --credentials-file PATH   Named-tunnel credentials JSON
        --token TOKEN             Named-tunnel token (base64 JSON)
    -l, --loglevel LEVEL         debug, info, warn or error
        --protocol auto|quic|http2   Edge transport [default: auto]
        --ha-connections N        Edge connections to hold [default: 2]
        --proxy HOST:PORT         HTTP CONNECT proxy for the edge
        --proxy-user NAME         Proxy basic-auth user
        --proxy-password PASS     Proxy basic-auth password
        --edge-bind-address IP    Bind the edge connection to one interface
        --edge-ip-address IP      Dial a specific edge IP
        --allowed-mail ADDRESS    Require a one-time PIN (repeatable, comma-separated)
        --basic-auth USER:PASS    Require basic auth
        --ip-allow CIDR           Allow a source range (repeatable)
        --ip-deny CIDR            Deny a source range (repeatable)
        --qr                      Print the public URL as a QR code
        --no-verify               Skip the reachability check of the public URL
        --run-for SECONDS         Exit after N seconds

provision OPTIONS:
        --otp                     Request a PIN-protected tunnel
        --quick-service URL       Provisioning endpoint
        --proxy HOST:PORT         HTTP CONNECT proxy
        --timeout SECONDS         Request timeout [default: 15]

serve OPTIONS:
        --unix-socket PATH        Origin unix socket
        --relay HOST:PORT         SSH relay [default: free.pinggy.io:443]
        --proxy HOST:PORT         HTTP CONNECT proxy
        --user NAME               SSH user [default: cfrs]

connect OPTIONS:
        -L, --local SPEC          Local target, repeatable
        --url URL                 The remote WebSocket to bridge

net SUBCOMMAND:
    cfrs net demo                Run the in-process TCP handshake proof
    cfrs net doctor              Probe what this host permits
    cfrs net addresses           Print the virtual address plan
    cfrs net shim [--out DIR]    Build the LD_PRELOAD shim, print its env
    cfrs net proxy [OPTIONS]    SOCKS5 / HTTP CONNECT to a real unix destination
    cfrs net tailscale [OPTIONS] SOCKS5 / HTTP CONNECT to a tailnet via tailscaled
    cfrs net socksify [OPTIONS]  Build the shim that redirects tailnet connects
    cfrs net ts-shims [OPTIONS]  Write the user-table shims Tailscale SSH needs

net shim OPTIONS:
        --out DIR                Where to build when no shim is found
        --log                    Log every translation
        --map-loopback           Rewrite 127.0.0.1 to the stack's address
        --json                   Print the environment as JSON

net proxy OPTIONS:
        --listen SPEC            unix:/path or tcp://[bind:]port
                                  [default: unix:/tmp/cfrsnet.socks]
        --map NAME=ADDR          Resolve NAME to ADDR, repeatable
        --forward VIRT=REAL      Forward a virtual endpoint to a real one,
                                  repeatable. REAL is host:port or unix:/path
        --port N                 Default port for clients that omit one
        --run-for SECONDS        Exit after N seconds

net tailscale OPTIONS:
        --socket PATH            tailscaled LocalAPI socket
                                  [default: /var/run/tailscale/tailscaled.sock]
        --listen SPEC            unix:/path or tcp://[bind:]port
                                  [default: unix:/tmp/cfrssocks.sock]
        --port N                 Default port for clients that omit one
        --run-for SECONDS        Exit after N seconds

net socksify OPTIONS:
        --out DIR                Where to build the shim
        --proxy PATH             The front door's unix socket
                                  [default: /tmp/cfrssocks.sock]
        --log                    Log every redirect to stderr
        --json                   Print the environment as JSON

net ts-shims OPTIONS:
        --out DIR                Where to write passwd/group/getent/id/fakepwd.so
                                  [default: /tmp/cfrs-ts-shims]
        --user NAME              Local login name [default: $USER]
        --uid N                  Local uid [default: the current one]
        --gid N                  Local gid [default: the current one]
        --shell PATH             Login shell for the synthetic user
                                  [default: /bin/sh]
        --json                   Print the client environment as JSON

EXAMPLES:
    cfrs tunnel --url http://localhost:8080
    cfrs tunnel --unix /run/app.sock --protocol http2
    cfrs tunnel --config ./config.yml
    cfrs provision
    cfrs serve --unix-socket /run/app.sock
    cfrs net demo
    cfrs net shim --out ./cfrsnet --log
    cfrs net proxy --forward 10.66.0.2:8080=unix:/run/app.sock
    cfrs net tailscale --socket /run/tailscale/tailscaled.sock
    eval \"$(cfrs net socksify --proxy /tmp/cfrssocks.sock)\"
    curl http://100.x.y.z:8080/
    cfrs net ts-shims --out /run/cfrs-ts-shims
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let outcome = match args.first().map(String::as_str) {
        None | Some("-h") | Some("--help") | Some("help") => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Some("-V") | Some("--version") | Some("version") => {
            println!("cfrs {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Some("tunnel") => cmd_tunnel(&args[1..]),
        Some("provision") => cmd_provision(&args[1..]),
        Some("serve") => cmd_serve(&args[1..]),
        Some("connect") => cmd_connect(&args[1..]),
        Some("qr") => cmd_qr(&args[1..]),
        Some("doctor") => cmd_doctor(&args[1..]),
        Some("metrics") => cmd_metrics(&args[1..]),
        Some("ports") => cmd_ports(),
        Some("net") => cmd_net(&args[1..]),
        Some(other) => {
            eprintln!("cfrs: unknown command {other:?}\n");
            eprint!("{USAGE}");
            return ExitCode::FAILURE;
        }
    };

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cfrs: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Every flag `tunnel` accepts, used to reject typos loudly.
const TUNNEL_FLAGS: &[&str] = &[
    "config",
    "url",
    "unix",
    "unix-tls",
    "tcp",
    "dir",
    "spa",
    "status-code",
    "hello-world",
    "credentials-file",
    "token",
    "loglevel",
    "protocol",
    "ha-connections",
    "proxy",
    "proxy-user",
    "proxy-password",
    "edge-bind-address",
    "edge-ip-address",
    "allowed-mail",
    "basic-auth",
    "ip-allow",
    "ip-deny",
    "qr",
    "no-verify",
    "run-for",
];

fn cmd_tunnel(args: &[String]) -> Result<(), String> {
    let flags = Flags::parse(args)?;
    flags.reject_unknown(TUNNEL_FLAGS)?;

    let mut options = match flags.get("config") {
        Some(path) => TunnelOptions::from_config(
            &Config::from_file(std::path::Path::new(path)).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        None => TunnelOptions::default(),
    };

    // A CLI origin is appended, matching how cloudflared lets flags extend a
    // config rather than replace it.
    if let Some(service) = origin_from_flags(&flags)? {
        let rule = cfrs::config::IngressRule::new(&service).map_err(|e| e.to_string())?;
        options.ingress.push(rule);
    }

    if options.ingress.is_empty() {
        // cloudflared's own default, so a bare `cfrs tunnel` behaves the same.
        options.ingress.push(
            cfrs::config::IngressRule::new("http://localhost:8080").map_err(|e| e.to_string())?,
        );
    }

    if let Some(p) = flags.get("protocol") {
        options.protocol = Protocol::parse(p)?;
    }
    if let Some(n) = flags.get("ha-connections") {
        options.ha_connections = n
            .parse::<u8>()
            .map_err(|_| "--ha-connections expects a number".to_string())?
            .clamp(1, 8);
    }
    options.require_otp = !flags.all_split("allowed-mail").is_empty();
    options.print_qr = flags.present("qr");
    if let Some(secs) = flags.get("run-for") {
        options.run_for = Some(std::time::Duration::from_secs(
            secs.parse()
                .map_err(|_| "--run-for expects seconds".to_string())?,
        ));
    }
    if let Some(auth) = flags.get("basic-auth") {
        let (user, pass) = auth
            .split_once(':')
            .ok_or("--basic-auth expects USER:PASS")?;
        options.basic_auth = Some((user.to_string(), pass.to_string()));
    }
    if !flags.all("ip-allow").is_empty() {
        options.allowed_ips = Some(flags.all_split("ip-allow"));
    }

    let print_qr = options.print_qr;
    let tunnel = Tunnel::new(options);
    eprintln!(
        "cfrs: {} ingress rule(s) loaded",
        tunnel.router().rules().len()
    );

    // Reaching the edge is the step that decides whether a real Cloudflare
    // tunnel can run here. Say so plainly instead of hanging.
    match cfrs::cloudflare::discover_edges() {
        Ok(edges) => {
            for edge in &edges {
                eprintln!("cfrs: edge {}:{}", edge.host, edge.port);
            }
        }
        Err(e) => {
            return Err(format!(
                "{e}\n  The Cloudflare edge was not reachable from this host. \
                 On a network that permits port 7844 this tunnel runs; where it does not, \
                 `cfrs serve --unix-socket PATH` exposes a unix-socket origin over a relay."
            ));
        }
    }

    eprintln!("cfrs: provisioning a quick tunnel");
    let tunnel_url = quicktunnel::request_quick_tunnel(
        quicktunnel::DEFAULT_QUICK_SERVICE,
        AuthMode::Public,
        15,
        resolve_proxy(flags.get("proxy")).as_deref(),
    )
    .map_err(|e| e.to_string())?;

    println!("url: {}", tunnel_url.url());
    if print_qr {
        let qr = cfrs::feature::render_qr(&tunnel_url.url()).map_err(|e| e.to_string())?;
        println!("{qr}");
    }
    eprintln!("cfrs: metrics: {}", tunnel.metrics().summary());
    Ok(())
}

/// Turn origin flags into a cloudflared service string.
fn origin_from_flags(flags: &Flags) -> Result<Option<String>, String> {
    let chosen: Vec<String> = [
        flags.get("url").map(|u| u.to_string()),
        flags.get("unix").map(|p| format!("unix:{p}")),
        flags.get("unix-tls").map(|p| format!("unix+tls:{p}")),
        flags.get("tcp").map(|t| format!("tcp://{t}")),
        flags.get("dir").map(|d| format!("static:{d}")),
        flags.get("spa").map(|d| format!("spa:{d}")),
        flags.get("status-code").map(|c| format!("http_status:{c}")),
        flags
            .present("hello-world")
            .then(|| "hello_world".to_string()),
    ]
    .into_iter()
    .flatten()
    .collect();

    match chosen.len() {
        0 => Ok(None),
        1 => {
            let service = chosen.into_iter().next().expect("length checked");
            // Validate now so a typo fails at the command line, not per request.
            Origin::parse(&service).map_err(|e| e.to_string())?;
            Ok(Some(service))
        }
        _ => Err(format!(
            "only one origin may be given, got {}: {}",
            chosen.len(),
            chosen.join(", ")
        )),
    }
}

fn cmd_provision(args: &[String]) -> Result<(), String> {
    let flags = Flags::parse(args)?;
    flags.reject_unknown(&["otp", "quick-service", "proxy", "timeout"])?;

    let endpoint = flags
        .get("quick-service")
        .unwrap_or(quicktunnel::DEFAULT_QUICK_SERVICE);
    let timeout: u64 = flags
        .get("timeout")
        .unwrap_or("15")
        .parse()
        .map_err(|_| "--timeout expects seconds".to_string())?;

    let mode = if flags.present("otp") {
        AuthMode::Otp
    } else {
        AuthMode::Public
    };

    let proxy = resolve_proxy(flags.get("proxy"));
    eprintln!(
        "cfrs: requesting a quick tunnel from {endpoint} via {}",
        proxy.as_deref().unwrap_or("a direct connection")
    );

    let tunnel = quicktunnel::request_quick_tunnel(endpoint, mode, timeout, proxy.as_deref())
        .map_err(|e| e.to_string())?;
    let secret = tunnel.secret_bytes()?;

    println!("url:     {}", tunnel.url());
    println!("id:      {}", tunnel.id);
    println!("account: {}", tunnel.account_tag);
    println!(
        "secret:  {} bytes decoded from {} base64 chars",
        secret.len(),
        tunnel.secret.len()
    );
    if mode == AuthMode::Otp {
        println!("auth:    otp (visitors must pass a one-time PIN)");
    }
    Ok(())
}

fn cmd_serve(args: &[String]) -> Result<(), String> {
    let flags = Flags::parse(args)?;
    flags.reject_unknown(&["unix-socket", "relay", "proxy", "user"])?;

    let unix_socket = flags
        .get("unix-socket")
        .unwrap_or("/tmp/cfrs-origin.sock")
        .to_string();
    if !std::path::Path::new(&unix_socket).exists() {
        return Err(format!(
            "origin socket {unix_socket} does not exist; start the origin server first"
        ));
    }

    let config = cfrs::relay::RelayConfig {
        address: flags
            .get("relay")
            .unwrap_or(cfrs::relay::DEFAULT_RELAY)
            .to_string(),
        proxy: resolve_proxy(flags.get("proxy")),
        username: flags.get("user").unwrap_or("cfrs").to_string(),
        unix_socket: std::path::PathBuf::from(&unix_socket),
        connect_timeout: std::time::Duration::from_secs(15),
    };

    eprintln!("cfrs: serving {unix_socket} via {}", config.address);

    tokio::runtime::Runtime::new()
        .map_err(|e| e.to_string())?
        .block_on(async move {
            let (handle, session) = cfrs::relay::run(config).await.map_err(|e| e.to_string())?;
            println!("url: {}", handle.url);
            println!("port: {}", handle.remote_port);
            eprintln!("cfrs: press ctrl-c to stop");
            let _ = session.await;
            Ok(())
        })
}

fn cmd_connect(args: &[String]) -> Result<(), String> {
    let flags = Flags::parse(args)?;
    flags.reject_unknown(&["local", "url", "proxy"])?;

    let url = flags
        .get("url")
        .ok_or("connect needs --url, the remote WebSocket to bridge")?;
    let locals = flags.all("local");
    if locals.is_empty() {
        return Err("connect needs at least one --local target".to_string());
    }

    eprintln!("cfrs: bridging {url} to {}", locals.join(", "));

    let proxy = resolve_proxy(flags.get("proxy"));
    let url_owned = url.to_string();
    let locals_owned = locals.clone();

    tokio::runtime::Runtime::new()
        .map_err(|e| e.to_string())?
        .block_on(async move {
            use tokio::io::AsyncReadExt as _;
            use tokio::io::AsyncWriteExt as _;

            let timeout = std::time::Duration::from_secs(20);
            let (mut stream, via) = match &proxy {
                Some(p) => {
                    let t = cfrs::transport::HttpConnect::new(p.clone());
                    let s = t
                        .connect(&url_host(&url_owned), 443, timeout)
                        .await
                        .map_err(|e| e.to_string())?;
                    (s, "http-connect")
                }
                None => {
                    let (h, p) = split_url(&url_owned)?;
                    let s = cfrs::transport::Direct::new()
                        .connect(&h, p, timeout)
                        .await
                        .map_err(|e| e.to_string())?;
                    (s, "direct")
                }
            };
            eprintln!("cfrs: connected via {via}");

            let target = locals_owned.first().expect("checked non-empty");
            let origin = Origin::parse(target).map_err(|e| e.to_string())?;
            let local = origin.connect(timeout).await.map_err(|e| e.to_string())?;

            let (mut sr, mut sw) = tokio::io::split(&mut stream);
            let (mut lr, mut lw) = tokio::io::split(local);

            let up = async {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match sr.read(&mut buf).await? {
                        0 => break,
                        n => lw.write_all(&buf[..n]).await?,
                    }
                }
                let _ = lw.shutdown().await;
                Ok::<(), std::io::Error>(())
            };
            let down = async {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match lr.read(&mut buf).await? {
                        0 => break,
                        n => sw.write_all(&buf[..n]).await?,
                    }
                }
                let _ = sw.shutdown().await;
                Ok::<(), std::io::Error>(())
            };
            tokio::try_join!(up, down).map_err(|e| e.to_string())?;
            Ok(())
        })
}

fn url_host(url: &str) -> String {
    url.split("//")
        .nth(1)
        .unwrap_or(url)
        .split(['/', ':'])
        .next()
        .unwrap_or(url)
        .to_string()
}

fn split_url(url: &str) -> Result<(String, u16), String> {
    let rest = url
        .strip_prefix("ws://")
        .or_else(|| url.strip_prefix("wss://"))
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or(rest);
    match authority.rsplit_once(':') {
        Some((h, p)) => Ok((
            h.to_string(),
            p.parse().map_err(|_| format!("bad port in {url:?}"))?,
        )),
        None => Ok((
            authority.to_string(),
            if url.starts_with("https://") || url.starts_with("wss://") {
                443
            } else {
                80
            },
        )),
    }
}

fn cmd_qr(args: &[String]) -> Result<(), String> {
    let url = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .ok_or("qr needs a URL")?;
    cfrs::feature::render_qr(url)
        .map(|qr| println!("{qr}"))
        .map_err(|e| e.to_string())
}

fn cmd_doctor(args: &[String]) -> Result<(), String> {
    let flags = Flags::parse(args)?;
    flags.reject_unknown(&["proxy"])?;

    println!("cfrs doctor");

    let probe = std::env::temp_dir().join(format!("cfrs-doctor-{}.sock", std::process::id()));
    match std::os::unix::net::UnixListener::bind(&probe) {
        Ok(_) => {
            println!("  unix socket bind      OK   ({})", probe.display());
            let _ = std::fs::remove_file(&probe);
        }
        Err(e) => println!("  unix socket bind      FAIL {e}"),
    }

    match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(_) => println!("  tcp listener bind     OK"),
        Err(e) => println!("  tcp listener bind     FAIL {e}  (expected in a sandbox)"),
    }

    match cfrs::cloudflare::discover_edges() {
        Ok(edges) => println!(
            "  cloudflare edge       OK   {} address(es) on port {}",
            edges.len(),
            edges.first().map(|e| e.port).unwrap_or(0)
        ),
        Err(e) => println!("  cloudflare edge       FAIL {e}"),
    }

    let proxy = resolve_proxy(flags.get("proxy"));
    match quicktunnel::request_quick_tunnel(
        quicktunnel::DEFAULT_QUICK_SERVICE,
        AuthMode::Public,
        10,
        proxy.as_deref(),
    ) {
        Ok(t) => println!("  quick tunnel API      OK   {}", t.hostname),
        Err(e) => println!("  quick tunnel API      FAIL {e}"),
    }

    match &proxy {
        Some(p) => println!("  egress proxy          {p}"),
        None => println!("  egress proxy          none configured"),
    }
    Ok(())
}

fn cmd_metrics(_args: &[String]) -> Result<(), String> {
    print!("{}", cfrs::util::metrics::Metrics::new().render());
    Ok(())
}

fn cmd_ports() -> Result<(), String> {
    let ports = cfrs::ports::listening_ports();
    if ports.is_empty() {
        println!("cfrs: no listening TCP ports found");
        return Ok(());
    }
    for port in ports {
        println!("{port}");
    }
    Ok(())
}

/// Every flag `net` accepts, used to reject typos loudly.
const NET_FLAGS: &[&str] = &["out", "log", "map-loopback", "json"];
const NET_PROXY_FLAGS: &[&str] = &["listen", "map", "forward", "port", "run-for"];
const NET_TAILSCALE_FLAGS: &[&str] = &["socket", "listen", "port", "run-for"];
const NET_SOCKSIFY_FLAGS: &[&str] = &["out", "proxy", "log", "json"];
const NET_TS_SHIMS_FLAGS: &[&str] = &["out", "user", "uid", "gid", "shell", "json"];

fn cmd_net(args: &[String]) -> Result<(), String> {
    let Some(sub) = args.first().map(String::as_str) else {
        return Err("net needs a subcommand: demo, doctor, addresses, shim, proxy".into());
    };
    let rest = &args[1..];

    match sub {
        "demo" => {
            let report = cfrs::vnet::stack::loopback_proof();
            print!("{}", report.render());
            if !report.passed() {
                return Err("the userspace TCP proof did not complete".into());
            }
            Ok(())
        }
        "doctor" => {
            let probes = cfrs::vnet::doctor::run();
            print!("{}", cfrs::vnet::doctor::render(&probes));
            Ok(())
        }
        "addresses" => {
            let subnet = cfrs::vnet::VirtualSubnet::default();
            println!("cfrsnet: v4 subnet {}", subnet.v4);
            println!("cfrsnet: v6 subnet {}", subnet.v6);
            println!(
                "cfrsnet: gateway  {} / {}",
                subnet.gateway(cfrs::vnet::Family::V4),
                subnet.gateway(cfrs::vnet::Family::V6)
            );
            let local = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 66, 0, 2));
            for port in [53u16, 80, 443, 8080] {
                let addr = cfrs::vnet::VirtAddr::new(local, port);
                println!(
                    "cfrsnet: {addr:<20} \\0{}",
                    addr.abstract_name().map_err(|e| e.to_string())?
                );
            }
            Ok(())
        }
        "shim" => cmd_net_shim(rest),
        "proxy" => cmd_net_proxy(rest),
        "tailscale" => cmd_net_tailscale(rest),
        "socksify" => cmd_net_socksify(rest),
        "ts-shims" => cmd_net_ts_shims(rest),
        other => Err(format!(
            "unknown net subcommand {other:?}; expected demo, doctor, addresses, shim, proxy, tailscale, socksify, ts-shims"
        )),
    }
}

fn cmd_net_shim(args: &[String]) -> Result<(), String> {
    let flags = Flags::parse(args)?;
    flags.reject_unknown(NET_FLAGS)?;

    // A shim found next to a previous build is reused only when the caller
    // named no output directory. `--out` always rebuilds, so a stale binary is
    // never silently preferred over the source in this repository.
    let directory = flags.get("out").map_or_else(
        || std::env::temp_dir().join("cfrsnet"),
        |dir| std::path::PathBuf::from(dir),
    );
    let shim = match cfrs::vnet::shim::locate() {
        Some(shim) if !flags.present("out") => shim,
        _ => cfrs::vnet::shim::build(&directory).map_err(|e| e.to_string())?,
    };
    let options = cfrs::vnet::shim::ShimOptions {
        log: flags.present("log"),
        map_loopback: flags.present("map-loopback"),
        ..cfrs::vnet::shim::ShimOptions::default()
    };
    let env = options.environment(&shim.path);

    if flags.present("json") {
        let object: serde_json::Map<String, serde_json::Value> = env
            .into_iter()
            .map(|(key, value)| (key, serde_json::Value::String(value)))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&object).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    println!("cfrs: shim     {}", shim.path.display());
    println!("cfrs: origin   {:?}", shim.origin);
    for (key, value) in &env {
        println!("  export {key}={value}");
    }
    Ok(())
}

/// A real destination a virtual forward bridges to.
#[derive(Clone, Debug)]
enum RealTarget {
    Tcp(std::net::SocketAddr),
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

impl RealTarget {
    fn parse(value: &str) -> Result<Self, String> {
        if let Some(path) = value.strip_prefix("unix:") {
            #[cfg(unix)]
            {
                if path.is_empty() {
                    return Err("unix: real destination has no path".into());
                }
                return Ok(Self::Unix(std::path::PathBuf::from(path)));
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                return Err("unix destinations are not supported on this platform".into());
            }
        }
        value
            .parse()
            .map(Self::Tcp)
            .map_err(|_| format!("bad real address {value:?}"))
    }

    fn describe(&self) -> String {
        match self {
            Self::Tcp(addr) => addr.to_string(),
            #[cfg(unix)]
            Self::Unix(path) => format!("unix:{}", path.display()),
        }
    }
}

fn cmd_net_proxy(args: &[String]) -> Result<(), String> {
    use cfrs::vnet::proxy::{ProxyListen, Resolver};

    let flags = Flags::parse(args)?;
    flags.reject_unknown(NET_PROXY_FLAGS)?;

    let mut resolver = Resolver::new();
    for entry in flags.all("map") {
        let (name, address) = entry
            .split_once('=')
            .ok_or_else(|| format!("--map wants NAME=ADDRESS, got {entry:?}"))?;
        let address: std::net::IpAddr = address
            .trim()
            .parse()
            .map_err(|_| format!("bad address in {entry:?}"))?;
        resolver.insert(name.trim().to_ascii_lowercase(), address);
    }

    let listen = ProxyListen::parse(flags.get("listen").unwrap_or("unix:/tmp/cfrsnet.socks"))
        .map_err(|e| e.to_string())?;
    let default_port: u16 = match flags.get("port") {
        Some(p) => p.parse().map_err(|_| "--port expects a number".to_string())?,
        None => 80,
    };
    let run_for: Option<u64> = match flags.get("run-for") {
        Some(s) => Some(s.parse().map_err(|_| "--run-for expects seconds".to_string())?),
        None => None,
    };

    // The runtime is built here rather than in main, because the other
    // subcommands are synchronous and this one is the only async command.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;

    runtime.block_on(async move {
        let net = std::sync::Arc::new(cfrs::vnet::NetStack::loopback());
        let mut proxy =
            cfrs::vnet::proxy::serve(net.clone(), listen, resolver, default_port)
                .await
                .map_err(|e| e.to_string())?;

        for spec in flags.all("forward") {
            let (virt, real) = spec
                .split_once('=')
                .ok_or_else(|| format!("--forward wants VIRT=REAL, got {spec:?}"))?;
            let virt: cfrs::vnet::VirtAddr = virt
                .trim()
                .parse()
                .map_err(|_| format!("bad virtual address {virt:?}"))?;
            let target = RealTarget::parse(real.trim())?;
            let dial_target = target.clone();
            proxy.spawn_forwards(net.clone(), virt, move || {
                let target = dial_target.clone();
                async move { target.dial().await }
            });
            println!("cfrs: forward  {virt} -> {}", target.describe());
        }

        match &proxy.listen {
            ProxyListen::Unix(path) => println!("cfrs: proxy    unix:{}", path.display()),
            ProxyListen::Tcp(addr) => println!("cfrs: proxy    tcp://{addr}"),
        }

        match run_for {
            Some(secs) => tokio::time::sleep(std::time::Duration::from_secs(secs)).await,
            None => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
        proxy.abort();
        Ok(())
    })
}

/// Type-erasure for the forwarded stream, so one forward can bridge to either
/// a TCP or a unix socket.
trait DialStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> DialStream for T {}

impl RealTarget {
    async fn dial(&self) -> std::io::Result<Box<dyn DialStream>> {
        match self {
            Self::Tcp(addr) => Ok(Box::new(tokio::net::TcpStream::connect(addr).await?)),
            #[cfg(unix)]
            Self::Unix(path) => Ok(Box::new(tokio::net::UnixStream::connect(path).await?)),
        }
    }
}

fn cmd_net_tailscale(args: &[String]) -> Result<(), String> {
    use cfrs::vnet::proxy::ProxyListen;
    use cfrs::vnet::tailscale::{self, Dialer};

    let flags = Flags::parse(args)?;
    flags.reject_unknown(NET_TAILSCALE_FLAGS)?;

    let socket = flags
        .get("socket")
        .unwrap_or(tailscale::DEFAULT_SOCKET)
        .to_string();
    let listen = ProxyListen::parse(flags.get("listen").unwrap_or("unix:/tmp/cfrssocks.sock"))
        .map_err(|e| e.to_string())?;
    let default_port: u16 = match flags.get("port") {
        Some(p) => p.parse().map_err(|_| "--port expects a number".to_string())?,
        None => 80,
    };
    let run_for: Option<u64> = match flags.get("run-for") {
        Some(s) => Some(s.parse().map_err(|_| "--run-for expects seconds".to_string())?),
        None => None,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;

    runtime.block_on(async move {
        let proxy = tailscale::serve(Dialer::new(&socket), listen, default_port)
            .await
            .map_err(|e| e.to_string())?;
        match &proxy.listen {
            ProxyListen::Unix(path) => println!("cfrs: proxy    unix:{}", path.display()),
            ProxyListen::Tcp(addr) => println!("cfrs: proxy    tcp://{addr}"),
        }
        println!("cfrs: localapi {socket}");
        println!("cfrs: note     tailscaled must be running with --tun=userspace-networking");
        println!("cfrs: shim     eval \"$(cfrs net socksify --proxy <listen-path>)\"");

        match run_for {
            Some(secs) => tokio::time::sleep(std::time::Duration::from_secs(secs)).await,
            None => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
        proxy.abort();
        Ok(())
    })
}

fn cmd_net_ts_shims(args: &[String]) -> Result<(), String> {
    use cfrs::vnet::tailscale_ssh;

    let flags = Flags::parse(args)?;
    flags.reject_unknown(NET_TS_SHIMS_FLAGS)?;

    let directory = flags.get("out").map_or_else(
        || std::env::temp_dir().join("cfrs-ts-shims"),
        std::path::PathBuf::from,
    );
    let mut user = tailscale_ssh::current_user();
    if let Some(name) = flags.get("user") {
        user.name = name.to_string();
    }
    if let Some(uid) = flags.get("uid") {
        user.uid = uid.parse().map_err(|_| "--uid expects a number".to_string())?;
    }
    if let Some(gid) = flags.get("gid") {
        user.gid = gid.parse().map_err(|_| "--gid expects a number".to_string())?;
    }
    if let Some(shell) = flags.get("shell") {
        user.shell = shell.to_string();
    }

    let shims = tailscale_ssh::install(&directory, &[user.clone()])
        .map_err(|e| e.to_string())?;
    let environment = tailscale_ssh::client_environment(&shims);

    if flags.present("json") {
        let object: serde_json::Map<String, serde_json::Value> = environment
            .into_iter()
            .map(|(key, value)| (key, serde_json::Value::String(value)))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&object).map_err(|e| e.to_string())?
        );
        return Ok(());
    }

    println!("cfrs: shims    {}", shims.dir.display());
    println!("cfrs: user     {} uid={} gid={}", user.name, user.uid, user.gid);
    println!("cfrs: passwd   {}", shims.passwd.display());
    println!("cfrs: fakepwd  {}", shims.fakepwd.display());
    println!(
        "cfrs: daemon   PATH={}:$PATH tailscaled ... --statedir {}",
        shims.dir.display(),
        shims.dir.display()
    );
    println!("cfrs: note     --statedir is what lets the daemon keep SSH host keys");
    for (key, value) in &environment {
        println!("  export {key}={value}");
    }
    Ok(())
}

fn cmd_net_socksify(args: &[String]) -> Result<(), String> {
    let flags = Flags::parse(args)?;
    flags.reject_unknown(NET_SOCKSIFY_FLAGS)?;

    let directory = flags.get("out").map_or_else(
        || std::env::temp_dir().join("cfrssocks"),
        std::path::PathBuf::from,
    );
    let shim = match cfrs::vnet::shim::locate_socks() {
        Some(shim) if !flags.present("out") => shim,
        _ => cfrs::vnet::shim::build_socks(&directory).map_err(|e| e.to_string())?,
    };
    let proxy = flags.get("proxy").unwrap_or("/tmp/cfrssocks.sock");

    let mut environment = vec![(
        "LD_PRELOAD".to_string(),
        match std::env::var("LD_PRELOAD") {
            Ok(existing) if !existing.is_empty() => format!("{}:{existing}", shim.path.display()),
            _ => shim.path.display().to_string(),
        },
    )];
    environment.push(("CFRSSOCKS_PROXY".to_string(), proxy.to_string()));
    if flags.present("log") {
        environment.push(("CFRSSOCKS_LOG".to_string(), "1".to_string()));
    }

    if flags.present("json") {
        let object: serde_json::Map<String, serde_json::Value> = environment
            .into_iter()
            .map(|(key, value)| (key, serde_json::Value::String(value)))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&object).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    eprintln!("cfrs: shim     {}", shim.path.display());
    eprintln!("cfrs: origin   {:?}", shim.origin);
    for (key, value) in &environment {
        println!("export {key}={value}");
    }
    Ok(())
}

fn resolve_proxy(explicit: Option<&str>) -> Option<String> {
    match explicit {
        Some(p) => Some(cfrs::proxy::strip_scheme(p.to_string())),
        None => std::env::var("HTTPS_PROXY")
            .ok()
            .or_else(|| std::env::var("https_proxy").ok())
            .map(cfrs::proxy::strip_scheme),
    }
}

/// Every flag is `--name value`, `--name=v1,v2`, or a bare `--name`.
#[derive(Debug, Default)]
struct Flags {
    values: Vec<(String, Vec<String>)>,
}

impl Flags {
    fn parse(args: &[String]) -> Result<Flags, String> {
        let mut values: Vec<(String, Vec<String>)> = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let Some(rest) = args[i].strip_prefix("--") else {
                return Err(format!("unexpected argument {:?}", args[i]));
            };
            let (name, inline) = match rest.split_once('=') {
                Some((n, v)) => (n.to_string(), Some(v.to_string())),
                None => (rest.to_string(), None),
            };

            let mut collected: Vec<String> = Vec::new();
            if let Some(v) = inline {
                collected.push(v);
                i += 1;
            } else {
                while let Some(next) = args.get(i + 1) {
                    if next.starts_with("--") {
                        break;
                    }
                    collected.push(next.clone());
                    i += 1;
                }
                i += 1;
            }

            match values.iter_mut().find(|(n, _)| *n == name) {
                Some(slot) => slot.1.extend(collected),
                None => values.push((name, collected)),
            }
        }
        Ok(Flags { values })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(n, _)| n == name)
            .and_then(|(_, v)| v.first())
            .map(|s| s.as_str())
    }

    fn all(&self, name: &str) -> Vec<String> {
        self.values
            .iter()
            .filter(|(n, _)| n == name)
            .flat_map(|(_, v)| v.clone())
            .collect()
    }

    fn present(&self, name: &str) -> bool {
        self.values.iter().any(|(n, _)| n == name)
    }

    /// Split comma-separated values, so `--allowed-mail a,b` behaves as two.
    fn all_split(&self, name: &str) -> Vec<String> {
        self.all(name)
            .into_iter()
            .flat_map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn reject_unknown(&self, allowed: &[&str]) -> Result<(), String> {
        for (name, _) in &self.values {
            if !allowed.contains(&name.as_str()) {
                let mut sorted = allowed.to_vec();
                sorted.sort_unstable();
                return Err(format!(
                    "unknown option --{name}; this command accepts: {}",
                    sorted
                        .iter()
                        .map(|s| format!("--{s}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flags_take_one_or_many_values() {
        let f = Flags::parse(&owned(&["--unix-socket", "/tmp/a.sock"])).expect("parse");
        assert_eq!(f.get("unix-socket"), Some("/tmp/a.sock"));

        let f = Flags::parse(&owned(&[
            "--ip-allow",
            "10.0.0.0/8",
            "--ip-allow",
            "192.168.0.0/16",
        ]))
        .expect("parse");
        assert_eq!(f.all("ip-allow"), vec!["10.0.0.0/8", "192.168.0.0/16"]);
    }

    #[test]
    fn comma_separated_values_split() {
        let f = Flags::parse(&owned(&["--allowed-mail", "a@x.com,b@x.com"])).expect("parse");
        assert_eq!(f.all_split("allowed-mail"), vec!["a@x.com", "b@x.com"]);
    }

    #[test]
    fn a_bare_flag_is_boolean_and_does_not_eat_the_next() {
        let f = Flags::parse(&owned(&["--qr", "--protocol", "quic"])).expect("parse");
        assert!(f.present("qr"));
        assert_eq!(f.get("protocol"), Some("quic"));
    }

    #[test]
    fn unknown_flags_are_rejected_by_name() {
        let f = Flags::parse(&["--protocal=quic".to_string()]).expect("parse");
        let err = f.reject_unknown(&["protocol"]).unwrap_err();
        assert!(err.contains("protocal"), "{err}");
        assert!(err.contains("--protocol"), "{err}");
    }

    #[test]
    fn positional_arguments_are_rejected() {
        assert!(Flags::parse(&owned(&["oops"])).is_err());
    }

    #[test]
    fn origin_flags_become_a_service_string() {
        for (args, want) in [
            (vec!["--unix", "/run/app.sock"], "unix:/run/app.sock"),
            (vec!["--tcp", "db:5432"], "tcp://db:5432"),
            (vec!["--dir", "/srv"], "static:/srv"),
            (vec!["--hello-world"], "hello_world"),
            (vec!["--status-code", "404"], "http_status:404"),
        ] {
            let f = Flags::parse(&owned(&args)).expect("parse");
            assert_eq!(
                origin_from_flags(&f).unwrap(),
                Some(want.to_string()),
                "{args:?}"
            );
        }
    }

    #[test]
    fn two_origins_are_refused_rather_than_silently_choosing() {
        let f = Flags::parse(&owned(&["--url", "http://a:1", "--dir", "/srv"])).expect("parse");
        let err = origin_from_flags(&f).unwrap_err();
        assert!(err.contains("only one origin"), "{err}");
    }

    #[test]
    fn an_invalid_origin_is_rejected_at_parse_time() {
        let f = Flags::parse(&owned(&["--status-code", "notanumber"])).expect("parse");
        assert!(origin_from_flags(&f).is_err());
    }

    #[test]
    fn url_helpers_split_authority_and_path() {
        assert_eq!(url_host("wss://relay.example.com/ws"), "relay.example.com");
        assert_eq!(
            split_url("wss://relay.example.com:8443/ws").unwrap(),
            ("relay.example.com".to_string(), 8443)
        );
        assert_eq!(
            split_url("https://example.com").unwrap(),
            ("example.com".to_string(), 443)
        );
    }

    #[test]
    fn proxy_scheme_is_stripped() {
        assert_eq!(
            cfrs::proxy::strip_scheme("http://1.2.3.4:8080".into()),
            "1.2.3.4:8080"
        );
        assert_eq!(
            cfrs::proxy::strip_scheme("1.2.3.4:8080".into()),
            "1.2.3.4:8080"
        );
    }

    #[test]
    fn connect_requires_a_url_and_a_target() {
        assert!(cmd_connect(&owned(&["--local", "tcp://a:1"])).is_err());
        assert!(cmd_connect(&owned(&["--url", "wss://x/y"])).is_err());
    }

    #[test]
    fn serve_refuses_a_missing_origin_socket() {
        let err = cmd_serve(&["--unix-socket=/tmp/cfrs-nope-98765.sock".into()]).unwrap_err();
        assert!(err.contains("does not exist"), "{err}");
    }

    #[test]
    fn tunnel_rejects_unknown_flags_before_anything_else() {
        let err = cmd_tunnel(&owned(&["--nonsense"])).unwrap_err();
        assert!(err.contains("unknown option"), "{err}");
    }

    #[test]
    fn qr_needs_a_url() {
        assert!(cmd_qr(&[]).is_err());
    }
}
