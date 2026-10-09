# cfrs

A Cloudflare quick-tunnel client written in Rust, for sandboxes where the
stock `cloudflared` binary cannot run.

`cloudflared` is a 40 MB Go binary that assumes it can bind a TCP port, resolve
DNS, and open UDP to a Cloudflare edge. In a locked-down sandbox it does none
of those things, and it has no HTTP-proxy flag for its edge connection, so it
fails before it reaches Cloudflare at all.

**What works today.** Two things, and this crate does both:

1. **Anonymous Cloudflare quick-tunnel provisioning**, credential-free, the same
   `POST /tunnel` call `cloudflared` makes.
2. **Actually exposing a server on the public web** from an origin that can
   only be a unix socket, over an HTTP CONNECT proxy with no direct egress.

**What does not work yet.** `cfrs tunnel` does not serve traffic. It loads
ingress rules, resolves the edge, provisions credentials and prints a URL, but
the HTTP/2 and QUIC transports are not driven by a serving loop, so no
connection is registered and no visitor is ever served. The transports build
connections and frame messages; nothing consumes them. Port 7844 is blocked
from the sandbox this was written in, so that part could not be tested against
the real edge either. `cfrs serve` is the path that produces a working public
URL here.

**A third thing, since the last revision.** `cfrs net` gives a process a real
IP address space without `AF_INET`, a network namespace or `CAP_NET_ADMIN`: an
`LD_PRELOAD` shim rewrites `AF_INET` sockets to `AF_UNIX` abstract sockets, and
a `smoltcp` stack owns a private `10.66.0.0/24`. This works, and it is
independent of the tunnel: `cfrs net demo` proves a TCP handshake and transfer
in-process with no kernel socket at all. See *Userspace virtual networking*
below and [`VIRTUAL-NETWORK.md`](./VIRTUAL-NETWORK.md).

## Install

```sh
cargo install --path .
```

## Use

```sh
# Request an anonymous quick tunnel. No account, no token.
cfrs provision

# Require visitors to pass a one-time PIN before reaching the origin.
cfrs provision --otp

# Expose a unix-socket origin on the public web and print the URL.
cfrs serve --unix-socket /tmp/app.sock

# Report what this machine can reach.
cfrs doctor
```

`serve` reads `$HTTPS_PROXY` by default and accepts `--proxy host:port`.
Set `CFRS_DEBUG=1` to trace every visitor channel and byte count.

```sh
# Run the userspace TCP proof: a handshake and a request/response with no
# kernel AF_INET call anywhere.
cfrs net demo

# Give a program an address space it can bind and connect on.
cfrs net shim --out ./cfrsnet --log
cfrs net doctor                    # what this host permits, measured now
cfrs net addresses                 # the address plan and its abstract names

# List local TCP ports that are already listening.
cfrs ports
```

## Userspace virtual networking

When a host refuses `AF_INET` binds entirely, `cfrs net` gives a process an
address space anyway. Two layers, usable separately and composed:

1. **Socket interposition.** `cfrs net shim` builds an `LD_PRELOAD` library that
   rewrites every `AF_INET`/`AF_INET6` socket to an `AF_UNIX` abstract socket
   named `\0cfrsnet/<family>/<address>/<port>`. An ordinary program binds and
   connects normally, and two interposed programs talk to each other with no host
   process at all.

   ```sh
   cfrs net shim --out /tmp/cfrsnet --log   # prints the environment to export
   LD_PRELOAD=/tmp/cfrsnet/libcfrsnet.so ./your-server
   ```

2. **A userspace IP stack.** `smoltcp` owns a private `10.66.0.0/24` and
   `fd00:66::/64` network over an in-process link. The library type is
   `cfrs::vnet::NetStack`, and `cfrs net proxy` exposes it to programs that
   cannot be interposed: a SOCKS5 / HTTP `CONNECT` front door on a unix socket
   that forwards virtual endpoints to real services.

   ```sh
   cfrs net proxy --forward 10.66.0.2:8080=unix:/run/app.sock
   ALL_PROXY=socks5h:///tmp/cfrsnet.socks curl http://10.66.0.2:8080/
   ```

**What is proven, and how.** The claim is that no `AF_INET` syscall reaches the
kernel. `cfrs net demo` shows a full TCP handshake and a request/response inside
the userspace stack, but that is the stack talking to itself, so it is not by
itself evidence about the kernel. `tests/af_inet_kernel.rs` is: it binds
`AF_INET 10.66.0.2:18091` in a real process with the shim preloaded, reads the
socket's inode from `/proc/self/fd`, and asserts the kernel files it under
`/proc/net/unix` and not `/proc/net/tcp`. The inode is used because the shim
interposes `getsockname`, so a probe built on that would measure the shim's own
bookkeeping; this was tried first and it answered `inet`. The control is the
same probe with no shim, which must fail with `EACCES`, or the host is not
sealed and nothing else in the file means anything.

`tests/shim_no_socket.rs` covers the programs the first test does not: ones that
close a descriptor, duplicate one, or ask for a socket name before they ever open
a socket. Those are the majority of programs, and they are where the port found
its worst bug.

Other subcommands: `cfrs net demo`, `cfrs net doctor` (the measured constraint
table, re-run on the running host), `cfrs net addresses`, `cfrs net shim` and
`cfrs net proxy`. The library adds `vnet::dns` (a virtual resolver),
`vnet::policy` (connect-time ACLs) and `vnet::record` (pcap capture and
deterministic replay). What is still open, including the single-waker caveat and
the unwired control server, is listed in §11 of
[`VIRTUAL-NETWORK.md`](./VIRTUAL-NETWORK.md).

## Tailscale, unpatched

A host that forbids `AF_INET` binds and restricts `AF_INET` connects to a few
ports can still join a tailnet. `tailscaled --tun=userspace-networking` runs
the whole stack in userspace, and the one door it always leaves open is its
`LocalAPI` unix socket. `cfrs net tailscale` puts a SOCKS5 / HTTP `CONNECT`
front door on an `AF_UNIX` socket and dials every request through the daemon's
`ts-dial` local API; `cfrs net socksify` builds the shim that redirects an
unmodified program's `connect(2)` to it. Nothing patches or re-links Tailscale.

```sh
cfrs net tailscale --socket /run/tailscale/tailscaled.sock \
                   --listen unix:/run/cfrssocks.sock
eval "$(cfrs net socksify --proxy /run/cfrssocks.sock)"
curl http://100.x.y.z:8080/
```

The daemon can also serve SSH (`tailscaled --ssh`) straight from its netstack,
which is the way *into* a sealed host. It resolves the login on the local
system, though, and a sandbox with no `/etc/passwd` and a read-only `/etc` has
nothing to resolve. `cfrs net ts-shims` writes the two helper commands the
static Go daemon shells out to (`getent`, `id`) plus an `LD_PRELOAD` table for
dynamic clients, so the daemon stays untouched:

```sh
cfrs net ts-shims --out /run/cfrs-ts-shims --user nemo
PATH=/run/cfrs-ts-shims:$PATH tailscaled --tun=userspace-networking \
    --statedir /run/cfrs-ts-shims --socket /run/tailscale/tailscaled.sock
```

An interactive *shell* needs one more step. The daemon is static Go, so it
cannot be given a userspace pty, and a pty request fails the session; a dynamic
`sshd` refuses the pty and carries on. `tools/ts-sshd.sh` runs one on a unix
socket, exposes it with `tailscale serve --tcp`, and gives the login shell
sandhome's `fakepty` and `errandsh`, so a pty-less session still has echo, a
prompt and line editing.

The measurements that force this shape, what is proven live, and the limits
(no UDP, names through `getaddrinfo`, `Dial-Self`) are in
[`TAILSCALE.md`](./TAILSCALE.md).

## `pod-netns`: proxying without shims

Every interposer above can only reach a *dynamic* binary. `pod-netns` is the
kernel-enforced answer: it runs a program in a network namespace whose only
interface is a TUN the parent drives with the `cfrs` userspace stack, so any
program — static, Go, libc-free — has its egress forced through a SOCKS5/HTTP
proxy. `pod-netns doctor` measures what the host permits first, and
`-x tailscale:<socket>` makes the tailnet the transport by dialling the
daemon's `ts-dial` LocalAPI directly, with no front door and no shim. See
[`POD-NETNS.md`](./POD-NETNS.md).

## What was measured, and where the boundary is

Every claim below was measured in the development sandbox on 2026-10-09. The
commands and their raw output are reproducible with `tools/prove-exposure.sh`.

### The sandbox's three constraints

| capability | result | consequence |
| --- | --- | --- |
| `bind()` a TCP listener | `EACCES` | the origin cannot be a TCP port; a unix socket is the only option |
| `connect()` any TCP destination | `EPERM`, loopback included | no tool can reach a local TCP origin, and no direct egress exists |
| UDP socket | `EPERM` | QUIC, and therefore cloudflared's default transport, is impossible |
| egress | HTTP CONNECT proxy at `169.254.169.1:44561`, hostname allow-list | the only route out, and it resolves DNS for us |

The proxy allow-list is per host **and** per port. Measured verdicts, taken by
sending a real `CONNECT` and reading the proxy's own status line:

```
ALLOWED  api.trycloudflare.com:443          BLOCKED  api.trycloudflare.com:7844
ALLOWED  trycloudflare.com:443              BLOCKED  trycloudflare.com:7844
ALLOWED  region1.v2.argotunnel.com:443      BLOCKED  region1.v2.argotunnel.com:7844
ALLOWED  login.trycloudflare.com:443        BLOCKED  bore.pub:7000
```

The tunnel edge lives on port **7844** (confirmed from the SRV record
`_v2-origintunneld._tcp.argotunnel.com`, which returns
`1 1 7844 region1.v2.argotunnel.com`). Port 7844 is blocked on every host
tested, so **a genuine Cloudflare tunnel cannot be established from this
sandbox**, over QUIC or HTTP/2 alike. Port 443 on the edge host is allowed but
is Cloudflare's ordinary HTTP frontend, not the tunnel endpoint: with SNI
`h2.cftunnel.com` it answers the HTTP/2 preface with
`HTTP/1.1 400 Bad Request` and negotiates no ALPN.

### Control: the real cloudflared binary

Downloaded `cloudflared` 2026.10.0 and ran it against the same unix origin:

```
$ cloudflared tunnel --no-autoupdate --protocol http2 --url unix:/tmp/cfrs_origin.sock
INF Requesting new quick Tunnel on trycloudflare.com...
failed to request quick Tunnel: Post "https://api.trycloudflare.com/tunnel":
  dial tcp: lookup api.trycloudflare.com on 9.9.9.9:53:
  write udp 10.0.2.15:37704->9.9.9.9:53: write: operation not permitted
```

It dies at DNS, before Cloudflare. It does not honour `HTTPS_PROXY`, and
`cloudflared tunnel --help` has no proxy flag for its own edge connection, so
there is no configuration that makes it work here. That is the failing-before
control for the provisioning path that `cfrs provision` then performs.

### What `cfrs provision` does instead

The same credential-free POST, routed through the CONNECT proxy so the proxy
resolves the hostname. Live output from the Rust binary:

```
$ cfrs provision
cfrs: requesting a quick tunnel from https://api.trycloudflare.com via 169.254.169.1:44561
url:     https://day-carroll-healing-consolidated.trycloudflare.com
id:      2983af16-7c68-4ef0-9590-e05f35a0cd7b
account: 5ab4e9dfbd435d24068829fda0077963
secret:  32 bytes decoded from 44 base64 chars
```

This is the real anonymous-provisioning step, reproduced from
`cmd/cloudflared/tunnel/quick_tunnel.go` (`RunQuickTunnel`) rather than from
documentation. The response carries real edge credentials; opening the edge is
what port 7844 prevents.

`--otp` sends `{"auth_mode":"otp"}` instead of an empty body. That mirrors
`cloudflared --allowed-mail`, where the allow-list itself never leaves the
client: Cloudflare is told only that a PIN is required.

### What `cfrs serve` does instead, and the proof

With the edge unreachable, the tunnel is carried over an SSH remote forward to
a relay that answers on port 443, which the allow-list permits. Each visitor's
`forwarded-tcpip` channel is spliced to the unix socket, so the blocked TCP
path is never used and the origin needs no listening TCP port.

Relay choice was measured, not guessed:

- tunnelmole is WebSocket-based and needs no account, but its endpoint is
  `wss://service.tunnelmole.com:8083`, and **8083 is blocked**. Ports 80 and
  443 answer but return 404 for every WebSocket path tried.
- `localhost.run`, `serveo.net`, `pinggy.io` and others serve SSH. Measured SSH
  banners through the proxy: `localhost.run:443` speaks TLS, not SSH;
  `free.pinggy.io:443` and `serveo.net:443` return real SSH banners.
- pinggy's documented `ssh -R0:localhost:PORT free.pinggy.io` maps exactly onto
  an SSH remote forward, and its docs describe the HTTP-proxy path.

The relay rejects `auth none` and offers `PublicKey` and `Password`, so `cfrs`
generates an ephemeral Ed25519 key from OS entropy and authenticates with it.

The proof, from `tools/prove-exposure.sh`:

```
== 2. baseline: origin directly over its unix socket ==
  cf-origin OK
  marker=1
  path=/baseline

== 3. start cfrs serve (SSH remote forward over CONNECT proxy) ==
public URL = https://eajet-27-34-73-125.free.pinggy.net  (remote port 7)

== 4. fetch the public URL from a fresh client ==
    http=200 time=5.865175s
  cf-origin OK
  marker=2
  path=/proof?via=public
  agent=cf-origin-unix-socket

== 5. fetch again (a fresh marker proves a real traversal) ==
    http=200 time=0.635670s
  cf-origin OK
  marker=3
  path=/proof?via=second

PASS: the public URL served the unix-socket origin through the tunnel.
```

The origin increments a marker per request, so `marker=2` then `marker=3` are
two genuine traversals rather than one cached response. With
`CFRS_DEBUG=1` the full path is visible on stderr:

```
cfrs: visitor channel opened from 0.0.0.0:7 -> "/tmp/cfrs-app.sock"
cfrs: channel->origin 461 bytes: "GET /hello HTTP/1.1\r\nHost: eajet-...free.pinggy.net..."
cfrs: origin->channel 146 bytes: "HTTP/1.1 200 OK\r\nContent-Type: text/plain..."
```

External visitor, through the relay edge, over the SSH channel, to a unix
socket that nothing else can reach.

### What this does not establish

- The relay carries the tunnel, so the relay operator can see the traffic.
  `cloudflared`'s edge is the private alternative, and it is unreachable here.
  For anything that must not be readable by a third party, run cfrs on a host
  that can reach port 7844 and point it at Cloudflare instead.
- `cfrs provision` returns working edge credentials but does not open the edge
  connection. Registration and visitor serving are not implemented. The HTTP/2
  and QUIC transports build connections and frame messages, but nothing drives
  them in a serving loop, so a `Tunnel` is configuration and routing rather than
  a running tunnel. Port 7844 is unreachable from the sandbox this was built in,
  so that part is untested rather than proven.
- The relay's host-key check accepts any key. The relay is anonymous and
  ephemeral, but a deployment fronting sensitive traffic should pin one.

## Design notes

### Why a unix socket, and why an SSH channel

The three sandbox constraints interact. `bind()` on TCP is refused, so a
listener is impossible; `connect()` on TCP is refused even to loopback, so even
a listener could not be reached. A unix socket dodges both: it can be bound,
and it is reached with `connect()` on `AF_UNIX`.

That only helps if the relay's data path is something other than TCP to a
local port. An SSH `forwarded-tcpip` channel is a raw byte pipe the relay
opens per visitor, so it can be spliced to anything. `copy_bidirectional` runs
both directions over **one** unix connection and waits for **both** to finish.

Getting that wrong was the interesting bug. An earlier version gave each
direction its own connection to the origin: the request reached the origin, the
reply came back on a socket that had never seen a request, and every visitor
timed out. The request leg must also signal end-of-request, or an origin that
reads to EOF waits forever. Both halves of that are pinned by
`copy_bidirectional_carries_request_and_response_on_one_origin_connection`,
which fails if the end-of-request signal is removed (verified by injecting the
regression and watching it fail).

### Checking the wire format against the reference, not against my reading of it

Header serialization was initially wrong in three ways: padded base64 where
cloudflared uses `base64.RawStdEncoding`, a trailing `;` that `SerializeHeaders`
does not emit, and header names that were not canonicalized through
`textproto.CanonicalMIMEHeaderKey` the way Go canonicalizes them. All three were
invisible to a unit test written from the same reading of the source that
produced the bug.

`tools/check-header-oracle.sh` closes that gap. It builds a verbatim copy of
`SerializeHeaders`, runs it, and diffs its output against `encode_headers` on
five cases. It also diffs against `tools/header-oracle.txt`, a captured run, so
the check survives a machine with no Go toolchain. `cargo test` asserts the same
recorded output, which is what catches a change to the encoding.

Running it against the reference is what caught a base64 literal I had written by
hand that was wrong in a single character: the base64 of the header name
`Cf-Connecting-Ip`, one letter off. It passed a unit test written from the same
reading of the source that produced it. Reproducing that literal in prose is
just as easy as it was in the test, which is why the corrected value lives in
`tools/header-oracle.txt` and is asserted from there rather than written down a
second time.

### Why the CONNECT proxy layer is generic

`proxy::connect_tunnel` returns a plain byte pipe, so anything that runs on TCP
runs on top of it. `read_connect_response` is generic over `Read` so the
parsing, the allow-list refusal, and the byte-coalescing case are all testable
without binding a socket, which a sandbox may refuse to do.

## Layout

| path | what it does |
| --- | --- |
| `src/proxy.rs` | HTTP CONNECT transport, generic over `Read`/`Write` |
| `src/quicktunnel.rs` | anonymous Cloudflare provisioning, no credentials |
| `src/relay.rs` | SSH remote forward, splicing channels to a unix socket |
| `src/cloudflare/mod.rs` | edge discovery, credentials, embedded edge roots |
| `src/cloudflare/http2.rs` | HTTP/2 edge transport, header encoding, stream classification |
| `src/cloudflare/quic.rs` | QUIC edge transport, ALPN and SNI, data-stream preamble |
| `src/config.rs` | cloudflared-compatible YAML config and ingress rules |
| `src/origin/` | TCP, unix-socket, static-file and SPA origins |
| `src/transport/` | SSH and WebSocket relays |
| `src/tunnel/mod.rs` | configuration, ingress routing, request preparation |
| `src/feature/mod.rs` | QR rendering and the feature flag surface |
| `src/share.rs` | path-token and PIN-gate access control for a public session |
| `src/ports.rs` | local listening TCP ports, from `/proc/net/tcp{,6}` |
| `src/vnet/` | the userspace IP stack: `addr`, `device`, `stack`, `dns`, `socks`, `proxy`, `policy`, `record`, `control`, `doctor`, `framing`, `shim` |
| `shim/cfrsnet.c` | the `LD_PRELOAD` socket interposer, built by `cfrs net shim` |
| `src/util/` | HTTP head parsing, TLS helpers, metrics |
| `src/bin/cfrs.rs` | CLI: `tunnel`, `provision`, `serve`, `connect`, `qr`, `doctor`, `metrics`, `ports`, `net` |
| `tools/cf-origin.rs` | test origin, serves over a unix socket with a marker |
| `tools/prove-exposure.sh` | end-to-end proof, origin to public URL |
| `tools/check-header-oracle.sh` | diff our header encoding against cloudflared's own Go code |
| `tools/header-oracle.txt` | captured oracle output, asserted by a test |
| `VIRTUAL-NETWORK.md` | the design and measured constraints behind `src/vnet/` |

## Tests

```sh
cargo test
```

332 tests, including a provisioning response captured from the live service, the
allow-list refusal string, byte-coalescing on the CONNECT response, URL
extraction from real relay output, and the splice ordering regression above.

The header-encoding tests are checked against `tools/header-oracle.txt` rather
than against literals typed into the test, which is deliberate: a base64 literal
written by eye is easy to get wrong and hard to notice.

The tests under `tests/` are the ones that had to be argued for. Each of them
was written after the failure was reproduced, and each was then checked by
removing the fix to confirm the test goes red:

| file | what it pins |
| --- | --- |
| `tests/af_inet_kernel.rs` | the kernel files a mapped socket as `AF_UNIX`, measured by socket inode, with the sealed-host control |
| `tests/shim_direct.rs` | two unmodified programs exchange data over abstract names |
| `tests/shim_no_socket.rs` | programs that never open a socket keep working |
| `tests/shim_socks.rs` | an unmodified program's `AF_INET` connect reaches an echo through the tailnet front door |
| `tests/vnet_regressions.rs` | the UTF-8 truncation panic, the decoder wedge, the socket leak and the poll-interval knob |

`tools/check-header-oracle.sh` is not part of `cargo test`. Run it to rebuild
the Go reference and re-diff; it needs a Go toolchain, so it is kept out of the
test run so that `cargo test` works without one.

Two environmental notes, because they look like failures and are not. Build
output must land on a filesystem that can `execve`: a test that compiles a C
program and runs it will fail with `Permission denied` on a `noexec` mount, and
`TMPDIR` has to point somewhere that can run binaries. And an abstract socket
name is one global namespace for the whole host, so every test that binds one
uses its own port; two tests sharing a port produce a `bind-failed` that reads
exactly like a shim that failed to interpose.

## Licence

0BSD. See `LICENSE`.