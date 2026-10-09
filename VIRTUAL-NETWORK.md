# Userspace Virtual Networking in a Sealed Sandbox

A design and reference implementation for giving a process its own IP address
space when the kernel will not provide one: no `AF_INET` `bind(2)`, no network
namespace, no TUN/TAP device, no `CAP_NET_ADMIN`.

The network exists entirely in userspace. The kernel sees only `AF_UNIX`
sockets and one byte stream to a tunnel endpoint.

This document is self-contained. §10 contains the complete source for both
proofs, §9 the exact output they produce, and nothing below depends on any
file or project outside this document.

**It is also now the specification of shipped code.** `src/vnet/` and
`shim/cfrsnet.c` in this repository implement it. Where the code and this
document disagree, §11 says which won and why; the notes there are the places
where implementation changed the design rather than where the design was
ignored. Read this document for the reasoning and `src/vnet/` for the current
truth.

---

## 1. Purpose

Provide, inside the cage:

- a private IPv4/IPv6 address space (`10.66.0.0/24` by default),
- TCP and UDP sockets on those addresses, for unmodified programs,
- a routing path between sandbox-local addresses and a remote peer over a
  tunnel,

without ever issuing an `AF_INET`/`AF_INET6` `bind(2)`, `connect(2)` or
`listen(2)`.

Two independent mechanisms are combined:

1. **Socket interposition** — rewrite the program's `AF_INET` sockets to
   `AF_UNIX` abstract sockets at the libc boundary, so programs keep their
   code and the kernel only ever sees `AF_UNIX`.
2. **A userspace IP stack** — a `smoltcp` stack whose link layer is an
   in-process packet queue (or a tunnel), providing real TCP/IP state machines
   and IP addressing above the interposed sockets.

Either layer works alone; together they give addressed, routed, unmodified
programs.

### 1.1 Conventions and terms

| Term | Meaning in this document |
|---|---|
| **cage**, **sealed sandbox** | a Linux process environment with the restrictions measured in §2 |
| **shim** | the `LD_PRELOAD` library that interposes the socket API (§4). The reference implementation calls it `libcfrsnet.so` and uses the abstract-name prefix `cfrsnet`; both names are arbitrary |
| **host process** | the process that runs the userspace stack (§5) and owns the control socket (§6.3). The reference implementation is a single Rust binary |
| **virtual network** | the address space the stack owns; `10.66.0.0/24` by default |
| **abstract namespace** | Linux `AF_UNIX` sockets addressed by a leading-NUL name (`\0name`), occupying no filesystem path |
| **tunnel** | an outbound, already-established byte-stream link to a rendezvous, used as the stack's link layer. Its transport is out of scope: it may be QUIC, WebSocket, TLS, a pipe, or a socketpair |
| **rendezvous**, **remote peer** | the endpoint at the far side of the tunnel |
| **stack** | the `smoltcp` instance |
| **device** | the `smoltcp` `Device` implementation (an in-process queue, or the tunnel) |

Nothing here depends on a particular tunnel implementation. Where the tunnel
is mentioned, any reliable, ordered byte stream works.

---

## 2. Environment constraints (measured)

| Operation | Result |
|---|---|
| `unshare(CLONE_NEWUSER)` | `EPERM` |
| `unshare(CLONE_NEWNET)` | `EPERM` |
| `unshare(CLONE_NEWNS)` | `EPERM` |
| `bind(AF_INET, 127.0.0.1:0)` | `EACCES` |
| `bind(AF_INET, 127.0.0.2:0)` | `EACCES` |
| `bind(AF_INET6, [::1]:0)` | `EACCES` |
| `bind(AF_VSOCK, CID_ANY:0)` | `EACCES` |
| `bind(AF_UNIX, /path)` | OK |
| `bind(AF_UNIX, \0abstract)` | OK |
| `bind(AF_NETLINK, ...)` | OK |
| `/dev/net/tun` | absent |
| `/dev/vsock` | absent |
| `cc -shared -fPIC` + `LD_PRELOAD` | works |

Process state: `Seccomp: 2` (filter mode), `NoNewPrivs: 1`,
`CapEff = CapBnd = 0`. The kernel's
`/proc/sys/kernel/unprivileged_userns_clone` is `1`, so the namespace `EPERM`
originates in the sandbox's filter, not in a kernel policy.

Consequences:

- No kernel network interface can be created, so no kernel routing, no
  `getifaddrs` entry, no host-visible address.
- `AF_UNIX` is fully available, including the abstract namespace, which is the
  substrate for everything below.
- `LD_PRELOAD` is available and already used by the cage's own shims
  (for example `fakepty.so`, `fakepwd.so`), so interposition is an
  established mechanism in this environment.

Reproducing the table (Linux):

```sh
unshare --user --map-root-user true          # expect: Operation not permitted
python3 - <<'EOF'
import socket, errno
for fam, addr in [(socket.AF_INET, ("127.0.0.1",0)),
                  (socket.AF_INET6, ("::1",0)),
                  (socket.AF_UNIX, "/tmp/probe.sock")]:
    s = socket.socket(fam, socket.SOCK_STREAM)
    try: s.bind(addr); print("OK  ", fam, s.getsockname())
    except OSError as e: print("FAIL", fam, errno.errorcode.get(e.errno))
    finally: s.close()
EOF
```

---

## 3. Design overview

```
        sandbox process(es)                host process (the stack)
  ┌───────────────────────────┐        ┌────────────────────────────┐
  │ application               │        │  smoltcp stack             │
  │   socket(AF_INET, ...)    │        │    iface 10.66.0.2/24      │
  │        │                  │        │    tcp sockets             │
  │   libcfrsnet.so           │        │        │                   │
  │   (LD_PRELOAD)            │        │        │ virtual link      │
  │        │ AF_UNIX abstract │        │        ▼                   │
  │        └──── \0cfrsnet/… ─┼───────►│  Device: packet queue      │
  └───────────────────────────┘        │        │                   │
                                       │        ▼                   │
                                       │  tunnel (any byte stream)  │
                                       └────────────────────────────┘
```

- The **shim** turns `AF_INET` sockets into `AF_UNIX` abstract sockets and
  encodes the intended IP endpoint in the socket name.
- The **stack** owns the `10.66.0.0/24` address space and implements IP/TCP/UDP
  state. Its link can be an in-process queue (loopback) or the tunnel.
- The **tunnel** is the only link to anything outside the sandbox.

---

## 4. Layer 1 — socket interposition

### 4.1 API surface

The shim (`libcfrsnet.so`) exports the libc socket symbols and forwards to
the real implementations obtained with `dlsym(RTLD_NEXT, …)`:

| Symbol | Behaviour for a virtual (`AF_INET`/`AF_INET6`) fd |
|---|---|
| `socket` | create `AF_UNIX` of the same `type`; mark the fd virtual |
| `bind` | translate the `sockaddr` to an abstract `AF_UNIX` name, call real `bind` |
| `connect` | translate, call real `connect` |
| `listen` | pass through |
| `accept` / `accept4` | pass through; new fd inherits virtual status, logical peer recorded |
| `getpeername` | return the recorded logical `sockaddr` |
| `getsockname` | return the recorded logical `sockaddr` |
| `close` | clear the fd's virtual state |
| `dup` / `dup2` / `dup3` / `fcntl(F_DUPFD*)` | copy virtual state to the new fd |

Not interposed, because the underlying fd is a real kernel `AF_UNIX` fd:
`read`, `write`, `send`, `recv`, `poll`, `select`, `epoll_*`, `shutdown`,
`setsockopt(SO_*)`. Readiness APIs work unchanged.

`socket(AF_INET6, SOCK_DGRAM, …)` and `SOCK_STREAM` both map to the same
`AF_UNIX` type. `SOCK_RAW`/`SOCK_PACKET` are not supported.

### 4.2 Address translation

An IP endpoint becomes a name in the abstract namespace:

```
\0cfrsnet/<family>/<address>/<port>
```

- `family`: `4` or `6`
- `address`: dotted-quad for v4, RFC 5952 compressed form for v6
- `port`: decimal

Examples:

```
10.66.0.2:8080        -> \0cfrsnet/4/10.66.0.2/8080
[fd00::2]:443         -> \0cfrsnet/6/fd00::2/443
```

`/` is the separator precisely because IPv6 literals use `:`. The maximum
name length is 107 bytes (`sun_path[108]` minus the leading NUL); a
compressed IPv6 literal is at most 45 bytes, so the longest name is
`cfrsnet/6/` (9) + 45 + `/` + 5 = 60 bytes.

The `socklen_t` passed to the real call is
`offsetof(struct sockaddr_un, sun_path) + 1 + strlen(name)`.

`bind` and `connect` are the only translation points. `listen`/`accept` are
family-agnostic. This means a mapped socket can be a listener or a connector
without any further changes.

### 4.3 fd state

Virtual status and logical addresses live in a process-wide table indexed by
fd:

```c
struct virt_fd {
    bool   is_virtual;
    struct sockaddr_storage local;    /* set by bind() */
    struct sockaddr_storage peer;     /* set by connect() or by accept() */
    socklen_t local_len, peer_len;
};
```

The table is guarded by a mutex (fds are process-wide, not thread-local).
`close` frees the slot; `dup*`/`fcntl` copy it. Slots for `accept`ed fds are
populated with the listener's local address and a synthesized peer derived
from the accepted `AF_UNIX` peer name when the stack uses the direct mode.
The reference shim in §10.3 uses a simpler boolean table and leaves
`getpeername`/`getsockname` for the open work in §11.

### 4.4 Initialization

`dlsym` must not be called from a constructor that can run after a
program's own constructor calls `socket`. Use a lazy, once-only resolver
called at the top of every interposed function:

```c
static pthread_once_t once = PTHREAD_ONCE_INIT;
static void resolve(void) {
    r_socket  = dlsym(RTLD_NEXT, "socket");
    r_bind    = dlsym(RTLD_NEXT, "bind");
    /* … */
}
```

`RTLD_NEXT` avoids self-recursion. `dlsym` itself does not call `socket`, so
the resolver is safe.

### 4.5 Limitations of the shim

- `setsockopt` with `IPPROTO_TCP`/`IPPROTO_IP`/`IPPROTO_IPV6` on a virtual fd
  returns `ENOPROTOOPT` from the underlying `AF_UNIX` socket. TCP-level options
  (`TCP_NODELAY`, `TCP_KEEPIDLE`, …) need to be swallowed and recorded.
- `sendto`/`recvfrom`/`sendmsg`/`recvmsg` with a destination `sockaddr` need
  the same translation as `bind`/`connect` for datagram sockets.
- `io_uring` and `sendmmsg`/`recvmmsg` bypass the interposed calls unless
  also interposed.
- Programs that inspect `/proc/net/tcp`, `getifaddrs`, or `/sys/class/net`
  will not see the virtual interface.
- A statically linked program cannot be interposed.
- `SOCK_RAW`/`SOCK_PACKET` and `AF_PACKET` are not mapped.

---

## 5. Layer 2 — userspace IP stack

### 5.1 Device model

`smoltcp` drives a `Device` that yields packets. For a self-contained stack,
`phy::Loopback` is a packet queue: every transmitted frame is re-delivered on
receive, in FIFO order.

```rust
use smoltcp::phy::{Loopback, Medium};

let mut device = Loopback::new(Medium::Ip);
```

`Medium::Ip` means the device carries IP packets (no Ethernet framing), which
matches a stream link such as a tunnel.

### 5.2 Interface and sockets

```rust
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint};

let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, Instant::ZERO);
iface.update_ip_addrs(|addrs| {
    addrs.push(IpCidr::new(IpAddress::v4(10, 66, 0, 2), 24)).unwrap();
});

let mut sockets = SocketSet::new(vec![]);
let server = sockets.add(tcp::Socket::new(
    tcp::SocketBuffer::new(vec![0u8; 4096]),
    tcp::SocketBuffer::new(vec![0u8; 4096]),
));
let client = sockets.add(tcp::Socket::new(
    tcp::SocketBuffer::new(vec![0u8; 4096]),
    tcp::SocketBuffer::new(vec![0u8; 4096]),
));

sockets.get_mut::<tcp::Socket>(server)
    .listen(IpListenEndpoint { addr: Some(IpAddress::v4(10, 66, 0, 2)), port: 8080 })
    .unwrap();
sockets.get_mut::<tcp::Socket>(client)
    .connect(iface.context(), (IpAddress::v4(10, 66, 0, 2), 8080), 49152)
    .unwrap();
```

`HardwareAddress::Ip` selects an IP-medium interface (no MAC). Buffer sizes
bound the per-connection window; 4 KiB each is a starting point.

### 5.3 Poll loop and clock

`smoltcp` is poll-driven and needs a monotonic millisecond clock. Any
monotonic source is acceptable; a counter or `std::time::Instant` mapped to
`smoltcp::time::Instant` both work.

```rust
let mut now_ms = 0i64;
loop {
    now_ms += 1;
    iface.poll(Instant::from_millis(now_ms), &mut device, &mut sockets);

    // service sockets
    let s = sockets.get_mut::<tcp::Socket>(server);
    if s.may_recv() { let mut b = [0u8; 512]; if let Ok(n) = s.recv_slice(&mut b) { /* … */ } }
    let c = sockets.get_mut::<tcp::Socket>(client);
    if c.may_send() { let _ = c.send_slice(b"GET / HTTP/1.0\r\n\r\n"); }
    if c.may_recv() { let mut b = [0u8; 512]; if let Ok(n) = c.recv_slice(&mut b) { /* … */ } }
}
```

A production loop replaces the fixed increment with a real clock and blocks in
`Device::wait` when idle.

### 5.4 Tunnel-backed device

To make the stack reach a remote peer, replace `Loopback` with a device whose
`transmit` writes the packet to the tunnel and whose `receive` pulls the next
packet from it:

```rust
impl Device for TunnelDevice {
    type RxToken<'a> = Rx;   // wraps a Vec<u8> packet
    type TxToken<'a> = Tx;   // wraps a &mut sink

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            medium: Medium::Ip,
            max_transmission_unit: 1280,   // conservative for a tunnel
            ..DeviceCapabilities::default()
        }
    }

    fn receive(&mut self, _t: Instant) -> Option<(Rx, Tx)> {
        self.rx.pop_front().map(|pkt| (Rx(pkt), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _t: Instant) -> Option<Tx> {
        Some(Tx(&mut self.tx))
    }

    fn wait(&mut self, _t: Instant) -> Option<Instant> {
        self.rx_waker.as_ref().map(|w| w.clone())
    }
}
```

`Rx::consume` copies the frame into smoltcp's buffer; `Tx::consume` frames the
packet and writes it to the tunnel. `wait` returns a waker so the poll loop can
block instead of spin.

### 5.5 Framing over a stream link

A QUIC or TCP stream is byte-oriented; IP packets need boundaries. Use a
length prefix:

```
u16 big-endian length | packet bytes
```

A WebSocket link already preserves message boundaries, so one packet per
binary message is an alternative with no prefix. `max_transmission_unit` must
be set below the link's maximum frame size.

---

## 6. Integration

### 6.1 Addressing plan

| Address | Role |
|---|---|
| `10.66.0.0/24` | virtual subnet |
| `10.66.0.1` | stack/gateway |
| `10.66.0.2` … `10.66.0.254` | sandbox programs |

Addresses are local to the stack; they are never configured on a kernel
interface.

### 6.2 Direct mode (same host)

The shim's translation is sufficient by itself. Two programs on the same host
exchange data through the abstract name; no stack is involved.

```
program A binds 10.66.0.2:8080  ->  \0cfrsnet/4/10.66.0.2/8080
program B connects 10.66.0.2:8080 -> \0cfrsnet/4/10.66.0.2/8080
```

Properties:

- Kernel-visible: two `AF_UNIX` stream sockets.
- Kernel-invisible: any IP packet, any `AF_INET` syscall.
- Throughput: a single `AF_UNIX` socket pair, i.e. a memory copy per
  direction; no IP processing.

### 6.3 Switch mode (cross host)

To reach a remote peer, the stack owns the abstract names instead of the
programs:

1. The shim's `bind`/`connect` connects to a control socket and registers the
   logical endpoint; the stack binds the corresponding abstract name.
2. A program's bytes are carried over `AF_UNIX` to the stack.
3. The stack's TCP state machine processes them; its `TunnelDevice` frames
   the resulting packets onto the tunnel.
4. Inbound tunnel packets are fed to `Device::receive`, and smoltcp delivers
   them to the listening socket, whose bytes are written back over `AF_UNIX`.

The control socket is a well-known abstract name:

```
\0cfrsnet/ctl
```

Control messages are length-prefixed:

```
u8 op | u16 len | payload
  op=1 REGISTER_BIND     payload = family,addr,port,fd-handle
  op=2 REGISTER_CONNECT  payload = family,addr,port
  op=3 UNREGISTER        payload = handle
  op=4 DATAGRAM          payload = family,addr,port,bytes
```

File descriptors are not passed; instead the shim keeps its `AF_UNIX`
connection to the stack and multiplexes logical connections over it with a
per-connection stream id. This avoids `SCM_RIGHTS` and keeps the stack
independent of the shim's process lifetime.

### 6.4 Proxy mode

For programs that honour proxy environment variables and cannot be
interposed (statically linked, or running under a different loader), the
stack also exposes SOCKS5 and HTTP `CONNECT` listeners on `AF_UNIX`:

```
ALL_PROXY=socks5h:///path/to/socks.sock
```

`SOCKS5` with `ATYP=DOMAINNAME` maps host names to virtual addresses through
an internal resolver, or to a fixed virtual address for a single-upstream
configuration.

### 6.5 Packet flow, inbound request to sandbox service

```
remote peer ──tunnel stream──► host process (stack)
                                  │
                                  ├─ TCP connection injected: 10.66.0.2:8080
                                  │
                                  ▼
                           smoltcp stack (10.66.0.2)
                                  │  TCP payload
                                  ▼
                           AF_UNIX \0cfrsnet/4/10.66.0.2/8080
                                  │
                                  ▼
                           sandbox program (shim)
```

### 6.6 Packet flow, sandbox program to remote peer

```
sandbox program ──AF_UNIX──► stack ──TCP/IP──► TunnelDevice ──► tunnel ──► remote
```

---

## 7. What it unlocks

The two layers compose, and the composition is where the leverage is. The
following are hypotheses and ideas, ordered from "falls out of the code as it
stands" to "needs the open work in §11".

### 7.1 Same-host, no kernel networking

- **`localhost` for programs that hardcode it.** Build tools, language
  servers, MCP servers, dev servers, test runners and browsers routinely bind
  `127.0.0.1` or connect to it. The shim lets them keep doing exactly that;
  the kernel only sees `AF_UNIX`. Hypothesis: the set of tools that fail
  solely because they need a loopback TCP listener is large, and this removes
  the failure without touching the tools.
- **Multi-service applications with real addresses.** A web process, a
  database, a cache and a queue get `10.66.0.2`, `.3`, `.4`, `.5` and talk
  over ordinary TCP. No Docker, no netns, no root. The addresses are stable
  for the lifetime of the stack.
- **Stable addresses across restarts.** Derive each service's address from a
  name hash (e.g. `10.66.0.(fnv(name) & 0xff)`) and a config file full of IP
  literals survives a restart, unlike an ephemeral tunnel hostname. The
  abstract names vanish with the process; the logical address does not have
  to.
- **Unprivileged "container network" for CI.** Nested test runners that need
  loopback, and compose-style multi-service integration tests, run in an
  environment with no namespaces and no privileges.

### 7.2 Cross-host and mesh

- **A process-level VPN.** The `TunnelDevice` link can be any transport — the
  tunnel, a relay, a userspace WireGuard-style handshake. Two nodes in the
  same `10.66.0.0/24` are then two *processes*, not two machines, and the
  "network" is a mesh of sandboxes and laptops.
- **The sandbox as a first-class node.** With the stack owning the abstract
  names (switch mode, §6.3), an inbound tunnel request becomes a TCP
  connection to `10.66.0.2:port`, and a sandbox program is a normal listener
  or connector on that address. The origin of a tunnel stops being a special
  case and becomes an IP endpoint.
- **Bridging unix-only services to IP clients.** A service that only speaks
  `AF_UNIX` is exposed at a virtual `IP:port`, so IP-only tooling reaches it;
  the reverse maps an IP service onto a unix socket for a unix-only consumer.
- **NAT and port mapping in userspace.** One virtual address can front many
  backends with health checks and load balancing, all in the stack, with no
  kernel netfilter.

### 7.3 Testing and simulation

- **Deterministic integration networks.** `smoltcp` is poll-driven and takes
  its clock from the caller, so N virtual nodes with fixed addresses can run
  in one process, in one test, with no containers and no real network. Time
  is a parameter, so a 30-second timeout is tested in milliseconds and a
  retransmission is exercised on demand.
- **Fault injection and chaos testing.** `smoltcp` ships `FaultInjector` and
  `FuzzInjector` devices. Wrapping the virtual link in one lets a test drop,
  reorder, duplicate or corrupt packets deterministically — retransmission,
  windowing and RTO behaviour become reproducible rather than flaky.
- **Packet capture without privileges.** `smoltcp` ships a `PcapWriter`
  device wrapper. Every packet on the virtual link can be written to a
  `.pcap` for Wireshark, with no `CAP_NET_RAW`, no `tcpdump` and no host
  interface.
- **Record and replay.** A captured virtual link can be replayed into the
  deterministic stack to reproduce a bug exactly, or to compare two stack
  versions on identical input.
- **Protocol fuzzing and development.** Feed arbitrary byte streams into a
  TCP-based protocol implementation with full control of timing and
  segmentation; or develop a custom wire protocol against the stack before
  any kernel is involved.

### 7.4 Observability and policy

- **A userspace sidecar.** Because every connection is a userspace socket,
  the stack can apply per-address ACLs, retries, metrics, tracing, header
  injection and mutual authentication between virtual nodes — full
  observability with no eBPF, no kernel module and no privileges.
- **Virtual DNS and discovery.** A resolver at `10.66.0.1:53` (or the SOCKS5
  `ATYP=DOMAINNAME` path) maps names to virtual addresses, so programs
  resolve service names without `/etc/hosts` or a real resolver.
- **Capability-scoped routing.** Routing policy can decide which virtual
  addresses a program may reach, per process, at connect time — a
  userspace equivalent of a per-pod network policy.

### 7.5 Replacing ad-hoc IPC

- **Existing IP tooling against sandbox services.** Once a service has a
  virtual address, `curl`, `redis-cli`, `psql`, `grpcurl` and friends work
  through the proxy mode or the shim, instead of each service inventing its
  own socket path and framing.
- **A single substrate for agent and plugin systems.** Plugins that expect to
  talk TCP to a host process get an address in a shared virtual network
  rather than a bespoke IPC channel, with the same isolation and observation
  hooks for all of them.

---

## 8. Failure modes

| Symptom | Cause | Handling |
|---|---|---|
| `EADDRINUSE` on abstract bind | a previous process left the name | abstract names vanish with the process; ensure `close`/`shutdown` or use a per-run suffix |
| `ECONNREFUSED` from `connect` | no listener at that abstract name, or the stack has no route | distinguish "no local listener" from "no route" in the control protocol |
| stalls under load | `SocketBuffer` exhausted, window zero | size buffers to the expected in-flight data; drain both directions each poll |
| packet loss on the tunnel | MTU larger than the link frame | set `max_transmission_unit` to the link's maximum; fragment is not implemented |
| `getpeername` returns `AF_UNIX` | fd not registered in the shim table | register `accept`ed fds and their logical peers |
| clock not advancing | poll loop not fed monotonic time | drive `Instant` from a monotonic source, not a fixed increment, in production |
| `ENOPROTOOPT` from `setsockopt` | TCP/IP option on an `AF_UNIX` fd | swallow and record the option in the shim |

---

## 9. Verification

### 9.1 Layer 2 — userspace TCP handshake and transfer

```sh
cargo run -q          # in the crate of §10.2
```

```
  server ACCEPTED from 10.66.0.2:49152
  client WROTE 23B request (state=ESTABLISHED)
  server READ 23B: GET /hello HTTP/1.0
  server WROTE response
  client READ 58B

--- verdict ---
link layer: in-process loopback
note: this proves the stack ran in-process. It cannot observe its own
      syscalls; tests/af_inet_kernel.rs measures the kernel side by socket inode.
server socket final state: ESTABLISHED
client socket final state: ESTABLISHED
PROOF: userspace TCP handshake + request/response complete
```

A full SYN / SYN-ACK / ACK sequence and a request/response round trip occur with
no kernel `AF_INET` bind or connect.

**This verdict does not prove that, and the wording was changed to stop it
looking as though it does.** The original printed "kernel AF_INET bind/connect
used: none" from a field set to a literal zero. A userspace stack cannot observe
its own syscalls, so that line was a claim about a number nothing ever counted,
and it would have stayed true if a direct `AF_INET` connect were added anywhere
on the path. What this output does establish is that the stack ran over an
in-process link and completed a handshake and a round trip. The kernel side is
measured separately, by socket inode, in `tests/af_inet_kernel.rs`; §9.3 says how
and §11 says why that method and not this one.

### 9.2 Layer 1 — unmodified programs mapped in

```sh
cc -O2 -shared -fPIC -o libcfrsnet.so cfrsnet.c -ldl
cc -O2 -o server server.c
cc -O2 -o client client.c
LD_PRELOAD=$PWD/libcfrsnet.so ./server &
sleep 0.3
LD_PRELOAD=$PWD/libcfrsnet.so ./client
wait
```

```
[cfrsnet] bind -> abstract cfrsnet/4/10.66.0.2/8080
server: listening on 10.66.0.2:8080 (no AF_INET bind reached the kernel)
[cfrsnet] connect -> abstract cfrsnet/4/10.66.0.2/8080
server: read 23B: GET /hello HTTP/1.0
client: got 49B from 10.66.0.2:8080:
HTTP/1.0 200 OK

userspace virtual net says hi
```

Both programs use ordinary `AF_INET` sockets and `bind`/`connect` calls; the
kernel only sees `AF_UNIX`.

### 9.3 Confirming no `AF_INET` syscall is issued

The shim logs every translation and counts them in `mapped`. To confirm
independently, attach a `ptrace`/`seccomp` observer and assert that no
`bind`/`connect`/`listen` with an `AF_INET`/`AF_INET6` argument is issued, or
run the program under an `LD_PRELOAD` audit library that records the same
calls.

---

## 10. Reference implementation (complete source)

The listings below are the whole implementation. Save them as shown, then
build with the commands in §9.

### 10.1 Prerequisites

- Linux (the abstract namespace and `LD_PRELOAD` are Linux features)
- Rust toolchain with `cargo` (edition 2021)
- a C compiler (`cc`)
- network access to crates.io for the one dependency, `smoltcp` 0.11

### 10.2 `Cargo.toml`

```toml
[package]
name = "netspike"
version = "0.1.0"
edition = "2021"

[dependencies]
smoltcp = { version = "0.11", default-features = false, features = ["std", "medium-ip", "proto-ipv4", "socket-tcp"] }
```

### 10.3 `src/main.rs` — userspace TCP handshake and transfer

```rust
// Userspace TCP/IP, no kernel sockets: prove a full TCP handshake + data
// transfer inside a smoltcp stack whose only "wire" is an in-process queue.
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Loopback, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint};

const IP: IpAddress = IpAddress::v4(10, 66, 0, 2);
const PORT: u16 = 8080;

fn main() {
    let mut device = Loopback::new(Medium::Ip);
    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, Instant::ZERO);
    iface.update_ip_addrs(|a| a.push(IpCidr::new(IP, 24)).unwrap());

    let mk = || tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; 4096]),
        tcp::SocketBuffer::new(vec![0u8; 4096]),
    );
    let mut sockets = SocketSet::new(vec![]);
    let server = sockets.add(mk());
    let client = sockets.add(mk());

    sockets.get_mut::<tcp::Socket>(server)
        .listen(IpListenEndpoint { addr: Some(IP), port: PORT }).unwrap();
    sockets.get_mut::<tcp::Socket>(client)
        .connect(iface.context(), (IP, PORT), 49152).unwrap();

    let mut now_ms = 0i64;
    let mut request_sent = false;
    let mut response: Vec<u8> = Vec::new();
    let mut accepted = false;
    let mut step_log = Vec::new();

    for _ in 0..2000 {
        now_ms += 1;
        let now = Instant::from_millis(now_ms);
        iface.poll(now, &mut device, &mut sockets);

        {
            let s = sockets.get_mut::<tcp::Socket>(server);
            if !accepted && s.may_recv() && s.may_send() {
                accepted = true;
                step_log.push(format!("server ACCEPTED from {:?}", s.remote_endpoint()));
            }
            if s.may_recv() {
                let mut buf = [0u8; 512];
                if let Ok(n) = s.recv_slice(&mut buf) {
                    if n > 0 {
                        let got = String::from_utf8_lossy(&buf[..n]).to_string();
                        step_log.push(format!("server READ {n}B: {}", got.trim()));
                        let resp = format!("HTTP/1.0 200 OK\r\n\r\nuserspace tcp says: {}", got.trim());
                        let _ = s.send_slice(resp.as_bytes());
                        step_log.push("server WROTE response".into());
                    }
                }
            }
        }
        {
            let c = sockets.get_mut::<tcp::Socket>(client);
            if !request_sent && c.may_send() {
                request_sent = true;
                let req = b"GET /hello HTTP/1.0\r\n\r\n";
                let n = c.send_slice(req).unwrap();
                step_log.push(format!("client WROTE {n}B request (state={})", c.state()));
            }
            if c.may_recv() {
                let mut buf = [0u8; 512];
                if let Ok(n) = c.recv_slice(&mut buf) {
                    if n > 0 {
                        response.extend_from_slice(&buf[..n]);
                        step_log.push(format!("client READ {n}B"));
                    }
                }
            }
        }
        if response.windows(4).any(|w| w == b"\r\n\r\n") && response.len() > 20 {
            break;
        }
    }

    for l in &step_log { println!("  {l}"); }
    println!("\n--- verdict ---");
    // Not a syscall count: this code cannot observe its own syscalls. It names
    // the link layer it ran over, which is the part it does know.
    println!("link layer: in-process loopback");
    println!("note: the kernel side is measured separately, by socket inode,");
    println!("      in tests/af_inet_kernel.rs");
    println!("server socket final state: {}", sockets.get::<tcp::Socket>(server).state());
    println!("client socket final state: {}", sockets.get::<tcp::Socket>(client).state());
    let body = String::from_utf8_lossy(&response);
    assert!(body.contains("200 OK"), "no HTTP response: {body:?}");
    assert!(body.contains("userspace tcp says: GET /hello HTTP/1.0"), "body wrong: {body:?}");
    println!("PROOF: userspace TCP handshake + request/response complete");
}
```

### 10.4 `shim/cfrsnet.c` — socket interposition

```c
// Map AF_INET/AF_INET6 sockets into a userspace virtual network by rewriting
// them to AF_UNIX (abstract) sockets. The kernel never sees an AF_INET bind
// or connect; the "wire" is a name in the abstract namespace, which is where
// the userspace switch (netstack) listens.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <errno.h>

static int (*r_socket)(int,int,int);
static int (*r_bind)(int,const struct sockaddr*,socklen_t);
static int (*r_connect)(int,const struct sockaddr*,socklen_t);
static int (*r_listen)(int,int);
static int (*r_accept)(int,struct sockaddr*,socklen_t*);

static int virt[4096];
static int is_virt(int fd){ return fd>=0 && fd<4096 && virt[fd]; }
static long mapped;

__attribute__((constructor)) static void init(void){
  r_socket=dlsym(RTLD_NEXT,"socket");
  r_bind=dlsym(RTLD_NEXT,"bind");
  r_connect=dlsym(RTLD_NEXT,"connect");
  r_listen=dlsym(RTLD_NEXT,"listen");
  r_accept=dlsym(RTLD_NEXT,"accept");
}

static int to_unix(const struct sockaddr *a, socklen_t len,
                   struct sockaddr_un *u, socklen_t *ul){
  char ip[64]; unsigned port=0; int fam=0;
  if(a->sa_family==AF_INET){
    const struct sockaddr_in *s=(const void*)a;
    if(len<sizeof *s){errno=EINVAL;return -1;}
    inet_ntop(AF_INET,&s->sin_addr,ip,sizeof ip); port=ntohs(s->sin_port); fam=4;
  } else if(a->sa_family==AF_INET6){
    const struct sockaddr_in6 *s=(const void*)a;
    if(len<sizeof *s){errno=EINVAL;return -1;}
    inet_ntop(AF_INET6,&s->sin6_addr,ip,sizeof ip); port=ntohs(s->sin6_port); fam=6;
  } else {errno=EAFNOSUPPORT;return -1;}
  memset(u,0,sizeof *u); u->sun_family=AF_UNIX;
  int n=snprintf(u->sun_path+1,sizeof(u->sun_path)-1,"cfrsnet/%d/%s/%u",fam,ip,port);
  *ul=(socklen_t)(offsetof(struct sockaddr_un,sun_path)+1+n);
  return 0;
}

int socket(int domain,int type,int protocol){
  if(domain==AF_INET||domain==AF_INET6){
    int fd=r_socket(AF_UNIX,type,0);
    if(fd>=0&&fd<4096) virt[fd]=1;
    return fd;
  }
  return r_socket(domain,type,protocol);
}
int bind(int fd,const struct sockaddr *a,socklen_t len){
  if(is_virt(fd)){
    struct sockaddr_un u; socklen_t ul;
    if(to_unix(a,len,&u,&ul)<0) return -1;
    mapped++;
    fprintf(stderr,"[cfrsnet] bind -> abstract %s\n", u.sun_path+1);
    return r_bind(fd,(struct sockaddr*)&u,ul);
  }
  return r_bind(fd,a,len);
}
int connect(int fd,const struct sockaddr *a,socklen_t len){
  if(is_virt(fd)){
    struct sockaddr_un u; socklen_t ul;
    if(to_unix(a,len,&u,&ul)<0) return -1;
    mapped++;
    fprintf(stderr,"[cfrsnet] connect -> abstract %s\n", u.sun_path+1);
    return r_connect(fd,(struct sockaddr*)&u,ul);
  }
  return r_connect(fd,a,len);
}
int listen(int fd,int backlog){ return r_listen(fd,backlog); }
int accept(int fd,struct sockaddr *a,socklen_t *l){ return r_accept(fd,a,l); }
```

### 10.5 `shim/server.c` — an unmodified `AF_INET` listener

```c
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0);
  struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(8080);
  inet_pton(AF_INET,"10.66.0.2",&a.sin_addr);
  if(bind(s,(struct sockaddr*)&a,sizeof a)<0){perror("bind");return 1;}
  listen(s,4);
  printf("server: listening on 10.66.0.2:8080 (no AF_INET bind reached the kernel)\n");
  int c=accept(s,0,0);
  char buf[256]={0}; int n=read(c,buf,sizeof buf-1);
  printf("server: read %dB: %s", n, buf);
  const char *r="HTTP/1.0 200 OK\r\n\r\nuserspace virtual net says hi\n";
  write(c,r,strlen(r)); close(c); close(s);
  return 0;
}
```

### 10.6 `shim/client.c` — an unmodified `AF_INET` client

```c
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0);
  struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(8080);
  inet_pton(AF_INET,"10.66.0.2",&a.sin_addr);
  if(connect(s,(struct sockaddr*)&a,sizeof a)<0){perror("connect");return 1;}
  const char *q="GET /hello HTTP/1.0\r\n\r\n";
  write(s,q,strlen(q));
  char buf[512]={0}; int n=read(s,buf,sizeof buf-1);
  printf("client: got %dB from 10.66.0.2:8080:\n%s", n, buf);
  close(s); return 0;
}
```

---

## 11. Open work

**Status as of this commit.** The implementation in `src/vnet/` closes more of
this list than the text below originally implied, and three items are closed in
a way the text does not describe. The table says which is which, so the list can
be read against the code rather than against a memory of it.

| item | state | where |
| --- | --- | --- |
| per-fd logical address table for `accept`, `dup`, `fcntl`, `close` | **closed** | `struct virt_fd` in `shim/cfrsnet.c` records family, local and peer addresses, and the TCP options; `fd_copy` covers `dup`, `dup2`, `dup3` and `fcntl(F_DUPFD*)` |
| `sendto`/`recvfrom`/`sendmsg`/`recvmsg` translation | **closed** | all four are interposed and translated to abstract names; `recvmmsg` is not |
| `TCP_NODELAY` and other `IPPROTO_TCP` options recorded | **closed in the shim, not yet plumbed to smoltcp** | `setsockopt`/`getsockopt` record `TCP_NODELAY` and `TCP_KEEPIDLE` per fd; the stack applies nagle from its own `TcpStream::set_nodelay` |
| control protocol: register/unregister and datagrams | **codec only** | `src/vnet/control.rs` encodes and decodes every op, and `ControlDecoder` resynchronises past a bad frame. There is no server: nothing binds `\0cfrsnet/ctl`, so switch mode is not wired end to end |
| `TunnelDevice` framing and MTU negotiation | **partly** | `framing.rs` frames packets; `device.rs` exposes a tunnel device whose queues an external pump moves bytes through. No pump ships, and the MTU is floored at 1280 rather than negotiated |
| UDP sockets and a datagram control op | **closed** | `NetStack::bind_udp`, `UdpSocket::send_to`/`recv_from`, and the `Datagram` control op |
| IPv6: prefixes, `sin6_scope_id`, RFC 5952 in the abstract name | **closed** | `addr.rs` hand-rolls RFC 5952 so the bytes in a socket name are pinned by tests and cannot drift with a Rust release; `scope_id` round-trips |
| a real monotonic clock | **closed** | `Clock` is backed by `std::time::Instant`; the reactor parks on the device's waker or the interface's next deadline rather than spinning |
| `Device::wait` implemented on the stack's device | **not done** | the reactor has its own `select!` arm, so the stack does block, but `LinkDevice` does not implement smoltcp's `wait` and another `Device` consumer would get the default |
| interposition for statically linked programs | **not done** | `cfrs net proxy` is the supported path for a program that cannot be preloaded, and the README says so |

Three items were closed differently from what this document described, and the
difference matters:

1. **§9.3's independent confirmation.** The document asks for a `ptrace` or
   seccomp observer. `tests/af_inet_kernel.rs` instead uses the socket **inode**:
   `/proc/self/fd/N` is a symlink to `socket:[INODE]` and the kernel files each
   socket under its own protocol table, which the shim interposes neither of.
   The reason `getsockname` cannot be used is that the shim interposes *it*, so a
   probe built on it would measure the shim's bookkeeping. That was tried first
   and it answered `inet`, which is the shim's record rather than the kernel's.
2. **`getsockname` and `getpeername` truncate.** §4.2 implies a fixed-size copy.
   Linux writes at most `*len` bytes, reports the address's true length, and
   succeeds; `getsockname(fd, NULL, &len)` is a supported way to ask for the
   length. The shim now does that, because a program that sizes its buffer that
   way is common and the previous behaviour segfaulted it.
3. **`FrameDecoder` cannot resynchronise past a zero-length frame.** A length
   prefix cannot distinguish "zero-length packet" from "the first half of the
   next frame", so a zero length is reported and the caller drops the connection
   deliberately. The control decoder, whose opcode field *is* enough to find a
   frame boundary, does resynchronise.

### Still open, and honestly so

- The single-waker slot in `PacketQueue` means a caller that parks on
  `recv()` while the reactor parks on `wait()` overwrites the other's
  registration. `recv_or` exists for the two-waiter case; nothing enforces its
  use.
- `LinkDevice`'s queues are unbounded, so §8's "packet loss on the tunnel" is
  avoided by buffering rather than by dropping, which is the same problem at a
  different scale.
- `LinkDevice::new` floors the MTU at 1280, so §8's "set `max_transmission_unit`
  to the link's maximum" cannot be followed by a caller that asks for less.
- A `ptrace`-based loader for statically linked programs, or an explicit
  statement that the proxy mode is the only path for them.
- The control server, which is what would make §6.3's switch mode real rather
  than a codec with no endpoint.

---

## 12. A tailnet as the tunnel, unpatched

§5.4 says the tunnel may be any reliable, ordered byte stream, and §7.2
sketches "a process-level VPN" where the far side is another machine. One such
transport already exists and needs no rendezvous of our own: Tailscale's
userspace netstack. `tailscaled --tun=userspace-networking` runs the stack in
process — no TUN, no `CAP_NET_ADMIN`, no `AF_INET` bind — and its local API
(`POST /localapi/v0/dial`, the `ts-dial` upgrade) dials a tailnet address and
hands back the byte stream.

`cfrs net tailscale` is that bridge: an `AF_UNIX` SOCKS5 / HTTP `CONNECT`
front door that dials through the daemon's local API, and `shim/cfrssocks.c`
redirects an unmodified program's `connect(2)` to it for `100.64.0.0/10` and
`fd7a:115c:a1e0::/48` only. Nothing patches Tailscale. It is the same shape as
this document's §4 interposition, with the daemon's netstack in place of the
one in §5, and it exists because a host can permit `AF_UNIX` and forbid the
`AF_INET` listener the daemon's own `--socks5-server` would use. The
measurements and the limits are in [`TAILSCALE.md`](./TAILSCALE.md).
