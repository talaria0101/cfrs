# `pod-netns`

Run any program — static or dynamic — in a network namespace whose only egress
is a SOCKS5 or HTTP proxy. No `LD_PRELOAD`, no shims, no interposers.

```sh
pod-netns -x socks5://127.0.0.1:1080 -- curl https://example.com
pod-netns doctor
```

A shim can only reach a dynamic binary: a static binary carries its own libc,
and a Go binary does not call libc's `connect(3)` at all. A network namespace is
enforced by the kernel, so every program is treated the same. This is the
practical use of the userspace virtual network in `cfrs::vnet`.

## Shape

```
pod-netns [opts] -- PROGRAM
  │
  ├─ child:  unshare(NEWUSER|NEWNET) → lo up → TUN eth0 → exec PROGRAM
  │
  └─ parent: smoltcp over the TUN, fake-IP DNS, SOCKS5/HTTP upstream
```

- The child makes a network namespace. `CLONE_NEWNET` alone is tried first
  (privileged); otherwise `CLONE_NEWUSER|CLONE_NEWNET`, and the **parent** writes
  the uid/gid maps — the child reports which case it hit over a socketpair and
  waits for the maps before touching the network.
- The TUN is configured with `SIOCSIFADDR`/`SIOCSIFNETMASK`/`SIOCSIFFLAGS`/
  `SIOCADDRT` ioctls rather than `ip`: RTNETLINK can fail inside a user
  namespace even when the ioctls succeed. The interface is called `eth0`, not
  `tun0`, because some software probes for `eth*` to decide it is online.
- The parent runs a `smoltcp` `Interface` over the TUN with `set_any_ip(true)`,
  so packets to **any** destination are accepted. A SYN is inspected before the
  stack consumes it, and a listen socket is created for that destination port;
  when it reaches `Established`, its `local_endpoint()` is the destination the
  guest asked for.
- UDP port 53 is answered from a fake-IP pool (`198.18.0.0/15`, the RFC 2544
  range proxychains uses). The name is kept and sent to the proxy, so DNS is
  resolved remotely and cannot leak.
- Each flow is spliced between the smoltcp socket and an upstream SOCKS5
  (`ATYP=DOMAIN` for fake IPs) or HTTP `CONNECT` connection.

## `doctor`

`pod-netns doctor` measures the host before anything is attempted and exits
`3` when no backend can run:

```
pod-netns: capability report
  unshare(CLONE_NEWNET)              no    Operation not permitted (os error 1)
  unshare(NEWUSER|NEWNET)            no    Operation not permitted (os error 1)
  open(/dev/net/tun)                 no    No such file or directory (os error 2)
  PTRACE_TRACEME (fallback backend)  no    ptrace not permitted
  seccomp(SECCOMP_RET_USER_NOTIF)    ok    listener installed
pod-netns: backend netns: unavailable
pod-netns: note: SECCOMP_RET_USER_NOTIF works, so a seccomp backend could run here
```

The last line is the important one on a sealed host: where namespaces and
ptrace are denied, `SECCOMP_RET_USER_NOTIF` can still intercept
`socket`/`connect` and hand the child a proxied descriptor with
`SECCOMP_IOCTL_NOTIF_ADDFD`. That is the planned second backend.

## The seccomp backend (works where namespaces are denied)

Where `unshare` and `/dev/net/tun` are unavailable — as in the sandbox above —
the kernel still offers `SECCOMP_RET_USER_NOTIF`. This backend intercepts
syscalls with no `LD_PRELOAD`, so a static binary is covered like any other.

```sh
pod-netns --backend seccomp -x unix:/run/socks.sock -- ./program
```

**How it works**

- A seccomp filter returns `SECCOMP_RET_USER_NOTIF` for `socket`, `connect`,
  `sendto`, `sendmsg`, `sendmmsg`, `bind`, `setsockopt`, `getsockopt`,
  `getsockname` and `getpeername`.
- On `socket(AF_INET, SOCK_STREAM)`, the supervisor creates a **socketpair**
  and installs one end in the child with `SECCOMP_IOCTL_NOTIF_ADDFD`. The child
  gets a real, connected descriptor, so `read`/`write`/`poll`/`epoll`/`close`
  all work natively — only `connect` needs answering.
- On `connect`, the supervisor reads the `sockaddr` from the child with
  `/proc/<pid>/mem`, dials the upstream proxy, replies `0`, and splices the
  socketpair with `copy_bidirectional`.
- UDP port 53 is answered from the fake-IP pool, so the proxy receives the
  **name**. glibc's resolver calls `setsockopt` before it sends; an `AF_UNIX`
  socketpair rejects that, so the supervisor answers it, or the resolver gives
  up before any packet exists.
- The child must be **blocking** unless it asked for `SOCK_NONBLOCK`: a tokio
  `pair()` is non-blocking on both ends, and `ADDFD`'s `newfd_flags` accepts
  only `O_CLOEXEC` on older kernels, so the flag is set on the shared
  description instead.

**Getting the listener fd to the supervisor without deadlock.** The filter must
be installed before the child passes the fd, but the only `SCM_RIGHTS` call is
`sendmsg`, which the filter intercepts — a self-deadlock. `/proc/<pid>/fd` is
refused for a seccomp listener, and `pidfd_getfd` needs ptrace. The answer is
that a filter is **per-thread** unless `TSYNC` is used: a helper thread installs
the filter and forks there, so the child inherits it while the fd stays in the
process's own fd table. No handshake is needed at all.

**Proven** (integration test `tests/pod_netns_seccomp.rs`): a SOCKS5 proxy on a
unix socket, and a C client built **both dynamically and statically**; each
reaches the proxy, and `getaddrinfo("example.com")` resolves to a `198.18.x.x`
fake IP with the proxy seeing `example.com:80`, not the address.

## Status

The netns backend needs a host that permits user namespaces and has
`/dev/net/tun`. The seccomp backend needs neither and runs in the sealed sandbox
(measured above); it is the default when the netns probes fail. Unit tests cover
the pure parts (proxy-spec parsing, fake-IP stability, base64, target splitting,
the SYN parser) and `tests/pod_netns_seccomp.rs` covers the whole path for both
binary kinds.

## Beyond TCP and DNS

The seccomp backend is a platform, not a one-trick. Three extensions are in and
tested; the interception point is what makes each cheap.

### UDP, not just DNS

UDP port 53 is answered locally from the fake-IP pool. Everything else on a
datagram socket is now relayed through the proxy's **`UDP ASSOCIATE`**: the
supervisor keeps the control connection, learns the relay address, wraps each
datagram in a SOCKS5 UDP header, and a reader task strips the header from the
replies and drops them into the child's socketpair. `tests/pod_netns_seccomp.rs`
proves a UDP echo round trip (`UDP:9:ECHO:PING`).

The sandbox permits UDP bind and send, so this is the one transport that was
never blocked and now works end to end.

### Chained proxies

`-x` is repeatable and the hops are **chained**: dial the first, ask each hop to
`CONNECT` to the next, and ask the last for the target. Each hop learns only the
address of the next, which is the usual multi-hop property. A unix-socket hop is
addressed as `unix:<path>` with port `0`, and the hop in front resolves it.

```sh
pod-netns --backend seccomp -x unix:/run/hop1.sock -x unix:/run/hop2.sock -- ./prog
```

The test asserts the first hop was asked for the second (`unix:…/p2.sock:0`)
and only the second saw `93.184.216.34:80`.

### Closing the `io_uring` bypass

`io_uring` submits network operations without going through the intercepted
syscalls, so a program using `IORING_OP_SOCKET`/`IORING_OP_CONNECT` would slip
past the filter entirely. `io_uring_setup` is intercepted and answered `EPERM`.
This sandbox already denies it, but the filter must not depend on that.

### Routing, inbound, and the closed bypass

**Per-destination routing.** `-r domain:NAME=PROXY` and `-r cidr:ADDR/PREFIX=PROXY`
select a single hop per destination, first match wins, and `-x` remains the
default chain. `select_chain` is one function and one call site.

```sh
pod-netns --backend seccomp -x unix:/run/default.sock \
    -r cidr:10.0.0.0/8=unix:/run/internal.sock -- ./prog
```

**Inbound.** `bind` records the requested address, `listen` creates the only
listener a sealed host can have — a unix socket at
`$--inbound-dir/<port>.sock` — and a reader task queues accepted connections;
`accept`/`accept4` draw one and install a socketpair end in the child. The
program sees a normal `bind`/`listen`/`accept` sequence. The listener is exposed
to the tailnet with stock Tailscale:

```sh
tailscale serve --bg --tcp 8080 unix:/tmp/pod-netns-inbound/8080.sock
```

**Descriptor lifetime is tracked.** `close` is intercepted so the supervisor
drops its end of an injected socketpair and the table entry when the child is
done with it, and both the descriptor table and the netns listener table are
capped, so a program that leaks or sweeps sockets cannot grow the supervisor
without bound.

**`io_uring` is denied completely, not partially.** `io_uring_setup`,
`io_uring_enter` and `io_uring_register` are all answered `EPERM`. A partial
filter would be unsound: the kernel performs the submitted network operations
itself, so there is no syscall for the filter to see. Denying the interface is
the only correct answer, and `the_filter_covers_the_bypass_surfaces` asserts it.

### The tailnet as the transport

`-x tailscale:/run/tailscale/tailscaled.sock` is not a proxy at all. The
supervisor dials the target through a running daemon's LocalAPI `ts-dial`
endpoint (`cfrs::vnet::tailscale::Dialer`), so the tailnet itself carries the
connection and there is no SOCKS front door, shim or `LD_PRELOAD` anywhere in
the path:

```sh
pod-netns --backend seccomp -x tailscale:/run/tailscale/tailscaled.sock -- ./prog
```

### Front door: an instance as a hop

`--serve unix:/path` makes an instance speak SOCKS5 and HTTP `CONNECT` and
forward each request through its own upstream chain. Instances therefore chain
with each other, and one can stand in for a shim's front door:

```sh
pod-netns --serve unix:/run/front.sock -x unix:/run/upstream.sock &
pod-netns --backend seccomp -x unix:/run/front.sock -- ./prog
```

`--serve` handles `CONNECT`, HTTP `CONNECT` and `UDP ASSOCIATE`. The UDP case
advertises a relay socket and forwards each datagram through the first upstream
proxy's own association, so a UDP relay chains through an instance the same way
a TCP one does. Request parsing reuses `cfrs::vnet::socks` and the listen spec
`cfrs::vnet::proxy::ProxyListen`, so the server side is the library's.

### Remaining host limits

**`getsockname`/`getpeername` address rewriting.** The supervisor needs
`O_RDWR` on `/proc/<pid>/mem` to write a fake `sockaddr` into the child. This
host denies it (`EACCES`; `PR_SET_DUMPABLE=1` does not change that), as it denies
`process_vm_writev` and ptrace. The code implements the write path — it works
where the host allows it — and otherwise falls through, so the kernel reports
the `AF_UNIX` peer. `pod-netns doctor` reports `write /proc/<pid>/mem` so the
limitation is visible before it matters. Programs that merely log the address
are unaffected; programs that require an `AF_INET` value from `getpeername` are
not supported on such a host.

