# Tailscale in a sealed sandbox, unpatched

`tailscaled` already does most of the hard work for a sealed host. Run it with
`--tun=userspace-networking` and it brings up a WireGuard endpoint and a full
TCP/IP stack **inside the process**: there is no TUN device, no
`CAP_NET_ADMIN`, no network namespace, and no `AF_INET` bind that the kernel
has to grant. It reaches the control plane on 443, joins the tailnet, and
carries peer traffic over the netstack.

The remaining problem is reaching *that* netstack from a program on the same
host. The daemon's own answer, `--socks5-server=127.0.0.1:1055`, is an
`AF_INET` TCP listener, and the host this was built in does not let a program
connect to it (see the measurements below). `tailscaled` is a static Go
binary, so `LD_PRELOAD` cannot interpose it, and patching the daemon is off the
table.

This document describes the bridge `cfrs net tailscale` uses instead, and
records the measurements that forced each choice. **Nothing here patches,
recompiles or re-links Tailscale.** It uses the daemon's own local API and its
own userspace dialer.

## The shape

```
  program                 cfrs net tailscale              tailscaled
 ┌──────────┐   AF_UNIX   ┌──────────────┐   AF_UNIX    ┌────────────┐
 │ curl     │────────────►│ SOCKS5 /     │─────────────►│ LocalAPI   │
 │ (shim)   │  SOCKS5     │ HTTP CONNECT │  ts-dial     │ /dial      │
 └──────────┘             └──────────────┘              └─────┬──────┘
                                                               │ netstack
                                                               ▼
                                                          the tailnet
```

- `cfrs net tailscale` listens on an `AF_UNIX` socket (the host permits
  `AF_UNIX` binds even when it denies every `AF_INET` bind) and speaks SOCKS5
  and HTTP `CONNECT`.
- For each request it opens the daemon's `LocalAPI` unix socket, sends a
  `POST /localapi/v0/dial` with the `Upgrade: ts-dial` handshake, and splices
  the two byte streams. The daemon runs the same `UserDial` path the built-in
  SOCKS5 server uses.
- `cfrs net socksify` builds an `LD_PRELOAD` shim (`shim/cfrssocks.c`) that
  rewrites an unmodified program's `connect(2)` to that front door, for
  Tailscale addresses only.

## Usage

```sh
# 1. the daemon, unmodified, userspace networking. No --socks5-server needed.
tailscaled --tun=userspace-networking \
           --state /var/lib/tailscale/tailscaled.state \
           --socket /run/tailscale/tailscaled.sock

# 2. the front door.
cfrs net tailscale --socket /run/tailscale/tailscaled.sock \
                   --listen unix:/run/cfrssocks.sock

# 3a. programs that honour ALL_PROXY
ALL_PROXY=socks5h:///run/cfrssocks.sock curl http://100.x.y.z:8080/

# 3b. or any program, with the shim
eval "$(cfrs net socksify --proxy /run/cfrssocks.sock)"
curl http://100.x.y.z:8080/
```

The shim routes only `100.64.0.0/10` and `fd7a:115c:a1e0::/48`
(`CFRSSOCKS_ALL=1` routes everything). Every other `connect(2)` reaches the
real libc untouched, so a local service and an ordinary HTTPS request keep
working.

## Measurements (sandbox it was built in, 2026-10-09)

The host is a `bailey` sandbox (Landlock ABI 10, seccomp filter mode 2,
`NoNewPrivs: 1`, `CapEff = 0`).

| Probe | Result |
|---|---|
| `bind(AF_INET, SOCK_STREAM)` 127.0.0.1:0 or any fixed port | `EACCES` |
| `bind(AF_INET, SOCK_DGRAM)` | OK |
| `bind(AF_UNIX, /path)` and `\0abstract` | OK |
| `connect(1.1.1.1:443)` | OK |
| `connect(1.1.1.1:80/53/22/8080)` | `EACCES` |
| `connect(127.0.0.1:443)` | `ECONNREFUSED` (allowed; nothing listening) |
| `connect(127.0.0.1:1055)` (a real listener) | `EACCES` |
| `unshare(CLONE_NEWUSER)` / `_NEWNET` | `EPERM` |
| `/dev/net/tun` | absent |

The port-dependence is the signature of **Landlock network rules**, which
handle TCP bind and connect by port and do not cover UDP or `AF_UNIX`. The
connect allowlist here is exactly port 443; the bind allowlist is empty. That
is why the built-in SOCKS5 listener is unreachable even though the daemon
started it.

`tailscaled` 1.104.1 (`--tun=userspace-networking`) joins the tailnet in this
host: `netcheck` reports UDP true and a DERP nearest-DC, and `tailscale ping`
gets a pong from a peer. The daemon itself is subject to the same host. In
particular the peer API it binds is an `AF_INET` listener and a probe from the
same shell cannot connect to it. The bridge does not depend on any of the
daemon's TCP listeners; it uses the daemon's unix socket only.

## What is proven

- `cargo test --lib --tests` exercises `vnet::tailscale` (the `ts-dial`
  handshake against a fake daemon, and a SOCKS5 client spliced through the
  bridge) and `tests/shim_socks.rs` (a compiled C program's `AF_INET` connect
  reaching an echo through the front door, with `getpeername` reporting the
  logical address).
- Live, against the real tailnet: with no `--socks5-server` on the daemon, a
  `curl` under `LD_PRELOAD=libcfrssocks.so` reached the sandbox's own peer API
  at `100.119.211.25:39387` and a peer's at `100.82.22.3:51105`, each `200`.
  Substituting the *other* node's port for each (`100.119.211.25:51105`,
  `100.82.22.3:39387`) returned no code, which shows the front door reaches
  the node and port asked for and not a loopback. A control request to
  `https://controlplane.tailscale.com` bypassed the shim entirely (`302`), with
  an empty redirect log.

The tarball is the stock release, not a build from this tree:

```
sha256(tailscale_1.104.1_amd64.tgz)          = 108d1d96ecf410d305571e173516f27038f870919a9b89c914a167c6d33a4528
sha256(tailscale_1.104.1_amd64/tailscaled)   = 8b16e5cb5c480f58ae6325d036e7b7a2362e8df07fb9cfbf31d16e2b6c7df76c
version: 1.104.1-t7f4efe814-g8da26756c (go1.27.1)
```

## Limits

- **No UDP.** SOCKS5 `UDP ASSOCIATE` is not implemented and the `ts-dial`
  protocol is used in its TCP form. Tailscale's own UDP-over-netstack features
  are unaffected; a program that speaks UDP to a peer cannot use this front
  door yet.
- **Names need a resolver.** The proxy accepts `ATYP=DOMAINNAME`, so a SOCKS5h
  client (`curl --socks5-hostname`) can ask for a MagicDNS name and the daemon
  resolves it. The shim sees an already-resolved address at `connect(2)` time
  and does not interpose `getaddrinfo`, so it routes names only through a
  `hosts` entry or a program that resolves them itself.
- **`Dial-Self` goes direct.** For an address not on the tailnet, the daemon
  answers `Dial-Self` with the resolved address, and the proxy dials it
  directly. That inherits the host's connect allowlist, so on this host only
  port 443 works that way. The daemon deliberately refuses to open non-tailnet
  connections on the caller's behalf, and this respects that.
- **The descriptor changes family.** After the handshake the shim `dup2`s an
  `AF_UNIX` socket over the original descriptor number, so `getsockname`
  reports `0.0.0.0:0` and TCP-level `setsockopt` is swallowed. A program that
  needs the real local port of its outbound connection (active FTP, some
  protocol negotiators) will not get it.

## Tailscale SSH in a passwd-less sandbox

`tailscaled --ssh` serves an SSH server from inside the same userspace
netstack. That is the natural way *into* a sealed host over the tailnet, and it
does not need the front door above. It does need a local login to serve, and
the host this was built in has no `/etc/passwd`, no `/etc/group`, and an
`/etc` that Landlock keeps read-only. The first attempt ends the session with
`No user exists for uid 966`.

`tailscaled` is a static Go binary, so `LD_PRELOAD` cannot interpose it, and it
does not call libc for this anyway. Reading its `osuser` package shows exactly
three things it does:

| call | source | fallback |
|---|---|---|
| `getent passwd [--] <name\|uid>` | `util/osuser/user.go` | `os/user` (reads `/etc/passwd`) |
| `id -Gz <name>` | `util/osuser/group_ids.go` | `user.GroupIds()` (reads `/etc/group`) |
| `/etc/group` | only if `id` failed | — |

Two helper commands first on the daemon's `PATH` answer the first two, and the
third is never reached. `cfrs net ts-shims` writes them, plus an `LD_PRELOAD`
table (`shim/fakepwd.c`) for a *dynamic* client on the same host, which still
calls `getpwuid(3)`:

```sh
cfrs net ts-shims --out /run/cfrs-ts-shims --user nemo
```

```
cfrs: shims    /run/cfrs-ts-shims
cfrs: user     nemo uid=966 gid=965
cfrs: passwd   /run/cfrs-ts-shims/passwd
cfrs: fakepwd  /run/cfrs-ts-shims/fakepwd.so
cfrs: daemon   PATH=/run/cfrs-ts-shims:$PATH tailscaled ... --statedir /run/cfrs-ts-shims
```

Two things are easy to miss:

- **`--statedir`.** Without a writable one the daemon logs `unable to get SSH
  host keys, SSH will appear as disabled for this node`, never advertises an
  SSH endpoint, and the client hangs. It is what makes the host keys in
  `HostInfo` possible.
- **The login must be the daemon's own uid.** An unprivileged daemon cannot
  `setuid(0)`; upstream `ssh/tailssh/incubator.go` calls
  `syscall.Setuid(wantUid)` and fatals on `EPERM`. `root@` fails however the
  user table is written. Log in as the daemon's user.

### What is proven

With the stock 1.104.1 daemon, `--tun=userspace-networking --ssh`, the
generated shims first on `PATH`, and a writable `--statedir`:

- `HostInfo` advertises `sshHostKeys` (`ssh-rsa`, `ecdsa-sha2-nistp256`,
  `ssh-ed25519`) and a `tcp:22` service, and the `unable to get SSH host keys`
  warning is gone.
- A connection to `nemo@100.119.211.25:22` is accepted by the server
  (`handling conn: ...->nemo@...:22`) and passes user and group resolution.
- It then stops at Tailscale's own **check-mode** ACL and prints
  `# Tailscale SSH requires an additional check. To authenticate, visit:
  https://login.tailscale.com/a/...`. That is the tailnet's SSH policy, not the
  sandbox: the daemon receives it from the coordination server, and a `check`
  rule asks for a browser approval. The policy in this tailnet has two rules
  with identical principals and `sshUsers` (`{"*": "=", "0": "", "root":
  "root"}`), the first `holdAndDelegate`, so the first always wins. Approve the
  URL once, or change the ACL's `ssh` action to `accept`.
- A control connection with the shims removed fails earlier, at
  `failed to look up local user's group IDs: open /etc/group: no such file or
  directory`, which is the fallback this avoids.

The daemon and the release tarball are the same stock binaries recorded above.
The only things added are scripts the daemon itself invokes and an
`LD_PRELOAD` library for the client; Tailscale is not patched, recompiled or
re-linked.

## A real shell: no `/dev/ptmx`, so the pty is userspace

The SSH server above is the way into a sealed host, but it cannot run an
interactive shell. The daemon that serves it is static Go, so its
`pty.Open()` cannot be interposed, and there is no kernel pty to give it:

| probe | result |
|---|---|
| `posix_openpt(O_RDWR)` | `ENOENT` (`/dev/ptmx` absent) |
| write a node in `/dev` | `EACCES` |
| `mknod /dev/ptmx c 5 2` | `EPERM` (no `CAP_MKNOD`) |
| `pty.openpty()` in Python | `OSError: out of pty devices` |

When the client asks for a pty, Tailscale's server calls `startWithPTY` and
returns its error: it *fails* the session. OpenSSH's `sshd` does the opposite —
it logs `openpty: No such file or directory`, refuses the pty and **carries on
over pipes** — which is the seam everything else hangs from.

### The shape

```
client ──tailnet──► tailscaled ──serve --tcp──► unix:/run/sshd.sock
                                                      │
                                              shim/unixsockd.c
                                                      │ accept, fork
                                              sshd -i  (dynamic, fakepwd)
                                                      │ refuses pty, pipes
                                              loginshell = faketty errandsh
                                                      │ fakepty.so
                                              a userspace terminal
```

- **`tailscale serve --tcp 2222 unix:/run/sshd.sock`** is stock Tailscale. It
  accepts on the tailnet and dials the daemon's own netstack to a unix socket,
  which the host permits.
- **`shim/unixsockd.c`** is the listener OpenSSH lacks: OpenSSH will not bind a
  unix socket, so this accepts and hands each connection to `sshd -i` on
  stdin/stdout. stderr goes to a log file, not the connection, or `sshd -e`
  corrupts the stream (`Bad packet length`).
- **`sshd` is dynamic**, so `fakepwd.so` resolves the login and `loginshell`
  runs. It is the same `fakepwd` the rest of this document uses; the daemon
  itself is still untouched.
- **`loginshell`** exports `SANDHOME_FAKEPTY` and execs `faketty errandsh`.
  `fakepty.so` is a userspace pty: it interposes `isatty`, `tcgetattr`,
  `tcsetattr` and the window-size `ioctl` for the session's own descriptors,
  and maps `/dev/tty` onto them. `errandsh` is sandhome's POSIX-sh line
  discipline: echo, a prompt with the last exit code, history, editing, tab
  completion and full-screen programs.

`tools/ts-sshd.sh` assembles all of it, fetching errandsh/faketty/fakepty from
sandhome at a pinned commit with sha256 checks:

```sh
cfrs net ts-shims --out /run/cfrs-ts-shims --user nemo
tools/ts-sshd.sh --shims /run/cfrs-ts-shims --port 2222 --serve
# put your public key in /run/cfrs-ts-shims/sshd/authorized_keys, then:
ssh -p 2222 root@<this-node>
```

### Two gates worth naming

- **`serve` for a unix socket needs root or a local admin.** `authorizeServeConfigForGOOSAndUserContext`
  calls `connIsLocalAdmin`, which for a non-root operator runs
  `sudo --other-user=<name> --list tailscale`; with no sudo and no `/etc/group`
  that fails. `shim/sudo` answers that one probe, and `tailscale set
  --operator=<daemon uid>` makes the daemon's own uid the operator. No
  privilege is assumed; the daemon runs as the same unprivileged user it
  already did.
- **The client must not force a pty.** With `RequestTTY auto` (the default when
  stdin is a terminal) OpenSSH warns `PTY allocation request failed` and
  continues; `force` (`ssh -tt`) treats the refusal as fatal. So the working
  client is plain `ssh -p 2222`, or `-T` for a non-interactive command.

### What is proven

With a dynamic `/usr/sbin/sshd`, the generated shims, and `tailscale serve
--tcp 2222 unix:/run/sshd.sock`:

- `ssh -p 2222 root@100.119.211.25 -- 'echo FINAL_OK; id; tty; echo TERM=$TERM'`
  returns `FINAL_OK`, `uid=966 gid=965 groups=965`, `/dev/tty`, and
  `TERM=xterm-256color`.
- Piping commands to an interactive session runs them through the errandsh
  prompt and returns their output, which shows the line discipline is live.
- `sshd -e` logs `Accepted publickey for root` and
  `session_pty_req: session 0 alloc failed` — the refusal is real, and the
  session continues anyway.

### Limits

- **`ssh -tt` aborts.** The server cannot allocate a pty, so a client that
  insists on one is refused. Use the default (`auto`) or `-T`.
- **The pty is userspace.** A statically linked full-screen program cannot be
  interposed and will not see a terminal; dynamic ones work.
- **Key auth is required.** This is a second SSH server; it does not inherit
  Tailscale's identity authentication. The client's public key goes in
  `authorized_keys`.
