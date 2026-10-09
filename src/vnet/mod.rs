//! A userspace virtual network for sealed sandboxes.
//!
//! This module implements the design in `VIRTUAL-NETWORK.md`: a private
//! IPv4/IPv6 address space that exists without a network namespace, without a
//! TUN/TAP device, and without `CAP_NET_ADMIN`. Two layers compose:
//!
//! 1. **Socket interposition** ([`shim`]) — an `LD_PRELOAD` library that
//!    rewrites a program's `AF_INET`/`AF_INET6` sockets to `AF_UNIX` abstract
//!    sockets, encoding the intended `IP:port` in the socket name
//!    ([`addr`]). The kernel only ever sees `AF_UNIX`.
//! 2. **A userspace IP stack** ([`stack`]) — a `smoltcp` interface whose link
//!    layer is an in-process packet queue ([`device`]) or a tunnel. It owns
//!    the addresses, the TCP and UDP state machines, and the routing.
//!
//! Either layer works alone: two interposed programs on the same host talk
//! over abstract names with no stack, and the stack gives an addressed
//! network that reaches a remote peer. Together they give addressed, routed,
//! unmodified programs.
//!
//! # Layers
//!
//! * [`addr`] — `cfrsnet/<family>/<address>/<port>` names and the `10.66.0.0/24`
//!   / `fd00:66::/64` plan.
//! * [`framing`] — length-prefixed packet framing over a byte stream.
//! * [`device`] — in-process link devices: queue, tunnel-backed, capture,
//!   fault injection and record/replay.
//! * [`stack`] — the `smoltcp` interface, listeners, connectors, UDP, and a
//!   monotonic poll loop.
//! * [`policy`] — per-address allow/deny, evaluated at connect time.
//! * [`dns`] — a virtual resolver at the gateway for names in the network.
//! * [`socks`] — SOCKS5 and HTTP `CONNECT` for programs that cannot be
//!   interposed.
//! * [`control`] — the shim/stack control protocol.
//! * [`shim`] — build and locate the `LD_PRELOAD` library.
//!
//! The CLI exposes it as `cfrs net`; see [`crate::main`]'s `net` command.

pub mod addr;
pub mod control;
pub mod device;
pub mod dns;
pub mod doctor;
pub mod framing;
pub mod policy;
pub mod proxy;
pub mod record;
pub mod shim;
pub mod socks;
pub mod stack;
pub mod tailscale;
pub mod tailscale_ssh;
pub mod upstream;

pub use addr::{Family, VirtAddr, VirtualSubnet};
pub use control::{ControlMessage, ControlOp};
pub use device::{DeviceStats, LinkDevice, TunnelDevice};
pub use policy::{Acl, AclAction, AclRule};
pub use proxy::{handle_connection, ProxyListen};
pub use record::{PcapFile, RecordedPacket, Recorder, Replayer};
pub use stack::{Clock, NetStack, StackConfig, StackEvent, TcpStream, UdpSocket};
pub use tailscale::{Dialer, TailscaleProxy};
pub use upstream::{Proxy, ProxyKind, Rule, Upstream};
pub use tailscale_ssh::{LocalUser, Shims};
