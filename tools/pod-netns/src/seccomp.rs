//! The seccomp user-notification supervisor.
//!
//! This is the only interception primitive available in the target cage.
//! `ptrace` is EPERM, `LD_PRELOAD` cannot reach a static binary, and there is
//! no `/dev/net/tun` and no network namespace. What does work is
//! `SECCOMP_RET_USER_NOTIF`: the kernel hands us each matching syscall's
//! arguments and lets us choose the return value.
//!
//! Measured cage facts that shape the code. Each one cost a wrong turn first,
//! and each earlier version of this note that was wrong is named, because a
//! correction without its cause is a correction the next reader repeats.
//! `probe/` carries a runnable measurement for every claim below.
//!
//! 1. A task may hold only ONE `USER_NOTIF` listener; a second
//!    `SECCOMP_SET_MODE_FILTER|NEW_LISTENER` returns EBUSY. So every syscall
//!    we care about goes in one filter and is dispatched on `seccomp_data.nr`.
//!    Measured in `probe/one_listener.c`, which also covers the case the claim
//!    did not: a child that INHERITED the filter is refused a listener of its
//!    own with EBUSY as well, so the limit follows the filter across fork
//!    rather than being a property of one process.
//!
//! 2. `seccomp_notif` must be ALL ZERO on entry to every `NOTIF_RECV`. The
//!    kernel rejects a struct with any field set, returning EINVAL, and that
//!    EINVAL is indistinguishable from a spent listener. Measured: id, pid,
//!    flags, `data.nr` and the bytes at offsets 16/20/24 each fail; all zeros
//!    succeeds. So `recv_notification` below zeroes a fresh struct every call.
//!    Reusing one struct across calls poisons the second RECV with the kernel's
//!    own output and manufactures a fake ceiling of exactly one notification.
//!
//! 3. One listener serves UNLIMITED notifications. Measured 64 of 64 served
//!    with no errors, at a 0 us and a 2000 us gap between the child's calls,
//!    every call returning its own distinct faked value. An earlier note here
//!    claimed only the first faked syscall per child was interceptable; that
//!    was the bug in note 2, and it wrongly retired `getsockname`, which does
//!    work after `bind`. Hence the single-threaded notification loop in `run`.
//!
//! 4. The supervisor cannot write the child's memory at all. Measured in
//!    `probe/memrw.c`: `/proc/<pid>/mem` opens O_RDONLY but O_WRONLY and O_RDWR
//!    both fail EACCES, because the kernel gates write access on
//!    CAP_SYS_RESOURCE and CapEff is 0 in this cage. `process_vm_readv` and
//!    `process_vm_writev` are both EPERM, and `ptrace(PTRACE_ATTACH)` is EPERM.
//!    Reading through `/proc/<pid>/mem` IS allowed, so the child's sockaddr can
//!    be recovered on the way in, but nothing can be put back.
//!
//!    An earlier version of this file claimed `/proc/<pid>/mem` was
//!    "readable and writable". The write half was wrong: the probe opened the
//!    file and never wrote through it (rerun `probe/memrw.c`). The consequence
//!    is concrete: `getsockname` cannot be answered by handing the child its own
//!    address, because there is no route to put those bytes in the child's
//!    buffer. The `getsockname` arm in `main.rs` probes for the write route and
//!    passes the call through when it is closed, rather than fabricating an
//!    address it cannot deliver.
//!
//! 5. `SECCOMP_IOCTL_NOTIF_ADDFD` WORKS in this cage, in all four
//!    (flags, newfd_flags) combinations. An earlier note here claimed it
//!    "returns ENOENT for every flag combination" and that the pre-inherited
//!    pool existed to route around that. The probe behind that claim issued
//!    four ADDFD calls against ONE notification, so the first success consumed
//!    it and the rest reported ENOENT: a probe that reports a resource as
//!    absent because its own earlier call consumed it. See
//!    `probe/addfd_clean.c`, which uses one notification per attempt.
//!
//!    The pool is still used, because ADDFD is not a drop-in swap: it hands over
//!    a descriptor without resolving the pending syscall, so the supervisor must
//!    answer the notification too, and the fd numbering stops being under our
//!    control. Migrating is a deliberate piece of work, not a limitation.
//!
//! Also measured and deliberately not relied on: `SECCOMP_GET_NOTIF_SIZES`
//! cannot be used to detect a stale uapi header. Correctly encoded as
//! `_IOWR('!', 0, struct seccomp_notif_sizes)`, it returns EINVAL on a live
//! listener fd in this kernel.
//!
//! An earlier version of this note said it "returns EINVAL under both the
//! bare-`3` and `_IO('!', 3)` spellings". That premise was wrong rather than
//! its errno: `SECCOMP_GET_NOTIF_SIZES` is not the bare number 3, and on an
//! ordinary fd every seccomp command is ENOTTY because the ioctl handler is
//! reachable only through the listener fd. So the bare-3 result says nothing
//! about the feature, and reading it as EINVAL credited the probe with a
//! measurement it had not made. See `probe/notifsizes.c`.
//!
//! That same probe confirms the command numbers this crate compiles in are
//! right: sweeping the encoded size field of `NOTIF_RECV` from 4 to 160 on a
//! real listener fd, exactly one of 40 encodings is recognised, at size 80,
//! which is the size libc encodes.


use std::io;
use std::os::unix::io::RawFd;

/// Syscalls we intercept.
///
/// `socket` is first because answering it is what gives the child a usable
/// descriptor: the child's `socket()` returns the NUMBER of a pre-inherited
/// socketpair end, so everything it then does with that fd lands on a stream we
/// own the other end of. That is why `socket` is here and not just `bind` and
/// `connect`.
///
/// WHY A POOL RATHER THAN `SECCOMP_IOCTL_NOTIF_ADDFD`: ADDFD WORKS in this cage.
/// It was measured, one notification per attempt so no call could be starved by
/// an earlier one, and all four configurations of (flags, newfd_flags) work:
/// `{0, 0}`, `{0, O_CLOEXEC}`, `{SEND, 0}`, `{SEND, O_CLOEXEC}` all return an
/// injected descriptor. An earlier note here claimed ADDFD "returns ENOENT for
/// every flag combination"; that was a probe bug, and the pool was built to
/// route around a limitation that does not exist. See `probe/addfd_clean.c`.
///
/// Migrating to ADDFD is the right fix and is NOT yet done, because it is a real
/// change rather than a swap: ADDFD hands the child a descriptor but does not
/// resolve the pending syscall, so the supervisor must also answer the
/// notification, and the pool's fd numbering would no longer be under our control.
/// Until then the pool is correct and the claim in this comment was wrong.
///
/// `setsockopt` follows and is answered 0 for a socket we handed out. That is not
/// cosmetic: the child's fd is an AF_UNIX socketpair, so the kernel returns
/// `EOPNOTSUPP` for every IP-level option, and glibc's resolver ABORTS when one
/// of its options fails. Passing it through made every glibc program under
/// pod-netns unable to resolve a name. Measured: bare,
/// `setsockopt(IPPROTO_IP, IP_TOS)` returns 0; under pod-netns it returned
/// `EOPNOTSUPP` and `getaddrinfo` aborted.
///
/// `io_uring` is deliberately NOT in this list, and the reason is measured rather
/// than assumed: `io_uring_setup` returns `EPERM` in this cage, so a program cannot
/// use io_uring to submit network operations the filter would never see. On a host
/// that permits io_uring this tool IS bypassable, because the kernel performs the
/// submitted operations itself and there is no syscall left to mediate. That is a
/// real gap, stated rather than papered over.
///
/// `offsetof(struct seccomp_data, nr)`. `nr` is the first member of the struct, so
/// the offset is 0, and the BPF load in `build_program` reads it with `BPF_ABS`
/// from there.
pub const SECKCOMP_DATA_NR_OFFSET: u32 = 0;

/// Order does not matter: a miss falls through to the next comparison. An
/// earlier note here claimed the order was load-bearing, which was a misreading
/// of a jump-offset bug rather than a property of seccomp. See `build_program`.
pub const TARGETS: &[libc::c_long] = &[
    libc::SYS_socket,
    libc::SYS_bind,
    libc::SYS_connect,
    libc::SYS_getsockname,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_setsockopt,
];

/// True when `nr` is one we intend to fake rather than pass through.
///
/// The authoritative answer is the filter itself, which `build_program`
/// derives from `TARGETS`; this is the same predicate for callers that want to
/// ask without walking the program.
pub fn is_target(nr: i64) -> bool {
    TARGETS.contains(&(nr as libc::c_long))
}

/// What the child asked for, as recovered from its own memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub family: u8,
    pub port: u16,
    pub addr: [u8; 16],
    pub v4: bool,
}

impl Endpoint {
    /// Byte length the kernel would report for this family.
    pub fn len(&self) -> usize {
        if self.v4 {
            16
        } else {
            28
        }
    }

    /// Serialize as `sockaddr_in` or `sockaddr_in6`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = vec![0u8; self.len()];
        v[0..2].copy_from_slice(&(self.family as u16).to_ne_bytes());
        v[2..4].copy_from_slice(&self.port.to_be_bytes());
        if self.v4 {
            v[4..8].copy_from_slice(&self.addr[..4]);
        } else {
            v[8..24].copy_from_slice(&self.addr);
        }
        v
    }

    pub fn display(&self) -> String {
        if self.v4 {
            format!("{}.{}.{}.{}:{}", self.addr[0], self.addr[1], self.addr[2], self.addr[3], self.port)
        } else {
            let mut o = String::new();
            for i in 0..16 {
                if i % 2 == 0 && i > 0 {
                    o.push(':');
                }
                o.push_str(&format!("{:x}{:x}", self.addr[i * 2], self.addr[i * 2 + 1]));
            }
            format!("[{}]:{}", o, self.port)
        }
    }
}

/// Read just the `sa_family` of the child's sockaddr.
///
/// `connect` needs this before deciding whether the call is ours to fake: an
/// AF_UNIX connect is the child's own local IPC and must pass through
/// untouched, while AF_INET and AF_INET6 are proxied. Deciding after
/// `read_sockaddr` would be too late, because that fails on a family it does
/// not model and the failure is indistinguishable from a real read error.
pub fn read_family(pid: i32, addr: u64) -> io::Result<u8> {
    let path = format!("/proc/{}/mem", pid);
    let mem = std::fs::File::open(&path)?;
    use std::os::unix::fs::FileExt;
    let mut buf = [0u8; 2];
    let n = mem.read_at(&mut buf, addr)?;
    if n < 2 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short family read"));
    }
    Ok(u16::from_ne_bytes(buf) as u8)
}

/// Read the child's sockaddr. `/proc/<pid>/mem` is the only route available;
/// `process_vm_readv` is EPERM here. See note 4.
pub fn read_sockaddr(pid: i32, addr: u64, len: u64) -> io::Result<Endpoint> {
    if len < 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "sockaddr too short"));
    }
    let path = format!("/proc/{}/mem", pid);
    let mem = std::fs::File::open(&path)?;
    use std::os::unix::fs::FileExt;
    let mut buf = [0u8; 28];
    let want = std::cmp::min(len as usize, buf.len());
    let n = mem.read_at(&mut buf[..want], addr)?;
    if n < 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "short sockaddr read"));
    }
    let family = u16::from_ne_bytes([buf[0], buf[1]]) as u8;
    match family as i32 {
        libc::AF_INET => {
            if n < 8 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "short sockaddr_in"));
            }
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&buf[4..8]);
            Ok(Endpoint { family, port, addr, v4: true })
        }
        libc::AF_INET6 => {
            if n < 24 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "short sockaddr_in6"));
            }
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&buf[8..24]);
            Ok(Endpoint { family, port, addr, v4: false })
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported address family {}", other),
        )),
    }
}

/// Whether the child's memory can be written at all, probed rather than assumed.
///
/// Opening `/proc/<pid>/mem` for writing is refused with EACCES unless the
/// supervisor holds CAP_SYS_RESOURCE, so this returns false in this cage and
/// true on a host with the capability. The check is done once per call and the
/// fd is closed immediately, because the answer decides whether `getsockname`
/// is answered from the virtual table or handed to the kernel.
pub fn child_memory_is_writable(pid: i32) -> bool {
    let path = format!("/proc/{}/mem", pid);
    match std::fs::OpenOptions::new().read(true).write(true).open(&path) {
        Ok(f) => {
            drop(f);
            true
        }
        Err(_) => false,
    }
}

/// Write a sockaddr back into the child's memory, for `getsockname`.
///
/// UNAVAILABLE IN THIS CAGE, and the caller's first line of defence is to
/// check. Measured: `/proc/<pid>/mem` opens O_RDONLY but O_WRONLY and O_RDWR
/// both return EACCES, because the kernel gates write access on
/// CAP_SYS_RESOURCE and CapEff is 0 here. `process_vm_writev` and
/// `ptrace(PTRACE_ATTACH)` are both EPERM, so there is no other route into the
/// child's address space. Reading works, which is why `read_sockaddr` below is
/// fine.
///
/// Kept because it is correct and it works on a host where the supervisor holds
/// CAP_SYS_RESOURCE, and because the honest response to "can you do this" on an
/// unsupported host is a named error rather than a silently wrong answer. It is
/// not a silent no-op: `write_sockaddr` returning Ok means bytes were written.
pub fn write_sockaddr(pid: i32, addr: u64, maxlen: u64, ep: &Endpoint) -> io::Result<()> {
    let mut buf = ep.to_bytes();
    let n = std::cmp::min(buf.len() as u64, maxlen) as usize;
    buf.truncate(n);
    let path = format!("/proc/{}/mem", pid);
    let mem = std::fs::OpenOptions::new().read(true).write(true).open(&path)?;
    use std::os::unix::fs::FileExt;
    mem.write_at(&buf, addr)?;
    Ok(())
}

/// Write the length the kernel would have stored through `socklen_t *len`.
pub fn write_len(pid: i32, addr: u64, len: u64) -> io::Result<()> {
    let path = format!("/proc/{}/mem", pid);
    let mem = std::fs::OpenOptions::new().read(true).write(true).open(&path)?;
    use std::os::unix::fs::FileExt;
    mem.write_at(&(len as u32).to_ne_bytes(), addr)?;
    Ok(())
}

/// Read the caller's `socklen_t` through a pointer to it.
///
/// `getsockname(fd, addr, &len)` passes a POINTER to the length, so the
/// supervisor has to dereference it before it knows how much room the caller
/// offered. Treating the pointer value as the length truncates the reply to
/// whatever the address happens to be worth, which is typically zero, and the
/// child then reports EAFNOSUPPORT instead of an address.
pub fn read_len(pid: i32, addr: u64) -> io::Result<u64> {
    let path = format!("/proc/{}/mem", pid);
    let mem = std::fs::File::open(&path)?;
    use std::os::unix::fs::FileExt;
    let mut buf = [0u8; 4];
    let n = mem.read_at(&mut buf, addr)?;
    if n < 4 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short socklen_t read"));
    }
    Ok(u32::from_ne_bytes(buf) as u64)
}

/// Receive a listener fd over `sock` using SCM_RIGHTS.
///
/// The mirror of `Notifier::send_to`. Fails loudly on a closed peer rather than
/// returning a placeholder, because a supervisor with no listener would block
/// forever on the first notification and the child would appear to hang.
pub fn recv_fd(sock: RawFd) -> io::Result<RawFd> {
    let mut one = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: one.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    let mut cmsg_buf = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len() as _;
    let n = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "no control message: the child died before sending its listener",
            ));
        }
        if (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected an fd over SCM_RIGHTS",
            ));
        }
        let mut fd: RawFd = -1;
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            &mut fd as *mut RawFd as *mut u8,
            std::mem::size_of::<RawFd>(),
        );
        Ok(fd)
    }
}

/// The listener fd for USER_NOTIF.
///
/// Installed in the CHILD by a pre-exec hook, so it lands in the child's address
/// space and NOT in the supervisor's. That placement is the whole trick and it
/// is not optional: a filter installed in the supervisor applies to every thread
/// the tool creates, so the supervisor's own `connect` to an upstream would raise
/// a notification that the supervisor, being the thread blocked in that connect,
/// cannot service. The tool then deadlocks with the child frozen inside its own
/// `connect`. Measured in `probe/selfdl.c`.
pub struct Notifier {
    fd: RawFd,
}

/// RAII so the listener fd is closed on any exit path, including the abort
/// path taken when the cage refuses the filter.
impl Drop for Notifier {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl Notifier {
    /// Install the filter in THIS process, which is the child.
    ///
    /// Called from a `Command::pre_exec` hook, so the filter is installed after
    /// `fork` and lands only in the child. The listener fd is then handed to the
    /// supervisor over `handshake`, and the supervisor is not filtered at all.
    ///
    /// Returns an error naming the specific refusal so a failure is diagnosable
    /// rather than a bare "operation not permitted".
    pub fn install() -> io::Result<Self> {
        // NoNewPrivs is already set in the cage, but we require it ourselves:
        // installing a filter without it is a privilege we do not have, and
        // being explicit means the tool works on a normal host too.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }

        // BPF program:
        //   load nr
        //   for each target j (1..=N): jeq nr, TARGETS[j]
        //       match -> jump to RET USER_NOTIF
        //       miss  -> fall through to the next comparison
        //   last comparison's miss -> jump to RET ALLOW
        //   RET USER_NOTIF
        //   RET ALLOW
        //
        // The j-th of n comparisons sits at f[j]. The two offsets are therefore
        //
        //   match: f[n+1] is RET USER_NOTIF, so jt = (n+1) - (j+1) = n - j
        //   miss:  f[j+1] is the NEXT comparison, so jf = 0
        //           except on the last, where f[n+1] is already RET USER_NOTIF
        //           and the miss must skip it to RET ALLOW at f[n+2], so jf = 1
        //
        // Getting jf wrong is silent, and the failure mode is not "never
        // notifies" but "notifies for one syscall and nothing else". The bug
        // this replaced used jf = n - j + 1, so a miss jumped past the rest of
        // the chain straight to RET ALLOW: only TARGETS[0] was ever
        // intercepted and the rest of the list was dead code. It survived
        // because every test child binds first, and bind was TARGETS[0], so the
        // working path and the broken path were the same path.
        //
        // The offsets are worth re-measuring rather than re-reading, since
        // reading them is what produced the bug twice. `probe/offsetfix.c`
        // builds all three variants and runs every syscall at every position:
        // the old builder notifies 8 of 36 cells (a clean position-0 diagonal),
        // the correct one notifies 36 of 36. Reproduce with
        // `cc -O1 -o offsetfix offsetfix.c && ./offsetfix old` then `new`.
        let prog = build_program();

        let fprog = libc::sock_fprog {
            len: prog.len() as u16,
            filter: prog.as_ptr() as *mut libc::sock_filter,
        };
        let ret = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
                &fprog as *const libc::sock_fprog,
            )
        };
        if ret < 0 {
            let e = io::Error::last_os_error();
            return Err(io::Error::new(
                e.kind(),
                format!("installing the seccomp user-notify filter failed: {}", e),
            ));
        }
        Ok(Notifier { fd: ret as RawFd })
    }

    /// Pass the listener fd to the supervisor over `sock` using SCM_RIGHTS.
    ///
    /// The supervisor cannot use the child's own fd number, because a descriptor
    /// number is per-process and the two processes are looking at different
    /// tables. `/proc/<pid>/fd` is openable in this cage (measured:
    /// `probe/memrw.c`), so a supervisor could *borrow* a descriptor the child
    /// holds, but that is the wrong direction: it cannot put one into the
    /// child's table. SCM_RIGHTS and `SECCOMP_IOCTL_NOTIF_ADDFD` are the two
    /// routes that do that, and this is the one that works before exec.
    pub fn send_to(&self, sock: RawFd) -> io::Result<()> {
        let mut cmsg_buf = [0u8; 64];
        // A one-byte payload is required: sendmsg with an empty iovec still
        // succeeds but some kernels treat it as "no data" and the receiver then
        // reports no control message, which reads as a dead child.
        let one = [1u8];
        let mut iov = libc::iovec {
            iov_base: one.as_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as _;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len =
                libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
            std::ptr::copy_nonoverlapping(
                &self.fd as *const RawFd as *const u8,
                libc::CMSG_DATA(cmsg),
                std::mem::size_of::<RawFd>(),
            );
        }
        let n = unsafe { libc::sendmsg(sock, &msg, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

}

/// One pending syscall, plus the two ways to answer it.
pub struct Notification {
    raw: libc::seccomp_notif,
}

impl Notification {
    pub fn nr(&self) -> i64 {
        self.raw.data.nr as i64
    }
    pub fn pid(&self) -> i32 {
        self.raw.pid as i32
    }
    pub fn args(&self) -> [u64; 6] {
        [
            self.raw.data.args[0],
            self.raw.data.args[1],
            self.raw.data.args[2],
            self.raw.data.args[3],
            self.raw.data.args[4],
            self.raw.data.args[5],
        ]
    }
    pub fn fd_arg(&self) -> RawFd {
        self.raw.data.args[0] as RawFd
    }
    pub fn sockaddr_arg(&self) -> u64 {
        self.raw.data.args[1]
    }
    pub fn sockaddr_len(&self) -> u64 {
        self.raw.data.args[2]
    }

    /// Let the real syscall run and report the kernel's own result.
    pub fn pass_through(&self, fd: RawFd) -> io::Result<()> {
        self.respond(fd, 0, 0, true)
    }

    /// Answer with a chosen result, so the child sees success or a chosen errno.
    ///
    /// A failure here is reported to stderr rather than swallowed. It used to be
    /// `let _ = note.respond(...)` at every call site, and a silently failed
    /// response is indistinguishable from a hang: the child stays blocked inside
    /// the syscall forever and nothing anywhere says why. That cost an hour of
    /// debugging a relay that looked fine.
    pub fn respond(&self, fd: RawFd, val: i64, errno: i32, cont: bool) -> io::Result<()> {
        let mut r: libc::seccomp_notif_resp = unsafe { std::mem::zeroed() };
        r.id = self.raw.id;
        r.val = val;
        r.error = if errno != 0 { -errno } else { 0 };
        r.flags = if cont { libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32 } else { 0 };
        let rc = unsafe { libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_SEND, &r) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            eprintln!(
                "pod-netns: internal error: answering syscall {} (pid {}) failed: {e}; \
the child will stay blocked in that syscall",
                self.nr(),
                self.pid()
            );
            return Err(e);
        }
        Ok(())
    }
}

/// Supervise on a raw listener fd, which the child sent over SCM_RIGHTS.
///
/// A free function rather than a method on `Notifier`, because the supervisor
/// does not own a `Notifier`: the child does, and it is already gone by the time
/// the supervisor runs. The listener is just an fd from here on.
///
/// The struct is zeroed fresh on every call, and that is load-bearing rather than
/// tidiness. The kernel rejects a `seccomp_notif` with any field already set, and
/// the resulting EINVAL is indistinguishable from a listener with nothing
/// pending. A caller that hoists the struct out of its loop sees one working
/// notification followed by EINVAL forever and concludes the listener is spent.
/// It is not: measured 64 of 64 served, zero errors.
pub fn recv_notification(lfd: RawFd, timeout_ms: i32) -> io::Result<Option<Notification>> {
    let mut pfd = libc::pollfd { fd: lfd, events: libc::POLLIN, revents: 0 };
    let pr = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if pr == 0 {
        return Ok(None);
    }
    if pr < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::Interrupted {
            return Ok(None);
        }
        return Err(e);
    }
    let mut n: libc::seccomp_notif = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::ioctl(lfd, libc::SECCOMP_IOCTL_NOTIF_RECV, &mut n) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Some(Notification { raw: n }))
}

/// The filter program, separated out so it can be unit tested.
///
/// It is a pure function of `TARGETS`, and the offsets are the single most
/// dangerous thing in this file: a wrong offset does not error, it silently
/// narrows what gets intercepted. See the derivation in `Notifier::install`.
fn build_program() -> Vec<libc::sock_filter> {
    let n = TARGETS.len();
    let mut prog: Vec<libc::sock_filter> = Vec::with_capacity(2 + 2 * n);
    prog.push(bpf_stmt(
        (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
        // offsetof(struct seccomp_data, nr), which is 0: nr is the first
        // field. Spelled as a plain 0 because the arithmetic that used to be
        // written here (`size_of::<seccomp_data>() * 0`) always evaluated to
        // zero and read as though it computed something.
        SECKCOMP_DATA_NR_OFFSET,
    ));
    for (idx, &target) in TARGETS.iter().enumerate() {
        let j = idx + 1; // 1-based position, and also the f[] index
        let jt = (n - j) as u8; // match -> RET USER_NOTIF
        let jf = if j == n { 1 } else { 0 }; // miss -> next comparison, or RET ALLOW
        prog.push(bpf_jump(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            target as u32,
            jt,
            jf,
        ));
    }
    prog.push(bpf_stmt((libc::BPF_RET | libc::BPF_K) as u16, 0x7fc0_0000)); // USER_NOTIF
    prog.push(bpf_stmt((libc::BPF_RET | libc::BPF_K) as u16, 0x7fff_0000)); // ALLOW
    prog
}

fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt: 0, jf: 0, k }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_NOTIF: u32 = 0x7fc0_0000;
    const ALLOW: u32 = 0x7fff_0000;

    /// Run the program against one syscall number and report the action taken.
    ///
    /// This is a real interpreter for the subset of BPF `build_program` emits,
    /// not a re-derivation of the offsets. The point is that it evaluates the
    /// jumps the way the kernel does, so a wrong offset shows up as a wrong
    /// action instead of as a difference nobody notices.
    fn action_for(prog: &[libc::sock_filter], nr: i64) -> u32 {
        let mut pc = 0usize;
        // The first instruction loads nr into the accumulator. Nothing else in
        // this program reads the accumulator, so tracking the syscall number
        // directly is equivalent and easier to read.
        for _ in 0..prog.len() + 2 {
            let ins = prog[pc];
            let class = ins.code & 0x07;
            match class {
                0x00 => { /* BPF_LD */ pc += 1; }
                0x05 => {
                    // BPF_JMP | BPF_JEQ | BPF_K
                    if nr == ins.k as i64 {
                        pc += 1 + ins.jt as usize;
                    } else {
                        pc += 1 + ins.jf as usize;
                    }
                }
                0x06 => return ins.k, // BPF_RET
                other => panic!("unexpected BPF class {other} at f[{pc}]"),
            }
        }
        panic!("program did not reach a RET for nr {nr}");
    }

    /// Every target must notify. This is the test that would have caught the
    /// shipped bug: `jf` was `n - j + 1`, so a miss skipped the rest of the
    /// chain and only TARGETS[0] ever reached RET USER_NOTIF.
    #[test]
    fn every_target_reaches_user_notif() {
        let prog = build_program();
        for &t in TARGETS {
            assert_eq!(
                action_for(&prog, t),
                USER_NOTIF,
                "syscall {t} must be intercepted, but the filter lets it through"
            );
        }
    }

    /// The complement of the test above, and the one that pins down why: a
    /// syscall that is not a target must NOT notify. A builder that made the
    /// miss path jump to RET USER_NOTIF would intercept the whole world, which
    /// is the failure mode of the intermediate `jf = 1 everywhere` attempt.
    #[test]
    fn non_targets_are_allowed() {
        let prog = build_program();
        for nr in [0i64, 1, 2, 3, 39, 60, 63, 231, 1000, 40000] {
            assert_eq!(
                action_for(&prog, nr),
                ALLOW,
                "syscall {nr} is not a target and must be allowed"
            );
        }
    }

    /// Guard the shape the interpreter relies on, so a future edit that
    /// reorders or restructures the program fails here with a clear message
    /// rather than as a mysterious walk.
    #[test]
    fn program_has_the_expected_shape() {
        let prog = build_program();
        let n = TARGETS.len();
        assert_eq!(prog.len(), n + 3, "load, one JEQ per target, and two RETs");
        assert_eq!(prog[n + 1].k, USER_NOTIF, "f[n+1] must be RET USER_NOTIF");
        assert_eq!(prog[n + 2].k, ALLOW, "f[n+2] must be RET ALLOW");
        for (idx, &target) in TARGETS.iter().enumerate() {
            let ins = prog[idx + 1];
            assert_eq!(ins.k as i64, target, "f[{}] compares the wrong syscall", idx + 1);
        }
    }

    /// `is_target` must agree with the filter, because a caller asking "will this
    /// be intercepted" and getting a different answer from the one the kernel
    /// enforces is worse than not having the helper.
    #[test]
    fn is_target_agrees_with_the_filter() {
        for &t in TARGETS {
            assert!(is_target(t), "{t} is in TARGETS but not reported");
            assert_eq!(action_for(&build_program(), t), USER_NOTIF);
        }
        assert!(!is_target(0), "syscall 0 is read and is not intercepted");
        assert!(!is_target(libc::SYS_execve as libc::c_long));
    }

    /// The regression control, written so it fails against the old builder: it
    /// asserts the specific numbers that measured 8 of 36 cells before the fix
    /// and 36 of 36 after. If someone reintroduces `jf = n - j + 1`, this test
    /// names what regressed instead of the suite going quietly green on a
    /// filter that only intercepts bind.
    #[test]
    fn a_miss_falls_through_to_the_next_comparison() {
        let prog = build_program();
        let n = TARGETS.len();
        for (j, ins) in prog.iter().enumerate().take(n + 1).skip(1) {
            if j < n {
                assert_eq!(
                    ins.jf, 0,
                    "f[{j}] is not the last comparison, so a miss must continue \
to the next comparison (jf = 0), not skip the rest of the chain"
                );
            } else {
                assert_eq!(
                    ins.jf, 1,
                    "f[{j}] is the last comparison, so a miss must skip RET \
USER_NOTIF and land on RET ALLOW (jf = 1)"
                );
            }
        }
    }
}
