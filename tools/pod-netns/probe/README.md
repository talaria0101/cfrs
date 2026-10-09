# Probes

One standalone C file per measurement claimed in `../README.md` or in a module
doc. Each builds with `cc -O1 -o <name> <name>.c` and runs without arguments
unless noted.

**Why these exist as files and not as paragraphs.** Six claims this crate made
about its own cage were wrong. Four were wrong because a probe had a bug rather
than because the host disagreed, and two were wrong because the code was wrong or
because a claim was never measured at all; the records below say which is which,
because "it was a probe bug" and "nobody checked" are different failures and only
one of them is reassuring. A reader who trusts a number with no way to re-run it
will trust the next wrong number too.

Compiled binaries are not committed. Rebuilding is one command and the source is
the evidence.

| probe | claim it backs | what it shows |
| --- | --- | --- |
| `multin.c` | README §1 | `./multin q1`: every non-zero field of `seccomp_notif` gives EINVAL, all-zeros succeeds. `./multin q2 64 0`: 64 of 64 notifications served. |
| `offsetfix.c` | README §2 | `./offsetfix old`: 8 of 36 cells, a clean position-0 diagonal. `./offsetfix new`: 36 of 36. |
| `selfdl.c` | README §3 | `timeout 10 ./selfdl` exits 124: a process whose own `connect` notifies never returns from it. |
| `memrw.c` | README §4 | `/proc/<pid>/mem` is O_RDONLY only; `process_vm_readv`, `process_vm_writev` and `ptrace` are all EPERM. `/proc/<pid>/fd` opens and its entries open, which is not what three places in the crate used to claim. |
| `sockopt.c` | README §5 | `./sockopt bare`: `IP_TOS` returns 0. `./sockopt sockpair`: the same option returns `EOPNOTSUPP`, which is what aborts a glibc resolver. `./sockopt faked`: prints the answer the supervisor gives. |
| `addfd_clean.c` | "Three open items" | ADDFD works in all four (flags, newfd_flags) combinations, including `newfd_flags=0`. |
| `notifsizes.c` | `seccomp.rs` module docs | Correctly encoded `SECCOMP_GET_NOTIF_SIZES` is EINVAL on a live listener fd, so it cannot detect a stale uapi header. Sweeping the encoded size of `NOTIF_RECV` from 4 to 160: exactly 1 of 40 recognised, at size 80, which is what libc encodes. Takes about 40 seconds, one forked child per size. |
| `one_listener.c` | `seccomp.rs` note 1 | A second `NEW_LISTENER` in the same task is EBUSY, and a child that inherited the filter is refused a listener of its own, also EBUSY. |
| `s5proxy.c` | "Three open items" | A working SOCKS5 server that records the CONNECT destination. It cannot bind TCP in this cage, which is the measurement behind the untested proxy path rather than a workaround for it. |
| `udp_io.c` | "Scope, stated plainly" | UDP `send` is EPERM; `io_uring_setup` is EPERM |

`issue_comment.md` in this directory is the text posted to cfrs issue #2. It is
kept here because it is the record of the byte counts and ADDFD output that
`../README.md` cites, and a reader who wants to check those against the comment
as posted should not have to fetch it.

## The probes that produced a wrong claim

Recorded because a correction without its cause is one the next reader repeats.

**The ADDFD mistake.** An earlier `verify_claims.c` issued four ADDFD calls
against ONE notification. Measured here by re-running that exact probe
(`git show e0d9ba3:tools/pod-netns/probe/verify_claims.c`, with claims 2 and 3
compiled out), **the first three succeeded and the fourth failed** with ENOENT:

```
ADDFD flags=flags=0    newfd_flags=0        -> rc=3 OK
ADDFD flags=flags=0    newfd_flags=O_CLOEXEC -> rc=4 OK
ADDFD flags=FLAG_SEND  newfd_flags=0        -> rc=5 OK
ADDFD flags=FLAG_SEND  newfd_flags=O_CLOEXEC -> rc=-1 No such file or directory
```

The cause is specific: the third call carries `SECCOMP_ADDFD_FLAG_SEND`, which
answers the pending notification, so by the fourth call there is nothing left to
add a descriptor to. The probe's own output said "ADDFD WORKED" three times, and
that output was read as "ENOENT for all flag combinations" anyway. `addfd_clean.c`
gives each combination its own child and its own notification and gets 4 of 4.
That probe was deleted rather than kept: a file in this directory that still
contains the bug would reproduce the wrong answer for anyone who ran it. A probe
reporting a resource as absent because its own earlier call consumed it is a
probe bug wearing a measurement's clothes.

**`multin.c` replaces four earlier `ceiling*.c` probes** that all reported a
one-notification limit. They declared `struct seccomp_notif nf` outside their loop
and called `memset` once, so the kernel's own output made the second RECV's input
non-zero, which is finding 1. Those probes were measuring their own struct reuse.

**`notifsizes.c` had two wrong versions before the right one**, both deleted. Both
failures read as findings, which is why the probe now checks its own encoder
against libc's constant before trusting its output.

1. The first swept the size field on fd 0, which is not a listener fd, so every
   seccomp command is ENOTTY there and the sweep recognised nothing.
2. The second built `_IOWR('!', 0, size)` with the type and size fields in each
   other's positions, so its command numbers were never valid either, and it
   still reported every size as unrecognised. Worse, on the way it hung: an
   `_IOWR('!', 0, size)` RECV against a real listener blocks waiting for a
   notification, and `O_NONBLOCK` does not help, because the kernel waits on a
   completion rather than on the fd's poll state. That is why the finished probe
   forks a child per size under `alarm(1)`.

**Two claims were wrong for a different reason, and are listed here so the count
above adds up.** They were not probe bugs, so no amount of fixing probes finds
them; they were claims nobody ran.

- **`/proc/<pid>/fd` was recorded as ENXIO** in three places, which is why this
  crate's `SCM_RIGHTS` design note read as though there were no alternative route
  to a descriptor. It is not ENXIO: the directory opens and its entries open.
  What it gives is the wrong direction, since a supervisor can borrow a
  descriptor the child holds but cannot put one into the child's table. Now
  measured in `probe/memrw.c`, and the three claims are corrected.
- **`SECCOMP_GET_NOTIF_SIZES` was described with two errno spellings that were
  never valid**, because the constant is not the bare number 3 as an ioctl
  command. Corrected, with the real reason, in `probe/notifsizes.c`.

And one was a code defect rather than a measurement error at all: passing
`setsockopt` through to the kernel broke DNS for every glibc program under this
tool, which the issue notes had explicitly warned about. `probe/sockopt.c` was a
correct probe throughout.