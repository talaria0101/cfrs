/* Are the compiled-in seccomp ioctl command numbers right?
 *
 * The module docs in src/seccomp.rs make two claims:
 *
 *   1. SECCOMP_GET_NOTIF_SIZES cannot be used to detect a stale uapi header.
 *   2. The compiled-in ioctl command number is correct: a sweep of the encoded
 *      struct size accepted nothing but 80 bytes.
 *
 * Claim 2 is confirmed below. Claim 1 was wrong as written, and finding out why
 * is the reason this probe exists.
 *
 * The docs said GET_NOTIF_SIZES "returns EINVAL under both the bare-3 and
 * _IO('!', 3) spellings". It does not, and it cannot: that constant is not an
 * ioctl command number at all. SECCOMP_GET_NOTIF_SIZES is dispatched as
 * _IOWR('!', 0, struct seccomp_notif_sizes), which encodes to 0xc0062100 with
 * this header. Passing the bare 3 asks the kernel for a command it has no
 * handler for, so the answer is ENOTTY, which is the kernel saying "I do not
 * know this command", not "this feature is unavailable". Those two are easy to
 * confuse and the second one reads like a real answer.
 *
 * GET_NOTIF_SIZES IS genuinely unavailable here, but the honest reason is
 * different: the seccomp ioctl handler is only reachable through the listener
 * fd returned by SECCOMP_FILTER_FLAG_NEW_LISTENER. On an ordinary fd every
 * seccomp command, correctly encoded, is ENOTTY. So the sweep has to run on a
 * real listener fd, and "does not work" has to be reported from there.
 *
 * METHOD, because two wrong versions of this probe preceded it and both are
 * worth recording:
 *
 *   - A sweep on fd 0 recognises nothing, because fd 0 is not a listener. Every
 *     seccomp command is ENOTTY there. This is the wrong-spelling effect above,
 *     not evidence about the encoding.
 *   - An _IOWR('!', 0, size) RECV on a listener blocks waiting for a
 *     notification, so a naive loop hangs on the first recognised size. Setting
 *     O_NONBLOCK does not help: the kernel waits on a completion, not on the
 *     fd's poll state. So each size is tried in a forked child under alarm(1).
 *     The child blocking until its alarm is the signal that the command was
 *     RECOGNISED; EINVAL means the kernel rejected the command number outright.
 *
 * The sweep builds command numbers from the _IOC layout rather than borrowing
 * _IOWR, and checks its own encoder against libc's constant before trusting its
 * output, because an encoder written wrong produces a sweep that is uniformly
 * negative and looks like a finding.
 *
 * Build: cc -O1 -o notifsizes notifsizes.c
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

/* _IOC(dir, type, nr, size): dir at bits 30-31, size at 16-29, type at 8-15,
 * nr at 0-7. Spelled out rather than borrowed, because the sweep needs to vary
 * exactly one field. */
#define MKIO(d, t, nr, sz)                                                  \
	(((unsigned)(d) << 30) | ((unsigned)(sz) << 16) | ((unsigned)(t) << 8) | \
	 (unsigned)(nr))

/* The kernel's struct seccomp_notif is 80 bytes; this program's own copy is not
 * used, so the buffer is generously sized and the real size comes from the
 * encoded command number. */
#define RECVBUF 256

static void say(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
}

/* Try one command number on the listener fd, in a child under a one-second
 * alarm. Returns 'R' if the child blocked (command recognised), 'E' on EINVAL
 * (command rejected), or '?' for anything else. */
static char try_cmd(long lfd, unsigned cmd)
{
	pid_t p = fork();
	if (p < 0)
		return '?';
	if (p == 0) {
		alarm(1);
		static char buf[RECVBUF];
		long r = syscall(SYS_ioctl, lfd, (unsigned long)cmd, buf);
		_exit(r < 0 ? (errno == EINVAL ? 30 : 31) : 32);
	}
	int st = 0;
	if (waitpid(p, &st, 0) < 0)
		return '?';
	if (WIFSIGNALED(st) && WTERMSIG(st) == SIGALRM)
		return 'R';
	if (WIFEXITED(st)) {
		if (WEXITSTATUS(st) == 30)
			return 'E';
		if (WEXITSTATUS(st) == 31) {
			fprintf(stderr, "  (command %s reached the handler but failed: %s)\n",
				"WITHOUT EINVAL", "see errno above");
			return '?';
		}
		if (WEXITSTATUS(st) == 32)
			return 'S';
	}
	return '?';
}

int main(void)
{
	int failures = 0;

	/* The encoder is checked against libc before its output is believed. */
	unsigned libc_recv = (unsigned)SECCOMP_IOCTL_NOTIF_RECV;
	unsigned self_recv = MKIO(3, '!', 0, 80);
	say("command number encoding:\n");
	say("  libc SECCOMP_IOCTL_NOTIF_RECV = 0x%08lx", (unsigned long)libc_recv);
	say("  (dir=%lu type='%c' nr=%lu size=%lu)\n", (libc_recv >> 30) & 3,
	    (int)((libc_recv >> 8) & 0xff), libc_recv & 0xff,
	    (unsigned long)((libc_recv >> 16) & 0x3fff));
	say("  this file's MKIO(3,'!',0,80) = 0x%08lx  %s\n",
	    self_recv, self_recv == libc_recv ? "matches libc" : "DOES NOT MATCH libc");
	if (self_recv != libc_recv) {
		say("\nverdict: this probe's own encoder is wrong, so its sweep would be\n"
		    "         meaningless. Fix the encoder before reading the numbers.\n");
		return 1;
	}

	/* A real listener fd, because that is the only fd where a seccomp ioctl
	 * is dispatched at all. */
	struct sock_filter allow[] = { BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW) };
	struct sock_fprog fp = { .len = 1, .filter = allow };
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		perror("prctl(PR_SET_NO_NEW_PRIVS)");
		return 1;
	}
	long lfd = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
			   SECCOMP_FILTER_FLAG_NEW_LISTENER, &fp);
	if (lfd < 0) {
		perror("seccomp(SET_MODE_FILTER|NEW_LISTENER)");
		return 1;
	}
	say("  listener fd = %ld\n", lfd);

	/* Claim 1, corrected: what GET_NOTIF_SIZES actually does, on both a
	 * non-listener fd and a real one. */
	unsigned sizes_cmd = MKIO(3, '!', 0, 6); /* _IOWR('!', 0, struct notif_sizes) */
	say("\nSECCOMP_GET_NOTIF_SIZES:\n");
	say("  correct encoding _IOWR('!',0,6) = 0x%08lx\n", sizes_cmd);

	errno = 0;
	char small[6];
	long r = syscall(SYS_ioctl, 0, (unsigned long)sizes_cmd, small);
	say("    on fd 0 (not a listener)  -> %ld  %s\n", r, r < 0 ? strerror(errno) : "OK");

	errno = 0;
	memset(small, 0, sizeof small);
	r = syscall(SYS_ioctl, lfd, (unsigned long)sizes_cmd, small);
	int enc_errno = errno;
	say("    on the listener fd      -> %ld  %s\n", r, r < 0 ? strerror(enc_errno) : "OK");

	errno = 0;
	memset(small, 0, sizeof small);
	r = syscall(SYS_ioctl, lfd, (unsigned long)SECCOMP_GET_NOTIF_SIZES, small);
	say("    bare 3, the wrong spelling -> %ld  %s\n", r, r < 0 ? strerror(errno) : "OK");
	say("  so: the bare-3 spelling cannot distinguish an absent feature from a\n"
	    "  command number that was never valid. Report it as the latter.\n");

	/* Claim 2: the sweep. */
	say("\nSECCOMP_IOCTL_NOTIF_RECV size sweep, 4 to 160 step 4, on the listener fd:\n");
	int recognised = 0, first_at = -1;
	for (unsigned size = 4; size <= 160; size += 4) {
		unsigned cmd = MKIO(3, '!', 0, size);
		char verdict = try_cmd(lfd, cmd);
		if (verdict == 'R') {
			recognised++;
			if (first_at < 0)
				first_at = (int)size;
			printf("  size=%3u  cmd=0x%08lx  RECOGNISED (blocked waiting for a "
			       "notification)\n",
			       size, cmd);
		} else if (verdict == 'E') {
			printf("  size=%3u  cmd=0x%08lx  EINVAL, command rejected\n", size, cmd);
		} else {
			printf("  size=%3u  cmd=0x%08lx  inconclusive\n", size, cmd);
		}
	}
	int total = (160 - 4) / 4 + 1;
	say("\n  %d of %d encodings recognised", recognised, total);
	if (first_at >= 0)
		say(", the only one at size %d", first_at);
	say("\n");

	if (recognised == 1 && first_at == 80) {
		say("verdict: exactly one encoding recognised, at size 80, which is the size\n"
		    "         libc compiles in. The compiled-in command numbers are correct.\n");
	} else {
		say("verdict: the claim does NOT hold. Expected exactly one recognised encoding\n"
		    "         at size 80, got %d with the first at %d. Do not trust the\n"
		    "         compiled-in command numbers until this is explained.\n",
		    recognised, first_at);
		failures = 1;
	}

	return failures;
}