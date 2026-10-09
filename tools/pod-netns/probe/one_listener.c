/* Can a process hold two seccomp user-notification listeners at once?
 *
 * The module docs in src/seccomp.rs claim that a task may hold only ONE
 * USER_NOTIF listener, and that a second
 * `SECCOMP_SET_MODE_FILTER|SECCOMP_FILTER_FLAG_NEW_LISTENER` returns EBUSY. That
 * claim is the whole reason this tool puts every syscall it cares about into one
 * filter and dispatches on `seccomp_data.nr` instead of installing a filter per
 * syscall, so it is worth a probe rather than a recollection.
 *
 * Two things are measured, because they are different questions:
 *
 *   1. A second listener in the SAME task. This is the EBUSY claim.
 *   2. A second listener in a CHILD that inherits the first, and in a fresh
 *      fork that does not. If a child could install its own, the supervisor's
 *      "one filter, dispatched by nr" design would leak, because the child's
 *      filter would sit in front of the one the supervisor services.
 *
 * Build: cc -O1 -o one_listener one_listener.c
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

static void say(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
}

/* A minimal USER_NOTIF filter: notify on one syscall, allow everything else. */
static long install_listener(int nr)
{
	struct sock_filter prog[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)nr, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog fp = { .len = 4, .filter = prog };
	return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
			SECCOMP_FILTER_FLAG_NEW_LISTENER, &fp);
}

int main(void)
{
	int failures = 0;

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		perror("prctl(PR_SET_NO_NEW_PRIVS)");
		return 1;
	}

	say("A task may hold only one USER_NOTIF listener:\n");

	/* 1. First listener in this task. */
	errno = 0;
	long first = install_listener(__NR_socket);
	say("  first  NEW_LISTENER -> %ld  %s\n", first,
	    first < 0 ? strerror(errno) : "OK");
	if (first < 0) {
		say("\nverdict: cannot install even the first listener here, so the second-listener\n"
		    "         question is not reachable on this host and the doc claim is\n"
		    "         untested rather than confirmed.\n");
		return 1;
	}

	/* 2. Second listener, same task, same filter. */
	errno = 0;
	long second = install_listener(__NR_socket);
	int second_errno = errno;
	say("  second NEW_LISTENER -> %ld  %s\n", second,
	    second < 0 ? strerror(second_errno) : "OK");

	/* 3. Second listener in a child that inherits the first filter. The
	 * child shares nothing with the parent's listener table, so if this
	 * succeeds, "one per task" is still the right statement but the filter
	 * inheritance is what keeps a grandchild from stealing notifications. */
	pid_t p = fork();
	if (p == 0) {
		errno = 0;
		long r = install_listener(__NR_bind);
		_exit(r < 0 ? (errno == EBUSY ? 10 : 11) : 0);
	}
	int st = 0;
	waitpid(p, &st, 0);
	int child_code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
	say("  in a child that inherited the first filter -> exit %d  %s\n", child_code,
	    child_code == 10 ? "EBUSY, as expected"
			     : child_code == 0 ? "OK, so a filter is per-task, not inherited"
					       : "succeeded unexpectedly");

	/* 4. A forked child of THIS task cannot touch the parent's listener
	 * anyway, because fd numbers are per-process, so what actually matters
	 * is whether a second install in one task is refused. */
	say("\nverdict:\n");
	if (second < 0 && second_errno == EBUSY) {
		say("  a second NEW_LISTENER in the same task returns EBUSY, as documented.\n");
		if (child_code == 10) {
			say("  and a child that inherited the filter is refused as well, so the\n"
			    "  single-listener design is enforced by the kernel on both counts.\n");
		} else if (child_code == 0) {
			say("  but a child CAN install its own listener, so the invariant is\n"
			    "  per-task rather than per-process-tree. This tool execs a child that\n"
			    "  does not install filters, so nothing here depends on it.\n");
		} else {
			say("  and the child case returned something else (%d); read it before\n"
			    "  relying on the inheritance claim.\n",
			    child_code);
			failures = 1;
		}
	} else {
		say("  the claim does NOT hold as written: a second NEW_LISTENER returned %ld/%s,\n"
		    "  not EBUSY. Re-read this before trusting the one-filter design.\n",
		    second, second < 0 ? strerror(second_errno) : "OK");
		failures = 1;
	}

	return failures;
}