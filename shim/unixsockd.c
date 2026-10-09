/* unixsockd - listen on a unix socket, spawn a server per connection.
 *
 * The sshd a sealed host can run is dynamic, so it can be interposed; but
 * OpenSSH will not listen on a unix socket. This is the missing listener:
 * accept, hand the connection to the server on stdin/stdout/stderr, exec. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: unixsockd SOCKPATH CMD [ARG...]\n"); return 2; }
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s", argv[1]);
    unlink(argv[1]);
    if (bind(s, (struct sockaddr *)&sa, sizeof sa) < 0) { perror("bind"); return 1; }
    if (listen(s, 16) < 0) { perror("listen"); return 1; }
    signal(SIGCHLD, SIG_IGN);
    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) { if (errno == EINTR) continue; perror("accept"); break; }
        pid_t p = fork();
        if (p == 0) {
            close(s);
            dup2(c, 0);
            dup2(c, 1);
            if (c > 2) close(c);
            /* stderr must NOT be the connection: sshd -e logs there and the
             * log bytes corrupt the SSH stream. */
            {
                const char *log = getenv("UNIXSOCKD_LOG");
                int lf = log ? open(log, O_WRONLY | O_CREAT | O_APPEND, 0644) : -1;
                if (lf < 0) lf = open("/dev/null", O_WRONLY);
                if (lf >= 0) { dup2(lf, 2); if (lf > 2) close(lf); }
            }
            execvp(argv[2], &argv[2]);
            _exit(127);
        }
        close(c);
    }
    return 0;
}
