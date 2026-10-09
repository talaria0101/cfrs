/*
 * libcfrssocks.so — send a program's tailnet TCP connections through a
 * userspace SOCKS5 front door on an AF_UNIX socket.
 *
 * A sealed host commonly denies AF_INET bind(2) outright and allows
 * connect(2) only to a short list of ports, so the SOCKS5 listener that
 * `tailscaled --tun=userspace-networking` opens on 127.0.0.1 is unreachable.
 * `cfrs net tailscale` re-exposes the same netstack over an AF_UNIX socket,
 * which the host does permit. This shim rewrites connect(2) to that socket.
 *
 * Only connections whose destination is a Tailscale address are rewritten:
 * 100.64.0.0/10 and fd7a:115c:a1e0::/48 (MagicDNS is 100.100.100.100). Every
 * other connect(2) is passed to the real libc untouched, so local services and
 * ordinary egress keep working. Set CFRSSOCKS_ALL=1 to route everything.
 *
 * The destination descriptor keeps its number. `dup2(2)` swaps the address
 * family of the existing descriptor for the AF_UNIX one after the SOCKS5
 * handshake completes, so the rest of the program sees a connected stream.
 *
 * This file is compiled from the embedded copy in src/vnet/shim.rs.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/* ── real symbols ─────────────────────────────────────────────────────────── */

static int (*r_connect)(int, const struct sockaddr *, socklen_t);
static int (*r_getpeername)(int, struct sockaddr *, socklen_t *);
static int (*r_getsockname)(int, struct sockaddr *, socklen_t *);
static int (*r_close)(int);
static int (*r_dup)(int);
static int (*r_dup2)(int, int);
static int (*r_dup3)(int, int, int);
static int (*r_fcntl)(int, int, ...);
static int (*r_setsockopt)(int, int, int, const void *, socklen_t);
static int (*r_socket)(int, int, int);

/* ── configuration ────────────────────────────────────────────────────────── */

struct config {
    char proxy[108];      /* CFRSSOCKS_PROXY: unix path, empty disables */
    int log;
    int route_all;        /* CFRSSOCKS_ALL */
    int max_fds;
};

static struct config cfg;
static pthread_once_t init_once = PTHREAD_ONCE_INIT;
static pthread_once_t cfg_once = PTHREAD_ONCE_INIT;

static void resolve_real(void) {
    r_connect = dlsym(RTLD_NEXT, "connect");
    r_getpeername = dlsym(RTLD_NEXT, "getpeername");
    r_getsockname = dlsym(RTLD_NEXT, "getsockname");
    r_close = dlsym(RTLD_NEXT, "close");
    r_dup = dlsym(RTLD_NEXT, "dup");
    r_dup2 = dlsym(RTLD_NEXT, "dup2");
    r_dup3 = dlsym(RTLD_NEXT, "dup3");
    r_fcntl = dlsym(RTLD_NEXT, "fcntl");
    r_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    r_socket = dlsym(RTLD_NEXT, "socket");
}

static void parse_config(void) {
    const char *v;
    memset(&cfg, 0, sizeof cfg);
    cfg.max_fds = 65536;
    if ((v = getenv("CFRSSOCKS_PROXY")) && *v) snprintf(cfg.proxy, sizeof cfg.proxy, "%s", v);
    cfg.log = (v = getenv("CFRSSOCKS_LOG")) && *v && *v != '0';
    cfg.route_all = (v = getenv("CFRSSOCKS_ALL")) && *v && *v != '0';
    if ((v = getenv("CFRSSOCKS_MAX_FDS")) && *v) {
        long n = strtol(v, NULL, 10);
        if (n > 0) cfg.max_fds = (int)n;
    }
}

static void ensure_init(void) {
    pthread_once(&init_once, resolve_real);
    pthread_once(&cfg_once, parse_config);
}

static void logf_(const char *fmt, ...) {
    if (!cfg.log) return;
    va_list ap;
    va_start(ap, fmt);
    fputs("[cfrssocks] ", stderr);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

/* ── fd state table ───────────────────────────────────────────────────────── */

struct virt_fd {
    unsigned char is_virtual;
    int tcp_nodelay;                 /* recorded before the swap */
    struct sockaddr_storage peer;
    socklen_t peer_len;
};

static struct virt_fd *fd_table;
static size_t fd_table_len;
static pthread_mutex_t fd_lock = PTHREAD_MUTEX_INITIALIZER;

static int table_ensure(int fd) {
    if (fd < 0 || fd >= cfg.max_fds) return -1;
    size_t want = (size_t)fd + 1;
    if (want > fd_table_len) {
        size_t grow = fd_table_len ? fd_table_len : 256;
        while (grow < want) grow *= 2;
        if (grow > (size_t)cfg.max_fds) grow = (size_t)cfg.max_fds;
        struct virt_fd *next = realloc(fd_table, grow * sizeof *next);
        if (!next) return -1;
        memset(next + fd_table_len, 0, (grow - fd_table_len) * sizeof *next);
        fd_table = next;
        fd_table_len = grow;
    }
    return 0;
}

static int fd_is_virtual(int fd) {
    int result = 0;
    pthread_mutex_lock(&fd_lock);
    if (fd >= 0 && (size_t)fd < fd_table_len) result = fd_table[fd].is_virtual;
    pthread_mutex_unlock(&fd_lock);
    return result;
}

static void fd_mark(int fd, const struct sockaddr *sa, socklen_t len) {
    pthread_mutex_lock(&fd_lock);
    if (table_ensure(fd) == 0) {
        fd_table[fd].is_virtual = 1;
        socklen_t copy = len < sizeof fd_table[fd].peer ? len : (socklen_t)sizeof fd_table[fd].peer;
        memcpy(&fd_table[fd].peer, sa, copy);
        fd_table[fd].peer_len = copy;
    }
    pthread_mutex_unlock(&fd_lock);
}

static void fd_clear(int fd) {
    pthread_mutex_lock(&fd_lock);
    if (fd >= 0 && (size_t)fd < fd_table_len) memset(&fd_table[fd], 0, sizeof fd_table[fd]);
    pthread_mutex_unlock(&fd_lock);
}

static void fd_copy(int from, int to) {
    pthread_mutex_lock(&fd_lock);
    if (table_ensure(to) == 0) {
        if (from >= 0 && (size_t)from < fd_table_len) fd_table[to] = fd_table[from];
        else memset(&fd_table[to], 0, sizeof fd_table[to]);
    }
    pthread_mutex_unlock(&fd_lock);
}

static void fd_record_nodelay(int fd, int value) {
    pthread_mutex_lock(&fd_lock);
    if (table_ensure(fd) == 0) fd_table[fd].tcp_nodelay = value;
    pthread_mutex_unlock(&fd_lock);
}

static int fd_get_nodelay(int fd) {
    int value = 0;
    pthread_mutex_lock(&fd_lock);
    if (fd >= 0 && (size_t)fd < fd_table_len) value = fd_table[fd].tcp_nodelay;
    pthread_mutex_unlock(&fd_lock);
    return value;
}

/* ── copy a logical address the way Linux does ───────────────────────────── */

static int copy_sockaddr(struct sockaddr *sa, socklen_t *slen,
                         const struct sockaddr_storage *addr, socklen_t addr_len) {
    if (!slen) {
        errno = EINVAL;
        return -1;
    }
    if (!sa) {
        *slen = addr_len;
        return 0;
    }
    socklen_t capacity = *slen;
    socklen_t copy = addr_len < capacity ? addr_len : capacity;
    if (copy) memcpy(sa, addr, copy);
    *slen = addr_len;
    return 0;
}

/* ── address filter ───────────────────────────────────────────────────────── */

static int is_tailnet_v4(const struct in_addr *a) {
    const unsigned char *o = (const unsigned char *)&a->s_addr;
    /* Network byte order on the wire; 100.64.0.0/10 is o[0]==100, 64..127. */
    return o[0] == 100 && (o[1] & 0xc0) == 64;
}

static int is_tailnet_v6(const struct in6_addr *a) {
    const unsigned char *o = a->s6_addr;
    return o[0] == 0xfd && o[1] == 0x7a && o[2] == 0x11 &&
           o[3] == 0x5c && o[4] == 0xa1 && o[5] == 0xe0;
}

static int should_route(const struct sockaddr *sa) {
    if (cfg.route_all) return 1;
    if (sa->sa_family == AF_INET) return is_tailnet_v4(&((const struct sockaddr_in *)sa)->sin_addr);
    if (sa->sa_family == AF_INET6) return is_tailnet_v6(&((const struct sockaddr_in6 *)sa)->sin6_addr);
    return 0;
}

/* ── SOCKS5 handshake to the front door ───────────────────────────────────── */

static int wait_fd(int fd, short events) {
    struct pollfd p;
    p.fd = fd;
    p.events = events;
    for (;;) {
        int r = poll(&p, 1, -1);
        if (r < 0 && errno == EINTR) continue;
        return r < 0 ? -1 : 0;
    }
}

static int read_all(int fd, void *buf, size_t n) {
    unsigned char *p = buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, p + got, n - got, 0);
        if (r == 0) {
            errno = ECONNRESET;
            return -1;
        }
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (wait_fd(fd, POLLIN) < 0) return -1;
                continue;
            }
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

static int write_all(int fd, const void *buf, size_t n) {
    const unsigned char *p = buf;
    size_t sent = 0;
    while (sent < n) {
        ssize_t r = send(fd, p + sent, n - sent, MSG_NOSIGNAL);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (wait_fd(fd, POLLOUT) < 0) return -1;
                continue;
            }
            return -1;
        }
        sent += (size_t)r;
    }
    return 0;
}

static int socks5_handshake(int fd, const struct sockaddr *sa) {
    unsigned char greeting[3] = {5, 1, 0};
    unsigned char reply[4];
    if (write_all(fd, greeting, sizeof greeting) < 0) return -1;
    if (read_all(fd, reply, 2) < 0) return -1;
    if (reply[0] != 5 || reply[1] == 0xff) {
        errno = EACCES;
        return -1;
    }

    unsigned char request[22];
    request[0] = 5;
    request[1] = 1;
    request[2] = 0;
    size_t n = 4;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *s = (const struct sockaddr_in *)sa;
        request[3] = 1;
        memcpy(request + n, &s->sin_addr, 4);
        n += 4;
        memcpy(request + n, &s->sin_port, 2);
        n += 2;
    } else {
        const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)sa;
        request[3] = 4;
        memcpy(request + n, &s->sin6_addr, 16);
        n += 16;
        memcpy(request + n, &s->sin6_port, 2);
        n += 2;
    }
    if (write_all(fd, request, n) < 0) return -1;

    if (read_all(fd, reply, 4) < 0) return -1;
    if (reply[0] != 5) {
        errno = EPROTO;
        return -1;
    }
    if (reply[1] != 0) {
        errno = reply[1] == 5 ? ECONNREFUSED : EHOSTUNREACH;
        return -1;
    }
    size_t address_len = 0;
    if (reply[3] == 1) address_len = 4;
    else if (reply[3] == 4) address_len = 16;
    else if (reply[3] == 3) {
        unsigned char len;
        if (read_all(fd, &len, 1) < 0) return -1;
        address_len = len;
    }
    unsigned char discard[256];
    if (address_len) {
        if (address_len > sizeof discard) address_len = sizeof discard;
        if (read_all(fd, discard, address_len) < 0) return -1;
    }
    unsigned char port[2];
    if (read_all(fd, port, 2) < 0) return -1;
    return 0;
}

/* Route `fd` through the front door, returning 0 on success. */
static int route_through_proxy(int fd, const struct sockaddr *sa) {
    int unix_fd = r_socket(AF_UNIX, SOCK_STREAM, 0);
    if (unix_fd < 0) return -1;

    struct sockaddr_un un;
    memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;
    snprintf(un.sun_path, sizeof un.sun_path, "%s", cfg.proxy);
    socklen_t un_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(un.sun_path) + 1);
    if (r_connect(unix_fd, (struct sockaddr *)&un, un_len) < 0) {
        int saved = errno;
        r_close(unix_fd);
        errno = saved;
        return -1;
    }
    if (socks5_handshake(unix_fd, sa) < 0) {
        int saved = errno;
        r_close(unix_fd);
        errno = saved;
        return -1;
    }

    int flags = r_fcntl(fd, F_GETFL, 0);
    int nodelay = fd_get_nodelay(fd);
    if (nodelay) r_setsockopt(unix_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof nodelay);
    if (r_dup2(unix_fd, fd) < 0) {
        int saved = errno;
        r_close(unix_fd);
        errno = saved;
        return -1;
    }
    r_close(unix_fd);
    if (flags >= 0 && (flags & O_NONBLOCK)) r_fcntl(fd, F_SETFL, flags);
    fd_mark(fd, sa, (socklen_t)(sa->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)));
    return 0;
}

/* ── interposed API ───────────────────────────────────────────────────────── */

int connect(int fd, const struct sockaddr *sa, socklen_t len) {
    ensure_init();
    if (!cfg.proxy[0] || !sa || (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)) {
        return r_connect(fd, sa, len);
    }
    if (!should_route(sa)) return r_connect(fd, sa, len);

    int type = 0;
    socklen_t type_len = sizeof type;
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_len) < 0 || type != SOCK_STREAM) {
        return r_connect(fd, sa, len);
    }
    if (route_through_proxy(fd, sa) < 0) return -1;
    logf_("connect fd=%d -> %s", fd, cfg.proxy);
    return 0;
}

int getpeername(int fd, struct sockaddr *sa, socklen_t *len) {
    ensure_init();
    if (fd_is_virtual(fd)) {
        pthread_mutex_lock(&fd_lock);
        struct sockaddr_storage peer = fd_table[fd].peer;
        socklen_t peer_len = fd_table[fd].peer_len;
        pthread_mutex_unlock(&fd_lock);
        return copy_sockaddr(sa, len, &peer, peer_len);
    }
    return r_getpeername(fd, sa, len);
}

int getsockname(int fd, struct sockaddr *sa, socklen_t *len) {
    ensure_init();
    if (fd_is_virtual(fd)) {
        struct sockaddr_storage local;
        memset(&local, 0, sizeof local);
        local.ss_family = AF_INET;
        struct sockaddr_in *in = (struct sockaddr_in *)&local;
        in->sin_family = AF_INET;
        in->sin_addr.s_addr = htonl(INADDR_ANY);
        in->sin_port = 0;
        return copy_sockaddr(sa, len, &local, sizeof(struct sockaddr_in));
    }
    return r_getsockname(fd, sa, len);
}

int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) {
    ensure_init();
    if (level == IPPROTO_TCP && optname == TCP_NODELAY && optval && optlen >= (socklen_t)sizeof(int)) {
        fd_record_nodelay(fd, *(const int *)optval);
    }
    if (fd_is_virtual(fd) && (level == IPPROTO_TCP || level == IPPROTO_IP || level == IPPROTO_IPV6)) {
        return 0;
    }
    return r_setsockopt(fd, level, optname, optval, optlen);
}

int close(int fd) {
    ensure_init();
    fd_clear(fd);
    return r_close(fd);
}

int dup(int fd) {
    ensure_init();
    int new_fd = r_dup(fd);
    if (new_fd >= 0) fd_copy(fd, new_fd);
    return new_fd;
}

int dup2(int old_fd, int new_fd) {
    ensure_init();
    int rc = r_dup2(old_fd, new_fd);
    if (rc >= 0) fd_copy(old_fd, new_fd);
    return rc;
}

int dup3(int old_fd, int new_fd, int flags) {
    ensure_init();
    int rc = r_dup3(old_fd, new_fd, flags);
    if (rc >= 0) fd_copy(old_fd, new_fd);
    return rc;
}

int fcntl(int fd, int cmd, ...) {
    ensure_init();
    va_list ap;
    va_start(ap, cmd);
    void *arg = va_arg(ap, void *);
    va_end(ap);

    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
        int min_fd = (int)(intptr_t)arg;
        int new_fd = r_fcntl(fd, cmd, min_fd);
        if (new_fd >= 0) fd_copy(fd, new_fd);
        return new_fd;
    }
    if (cmd == F_GETFL || cmd == F_GETFD || cmd == F_GETOWN || cmd == F_GETSIG) {
        return r_fcntl(fd, cmd);
    }
    if (cmd == F_SETFL || cmd == F_SETFD || cmd == F_SETOWN || cmd == F_SETSIG) {
        return r_fcntl(fd, cmd, (int)(intptr_t)arg);
    }
    return r_fcntl(fd, cmd, arg);
}
