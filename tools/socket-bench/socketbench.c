#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "../_bench_evidence.h"

static pthread_once_t once = PTHREAD_ONCE_INIT;
static _Thread_local int resolving;
static int (*next_socket)(int, int, int);
static int (*next_accept)(int, struct sockaddr *, socklen_t *);
static int (*next_accept4)(int, struct sockaddr *, socklen_t *, int);
static int nodelay = -1, sndbuf = -1, rcvbuf = -1;
static _Atomic unsigned successes;

__attribute__((constructor)) static void evidence_constructor(void) {
    bench_init();
    bench_record('A', 0, 0, 0, 0, NULL);
}

static int setting(const char *key, int fallback) {
    const char *value = getenv(key);
    return value ? (int)strtol(value, NULL, 10) : fallback;
}

static void initialize(void) {
    next_socket = (int (*)(int, int, int))dlsym(RTLD_NEXT, "socket");
    next_accept = (int (*)(int, struct sockaddr *, socklen_t *))dlsym(RTLD_NEXT, "accept");
    next_accept4 = (int (*)(int, struct sockaddr *, socklen_t *, int))dlsym(RTLD_NEXT, "accept4");
    nodelay = setting("BENCH_TCP_NODELAY", -1);
    sndbuf = setting("BENCH_SNDBUF", -1);
    rcvbuf = setting("BENCH_RCVBUF", -1);
}

static void init(void) {
    resolving = 1;
    pthread_once(&once, initialize);
    resolving = 0;
}

static void failed(const char *operation, int error) {
    bench_record('E', error, 0, 0, 0, operation);
}

static int read_option(int fd, int level, int option, int *value) {
    socklen_t len = sizeof *value;
    return getsockopt(fd, level, option, value, &len);
}

/* On an instrumentation error, close the newly created fd and report the
 * original error to the caller.  A successful report is never fabricated. */
static int apply(int fd, int domain) {
    int nd, sb, rb, error;
    const char *operation;
    if (nodelay >= 0 && setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof nodelay) < 0) {
        operation = "setsockopt(TCP_NODELAY)"; goto fail;
    }
    if (sndbuf >= 0 && setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf) < 0) {
        operation = "setsockopt(SO_SNDBUF)"; goto fail;
    }
    if (rcvbuf >= 0 && setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf) < 0) {
        operation = "setsockopt(SO_RCVBUF)"; goto fail;
    }
    if (read_option(fd, IPPROTO_TCP, TCP_NODELAY, &nd) < 0) {
        operation = "getsockopt(TCP_NODELAY)"; goto fail;
    }
    if (read_option(fd, SOL_SOCKET, SO_SNDBUF, &sb) < 0) {
        operation = "getsockopt(SO_SNDBUF)"; goto fail;
    }
    if (read_option(fd, SOL_SOCKET, SO_RCVBUF, &rb) < 0) {
        operation = "getsockopt(SO_RCVBUF)"; goto fail;
    }
    unsigned sample = atomic_fetch_add_explicit(&successes, 1, memory_order_relaxed);
    if (sample < 128) bench_record('S', domain, nd, sb, rb, NULL);
    else if (sample == 128) bench_record('T', 0, 0, 0, 0, "socket evidence sampling truncated");
    return fd;
fail:
    error = errno;
    failed(operation, error);
    (void)close(fd);
    errno = error;
    return -1;
}

static int accepted(int fd) {
    int domain, type, protocol, saved = errno;
    if (fd < 0) return fd;
    if (read_option(fd, SOL_SOCKET, SO_DOMAIN, &domain) < 0) {
        int error = errno; failed("getsockopt(SO_DOMAIN)", error); (void)close(fd); errno = error; return -1;
    }
    if (domain != AF_INET && domain != AF_INET6) { errno = saved; return fd; }
    if (read_option(fd, SOL_SOCKET, SO_TYPE, &type) < 0 ||
        read_option(fd, SOL_SOCKET, SO_PROTOCOL, &protocol) < 0) {
        int error = errno; failed("getsockopt(SO_TYPE/SO_PROTOCOL)", error); (void)close(fd); errno = error; return -1;
    }
    if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
        fd = apply(fd, domain);
        if (fd < 0) return -1;
    }
    errno = saved;
    return fd;
}

int socket(int domain, int type, int protocol) {
    if (resolving) return (int)syscall(SYS_socket, domain, type, protocol);
    init();
    if (!next_socket) { failed("resolve socket", ENOSYS); errno = ENOSYS; return -1; }
    int fd = next_socket(domain, type, protocol), saved = errno;
    if (fd >= 0 && (domain == AF_INET || domain == AF_INET6) &&
        (type & 15) == SOCK_STREAM && (protocol == 0 || protocol == IPPROTO_TCP)) {
        fd = apply(fd, domain);
        if (fd < 0) return -1;
    }
    errno = saved;
    return fd;
}

int accept(int fd, struct sockaddr *address, socklen_t *length) {
    if (resolving) return (int)syscall(SYS_accept, fd, address, length);
    init();
    if (!next_accept) { failed("resolve accept", ENOSYS); errno = ENOSYS; return -1; }
    return accepted(next_accept(fd, address, length));
}

int accept4(int fd, struct sockaddr *address, socklen_t *length, int flags) {
    if (resolving) return (int)syscall(SYS_accept4, fd, address, length, flags);
    init();
    if (!next_accept4) { failed("resolve accept4", ENOSYS); errno = ENOSYS; return -1; }
    return accepted(next_accept4(fd, address, length, flags));
}
