#ifndef BENCH_EVIDENCE_H
#define BENCH_EVIDENCE_H
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* This layout is shared with tools/_bench.py.  The random token prevents a
 * descriptor closed and reused by the application from identifying the wrong
 * file after a later exec.  No descriptor is retained for evidence writes. */
#define BENCH_CAPACITY 2048
struct bench_record {
    _Atomic uint32_t ready;
    int32_t pid;
    uint32_t kind;
    int32_t a, b, c, d;
    uint32_t padding;
    uint64_t dev, ino;
    char exe[512];
    char detail[1024];
};
struct bench_area {
    char magic[8];
    char token[32];
    uint32_t version;
    _Atomic uint32_t count;
    _Atomic uint32_t overflow;
    uint32_t reserved;
    struct bench_record records[BENCH_CAPACITY];
};
static struct bench_area *bench_area;

/* getenv() is not reliably initialized in glibc's audit namespace. */
static int bench_parameters(int *result_fd, char token[32]) {
    static const char fd_key[] = "BENCH_EVIDENCE_FD=";
    static const char token_key[] = "BENCH_EVIDENCE_TOKEN=";
    char buf[1024], entry[128];
    size_t used = 0, total = 0;
    int got_fd = 0, got_token = 0;
    int proc = open("/proc/self/environ", O_RDONLY | O_CLOEXEC);
    if (proc < 0) return 0;
    while (total < 4U * 1024U * 1024U) {
        ssize_t n = read(proc, buf, sizeof buf);
        if (n <= 0) break;
        total += (size_t)n;
        for (ssize_t i = 0; i < n; ++i) {
            char c = buf[i];
            if (c) {
                if (used < sizeof entry) entry[used++] = c;
                else used = sizeof entry;
                continue;
            }
            size_t j;
            if (used > sizeof(fd_key) - 1 && used < sizeof entry) {
                for (j = 0; j < sizeof(fd_key) - 1 && entry[j] == fd_key[j]; ++j) {}
                if (j == sizeof(fd_key) - 1) {
                    unsigned value = 0;
                    for (; j < used && entry[j] >= '0' && entry[j] <= '9' && value <= 1000000U; ++j)
                        value = value * 10U + (unsigned)(entry[j] - '0');
                    if (j == used) { *result_fd = (int)value; got_fd = 1; }
                }
            }
            if (used == sizeof(token_key) - 1 + 32) {
                for (j = 0; j < sizeof(token_key) - 1 && entry[j] == token_key[j]; ++j) {}
                if (j == sizeof(token_key) - 1) {
                    for (j = 0; j < 32; ++j) token[j] = entry[sizeof(token_key) - 1 + j];
                    got_token = 1;
                }
            }
            used = 0;
            if (got_fd && got_token) { close(proc); return 1; }
        }
    }
    close(proc);
    return 0;
}

static void bench_init(void) {
    static const char magic[8] = {'B','E','N','C','H','0','1','\0'};
    int fd = -1;
    char token[32];
    struct stat st;
    if (!bench_parameters(&fd, token) || fd < 0) return;
    /* Capture a separate reference before checking the object, then map it.
     * Once mapped, later close/dup2 of the original descriptor is harmless. */
    int copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    if (copy < 0) return;
    if (fstat(copy, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size != (off_t)sizeof(struct bench_area)) {
        close(copy); return;
    }
    void *mapping = mmap(NULL, sizeof(struct bench_area), PROT_READ | PROT_WRITE, MAP_SHARED, copy, 0);
    close(copy);
    if (mapping == MAP_FAILED) return;
    struct bench_area *area = mapping;
    for (unsigned i = 0; i < 8; ++i) if (area->magic[i] != magic[i]) goto invalid;
    for (unsigned i = 0; i < 32; ++i) if (area->token[i] != token[i]) goto invalid;
    if (area->version != 1) goto invalid;
    bench_area = area;
    return;
invalid:
    munmap(mapping, sizeof(struct bench_area));
}

static void bench_record(uint32_t kind, int a, int b, int c, int d, const char *detail) {
    struct bench_area *area = bench_area;
    if (!area) return;
    uint32_t index = atomic_fetch_add_explicit(&area->count, 1, memory_order_relaxed);
    if (index >= BENCH_CAPACITY) {
        atomic_store_explicit(&area->overflow, 1, memory_order_relaxed);
        return;
    }
    struct bench_record *r = &area->records[index];
    struct stat st;
    r->pid = (int32_t)getpid();
    r->kind = kind;
    r->a = a; r->b = b; r->c = c; r->d = d;
    if (stat("/proc/self/exe", &st) == 0) { r->dev = (uint64_t)st.st_dev; r->ino = (uint64_t)st.st_ino; }
    ssize_t n = readlink("/proc/self/exe", r->exe, sizeof(r->exe) - 1);
    if (n >= 0) r->exe[n] = '\0';
    if (detail) {
        size_t i = 0;
        while (detail[i] && i < sizeof(r->detail) - 1) { r->detail[i] = detail[i]; ++i; }
        r->detail[i] = '\0';
    }
    atomic_store_explicit(&r->ready, 1, memory_order_release);
}
#endif
