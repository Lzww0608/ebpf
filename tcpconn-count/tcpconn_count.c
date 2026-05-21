#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "tcpconn_count.h"
#include "tcpconn_count.skel.h"

static volatile sig_atomic_t exiting;

struct row {
    struct proc_key key;
    struct proc_val val;
};

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    return setrlimit(RLIMIT_MEMLOCK, &rlim);
}

static int cmp_row_desc(const void *a, const void *b)
{
    const struct row *ra = a;
    const struct row *rb = b;
    unsigned long long ta = ra->val.active + ra->val.passive;
    unsigned long long tb = rb->val.active + rb->val.passive;

    if (ta < tb)
        return 1;
    if (ta > tb)
        return -1;
    return 0;
}

static void print_time_header(void)
{
    time_t now = time(NULL);
    struct tm tm;
    char buf[64];

    localtime_r(&now, &tm);
    strftime(buf, sizeof(buf), "%F %T", &tm);

    printf("\n[%s]\n", buf);
}

static void print_counts(int map_fd)
{
    struct proc_key key;
    struct proc_key next_key;
    struct proc_key *prev_key = NULL;
    struct row *rows = NULL;
    size_t rows_len = 0;
    size_t rows_cap = 0;

    while (bpf_map_get_next_key(map_fd, prev_key, &next_key) == 0) {
        struct proc_val val;

        if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0) {
            if (rows_len == rows_cap) {
                size_t new_cap = rows_cap ? rows_cap * 2 : 64;
                struct row *new_rows = realloc(rows, new_cap * sizeof(*rows));

                if (!new_rows) {
                    free(rows);
                    fprintf(stderr, "realloc failed\n");
                    return;
                }

                rows = new_rows;
                rows_cap = new_cap;
            }

            rows[rows_len].key = next_key;
            rows[rows_len].val = val;
            rows_len++;
        }

        key = next_key;
        prev_key = &key;
    }

    qsort(rows, rows_len, sizeof(*rows), cmp_row_desc);

    print_time_header();

    printf("%-8s %-16s %-12s %-12s %-12s\n",
           "PID", "COMM", "ACTIVE", "PASSIVE", "TOTAL");

    for (size_t i = 0; i < rows_len; i++) {
        char comm[COMM_LEN + 1] = {};
        unsigned long long active = rows[i].val.active;
        unsigned long long passive = rows[i].val.passive;
        unsigned long long total = active + passive;

        if (!total)
            continue;

        memcpy(comm, rows[i].val.comm, COMM_LEN);

        printf("%-8u %-16s %-12llu %-12llu %-12llu\n",
               rows[i].key.tgid,
               comm,
               active,
               passive,
               total);
    }

    free(rows);
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-i interval_seconds]\n"
            "\n"
            "Example:\n"
            "  sudo %s -i 2\n",
            prog, prog);
}

int main(int argc, char **argv)
{
    struct tcpconn_count_bpf *skel = NULL;
    int counts_fd;
    int interval = 2;
    int opt;
    int err = 0;

    while ((opt = getopt(argc, argv, "i:h")) != -1) {
        switch (opt) {
        case 'i':
            interval = atoi(optarg);
            if (interval <= 0)
                interval = 2;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (bump_memlock_rlimit()) {
        fprintf(stderr, "failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
        return 1;
    }

    skel = tcpconn_count_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open and load BPF skeleton\n");
        return 1;
    }

    err = tcpconn_count_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    counts_fd = bpf_map__fd(skel->maps.counts);

    printf("Tracing TCP connection establishments. Press Ctrl-C to exit.\n");

    while (!exiting) {
        sleep(interval);
        print_counts(counts_fd);
    }

cleanup:
    tcpconn_count_bpf__destroy(skel);
    return err < 0 ? -err : err;
}
