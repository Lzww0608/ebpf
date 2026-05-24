#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "slow_sql.h"
#include "slow_sql.skel.h"

static volatile sig_atomic_t exiting;

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

static void fmt_time(char *buf, size_t len)
{
    time_t now = time(NULL);
    struct tm tm;

    localtime_r(&now, &tm);
    strftime(buf, len, "%F %T", &tm);
}

static void sanitize_sql(char *sql)
{
    int i;

    for (i = 0; sql[i]; i++) {
        unsigned char c = (unsigned char)sql[i];

        if (c == '\n' || c == '\r' || c == '\t')
            sql[i] = ' ';
        else if (c < 32 || c == 127)
            sql[i] = '?';
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    char ts[32];
    char comm[TASK_COMM_LEN + 1] = {};
    char sql[MAX_SQL_LEN + 1] = {};
    unsigned int sql_len = e->sql_len;
    double latency_ms;

    (void)ctx;
    (void)data_sz;

    if (sql_len > MAX_SQL_LEN - 1)
        sql_len = MAX_SQL_LEN - 1;

    memcpy(comm, e->comm, TASK_COMM_LEN);
    memcpy(sql, e->sql, sql_len);
    sql[sql_len] = '\0';

    sanitize_sql(sql);
    fmt_time(ts, sizeof(ts));

    latency_ms = (double)e->latency_ns / 1000000.0;

    printf("%-19s %-7u %-7u %-6u %-5d %-9.3f %-10s %s\n",
           ts,
           e->tgid,
           e->tid,
           e->uid,
           e->fd,
           latency_ms,
           comm,
           sql);

    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [--pid PID] [--threshold-ms N]\n"
            "\n"
            "Options:\n"
            "  --pid PID            trace a specific mysqld or mariadbd process\n"
            "  --threshold-ms N     slow SQL threshold, default 100\n"
            "\n"
            "Examples:\n"
            "  sudo %s --pid $(pidof mysqld) --threshold-ms 100\n"
            "  sudo %s --threshold-ms 200\n",
            prog, prog, prog);
}

int main(int argc, char **argv)
{
    struct slow_sql_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    unsigned int pid_filter = 0;
    unsigned long long threshold_ms = 100;
    int err = 0;
    int opt;

    static const struct option long_options[] = {
        {"pid", required_argument, NULL, 'p'},
        {"threshold-ms", required_argument, NULL, 't'},
        {"help", no_argument, NULL, 'h'},
        {}
    };

    while ((opt = getopt_long(argc, argv, "p:t:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'p':
            pid_filter = (unsigned int)atoi(optarg);
            if (pid_filter == 0) {
                fprintf(stderr, "invalid --pid value: %s\n", optarg);
                return 1;
            }
            break;
        case 't':
            threshold_ms = strtoull(optarg, NULL, 10);
            if (threshold_ms == 0) {
                fprintf(stderr, "invalid --threshold-ms value: %s\n", optarg);
                return 1;
            }
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

    skel = slow_sql_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    skel->rodata->target_tgid = pid_filter;
    skel->rodata->threshold_ns = threshold_ms * 1000000ULL;

    err = slow_sql_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = slow_sql_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        NULL,
        NULL);
    if (!rb) {
        err = -errno;
        fprintf(stderr, "failed to create ring buffer: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("%-19s %-7s %-7s %-6s %-5s %-9s %-10s %s\n",
           "TIME", "PID", "TID", "UID", "FD", "LAT(ms)", "COMM", "SQL");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }

        if (err < 0) {
            fprintf(stderr, "error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    slow_sql_bpf__destroy(skel);

    return err < 0 ? -err : err;
}
