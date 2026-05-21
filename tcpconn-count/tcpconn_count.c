#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "tcpconn_count.h"
#include "tcpconn_count.skel.h"

enum group_mode {
    GROUP_BY_PID,
    GROUP_BY_CGROUP,
};

enum long_option_id {
    OPT_ACTIVE_ONLY = 256,
    OPT_PASSIVE_ONLY,
    OPT_EVENTS,
    OPT_PROMETHEUS,
    OPT_GROUP_BY,
    OPT_CLEANUP,
};

struct options {
    int interval;
    unsigned int pid;
    char comm[COMM_LEN];
    bool has_pid;
    bool has_comm;
    bool active_only;
    bool passive_only;
    bool events;
    bool prometheus;
    bool cleanup;
    enum group_mode group_by;
};

struct row {
    struct proc_key key;
    struct proc_val val;
};

struct cgroup_row {
    unsigned long long cgroup_id;
    unsigned long long active;
    unsigned long long passive;
    unsigned int last_remote_addr_v4;
    unsigned int last_remote_addr_v6[4];
    unsigned short last_remote_port;
    unsigned char last_family;
};

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

static int cmp_row_total_desc(const void *a, const void *b)
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

static int cmp_row_cgroup_asc(const void *a, const void *b)
{
    const struct row *ra = a;
    const struct row *rb = b;

    if (ra->val.cgroup_id < rb->val.cgroup_id)
        return -1;
    if (ra->val.cgroup_id > rb->val.cgroup_id)
        return 1;
    return 0;
}

static int cmp_cgroup_total_desc(const void *a, const void *b)
{
    const struct cgroup_row *ra = a;
    const struct cgroup_row *rb = b;
    unsigned long long ta = ra->active + ra->passive;
    unsigned long long tb = rb->active + rb->passive;

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

static int parse_uint(const char *arg, unsigned int *out, const char *name)
{
    char *end = NULL;
    unsigned long value;

    errno = 0;
    value = strtoul(arg, &end, 10);
    if (errno || !end || *end || value > UINT_MAX) {
        fprintf(stderr, "invalid %s: %s\n", name, arg);
        return -1;
    }

    *out = (unsigned int)value;
    return 0;
}

static void format_endpoint(unsigned char family,
                            unsigned int addr_v4,
                            const unsigned int addr_v6[4],
                            unsigned short port,
                            char *buf,
                            size_t buf_len)
{
    char ip[INET6_ADDRSTRLEN] = "-";
    const void *addr = NULL;
    int af = 0;

    if (!buf_len)
        return;

    if (family == TCPCONN_FAMILY_IPV4) {
        af = AF_INET;
        addr = &addr_v4;
    } else if (family == TCPCONN_FAMILY_IPV6) {
        af = AF_INET6;
        addr = addr_v6;
    } else {
        snprintf(buf, buf_len, "-");
        return;
    }

    if (!inet_ntop(af, addr, ip, sizeof(ip)))
        snprintf(ip, sizeof(ip), "-");

    if (family == TCPCONN_FAMILY_IPV6)
        snprintf(buf, buf_len, "[%s]:%u", ip, port);
    else
        snprintf(buf, buf_len, "%s:%u", ip, port);
}

static void format_remote_from_val(const struct proc_val *val,
                                   char *buf,
                                   size_t buf_len)
{
    format_endpoint(val->last_family,
                    val->last_remote_addr_v4,
                    val->last_remote_addr_v6,
                    val->last_remote_port,
                    buf,
                    buf_len);
}

static void format_remote_from_cgroup(const struct cgroup_row *row,
                                      char *buf,
                                      size_t buf_len)
{
    format_endpoint(row->last_family,
                    row->last_remote_addr_v4,
                    row->last_remote_addr_v6,
                    row->last_remote_port,
                    buf,
                    buf_len);
}

static void format_event_endpoint(const struct conn_event *event,
                                  bool remote,
                                  char *buf,
                                  size_t buf_len)
{
    if (remote) {
        format_endpoint(event->family,
                        event->remote_addr_v4,
                        event->remote_addr_v6,
                        event->remote_port,
                        buf,
                        buf_len);
        return;
    }

    format_endpoint(event->family,
                    event->local_addr_v4,
                    event->local_addr_v6,
                    event->local_port,
                    buf,
                    buf_len);
}

static void print_escaped_label(const char *s)
{
    for (; s && *s; s++) {
        if (*s == '\\' || *s == '"')
            putchar('\\');
        if (*s == '\n') {
            fputs("\\n", stdout);
            continue;
        }
        putchar(*s);
    }
}

static int collect_rows(int map_fd, struct row **out_rows, size_t *out_len)
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
                    return -1;
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

    *out_rows = rows;
    *out_len = rows_len;
    return 0;
}

static bool pid_exists(unsigned int pid)
{
    char path[64];

    snprintf(path, sizeof(path), "/proc/%u", pid);
    return access(path, F_OK) == 0;
}

static int cleanup_dead_pids(int map_fd)
{
    struct row *rows = NULL;
    struct proc_key *dead = NULL;
    size_t rows_len = 0;
    size_t dead_len = 0;
    size_t dead_cap = 0;
    int deleted = 0;

    if (collect_rows(map_fd, &rows, &rows_len))
        return -1;

    for (size_t i = 0; i < rows_len; i++) {
        if (pid_exists(rows[i].key.tgid))
            continue;

        if (dead_len == dead_cap) {
            size_t new_cap = dead_cap ? dead_cap * 2 : 64;
            struct proc_key *new_dead = realloc(dead, new_cap * sizeof(*dead));

            if (!new_dead) {
                free(dead);
                free(rows);
                return -1;
            }

            dead = new_dead;
            dead_cap = new_cap;
        }

        dead[dead_len++] = rows[i].key;
    }

    for (size_t i = 0; i < dead_len; i++) {
        if (bpf_map_delete_elem(map_fd, &dead[i]) == 0)
            deleted++;
    }

    free(dead);
    free(rows);
    return deleted;
}

static void print_prometheus_pid(const struct row *rows, size_t rows_len)
{
    printf("# TYPE tcpconn_established_total counter\n");

    for (size_t i = 0; i < rows_len; i++) {
        char comm[COMM_LEN + 1] = {};
        unsigned long long active = rows[i].val.active;
        unsigned long long passive = rows[i].val.passive;
        unsigned long long total = active + passive;

        if (!total)
            continue;

        memcpy(comm, rows[i].val.comm, COMM_LEN);

        printf("tcpconn_established_total{direction=\"active\",pid=\"%u\",comm=\"",
               rows[i].key.tgid);
        print_escaped_label(comm);
        printf("\",cgroup_id=\"%llu\"} %llu\n", rows[i].val.cgroup_id, active);

        printf("tcpconn_established_total{direction=\"passive\",pid=\"%u\",comm=\"",
               rows[i].key.tgid);
        print_escaped_label(comm);
        printf("\",cgroup_id=\"%llu\"} %llu\n", rows[i].val.cgroup_id, passive);

        printf("tcpconn_established_total{direction=\"total\",pid=\"%u\",comm=\"",
               rows[i].key.tgid);
        print_escaped_label(comm);
        printf("\",cgroup_id=\"%llu\"} %llu\n", rows[i].val.cgroup_id, total);
    }
}

static void print_pid_table(const struct row *rows, size_t rows_len)
{
    print_time_header();

    printf("%-8s %-16s %-20s %-12s %-12s %-12s %-48s\n",
           "PID", "COMM", "CGROUP_ID", "ACTIVE", "PASSIVE", "TOTAL", "LAST_REMOTE");

    for (size_t i = 0; i < rows_len; i++) {
        char comm[COMM_LEN + 1] = {};
        char remote[80];
        unsigned long long active = rows[i].val.active;
        unsigned long long passive = rows[i].val.passive;
        unsigned long long total = active + passive;

        if (!total)
            continue;

        memcpy(comm, rows[i].val.comm, COMM_LEN);
        format_remote_from_val(&rows[i].val, remote, sizeof(remote));

        printf("%-8u %-16s %-20llu %-12llu %-12llu %-12llu %-48s\n",
               rows[i].key.tgid,
               comm,
               rows[i].val.cgroup_id,
               active,
               passive,
               total,
               remote);
    }
}

static int build_cgroup_rows(const struct row *rows,
                             size_t rows_len,
                             struct cgroup_row **out_groups,
                             size_t *out_len)
{
    struct row *sorted = NULL;
    struct cgroup_row *groups = NULL;
    size_t groups_len = 0;
    size_t groups_cap = 0;

    if (rows_len) {
        sorted = malloc(rows_len * sizeof(*sorted));
        if (!sorted)
            return -1;

        memcpy(sorted, rows, rows_len * sizeof(*sorted));
        qsort(sorted, rows_len, sizeof(*sorted), cmp_row_cgroup_asc);
    }

    for (size_t i = 0; i < rows_len; i++) {
        unsigned long long total = sorted[i].val.active + sorted[i].val.passive;
        struct cgroup_row *group;

        if (!total)
            continue;

        if (!groups_len || groups[groups_len - 1].cgroup_id != sorted[i].val.cgroup_id) {
            if (groups_len == groups_cap) {
                size_t new_cap = groups_cap ? groups_cap * 2 : 32;
                struct cgroup_row *new_groups = realloc(groups, new_cap * sizeof(*groups));

                if (!new_groups) {
                    free(groups);
                    free(sorted);
                    return -1;
                }

                groups = new_groups;
                groups_cap = new_cap;
            }

            groups[groups_len] = (struct cgroup_row){
                .cgroup_id = sorted[i].val.cgroup_id,
            };
            groups_len++;
        }

        group = &groups[groups_len - 1];
        group->active += sorted[i].val.active;
        group->passive += sorted[i].val.passive;
        group->last_family = sorted[i].val.last_family;
        group->last_remote_port = sorted[i].val.last_remote_port;
        group->last_remote_addr_v4 = sorted[i].val.last_remote_addr_v4;
        memcpy(group->last_remote_addr_v6,
               sorted[i].val.last_remote_addr_v6,
               sizeof(group->last_remote_addr_v6));
    }

    free(sorted);
    *out_groups = groups;
    *out_len = groups_len;
    return 0;
}

static void print_prometheus_cgroup(const struct cgroup_row *groups, size_t groups_len)
{
    printf("# TYPE tcpconn_established_total counter\n");

    for (size_t i = 0; i < groups_len; i++) {
        unsigned long long total = groups[i].active + groups[i].passive;

        if (!total)
            continue;

        printf("tcpconn_established_total{direction=\"active\",cgroup_id=\"%llu\"} %llu\n",
               groups[i].cgroup_id,
               groups[i].active);
        printf("tcpconn_established_total{direction=\"passive\",cgroup_id=\"%llu\"} %llu\n",
               groups[i].cgroup_id,
               groups[i].passive);
        printf("tcpconn_established_total{direction=\"total\",cgroup_id=\"%llu\"} %llu\n",
               groups[i].cgroup_id,
               total);
    }
}

static void print_cgroup_table(const struct cgroup_row *groups, size_t groups_len)
{
    print_time_header();

    printf("%-20s %-12s %-12s %-12s %-48s\n",
           "CGROUP_ID", "ACTIVE", "PASSIVE", "TOTAL", "LAST_REMOTE");

    for (size_t i = 0; i < groups_len; i++) {
        char remote[80];
        unsigned long long total = groups[i].active + groups[i].passive;

        if (!total)
            continue;

        format_remote_from_cgroup(&groups[i], remote, sizeof(remote));

        printf("%-20llu %-12llu %-12llu %-12llu %-48s\n",
               groups[i].cgroup_id,
               groups[i].active,
               groups[i].passive,
               total,
               remote);
    }
}

static void print_counts(int map_fd, const struct options *opts)
{
    struct row *rows = NULL;
    size_t rows_len = 0;

    if (collect_rows(map_fd, &rows, &rows_len)) {
        fprintf(stderr, "failed to read counts map\n");
        return;
    }

    if (opts->group_by == GROUP_BY_CGROUP) {
        struct cgroup_row *groups = NULL;
        size_t groups_len = 0;

        if (build_cgroup_rows(rows, rows_len, &groups, &groups_len)) {
            fprintf(stderr, "failed to aggregate cgroup rows\n");
            free(rows);
            return;
        }

        qsort(groups, groups_len, sizeof(*groups), cmp_cgroup_total_desc);

        if (opts->prometheus)
            print_prometheus_cgroup(groups, groups_len);
        else
            print_cgroup_table(groups, groups_len);

        free(groups);
        free(rows);
        return;
    }

    qsort(rows, rows_len, sizeof(*rows), cmp_row_total_desc);

    if (opts->prometheus)
        print_prometheus_pid(rows, rows_len);
    else
        print_pid_table(rows, rows_len);

    free(rows);
}

static void print_event(const struct conn_event *event)
{
    time_t now = time(NULL);
    struct tm tm;
    char ts[32];
    char comm[COMM_LEN + 1] = {};
    char local[80];
    char remote[80];
    const char *type = event->type == TCPCONN_EVENT_ACTIVE ? "active" : "passive";

    localtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%F %T", &tm);

    memcpy(comm, event->comm, COMM_LEN);
    format_event_endpoint(event, false, local, sizeof(local));
    format_event_endpoint(event, true, remote, sizeof(remote));

    printf("%s %-7s pid=%u comm=%s cgroup=%llu %s -> %s\n",
           ts,
           type,
           event->tgid,
           comm,
           event->cgroup_id,
           local,
           remote);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct conn_event *event = data;

    (void)ctx;

    if (data_sz < sizeof(*event))
        return 0;

    print_event(event);
    return 0;
}

static void build_bpf_config(const struct options *opts, struct tcpconn_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));

    if (opts->has_pid) {
        cfg->target_tgid = opts->pid;
        cfg->flags |= TCPCONN_CFG_HAS_PID;
    }

    if (opts->has_comm) {
        memcpy(cfg->target_comm, opts->comm, COMM_LEN);
        cfg->flags |= TCPCONN_CFG_HAS_COMM;
    }

    if (opts->active_only)
        cfg->flags |= TCPCONN_CFG_ACTIVE_ONLY;
    if (opts->passive_only)
        cfg->flags |= TCPCONN_CFG_PASSIVE_ONLY;
    if (opts->events)
        cfg->flags |= TCPCONN_CFG_EMIT_EVENTS;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [options]\n"
            "\n"
            "Options:\n"
            "  -i, --interval SEC     Output interval, default 2\n"
            "  -p, --pid PID          Only count this process PID\n"
            "  -c, --comm COMM        Only count this task comm, max 15 bytes\n"
            "      --active-only      Only count active TCP connects\n"
            "      --passive-only     Only count passive accepts\n"
            "      --events           Print one line per established connection\n"
            "      --prometheus       Print Prometheus text metrics instead of tables\n"
            "      --group-by MODE    Aggregate by pid or cgroup, default pid\n"
            "      --cleanup          Delete count rows for exited PIDs each interval\n"
            "  -h, --help             Show this help\n"
            "\n"
            "Examples:\n"
            "  sudo %s -i 2\n"
            "  sudo %s --events --comm curl\n"
            "  sudo %s --group-by cgroup --prometheus\n",
            prog, prog, prog, prog);
}

static int parse_args(int argc, char **argv, struct options *opts)
{
    static const struct option long_options[] = {
        {"interval", required_argument, NULL, 'i'},
        {"pid", required_argument, NULL, 'p'},
        {"comm", required_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
        {"active-only", no_argument, NULL, OPT_ACTIVE_ONLY},
        {"passive-only", no_argument, NULL, OPT_PASSIVE_ONLY},
        {"events", no_argument, NULL, OPT_EVENTS},
        {"prometheus", no_argument, NULL, OPT_PROMETHEUS},
        {"group-by", required_argument, NULL, OPT_GROUP_BY},
        {"cleanup", no_argument, NULL, OPT_CLEANUP},
        {},
    };
    int opt;

    *opts = (struct options){
        .interval = 2,
        .group_by = GROUP_BY_PID,
    };

    while ((opt = getopt_long(argc, argv, "i:p:c:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'i': {
            unsigned int interval;

            if (parse_uint(optarg, &interval, "interval"))
                return -1;
            opts->interval = (int)interval;
            if (opts->interval <= 0)
                opts->interval = 2;
            break;
        }
        case 'p':
            if (parse_uint(optarg, &opts->pid, "pid"))
                return -1;
            opts->has_pid = true;
            break;
        case 'c':
            if (strlen(optarg) >= COMM_LEN) {
                fprintf(stderr, "comm is too long, max %d bytes: %s\n",
                        COMM_LEN - 1,
                        optarg);
                return -1;
            }
            memcpy(opts->comm, optarg, strlen(optarg) + 1);
            opts->has_comm = true;
            break;
        case OPT_ACTIVE_ONLY:
            opts->active_only = true;
            break;
        case OPT_PASSIVE_ONLY:
            opts->passive_only = true;
            break;
        case OPT_EVENTS:
            opts->events = true;
            break;
        case OPT_PROMETHEUS:
            opts->prometheus = true;
            break;
        case OPT_GROUP_BY:
            if (strcmp(optarg, "pid") == 0) {
                opts->group_by = GROUP_BY_PID;
            } else if (strcmp(optarg, "cgroup") == 0) {
                opts->group_by = GROUP_BY_CGROUP;
            } else {
                fprintf(stderr, "invalid group mode: %s\n", optarg);
                return -1;
            }
            break;
        case OPT_CLEANUP:
            opts->cleanup = true;
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            return -1;
        }
    }

    if (opts->active_only && opts->passive_only) {
        fprintf(stderr, "--active-only and --passive-only cannot be combined\n");
        return -1;
    }

    if (opts->events && opts->prometheus) {
        fprintf(stderr, "--events and --prometheus cannot be combined on stdout\n");
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct tcpconn_count_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    struct options opts;
    struct tcpconn_config cfg;
    unsigned int zero = 0;
    int counts_fd;
    int err = 0;
    time_t next_print;

    if (parse_args(argc, argv, &opts))
        return 1;

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

    build_bpf_config(&opts, &cfg);
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.config_map),
                              &zero,
                              &cfg,
                              BPF_ANY);
    if (err) {
        fprintf(stderr, "failed to update config map: %s\n", strerror(errno));
        goto cleanup;
    }

    err = tcpconn_count_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    if (opts.events) {
        rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                              handle_event,
                              NULL,
                              NULL);
        if (!rb) {
            err = -errno;
            fprintf(stderr, "failed to create ring buffer: %s\n", strerror(errno));
            goto cleanup;
        }
    }

    counts_fd = bpf_map__fd(skel->maps.counts);

    if (!opts.prometheus)
        printf("Tracing TCP connection establishments. Press Ctrl-C to exit.\n");

    next_print = time(NULL) + opts.interval;

    while (!exiting) {
        time_t now;

        if (rb) {
            err = ring_buffer__poll(rb, 100);
            if (err == -EINTR) {
                err = 0;
                break;
            }
            if (err < 0) {
                fprintf(stderr, "error polling ring buffer: %d\n", err);
                break;
            }
        } else {
            sleep(1);
        }

        now = time(NULL);
        if (now < next_print)
            continue;

        if (opts.cleanup) {
            int deleted = cleanup_dead_pids(counts_fd);

            if (deleted < 0)
                fprintf(stderr, "failed to clean exited PID rows\n");
        }

        print_counts(counts_fd, &opts);
        next_print = now + opts.interval;
    }

cleanup:
    ring_buffer__free(rb);
    tcpconn_count_bpf__destroy(skel);
    return err < 0 ? -err : err;
}
