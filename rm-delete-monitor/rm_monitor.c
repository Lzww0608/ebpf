#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "rm_monitor.h"
#include "rm_monitor.skel.h"

static volatile sig_atomic_t exiting = 0;
static bool only_rm = true;

static void sig_handler(int sig) {
    exiting = 1;
}

static int bump_memlock_rlimit(void) {
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    return setrlimit(RLIMIT_MEMLOCK, &rlim);
}

static const char *op_to_str(unsigned char op) {
    switch (op) {
    case OP_UNLINK:
        return "unlink";
    case OP_RMDIR:
        return "rmdir";
    default:
        return "unknown";
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;

    if (only_rm && strcmp(e->comm, "rm") != 0)
        return 0;

    time_t now = time(NULL);
    struct tm tm;
    char ts[32];

    localtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%F %T", &tm);

    printf("%-19s  %-7u %-7u %-6u %-16s %-8s %s\n",
           ts,
           e->tgid,
           e->tid,
           e->uid,
           e->comm,
           op_to_str(e->op),
           e->path);

    return 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [--all]\n"
            "\n"
            "  default : only show delete events from comm == \"rm\"\n"
            "  --all   : show delete events from all processes\n",
            prog);
}

int main(int argc, char **argv) {
    struct rm_monitor_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    if (argc == 2 && strcmp(argv[1], "--all") == 0) {
        only_rm = false;
    } else if (argc > 1) {
        usage(argv[0]);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (bump_memlock_rlimit()) {
        fprintf(stderr, "failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
        return 1;
    }

    skel = rm_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open and load BPF skeleton\n");
        return 1;
    }

    err = rm_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        NULL,
        NULL
    );

    if (!rb) {
        err = -errno;
        fprintf(stderr, "failed to create ring buffer: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("%-19s  %-7s %-7s %-6s %-16s %-8s %s\n",
           "TIME", "TGID", "TID", "UID", "COMM", "OP", "PATH");

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
    rm_monitor_bpf__destroy(skel);
    return err < 0 ? -err : err;
}