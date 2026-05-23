#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "killmon.h"
#include "killmon.skel.h"

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

static const char *sig_name(int sig)
{
    switch (sig) {
    case 1:
        return "SIGHUP";
    case 2:
        return "SIGINT";
    case 3:
        return "SIGQUIT";
    case 4:
        return "SIGILL";
    case 5:
        return "SIGTRAP";
    case 6:
        return "SIGABRT";
    case 7:
        return "SIGBUS";
    case 8:
        return "SIGFPE";
    case 9:
        return "SIGKILL";
    case 10:
        return "SIGUSR1";
    case 11:
        return "SIGSEGV";
    case 12:
        return "SIGUSR2";
    case 13:
        return "SIGPIPE";
    case 14:
        return "SIGALRM";
    case 15:
        return "SIGTERM";
    case 16:
        return "SIGSTKFLT";
    case 17:
        return "SIGCHLD";
    case 18:
        return "SIGCONT";
    case 19:
        return "SIGSTOP";
    case 20:
        return "SIGTSTP";
    case 21:
        return "SIGTTIN";
    case 22:
        return "SIGTTOU";
    case 23:
        return "SIGURG";
    case 24:
        return "SIGXCPU";
    case 25:
        return "SIGXFSZ";
    case 26:
        return "SIGVTALRM";
    case 27:
        return "SIGPROF";
    case 28:
        return "SIGWINCH";
    case 29:
        return "SIGIO";
    case 30:
        return "SIGPWR";
    case 31:
        return "SIGSYS";
    default:
        if (sig >= 32 && sig <= 64)
            return "SIGRT";
        return "UNKNOWN";
    }
}

static void fmt_time(char *buf, size_t len, time_t sec)
{
    struct tm tm;

    localtime_r(&sec, &tm);
    strftime(buf, len, "%F %T", &tm);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    char sender_comm[TASK_COMM_LEN + 1] = {};
    char comm[TASK_COMM_LEN + 1] = {};
    char ts[32];
    time_t now;

    (void)ctx;

    if (data_sz < sizeof(*e))
        return 0;

    now = time(NULL);
    fmt_time(ts, sizeof(ts), now);

    memcpy(comm, e->comm, TASK_COMM_LEN);
    memcpy(sender_comm, e->sender_comm, TASK_COMM_LEN);

    if (e->has_sender) {
        printf("%-19s %-7u %-7u %-7u %-6u %-16s %-10s %-5s %-11u %-16s\n",
               ts,
               e->pid,
               e->tid,
               e->ppid,
               e->uid,
               comm,
               sig_name(e->sig),
               e->core_dumped ? "yes" : "no",
               e->sender_tgid,
               sender_comm);
    } else {
        printf("%-19s %-7u %-7u %-7u %-6u %-16s %-10s %-5s %-11s %-16s\n",
               ts,
               e->pid,
               e->tid,
               e->ppid,
               e->uid,
               comm,
               sig_name(e->sig),
               e->core_dumped ? "yes" : "no",
               "-",
               "-");
    }

    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [--pid PID] [--per-thread]\n"
            "\n"
            "Options:\n"
            "  --pid PID       only trace this process PID\n"
            "  --per-thread    record killed threads instead of only process leaders\n"
            "\n"
            "Examples:\n"
            "  sudo %s\n"
            "  sudo %s --pid 1234\n"
            "  sudo %s --per-thread\n",
            prog,
            prog,
            prog,
            prog);
}

int main(int argc, char **argv)
{
    static const struct option long_options[] = {
        {"pid", required_argument, NULL, 'p'},
        {"per-thread", no_argument, NULL, 't'},
        {"help", no_argument, NULL, 'h'},
        {},
    };
    struct killmon_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    bool per_thread = false;
    int pid_filter = 0;
    int err = 0;
    int opt;

    while ((opt = getopt_long(argc, argv, "p:th", long_options, NULL)) != -1) {
        switch (opt) {
        case 'p':
            pid_filter = atoi(optarg);
            if (pid_filter <= 0) {
                fprintf(stderr, "invalid --pid value: %s\n", optarg);
                return 1;
            }
            break;
        case 't':
            per_thread = true;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (bump_memlock_rlimit()) {
        fprintf(stderr, "failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
        return 1;
    }

    skel = killmon_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    skel->rodata->target_pid = pid_filter;
    skel->rodata->per_thread = per_thread;

    err = killmon_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = killmon_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                          handle_event,
                          NULL,
                          NULL);
    if (!rb) {
        err = -errno;
        fprintf(stderr, "failed to create ring buffer: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("%-19s %-7s %-7s %-7s %-6s %-16s %-10s %-5s %-11s %-16s\n",
           "TIME",
           "PID",
           "TID",
           "PPID",
           "UID",
           "COMM",
           "SIG",
           "CORE",
           "KILLER_PID",
           "KILLER_COMM");

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
    killmon_bpf__destroy(skel);
    return err < 0 ? -err : err;
}
