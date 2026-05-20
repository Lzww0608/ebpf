#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "rm_monitor_format.h"
#include "rm_monitor.h"
#include "rm_monitor.skel.h"

#define PROC_CMDLINE_LEN 4096

static volatile sig_atomic_t exiting = 0;
static bool only_rm = true;
static unsigned long long total_events;
static unsigned long long success_events;
static unsigned long long failure_events;
static unsigned long long unlink_success_events;
static unsigned long long unlink_failure_events;
static unsigned long long rmdir_success_events;
static unsigned long long rmdir_failure_events;

static void sig_handler(int sig) {
    (void)sig;
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

static const char *path_or_dash(const char *path) {
    return path && path[0] ? path : "-";
}

static void append_truncation_marker(char *buf, size_t buf_len) {
    size_t len = strlen(buf);

    if (len + 5 < buf_len)
        strcat(buf, " ...");
}

static unsigned int read_proc_cmdline(unsigned int pid, char *buf, size_t buf_len) {
    char path[64];
    FILE *file;
    size_t nread;

    if (!buf_len)
        return 0;

    buf[0] = '\0';
    snprintf(path, sizeof(path), "/proc/%u/cmdline", pid);

    file = fopen(path, "rb");
    if (!file)
        return 0;

    nread = fread(buf, 1, buf_len - 1, file);
    fclose(file);

    if (!nread)
        return 0;

    buf[nread] = '\0';
    return (unsigned int)nread;
}

static void update_stats(const struct event *e) {
    bool success = e->ret == 0;

    total_events++;
    if (success)
        success_events++;
    else
        failure_events++;

    if (e->op == OP_RMDIR) {
        if (success)
            rmdir_success_events++;
        else
            rmdir_failure_events++;
        return;
    }

    if (success)
        unlink_success_events++;
    else
        unlink_failure_events++;
}

static void print_summary(void) {
    fprintf(stderr,
            "\nsummary: total=%llu success=%llu fail=%llu "
            "unlink_ok=%llu unlink_fail=%llu rmdir_ok=%llu rmdir_fail=%llu\n",
            total_events,
            success_events,
            failure_events,
            unlink_success_events,
            unlink_failure_events,
            rmdir_success_events,
            rmdir_failure_events);
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    char proc_cmdline[PROC_CMDLINE_LEN];
    char cmdline[PROC_CMDLINE_LEN + 16];
    char resolved_path[RM_MONITOR_RESOLVED_PATH_LEN + RM_MONITOR_NAME_LEN + 2];
    const char *err_text = "-";
    const char *cmdline_src;
    unsigned int cmdline_len;
    unsigned int proc_cmdline_len;
    bool cmdline_truncated;
    int err_no;

    (void)ctx;

    if (data_sz < sizeof(*e))
        return 0;

    if (only_rm && strcmp(e->comm, "rm") != 0)
        return 0;

    cmdline_src = e->cmdline;
    cmdline_len = e->cmdline_len;
    cmdline_truncated = (e->event_flags & EVENT_F_CMDLINE_TRUNCATED) != 0;

    update_stats(e);
    proc_cmdline_len = read_proc_cmdline(e->tgid,
                                         proc_cmdline,
                                         sizeof(proc_cmdline));
    if (proc_cmdline_len > 0) {
        cmdline_src = proc_cmdline;
        cmdline_len = proc_cmdline_len;
        cmdline_truncated = proc_cmdline_len == sizeof(proc_cmdline) - 1;
    }

    rm_monitor_format_cmdline(cmdline,
                              sizeof(cmdline),
                              cmdline_src,
                              cmdline_len,
                              e->comm);

    if (cmdline_truncated)
        append_truncation_marker(cmdline, sizeof(cmdline));

    rm_monitor_format_resolved_path(resolved_path, sizeof(resolved_path), e);

    err_no = rm_monitor_errno(e->ret);
    if (err_no)
        err_text = strerror(err_no);

    time_t now = time(NULL);
    struct tm tm;
    char ts[32];

    localtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%F %T", &tm);

    printf("%s pid=%u tid=%u uid=%u comm=%s op=%s result=%s ret=%ld errno=%d(%s) "
           "dfd=%d flags=0x%x lsm=%s lsm_ret=%d path=\"%s\" resolved=\"%s\" cmdline=\"%s\"\n",
           ts,
           e->tgid,
           e->tid,
           e->uid,
           e->comm,
           op_to_str(e->op),
           rm_monitor_status(e->ret),
           e->ret,
           err_no,
           err_text,
           e->dfd,
           e->flags,
           (e->event_flags & EVENT_F_LSM_SEEN) ? "yes" : "no",
           e->lsm_ret,
           path_or_dash(e->path),
           path_or_dash(resolved_path),
           cmdline);

    return 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [--all]\n"
            "\n"
            "  default : only show delete attempts from comm == \"rm\"\n"
            "  --all   : show delete attempts from all processes\n",
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

    printf("Monitoring delete attempts. Press Ctrl-C to stop.\n");

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
    if (total_events)
        print_summary();
    ring_buffer__free(rb);
    rm_monitor_bpf__destroy(skel);
    return err < 0 ? -err : err;
}
