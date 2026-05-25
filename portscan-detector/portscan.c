#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "portscan.h"
#include "portscan.skel.h"

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

static int parse_uint_arg(const char *arg, unsigned int *out, const char *name)
{
    char *end = NULL;
    unsigned long value;

    errno = 0;
    value = strtoul(arg, &end, 10);
    if (errno || !end || *end || value == 0 || value > UINT_MAX) {
        fprintf(stderr, "invalid %s value: %s\n", name, arg);
        return -1;
    }

    *out = (unsigned int)value;
    return 0;
}

static int parse_ull_arg(const char *arg, unsigned long long *out, const char *name)
{
    char *end = NULL;
    unsigned long long value;

    errno = 0;
    value = strtoull(arg, &end, 10);
    if (errno || !end || *end || value == 0) {
        fprintf(stderr, "invalid %s value: %s\n", name, arg);
        return -1;
    }

    *out = value;
    return 0;
}

static void fmt_time(char *buf, size_t len)
{
    time_t now = time(NULL);
    struct tm tm;

    localtime_r(&now, &tm);
    strftime(buf, len, "%F %T", &tm);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct alert_event *e = data;
    struct in_addr addr = {
        .s_addr = e->src_ip,
    };
    char ts[32];
    char ip[INET_ADDRSTRLEN];
    double win_sec;

    (void)ctx;

    if (data_sz < sizeof(*e))
        return 0;

    fmt_time(ts, sizeof(ts));
    if (!inet_ntop(AF_INET, &addr, ip, sizeof(ip)))
        snprintf(ip, sizeof(ip), "unknown");

    win_sec = (double)e->window_ns / 1000000000.0;
    printf("%-19s %-8u %-15s %-6u %-10u %-9.0f %-9u\n",
           ts,
           e->ifindex,
           ip,
           e->distinct_ports,
           e->threshold_ports,
           win_sec,
           e->last_dport);

    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s -i IFACE [--ports N] [--window SEC] [--mode skb|drv] [--drop] [--force]\n"
            "\n"
            "Options:\n"
            "  -i, --iface IFACE     network interface, for example eth0\n"
            "  -p, --ports N         distinct destination ports threshold, default 20\n"
            "  -w, --window SEC      detection window in seconds, default 10\n"
            "  -m, --mode MODE       XDP mode: skb or drv, default skb\n"
            "      --drop            drop SYN packets from IP after alert in current window\n"
            "      --force           replace existing XDP program on this interface\n"
            "  -h, --help            show this help\n"
            "\n"
            "Examples:\n"
            "  sudo %s -i eth0 --ports 20 --window 10\n"
            "  sudo %s -i eth0 --ports 10 --window 5 --mode drv\n",
            prog, prog, prog);
}

int main(int argc, char **argv)
{
    struct portscan_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    const char *ifname = NULL;
    unsigned int ifindex;
    unsigned int ports = 20;
    unsigned long long window_sec = 10;
    unsigned int drop = 0;
    bool force = false;
    bool skb_mode = true;
    int opt;
    int err = 0;
    int prog_fd;
    unsigned int mode_flags = XDP_FLAGS_SKB_MODE;
    unsigned int attach_flags;

    static const struct option long_options[] = {
        {"iface", required_argument, NULL, 'i'},
        {"ports", required_argument, NULL, 'p'},
        {"window", required_argument, NULL, 'w'},
        {"mode", required_argument, NULL, 'm'},
        {"drop", no_argument, NULL, 'd'},
        {"force", no_argument, NULL, 'f'},
        {"help", no_argument, NULL, 'h'},
        {}
    };

    while ((opt = getopt_long(argc, argv, "i:p:w:m:dfh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'i':
            ifname = optarg;
            break;
        case 'p':
            if (parse_uint_arg(optarg, &ports, "--ports"))
                return 1;
            break;
        case 'w':
            if (parse_ull_arg(optarg, &window_sec, "--window"))
                return 1;
            break;
        case 'm':
            if (strcmp(optarg, "skb") == 0) {
                skb_mode = true;
                mode_flags = XDP_FLAGS_SKB_MODE;
            } else if (strcmp(optarg, "drv") == 0) {
                skb_mode = false;
                mode_flags = XDP_FLAGS_DRV_MODE;
            } else {
                fprintf(stderr, "invalid --mode: %s\n", optarg);
                return 1;
            }
            break;
        case 'd':
            drop = 1;
            break;
        case 'f':
            force = true;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (!ifname) {
        usage(argv[0]);
        return 1;
    }

    if (window_sec > ULLONG_MAX / 1000000000ULL) {
        fprintf(stderr, "--window is too large\n");
        return 1;
    }

    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "unknown interface %s: %s\n", ifname, strerror(errno));
        return 1;
    }

    attach_flags = mode_flags;
    if (!force)
        attach_flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;

    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (bump_memlock_rlimit()) {
        fprintf(stderr, "failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
        return 1;
    }

    skel = portscan_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    skel->rodata->threshold_ports = ports;
    skel->rodata->window_ns = window_sec * 1000000000ULL;
    skel->rodata->drop_after_alert = drop;

    err = portscan_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    prog_fd = bpf_program__fd(skel->progs.xdp_portscan_detector);
    if (prog_fd < 0) {
        fprintf(stderr, "failed to get XDP program fd\n");
        err = 1;
        goto cleanup;
    }

    err = bpf_xdp_attach(ifindex, prog_fd, attach_flags, NULL);
    if (err) {
        fprintf(stderr,
                "failed to attach XDP program to %s: %s\n"
                "hint: try --mode skb, or use --force if another XDP program is attached\n",
                ifname,
                strerror(-err));
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                          handle_event,
                          NULL,
                          NULL);
    if (!rb) {
        err = -errno;
        fprintf(stderr, "failed to create ring buffer: %s\n", strerror(errno));
        goto cleanup_detach;
    }

    printf("Monitoring %s ifindex=%u threshold=%u ports window=%llus mode=%s drop=%s\n",
           ifname,
           ifindex,
           ports,
           window_sec,
           skb_mode ? "skb" : "drv",
           drop ? "yes" : "no");

    printf("%-19s %-8s %-15s %-6s %-10s %-9s %-9s\n",
           "TIME",
           "IFINDEX",
           "SRC_IP",
           "PORTS",
           "THRESHOLD",
           "WINDOW(s)",
           "LAST_PORT");

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

cleanup_detach:
    bpf_xdp_detach(ifindex, mode_flags, NULL);

cleanup:
    ring_buffer__free(rb);
    portscan_bpf__destroy(skel);

    return err < 0 ? -err : err;
}
