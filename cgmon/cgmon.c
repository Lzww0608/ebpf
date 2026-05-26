#define _GNU_SOURCE

#include "cgmon.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CGMON_UNIT_TEST
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "cgmon.skel.h"
#endif

#define MAX_CGROUPS 8192
#define CGROUP_ROOT "/sys/fs/cgroup"
#define CGROUP_HANDLE_MAX 128

struct cg_info {
    unsigned long long id;
    char path[MAX_PATH_LEN];
    char name[MAX_NAME_LEN];

    unsigned long long mem_current;
    unsigned long long cpu_usage_usec;

    unsigned long long io_rbytes;
    unsigned long long io_wbytes;
};

struct prev_sample {
    unsigned long long id;

    unsigned long long bpf_cpu_ns;
    unsigned long long bpf_read_bytes;
    unsigned long long bpf_write_bytes;

    unsigned long long io_rbytes;
    unsigned long long io_wbytes;
};

struct cg_row {
    struct cg_info cg;
    double cpu_pct;
    double mem_mb;
    double io_r_mbs;
    double io_w_mbs;
    double sys_r_mbs;
    double sys_w_mbs;
};

#ifndef CGMON_UNIT_TEST
static volatile sig_atomic_t exiting;
static struct prev_sample prevs[MAX_CGROUPS];
static int prev_count;
static struct cg_info cg_items[MAX_CGROUPS];
static struct cg_row cg_rows[MAX_CGROUPS];

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

static int read_ull_file(const char *path, unsigned long long *value)
{
    FILE *f;
    unsigned long long v = 0;
    int ret;

    f = fopen(path, "r");
    if (!f)
        return -1;

    ret = fscanf(f, "%llu", &v);
    fclose(f);

    if (ret != 1)
        return -1;

    *value = v;
    return 0;
}

static int read_cpu_stat(const char *cgpath, unsigned long long *usage_usec)
{
    char file[PATH_MAX];
    FILE *f;
    char key[128];
    unsigned long long val;
    int n;

    n = snprintf(file, sizeof(file), "%s/cpu.stat", cgpath);
    if (n < 0 || (size_t)n >= sizeof(file))
        return -1;

    f = fopen(file, "r");
    if (!f)
        return -1;

    *usage_usec = 0;

    while (fscanf(f, "%127s %llu", key, &val) == 2) {
        if (strcmp(key, "usage_usec") == 0) {
            *usage_usec = val;
            fclose(f);
            return 0;
        }
    }

    fclose(f);
    return -1;
}
#endif

static int cgmon_is_hex_id(const char *s)
{
    int n = 0;

    if (!s || !*s)
        return 0;

    while (*s) {
        char c = *s++;

        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return 0;

        n++;
    }

    return n >= 12;
}

static const char *cgmon_base_name(const char *path)
{
    const char *p;

    if (!path)
        return "";

    p = strrchr(path, '/');
    return p ? p + 1 : path;
}

static bool cgmon_looks_like_container_cgroup(const char *path)
{
    const char *b;

    if (!path)
        return false;

    if (strstr(path, "docker-") && strstr(path, ".scope"))
        return true;

    if (strstr(path, "cri-containerd-") && strstr(path, ".scope"))
        return true;

    if (strstr(path, "containerd-") && strstr(path, ".scope"))
        return true;

    if (strstr(path, "libpod-") && strstr(path, ".scope"))
        return true;

    if (strstr(path, "/kubepods"))
        return true;

    b = cgmon_base_name(path);
    if (cgmon_is_hex_id(b))
        return true;

    return false;
}

static void cgmon_extract_name(const char *path, char *out, size_t out_len)
{
    const char *b = cgmon_base_name(path);
    char tmp[MAX_NAME_LEN];
    char *scope;

    if (out_len == 0)
        return;

    if (strncmp(b, "docker-", 7) == 0)
        b += 7;
    else if (strncmp(b, "cri-containerd-", 15) == 0)
        b += 15;
    else if (strncmp(b, "containerd-", 11) == 0)
        b += 11;
    else if (strncmp(b, "libpod-", 7) == 0)
        b += 7;

    snprintf(tmp, sizeof(tmp), "%s", b);

    scope = strstr(tmp, ".scope");
    if (scope)
        *scope = '\0';

    if (strlen(tmp) > 12 && cgmon_is_hex_id(tmp))
        tmp[12] = '\0';

    snprintf(out, out_len, "%s", tmp);
}

static void cgmon_parse_io_stat_line(const char *line,
                                     unsigned long long *rbytes,
                                     unsigned long long *wbytes)
{
    char buf[2048];
    char *tok;

    if (!line)
        return;

    snprintf(buf, sizeof(buf), "%s", line);

    tok = strtok(buf, " \n");
    while (tok) {
        unsigned long long val;

        if (sscanf(tok, "rbytes=%llu", &val) == 1)
            *rbytes += val;
        else if (sscanf(tok, "wbytes=%llu", &val) == 1)
            *wbytes += val;

        tok = strtok(NULL, " \n");
    }
}

#ifndef CGMON_UNIT_TEST
static int read_io_stat(const char *cgpath,
                        unsigned long long *rbytes,
                        unsigned long long *wbytes)
{
    char file[PATH_MAX];
    FILE *f;
    char line[2048];
    int n;

    n = snprintf(file, sizeof(file), "%s/io.stat", cgpath);
    if (n < 0 || (size_t)n >= sizeof(file))
        return -1;

    f = fopen(file, "r");
    if (!f)
        return -1;

    *rbytes = 0;
    *wbytes = 0;

    while (fgets(line, sizeof(line), f))
        cgmon_parse_io_stat_line(line, rbytes, wbytes);

    fclose(f);
    return 0;
}

static int read_cgroup_id(const char *path, unsigned long long *id)
{
    struct {
        struct file_handle handle;
        unsigned char bytes[CGROUP_HANDLE_MAX];
    } fh = {};
    int mount_id = 0;
    struct stat st;

    fh.handle.handle_bytes = sizeof(fh.bytes);

    if (name_to_handle_at(AT_FDCWD, path, &fh.handle, &mount_id, 0) == 0 &&
        fh.handle.handle_bytes >= sizeof(*id)) {
        memcpy(id, fh.handle.f_handle, sizeof(*id));
        return 0;
    }

    if (stat(path, &st) == 0) {
        *id = (unsigned long long)st.st_ino;
        return 0;
    }

    return -1;
}

static int collect_cgroup(const char *path,
                          struct cg_info *items,
                          int *count,
                          bool all_cgroups)
{
    char memfile[PATH_MAX];
    struct cg_info *it;
    int n;

    if (*count >= MAX_CGROUPS)
        return 0;

    if (!all_cgroups && !cgmon_looks_like_container_cgroup(path))
        return 0;

    it = &items[*count];
    memset(it, 0, sizeof(*it));

    if (read_cgroup_id(path, &it->id) != 0)
        return 0;

    snprintf(it->path, sizeof(it->path), "%s", path);
    cgmon_extract_name(path, it->name, sizeof(it->name));

    n = snprintf(memfile, sizeof(memfile), "%s/memory.current", path);
    if (n >= 0 && (size_t)n < sizeof(memfile))
        read_ull_file(memfile, &it->mem_current);

    read_cpu_stat(path, &it->cpu_usage_usec);
    read_io_stat(path, &it->io_rbytes, &it->io_wbytes);

    (*count)++;
    return 0;
}

static int scan_cgroups_recursive(const char *root,
                                  struct cg_info *items,
                                  int *count,
                                  bool all_cgroups)
{
    DIR *dir;
    struct dirent *de;

    if (*count >= MAX_CGROUPS)
        return 0;

    collect_cgroup(root, items, count, all_cgroups);

    dir = opendir(root);
    if (!dir)
        return -1;

    while ((de = readdir(dir)) != NULL) {
        char child[PATH_MAX];
        struct stat st;
        int n;

        if (de->d_name[0] == '.')
            continue;

        n = snprintf(child, sizeof(child), "%s/%s", root, de->d_name);
        if (n < 0 || (size_t)n >= sizeof(child))
            continue;

        if (lstat(child, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;

        scan_cgroups_recursive(child, items, count, all_cgroups);

        if (*count >= MAX_CGROUPS)
            break;
    }

    closedir(dir);
    return 0;
}

static struct prev_sample *find_prev(unsigned long long id)
{
    struct prev_sample *p;

    for (int i = 0; i < prev_count; i++) {
        if (prevs[i].id == id)
            return &prevs[i];
    }

    if (prev_count >= MAX_CGROUPS)
        return NULL;

    p = &prevs[prev_count++];
    memset(p, 0, sizeof(*p));
    p->id = id;

    return p;
}

static int cmp_row_desc(const void *a, const void *b)
{
    const struct cg_row *ra = a;
    const struct cg_row *rb = b;

    if (ra->cpu_pct < rb->cpu_pct)
        return 1;
    if (ra->cpu_pct > rb->cpu_pct)
        return -1;

    if (ra->mem_mb < rb->mem_mb)
        return 1;
    if (ra->mem_mb > rb->mem_mb)
        return -1;

    return 0;
}

static void add_snapshot_row(const struct cg_info *cg,
                             const struct cg_stats *st,
                             struct prev_sample *prev,
                             int interval_sec,
                             struct cg_row *row)
{
    unsigned long long delta_cpu_ns = 0;
    unsigned long long delta_sys_r = 0;
    unsigned long long delta_sys_w = 0;
    unsigned long long delta_io_r = 0;
    unsigned long long delta_io_w = 0;

    memset(row, 0, sizeof(*row));
    row->cg = *cg;

    if (st->cpu_ns >= prev->bpf_cpu_ns)
        delta_cpu_ns = st->cpu_ns - prev->bpf_cpu_ns;

    if (st->read_bytes >= prev->bpf_read_bytes)
        delta_sys_r = st->read_bytes - prev->bpf_read_bytes;

    if (st->write_bytes >= prev->bpf_write_bytes)
        delta_sys_w = st->write_bytes - prev->bpf_write_bytes;

    if (cg->io_rbytes >= prev->io_rbytes)
        delta_io_r = cg->io_rbytes - prev->io_rbytes;

    if (cg->io_wbytes >= prev->io_wbytes)
        delta_io_w = cg->io_wbytes - prev->io_wbytes;

    prev->bpf_cpu_ns = st->cpu_ns;
    prev->bpf_read_bytes = st->read_bytes;
    prev->bpf_write_bytes = st->write_bytes;
    prev->io_rbytes = cg->io_rbytes;
    prev->io_wbytes = cg->io_wbytes;

    row->cpu_pct = ((double)delta_cpu_ns /
                    ((double)interval_sec * 1000000000.0)) * 100.0;
    row->mem_mb = (double)cg->mem_current / 1024.0 / 1024.0;
    row->io_r_mbs = (double)delta_io_r / 1024.0 / 1024.0 / interval_sec;
    row->io_w_mbs = (double)delta_io_w / 1024.0 / 1024.0 / interval_sec;
    row->sys_r_mbs = (double)delta_sys_r / 1024.0 / 1024.0 / interval_sec;
    row->sys_w_mbs = (double)delta_sys_w / 1024.0 / 1024.0 / interval_sec;
}

static bool row_is_idle(const struct cg_row *row)
{
    return row->cpu_pct == 0.0 &&
           row->mem_mb == 0.0 &&
           row->io_r_mbs == 0.0 &&
           row->io_w_mbs == 0.0 &&
           row->sys_r_mbs == 0.0 &&
           row->sys_w_mbs == 0.0;
}

static void print_snapshot(int map_fd,
                           int interval_sec,
                           bool all_cgroups,
                           int topn)
{
    int count = 0;
    int row_count = 0;
    char ts[32];
    int printed = 0;

    scan_cgroups_recursive(CGROUP_ROOT, cg_items, &count, all_cgroups);

    for (int i = 0; i < count && row_count < MAX_CGROUPS; i++) {
        struct cg_info *cg = &cg_items[i];
        struct cg_stats st = {};
        struct prev_sample *prev;

        bpf_map_lookup_elem(map_fd, &cg->id, &st);

        prev = find_prev(cg->id);
        if (!prev)
            continue;

        add_snapshot_row(cg, &st, prev, interval_sec, &cg_rows[row_count]);

        if (!all_cgroups && row_is_idle(&cg_rows[row_count]))
            continue;

        row_count++;
    }

    qsort(cg_rows, row_count, sizeof(cg_rows[0]), cmp_row_desc);

    fmt_time(ts, sizeof(ts));

    printf("\n%-19s %-14s %-16s %-8s %-9s %-10s %-10s %-11s %-11s\n",
           "TIME",
           "CGROUP_ID",
           "CONTAINER",
           "CPU%",
           "MEM(MB)",
           "IO_R(MB/s)",
           "IO_W(MB/s)",
           "SYS_R(MB/s)",
           "SYS_W(MB/s)");

    for (int i = 0; i < row_count; i++) {
        struct cg_row *row = &cg_rows[i];

        printf("%-19s %-14llu %-16s %-8.2f %-9.1f %-10.2f %-10.2f %-11.2f %-11.2f\n",
               ts,
               row->cg.id,
               row->cg.name[0] ? row->cg.name : "-",
               row->cpu_pct,
               row->mem_mb,
               row->io_r_mbs,
               row->io_w_mbs,
               row->sys_r_mbs,
               row->sys_w_mbs);

        printed++;
        if (topn > 0 && printed >= topn)
            break;
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-i SEC] [--all-cgroups] [--top N]\n"
            "\n"
            "Options:\n"
            "  -i, --interval SEC   print interval, default 2\n"
            "      --all-cgroups    show all cgroups, not only container-looking cgroups\n"
            "      --top N          show top N rows, default 20\n"
            "\n"
            "Examples:\n"
            "  sudo %s -i 2\n"
            "  sudo %s -i 1 --all-cgroups --top 30\n",
            prog, prog, prog);
}

int main(int argc, char **argv)
{
    struct cgmon_bpf *skel = NULL;
    int interval_sec = 2;
    int topn = 20;
    bool all_cgroups = false;
    int opt;
    int err = 0;
    int stats_fd;

    static const struct option long_options[] = {
        {"interval", required_argument, NULL, 'i'},
        {"all-cgroups", no_argument, NULL, 'a'},
        {"top", required_argument, NULL, 't'},
        {"help", no_argument, NULL, 'h'},
        {}
    };

    while ((opt = getopt_long(argc, argv, "i:t:ah", long_options, NULL)) != -1) {
        switch (opt) {
        case 'i':
            interval_sec = atoi(optarg);
            if (interval_sec <= 0)
                interval_sec = 2;
            break;
        case 't':
            topn = atoi(optarg);
            if (topn <= 0)
                topn = 20;
            break;
        case 'a':
            all_cgroups = true;
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

    skel = cgmon_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open and load BPF skeleton\n");
        return 1;
    }

    err = cgmon_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    stats_fd = bpf_map__fd(skel->maps.cg_stats_map);

    printf("cgmon started. interval=%ds top=%d all_cgroups=%s\n",
           interval_sec,
           topn,
           all_cgroups ? "yes" : "no");

    while (!exiting) {
        sleep(interval_sec);
        print_snapshot(stats_fd, interval_sec, all_cgroups, topn);
    }

cleanup:
    cgmon_bpf__destroy(skel);
    return err < 0 ? -err : err;
}
#endif
