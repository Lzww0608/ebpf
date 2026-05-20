#include "vmlinux.h"
#include "rm_monitor.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define AT_FDCWD -100
#define AT_REMOVEDIR 0x200
#define SET_PATH_LITERAL(dst, literal) __builtin_memcpy((dst), (literal), sizeof(literal))

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, unsigned long long);
    __type(value, struct event);
} inflight SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event);
} scratch_events SEC(".maps");

static __always_inline void reset_event(struct event *e) {
    e->ts_ns = 0;
    e->tgid = 0;
    e->tid = 0;
    e->uid = 0;
    e->event_flags = 0;
    e->cmdline_len = 0;
    e->dfd = 0;
    e->flags = 0;
    e->lsm_ret = 0;
    e->ret = 0;
    e->op = 0;
    e->comm[0] = '\0';
    e->path[0] = '\0';
    e->resolved_path[0] = '\0';
    e->cmdline[0] = '\0';
}

static __always_inline void read_current_cmdline(struct event *e) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct mm_struct *mm;
    unsigned long arg_start;
    unsigned long arg_end;
    unsigned long arg_len;
    unsigned int read_len;

    if (!task)
        return;

    mm = BPF_CORE_READ(task, mm);
    if (!mm)
        return;

    arg_start = BPF_CORE_READ(mm, arg_start);
    arg_end = BPF_CORE_READ(mm, arg_end);
    if (!arg_start || arg_end <= arg_start)
        return;

    arg_len = arg_end - arg_start;
    read_len = RM_MONITOR_CMDLINE_LEN - 1;
    if (arg_len < read_len)
        read_len = (unsigned int)arg_len;

    if (!read_len)
        return;

    if (arg_len >= RM_MONITOR_CMDLINE_LEN)
        e->event_flags |= EVENT_F_CMDLINE_TRUNCATED;

    if (bpf_probe_read_user(e->cmdline, read_len, (const void *)arg_start) == 0)
        e->cmdline_len = read_len;

    e->cmdline[RM_MONITOR_CMDLINE_LEN - 1] = '\0';
}

static __always_inline void read_user_path(struct event *e, const char *pathname) {
    if (!pathname) {
        SET_PATH_LITERAL(e->path, "<null>");
        return;
    }

    if (bpf_probe_read_user_str(e->path, sizeof(e->path), pathname) < 0)
        SET_PATH_LITERAL(e->path, "<unreadable>");
}

static __always_inline int trace_enter_delete(
    const char *pathname,
    int dfd,
    int flags,
    unsigned char op
) {
    unsigned long long key = bpf_get_current_pid_tgid();
    __u32 zero = 0;
    struct event *e;

    e = bpf_map_lookup_elem(&scratch_events, &zero);
    if (!e)
        return 0;

    reset_event(e);

    e->ts_ns = bpf_ktime_get_ns();
    e->tgid = key >> 32;
    e->tid = (unsigned int)key;
    e->uid = (unsigned int)bpf_get_current_uid_gid();
    e->dfd = dfd;
    e->flags = flags;
    e->op = op;

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    read_user_path(e, pathname);
    read_current_cmdline(e);

    bpf_map_update_elem(&inflight, &key, e, BPF_ANY);
    return 0;
}

static __always_inline int trace_exit_delete(struct trace_event_raw_sys_exit *ctx) {
    unsigned long long key = bpf_get_current_pid_tgid();

    struct event *e = bpf_map_lookup_elem(&inflight, &key);
    if (!e)
        return 0;

    e->ret = ctx->ret;
    bpf_ringbuf_output(&events, e, sizeof(*e), 0);

    bpf_map_delete_elem(&inflight, &key);
    return 0;
}

static __always_inline int trace_lsm_delete(
    const struct path *dir,
    struct dentry *dentry,
    unsigned char op,
    int ret
) {
    unsigned long long key = bpf_get_current_pid_tgid();
    struct event *e = bpf_map_lookup_elem(&inflight, &key);
    struct path target_path;
    long path_len;

    if (!e)
        return ret;

    e->event_flags |= EVENT_F_LSM_SEEN;
    e->lsm_ret = ret;
    e->op = op;

    if (!dir || !dentry)
        return ret;

    target_path.mnt = BPF_CORE_READ(dir, mnt);
    target_path.dentry = dentry;

    path_len = bpf_d_path(&target_path, e->resolved_path, sizeof(e->resolved_path));
    if (path_len > 0)
        e->event_flags |= EVENT_F_PATH_RESOLVED;

    return ret;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_enter_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    int dfd = (int)ctx->args[0];
    const char *pathname = (const char *)ctx->args[1];
    int flags = (int)ctx->args[2];

    unsigned char op = (flags & AT_REMOVEDIR) ? OP_RMDIR : OP_UNLINK;
    return trace_enter_delete(pathname, dfd, flags, op);
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int handle_exit_unlinkat(struct trace_event_raw_sys_exit *ctx) {
    return trace_exit_delete(ctx);
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int handle_enter_unlink(struct trace_event_raw_sys_enter *ctx) {
    const char *pathname = (const char *)ctx->args[0];
    return trace_enter_delete(pathname, AT_FDCWD, 0, OP_UNLINK);
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int handle_exit_unlink(struct trace_event_raw_sys_exit *ctx) {
    return trace_exit_delete(ctx);
}

SEC("tracepoint/syscalls/sys_enter_rmdir")
int handle_enter_rmdir(struct trace_event_raw_sys_enter *ctx) {
    const char *pathname = (const char *)ctx->args[0];
    return trace_enter_delete(pathname, AT_FDCWD, AT_REMOVEDIR, OP_RMDIR);
}

SEC("tracepoint/syscalls/sys_exit_rmdir")
int handle_exit_rmdir(struct trace_event_raw_sys_exit *ctx) {
    return trace_exit_delete(ctx);
}

SEC("lsm/path_unlink")
int BPF_PROG(handle_lsm_path_unlink, const struct path *dir, struct dentry *dentry, int ret) {
    return trace_lsm_delete(dir, dentry, OP_UNLINK, ret);
}

SEC("lsm/path_rmdir")
int BPF_PROG(handle_lsm_path_rmdir, const struct path *dir, struct dentry *dentry, int ret) {
    return trace_lsm_delete(dir, dentry, OP_RMDIR, ret);
}
