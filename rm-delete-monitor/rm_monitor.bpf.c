#include "vmlinux.h"
#include "rm_monitor.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define AT_REMOVEDIR 0x200

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

static __always_inline int trace_enter_delete(
    const char *pathname,
    int dfd,
    int flags,
    unsigned char op
) {
    if (!pathname)
        return 0;

    unsigned long long key = bpf_get_current_pid_tgid();

    struct event e = {};
    e.ts_ns = bpf_ktime_get_ns();
    e.tgid = key >> 32;
    e.tid = (unsigned int)key;
    e.uid = (unsigned int)bpf_get_current_uid_gid();
    e.dfd = dfd;
    e.flags = flags;
    e.op = op;

    bpf_get_current_comm(e.comm, sizeof(e.comm));

    if (bpf_probe_read_user_str(e.path, sizeof(e.path), pathname) < 0)
        return 0;

    bpf_map_update_elem(&inflight, &key, &e, BPF_ANY);
    return 0;
}

static __always_inline int trace_exit_delete(struct trace_event_raw_sys_exit *ctx) {
    unsigned long long key = bpf_get_current_pid_tgid();

    struct event *e = bpf_map_lookup_elem(&inflight, &key);
    if (!e)
        return 0;

    e->ret = ctx->ret;

    if (ctx->ret == 0) {
        bpf_ringbuf_output(&events, e, sizeof(*e), 0);
    }

    bpf_map_delete_elem(&inflight, &key);
    return 0;
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
    return trace_enter_delete(pathname, -100, 0, OP_UNLINK);
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int handle_exit_unlink(struct trace_event_raw_sys_exit *ctx) {
    return trace_exit_delete(ctx);
}

SEC("tracepoint/syscalls/sys_enter_rmdir")
int handle_enter_rmdir(struct trace_event_raw_sys_enter *ctx) {
    const char *pathname = (const char *)ctx->args[0];
    return trace_enter_delete(pathname, -100, AT_REMOVEDIR, OP_RMDIR);
}

SEC("tracepoint/syscalls/sys_exit_rmdir")
int handle_exit_rmdir(struct trace_event_raw_sys_exit *ctx) {
    return trace_exit_delete(ctx);
}