//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_BUF 192
#define MAX_METHOD 8
#define MAX_PATH 96

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u32 target_tgid = 0;

struct io_args_t {
    __s32 fd;
    __u64 buf;
    __u64 count;
};

struct conn_key_t {
    __u32 tgid;
    __s32 fd;
};

struct req_ctx_t {
    __u64 start_ns;
    char method[MAX_METHOD];
    char path[MAX_PATH];
};

struct event {
    __u32 tgid;
    __u32 pid;
    __s32 fd;
    __u64 latency_ns;
    __u32 status;
    char comm[16];
    char method[MAX_METHOD];
    char path[MAX_PATH];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event);
} event_type_anchor SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct io_args_t);
} active_reads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct conn_key_t);
    __type(value, struct req_ctx_t);
} inflight SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int should_skip(void)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;

    if (target_tgid != 0 && tgid != target_tgid)
        return 1;

    return 0;
}

static __always_inline int method_len(char *d)
{
    if (d[0] == 'G' && d[1] == 'E' && d[2] == 'T' && d[3] == ' ')
        return 3;

    if (d[0] == 'P' && d[1] == 'O' && d[2] == 'S' && d[3] == 'T' && d[4] == ' ')
        return 4;

    if (d[0] == 'P' && d[1] == 'U' && d[2] == 'T' && d[3] == ' ')
        return 3;

    if (d[0] == 'D' && d[1] == 'E' && d[2] == 'L' && d[3] == 'E' &&
        d[4] == 'T' && d[5] == 'E' && d[6] == ' ')
        return 6;

    if (d[0] == 'P' && d[1] == 'A' && d[2] == 'T' && d[3] == 'C' &&
        d[4] == 'H' && d[5] == ' ')
        return 5;

    if (d[0] == 'H' && d[1] == 'E' && d[2] == 'A' && d[3] == 'D' && d[4] == ' ')
        return 4;

    return 0;
}

static __always_inline void copy_method_and_path(char *data, int mlen, struct req_ctx_t *req)
{
    if (mlen <= 0 || mlen > 6)
        return;

#pragma unroll
    for (int i = 0; i < MAX_METHOD; i++)
        req->method[i] = 0;

#pragma unroll
    for (int i = 0; i < MAX_METHOD - 1; i++) {
        if (i < mlen)
            req->method[i] = data[i];
    }
}

static __always_inline void copy_path_from_4(char *data, struct req_ctx_t *req)
{
#pragma unroll
    for (int i = 0; i < MAX_PATH - 1; i++) {
        char c = data[4 + i];
        if (c == ' ' || c == '?' || c == '\r' || c == '\n' || c == 0) {
            req->path[i] = 0;
            break;
        }

        req->path[i] = c;
    }

    req->path[MAX_PATH - 1] = 0;
}

static __always_inline void copy_path_from_5(char *data, struct req_ctx_t *req)
{
#pragma unroll
    for (int i = 0; i < MAX_PATH - 1; i++) {
        char c = data[5 + i];
        if (c == ' ' || c == '?' || c == '\r' || c == '\n' || c == 0) {
            req->path[i] = 0;
            break;
        }

        req->path[i] = c;
    }

    req->path[MAX_PATH - 1] = 0;
}

static __always_inline void copy_path_from_6(char *data, struct req_ctx_t *req)
{
#pragma unroll
    for (int i = 0; i < MAX_PATH - 1; i++) {
        char c = data[6 + i];
        if (c == ' ' || c == '?' || c == '\r' || c == '\n' || c == 0) {
            req->path[i] = 0;
            break;
        }

        req->path[i] = c;
    }

    req->path[MAX_PATH - 1] = 0;
}

static __always_inline void copy_path_from_7(char *data, struct req_ctx_t *req)
{
#pragma unroll
    for (int i = 0; i < MAX_PATH - 1; i++) {
        char c = data[7 + i];
        if (c == ' ' || c == '?' || c == '\r' || c == '\n' || c == 0) {
            req->path[i] = 0;
            break;
        }

        req->path[i] = c;
    }

    req->path[MAX_PATH - 1] = 0;
}

static __always_inline void copy_path(char *data, int mlen, struct req_ctx_t *req)
{
    if (mlen == 3)
        copy_path_from_4(data, req);
    else if (mlen == 4)
        copy_path_from_5(data, req);
    else if (mlen == 5)
        copy_path_from_6(data, req);
    else if (mlen == 6)
        copy_path_from_7(data, req);
}

static __always_inline int parse_status(char *d)
{
    if (!(d[0] == 'H' && d[1] == 'T' && d[2] == 'T' && d[3] == 'P'))
        return 0;

    if (d[4] != '/' || d[8] != ' ')
        return 0;

    char a = d[9];
    char b = d[10];
    char c = d[11];

    if (a < '0' || a > '9' || b < '0' || b > '9' || c < '0' || c > '9')
        return 0;

    return (a - '0') * 100 + (b - '0') * 10 + (c - '0');
}

SEC("tracepoint/syscalls/sys_enter_read")
int handle_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    struct io_args_t args = {};

    args.fd = (__s32)ctx->args[0];
    args.buf = (__u64)ctx->args[1];
    args.count = (__u64)ctx->args[2];

    bpf_map_update_elem(&active_reads, &id, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int handle_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    if (should_skip())
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    struct io_args_t *args = bpf_map_lookup_elem(&active_reads, &id);

    if (!args)
        return 0;

    long ret = ctx->ret;
    if (ret <= 0) {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }

    if (ret < 12 || args->count < MAX_BUF) {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }

    char data[MAX_BUF] = {};
    if (bpf_probe_read_user(data, MAX_BUF, (const void *)args->buf) != 0) {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }

    int mlen = method_len(data);
    if (mlen > 0) {
        struct conn_key_t key = {};
        struct req_ctx_t req = {};

        key.tgid = tgid;
        key.fd = args->fd;

        req.start_ns = bpf_ktime_get_ns();
        copy_method_and_path(data, mlen, &req);
        copy_path(data, mlen, &req);

        bpf_map_update_elem(&inflight, &key, &req, BPF_ANY);
    }

    bpf_map_delete_elem(&active_reads, &id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    __u32 pid = (__u32)id;
    __s32 fd = (__s32)ctx->args[0];
    const char *buf = (const char *)ctx->args[1];
    __u64 count = (__u64)ctx->args[2];

    if (count < 12)
        return 0;

    char data[16] = {};
    if (bpf_probe_read_user(data, sizeof(data), buf) != 0)
        return 0;

    int status = parse_status(data);
    if (status == 0)
        return 0;

    struct conn_key_t key = {};
    key.tgid = tgid;
    key.fd = fd;

    struct req_ctx_t *req = bpf_map_lookup_elem(&inflight, &key);
    if (!req)
        return 0;

    struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->tgid = tgid;
    event->pid = pid;
    event->fd = fd;
    event->latency_ns = bpf_ktime_get_ns() - req->start_ns;
    event->status = status;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

#pragma unroll
    for (int i = 0; i < MAX_METHOD; i++)
        event->method[i] = req->method[i];

#pragma unroll
    for (int i = 0; i < MAX_PATH; i++)
        event->path[i] = req->path[i];

    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&inflight, &key);
    return 0;
}
