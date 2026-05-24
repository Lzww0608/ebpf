#include "vmlinux.h"
#include "slow_sql.h"

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define COM_QUERY 0x03

const volatile unsigned int target_tgid = 0;
const volatile unsigned long long threshold_ns = 100000000ULL;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, unsigned long long);
    __type(value, struct io_arg);
} read_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, unsigned long long);
    __type(value, struct io_arg);
} write_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct conn_key);
    __type(value, struct query_val);
} pending_queries SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int is_mysqld_comm(const char comm[TASK_COMM_LEN])
{
    int mysqld =
        comm[0] == 'm' &&
        comm[1] == 'y' &&
        comm[2] == 's' &&
        comm[3] == 'q' &&
        comm[4] == 'l' &&
        comm[5] == 'd' &&
        comm[6] == '\0';

    int mariadbd =
        comm[0] == 'm' &&
        comm[1] == 'a' &&
        comm[2] == 'r' &&
        comm[3] == 'i' &&
        comm[4] == 'a' &&
        comm[5] == 'd' &&
        comm[6] == 'b' &&
        comm[7] == 'd' &&
        comm[8] == '\0';

    return mysqld || mariadbd;
}

static __always_inline int is_target_process(void)
{
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    unsigned int tgid = pid_tgid >> 32;
    char comm[TASK_COMM_LEN] = {};

    if (target_tgid != 0)
        return tgid == target_tgid;

    bpf_get_current_comm(comm, sizeof(comm));
    return is_mysqld_comm(comm);
}

static __always_inline int save_read_arg(int fd, const char *buf)
{
    unsigned long long pid_tgid;
    struct io_arg arg = {};

    if (!is_target_process())
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    arg.fd = fd;
    arg.buf = (unsigned long long)buf;

    bpf_map_update_elem(&read_args, &pid_tgid, &arg, BPF_ANY);
    return 0;
}

static __always_inline int save_write_arg(int fd)
{
    unsigned long long pid_tgid;
    struct io_arg arg = {};

    if (!is_target_process())
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    arg.fd = fd;

    bpf_map_update_elem(&write_args, &pid_tgid, &arg, BPF_ANY);
    return 0;
}

static __always_inline int handle_read_exit(long ret)
{
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    struct io_arg *arg = bpf_map_lookup_elem(&read_args, &pid_tgid);
    unsigned int payload_len;
    unsigned int available;
    unsigned int declared_sql_len;
    unsigned int copy_len;
    unsigned char hdr[5] = {};
    struct query_val q = {};
    struct conn_key key = {};

    if (!arg)
        return 0;

    if (ret < 5)
        goto cleanup;

    if (bpf_probe_read_user(hdr, sizeof(hdr), (void *)arg->buf) < 0)
        goto cleanup;

    /*
     * MySQL packet:
     *   3 bytes payload length
     *   1 byte sequence id
     *   payload[0] = command
     */
    payload_len =
        (unsigned int)hdr[0] |
        ((unsigned int)hdr[1] << 8) |
        ((unsigned int)hdr[2] << 16);

    if (payload_len < 1)
        goto cleanup;

    if (hdr[3] != 0)
        goto cleanup;

    if (hdr[4] != COM_QUERY)
        goto cleanup;

    available = (unsigned int)ret - 5;
    declared_sql_len = payload_len - 1;
    if (declared_sql_len < available)
        available = declared_sql_len;

    if (available == 0)
        goto cleanup;

    copy_len = available;
    if (copy_len > MAX_SQL_LEN - 1)
        copy_len = MAX_SQL_LEN - 1;

    q.start_ns = bpf_ktime_get_ns();
    q.tgid = pid_tgid >> 32;
    q.tid = (unsigned int)pid_tgid;
    q.uid = (unsigned int)bpf_get_current_uid_gid();
    q.fd = arg->fd;
    q.sql_len = copy_len;

    bpf_get_current_comm(q.comm, sizeof(q.comm));

    /* Keep helper size constant for verifier compatibility. */
    if (bpf_probe_read_user(q.sql, MAX_SQL_LEN - 1, (void *)(arg->buf + 5)) < 0)
        goto cleanup;

    q.sql[copy_len] = '\0';

    key.tgid = q.tgid;
    key.fd = q.fd;
    bpf_map_update_elem(&pending_queries, &key, &q, BPF_ANY);

cleanup:
    bpf_map_delete_elem(&read_args, &pid_tgid);
    return 0;
}

static __always_inline int handle_write_exit(long ret)
{
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    struct io_arg *arg = bpf_map_lookup_elem(&write_args, &pid_tgid);
    struct conn_key key = {};
    struct query_val *q;
    unsigned long long now;
    unsigned long long latency;

    if (!arg)
        return 0;

    if (ret <= 0)
        goto cleanup;

    key.tgid = pid_tgid >> 32;
    key.fd = arg->fd;

    q = bpf_map_lookup_elem(&pending_queries, &key);
    if (!q)
        goto cleanup;

    now = bpf_ktime_get_ns();
    latency = now - q->start_ns;

    if (latency >= threshold_ns) {
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

        if (e) {
            e->ts_ns = now;
            e->latency_ns = latency;
            e->tgid = q->tgid;
            e->tid = q->tid;
            e->uid = q->uid;
            e->fd = q->fd;
            e->sql_len = q->sql_len;

            __builtin_memcpy(e->comm, q->comm, TASK_COMM_LEN);
            __builtin_memcpy(e->sql, q->sql, MAX_SQL_LEN);
            bpf_ringbuf_submit(e, 0);
        }
    }

    /*
     * MVP semantics: first response write ends the query. This measures
     * time-to-first-response, not full result-set transmission time.
     */
    bpf_map_delete_elem(&pending_queries, &key);

cleanup:
    bpf_map_delete_elem(&write_args, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    int fd = (int)ctx->args[0];
    const char *buf = (const char *)ctx->args[1];

    return save_read_arg(fd, buf);
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    return handle_read_exit(ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_enter_recvfrom(struct trace_event_raw_sys_enter *ctx)
{
    int fd = (int)ctx->args[0];
    const char *buf = (const char *)ctx->args[1];

    return save_read_arg(fd, buf);
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_exit_recvfrom(struct trace_event_raw_sys_exit *ctx)
{
    return handle_read_exit(ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    int fd = (int)ctx->args[0];

    return save_write_arg(fd);
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_exit_write(struct trace_event_raw_sys_exit *ctx)
{
    return handle_write_exit(ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_writev")
int trace_enter_writev(struct trace_event_raw_sys_enter *ctx)
{
    int fd = (int)ctx->args[0];

    return save_write_arg(fd);
}

SEC("tracepoint/syscalls/sys_exit_writev")
int trace_exit_writev(struct trace_event_raw_sys_exit *ctx)
{
    return handle_write_exit(ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_enter_sendto(struct trace_event_raw_sys_enter *ctx)
{
    int fd = (int)ctx->args[0];

    return save_write_arg(fd);
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int trace_exit_sendto(struct trace_event_raw_sys_exit *ctx)
{
    return handle_write_exit(ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_enter_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
    int fd = (int)ctx->args[0];

    return save_write_arg(fd);
}

SEC("tracepoint/syscalls/sys_exit_sendmsg")
int trace_exit_sendmsg(struct trace_event_raw_sys_exit *ctx)
{
    return handle_write_exit(ctx->ret);
}
