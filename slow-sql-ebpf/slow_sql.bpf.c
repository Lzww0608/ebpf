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
    __type(value, struct packet_header);
} packet_headers SEC(".maps");

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

static __always_inline unsigned int mysql_payload_len(const unsigned char hdr[4])
{
    return (unsigned int)hdr[0] |
           ((unsigned int)hdr[1] << 8) |
           ((unsigned int)hdr[2] << 16);
}

static __always_inline int save_packet_header(struct conn_key *key,
                                              struct io_arg *arg)
{
    struct packet_header ph = {};
    unsigned char hdr[4] = {};

    if (bpf_probe_read_user(hdr, sizeof(hdr), (void *)arg->buf) < 0)
        return 0;

    ph.payload_len = mysql_payload_len(hdr);
    ph.seq_id = hdr[3];

    if (ph.payload_len > 0)
        bpf_map_update_elem(&packet_headers, key, &ph, BPF_ANY);

    return 0;
}

static __always_inline int save_query_from_payload(struct conn_key *key,
                                                   struct io_arg *arg,
                                                   unsigned long long pid_tgid,
                                                   unsigned int payload_len,
                                                   unsigned int bytes_read,
                                                   unsigned int payload_off)
{
    unsigned char prefix[3] = {};
    unsigned int data_off = payload_off + 1;
    unsigned int available;
    unsigned int declared_sql_len;
    unsigned int copy_len;
    struct query_val q = {};

    bytes_read &= 0xffff;
    payload_len &= 0xffffff;

    if (payload_len < 1 || bytes_read < 1)
        return 0;

    if (bpf_probe_read_user(prefix, 1, (void *)(arg->buf + payload_off)) < 0)
        return 0;

    if (prefix[0] != COM_QUERY)
        return 0;

    /*
     * MySQL 8 clients may send COM_QUERY as:
     *   command, parameter_count=0, parameter_set_count=1, SQL
     * when CLIENT_QUERY_ATTRIBUTES is negotiated but no attributes are used.
     */
    if (payload_len >= 3 && bytes_read >= 3) {
        if (bpf_probe_read_user(prefix, sizeof(prefix),
                                (void *)(arg->buf + payload_off)) < 0)
            return 0;

        if (prefix[1] == 0 && prefix[2] == 1)
            data_off = payload_off + 3;
    }

    if (data_off == payload_off + 3) {
        if (payload_len <= 3 || bytes_read <= 3)
            return 0;

        available = bytes_read - 3;
        declared_sql_len = payload_len - 3;
    } else {
        if (payload_len <= 1 || bytes_read <= 1)
            return 0;

        available = bytes_read - 1;
        declared_sql_len = payload_len - 1;
    }

    available &= 0xffff;
    declared_sql_len &= 0xffffff;
    if (declared_sql_len < available)
        available = declared_sql_len;

    if (available == 0)
        return 0;

    copy_len = available;
    if (copy_len > MAX_SQL_LEN - 1)
        copy_len = MAX_SQL_LEN - 1;
    copy_len &= 0xff;
    if (copy_len == 0 || copy_len > MAX_SQL_LEN - 1)
        return 0;

    q.start_ns = bpf_ktime_get_ns();
    q.tgid = pid_tgid >> 32;
    q.tid = (unsigned int)pid_tgid;
    q.uid = (unsigned int)bpf_get_current_uid_gid();
    q.fd = arg->fd;
    q.sql_len = copy_len;

    bpf_get_current_comm(q.comm, sizeof(q.comm));

    /*
     * Use a constant helper size. The real SQL length is carried in sql_len,
     * and userspace only prints that many bytes.
     */
    if (bpf_probe_read_user(q.sql, MAX_SQL_LEN - 1,
                            (void *)(arg->buf + data_off)) < 0)
        return 0;

    bpf_map_update_elem(&pending_queries, key, &q, BPF_ANY);
    return 0;
}

static __always_inline int handle_read_exit(long ret)
{
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    struct io_arg *arg = bpf_map_lookup_elem(&read_args, &pid_tgid);
    struct packet_header *ph;
    struct conn_key key = {};
    unsigned int payload_len;
    unsigned int bytes_read;
    unsigned char hdr[4] = {};

    if (!arg)
        return 0;

    if (ret <= 0)
        goto cleanup;

    key.tgid = pid_tgid >> 32;
    key.fd = arg->fd;
    bytes_read = (unsigned int)ret;

    if (ret == 4) {
        save_packet_header(&key, arg);
        goto cleanup;
    }

    ph = bpf_map_lookup_elem(&packet_headers, &key);
    if (ph) {
        if (ph->seq_id == 0)
            save_query_from_payload(&key, arg, pid_tgid,
                                    ph->payload_len, bytes_read, 0);

        bpf_map_delete_elem(&packet_headers, &key);
        goto cleanup;
    }

    if (ret < 5)
        goto cleanup;

    if (bpf_probe_read_user(hdr, sizeof(hdr), (void *)arg->buf) < 0)
        goto cleanup;

    payload_len = mysql_payload_len(hdr);

    if (payload_len < 1)
        goto cleanup;

    if (hdr[3] != 0)
        goto cleanup;

    save_query_from_payload(&key, arg, pid_tgid, payload_len, bytes_read - 4, 4);

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
