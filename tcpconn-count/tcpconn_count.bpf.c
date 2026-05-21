#include "vmlinux.h"
#include "tcpconn_count.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_INET_VALUE 2
#define AF_INET6_VALUE 10

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, unsigned long long);
    __type(value, struct sock_owner);
} sk_owners SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, unsigned long long);
    __type(value, unsigned long long);
} inflight_connect SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct proc_key);
    __type(value, struct proc_val);
} counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct tcpconn_config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline struct tcpconn_config *get_config(void)
{
    unsigned int key = 0;

    return bpf_map_lookup_elem(&config_map, &key);
}

static __always_inline int comm_eq(const char lhs[COMM_LEN], const char rhs[COMM_LEN])
{
#pragma unroll
    for (int i = 0; i < COMM_LEN; i++) {
        if (lhs[i] != rhs[i])
            return 0;
        if (lhs[i] == '\0')
            return 1;
    }

    return 1;
}

static __always_inline int should_trace(unsigned int tgid,
                                        const char comm[COMM_LEN],
                                        int active)
{
    struct tcpconn_config *cfg = get_config();

    if (!cfg)
        return 1;

    if ((cfg->flags & TCPCONN_CFG_ACTIVE_ONLY) && !active)
        return 0;
    if ((cfg->flags & TCPCONN_CFG_PASSIVE_ONLY) && active)
        return 0;
    if ((cfg->flags & TCPCONN_CFG_HAS_PID) && cfg->target_tgid != tgid)
        return 0;
    if ((cfg->flags & TCPCONN_CFG_HAS_COMM) &&
        !comm_eq(comm, cfg->target_comm))
        return 0;

    return 1;
}

static __always_inline void read_sock_tuple(struct sock *sk,
                                            unsigned char family,
                                            struct conn_event *event)
{
    event->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if (family == TCPCONN_FAMILY_IPV6) {
        BPF_CORE_READ_INTO(&event->local_addr_v6,
                           sk,
                           __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&event->remote_addr_v6,
                           sk,
                           __sk_common.skc_v6_daddr.in6_u.u6_addr32);
        return;
    }

    event->local_addr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    event->remote_addr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
}

static __always_inline void inc_count(unsigned int tgid,
                                      unsigned long long cgroup_id,
                                      const char comm[COMM_LEN],
                                      int active,
                                      const struct conn_event *event)
{
    struct proc_key key = {
        .tgid = tgid,
    };
    struct proc_val zero = {};
    struct proc_val *val;

    __builtin_memcpy(zero.comm, comm, COMM_LEN);
    zero.cgroup_id = cgroup_id;
    bpf_map_update_elem(&counts, &key, &zero, BPF_NOEXIST);

    val = bpf_map_lookup_elem(&counts, &key);
    if (!val)
        return;

    __builtin_memcpy(val->comm, comm, COMM_LEN);
    val->cgroup_id = cgroup_id;
    val->last_family = event->family;
    val->last_remote_port = event->remote_port;
    val->last_remote_addr_v4 = event->remote_addr_v4;
    __builtin_memcpy(val->last_remote_addr_v6,
                     event->remote_addr_v6,
                     sizeof(val->last_remote_addr_v6));

    if (active)
        __sync_fetch_and_add(&val->active, 1);
    else
        __sync_fetch_and_add(&val->passive, 1);
}

static __always_inline int config_wants_events(void)
{
    struct tcpconn_config *cfg = get_config();

    return cfg && (cfg->flags & TCPCONN_CFG_EMIT_EVENTS);
}

static __always_inline void record_connection(struct sock *sk,
                                              unsigned int tgid,
                                              unsigned long long cgroup_id,
                                              const char comm[COMM_LEN],
                                              unsigned char family,
                                              int active)
{
    struct conn_event event = {};

    if (!should_trace(tgid, comm, active))
        return;

    event.ts_ns = bpf_ktime_get_ns();
    event.tgid = tgid;
    event.cgroup_id = cgroup_id;
    event.type = active ? TCPCONN_EVENT_ACTIVE : TCPCONN_EVENT_PASSIVE;
    event.family = family;
    __builtin_memcpy(event.comm, comm, COMM_LEN);
    read_sock_tuple(sk, family, &event);

    inc_count(tgid, cgroup_id, comm, active, &event);

    if (config_wants_events())
        bpf_ringbuf_output(&events, &event, sizeof(event), 0);
}

static __always_inline int record_connect_start(struct sock *sk,
                                                unsigned char family)
{
    unsigned long long pid_tgid;
    unsigned long long skaddr;
    struct sock_owner owner = {};

    if (!sk)
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    skaddr = (unsigned long long)sk;

    owner.tgid = pid_tgid >> 32;
    owner.cgroup_id = bpf_get_current_cgroup_id();
    owner.family = family;
    bpf_get_current_comm(owner.comm, sizeof(owner.comm));

    bpf_map_update_elem(&sk_owners, &skaddr, &owner, BPF_ANY);
    bpf_map_update_elem(&inflight_connect, &pid_tgid, &skaddr, BPF_ANY);

    return 0;
}

static __always_inline int record_connect_return(long ret)
{
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    unsigned long long *skaddrp;

    skaddrp = bpf_map_lookup_elem(&inflight_connect, &pid_tgid);
    if (!skaddrp)
        return 0;

    if (ret < 0)
        bpf_map_delete_elem(&sk_owners, skaddrp);

    bpf_map_delete_elem(&inflight_connect, &pid_tgid);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(handle_tcp_v4_connect_entry, struct sock *sk)
{
    return record_connect_start(sk, TCPCONN_FAMILY_IPV4);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(handle_tcp_v4_connect_exit, long ret)
{
    return record_connect_return(ret);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(handle_tcp_v6_connect_entry, struct sock *sk)
{
    return record_connect_start(sk, TCPCONN_FAMILY_IPV6);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(handle_tcp_v6_connect_exit, long ret)
{
    return record_connect_return(ret);
}

SEC("kprobe/tcp_finish_connect")
int BPF_KPROBE(handle_tcp_finish_connect, struct sock *sk)
{
    unsigned long long skaddr = (unsigned long long)sk;
    struct sock_owner *owner;

    owner = bpf_map_lookup_elem(&sk_owners, &skaddr);
    if (!owner)
        return 0;

    record_connection(sk,
                      owner->tgid,
                      owner->cgroup_id,
                      owner->comm,
                      owner->family,
                      1);
    bpf_map_delete_elem(&sk_owners, &skaddr);
    return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(handle_tcp_close, struct sock *sk)
{
    unsigned long long skaddr = (unsigned long long)sk;

    bpf_map_delete_elem(&sk_owners, &skaddr);
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(handle_inet_csk_accept_exit, struct sock *newsk)
{
    unsigned long long pid_tgid;
    unsigned long long cgroup_id;
    unsigned int tgid;
    unsigned short sk_family;
    unsigned char family;
    char comm[COMM_LEN] = {};

    if (!newsk)
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    tgid = pid_tgid >> 32;
    cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(comm, sizeof(comm));

    sk_family = BPF_CORE_READ(newsk, __sk_common.skc_family);
    family = sk_family == AF_INET6_VALUE ? TCPCONN_FAMILY_IPV6 : TCPCONN_FAMILY_IPV4;

    if (sk_family != AF_INET_VALUE && sk_family != AF_INET6_VALUE)
        return 0;

    record_connection(newsk, tgid, cgroup_id, comm, family, 0);
    return 0;
}
