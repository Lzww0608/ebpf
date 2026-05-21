#include "vmlinux.h"
#include "tcpconn_count.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

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

static __always_inline void inc_count(unsigned int tgid,
                                      const char comm[COMM_LEN],
                                      int active)
{
    struct proc_key key = {
        .tgid = tgid,
    };
    struct proc_val zero = {};
    struct proc_val *val;

    __builtin_memcpy(zero.comm, comm, COMM_LEN);
    bpf_map_update_elem(&counts, &key, &zero, BPF_NOEXIST);

    val = bpf_map_lookup_elem(&counts, &key);
    if (!val)
        return;

    __builtin_memcpy(val->comm, comm, COMM_LEN);

    if (active)
        __sync_fetch_and_add(&val->active, 1);
    else
        __sync_fetch_and_add(&val->passive, 1);
}

static __always_inline int record_connect_start(struct sock *sk)
{
    unsigned long long pid_tgid;
    unsigned long long skaddr;
    struct sock_owner owner = {};

    if (!sk)
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    skaddr = (unsigned long long)sk;

    owner.tgid = pid_tgid >> 32;
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
    return record_connect_start(sk);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(handle_tcp_v4_connect_exit, long ret)
{
    return record_connect_return(ret);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(handle_tcp_v6_connect_entry, struct sock *sk)
{
    return record_connect_start(sk);
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

    inc_count(owner->tgid, owner->comm, 1);
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
    unsigned int tgid;
    char comm[COMM_LEN] = {};

    if (!newsk)
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    tgid = pid_tgid >> 32;
    bpf_get_current_comm(comm, sizeof(comm));

    inc_count(tgid, comm, 0);
    return 0;
}
