#include "vmlinux.h"
#include "portscan.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6

#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10

#ifndef XDP_PASS
#define XDP_ABORTED 0
#define XDP_DROP 1
#define XDP_PASS 2
#define XDP_TX 3
#define XDP_REDIRECT 4
#endif

const volatile unsigned int threshold_ports = 20;
const volatile unsigned long long window_ns = 10ULL * 1000000000ULL;
const volatile unsigned int drop_after_alert = 0;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, unsigned int);
    __type(value, struct scan_state);
} scan_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 524288);
    __type(key, struct port_key);
    __type(value, unsigned char);
} seen_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int parse_ipv4_tcp_syn(struct xdp_md *ctx,
                                              unsigned int *src_ip,
                                              unsigned short *dport)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcp;
    unsigned int ihl_len;
    unsigned short frag_off;
    unsigned short tot_len;
    unsigned char flags;

    if ((void *)(eth + 1) > data_end)
        return 0;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;

    iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return 0;

    if (iph->protocol != IPPROTO_TCP)
        return 0;

    frag_off = bpf_ntohs(iph->frag_off);
    if (frag_off & 0x3fff)
        return 0;

    ihl_len = iph->ihl * 4;
    if (ihl_len < sizeof(*iph))
        return 0;

    if ((void *)iph + ihl_len > data_end)
        return 0;

    tot_len = bpf_ntohs(iph->tot_len);
    if (tot_len < ihl_len + sizeof(*tcp))
        return 0;

    tcp = (void *)iph + ihl_len;
    if ((void *)(tcp + 1) > data_end)
        return 0;

    flags = *((unsigned char *)tcp + 13);
    if (!(flags & TCP_FLAG_SYN))
        return 0;
    if (flags & TCP_FLAG_ACK)
        return 0;

    *src_ip = iph->saddr;
    *dport = bpf_ntohs(tcp->dest);
    return 1;
}

static __always_inline void submit_alert(struct xdp_md *ctx,
                                         unsigned int src_ip,
                                         unsigned short dport,
                                         struct scan_state *state,
                                         unsigned int count)
{
    struct alert_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    e->ts_ns = bpf_ktime_get_ns();
    e->window_start_ns = state->window_start_ns;
    e->window_ns = window_ns;
    e->ifindex = ctx->ingress_ifindex;
    e->src_ip = src_ip;
    e->distinct_ports = count;
    e->threshold_ports = threshold_ports;
    e->last_dport = dport;
    e->pad = 0;

    bpf_ringbuf_submit(e, 0);
}

SEC("xdp")
int xdp_portscan_detector(struct xdp_md *ctx)
{
    unsigned int src_ip = 0;
    unsigned short dport = 0;
    unsigned long long now;
    struct scan_state *state;
    struct port_key pkey = {};
    unsigned char one = 1;
    unsigned int new_count;

    if (!parse_ipv4_tcp_syn(ctx, &src_ip, &dport))
        return XDP_PASS;

    now = bpf_ktime_get_ns();
    state = bpf_map_lookup_elem(&scan_states, &src_ip);

    if (!state || now - state->window_start_ns > window_ns) {
        struct scan_state init = {};

        init.window_start_ns = now;
        init.last_seen_ns = now;
        init.distinct_ports = 0;
        init.alerted = 0;

        bpf_map_update_elem(&scan_states, &src_ip, &init, BPF_ANY);
        state = bpf_map_lookup_elem(&scan_states, &src_ip);
        if (!state)
            return XDP_PASS;
    }

    state->last_seen_ns = now;

    if (state->alerted && drop_after_alert)
        return XDP_DROP;

    pkey.src_ip = src_ip;
    pkey.dport = dport;
    pkey.window_start_ns = state->window_start_ns;

    if (bpf_map_update_elem(&seen_ports, &pkey, &one, BPF_NOEXIST) != 0)
        return XDP_PASS;

    new_count = __sync_fetch_and_add(&state->distinct_ports, 1) + 1;
    if (new_count >= threshold_ports) {
        unsigned int old_alerted;

        old_alerted = __sync_val_compare_and_swap(&state->alerted, 0, 1);
        if (old_alerted == 0)
            submit_alert(ctx, src_ip, dport, state, new_count);

        if (drop_after_alert)
            return XDP_DROP;
    }

    return XDP_PASS;
}
