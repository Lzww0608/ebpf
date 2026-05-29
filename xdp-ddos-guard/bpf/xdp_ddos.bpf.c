//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef XDP_ABORTED
#define XDP_ABORTED 0
#endif
#ifndef XDP_DROP
#define XDP_DROP 1
#endif
#ifndef XDP_PASS
#define XDP_PASS 2
#endif

#define ETH_P_IP     0x0800
#define ETH_P_8021Q  0x8100
#define ETH_P_8021AD 0x88A8

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IP_OFFSET_MASK 0x1FFF

#define NSEC_PER_SEC 1000000000ULL

#define STAT_TOTAL          0
#define STAT_PASS           1
#define STAT_DROP_BLACKLIST 2
#define STAT_DROP_RATELIMIT 3
#define STAT_PASS_WHITELIST 4
#define STAT_NON_IPV4       5
#define STAT_MAX            6

struct eth_hdr {
    __u8 dst[6];
    __u8 src[6];
    __be16 proto;
};

struct vlan_hdr_guard {
    __be16 tci;
    __be16 proto;
};

struct ipv4_hdr {
    __u8 version_ihl;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __be16 check;
    __be32 saddr;
    __be32 daddr;
};

struct tcp_hdr_guard {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __be16 doff_flags;
    __be16 window;
    __be16 check;
    __be16 urg_ptr;
};

struct udp_hdr_guard {
    __be16 source;
    __be16 dest;
    __be16 len;
    __be16 check;
};

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u8 addr[4];
};

struct ipv4_key {
    __u8 addr[4];
};

struct rate_state {
    __u64 window_start_ns;
    __u64 packets;
    __u64 bytes;
    __u64 blocked_until_ns;
};

struct config {
    __u64 pps_limit;
    __u64 bps_limit;
    __u64 block_ns;
    __u16 protect_port;
    __u8 enabled;
    __u8 _pad[5];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u8);
} whitelist_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u8);
} blacklist_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1048576);
    __type(key, struct ipv4_key);
    __type(value, struct rate_state);
} rate_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

static __always_inline void inc_stat(__u32 idx)
{
    __u64 *value = bpf_map_lookup_elem(&stats_map, &idx);
    if (value)
        *value += 1;
}

static __always_inline int parse_eth(void **cursor, void *data_end, __be16 *eth_proto)
{
    struct eth_hdr *eth = *cursor;

    if ((void *)(eth + 1) > data_end)
        return -1;

    *eth_proto = eth->proto;
    *cursor = eth + 1;

#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (*eth_proto != bpf_htons(ETH_P_8021Q) &&
            *eth_proto != bpf_htons(ETH_P_8021AD))
            break;

        struct vlan_hdr_guard *vh = *cursor;
        if ((void *)(vh + 1) > data_end)
            return -1;

        *eth_proto = vh->proto;
        *cursor = vh + 1;
    }

    return 0;
}

static __always_inline int parse_l4_dport(struct ipv4_hdr *iph, void *data_end, __u16 *dport)
{
    __u8 ihl = iph->version_ihl & 0x0f;
    if (ihl < 5)
        return -1;

    __u32 ihl_len = (__u32)ihl * 4;
    void *l4 = (void *)iph + ihl_len;
    if (l4 > data_end)
        return -1;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcp_hdr_guard *tcp = l4;

        if ((void *)(tcp + 1) > data_end)
            return -1;

        *dport = bpf_ntohs(tcp->dest);
        return 0;
    }

    if (iph->protocol == IPPROTO_UDP) {
        struct udp_hdr_guard *udp = l4;

        if ((void *)(udp + 1) > data_end)
            return -1;

        *dport = bpf_ntohs(udp->dest);
        return 0;
    }

    return -1;
}

static __always_inline int is_non_initial_fragment(struct ipv4_hdr *iph)
{
    return (bpf_ntohs(iph->frag_off) & IP_OFFSET_MASK) != 0;
}

static __always_inline void make_ip_key_from_saddr(struct ipv4_key *key, __be32 saddr)
{
    __builtin_memcpy(key->addr, &saddr, 4);
}

static __always_inline void make_lpm_lookup_key(struct ipv4_lpm_key *key, __be32 saddr)
{
    key->prefixlen = 32;
    __builtin_memcpy(key->addr, &saddr, 4);
}

static __always_inline int is_whitelisted(__be32 saddr)
{
    struct ipv4_lpm_key key = {};

    make_lpm_lookup_key(&key, saddr);
    return bpf_map_lookup_elem(&whitelist_v4, &key) != 0;
}

static __always_inline int is_blacklisted(__be32 saddr)
{
    struct ipv4_lpm_key key = {};

    make_lpm_lookup_key(&key, saddr);
    return bpf_map_lookup_elem(&blacklist_v4, &key) != 0;
}

static __always_inline int over_limit(struct rate_state *state, struct config *cfg)
{
    if (cfg->pps_limit > 0 && state->packets > cfg->pps_limit)
        return 1;

    if (cfg->bps_limit > 0 && state->bytes > cfg->bps_limit)
        return 1;

    return 0;
}

static __always_inline int rate_limit_ipv4(__be32 saddr, __u64 pkt_len, struct config *cfg)
{
    struct ipv4_key key = {};
    struct rate_state new_state = {};
    struct rate_state *state;
    __u64 now = bpf_ktime_get_ns();

    make_ip_key_from_saddr(&key, saddr);

    state = bpf_map_lookup_elem(&rate_v4, &key);
    if (!state) {
        new_state.window_start_ns = now;
        new_state.packets = 1;
        new_state.bytes = pkt_len;

        if (over_limit(&new_state, cfg)) {
            new_state.blocked_until_ns = now + cfg->block_ns;
            bpf_map_update_elem(&rate_v4, &key, &new_state, BPF_ANY);
            return 1;
        }

        bpf_map_update_elem(&rate_v4, &key, &new_state, BPF_ANY);
        return 0;
    }

    if (state->blocked_until_ns > now)
        return 1;

    if (now - state->window_start_ns >= NSEC_PER_SEC) {
        state->window_start_ns = now;
        state->packets = 0;
        state->bytes = 0;
    }

    state->packets += 1;
    state->bytes += pkt_len;

    if (over_limit(state, cfg)) {
        state->blocked_until_ns = now + cfg->block_ns;
        return 1;
    }

    return 0;
}

SEC("xdp")
int xdp_ddos_guard(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    void *cursor = data;
    __u64 pkt_len = (__u64)((long)data_end - (long)data);
    __be16 eth_proto = 0;

    inc_stat(STAT_TOTAL);

    if (parse_eth(&cursor, data_end, &eth_proto) < 0) {
        inc_stat(STAT_PASS);
        return XDP_PASS;
    }

    if (eth_proto != bpf_htons(ETH_P_IP)) {
        inc_stat(STAT_NON_IPV4);
        return XDP_PASS;
    }

    struct ipv4_hdr *iph = cursor;
    if ((void *)(iph + 1) > data_end) {
        inc_stat(STAT_PASS);
        return XDP_PASS;
    }

    if (is_whitelisted(iph->saddr)) {
        inc_stat(STAT_PASS_WHITELIST);
        return XDP_PASS;
    }

    if (is_blacklisted(iph->saddr)) {
        inc_stat(STAT_DROP_BLACKLIST);
        return XDP_DROP;
    }

    __u32 cfg_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (!cfg || !cfg->enabled) {
        inc_stat(STAT_PASS);
        return XDP_PASS;
    }

    if (cfg->protect_port != 0) {
        __u16 dport = 0;

        if (is_non_initial_fragment(iph)) {
            inc_stat(STAT_PASS);
            return XDP_PASS;
        }

        if (parse_l4_dport(iph, data_end, &dport) < 0) {
            inc_stat(STAT_PASS);
            return XDP_PASS;
        }

        if (dport != cfg->protect_port) {
            inc_stat(STAT_PASS);
            return XDP_PASS;
        }
    }

    if (rate_limit_ipv4(iph->saddr, pkt_len, cfg)) {
        inc_stat(STAT_DROP_RATELIMIT);
        return XDP_DROP;
    }

    inc_stat(STAT_PASS);
    return XDP_PASS;
}
