#ifndef __PORTSCAN_H
#define __PORTSCAN_H

struct scan_state {
    unsigned long long window_start_ns;
    unsigned long long last_seen_ns;

    unsigned long long distinct_ports;
    unsigned long long alerted;
};
struct port_key {
    unsigned int src_ip;
    unsigned short dport;
    unsigned short pad;
    unsigned long long window_start_ns;
};

struct alert_event {
    unsigned long long ts_ns;
    unsigned long long window_start_ns;
    unsigned long long window_ns;
    unsigned int ifindex;
    unsigned int src_ip;
    unsigned int distinct_ports;
    unsigned int threshold_ports;
    unsigned short last_dport;
    unsigned short pad;
};

#endif
