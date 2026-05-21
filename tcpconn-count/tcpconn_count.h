#ifndef __TCPCONN_COUNT_H
#define __TCPCONN_COUNT_H

#define COMM_LEN 16

#define TCPCONN_FAMILY_IPV4 4
#define TCPCONN_FAMILY_IPV6 6

#define TCPCONN_EVENT_ACTIVE 1
#define TCPCONN_EVENT_PASSIVE 2

#define TCPCONN_CFG_ACTIVE_ONLY (1U << 0)
#define TCPCONN_CFG_PASSIVE_ONLY (1U << 1)
#define TCPCONN_CFG_HAS_PID (1U << 2)
#define TCPCONN_CFG_HAS_COMM (1U << 3)
#define TCPCONN_CFG_EMIT_EVENTS (1U << 4)

struct proc_key {
    unsigned int tgid;
};

struct proc_val {
    unsigned long long active;
    unsigned long long passive;
    unsigned long long cgroup_id;
    unsigned int last_remote_addr_v4;
    unsigned int last_remote_addr_v6[4];
    unsigned short last_remote_port;
    unsigned char last_family;
    char comm[COMM_LEN];
};

struct sock_owner {
    unsigned int tgid;
    unsigned long long cgroup_id;
    unsigned char family;
    char comm[COMM_LEN];
};

struct tcpconn_config {
    unsigned int target_tgid;
    unsigned int flags;
    char target_comm[COMM_LEN];
};

struct conn_event {
    unsigned long long ts_ns;
    unsigned long long cgroup_id;
    unsigned int tgid;
    unsigned int type;
    unsigned char family;
    unsigned short local_port;
    unsigned short remote_port;
    char comm[COMM_LEN];
    unsigned int local_addr_v4;
    unsigned int remote_addr_v4;
    unsigned int local_addr_v6[4];
    unsigned int remote_addr_v6[4];
};

#endif
