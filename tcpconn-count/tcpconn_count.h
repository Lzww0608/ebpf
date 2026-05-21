#ifndef __TCPCONN_COUNT_H
#define __TCPCONN_COUNT_H

#define COMM_LEN 16

struct proc_key {
    unsigned int tgid;
};

struct proc_val {
    unsigned long long active;
    unsigned long long passive;
    char comm[COMM_LEN];
};

struct sock_owner {
    unsigned int tgid;
    char comm[COMM_LEN];
};

#endif
