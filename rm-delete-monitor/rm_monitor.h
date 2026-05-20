#ifndef __RM_MONITOR_H
#define __RM_MONITOR_H

#define RM_MONITOR_COMM_LEN 16
#define RM_MONITOR_PATH_LEN 256

enum op_type {
    OP_UNLINK = 1,
    OP_RMDIR  = 2,
};

struct event {
    unsigned long long ts_ns;

    unsigned int tgid;   // 进程 ID，通常用户看到的 PID
    unsigned int tid;    // 线程 ID
    unsigned int uid;

    int dfd;
    int flags;
    long ret;

    unsigned char op;

    char comm[RM_MONITOR_COMM_LEN];
    char path[RM_MONITOR_PATH_LEN];
};

#endif