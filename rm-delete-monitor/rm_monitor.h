#ifndef __RM_MONITOR_H
#define __RM_MONITOR_H

#define RM_MONITOR_COMM_LEN 16
#define RM_MONITOR_PATH_LEN 256
#define RM_MONITOR_RESOLVED_PATH_LEN 512
#define RM_MONITOR_NAME_LEN 256
#define RM_MONITOR_CMDLINE_LEN 512

enum op_type {
    OP_UNLINK = 1,
    OP_RMDIR  = 2,
};

enum event_flags {
    EVENT_F_LSM_SEEN = 1 << 0,
    EVENT_F_PATH_RESOLVED = 1 << 1,
    EVENT_F_CMDLINE_TRUNCATED = 1 << 2,
};

struct event {
    unsigned long long ts_ns;

    unsigned int tgid;
    unsigned int tid;
    unsigned int uid;
    unsigned int event_flags;
    unsigned int cmdline_len;

    int dfd;
    int flags;
    int lsm_ret;
    long ret;

    unsigned char op;

    char comm[RM_MONITOR_COMM_LEN];
    char path[RM_MONITOR_PATH_LEN];
    char resolved_path[RM_MONITOR_RESOLVED_PATH_LEN];
    char target_name[RM_MONITOR_NAME_LEN];
    char cmdline[RM_MONITOR_CMDLINE_LEN];
};

#endif
