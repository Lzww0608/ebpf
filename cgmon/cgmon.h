#ifndef __CGMON_H
#define __CGMON_H

#define TASK_COMM_LEN 16
#define MAX_NAME_LEN 64
#define MAX_PATH_LEN 512

struct cg_stats {
    unsigned long long cpu_ns;

    unsigned long long read_bytes;
    unsigned long long write_bytes;

    unsigned long long read_calls;
    unsigned long long write_calls;
};

#endif
