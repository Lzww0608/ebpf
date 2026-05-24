#ifndef __SLOW_SQL_H
#define __SLOW_SQL_H

#define TASK_COMM_LEN 16
#define MAX_SQL_LEN 256

struct io_arg {
    int fd;
    unsigned long long buf;
};

struct conn_key {
    unsigned int tgid;
    int fd;
};

struct query_val {
    unsigned long long start_ns;

    unsigned int tgid;
    unsigned int tid;
    unsigned int uid;

    int fd;
    unsigned int sql_len;

    char comm[TASK_COMM_LEN];
    char sql[MAX_SQL_LEN];
};

struct event {
    unsigned long long ts_ns;
    unsigned long long latency_ns;

    unsigned int tgid;
    unsigned int tid;
    unsigned int uid;

    int fd;
    unsigned int sql_len;

    char comm[TASK_COMM_LEN];
    char sql[MAX_SQL_LEN];
};

#endif
