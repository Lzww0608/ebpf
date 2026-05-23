#ifndef __KILLMON_H
#define __KILLMON_H

#define TASK_COMM_LEN 16

struct signal_info {
    unsigned long long ts_ns;

    unsigned int target_pid;

    unsigned int sender_tgid;
    unsigned int sender_tid;
    unsigned int sender_uid;

    int sig;
    int result;

    char sender_comm[TASK_COMM_LEN];
};

struct event {
    unsigned long long ts_ns;
    unsigned long long start_time_ns;

    unsigned int pid;
    unsigned int tid;
    unsigned int ppid;
    unsigned int uid;

    int exit_code;
    int sig;

    unsigned char core_dumped;
    unsigned char has_sender;

    unsigned int sender_tgid;
    unsigned int sender_tid;
    unsigned int sender_uid;
    int sender_sig;
    int sender_result;

    char comm[TASK_COMM_LEN];
    char sender_comm[TASK_COMM_LEN];
};

#endif
