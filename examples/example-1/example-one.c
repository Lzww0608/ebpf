/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

// 定义 BPF_NO_GLOBAL_DATA 宏，禁用全局数据
#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;
const volatile pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 监听 syscalls:sys_enter_write
SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx) {
    // 获取当前进程 PID
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    // 如果 PID 过滤条件通过，返回 0
    if (pid_filter && pid != pid_filter) {
        return 0;
    }
    // 打印日志
    bpf_printk("BPF triggered sys_enter_write from PID %d.\n", pid);
    // 返回 0
    return 0;
}


/*
用户态进程调用 write()
        ↓
进入内核 syscall 入口
        ↓
触发 tracepoint: syscalls:sys_enter_write
        ↓
执行 handle_tp()
        ↓
获取当前进程 PID
        ↓
如果 PID 过滤条件通过，打印日志
        ↓
返回 0，write() 继续执行
*/