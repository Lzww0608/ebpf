#include "vmlinux.h"
#include "killmon.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define TRACE_SIGNAL_DELIVERED 0

#define SIGNAL_MASK 0x7f
#define CORE_DUMPED 0x80

#define MAX_SIGNAL_AGE_NS (60ULL * 1000000000ULL)

const volatile int target_pid = 0;
const volatile bool per_thread = false;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, unsigned int);
    __type(value, struct signal_info);
} last_signals SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int valid_signal(int sig)
{
    return sig > 0 && sig <= 64;
}

SEC("tracepoint/signal/signal_generate")
int handle_signal_generate(struct trace_event_raw_signal_generate *ctx)
{
    unsigned long long pid_tgid;
    unsigned int victim_pid;
    struct signal_info info = {};
    int sig = ctx->sig;

    if (!valid_signal(sig))
        return 0;

    if (ctx->result != TRACE_SIGNAL_DELIVERED)
        return 0;

    victim_pid = ctx->pid;
    pid_tgid = bpf_get_current_pid_tgid();

    info.ts_ns = bpf_ktime_get_ns();
    info.target_pid = victim_pid;
    info.sender_tgid = pid_tgid >> 32;
    info.sender_tid = (unsigned int)pid_tgid;
    info.sender_uid = (unsigned int)bpf_get_current_uid_gid();
    info.sig = sig;
    info.result = ctx->result;

    bpf_get_current_comm(info.sender_comm, sizeof(info.sender_comm));

    bpf_map_update_elem(&last_signals, &victim_pid, &info, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct signal_info *si;
    struct event *e;
    unsigned int tid;
    unsigned int tgid;
    int exit_code;
    int sig;

    (void)ctx;

    tid = BPF_CORE_READ(task, pid);
    tgid = BPF_CORE_READ(task, tgid);

    if (!per_thread && tid != tgid)
        return 0;

    if (target_pid != 0 && tgid != (unsigned int)target_pid)
        return 0;

    exit_code = BPF_CORE_READ(task, exit_code);
    sig = exit_code & SIGNAL_MASK;
    if (!valid_signal(sig))
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    e->ts_ns = bpf_ktime_get_ns();
    e->start_time_ns = BPF_CORE_READ(task, start_time);
    e->pid = tgid;
    e->tid = tid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->uid = (unsigned int)bpf_get_current_uid_gid();
    e->exit_code = exit_code;
    e->sig = sig;
    e->core_dumped = !!(exit_code & CORE_DUMPED);

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    si = bpf_map_lookup_elem(&last_signals, &tid);
    if (!si && tid != tgid)
        si = bpf_map_lookup_elem(&last_signals, &tgid);

    if (si) {
        unsigned long long age = e->ts_ns - si->ts_ns;

        if (si->sig == sig && age <= MAX_SIGNAL_AGE_NS) {
            e->has_sender = 1;
            e->sender_tgid = si->sender_tgid;
            e->sender_tid = si->sender_tid;
            e->sender_uid = si->sender_uid;
            e->sender_sig = si->sig;
            e->sender_result = si->result;
            __builtin_memcpy(e->sender_comm, si->sender_comm, TASK_COMM_LEN);
        }
    }

    bpf_map_delete_elem(&last_signals, &tid);
    if (tid != tgid)
        bpf_map_delete_elem(&last_signals, &tgid);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
