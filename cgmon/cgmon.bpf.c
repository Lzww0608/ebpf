#include "vmlinux.h"
#include "cgmon.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct task_runtime {
    unsigned long long start_ns;
    unsigned long long cgid;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, unsigned long long);
    __type(value, struct task_runtime);
} task_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, unsigned long long);
    __type(value, struct cg_stats);
} cg_stats_map SEC(".maps");

static __always_inline void ensure_cg_stats(unsigned long long cgid)
{
    struct cg_stats zero = {};

    if (cgid == 0)
        return;

    bpf_map_update_elem(&cg_stats_map, &cgid, &zero, BPF_NOEXIST);
}

static __always_inline void add_cpu(unsigned long long cgid,
                                    unsigned long long delta_ns)
{
    struct cg_stats *s;

    if (cgid == 0 || delta_ns == 0)
        return;

    ensure_cg_stats(cgid);

    s = bpf_map_lookup_elem(&cg_stats_map, &cgid);
    if (!s)
        return;

    __sync_fetch_and_add(&s->cpu_ns, delta_ns);
}

static __always_inline void add_io(long ret, int is_write)
{
    unsigned long long cgid;
    struct cg_stats *s;

    if (ret <= 0)
        return;

    cgid = bpf_get_current_cgroup_id();
    if (cgid == 0)
        return;

    ensure_cg_stats(cgid);

    s = bpf_map_lookup_elem(&cg_stats_map, &cgid);
    if (!s)
        return;

    if (is_write) {
        __sync_fetch_and_add(&s->write_bytes, (unsigned long long)ret);
        __sync_fetch_and_add(&s->write_calls, 1);
        return;
    }

    __sync_fetch_and_add(&s->read_bytes, (unsigned long long)ret);
    __sync_fetch_and_add(&s->read_calls, 1);
}

static __always_inline unsigned long long task_cgroup_id(struct task_struct *task)
{
    struct css_set *cgroups;
    struct cgroup *cgrp;
    struct kernfs_node *kn;

    cgroups = BPF_CORE_READ(task, cgroups);
    if (!cgroups)
        return 0;

    cgrp = BPF_CORE_READ(cgroups, dfl_cgrp);
    if (!cgrp)
        return 0;

    kn = BPF_CORE_READ(cgrp, kn);
    if (!kn)
        return 0;

    return BPF_CORE_READ(kn, id);
}

static __always_inline unsigned long long task_pid_tgid(struct task_struct *task)
{
    unsigned int pid = BPF_CORE_READ(task, pid);
    unsigned int tgid = BPF_CORE_READ(task, tgid);

    return ((unsigned long long)tgid << 32) | pid;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(handle_sched_switch,
             bool preempt,
             struct task_struct *prev,
             struct task_struct *next,
             unsigned int prev_state)
{
    unsigned long long now = bpf_ktime_get_ns();
    unsigned long long prev_key = task_pid_tgid(prev);
    struct task_runtime *rt;
    unsigned long long next_key;
    unsigned long long next_cgid;
    struct task_runtime new_rt;

    (void)preempt;
    (void)prev_state;

    rt = bpf_map_lookup_elem(&task_start, &prev_key);
    if (rt) {
        if (now > rt->start_ns)
            add_cpu(rt->cgid, now - rt->start_ns);

        bpf_map_delete_elem(&task_start, &prev_key);
    }

    next_key = task_pid_tgid(next);
    next_cgid = task_cgroup_id(next);
    if (next_cgid == 0)
        return 0;

    new_rt.start_ns = now;
    new_rt.cgid = next_cgid;
    bpf_map_update_elem(&task_start, &next_key, &new_rt, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int handle_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    add_io(ctx->ret, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pread64")
int handle_exit_pread64(struct trace_event_raw_sys_exit *ctx)
{
    add_io(ctx->ret, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_readv")
int handle_exit_readv(struct trace_event_raw_sys_exit *ctx)
{
    add_io(ctx->ret, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int handle_exit_write(struct trace_event_raw_sys_exit *ctx)
{
    add_io(ctx->ret, 1);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pwrite64")
int handle_exit_pwrite64(struct trace_event_raw_sys_exit *ctx)
{
    add_io(ctx->ret, 1);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_writev")
int handle_exit_writev(struct trace_event_raw_sys_exit *ctx)
{
    add_io(ctx->ret, 1);
    return 0;
}
