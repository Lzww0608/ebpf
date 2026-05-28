//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_PATH 256

#define EVT_EXEC    1
#define EVT_FILE    2
#define EVT_SYSCALL 3
#define EVT_PRIV    4

#define SEV_LOW      1
#define SEV_MEDIUM   2
#define SEV_HIGH     3
#define SEV_CRITICAL 4

#define SYS_PTRACE          101
#define SYS_BPF             321
#define SYS_OPENAT          257
#define SYS_EXECVE          59
#define SYS_SETUID          105
#define SYS_SETGID          106
#define SYS_SETRESUID       117
#define SYS_SETRESGID       119
#define SYS_CAPSET          126
#define SYS_PERF_EVENT_OPEN 298
#define SYS_MOUNT           165
#define SYS_UMOUNT2         166
#define SYS_PIVOT_ROOT      155
#define SYS_SETNS           308
#define SYS_UNSHARE         272
#define SYS_INIT_MODULE     175
#define SYS_FINIT_MODULE    313
#define SYS_DELETE_MODULE   176
#define SYS_KEXEC_LOAD      246
#define SYS_EXECVEAT        322
#define SYS_OPENAT2         437

#define O_WRONLY 00000001
#define O_RDWR   00000002
#define O_CREAT  00000100
#define O_TRUNC  00001000

const volatile __u32 target_tgid = 0;

struct event {
    __u64 ts_ns;

    __u32 type;
    __u32 severity;

    __u32 tgid;
    __u32 pid;
    __u32 uid;
    __u32 gid;

    __s32 syscall_id;
    __s32 ret;

    __u64 arg0;
    __u64 arg1;
    __u64 arg2;

    char comm[16];
    char path[MAX_PATH];
};

struct id_change_args {
    __u32 old_id;
    __u32 new_id;
    __s32 syscall_id;
};

struct open_how_compat {
    __u64 flags;
    __u64 mode;
    __u64 resolve;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event);
} event_type_anchor SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct id_change_args);
} active_id_changes SEC(".maps");

static __always_inline int should_skip(void)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;

    if (target_tgid != 0 && tgid != target_tgid)
        return 1;

    return 0;
}

static __always_inline void fill_common(struct event *e, __u32 type, __u32 sev, __s32 syscall_id)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    e->ts_ns = bpf_ktime_get_ns();
    e->type = type;
    e->severity = sev;

    e->tgid = pid_tgid >> 32;
    e->pid = (__u32)pid_tgid;
    e->uid = (__u32)uid_gid;
    e->gid = (__u32)(uid_gid >> 32);

    e->syscall_id = syscall_id;
    e->ret = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline struct event *reserve_event(__u32 type, __u32 sev, __s32 syscall_id)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, type, sev, syscall_id);
    return e;
}

static __always_inline int starts_with(const char *s, const char *prefix, int n)
{
#pragma unroll
    for (int i = 0; i < 32; i++) {
        if (i >= n)
            return 1;
        if (s[i] != prefix[i])
            return 0;
        if (prefix[i] == 0)
            return 1;
    }
    return 0;
}

static __always_inline int has_ssh_segment(char *path)
{
#pragma unroll
    for (int i = 0; i < 128; i++) {
        if (path[i] == 0)
            return 0;
        if (path[i] == '/' && path[i + 1] == '.' && path[i + 2] == 's' &&
            path[i + 3] == 's' && path[i + 4] == 'h' &&
            (path[i + 5] == 0 || path[i + 5] == '/'))
            return 1;
    }

    return 0;
}

static __always_inline int sensitive_path_severity(char *path)
{
    if (starts_with(path, "/etc/shadow", 11))
        return SEV_CRITICAL;
    if (starts_with(path, "/etc/sudoers", 12))
        return SEV_CRITICAL;
    if (starts_with(path, "/etc/passwd", 11))
        return SEV_MEDIUM;
    if (starts_with(path, "/root/.ssh", 10))
        return SEV_CRITICAL;
    if (starts_with(path, "/home/", 6) && has_ssh_segment(path))
        return SEV_HIGH;
    if (starts_with(path, "/proc/kcore", 11))
        return SEV_CRITICAL;
    if (starts_with(path, "/proc/sys/kernel", 16))
        return SEV_HIGH;
    if (starts_with(path, "/var/log/auth.log", 17))
        return SEV_MEDIUM;
    if (starts_with(path, "/var/log/secure", 15))
        return SEV_MEDIUM;

    return 0;
}

static __always_inline int write_like_flags(__u64 flags)
{
    return (flags & O_WRONLY) || (flags & O_RDWR) || (flags & O_CREAT) || (flags & O_TRUNC);
}

static __always_inline int submit_file_event(const char *filename, __u64 flags, __s32 syscall_id)
{
    struct event *e = reserve_event(EVT_FILE, SEV_LOW, syscall_id);
    if (!e)
        return 0;

    long n = bpf_probe_read_user_str(e->path, sizeof(e->path), filename);
    if (n <= 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    int sev = sensitive_path_severity(e->path);
    if (sev == 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    if (write_like_flags(flags) && sev < SEV_CRITICAL)
        sev = SEV_CRITICAL;

    e->severity = sev;
    e->arg0 = flags;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline int submit_exec_event(const char *filename, __s32 syscall_id)
{
    struct event *e = reserve_event(EVT_EXEC, SEV_LOW, syscall_id);
    if (!e)
        return 0;

    long n = bpf_probe_read_user_str(e->path, sizeof(e->path), filename);
    if (n <= 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline int submit_syscall_event(struct trace_event_raw_sys_enter *ctx, __s32 syscall_id, __u32 sev)
{
    struct event *e = reserve_event(EVT_SYSCALL, sev, syscall_id);
    if (!e)
        return 0;

    e->arg0 = ctx->args[0];
    e->arg1 = ctx->args[1];
    e->arg2 = ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;

    const char *filename = (const char *)ctx->args[1];
    __u64 flags = (__u64)ctx->args[2];
    return submit_file_event(filename, flags, SYS_OPENAT);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_openat2(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;

    const char *filename = (const char *)ctx->args[1];
    const struct open_how_compat *user_how = (const struct open_how_compat *)ctx->args[2];
    struct open_how_compat how = {};

    bpf_probe_read_user(&how, sizeof(how), user_how);
    return submit_file_event(filename, how.flags, SYS_OPENAT2);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;

    return submit_exec_event((const char *)ctx->args[0], SYS_EXECVE);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;

    return submit_exec_event((const char *)ctx->args[1], SYS_EXECVEAT);
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;
    return submit_syscall_event(ctx, SYS_PTRACE, SEV_HIGH);
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;
    return submit_syscall_event(ctx, SYS_BPF, SEV_HIGH);
}

SEC("tracepoint/syscalls/sys_enter_perf_event_open")
int trace_perf_event_open(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;
    return submit_syscall_event(ctx, SYS_PERF_EVENT_OPEN, SEV_MEDIUM);
}

SEC("tracepoint/syscalls/sys_enter_mount")
int trace_mount(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;
    return submit_syscall_event(ctx, SYS_MOUNT, SEV_HIGH);
}

SEC("tracepoint/syscalls/sys_enter_umount2")
int trace_umount2(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;
    return submit_syscall_event(ctx, SYS_UMOUNT2, SEV_HIGH);
}

SEC("tracepoint/syscalls/sys_enter_pivot_root")
int trace_pivot_root(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;
    return submit_syscall_event(ctx, SYS_PIVOT_ROOT, SEV_HIGH);
}

SEC("tracepoint/syscalls/sys_enter_setns")
int trace_setns(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;
    return submit_syscall_event(ctx, SYS_SETNS, SEV_HIGH);
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int trace_unshare(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;
    return submit_syscall_event(ctx, SYS_UNSHARE, SEV_MEDIUM);
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int trace_init_module(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;
    return submit_syscall_event(ctx, SYS_INIT_MODULE, SEV_CRITICAL);
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int trace_finit_module(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;
    return submit_syscall_event(ctx, SYS_FINIT_MODULE, SEV_CRITICAL);
}

SEC("tracepoint/syscalls/sys_enter_delete_module")
int trace_delete_module(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;
    return submit_syscall_event(ctx, SYS_DELETE_MODULE, SEV_CRITICAL);
}

SEC("tracepoint/syscalls/sys_enter_kexec_load")
int trace_kexec_load(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;
    return submit_syscall_event(ctx, SYS_KEXEC_LOAD, SEV_CRITICAL);
}

SEC("tracepoint/syscalls/sys_enter_capset")
int trace_capset(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;

    struct event *e = reserve_event(EVT_PRIV, SEV_CRITICAL, SYS_CAPSET);
    if (!e)
        return 0;

    e->arg0 = ctx->args[0];
    e->arg1 = ctx->args[1];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline void remember_id_change(__s32 syscall_id, __u32 old_id, __u32 new_id)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct id_change_args args = {};

    args.old_id = old_id;
    args.new_id = new_id;
    args.syscall_id = syscall_id;

    bpf_map_update_elem(&active_id_changes, &pid_tgid, &args, BPF_ANY);
}

static __always_inline __u32 choose_setres_id(__u64 a0, __u64 a1, __u64 a2, __u32 old_id)
{
    __u32 no_change = (__u32)-1;
    __u32 v0 = (__u32)a0;
    __u32 v1 = (__u32)a1;
    __u32 v2 = (__u32)a2;

    if (v1 != no_change)
        return v1;
    if (v0 != no_change)
        return v0;
    if (v2 != no_change)
        return v2;
    return old_id;
}

static __always_inline int submit_id_change_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct id_change_args *args = bpf_map_lookup_elem(&active_id_changes, &pid_tgid);
    if (!args)
        return 0;

    if (ctx->ret == 0) {
        struct event *e = reserve_event(EVT_PRIV, SEV_MEDIUM, args->syscall_id);
        if (e) {
            e->ret = (__s32)ctx->ret;
            e->arg0 = args->old_id;
            e->arg1 = args->new_id;

            if (args->old_id != 0 && args->new_id == 0)
                e->severity = SEV_CRITICAL;
            else if (args->old_id != args->new_id)
                e->severity = SEV_HIGH;

            bpf_ringbuf_submit(e, 0);
        }
    }

    bpf_map_delete_elem(&active_id_changes, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_enter_setuid(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;

    __u64 uid_gid = bpf_get_current_uid_gid();
    remember_id_change(SYS_SETUID, (__u32)uid_gid, (__u32)ctx->args[0]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setuid")
int trace_exit_setuid(struct trace_event_raw_sys_exit *ctx)
{
    return submit_id_change_exit(ctx);
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_enter_setgid(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;

    __u64 uid_gid = bpf_get_current_uid_gid();
    remember_id_change(SYS_SETGID, (__u32)(uid_gid >> 32), (__u32)ctx->args[0]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setgid")
int trace_exit_setgid(struct trace_event_raw_sys_exit *ctx)
{
    return submit_id_change_exit(ctx);
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int trace_enter_setresuid(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 old_uid = (__u32)uid_gid;
    __u32 new_uid = choose_setres_id(ctx->args[0], ctx->args[1], ctx->args[2], old_uid);

    remember_id_change(SYS_SETRESUID, old_uid, new_uid);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setresuid")
int trace_exit_setresuid(struct trace_event_raw_sys_exit *ctx)
{
    return submit_id_change_exit(ctx);
}

SEC("tracepoint/syscalls/sys_enter_setresgid")
int trace_enter_setresgid(struct trace_event_raw_sys_enter *ctx)
{
    if (should_skip())
        return 0;

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 old_gid = (__u32)(uid_gid >> 32);
    __u32 new_gid = choose_setres_id(ctx->args[0], ctx->args[1], ctx->args[2], old_gid);

    remember_id_change(SYS_SETRESGID, old_gid, new_gid);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setresgid")
int trace_exit_setresgid(struct trace_event_raw_sys_exit *ctx)
{
    return submit_id_change_exit(ctx);
}
