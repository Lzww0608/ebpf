# ebpf-mini-ids

`ebpf-mini-ids` 是一个审计型轻量 IDS Agent。它通过 eBPF tracepoint 观察高风险 syscall、敏感文件访问和 UID/GID/CAP 权限变化，在用户态执行评分、白名单和去重，然后输出 JSON 告警并暴露 Prometheus 指标。

## 能力

- 敏感文件访问：`openat`、`openat2` 访问 `/etc/shadow`、`/etc/sudoers`、`/etc/passwd`、`/root/.ssh`、`/home/*/.ssh`、`/proc/kcore`、`/proc/sys/kernel` 等路径。
- 高风险 syscall：`ptrace`、`bpf`、`perf_event_open`、`mount`、`umount2`、`pivot_root`、`setns`、`unshare`、`init_module`、`finit_module`、`delete_module`、`kexec_load`。
- 权限变化：`setuid`、`setgid`、`setresuid`、`setresgid` 成功返回后告警，`capset` 调用直接告警。
- 执行行为：`execve`、`execveat` 执行 `sudo`、`su`、`pkexec`、`doas`，或服务进程执行 shell 时告警。
- 指标：`mini_ids_events_total`、`mini_ids_alerts_total`、`mini_ids_ringbuf_read_errors_total`。

当前版本只检测和告警，不阻断行为。

## 构建

需要 Linux、内核 BTF、root 或 BPF 权限，以及 `clang`、`bpftool`、`make` 和 Go。

```bash
cd ebpf-mini-ids
go mod tidy
make
```

非 x86_64 目标可以指定 BPF 架构：

```bash
make ARCH=arm64
```

只运行用户态规则测试：

```bash
make test
```

## 运行

监控整台主机：

```bash
sudo ./mini-ids --listen :2113
```

只监控单个进程：

```bash
sudo ./mini-ids --pid 1234 --listen :2113
```

默认 60 秒内相同 `{type,pid,uid,comm,path,syscall}` 告警只输出一次。可以关闭去重：

```bash
sudo ./mini-ids --dedupe-window 0
```

告警输出为一行一个 JSON：

```json
{"time":"2026-05-28T10:23:11+08:00","type":"sensitive_file_access","severity":"critical","score":95,"pid":38291,"uid":1000,"comm":"cat","path":"/etc/shadow","reason":"accessed /etc/shadow"}
```

查看指标：

```bash
curl -s http://127.0.0.1:2113/metrics | grep '^mini_ids'
```

## 测试场景

```bash
cat /etc/passwd > /dev/null
sudo cat /etc/shadow > /dev/null
strace -p 1
bpftool prog show > /dev/null
curl -s http://127.0.0.1:2113/metrics | grep '^mini_ids'
```

预期分别产生 `/etc/passwd` medium、`/etc/shadow` critical、非白名单 `ptrace` high、非白名单 `bpf` high 告警；如果命令在白名单中，用户态规则会忽略对应告警。

## 当前边界

- `openat/openat2` 记录的是用户传入路径；相对路径暂不做 `/proc/<pid>/cwd` 还原。
- tracepoint 适合审计，不适合阻断；阻断版本应改用 eBPF LSM hook。
- `capset` V0 只记录调用，不解析 capability bitmap 是否增加了具体权限。
- `configs/rules.yaml` 是 V1 YAML 规则化的配置模板，当前二进制仍使用硬编码规则。
- 不把完整 path 放进 Prometheus label，避免高基数；完整路径只进入 JSON 告警。

## 清理

```bash
make clean
```
