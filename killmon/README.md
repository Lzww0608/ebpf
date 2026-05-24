# killmon

`killmon` 是一个基于 eBPF/libbpf 的进程终止监控工具。它关注“进程最终是否真的因信号退出”，而不是只记录谁调用了 `kill()`。

运行后，当进程因为 `SIGKILL`、`SIGTERM`、`SIGSEGV` 等信号终止时，工具会输出被终止进程的信息，以及最近一次向它发送同号信号的进程信息。

## 功能

- 记录被信号终止的进程 `PID`、`TID`、`PPID`、`UID`、`COMM`
- 记录导致退出的信号名，例如 `SIGKILL`、`SIGTERM`
- 标记该退出是否带 core dump 标志
- 关联最近一次发送同号信号的进程 `PID` 和 `COMM`
- 支持只监控指定 PID
- 支持按线程粒度输出退出事件

## 原理

`killmon` 同时监听两个 tracepoint：

- `signal/signal_generate`：记录当前进程向目标 task 发送了什么信号
- `sched/sched_process_exit`：在 task 退出时读取 `task_struct->exit_code`，判断是否因信号退出

如果退出信号和最近一次记录的目标信号一致，并且时间间隔在 60 秒内，输出中会带上发送者信息。

这比只 hook `kill()` 更接近实际结果，因为 `SIGTERM` 可能被程序捕获后正常退出，`kill(pid, 0)` 也不会发送真实信号。

## 构建

需要 Linux 内核 BTF、`clang`、`bpftool`、`pkg-config`、`libbpf`、`libelf` 和 `zlib`。

```bash
cd killmon
make check-libbpf
make
```

如果目标机器不是 x86_64，可以通过 `ARCH` 指定 BPF 目标架构：

```bash
make ARCH=arm64
```

## 使用

直接运行：

```bash
sudo ./killmon
```

输出格式：

```text
TIME                PID     TID     PPID    UID    COMM             SIG        CORE  KILLER_PID  KILLER_COMM
2026-05-23 18:22:01 18422   18422   18100   1000   sleep            SIGKILL    no    18390       bash
```

只监控某个进程：

```bash
sudo ./killmon --pid 12345
```

按线程粒度输出：

```bash
sudo ./killmon --per-thread
```

## 测试

在一个终端启动监控：

```bash
sudo ./killmon
```

在另一个终端触发 `SIGKILL`：

```bash
sleep 1000 &
PID=$!
kill -9 "$PID"
```

触发 `SIGTERM`：

```bash
sleep 1000 &
PID=$!
kill -TERM "$PID"
```

注意：如果目标程序捕获了 `SIGTERM` 并自行正常退出，`killmon` 不会把它记录为“被 SIGTERM 杀死”。例如程序注册了 `SIGTERM` handler，只是设置退出标志并 `return`，这属于正常退出。

## 清理

```bash
make clean
```

## 当前限制

- 发送者是“最近一次发送同号信号的进程”，不是严格的因果证明
- 多个进程几乎同时发送同一 fatal signal 时，归因可能落到最后一次记录的发送者
- 只记录 16 字节 `comm`，不记录完整命令行
- 默认只输出进程 leader 的退出事件；需要每个线程时使用 `--per-thread`
- 正常 `exit(0)`、`exit(1)` 等非信号退出不会输出
