# tcpconn-count

`tcpconn-count` 是一个基于 eBPF/libbpf 的 TCP 连接建立统计工具，用于统计系统中进程的 TCP 连接建立次数，并区分主动连接和被动接受连接。

## 功能

- 统计每个进程的主动 TCP 连接数：`active`
- 统计每个进程通过 `accept/accept4` 接收的连接数：`passive`
- 显示总连接数：`total = active + passive`
- 显示最近一次连接的远端 IP/端口
- 支持按 PID 或 cgroup id 聚合
- 支持按 PID、进程名过滤
- 支持只统计主动连接或只统计被动连接
- 支持 ring buffer 实时输出每次连接事件
- 支持 Prometheus text 格式输出
- 支持定期清理已退出进程的统计行

## 实现概览

工具挂载内核 TCP 栈函数，而不是简单监听 `connect()` syscall：

- `tcp_v4_connect` / `tcp_v6_connect`：记录主动连接发起者
- `tcp_finish_connect`：主动连接真正建立后计数
- `inet_csk_accept`：服务端进程成功 accept 后计数
- `tcp_close`：清理未完成连接的残留状态

## 构建

确认目标系统已安装 `clang`、`bpftool`、`libbpf`、`pkg-config` 等依赖后执行：

```bash
make clean
make
```

默认按 x86 架构编译 BPF 程序。其他架构可指定 `ARCH`，例如：

```bash
make ARCH=arm64
```

## 使用

基础运行：

```bash
sudo ./tcpconn_count -i 2
```

输出示例：

```text
PID      COMM             CGROUP_ID            ACTIVE       PASSIVE      TOTAL        LAST_REMOTE
18420    curl             12345                5            0            5            93.184.216.34:443
18431    python3          67890                0            12           12           127.0.0.1:51844
```

查看帮助：

```bash
./tcpconn_count --help
```

常用参数：

```text
-i, --interval SEC     输出间隔，默认 2 秒
-p, --pid PID          只统计指定 PID
-c, --comm COMM        只统计指定进程名，最多 15 字节
    --active-only      只统计主动连接
    --passive-only     只统计被动 accept
    --events           实时输出每次连接事件
    --prometheus       输出 Prometheus text 格式
    --group-by MODE    聚合方式：pid 或 cgroup
    --cleanup          每个输出周期清理已退出 PID 的统计行
```

## 示例

只看 `curl` 的连接事件：

```bash
sudo ./tcpconn_count --events --comm curl
```

只统计某个进程的主动连接：

```bash
sudo ./tcpconn_count --pid 1234 --active-only
```

按 cgroup 聚合：

```bash
sudo ./tcpconn_count --group-by cgroup
```

输出 Prometheus text metrics：

```bash
sudo ./tcpconn_count --prometheus
```

定期清理已退出进程：

```bash
sudo ./tcpconn_count --cleanup
```

## 测试方式

主动连接测试：

```bash
curl -s https://example.com >/dev/null
```

被动连接测试：

```bash
python3 -m http.server 8000
curl -s http://127.0.0.1:8000 >/dev/null
```

此时 `curl` 应增加 `active`，`python3` 应增加 `passive`。

## 限制

- `comm` 来自 Linux task comm，最长 16 字节，显示完整命令行需要额外读取 `/proc/<pid>/cmdline`。
- cgroup/container 聚合当前按内核 `cgroup_id` 展示，不反查容器名称。
- `passive` 统计的是用户态进程成功 accept 的次数；TCP 三次握手完成可能早于 accept。
- 特殊 TCP 路径、MPTCP 或内核模块自定义路径可能不完全经过当前 hook 点。
