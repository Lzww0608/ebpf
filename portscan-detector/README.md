# portscan-detector

`portscan-detector` 是一个基于 XDP/eBPF 的端口扫描检测练习项目。它在指定网卡的 ingress 路径上统计 IPv4 TCP `SYN && !ACK` 包；如果同一个源 IP 在短时间窗口内访问了大量不同目的端口，就通过 ring buffer 输出告警。

默认只监控不丢包，XDP 程序返回 `XDP_PASS`。只有显式指定 `--drop` 后，才会在某个源 IP 触发告警后丢弃该窗口内后续来自这个源 IP 的 TCP SYN 包。

## 检测语义

- 只统计 IPv4 + TCP + SYN + 非 ACK 的入站连接尝试
- 按源 IPv4 地址聚合
- `scan_states` 记录每个源 IP 的窗口开始时间、最近访问时间、不同端口数和告警状态
- `seen_ports` 用 `src_ip + window_start_ns + dst_port` 去重，避免重复访问同一端口时重复计数
- `events` ring buffer 把首次达到阈值的告警发送到用户态

当前窗口是 per-source tumbling window，不是严格 sliding window：

```text
源 IP 第一次 SYN 到达 -> 开始窗口
窗口内每出现一个新的目的端口 -> distinct_ports + 1
达到阈值 -> 告警一次
窗口过期后 -> 重新统计
```

## 构建

需要 Linux 内核 BTF、`clang`、`bpftool`、`pkg-config`、`libbpf`、`libelf` 和 `zlib`。

```bash
cd portscan-detector
make check-libbpf
make
```

如果目标机器不是 x86_64，可以通过 `ARCH` 指定 BPF 目标架构：

```bash
make ARCH=arm64
```

## 使用

查看网卡名：

```bash
ip link
```

在 `eth0` 上监控，10 秒内访问 20 个不同目的端口时告警：

```bash
sudo ./portscan -i eth0 --ports 20 --window 10 --mode skb
```

`--mode skb` 是 generic XDP，兼容性最好；`--mode drv` 是 native XDP，性能更好，但需要网卡驱动支持。

如果该网卡已经挂载了 XDP 程序，可以用 `--force` 替换：

```bash
sudo ./portscan -i eth0 --ports 20 --window 10 --mode skb --force
```

启用告警后丢包：

```bash
sudo ./portscan -i eth0 --ports 20 --window 10 --drop
```

建议先观察误报情况，再启用 `--drop`。

输出示例：

```text
TIME                IFINDEX  SRC_IP          PORTS  THRESHOLD  WINDOW(s) LAST_PORT
2026-05-25 16:20:31 2        192.168.1.55    20     20         10        3306
```

## 测试

只在你控制的实验环境里执行测试。假设实验机 IP 是 `192.168.1.100`，在另一台机器上执行：

```bash
nmap -sS -p 1-100 192.168.1.100
```

也可以不用 `nmap`，用 Bash 触发一批 TCP 连接尝试：

```bash
for p in $(seq 1 30); do
  timeout 0.2 bash -c "</dev/tcp/192.168.1.100/$p" 2>/dev/null &
done
wait
```

确认 XDP 挂载状态：

```bash
ip -details link show eth0
```

如果异常退出导致 XDP 程序残留，可以手动卸载：

```bash
sudo ip link set dev eth0 xdp off
```

## 清理

```bash
make clean
```

## 当前限制

- 不统计 TCP SYN+ACK、ACK、UDP scan、IPv6 scan、FIN scan、NULL scan、XMAS scan
- 不解析 VLAN、GRE、VXLAN 等封装流量
- NAT 后的多个用户会被聚合成同一个源 IP，可能造成误报
- 使用 per-source tumbling window，低速扫描可以通过拉长时间间隔降低触发概率
- XDP 挂在单个网卡上，多入口网卡需要分别运行或扩展多 `-i` 支持
