# xdp-ddos-guard

`xdp-ddos-guard` 是一个基于 XDP/eBPF 的轻量级 L3/L4 DDoS 防护工具。它在网卡入口路径解析 IPv4 流量，优先放行白名单 CIDR，丢弃黑名单 CIDR，并对每个源 IPv4 做 PPS/BPS 固定窗口限流；超过阈值的源 IP 会被临时封禁。

## 能力

- 白名单：`BPF_MAP_TYPE_LPM_TRIE`，按 IPv4 CIDR 优先放行。
- 黑名单：`BPF_MAP_TYPE_LPM_TRIE`，按 IPv4 CIDR 丢弃。
- 限流：`BPF_MAP_TYPE_LRU_HASH` 保存每个源 IP 的 1 秒窗口状态。
- 临时封禁：超过 PPS 或 BPS 阈值后，在 `rate_v4` 中设置封禁截止时间。
- 动态规则：HTTP API 更新黑白名单 Map，不需要重新加载 XDP 程序。
- 指标：`/stats` 返回 JSON，`/metrics` 暴露 Prometheus 指标。

当前版本只支持 IPv4。白名单优先级高于黑名单，黑名单优先级高于限流。

## 构建

需要 Linux、内核 BTF、root 或 BPF 权限，以及 `clang`、`bpftool`、`make` 和 Go。

```bash
cd xdp-ddos-guard
go mod tidy
make
```

非 x86_64 目标可以指定 BPF 架构：

```bash
make ARCH=arm64
```

只运行用户态 helper 测试：

```bash
make test
```

## 运行

保护 `eth0` 上的所有入站 IPv4 流量：

```bash
sudo ./xdp-ddos-guard \
  --iface eth0 \
  --pps 5000 \
  --bps 52428800 \
  --block-seconds 10 \
  --listen :2114
```

只对目标端口 `8080` 的 TCP/UDP 流量限流：

```bash
sudo ./xdp-ddos-guard \
  --iface eth0 \
  --pps 100 \
  --bps 1048576 \
  --block-seconds 10 \
  --port 8080
```

启动时加载初始规则：

```bash
sudo ./xdp-ddos-guard \
  --iface eth0 \
  --blacklist 203.0.113.0/24 \
  --whitelist 10.0.0.0/8
```

## 动态规则

添加黑名单：

```bash
curl -X POST http://127.0.0.1:2114/blacklist \
  -H 'Content-Type: application/json' \
  -d '{"cidr":"198.51.100.23/32"}'
```

删除黑名单：

```bash
curl -X DELETE 'http://127.0.0.1:2114/blacklist?cidr=198.51.100.23/32'
```

添加白名单：

```bash
curl -X POST http://127.0.0.1:2114/whitelist \
  -H 'Content-Type: application/json' \
  -d '{"cidr":"10.1.0.0/16"}'
```

## 观测

查看 JSON 统计：

```bash
curl http://127.0.0.1:2114/stats
```

查看 Prometheus 指标：

```bash
curl -s http://127.0.0.1:2114/metrics | grep '^xdp_ddos'
```

指标名：

- `xdp_ddos_packets_total{action="total"}`
- `xdp_ddos_packets_total{action="pass"}`
- `xdp_ddos_packets_total{action="drop_blacklist"}`
- `xdp_ddos_packets_total{action="drop_ratelimit"}`
- `xdp_ddos_packets_total{action="pass_whitelist"}`
- `xdp_ddos_packets_total{action="non_ipv4"}`

## 验证建议

```bash
python3 -m http.server 8080
sudo ./xdp-ddos-guard --iface eth0 --pps 100 --bps 1048576 --block-seconds 10 --port 8080
curl http://<server-ip>:8080/
```

黑名单验证：

```bash
curl -X POST http://127.0.0.1:2114/blacklist \
  -H 'Content-Type: application/json' \
  -d '{"cidr":"<client-ip>/32"}'
```

预期客户端访问失败或超时，`drop_blacklist` 增加。

白名单优先级验证：将同一 IP 同时加入黑名单和白名单，预期流量继续通过，`pass_whitelist` 增加。

## 当前边界

- 只支持 IPv4；IPv6 需要增加独立的 LPM Trie 和 rate map。
- 限流使用固定窗口，窗口边界可能允许短时间突刺。
- per-source-IP 状态在多核 XDP 路径上是近似计数，适合削峰，不适合计费级精确统计。
- 不做 L7 HTTP 语义分析。
- 不逐包上报 drop 事件，避免攻击时拖垮用户态。
- 端口保护模式下，非首片 IPv4 分片会放行。

## 清理

```bash
make clean
```
