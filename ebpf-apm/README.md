# ebpf-apm

`ebpf-apm` 是一个最小可运行的轻量 APM Agent。它在 syscall 层观察指定进程的明文 HTTP/1.x `read`/`write`，自动解析请求方法、路径和响应状态码，并通过 Prometheus 暴露接口调用次数、延迟直方图和 5xx 错误数。

## 指标

- `http_requests_total{method,route,status}`：按 HTTP method、归一化 route 和状态码统计请求数。
- `http_request_duration_seconds{method,route}`：请求从读到请求行到写出响应行的延迟直方图。
- `http_errors_total{method,route}`：状态码大于等于 500 的服务端错误数。

错误率可以在 Prometheus 中按需查询，例如：

```promql
sum(rate(http_errors_total[5m])) by (method, route)
/
sum(rate(http_requests_total[5m])) by (method, route)
```

## 原理

- `tracepoint/syscalls/sys_enter_read` 记录当前线程的 `fd`、`buf` 和 `count`。
- `tracepoint/syscalls/sys_exit_read` 在读取成功后解析 HTTP 请求行，提取 `method` 和原始 `path`，并按 `{tgid, fd}` 记录开始时间。
- `tracepoint/syscalls/sys_enter_write` 解析 HTTP 响应行状态码，查找同一 `{tgid, fd}` 上的 inflight 请求，计算延迟后通过 ring buffer 发送事件。
- Go 用户态 Agent 读取事件，归一化 `/api/users/123` 和 UUID 路径段，然后维护 Prometheus 指标。

## 构建

需要 Linux 5.8+、内核 BTF、root 或相应 BPF 权限，以及 `clang`、`bpftool`、`make` 和 Go。

```bash
cd ebpf-apm
go mod tidy
make
```

非 x86_64 目标可以指定 BPF 架构：

```bash
make ARCH=arm64
```

只运行用户态归一化测试：

```bash
make test
```

## Demo

启动测试 HTTP 服务：

```bash
cd ebpf-apm
make demo
./demo-http
```

另一个终端启动 Agent：

```bash
PID=$(pidof demo-http)
sudo ./ebpf-apm --pid "$PID" --listen :2112
```

也可以用 Makefile 构建并运行：

```bash
make run PID=$(pidof demo-http)
```

压测几次接口：

```bash
for i in $(seq 1 100); do
  curl -s "http://127.0.0.1:8080/api/users/$i" > /dev/null
  curl -s -X POST "http://127.0.0.1:8080/api/orders" > /dev/null
done
```

查看指标：

```bash
curl -s http://127.0.0.1:2112/metrics | grep '^http_'
```

预期能看到类似：

```text
http_requests_total{method="GET",route="/api/users/{id}",status="200"} 100
http_errors_total{method="POST",route="/api/orders"} 17
http_request_duration_seconds_count{method="GET",route="/api/users/{id}"} 100
```

## 当前边界

- 只解析明文 HTTP/1.x。
- 只 hook `read` 和 `write`，暂不覆盖 `recvfrom`、`sendto`、`writev`、`sendmsg`、`io_uring` 和 `sendfile`。
- `{tgid, fd}` 关联模型适合 HTTP/1.1 串行 keep-alive，不适合 HTTP pipelining、HTTP/2 或多路复用协议。
- 路由归一化只处理数字段和 UUID 段；生产环境应接入显式 route 规则，避免 Prometheus 高基数。
- 延迟口径是“读到请求行”到“写出响应行”，不是完整响应体发送完毕时间。

## 排查

确认服务是否真的通过当前 MVP 支持的 syscall 收发明文 HTTP：

```bash
sudo strace -fp "$PID" -e trace=read,write,recvfrom,sendto,writev,sendmsg
```

如果看到 TLS 密文、HTTP/2 frame、`recvmsg` 或 `writev` 路径，需要扩展对应 hook 或改用 `SSL_read`/`SSL_write` uprobe。

## 清理

```bash
make clean
```
