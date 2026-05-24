# slow-sql-ebpf

`slow-sql-ebpf` 是一个基于 eBPF/libbpf 的 MySQL 慢 SQL 监控工具。它在 syscall 层解析明文 MySQL Classic Protocol 的 `COM_QUERY` 请求，并用 MySQL 第一次写响应的时间估算 SQL 延迟。

## 原理

- 监听 `mysqld`/`mariadbd` 的 `read`、`recvfrom`，解析 MySQL packet 头和 `COM_QUERY` payload。
- 支持常见的两段式读取：一次 syscall 读取 4 字节 packet header，下一次 syscall 读取 payload。
- 按 `tgid + fd` 保存 SQL 文本、开始时间、线程和用户信息。
- 监听 `write`、`writev`、`sendto`、`sendmsg`，把第一次响应写出视为 SQL 完成到首包响应。
- 当延迟超过阈值时，通过 ring buffer 输出慢 SQL 事件。

这个工具统计的是“收到 `COM_QUERY` 到首次响应写出”的时间，不是完整结果集全部发送完成的时间。

## 支持范围

- MySQL Classic Protocol
- 明文 `COM_QUERY`
- MySQL 8 客户端无 query attributes 时常见的 `command + 0 + 1 + SQL` payload
- Unix socket / TCP socket，只要 syscall 层能看到明文 MySQL packet
- 指定 PID 过滤，或默认按 `comm == "mysqld"` / `comm == "mariadbd"` 过滤

## 不支持

- TLS 加密连接
- MySQL compression
- prepared statement 的完整 SQL 还原
- `recvmsg` / `readv` 请求解析
- 多包 SQL 完整重组
- 完整结果集发送结束时间
- `CLIENT_QUERY_ATTRIBUTES` 下带真实 attributes 的完整结构

## 构建

需要 Linux 内核 BTF、`clang`、`bpftool`、`pkg-config`、`libbpf`、`libelf` 和 `zlib`。

```bash
cd slow-sql-ebpf
make check-libbpf
make
```

如果目标机器不是 x86_64，可以通过 `ARCH` 指定 BPF 目标架构：

```bash
make ARCH=arm64
```

## 使用

推荐指定 MySQL Server 的 PID：

```bash
sudo ./slow_sql --pid $(pidof mysqld) --threshold-ms 100
```

MariaDB：

```bash
sudo ./slow_sql --pid $(pidof mariadbd) --threshold-ms 100
```

不指定 `--pid` 时，BPF 程序按进程名过滤 `mysqld` 和 `mariadbd`。

输出格式：

```text
TIME                PID     TID     UID    FD    LAT(ms)   COMM       SQL
2026-05-24 22:10:31 1832    1960    112    45    201.434   mysqld     SELECT SLEEP(0.2)
```

## 测试

在一个终端启动监控：

```bash
sudo ./slow_sql --pid $(pidof mysqld) --threshold-ms 100
```

在另一个终端执行慢 SQL：

```bash
mysql -uroot -e "SELECT SLEEP(0.2);"
```

如果需要强制走 TCP 明文连接：

```bash
mysql --protocol=TCP --ssl-mode=DISABLED -h127.0.0.1 -uroot -p -e "SELECT SLEEP(0.2);"
```

低于阈值的 SQL 默认不会输出：

```bash
mysql -uroot -e "SELECT 1;"
```

## 排查

确认 MySQL 是否使用了当前 MVP 支持的 syscall：

```bash
sudo strace -fp $(pidof mysqld) \
  -e trace=read,recvfrom,recvmsg,readv,write,writev,sendto,sendmsg
```

如果请求走 `recvmsg` 或 `readv`，当前版本抓不到 SQL 请求，需要扩展 iovec 解析。

如果看到类似下面的两段式读取，这是当前版本支持的路径：

```text
recvfrom(fd, "\24\0\0\0", 4, ...) = 4
recvfrom(fd, "\3\0\1SELECT SLEEP(0.2)", 20, ...) = 20
```

如果启用了 TLS，syscall 层看到的是 TLS record，不是 MySQL 明文包。更准确的生产级方案通常是 uprobe `SSL_read`/`SSL_write`，或 uprobe MySQL 内部 `dispatch_command` 路径。

## 清理

```bash
make clean
```
