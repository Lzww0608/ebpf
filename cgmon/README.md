# cgmon

`cgmon` 是一个基于 eBPF/libbpf 和 cgroup v2 的容器资源监控工具。它用 tracing 程序按 cgroup id 统计 CPU runtime 和 read/write syscall 字节数，同时在用户态读取 cgroupfs 中的内存与块 IO 账本。

## 指标

- `CPU%`：eBPF 通过 `tp_btf/sched_switch` 估算的 cgroup CPU runtime，可能超过 100%。
- `MEM(MB)`：读取 `/sys/fs/cgroup/.../memory.current`。
- `IO_R/IO_W`：读取 cgroup v2 `io.stat` 中的块设备 `rbytes/wbytes`。
- `SYS_R/SYS_W`：eBPF 统计 `read/readv/pread64` 和 `write/writev/pwrite64` 返回字节数，包含文件、socket、pipe、tmpfs 和 page cache 命中，不等同于块设备 IO。

## 构建

需要 Linux cgroup v2、内核 BTF、`clang`、`bpftool`、`pkg-config`、`libbpf`、`libelf` 和 `zlib`。

```bash
cd cgmon
make check-libbpf
make
```

非 x86_64 目标可以指定 BPF 架构：

```bash
make ARCH=arm64
```

用户态解析逻辑可以单独测试：

```bash
make unit-test
```

## 使用

默认只显示路径看起来像容器的 cgroup：

```bash
sudo ./cgmon -i 2
```

显示所有 cgroup，并限制前 30 行：

```bash
sudo ./cgmon -i 1 --all-cgroups --top 30
```

输出示例：

```text
TIME                CGROUP_ID      CONTAINER        CPU%    MEM(MB)   IO_R(MB/s) IO_W(MB/s) SYS_R(MB/s) SYS_W(MB/s)
2026-05-26 21:10:22 88421          9f3a2c1b7e91     23.41   312.7     1.20       0.33       5.80        1.02
```

## 测试场景

CPU：

```bash
docker run --rm --name cpu-test -d ubuntu:24.04 sh -c 'yes > /dev/null'
sudo ./cgmon -i 2
docker stop cpu-test
```

内存：

```bash
docker run --rm --name mem-test -d python:3.12 python3 -c 'a=bytearray(300*1024*1024); import time; time.sleep(300)'
sudo ./cgmon -i 2
docker stop mem-test
```

块 IO：

```bash
docker run --rm --name io-test -d ubuntu:24.04 sh -c 'dd if=/dev/zero of=/tmp/test bs=1M count=1024 oflag=direct; sleep 60'
sudo ./cgmon -i 2
docker stop io-test
```

## 当前限制

- CPU 统计依赖 `tp_btf/sched_switch`，不支持时可以用 `cpu.stat usage_usec` 作为退化方案，但当前程序没有自动退化。
- cgroup id 用户态优先用 `name_to_handle_at()` 获取，失败时退回目录 inode；不同系统上退回路径可能无法和 BPF map key 完全一致。
- 容器识别是基于 cgroup path 的启发式规则，生产环境应接入 Docker/containerd/CRI 元数据。
- 内存与块 IO 使用 cgroup v2 的权威账本；eBPF syscall IO 只是补充维度。

## 清理

```bash
make clean
```
