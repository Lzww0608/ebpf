# rm-delete-monitor

一个基于 eBPF 的 Linux 删除操作监控工具，用来观察 `rm` 或其他进程执行的文件/目录删除尝试。

## 功能

- 监控 `unlink`、`unlinkat`、`rmdir` 删除操作
- 记录成功和失败的删除结果
- 输出 PID、UID、进程名、完整命令行、返回值和 errno
- 通过 BPF LSM 补充更接近 VFS 层的删除路径
- 程序退出时输出简单统计信息

## 构建

需要 Linux 环境，并安装 `clang`、`bpftool`、`libbpf`、`elfutils`、`zlib` 等依赖。

```bash
make
```

## 运行

默认只显示进程名为 `rm` 的删除事件：

```bash
sudo ./rm_monitor
```

显示所有进程的删除事件：

```bash
sudo ./rm_monitor --all
```

## 清理

```bash
make clean
```

注意：BPF LSM 需要内核支持并启用，否则程序可能加载失败。
