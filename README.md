下面是一套**按 Eunomia eBPF 教程体系整理的完整学习路线**。核心思路是：**先用 eunomia-bpf 快速跑通 eBPF 小工具，再切到 libbpf / CO-RE 构建完整项目，最后按方向深入可观测性、网络、安全、调度器、GPU、用户态 eBPF 等专题。**

Eunomia 这套教程本身是基于 **CO-RE，一次编译、到处运行** 的 eBPF 开发教程，覆盖基本概念、代码示例和实际应用，并使用 `libbpf`、`Cilium`、`libbpf-rs`、`eunomia-bpf` 等框架，包含 C、Go、Rust 示例；它的定位不是长篇理论书，而是通过短小 eBPF 工具案例快速掌握开发方法。([Eunomia][1])

---

# 一、总学习路线

```text
阶段 0：环境与基础准备
  ↓
阶段 1：eBPF 核心概念
  ↓
阶段 2：入门示例 0-10，掌握 hook、map、事件输出
  ↓
阶段 3：高级示例 11-21，掌握 libbpf、CO-RE、完整用户态程序
  ↓
阶段 4：选择专题方向：可观测性 / 网络 / 安全 / 用户态 / 调度器 / GPU
  ↓
阶段 5：做一个自己的 eBPF 工具
```

建议学习周期：

| 节奏   |      时间 | 适合人群                      |
| ---- | ------: | ------------------------- |
| 快速入门 |   2-3 周 | 已熟悉 Linux / C / 网络 / 系统调用 |
| 正常路线 |   6-8 周 | 有 Linux 基础，但没写过 eBPF      |
| 扎实路线 | 10-12 周 | 想系统掌握并做项目                 |

---

# 二、阶段 0：环境与前置基础

## 0.1 你需要具备的基础

在正式开始前，至少要会：

| 基础         | 需要掌握到什么程度                                    |
| ---------- | -------------------------------------------- |
| Linux 命令   | `ps`、`top`、`strace`、`lsof`、`ip`、`tc`、`dmesg` |
| C 语言       | struct、指针、宏、头文件、Makefile 基础                  |
| Linux 系统概念 | 进程、线程、PID、系统调用、文件描述符                         |
| 网络基础       | TCP 三次握手、端口、socket、网卡、包处理                    |
| 内核基础       | 不要求会写内核模块，但要知道用户态 / 内核态区别                    |

Eunomia 教程明确要求较新的 Linux 内核，并建议至少 Linux 5.15+；它也强调 eBPF 程序主要由**内核态部分**和**用户态部分**组成，前者包含实际逻辑，后者负责加载、运行和监控。([Eunomia][2])

## 0.2 Ubuntu 环境安装

在 Ubuntu 上建议准备：

```bash
sudo apt update
sudo apt install -y \
  git \
  gcc \
  make \
  clang \
  llvm \
  pkg-config \
  libelf1 \
  libelf-dev \
  zlib1g-dev \
  linux-headers-$(uname -r) \
  linux-tools-common \
  linux-tools-generic
```

Eunomia 的 libbpf 示例说明，构建示例需要 `clang`、`libelf`、`zlib`，并给出了 Ubuntu/Debian 下安装 `clang libelf1 libelf-dev zlib1g-dev` 的命令。([Eunomia][3])

## 0.3 下载教程源码

```bash
git clone https://github.com/eunomia-bpf/bpf-developer-tutorial.git
cd bpf-developer-tutorial
git submodule update --init --recursive
```

这个仓库是教程完整代码所在位置，Eunomia 页面说明完整代码和教程在 GitHub 开源仓库中。([Eunomia][1])

## 0.4 安装 eunomia-bpf 工具

先安装 `ecli`，用于运行 eBPF 程序：

```bash
wget https://aka.pw/bpf-ecli -O ecli
chmod +x ./ecli
./ecli -h
```

再安装 `ecc`，用于编译 eBPF 内核代码：

```bash
wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc
chmod +x ./ecc
./ecc -h
```

教程中就是用 `ecli` 运行 eBPF 程序，用 `ecc` 将 eBPF 内核代码编译为配置文件或 WASM 模块。([Eunomia][2])

---

# 三、阶段 1：核心概念，不急着写复杂代码

目标：先搞清楚 eBPF 是什么、能挂在哪里、怎么和用户态通信。

学习内容：

| 概念                       | 你要能解释什么                                    |
| ------------------------ | ------------------------------------------ |
| BPF / eBPF               | eBPF 是在内核中安全运行小程序的机制                       |
| verifier                 | 为什么 eBPF 程序不能随便访问内存                        |
| JIT                      | eBPF 字节码如何接近原生速度运行                         |
| hook point               | tracepoint、kprobe、fentry、uprobe、XDP、TC、LSM |
| helper function          | eBPF 程序如何调用内核提供的安全函数                       |
| BPF map                  | 用户态和内核态如何共享数据                              |
| ring buffer / perf event | 内核态如何把事件发送到用户态                             |
| CO-RE / BTF              | 为什么可以“一次编译，到处运行”                           |

阅读顺序：

```text
lesson 0-introduce
→ eBPF 简介
→ eBPF 的强大之处
→ 如何使用 eBPF 编程
→ eBPF 开发工具
→ 学习 eBPF 开发的一些技巧
```

Eunomia 的 lesson 0 明确指出：eBPF 允许开发者在内核空间安全高效地运行小型程序，并通过 verifier、JIT 等机制保证安全和性能；它还总结了 eBPF 当前的主要应用领域，包括网络、可观测性、追踪分析、安全、调度器优化等。([Eunomia][4])

阶段 1 的通关标准：

```text
你应该能回答：

1. eBPF 和传统内核模块有什么区别？
2. eBPF 程序为什么需要 verifier？
3. 什么是 BPF map？
4. 什么是 tracepoint / kprobe / uprobe / XDP / TC / LSM？
5. 用户态程序和内核态 eBPF 程序分别负责什么？
```

Eunomia 也建议在入门阶段回答三个问题：eBPF 是什么、它在内核中能做什么、可用于哪些场景，例如网络、安全、可观测性。([Eunomia][4])

---

# 四、阶段 2：入门示例 0-10，掌握 eBPF 基本开发能力

这一阶段是必修。Eunomia 的入门部分主要利用 `eunomia-bpf` 简化开发，介绍 eBPF 的基本用法和开发流程。([Eunomia][1])

## 学习目标

完成后你应该能：

```text
1. 写一个最小 eBPF 程序
2. 挂载到 tracepoint / kprobe / fentry / uprobe
3. 使用 BPF map 保存状态
4. 使用 perf event array 或 ring buffer 输出事件
5. 编写简单的系统调用追踪工具
6. 理解调度延迟、进程执行、文件打开、信号发送等典型观测场景
```

## 建议学习顺序

| 顺序 | 教程                           | 重点                                 |
| -: | ---------------------------- | ---------------------------------- |
|  0 | lesson 0-introduce           | 核心概念、工具、学习方法                       |
|  1 | lesson 1-helloworld          | 最小 eBPF 程序、tracepoint、`bpf_printk` |
|  2 | lesson 2-kprobe-unlink       | 用 kprobe 监控 `unlink` 系统调用          |
|  3 | lesson 3-fentry-unlink       | 用 fentry 监控内核函数，和 kprobe 对比        |
|  4 | lesson 4-opensnoop           | 捕获文件打开事件，使用全局变量过滤 PID              |
|  5 | lesson 5-uprobe-bashreadline | 用 uprobe 追踪用户态函数                   |
|  6 | lesson 6-sigsnoop            | 使用 hash map 保存状态                   |
|  7 | lesson 7-execsnoop           | 捕获进程执行事件，用 perf event array 输出     |
|  8 | lesson 8-exitsnoop           | 监控进程退出事件，用 ring buffer 输出          |
|  9 | lesson 9-runqlat             | 捕获调度延迟，用直方图记录                      |
| 10 | lesson 10-hardirqs           | 追踪 hardirq / softirq 中断事件          |

## 每个示例都按这个方法学

不要只是运行命令。每一章都做四件事：

```text
1. 运行原始示例
2. 画出 hook 点：这个程序挂在哪里？
3. 找出 map：用了什么 map？key/value 是什么？
4. 修改一个参数或过滤条件
```

例如 lesson 1 之后，你应该能修改：

```c
const pid_t pid_filter = 0;
```

让程序只追踪某个 PID。

lesson 1 说明了最小 eBPF 程序会挂载到 `sys_enter_write` tracepoint，使用 `bpf_get_current_pid_tgid()` 获取 PID，并用 `bpf_printk()` 输出调试信息。([Eunomia][5])

## 阶段 2 作业

完成以下三个小作业：

```text
作业 1：基于 lesson 4 opensnoop，只打印某个进程名的 open 事件。

作业 2：基于 lesson 7 execsnoop，把进程名、PID、PPID、执行路径输出到用户态。

作业 3：基于 lesson 8 exitsnoop，把 ring buffer 输出结构体扩展一个字段，例如 exit_code 或运行时长。
```

通关标准：

```text
你能从零解释一个 eBPF 程序的生命周期：

写 C 代码
→ 编译为 BPF 字节码
→ 加载进内核
→ verifier 检查
→ attach 到 hook 点
→ 运行
→ 通过 map/ringbuf/perf 输出数据
→ detach / unload
```

---

# 五、阶段 3：高级示例 11-21，进入 libbpf / CO-RE 主线

这一阶段是从“会跑小例子”到“能写完整 eBPF 工具”的关键。Eunomia 的高级部分开始构建完整 eBPF 项目，主要基于 `libbpf`，并结合实际应用场景。([Eunomia][1])

## 核心目标

完成后你应该能：

```text
1. 理解 libbpf skeleton
2. 理解 vmlinux.h、BTF、CO-RE
3. 编写用户态 loader
4. 处理 ring buffer 事件
5. 使用命令行参数控制 eBPF 程序
6. 写出完整的可执行 eBPF 工具
7. 进入网络、安全、性能分析方向
```

## 学习顺序

| 顺序 | 教程                        | 重点                        |
| -: | ------------------------- | ------------------------- |
| 11 | lesson 11-bootstrap       | libbpf、用户态程序、exec/exit 追踪 |
| 12 | lesson 12-profile         | eBPF profile、性能分析         |
| 13 | lesson 13-tcpconnlat      | TCP 连接延迟统计                |
| 14 | lesson 14-tcpstates       | TCP 状态与 RTT               |
| 15 | lesson 15-javagc          | USDT，用户态 Java GC 事件       |
| 16 | lesson 16-memleak         | 内存泄漏监控                    |
| 17 | lesson 17-biopattern      | 随机 / 顺序磁盘 I/O             |
| 18 | lesson 18-further-reading | 论文、项目、扩展阅读                |
| 19 | lesson 19-lsm-connect     | LSM 安全检测与防御               |
| 20 | lesson 20-tc              | TC 流量控制                   |
| 21 | lesson 21-xdp             | XDP 可编程数据包处理              |

## 重点章节：lesson 11-bootstrap

这一章必须吃透。它是后续所有完整 eBPF 工具的基础。

你要掌握：

```text
1. .bpf.c 是内核态程序
2. .c 是用户态 loader
3. .h 定义内核态和用户态共享的数据结构
4. skeleton 如何生成
5. libbpf 如何 open / load / attach / poll / cleanup
6. ring buffer 如何把事件从内核态发到用户态
```

lesson 11 明确说明它会讲内核态和用户态 eBPF 程序如何协同工作，并使用原生 `libbpf` 开发用户态程序，将 eBPF 应用打包为可执行文件，实现跨内核版本分发。([Eunomia][3])

它还说明 `libbpf` 和 BTF 是 CO-RE 兼容性的关键：BTF 让 eBPF 程序无需硬编码特定内核版本的数据结构，CO-RE 则利用 BTF 生成可在不同内核版本运行的程序。([Eunomia][3])

## 阶段 3 作业

```text
作业 1：基于 lesson 11-bootstrap，新增一个命令行参数：
       只显示指定进程名的 EXEC / EXIT 事件。

作业 2：基于 lesson 13 或 14，写一个 TCP 连接观测小工具：
       输出目标 IP、端口、连接耗时、RTT。

作业 3：基于 lesson 16 或 17，写一个系统资源观测工具：
       选择内存泄漏或磁盘 I/O 其中之一。
```

通关标准：

```text
你可以不用 eunomia-bpf，只用 libbpf 写出一个完整的 eBPF 程序：

内核态 .bpf.c
共享头文件 .h
用户态 loader .c
Makefile
编译
运行
输出事件
Ctrl-C 清理
```

lesson 11 的用户态程序流程就是解析命令行参数、打开 skeleton、加载并 attach eBPF 程序、创建 ring buffer 接收事件、轮询事件并在退出时清理。([Eunomia][3])

---

# 六、阶段 4：专题深入路线

不要一口气把所有深入主题都学完。完成 lesson 0-21 后，按目标选择方向。

Eunomia 的深入部分覆盖 Android、攻击与防御、复杂追踪、GPU、调度器、网络、Tracing、安全和新特性等内容，并提示内核态与用户态结合会带来强大能力，也可能带来安全风险。([Eunomia][1])

---

## 路线 A：可观测性 / 性能分析方向

适合目标：

```text
系统性能分析
故障排查
SRE / 运维
可观测性平台
APM / tracing 工具
```

学习顺序：

```text
lesson 12-profile
lesson 16-memleak
lesson 17-biopattern
lesson 30-sslsniff
lesson 31-goroutine
lesson 33-funclatency
lesson 39-nginx
lesson 40-mysql
lesson 48-energy
```

重点能力：

| 能力            | 说明                              |
| ------------- | ------------------------------- |
| CPU profiling | 采样、栈、火焰图                        |
| 内存观测          | malloc/free、泄漏检测                |
| 磁盘 I/O        | block layer 事件、随机/顺序 I/O        |
| 用户态 tracing   | uprobe、USDT、Go/Rust/Nginx/MySQL |
| 延迟分析          | 函数耗时、请求耗时、调度延迟                  |

项目建议：

```text
做一个 mini observability agent：

1. 追踪进程 exec/exit
2. 追踪 open/read/write
3. 统计 TCP 连接延迟
4. 统计函数耗时
5. 通过 ring buffer 输出 JSON
```

---

## 路线 B：网络方向

适合目标：

```text
Cilium
云原生网络
XDP
TC
负载均衡
网络安全
高性能网关
```

学习顺序：

```text
lesson 13-tcpconnlat
lesson 14-tcpstates
lesson 20-tc
lesson 21-xdp
lesson 23-http
lesson 29-sockops
lesson 41-xdp-tcpdump
lesson 42-xdp-loadbalancer
lesson 46-xdp-test
lesson 50-tcx
```

重点能力：

| 能力             | 说明                    |
| -------------- | --------------------- |
| TCP 观测         | 连接延迟、状态变化、RTT         |
| TC             | ingress / egress 流量控制 |
| XDP            | 网卡入口快速包处理             |
| socket tracing | 追踪 L4 / L7 请求         |
| sockops        | socket 层优化            |
| load balancer  | 基于 XDP 的简单负载均衡        |

项目建议：

```text
做一个 XDP TCP 统计器：

1. 按源 IP / 目标 IP 统计包数
2. 按端口统计流量
3. 识别 SYN / ACK / FIN / RST
4. 用 map 保存统计结果
5. 用户态定期读取并打印
```

---

## 路线 C：安全方向

适合目标：

```text
运行时安全
入侵检测
EDR
Falco 类工具
容器安全
系统调用审计
```

学习顺序：

```text
lesson 19-lsm-connect
lesson 24-hide
lesson 25-signal
lesson 28-detach
lesson 34-syscall
cgroup-based Policy Control
BPF Token
```

可选阅读：

```text
lesson 26-sudo
lesson 27-replace
```

这两个属于攻击面理解内容，只建议在**隔离虚拟机**中学习，目标是理解 eBPF 滥用风险和防御思路，不建议在真实机器或生产环境运行。Eunomia 也把深入主题描述为包含潜在攻击、防御和安全风险。([Eunomia][1])

重点能力：

| 能力                     | 说明                   |
| ---------------------- | -------------------- |
| LSM hook               | 拦截 connect、文件访问等安全事件 |
| syscall tracing        | 系统调用审计               |
| process/file hiding 风险 | 理解恶意 eBPF 的隐蔽性       |
| signal defense         | 识别并终止异常进程            |
| cgroup policy          | 基于 cgroup 做策略控制      |
| BPF Token              | 委托式权限与安全加载           |

项目建议：

```text
做一个进程安全审计工具：

1. 监控 execve
2. 记录可疑命令
3. 监控 connect
4. 阻止访问黑名单 IP
5. 对异常行为输出告警
```

---

## 路线 D：现代 eBPF 特性 / Runtime 方向

适合目标：

```text
深入 eBPF 机制
研究新内核特性
写基础设施
做 eBPF runtime / SDK / 框架
```

学习顺序：

```text
lesson 35-user-ringbuf
lesson 36-userspace-ebpf
lesson 38-btf-uprobe
lesson 43-kfuncs
BPF Token
BPF Workqueues
BPF struct_ops
BPF dynptr
BPF arena
BPF iterators
```

重点能力：

| 能力                | 说明                  |
| ----------------- | ------------------- |
| user ring buffer  | 用户态异步发送信息到内核态       |
| userspace eBPF    | eBPF 扩展到用户态 runtime |
| BTF for userspace | 用户态 CO-RE           |
| kfunc             | 扩展 eBPF 能力          |
| dynptr            | 处理可变长数据             |
| arena             | 零拷贝共享内存             |
| iterators         | 导出内核数据              |
| struct_ops        | 用 BPF 扩展内核子系统       |

---

## 路线 E：调度器 / GPU / Android 方向

这是高级研究路线，不建议初学者一开始碰。

学习顺序：

```text
调度器：
lesson 44-scx-simple
lesson 45-scx-nest

GPU：
lesson 47-cuda-events
xpu flamegraph
xpu/gpu-kernel-driver
xpu/npu-kernel-driver

Android：
lesson 22-android
```

适合目标：

```text
Linux 调度器研究
GPU 性能观测
移动系统
内核扩展机制研究
```

---

# 七、推荐的 8 周学习计划

## 第 1 周：概念 + 环境

```text
Day 1：准备 Ubuntu 环境、安装依赖、clone 仓库
Day 2：读 lesson 0，整理 eBPF 核心概念
Day 3：运行 lesson 1 Hello World
Day 4：理解 tracepoint、SEC 宏、bpf_printk
Day 5：修改 Hello World，增加 PID 过滤
Day 6-7：复盘：写一篇笔记《一个 eBPF 程序如何运行》
```

## 第 2 周：hook 机制

```text
lesson 2：kprobe
lesson 3：fentry
lesson 4：opensnoop
lesson 5：uprobe
```

通关要求：

```text
你能说清楚：

kprobe 和 fentry 的区别
tracepoint 和 kprobe 的区别
uprobe 为什么能追踪用户态函数
```

## 第 3 周：map 与事件输出

```text
lesson 6：hash map
lesson 7：perf event array
lesson 8：ring buffer
lesson 9：histogram
lesson 10：hardirq / softirq
```

通关要求：

```text
你能说清楚：

BPF map 的 key/value 是什么
ring buffer 和 perf event array 的区别
为什么高频事件不能一直 bpf_printk
```

## 第 4 周：libbpf / CO-RE

```text
lesson 11-bootstrap
```

这一周只学这一章也不亏。

通关要求：

```text
你能自己解释：

vmlinux.h 是什么
BTF 是什么
CO-RE 是什么
skeleton 是什么
用户态程序如何 open/load/attach/poll/cleanup
```

## 第 5 周：性能与资源观测

```text
lesson 12-profile
lesson 16-memleak
lesson 17-biopattern
```

通关要求：

```text
你能写一个简单资源观测工具：
CPU / 内存 / 磁盘 I/O 选一个即可。
```

## 第 6 周：网络核心

```text
lesson 13-tcpconnlat
lesson 14-tcpstates
lesson 20-tc
lesson 21-xdp
```

通关要求：

```text
你能解释：

TCP 连接延迟如何捕获
TC 和 XDP 的位置差异
为什么 XDP 性能高
```

## 第 7 周：安全与策略

```text
lesson 19-lsm-connect
lesson 25-signal
lesson 34-syscall
cgroup-based Policy Control
```

通关要求：

```text
你能写一个安全观测小工具：
监控进程启动 + 网络连接 + 可疑行为输出。
```

## 第 8 周：毕业项目

从下面选一个：

```text
项目 1：execsnoop-plus
追踪进程启动、退出、父进程、命令行、运行时长。

项目 2：tcp-latency-monitor
统计 TCP 连接耗时、RTT、目标地址、端口。

项目 3：file-audit
追踪 open/unlink/rename/write，记录进程名、PID、路径。

项目 4：xdp-counter
基于 XDP 统计 TCP/UDP/ICMP 包数和端口分布。

项目 5：lsm-connect-guard
基于 LSM 拦截或记录 connect 行为。
```

---

# 八、每章都要做的笔记模板

每学一章，用这个模板写笔记：

```text
章节：
示例名称：
它解决什么问题：

1. Hook 点：
   例如 tracepoint / kprobe / fentry / uprobe / XDP / TC / LSM

2. 内核态代码做什么：
   读取什么数据？
   调用什么 helper？
   写入什么 map？

3. 用户态代码做什么：
   如何加载？
   如何 attach？
   如何读取事件？
   如何退出清理？

4. 使用了哪些 map：
   map 类型：
   key：
   value：
   生命周期：

5. 数据如何从内核态传到用户态：
   ring buffer / perf event array / map polling / printk

6. 我做了什么修改：
   修改点：
   遇到的问题：
   解决方法：

7. 本章可以扩展成什么工具：
```

---

# 九、最终掌握标准

学完这条路线后，你应该能独立完成以下事情：

```text
1. 选择合适的 hook 点：
   tracepoint / kprobe / fentry / uprobe / USDT / XDP / TC / LSM

2. 写内核态 eBPF 程序：
   使用 helper
   使用 map
   读取上下文
   做过滤和聚合

3. 写用户态程序：
   加载 eBPF
   attach
   读取 ring buffer
   解析参数
   输出结果
   清理资源

4. 理解 CO-RE：
   vmlinux.h
   BTF
   BPF_CORE_READ
   skeleton

5. 能分析 verifier 错误：
   invalid mem access
   unbounded loop
   pointer type mismatch
   map access error

6. 能做一个自己的 eBPF 工具：
   不是照抄教程，而是能根据需求设计。
```

---

# 十、最推荐的开始方式

今天直接做这三步：

```bash
git clone https://github.com/eunomia-bpf/bpf-developer-tutorial.git
cd bpf-developer-tutorial
git submodule update --init --recursive
```

然后按顺序学：

```text
第 1 天：lesson 0-introduce
第 2 天：lesson 1-helloworld
第 3 天：修改 helloworld，加 PID 过滤
第 4 天：lesson 2-kprobe-unlink
第 5 天：lesson 3-fentry-unlink
```

不要一开始就跳到 XDP、LSM、调度器或 GPU。先把 **tracepoint / kprobe / fentry / uprobe / map / ring buffer / libbpf** 这几个核心点打牢。Eunomia 的教程设计也是先用入门示例介绍基本用法和开发流程，再进入基于 libbpf 的完整项目，最后再扩展到深入主题。([Eunomia][1])

[1]: https://eunomia.dev/zh/tutorials/ "eBPF 开发实践教程：基于 CO-RE，通过小工具快速上手 eBPF 开发 - eunomia"
[2]: https://eunomia.dev/zh/tutorials/1-helloworld/ "eBPF 入门开发实践教程一：Hello World，基本框架和开发流程 - eunomia"
[3]: https://eunomia.dev/zh/tutorials/11-bootstrap/ "eBPF 入门开发实践教程十一：在 eBPF 中使用 libbpf 开发用户态程序并跟踪 exec() 和 exit() 系统调用 - eunomia"
[4]: https://eunomia.dev/zh/tutorials/0-introduce/ "eBPF 示例教程 0：核心概念与工具简介 - eunomia"
[5]: https://eunomia.dev/tutorials/1-helloworld/ "eBPF Tutorial by Example 1: Hello World, Framework and Development - eunomia"
