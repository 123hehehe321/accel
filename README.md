# accel — 高性能服务器端 TCP 加速器

> **一句话介绍**：装在 Linux 服务器上的 TCP 加速器，使用 eBPF/XDP + 用户态 TCP 栈 + 自研 ZetaTCP 算法，实现跨境链路下接近/超越商业锐速的加速效果。客户端无需任何改动。

---

## 目录

1. [项目定位](#1-项目定位)
2. [技术栈](#2-技术栈)
3. [整体架构](#3-整体架构)
4. [项目文件结构](#4-项目文件结构)
5. [配置文件](#5-配置文件)
6. [开发路线图](#6-开发路线图)
7. [第一步：eBPF 分流](#7-第一步ebpf-分流)
8. [第二步子阶段 2.1：AF_XDP 收包](#8-第二步子阶段-21af_xdp-收包)
9. [第二步子阶段 2.2：smoltcp + 转发](#9-第二步子阶段-22smoltcp--转发)
10. [测试方法](#10-测试方法)
11. [已知限制](#11-已知限制)
12. [编码规范](#12-编码规范)
13. [给 Claude Code 的工作指引](#13-给-claude-code-的工作指引)

---

## 1. 项目定位

### 1.1 要做什么

做一个 **服务器端安装、客户端零感知** 的 TCP 加速器：

```
用户（任何浏览器/手机/客户端，无需修改）
   ↓ 普通 TCP 连接
[你的服务器 + accel 加速器]
   ↓ 本机服务（Nginx / V2Ray / Xray / SS / 任何 TCP 服务）
```

### 1.2 核心价值

**最高加速性能**。这是项目唯一的存在理由。如果不追求最高性能，用 BBR 或 lotspeed 就够了。

### 1.3 目标效果

- **目标**：在跨境高丢包/高延时链路下，追求接近或超越商业锐速 (ZetaTCP/LotServer) 的加速体感
- **注意**：真实加速效果依赖于第三步/第四步的算法实现和真实网络调优（2-4 周调参期）
- **基础设施**：单机支持 1Gbps+ 流量处理能力，CPU 占用目标低于 30%

**重要提示**：第一步 + 第二步完成后流量能通但还没有加速效果（速度和直连相当）。真正的加速效果要等后续算法阶段。

### 1.4 支持的系统

- **Debian 10**：需升级内核到 backports 版本 (5.10+)
- **Debian 11, 12, 13**：默认内核即可
- **架构**：x86_64（aarch64 理论支持，未验证）

---

## 2. 技术栈

| 层 | 技术 | 作用 | 为什么选它 |
|---|------|------|----------|
| 内核态分流 | aya-rs + eBPF (C) | 判断端口，分流流量 | Rust 生态最成熟的 eBPF 框架 |
| 内核↔用户态 | AF_XDP + xsk-rs | 零拷贝传输数据包 | 基于内核官方 libxdp，性能接近理论上限 |
| 用户态运行时 | Monoio | 异步 I/O 运行时 | 基于 io_uring，thread-per-core 架构 |
| 用户态 TCP 栈 | smoltcp | 用户态 TCP 状态机 | Rust embedded 社区旗舰项目，成熟稳定 |
| 配置格式 | TOML | 配置文件 | Rust 生态标准，人类可读 |
| 主控语言 | Rust | 全部用户态代码 | 内存安全，性能接近 C |

**核心原则**：
1. 不牺牲性能换简单
2. 不重复造轮子（用成熟库）
3. 整体代码量控制在 **1500 行以内**（超过说明可能有过度设计，**需与用户研究确认后再继续**）
4. 所有错误在终端直接显示，不散落在日志文件里

**关于代码规模**：本文档中描述的"小模块/中模块"是规模感，**不是精确数字**。Claude Code 应按代码质量和实际需求决定行数，不要为凑数字牺牲质量或强行压缩。

**但有一条硬规则**：整体代码量超过 1500 行警戒线时，**Claude Code 必须停下来和用户研究确认**，不能自行继续。通常这说明：
- 出现了不必要的抽象层或重复代码
- 加入了 README 未要求的功能
- 某个模块职责过重需要重新设计

**确认流程**：Claude Code 发现即将超线时 → 向用户汇报当前代码量和超线的原因 → 等待用户决策（是简化重构、还是同意放宽限额）→ 得到明确回复后再继续。

---

## 3. 整体架构

### 3.1 数据流图

**概念图**（简化展示，实际数据流是双向的，proxy 会通过 smoltcp 回包给客户端）：

```
┌──────────────────────────────────────────────────────────┐
│  用户 (浏览器/手机/任何 TCP 客户端，零改动)                    │
└─────────────────────────┬────────────────────────────────┘
                          │ 普通 TCP 连接
                          ↓
┌──────────────────────────────────────────────────────────┐
│  你的服务器                                                 │
│                                                           │
│  ┌─────────────────────────────────────────┐            │
│  │  eth0 (网卡)                              │            │
│  └────────────┬─────────────────────────────┘            │
│               ↓                                           │
│  ┌─────────────────────────────────────────┐            │
│  │  eBPF/XDP 程序 (ebpf/classifier.c)      │            │
│  │  判断:                                   │            │
│  │   ├─ 加速端口 (443, 5000-20000)?         │            │
│  │   │   → XDP_REDIRECT 到 AF_XDP 队列      │            │
│  │   └─ 其他端口?                           │            │
│  │       → XDP_PASS (走内核,零影响)         │            │
│  └────────────┬─────────────────────────────┘            │
│               │                                           │
│   ┌───────────┴───────────┐                              │
│   ↓ 加速流量               ↓ 其他流量                      │
│                                                           │
│  ┌─────────────────────────┐   ┌──────────────────┐     │
│  │  AF_XDP 队列 (零拷贝)     │   │  内核协议栈 (正常) │     │
│  │                         │   └──────────────────┘     │
│  │  accel 用户态进程:        │                            │
│  │  ┌────────────────────┐│                            │
│  │  │ packet_io (xsk-rs)  ││                            │
│  │  └────────┬───────────┘│                            │
│  │           ↓             │                            │
│  │  ┌────────────────────┐│                            │
│  │  │ smoltcp TCP 栈      ││                            │
│  │  │ (用户态实现)         ││                            │
│  │  └────────┬───────────┘│                            │
│  │           ↓             │                            │
│  │  ┌────────────────────┐│                            │
│  │  │ proxy (双向桥接)    ││                            │
│  │  └────────┬───────────┘│                            │
│  └───────────┼────────────┘                            │
│              ↓                                           │
│  ┌─────────────────────────────────┐                    │
│  │  本机服务 (backend:原始目的端口)  │                    │
│  │  Nginx / V2Ray / Xray / SS       │                    │
│  └─────────────────────────────────┘                    │
└──────────────────────────────────────────────────────────┘
```

### 3.2 关键设计决策

| 决策 | 选择 | 理由 |
|-----|------|-----|
| 分流粒度 | 按端口 | 简单、够用、非加速流量零影响 |
| 传输方式 | AF_XDP 零拷贝 | 性能接近理论上限 |
| TCP 栈 | smoltcp (用户态) | 可以插入自定义拥塞算法 |
| 运行模式 | 前台进程 | 开发期易调试，生产期由 systemd 管理 |
| 配置方式 | 同目录 TOML 文件 | 简单、不搞标准路径 |
| 通信机制 | Unix Socket | status/stop 命令的实现方式 |

---

## 4. 项目文件结构

```
accel/
├── README.md                 ← 本文件
├── Cargo.toml                ← Rust 项目配置
├── acc.conf                  ← 配置文件（和二进制同目录）
├── run-test.sh               ← 一键测试脚本
│
├── ebpf/
│   └── classifier.c          ← eBPF 程序 (C, 小模块)
│
└── src/
    ├── main.rs               ← 主入口 (小模块)
    ├── mode.rs               ← XDP 模式自动检测 (小模块)
    ├── config.rs             ← 配置文件解析 (小模块)
    ├── socket.rs             ← Unix Socket 服务端 (小模块)
    ├── status.rs             ← 状态采集 (小模块)
    ├── signal.rs             ← SIGTERM/SIGINT 处理 (微模块)
    ├── cli.rs                ← status/stop 客户端 (微模块)
    ├── packet_io.rs          ← AF_XDP 收发包 (小模块)    [阶段 2.1]
    └── proxy.rs              ← smoltcp + 转发 (中模块)   [阶段 2.2]
```

**规模感参考**（不是硬性指标）：
- **微模块**：几十行（单一简单功能）
- **小模块**：100-200 行（一个完整子功能）
- **中模块**：200-350 行（核心业务，包含多个相关功能）

**整体警戒线**：全部代码（含 eBPF）控制在 **1500 行以内**。**超过时必须停止并与用户研究确认**，不得自行继续。

### 文件职责一句话说明

| 文件 | 一句话职责 |
|-----|---------|
| `ebpf/classifier.c` | 判断端口，匹配的包 redirect 到 AF_XDP |
| `src/main.rs` | 启动流程，把所有模块串起来 |
| `src/mode.rs` | 尝试 XDP native，不行就退到 generic |
| `src/config.rs` | 读 acc.conf，解析成 Rust struct |
| `src/socket.rs` | 在 Unix Socket 上监听 status/stop 请求 |
| `src/status.rs` | 采集状态数据（读 /proc/self/、统计包数等） |
| `src/signal.rs` | 收到 SIGTERM/SIGINT 优雅退出 |
| `src/cli.rs` | 实现 `./accel status` 和 `./accel stop` 客户端 |
| `src/packet_io.rs` | 用 xsk-rs 封装 AF_XDP 收发包 |
| `src/proxy.rs` | 用 smoltcp 建 TCP 栈 + 转发到后端 |

---

## 5. 配置文件

配置文件名：`acc.conf`  
位置：**和二进制 `accel` 同一目录**（不使用 `/etc/`）

```toml
# accel TCP 加速器配置
# 版本: 0.1

[network]
# 加速的网卡名
interface = "eth0"

# 加速端口
# 支持格式:
#   单端口:    "443"
#   多个:     "443,8443,10443"
#   范围:     "5000-20000"
#   混合:     "443,5000-20000,30000-40000"
ports = "443,5000-20000"

# XDP 模式:
#   "auto" - 优先 native，失败退到 generic (推荐)
#   "native" - 强制 native XDP (最高性能，需驱动支持)
#   "generic" - 强制 generic XDP (所有网卡都支持，性能略低)
mode = "auto"


[runtime]
# Unix Socket 路径:
# 空字符串 = 智能决策:
#   - 被 systemd 启动 → /run/accel/accel.sock
#   - 手动启动       → ./accel.sock (二进制同目录)
socket = ""


[forward]
# 后端服务地址（流量转发目标）
# 通常就是本机回环地址
#
# 端口策略：**后端端口 = 前端端口**（透明代理模式）
#   例：客户端访问服务器 :443 → accel 转发到 backend:443
#   例：客户端访问服务器 :8443 → accel 转发到 backend:8443
# 因此 backend 只配地址，不配端口。
backend = "127.0.0.1"


# ========== 以下为后续阶段占位，当前未使用 ==========

[algorithm]
# 预留给后续 ZetaTCP 算法配置
```

**修改配置 = 停掉程序改文件重启**：

```bash
# 停
./accel stop  # 或 Ctrl+C

# 改
vim acc.conf

# 启
sudo ./accel
```

---

## 6. 开发路线图

### 6.1 整体规划

| 阶段 | 内容 | 规模 | 预计时间 | 能验证什么 |
|-----|------|------|--------|----------|
| **第一步** | eBPF 分流 | 主体规模 | 2-3 天 | 流量被捕获（但链路未通） |
| **第二步 2.1** | AF_XDP 收包 | 新增小模块 | 2-3 天 | 用户态看到流量包 |
| **第二步 2.2** | smoltcp + 转发 | 新增中模块 | 4-5 天 | curl 能正常访问 |
| 第三步 | 拥塞算法框架 | (后续) | - | - |
| 第四步 | ZetaTCP 算法 | (后续) | - | - |

**整体警戒线**：第一步 + 第二步完成时总代码量应在 **1500 行以内**。**超过必须与用户确认**，不得自行继续。

### 6.2 当前目标（本文档覆盖的范围）

**完成第一步 + 第二步（2.1 + 2.2）**，达到：

- ✅ 服务器上装好 accel 并启动
- ✅ 用户 curl https://vps-ip 能正常返回页面
- ✅ accel status 看到连接数、包数在涨
- ✅ 各种错误有明确提示
- ⚠️ 此时**速度和直连相当**（因为还没加速算法）

### 6.3 快速体验第一步

第一步已经编译好了二进制，放在 `binaries` 分支，可以直接下载试跑（**还没有加速效果**，本节只为验证基础设施能跑起来）：

```bash
# 1. 下载
curl -LO https://github.com/123hehehe321/accel/raw/binaries/accel
curl -LO https://github.com/123hehehe321/accel/raw/binaries/acc.conf.example
chmod +x accel
mv acc.conf.example acc.conf

# 2. 改配置 —— ⚠️ 建议第一次只测一个不重要的端口，别动 22 (SSH)，出问题会失联
vim acc.conf          # 把 ports 先改成 "8888" 之类的单端口
                      # interface 改成 `ip link show` 看到的实际网卡名

# 3. 启动（前台，Ctrl+C 退出）
sudo ./accel

# 4. 另开一个终端查状态
./accel status        # 看 pkt_total / pkt_accel / accel_ratio
./accel stop          # 优雅退出
```

确认 `accel status` 里 `pkt_accel` 数字在涨，说明 eBPF 分流工作正常。后续 2.1 完成后才能看到流量真正被用户态处理。

---

## 7. 第一步：eBPF 分流

### 7.1 目标

在服务器的网卡上挂载 eBPF 程序，根据配置的端口规则，把需要加速的 TCP 包从内核网络栈"截"下来，送到 AF_XDP 队列。不需要加速的流量零影响。

### 7.2 输入输出

**输入**：
- 配置文件 `acc.conf` 里的 `interface` 和 `ports`
- 物理网卡上收到的所有 TCP 包

**输出**：
- 配置端口的 TCP 包 → AF_XDP 队列 (第二步会来处理)
- 非配置端口的 TCP 包 → XDP_PASS (内核继续处理)
- 统计计数：总包数 / 加速包数 / 跳过包数

### 7.3 实现要点

#### 7.3.1 eBPF 程序 (`ebpf/classifier.c`)

**必须包含的功能**：
- 解析以太网头、IP 头、TCP 头
- 从 eBPF map 读取端口配置
- 端口匹配（单端口 + 范围）
- 匹配 → `bpf_redirect_map(&xsks_map, queue_id, 0)`
- 不匹配 → `XDP_PASS`
- 维护统计计数器

**必须定义的 maps**：
- `xsks_map`: BPF_MAP_TYPE_XSKMAP, 给 AF_XDP 用
- `port_config`: 端口规则配置 (单端口数组 + 范围数组)
- `stats`: BPF_MAP_TYPE_PERCPU_ARRAY, 统计计数

#### 7.3.2 Rust 加载器 (`src/main.rs` + 辅助模块)

**必须实现**：
- 读 acc.conf 解析端口配置
- 用 aya-rs 加载 eBPF 程序
- 把端口配置写入 eBPF map
- 启动 socket 服务监听 status/stop 请求
- 注册 SIGTERM/SIGINT handler

#### 7.3.3 模式自动检测 (`src/mode.rs`)

```
如果配置 mode = "auto":
    尝试 XDP native 加载
    if 成功: 使用 native，打印 "mode: native"
    else:
        尝试 XDP generic 加载
        if 成功: 使用 generic，打印 "mode: generic"
        else: 报错退出

如果配置 mode = "native": 强制 native，失败就退出
如果配置 mode = "generic": 直接用 generic
```

### 7.4 启动输出

```
$ sudo ./accel

accel starting...
  detect mode: trying native ... ok
  
  iface:     eth0
  driver:    virtio_net
  mode:      native
  ports:     443, 5000-20000
  socket:    ./accel.sock
  
accel running. (pid=12345)
press ctrl+c to stop, or run './accel stop' from another terminal.
```

### 7.5 第一步验收

完成第一步后能做：

1. 启动 accel，能看到上面的输出
2. `./accel status` 在另一个终端显示状态
3. 从其他机器发流量到 443 端口，status 里 `pkt_accel` 数字增长
4. 22 端口的 SSH 不受影响（status 里 `pkt_total` 增长但 `pkt_accel` 不增长）
5. Ctrl+C 或 `./accel stop` 能优雅退出，eBPF 被卸载

**status 命令输出示例**（第一步完成时）：
```
$ ./accel status

accel status:
  running:    yes (pid=12345)
  uptime:     1h 23m

  iface:      eth0 (virtio_net)
  mode:       native
  ports:      443, 5000-20000
  socket:     ./accel.sock

  cpu:        0.1%
  mem:        32 MB

  stats:
    pkt_total:       1,234,567
    pkt_accel:         987,654
    accel_ratio:        80.0%
```

**注意**：此时 443 的流量会被截住没人处理，curl 会超时，这是预期的（等 2.1 和 2.2 完成才能通）。

---

## 8. 第二步子阶段 2.1：AF_XDP 收包

### 8.1 目标

在第一步的基础上，加入用户态的 AF_XDP socket，把 eBPF 送过来的包"接住"，并在屏幕上打印出来。**此时还不转发**。

### 8.2 输入输出

**输入**：
- eBPF 程序 redirect 过来的 TCP 包（在 AF_XDP 队列里）

**输出**：
- 屏幕打印每个收到的包的摘要信息（源 IP:端口 → 目的 IP:端口 标志位）

### 8.3 实现要点

#### 8.3.1 使用 xsk-rs 库

在 `Cargo.toml` 加依赖（**版本号请用 `cargo add xsk-rs` 自动选择最新兼容版本**，不要硬编码老版本）：

```toml
[dependencies]
xsk-rs = "*"  # 占位，实际用 cargo add 决定版本
```

xsk-rs 的核心 API：
- `Umem::new()` - 分配共享内存
- `Socket::new()` - 绑定到网卡队列
- 收包：从 RxQueue 消费描述符，读 Umem 对应位置的数据
- 发包：写数据到 Umem，通过 TxQueue 发送

**参考官方示例**：
- `examples/hello_xdp.rs`
- `examples/dev2_to_dev1.rs`

#### 8.3.2 Monoio 集成

xsk-rs 的 socket 底层是 fd，可以用 Monoio 的 AsyncFd 包装：

```
用 AsyncFd 包住 xsk 的 fd
等待 fd 可读 → 调用 xsk 的同步 API 批量消费
```

#### 8.3.3 收包逻辑 (`src/packet_io.rs`)

伪代码：

```
async fn recv_loop():
    loop:
        等待 AsyncFd 可读
        while let Some(frame) = rx_queue.recv_one():
            data = umem.get(frame)
            (src_ip, src_port, dst_ip, dst_port, flags) = 解析 TCP 头(data)
            // flags 格式: [SYN] / [SYN,ACK] / [PSH,ACK] / [FIN] / [RST] 等
            println!("[packet] {}:{} -> {}:{} {}", src_ip, src_port, dst_ip, dst_port, flags)
            // 归还 frame 到 fill queue
            fill_queue.produce_one(frame)
```

### 8.4 eBPF 修改

第一步的 `classifier.c` 在子阶段 2.1 需要**确保 `bpf_redirect_map()` 的 queue_id 和用户态绑定的队列匹配**。简化起见，**都用 queue 0**。

### 8.5 子阶段 2.1 验收

完成后能做：

1. 启动 accel
2. 从其他机器 `curl https://vps-ip`
3. accel 屏幕打印：
   ```
   [packet] 1.2.3.4:54321 -> 5.6.7.8:443 [SYN]
   ```
4. curl 会超时（正常，因为没回应）
5. status 里 `pkt_accel` 数字和打印的行数一致

**子阶段 2.1 完成 = 流量成功从内核到用户态零拷贝送达**

---

## 9. 第二步子阶段 2.2：smoltcp + 转发

### 9.1 目标

在 2.1 基础上，用 smoltcp 在用户态做完整 TCP 通信：
- 和客户端完成 TCP 握手
- 建立到本地后端服务的连接
- 双向桥接数据

**完成后，curl 能正常返回页面**。

### 9.2 输入输出

**输入**：
- AF_XDP 队列送来的 TCP 包（来自配置的所有加速端口，例如 443、5000-20000）

**输出**：
- 通过 AF_XDP 队列发回客户端的 TCP 包
- 通过普通 socket 连接本地后端服务（`backend` + 原始目的端口）

### 9.3 实现要点

#### 9.3.1 smoltcp 基础用法

在 `Cargo.toml` 加依赖（**版本号用 `cargo add smoltcp --features "std,medium-ip,proto-ipv4,socket-tcp"` 自动选择最新版**）：

```toml
[dependencies]
smoltcp = { version = "*", default-features = false, features = [
    "std",
    "medium-ip",
    "proto-ipv4",
    "socket-tcp",
] }
```

smoltcp 的核心概念：
- `Interface`: 虚拟网络接口
- `Device`: 收发数据包的抽象（我们用 AF_XDP 实现）
- `SocketSet`: 管理所有 socket
- `TcpSocket`: 一个 TCP 连接

#### 9.3.2 工作模式（支持多端口/端口范围）

```
我们实现 smoltcp 的 Device trait:
    transmit(): 从 Umem 拿一个空 frame，返回给 smoltcp 写
    receive(): 从 RxQueue 取包，交给 smoltcp 处理

处理流程（每个收到的包）:
    解析 TCP 头，拿到目的端口 dst_port
    检查是否已有连接（通过五元组）：
        - 有 → 交给对应 TcpSocket 处理
        - 无，且是 SYN →
            动态创建 TcpSocket 监听 dst_port
            接受连接
            新建到后端的连接: TcpStream::connect(backend + dst_port)
            记录 HashMap<SocketHandle, TcpStream>

双向数据桥:
    smoltcp_socket.recv() → backend.write()
    backend.read()        → smoltcp_socket.send()
```

**关键点**：smoltcp 不预先监听固定端口。对每个新 SYN **动态创建** TcpSocket 监听其 dst_port。这样天然支持任意端口组合（单端口/多端口/范围）。

#### 9.3.3 连接跟踪

**使用 smoltcp 自带的 `SocketSet`**，不要自己造轮子。

每个前端连接（smoltcp TcpSocket）对应一个后端连接（Monoio TcpStream），用 HashMap 维护映射：

```
type ConnMap = HashMap<SocketHandle, Arc<TcpStream>>
```

#### 9.3.4 端口策略

- **客户端看到的端口** = 配置里的加速端口（由 eBPF 决定哪些流量送过来）
- **后端连接的端口** = 客户端请求的原始目的端口（透明代理）

示例：
- 客户端访问 `服务器:443` → accel 转发到 `backend:443`
- 客户端访问 `服务器:8443` → accel 转发到 `backend:8443`
- 客户端访问 `服务器:12345`（在 5000-20000 范围内）→ accel 转发到 `backend:12345`

所以本地服务（Nginx/V2Ray 等）应该在相同的端口监听。

### 9.4 status 扩展

2.2 完成后，status 输出增加一个字段：

```
stats:
  pkt_total:      1,234,567,890
  pkt_accel:        987,654,321
  accel_ratio:          80.0%

connections:               [新增]
  active:              127
```

**只加 `active`（当前活跃连接数）**。一个原子计数器即可实现，**不要**做 total_handled、avg_duration 之类的复杂统计（过度设计）。

### 9.5 子阶段 2.2 验收

完成后能做：

1. 启动 accel
2. 本地 Nginx 监听 443
3. 从其他机器 `curl https://vps-ip` → 返回 Nginx 页面 ✅
4. `ab -n 1000 -c 50 https://vps-ip/` 压力测试稳定 ✅
5. 下载 100MB 大文件完整 ✅
6. status 显示 `active` 连接数变化

**子阶段 2.2 完成 = 流量真正能通，基础设施就绪，为后续加速算法做准备**

---

## 10. 测试方法

### 10.1 一键测试脚本

`run-test.sh` 根据当前开发阶段自动选择对应的测试，每项直接在终端显示结果。

**用法**：
```bash
sudo ./run-test.sh           # 自动检测阶段，跑对应测试
sudo ./run-test.sh phase1    # 只跑第一步测试
sudo ./run-test.sh phase2.1  # 只跑子阶段 2.1 测试
sudo ./run-test.sh phase2.2  # 只跑子阶段 2.2 测试
sudo ./run-test.sh all       # 所有测试都跑（需整个项目完成）
```

**测试分组**：

**第一步测试（4 个）**：
```bash
$ sudo ./run-test.sh phase1
[phase1] test 1/4: load ebpf           ... ok (42ms)
[phase1] test 2/4: configure ports     ... ok
[phase1] test 3/4: capture 443 traffic ... ok (1000/1000 packets)
[phase1] test 4/4: skip 22 traffic     ... ok (0/1000 captured)

result: 4/4 passed
```

**子阶段 2.1 测试（2 个）**：
```bash
$ sudo ./run-test.sh phase2.1
[phase2.1] test 1/2: af_xdp socket bind ... ok
[phase2.1] test 2/2: recv packet in userspace ... ok (print count matches)

result: 2/2 passed
```

**子阶段 2.2 测试（4 个）**：
```bash
$ sudo ./run-test.sh phase2.2
[phase2.2] test 1/4: tcp handshake via accel   ... ok
[phase2.2] test 2/4: http get through accel    ... ok
[phase2.2] test 3/4: 100 concurrent connections ... ok
[phase2.2] test 4/4: large file transfer       ... ok (100MB in 1.2s)

result: 4/4 passed
```

**全局测试（1 个，任何阶段都能跑）**：
```bash
[global] test 1/1: graceful shutdown ... ok
```

**总计**：第一步 4 个 + 2.1 两个 + 2.2 四个 + 全局 1 个 = **11 个测试用例**。

### 10.2 手动验证

```bash
# 启动 accel（在 screen/tmux 里）
sudo ./accel

# 在另一个终端观察状态
./accel status

# 发起测试流量
curl -v https://your-vps-ip
ab -n 10000 -c 100 https://your-vps-ip/

# 再看状态
./accel status

# 优雅停止
./accel stop
```

### 10.3 错误排查流程

**所有错误都在终端直接显示**，不需要翻日志文件。

遇到错误时：
1. 截图/复制终端输出
2. 把**错误内容 + README.md + 相关源文件**一起给 Claude Code
3. Claude Code 根据 README.md 的上下文定位问题

---

## 11. 已知限制

### 11.1 系统要求

- **Debian 10 (Buster)**：默认内核 4.19，AF_XDP 支持不完整。**必须**升级到 backports 内核：
  ```bash
  sudo sh -c 'echo "deb http://deb.debian.org/debian buster-backports main" > /etc/apt/sources.list.d/backports.list'
  sudo apt update
  sudo apt install -t buster-backports linux-image-amd64
  sudo reboot
  ```
  升级后内核 5.10+，AF_XDP 完整支持。

- **Debian 11, 12, 13**：默认内核即可。

### 11.2 网卡驱动

- **原生支持 XDP (native mode)**：ixgbe, i40e, mlx5, virtio_net (新版本), veth 等
- **仅支持 generic mode**：老版本驱动，性能约为 native 的 70%
- **完全不支持**：极少数老 Xen 驱动。这种情况 accel 启动时会报错退出

### 11.3 权限

必须 root 或具有以下 capabilities 运行：
- `CAP_NET_ADMIN`
- `CAP_BPF` (内核 5.8+) 或 `CAP_SYS_ADMIN`

开发期直接用 sudo 即可。

### 11.4 当前阶段的限制

**第一步+第二步完成后**：
- ✅ 流量能通
- ✅ 功能完整
- ⚠️ **速度和直连相当**（因为 smoltcp 默认用 CUBIC，和内核 TCP 差不多）

**真正的加速效果要等第三步、第四步（ZetaTCP 算法）完成**。

---

## 12. 编码规范

### 12.1 Rust 代码

- 使用 Rust 2021 edition
- **避免使用 `unsafe`**，仅在和 C FFI / eBPF map 交互时使用（xsk-rs 调用本身会带 unsafe，这是正常的）
- 所有 `unsafe` 块必须有注释说明**为什么这里是安全的**（不变式保证）
- 错误处理用 `anyhow::Result` (应用层) 或 `thiserror` (库层)
- 避免 `.unwrap()`，除非在测试代码或明确知道不会 panic 的场景（并用注释说明原因）

### 12.2 错误输出

错误直接打印到 stderr，**简洁、具体、可操作**：

```
✅ error: kernel 3.10.0 too old, need >= 4.19 (on Debian 10, install linux-image from backports)

❌ Error occurred.
❌ Failed.
```

### 12.3 日志

- 错误信息：`eprintln!` 打印到 stderr
- 普通状态：`println!` 打印到 stdout
- **不写日志文件**
- **不引入 tracing/log 等日志框架**（当前规模不需要）
- 调试信息通过环境变量 `ACCEL_DEBUG=1` 开启

### 12.4 代码风格

- `cargo fmt` 格式化
- `cargo clippy` 无警告
- 每个函数专注做一件事（自然控制在合理长度）
- 单个文件规模参考第 4 章"规模感参考"（微/小/中模块）
- 若某文件超过 350 行，需考虑职责是否过重

---

## 13. 给 Claude Code 的工作指引

### 13.1 工作节奏

**严格按阶段顺序工作，不要跳步**：

```
第一步 (2-3 天) → 验证通过 → 第二步 2.1 (2-3 天) → 验证通过 → 第二步 2.2 (4-5 天)
```

每个阶段都要：
1. 写代码
2. 编译通过
3. 跑测试通过
4. 验收清单全部打勾
5. **然后才进入下一阶段**

**不要试图一次写完整个项目**。

### 13.2 每天一个小目标

把每个阶段拆成"每天能 demo 一件事"的小目标：

**第一步示例**：
- Day 1：Cargo 项目 + hello world + 读配置
- Day 2：eBPF 程序能加载 + 打印收到的包
- Day 3：端口匹配 + status 命令 + 测试全过

**子阶段 2.1 示例**：
- Day 1：xsk-rs 依赖通 + 能建 UMEM
- Day 2：AF_XDP socket 绑定 + 收到第一个包
- Day 3：Monoio 集成 + 持续打印收到的包

**子阶段 2.2 示例**：
- Day 1：smoltcp 能建 Device + 注入第一个包
- Day 2：TCP 握手成功
- Day 3：后端连接 + 单向转发
- Day 4：双向桥接 + 连接管理
- Day 5：压力测试 + 修 bug

### 13.3 参考项目

遇到不确定的细节，参考这些成熟项目：

- **aya-rs 示例**: https://github.com/aya-rs/aya/tree/main/examples
- **xsk-rs 示例**: https://github.com/DouglasGray/xsk-rs/tree/master/examples
- **smoltcp 示例**: https://github.com/smoltcp-rs/smoltcp/tree/main/examples
- **Monoio 示例**: https://github.com/bytedance/monoio/tree/master/examples
- **lotspeed (对比参考)**: https://github.com/uk0/lotspeed

### 13.4 调试工具清单

- `cargo build` - 编译
- `sudo bpftool prog show` - 查看加载的 eBPF 程序
- `sudo bpftool map dump id <id>` - 查看 eBPF map 内容
- `sudo tcpdump -i eth0 -nn` - 抓包对比
- `ethtool -i eth0` - 查看网卡驱动
- `uname -r` - 查看内核版本
- `dmesg | tail` - 看内核日志（eBPF verifier 错误在这里）
- `sudo ss -xtnlp | grep accel` - 查看 Unix Socket

### 13.5 常见错误及修复方向

| 错误 | 常见原因 | 修复方向 |
|-----|---------|---------|
| `Failed to load BPF program` | 内核版本或权限 | 检查 kernel 版本，用 sudo |
| `verifier rejected` | eBPF 代码不符合验证器 | 看 dmesg 的 verifier 日志，通常是指针边界检查 |
| `AF_XDP bind failed` | 网卡队列配置 | 检查 `ethtool -l eth0` 的 combined 数 |
| `Permission denied` | 非 root | `sudo ./accel` |
| `no such device` | 网卡名错 | 改配置 `interface =` |
| `address already in use` | 前一次没清理 socket | 删 `accel.sock` 文件 |
| smoltcp 无响应 | Device trait 实现问题 | 检查 capabilities() 返回值、poll() 调用时机、Instant 时间传入 |

### 13.6 不要做的事

❌ 不要自作主张改变架构（例如改用 TUN 代替 AF_XDP）  
❌ 不要加"可能有用"的功能（只做 README 列出的）  
❌ 不要把代码拆成过多文件（当前设计 10 个源文件足够）  
❌ 不要用复杂的抽象（trait 泛型嵌套、状态机框架等）  
❌ 不要加日志文件（所有输出到 stderr）  
❌ 不要加 daemon 模式（程序就前台运行）  
❌ 不要加运行时改配置的 API（停掉改文件重启）  
❌ **不要在总代码量超过 1500 行时自行继续 —— 必须停下来和用户研究确认**  

### 13.7 可以做的事

✅ 在 README 划定的范围内优化代码质量  
✅ 添加必要的注释（特别是 unsafe 块）  
✅ 补充明显缺失的错误处理  
✅ 写清晰的 commit message  
✅ **发现 README 有歧义或矛盾时，必须先询问用户再修改 —— 不能自行选择一边或自行修改文档**  

---

## 附录 A：验收清单

### 第一步验收清单

- [ ] `cargo build --release` 成功
- [ ] `sudo ./accel` 能启动并显示欢迎信息
- [ ] 启动后 `bpftool prog show` 能看到 eBPF 程序
- [ ] `./accel status` 显示正确状态
- [ ] 发送 443 流量，status 里 `pkt_accel` 增长
- [ ] 发送 22 流量，`pkt_accel` 不增长
- [ ] `./accel stop` 能优雅退出
- [ ] Ctrl+C 也能优雅退出
- [ ] eBPF 程序退出时被卸载 (`bpftool prog show` 看不到)
- [ ] `sudo ./run-test.sh` 相关测试通过

### 子阶段 2.1 验收清单

- [ ] xsk-rs 依赖编译通过
- [ ] AF_XDP socket 能绑定成功
- [ ] 发 443 流量能在屏幕看到包的打印
- [ ] 统计数字和打印行数一致
- [ ] 关闭程序能释放 AF_XDP 资源

### 子阶段 2.2 验收清单

- [ ] smoltcp 能通过 AF_XDP 发包
- [ ] curl https://vps-ip 返回 Nginx 页面
- [ ] 100 并发连接稳定
- [ ] 100MB 大文件传输完整（md5 一致）
- [ ] 连接关闭后后端连接也关闭
- [ ] status 显示 `active` 连接数变化
- [ ] 10 分钟连续压力测试，内存稳定无明显增长（**人工验收**）

---

## 附录 B：版本历史

| 版本 | 日期 | 说明 |
|-----|------|-----|
| 0.1 | 2026-04 | 初始版本，覆盖第一步 + 第二步 |

---

## 附录 C：License 与贡献

License: MIT（建议）

**本 README 是给 Claude Code 的开发圣经，请严格遵守其中的架构决策和工作指引**。
