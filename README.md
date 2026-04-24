# accel — 高性能服务器端 TCP 加速器

> **一句话介绍**：装在 Linux 服务器上的 TCP 加速器,使用 eBPF struct_ops 自定义 TCP 拥塞控制算法,和锐速同层级但架构更灵活。所有 TCP 服务零改动、真实客户端 IP 保留、与任何其他服务零冲突。

---

## 目录

1. [项目定位](#1-项目定位)
2. [技术栈](#2-技术栈)
3. [整体架构](#3-整体架构)
4. [项目文件结构](#4-项目文件结构)
5. [配置文件](#5-配置文件)
6. [开发路线图](#6-开发路线图)
7. [第一步:eBPF 分流(已完成 + 将迁移)](#7-第一步ebpf-分流已完成--将迁移)
8. [第二步:struct_ops 算法](#8-第二步struct_ops-算法)
9. [第三步:激进算法](#9-第三步激进算法)
10. [验证机制](#10-验证机制)
11. [测试方法](#11-测试方法)
12. [已知限制](#12-已知限制)
13. [编码规范与工作指引](#13-编码规范与工作指引)
- 附录 A:[验收清单](#附录-a验收清单)
- 附录 B:[版本历史](#附录-b版本历史)
- 附录 C:[许可证](#附录-c许可证)

---

## 1. 项目定位

### 1.1 要做什么

做一个**服务器端安装、所有服务零改动**的 TCP 加速器:

```
用户(任何客户端,无需修改)
   ↓ 普通 TCP 连接
[你的服务器 + accel 加速器]
   ↓ 本机服务(haproxy / Nginx / V2Ray / Xray / 任何 TCP 服务,配置零改动)
```

accel 以 **eBPF struct_ops 自定义 TCP 拥塞控制算法**的形式工作,和内核自带的 BBR、CUBIC 处于同一层级,替换的是内核 TCP 栈里"如何发包"的决策逻辑。**不拦截、不代理、不改包**。

### 1.2 核心价值

**最高加速性能**。这是项目唯一的存在理由。如果不追求最高性能,用内核自带的 BBR 就够了。

比 BBR 更快的理由:
- BBR 是通用算法,参数保守
- accel 专门面向**跨境高丢包/高延时场景**调优
- 可加载多种策略(稳健版、激进版),按网络情况切换
- 未来可融合 tcp-brutal 思想、AI 学习调参等

### 1.3 目标效果

- **目标**:跨境高丢包/高延时链路下,接近或超越商业锐速 (ZetaTCP/LotServer) 的加速体感
- **架构上限**:和锐速同层级(内核 TCP 栈),但可热插拔算法更灵活,上限不低于锐速
- **单机性能**:目标支持 1 Gbps+ 流量处理,CPU 占用低于 30%

**重要提示**:
- 第一步已完成(eBPF 分流 + 管理接口),**无加速效果**,只做流量观测
- 第二步 2.1 完成后:accel 算法能跑(等效 CUBIC),**无明显加速效果**
- 第二步 2.2 完成后:BBR 移植版就绪,**跨境场景开始有明显提升**
- 第三步完成后:激进算法就绪,**高丢包场景吞吐显著提升**

### 1.4 对用户和服务的承诺

accel 的核心工程承诺是**用户零改动**:

- ✅ 任何 TCP 服务配置不用改(haproxy / nginx / v2ray / openvpn 等)
- ✅ 所有服务看到真实客户端 IP(不经过代理)
- ✅ 不和其他服务冲突(VPN / Warp / TUN / Docker 网络等共存)
- ✅ 不改系统路由表、防火墙规则
- ✅ 启用只需 `sudo ./accel` 一条命令

### 1.5 支持的系统

accel 使用 eBPF struct_ops Link API,需要 **Linux 内核 6.4+**(Linux commit 68b04864,2023-03)。

- **Debian 13**:默认内核即可(6.12+) ✅ 推荐
- **Debian 12**:必须升级到 bookworm-backports 内核(6.7+,推荐 6.12)
  ```bash
  sudo sh -c 'echo "deb http://deb.debian.org/debian bookworm-backports main" > /etc/apt/sources.list.d/backports.list'
  sudo apt update
  sudo apt install -t bookworm-backports linux-image-amd64
  sudo reboot
  ```
- **Debian 11**:**不推荐**。bullseye-backports 最高到 6.1,不支持 struct_ops Link 语义。建议升级到 Debian 12/13。
- **架构**:x86_64(aarch64 理论支持,未验证)
- **不支持 Debian 10**:内核太旧,不支持 struct_ops BPF

---

## 2. 技术栈

| 层 | 技术 | 作用 | 为什么选它 |
|---|------|------|----------|
| 加速算法 | **eBPF struct_ops (C)** | 自定义 TCP 拥塞控制 | Linux 内核标准机制,和 BBR 同层级,可动态加载 |
| eBPF 加载器 | **libbpf-rs + libbpf-cargo** | 从 Rust 加载 eBPF 到内核 | 支持 struct_ops(aya-rs 不支持),工业级稳定,支持 CO-RE |
| 算法管理 | **bpftool** | 热插拔算法 | Linux 自带,秒级 register/unregister |
| 配置格式 | TOML | 配置文件 | Rust 生态标准,人类可读 |
| 主控语言 | Rust | 用户态加载器、管理接口、CLI | 内存安全,性能好 |

### 2.1 核心原则

1. **不牺牲性能换简单** —— 内核态运行,接近硬件极限
2. **不重复造轮子** —— 算法基于 Linux 内核现成代码改造(参考 `bpf_cubic.c`、`tcp_bbr.c`)
3. **不改用户配置** —— 任何后方服务无需修改 bind 地址、路由、防火墙
4. **不冲突其他服务** —— 与 VPN/TUN/Warp/Docker 网络共存
5. **无死代码** —— 任何未被调用的函数、未读的字段、未使用的依赖必须删除
6. **整体代码量控制在 2500 行以内** —— 超过需停下来和用户研究确认

### 2.2 关于代码规模

本文档描述的"小模块/中模块"是**规模感参考**,不是精确数字。Claude Code 应按代码质量和实际需求决定行数,**不要为凑数字牺牲质量或强行压缩**。

**硬规则**:
- 整体代码量超过 **2500 行** 时必须停下来汇报,等用户确认
- 用户同意放宽到 **3000 行**,再超过时**再次停下来确认**
- 绝不允许连续超线

**强制死代码检查**:每个阶段验收前必须跑 `cargo clippy -- -D dead_code -D unused_imports`,无警告才能合入。

### 2.3 许可证说明

项目采用**双许可证**(见附录 C):
- **用户态 Rust 代码(src/\*.rs)**:MIT
- **eBPF C 代码(ebpf/\*.c)**:GPL-2.0(Linux 内核要求 struct_ops 必须 GPL)

---

## 3. 整体架构

### 3.1 核心理念

**accel 不拦截、不代理、不改包。它替换的是"内核 TCP 栈里如何发包"的决策逻辑。**

打比方:
- **用户态代理方案**(很多加速器):在网卡入口拦截车辆,改走 VIP 通道 → 复杂、冲突多
- **accel(struct_ops)**:车辆走原路,但改变交警的指挥方式(发包时机、速率)→ 简单、零冲突

### 3.2 数据流图

```
┌──────────────────────────────────────────────────────────┐
│  用户(任何客户端,零改动)                                     │
│  真实 IP:1.2.3.4                                          │
└─────────────────────────┬────────────────────────────────┘
                          │ 普通 TCP 连接
                          ↓
┌──────────────────────────────────────────────────────────┐
│  你的服务器                                                 │
│                                                           │
│  eth0 (网卡)                                              │
│    ↓                                                     │
│  Linux 内核 TCP 协议栈                                     │
│                                                           │
│  ┌──────────────────────────────────────────┐           │
│  │  拥塞控制插槽 (struct tcp_congestion_ops)   │           │
│  │                                           │           │
│  │  当前算法:accel_bbr ← 我们的!              │           │
│  │  (替换了内核自带的 BBR / CUBIC)             │           │
│  │                                           │           │
│  │  负责决策:                                  │           │
│  │    - 什么时候发包                           │           │
│  │    - 发多快(cwnd / pacing_rate)           │           │
│  │    - 什么时候重传                           │           │
│  └──────────────────────────────────────────┘           │
│                                                           │
│  真实客户端 IP 1.2.3.4 全程保留                             │
│    ↓                                                     │
│  本机服务 (haproxy / nginx / v2ray / 任何 TCP 服务)          │
│  看到的源 IP:1.2.3.4 ✅                                    │
│  配置零改动                                                │
└──────────────────────────────────────────────────────────┘
```

### 3.3 关键设计决策

| 决策 | 选择 | 理由 |
|-----|------|-----|
| 加速位置 | 内核 TCP 栈内(struct_ops)| 零拷贝、零干预、真实 IP 保留、和所有服务兼容 |
| 算法格式 | eBPF struct_ops(非传统内核模块)| 可热插拔、不改内核、用户态升级 |
| 算法来源 | 基于 Linux 内核现成算法改造 | 不重造轮子,风险低,开发快 |
| 用户接口 | `sysctl` + `./accel` CLI | 系统原生机制 + 管理命令 |
| 算法切换 | `./accel algo switch`(封装 bpftool)| 秒级切换,已有连接继续用旧算法,新连接用新算法 |
| 运行模式 | 前台进程 | 开发期易调试,生产期由 systemd 管理 |
| 配置方式 | 同目录 TOML 文件 | 简单、不搞标准路径 |

### 3.4 和其他方案对比

| 方案 | 用户改配置 | 真实 IP | VPN/TUN 冲突 | 性能 |
|-----|---------|------|----------|-----|
| 锐速(内核模块,闭源)| 不用 | ✅ | 低 | 极高 |
| 用户态代理 | 改 bind + 路由 | ❌ 127.0.0.1 | 高 | 高 |
| PROXY 协议 | 改 bind + 应用支持 | ⚠️ 需应用解析 | 中 | 高 |
| **accel (struct_ops)** | **不用** | **✅** | **零** | **极高** |

**accel 是唯一同时满足"零改动、真实 IP、零冲突、极致性能"的方案**。

### 3.5 算法热插拔

accel 把每个算法做成独立的 `.bpf.o` 文件。运行时可秒级切换:

```bash
./accel algo list               # 看当前加载的算法
./accel algo switch accel_brutal # 切到激进模式(高丢包时用)
./accel algo switch accel_bbr    # 切回稳健模式
```

**切换过程**:
- 已有连接不中断(继续用旧算法)
- 新连接使用新算法
- 整个切换在 100ms 内完成

---

## 4. 项目文件结构

```
accel/
├── README.md                       ← 本文件
├── Cargo.toml                      ← Rust 项目配置(依赖 libbpf-rs)
├── acc.conf                        ← 配置文件(和二进制同目录)
├── run-test.sh                     ← 一键测试脚本
│
├── ebpf/                           ← eBPF C 代码(GPL-2.0)
│   └── algorithms/
│       ├── accel_cubic.bpf.c       ← [2.1] 基于 Linux 内核 bpf_cubic.c
│       ├── accel_bbr.bpf.c         ← [2.2] 基于 Linux 内核 tcp_bbr.c 移植
│       └── accel_brutal.bpf.c      ← [第三步] 自研激进版
│
└── src/                            ← Rust 用户态代码(MIT)
    ├── main.rs                     ← 入口派发
    ├── cli.rs                      ← CLI(含 status/stop/test/benchmark/algo 子命令)
    ├── config.rs                   ← TOML 配置解析
    ├── ebpf_loader.rs              ← libbpf-rs 加载器
    ├── algo.rs                     ← 算法管理 list/switch
    ├── socket.rs                   ← Unix Socket 服务
    ├── status.rs                   ← 状态采集(TCP_INFO / ss)
    ├── health.rs                   ← 后台健康检查 + 自愈
    ├── incidents.rs                ← 事件日志记录
    ├── benchmark.rs                ← 性能测试
    └── tcp_info.rs                 ← TCP_INFO 解析
```

**规模感参考**(不是硬指标):
- **微模块**:几十行(单一简单功能)
- **小模块**:100-200 行(一个完整子功能)
- **中模块**:200-400 行(核心业务,包含多个相关功能)

**整体警戒线**:全部代码控制在 **2500 行以内**。

### 文件职责一句话说明

| 文件 | 一句话职责 |
|-----|---------|
| `ebpf/algorithms/accel_*.bpf.c` | struct_ops TCP 拥塞控制算法 |
| `src/main.rs` | 启动入口,分发到 CLI 子命令 |
| `src/cli.rs` | 所有 CLI 子命令的实现 |
| `src/config.rs` | 读 acc.conf 解析为 Rust struct |
| `src/ebpf_loader.rs` | 用 libbpf-rs 把 .o 文件加载进内核 |
| `src/algo.rs` | 算法的注册、卸载、切换 |
| `src/socket.rs` | Unix Socket 服务端(status/stop 入口)|
| `src/status.rs` | 采集当前状态(进程/算法/TCP_INFO/incident 汇总)|
| `src/health.rs` | 每 30 秒后台检查:算法注册、sysctl、JIT、资源 |
| `src/incidents.rs` | 事件日志的读写(追加型文本文件)|
| `src/benchmark.rs` | `./accel test` 和 `./accel benchmark` 的实现 |
| `src/tcp_info.rs` | 调用 getsockopt(TCP_INFO) 或解析 ss 输出 |

---

## 5. 配置文件

配置文件名:`acc.conf`
位置:**和二进制 `accel` 同一目录**(不使用 `/etc/`)

```toml
# accel TCP 加速器配置
# 版本: 0.2

[algorithm]
# 默认使用的算法
# 可选值(按当前阶段可用性):
#   accel_cubic   [2.1 起可用,稳定基线]
#   accel_bbr     [2.2 起可用,推荐生产用]
#   accel_brutal  [第三步起可用,高丢包跨境场景]
default = "accel_bbr"

# 算法 .bpf.o 文件所在目录(相对路径从二进制目录算起,或绝对路径)
algo_dir = "./algorithms"


[runtime]
# Unix Socket 路径
# 空字符串 = 智能决策:
#   - 被 systemd 启动 → /run/accel/accel.sock
#   - 手动启动       → ./accel.sock
socket = ""
```

**修改配置 = 停掉程序改文件重启**:

```bash
./accel stop       # 或 Ctrl+C
vim acc.conf
sudo ./accel
```

**不设计运行时改配置 API**:停→改→重启是唯一的配置变更方式。算法切换用 `./accel algo switch` 命令,不修改配置文件。

---

## 6. 开发路线图

### 6.1 整体规划

| 阶段 | 内容 | 规模 | 预计时间 | 能验证什么 |
|-----|------|------|--------|----------|
| **第一步(已完成)** | eBPF 分流框架 + 管理接口 | 948 行 | 完成 | 基础设施就绪 |
| **2.1** | 库迁移(aya→libbpf-rs)+ 首个 struct_ops 算法 | 累计 ~1350 | 4-5 天 | 算法链路通畅,等效 CUBIC |
| **2.2** | accel_bbr(基于 Linux tcp_bbr.c 移植)| 累计 ~1750 | 4-5 天 | 跨境场景开始有加速效果 |
| **第三步** | accel_brutal(激进算法,融合 tcp-brutal 思想)| 累计 ~2250 | 5-7 天 | 高丢包吞吐显著提升 |

### 6.2 当前阶段

**本文档覆盖的范围**:第一步 → 2.1 → 2.2 → 第三步。

**每个阶段完成后**:
- 代码推到 main 分支
- release 二进制编译推到 `binaries` 孤儿分支
- 用户在 VPS 上实测

### 6.3 快速体验最新版

每个开发阶段完成后,编译好的二进制推到 `binaries` 分支。

```bash
# 下载当前阶段二进制
curl -LO https://github.com/123hehehe321/accel/raw/binaries/accel
curl -LO https://github.com/123hehehe321/accel/raw/binaries/acc.conf.example
chmod +x accel
mv acc.conf.example acc.conf
vim acc.conf          # 确认 algorithm.default 是当前阶段可用的算法

# 启动
sudo ./accel

# 验证工作状态
./accel status

# 停止
./accel stop
```

**⚠️ 生产使用前先在测试 VPS 验证**。

---

## 7. 第一步:eBPF 分流(已完成 + 将迁移)

### 7.1 现状

第一步已完成(948 行),实现:
- TOML 配置解析
- eBPF XDP 分流程序(识别端口 + 统计计数)
- Unix Socket 管理服务
- `./accel status` / `stop` 命令
- 防半死不活机制(populate→attach 顺序、超时、panic 捕获等)

### 7.2 为什么要迁移

第一步用的是 **aya-rs** 做 eBPF 加载。但新架构需要 **struct_ops**,而 aya-rs 不支持。

**迁移到 libbpf-rs**:
- 支持 struct_ops(新架构核心需求)
- 工业级稳定(Meta、Cilium、RedHat 在用)
- 支持 CO-RE(Compile Once, Run Everywhere)

### 7.3 同时做架构清理

新架构不需要 XDP 分流层(算法通过 sysctl 对所有 TCP 生效),所以本次迁移同时清理以下内容:

**删除**:
- `ebpf/classifier.c`(整个文件)
- `src/ports.rs`(整个文件)
- `src/mode.rs`(整个文件)
- `src/config.rs` 的 `[network]` 段和 `backend` 字段
- `src/cli.rs` 的 XDP attach 逻辑
- `src/status.rs` 的 `mode`、`ports`、端口级流量统计字段
- `Cargo.toml` 的 aya 系列依赖
- `build.rs` 的手动 clang 编译逻辑(libbpf-cargo 接管)
- `acc.conf` 简化为 `[algorithm]` + `[runtime]` 两节

**保留**(核心业务逻辑):
- `src/main.rs`(入口)
- `src/socket.rs`(Unix Socket 服务)
- `src/status.rs`(重写采集逻辑,但框架保留)
- `src/cli.rs`(去除 XDP 相关,保留 status/stop)
- `src/config.rs`(只保留新配置结构)
- 防半死不活机制(Day 3B 所有补丁)

**迁移后预计**:948 - 408 (删除) = ~540 行基础代码

---

## 8. 第二步:struct_ops 算法

### 8.1 目标

把 Linux 内核提供的 TCP 拥塞控制算法**以 eBPF 格式**加载到内核,使用 struct_ops 机制替换内核 TCP 栈的拥塞控制决策。

### 8.2 子阶段 2.1:首个算法(accel_cubic)

#### 目标

- 完成 aya → libbpf-rs 迁移(见 §7)
- 从 Linux 源码 `tools/testing/selftests/bpf/progs/bpf_cubic.c` 照抄改造成 `accel_cubic.bpf.c`
- 实现算法加载/切换 CLI
- 验证整条链路:eBPF 编译 → 加载 → 注册 → sysctl 切换 → TCP 连接正常

**此时的加速效果**:等效 CUBIC(因为就是抄的 CUBIC)。**本阶段不追求性能提升,追求链路通畅**。

#### 关键工作

1. **库迁移**:`src/ebpf_loader.rs` 基于 libbpf-rs 重写加载逻辑
2. **算法文件**:`ebpf/algorithms/accel_cubic.bpf.c`
   - 从 Linux 内核 `bpf_cubic.c` 复制
   - 重命名为 `accel_cubic`(避免和内核 CUBIC 冲突)
   - 加 GPL license 声明
   - 编译后生成 `.bpf.o` 文件
3. **算法管理**:`src/algo.rs`
   - `register_algo(name, path_to_o)`:加载到内核
   - `switch_algo(name)`:`sysctl tcp_congestion_control=<name>`
   - `list_algos()`:读 `/proc/sys/net/ipv4/tcp_available_congestion_control`
4. **CLI 子命令**:`./accel algo list/switch`
5. **启动流程**:accel 启动时自动加载配置中 `default` 指定的算法并设置 sysctl(IPv4 + IPv6 都设置)

#### 2.1 阶段检测机制(8 项)

实现到 `health.rs` / `incidents.rs` / `status.rs`:

| # | 检测项 | 实现位置 | 触发动作 |
|---|------|-------|-------|
| 1 | 进程挂 | systemd 拉起 + 启动时记录 | `incidents.rs` 记录 Startup |
| 2 | 算法注册丢失 | `health.rs` 每 30s 检查 | 重新注册 + 记录 AlgoRelost |
| 3 | sysctl 被改回 | `health.rs` 每 30s 检查 | 重设 + 记录 SysctlReset |
| 4 | JIT 被关 | 启动检查 + health 检查 | 警告 + 记录 JitDisabled |
| 5 | 内核版本记录 | 启动时一次性 | 记录到 incident log |
| 6 | kernel panic 推断 | 启动时检查上次 shutdown 记录 | 如果非 clean/crash → KernelPanic |
| 7 | fd 耗尽 | accept 错误时 | 通知主线程退出(Day 3B 已有)|
| 8 | OOM 检测 | 启动时扫一次 dmesg | 如果发现 OOM → 记录 OomKilled |

#### 2.1 验收

- [ ] cargo build + clippy (含 `-D dead_code`) 干净
- [ ] `sudo ./accel` 启动成功,算法自动加载并 sysctl 设置
- [ ] `./accel algo list` 显示 `accel_cubic (active)`
- [ ] TCP 连接功能正常(curl、ssh、scp 等)
- [ ] `./accel status` 显示当前算法、连接数、TCP 健康指标
- [ ] `./accel stop` 优雅退出:自动卸载 struct_ops、清理 socket 文件
- [ ] 外部卸载 struct_ops 后,health check 自动恢复
- [ ] 外部改 sysctl 后,health check 自动恢复
- [ ] `accel-incidents.log` 记录了 startup、shutdown 等事件

---

### 8.3 子阶段 2.2:BBR 移植(accel_bbr)

#### 目标

- 基于 Linux 内核 `net/ipv4/tcp_bbr.c`(约 500 行)移植到 BPF 版本
- 保持和内核 BBR 等价的算法逻辑
- 作为 **生产默认算法**

**此时的加速效果**:对比 CUBIC 有显著提升(跨境场景 1.5-2 倍吞吐)。

#### 关键工作

1. **算法移植**:`ebpf/algorithms/accel_bbr.bpf.c`
   - 参考 Linux 内核 `tcp_bbr.c`
   - 调整为满足 BPF verifier 的要求(bounds check、循环展开等)
   - 预计修改量 ~20-30%(主要是 verifier 要求的调整)
2. **默认算法切换**:`acc.conf` 的 `default` 改为 `accel_bbr`
3. **算法对比机制**:`./accel test` / `./accel benchmark`

#### 2.2 阶段检测机制(6 项新增)

| # | 检测项 | 实现 |
|---|------|----|
| 9 | 算法性能自检 | `./accel test`:loopback iperf3,对比 CUBIC 基线 |
| 10 | 算法 init 失败率 | BPF map 里加计数器,status 显示 |
| 11 | 连接统计 | status 显示 "connections using accel_bbr: X" |
| 12 | TCP_INFO 实时指标 | status 显示 cwnd/rtt/retrans/ca_state 汇总 |
| 13 | 网络质量评估 | status 显示 avg RTT / 丢包估算 + 文字判断 |
| 14 | cwnd=0 异常 | status 统计 cwnd=0 的连接数(正常应为 0)|

#### 2.2 验收

- [ ] cargo build + clippy 干净
- [ ] `accel_bbr` 算法加载成功
- [ ] `./accel algo switch accel_bbr` 秒级切换
- [ ] 切换时已有连接不中断
- [ ] `./accel test` 显示 accel_bbr 比 accel_cubic 吞吐更高
- [ ] 跨境 VPS 实测:HTTP 下载速度比 CUBIC 提升 1.5 倍以上
- [ ] status 显示 "connections using accel_bbr: N"(N > 0)
- [ ] status 显示 TCP_INFO 汇总指标
- [ ] incident log 无异常事件

---

## 9. 第三步:激进算法

### 9.1 目标

开发 accel 自研的激进算法 `accel_brutal`,融合 tcp-brutal 思想:
- BBR 底盘(RTT + 带宽估算)
- 高丢包时切换到"无视丢包"激进模式
- 根据实时丢包率动态调整策略

**适用场景**:跨境高丢包链路(丢包率 > 2%)

### 9.2 关键工作

1. **算法设计**:`ebpf/algorithms/accel_brutal.bpf.c`
   - 基于 `accel_bbr` 扩展
   - 新增策略切换逻辑(根据 retrans rate 切换 BBR 模式 / brutal 模式)
   - 可配置激进度(通过 BPF map 实现参数动态调整)
2. **`./accel benchmark` 正式测试**
   - 自动切换 CUBIC → BBR → accel_bbr → accel_brutal
   - 对比吞吐、重传率、RTT
   - 结果落地到 `accel-benchmark-<date>.json`

### 9.3 第三步阶段检测机制(4 项新增)

| # | 检测项 | 实现 |
|---|------|----|
| 15 | 正式 benchmark | `./accel benchmark` 三算法对比 |
| 16 | 内存泄漏 | RSS 历史峰值,超过初始值 3 倍警告 |
| 17 | CPU 异常 | CPU 历史峰值,超过 10% 持续 5 分钟警告 |
| 18 | 长时间无流量 | status 区分"零连接"和"零包"场景 |

### 9.4 第三步验收

- [ ] `accel_brutal` 算法加载成功
- [ ] `./accel benchmark` 显示 accel_brutal 在高丢包场景显著优于 accel_bbr
- [ ] 正常网络环境下,accel_brutal 不差于 accel_bbr(不倒退)
- [ ] 长时间(72h+)运行 incident log 无异常增长
- [ ] 内存/CPU 历史峰值在合理范围

---

## 10. 验证机制

### 10.1 设计原则

用户必须能**持续验证 accel 真的在工作**。不能只看启动成功,要有持续证据。

**四重验证**:
1. **静态验证**:进程活着、算法注册、sysctl 指向我们
2. **动态验证**:有连接在用、TCP 指标正常
3. **主动验证**:`./accel test` / `./accel benchmark` 按需运行
4. **可靠性验证**:incident log 累计统计、自愈日志

### 10.2 `./accel status` 完整输出

```
accel status:
  version:           0.2
  running:           yes (pid=12345)
  uptime:            2h 15m
  socket:            ./accel.sock

algorithm:
  loaded:            accel_cubic, accel_bbr, accel_brutal
  active:            accel_bbr
  kernel sysctl:     accel_bbr (ipv4) / accel_bbr (ipv6)
  registered:        yes (struct_ops id=105)
  bpf jit:           enabled

connections using accel:
  total tcp:         127
  using accel_bbr:   123 (96.8%)
  using other:       4 (cubic legacy, internal)

realtime metrics (last 60s, averaged):
  avg throughput:    145 Mbps per connection
  avg rtt:           186 ms
  avg min_rtt:       178 ms
  retrans rate:      0.12%
  ca_state breakdown: Open 94%, Disorder 3%, CWR 1%, Recovery 2%, Loss 0%
  avg cwnd:          284 packets
  cwnd=0 abnormal:   0                          ← 算法 bug 哨兵

network quality:
  assessment:        moderate loss, high rtt (cross-border typical)
                     accel should show meaningful improvement here

reliability:
  current uptime:    2h 15m
  total uptime:      4d 12h 33m
  restarts:          3
  last restart:      8h ago (reason: socket_panic)

  incidents (last 7 days):
    algo relost:     2
    sysctl reset:    5
    socket panic:    1
    kernel events:   0

  health check:      every 30s, last ok 14s ago

observation (sample connections):
  1.2.3.4:54321    accel_bbr cwnd=280 rtt=185ms  45 Mbps
  5.6.7.8:12345    accel_bbr cwnd=210 rtt=192ms  32 Mbps
  9.10.11.12:443   accel_bbr cwnd=295 rtt=178ms  68 Mbps
```

### 10.3 `./accel test`(快速自检)

**什么时候用**:日常检查,确认算法在当前机器上工作正常(3-5 秒)。

```bash
$ ./accel test

accel self-test:

  [1/3] algo loaded        ... ok (accel_bbr registered, id=105)
  [2/3] sysctl active      ... ok (ipv4=accel_bbr, ipv6=accel_bbr)
  [3/3] loopback throughput ... ok (8.4 Gbps, >5 Gbps baseline)

  all checks passed.
```

### 10.4 `./accel benchmark`(性能测试)

**什么时候用**:
- 部署后首次验证加速效果
- 第三步验证 accel_brutal 是否优于 accel_bbr
- 对比不同 VPS 地区的加速效果

```bash
$ ./accel benchmark
accel benchmark:

  Running 30s iperf3 test...

  phase 1/3: kernel cubic  ... 48.2 Mbps avg, 2.3% retrans
  phase 2/3: kernel bbr    ... 67.5 Mbps avg, 0.8% retrans
  phase 3/3: accel_bbr     ... 95.3 Mbps avg, 0.4% retrans

  result:
    accel_bbr vs cubic:  +97.7%  ✅
    accel_bbr vs bbr:    +41.2%  ✅

  saved to ./accel-benchmark-2026-04-24.json
```

### 10.5 Incident Log(累计可靠性证据)

**文件位置**:
- 手动启动:`./accel-incidents.log`
- systemd 启动:`/run/accel/accel-incidents.log`

**格式**(追加型文本文件,自动轮转保留最新 500 行):

```
# accel incidents log

2026-04-24T10:15:32Z | startup          | pid=12345 kernel=6.1.0-17-amd64 last_shutdown=clean
2026-04-24T10:15:33Z | jit_enabled      | ok
2026-04-24T10:15:34Z | sysctl_set       | tcp_cc=accel_bbr (ipv4+ipv6)
2026-04-24T14:22:18Z | algo_relost      | accel_bbr unregistered externally, restored
2026-04-24T18:47:03Z | sysctl_reset     | tcp_cc changed to bbr, restored
2026-04-25T03:12:44Z | socket_panic     | socket thread panicked
2026-04-25T03:12:45Z | startup          | pid=23451 last_shutdown=socket_panic
2026-04-25T09:33:21Z | daily_summary    | uptime=22h mem_peak=48MB cpu_peak=2.3%
2026-04-26T02:11:08Z | startup          | pid=33876 last_shutdown=unknown
2026-04-26T02:11:09Z | oom_detected     | dmesg shows oom killed accel pid=23451
```

**价值**:用户扫一眼就能发现"几小时才出现一次的 bug"。

### 10.6 Health Check(后台自愈)

每 30 秒执行一次:
1. 算法是否还注册 → 丢失则重新注册
2. sysctl 是否还是我们的值 → 被改则恢复
3. JIT 是否开启 → 被关则警告
4. 进程 RSS 是否异常增长 → 超阈值记录
5. 进程 CPU 是否异常 → 超阈值记录
6. fd 使用率 → 超 80% 警告

**自愈以 incident log 为记录,不打扰用户**。status 命令可查看。

---

## 11. 测试方法

### 11.1 一键测试脚本

`run-test.sh` 根据当前阶段自动选择测试。

```bash
sudo ./run-test.sh           # 自动检测当前阶段
sudo ./run-test.sh phase1    # 只跑第一步迁移后的测试
sudo ./run-test.sh phase2.1  # 2.1 测试(算法加载 + sysctl)
sudo ./run-test.sh phase2.2  # 2.2 测试(BBR 性能对比)
sudo ./run-test.sh phase3    # 第三步测试(brutal 算法)
sudo ./run-test.sh all       # 所有阶段
```

**注意**:`run-test.sh` 在 2.2 完成时一次性写齐所有阶段测试(避免分次修改同一文件)。

### 11.2 手动验证

```bash
# 启动 accel(screen/tmux 里)
sudo ./accel

# 另一个终端看状态
./accel status

# 快速自检
./accel test

# 正式基准测试
./accel benchmark

# 切换算法
./accel algo switch accel_brutal
./accel algo switch accel_bbr

# 停止
./accel stop
```

### 11.3 错误排查

**所有错误在终端直接显示**,不翻日志文件。

遇到问题:
1. 保存终端输出
2. 保存 `accel-incidents.log`
3. 把错误内容 + README + 相关源文件给 Claude Code
4. Claude Code 根据 README 上下文定位

---

## 12. 已知限制

### 12.1 系统要求

- **Debian 11**:需 backports 内核(6.1+)
- **Debian 12 / 13**:默认内核即可
- **不支持 Debian 10**:内核不支持 struct_ops
- **不支持其他发行版**:未测试(理论上内核 6.1+ 的任何发行版都能用)

### 12.2 权限

必须 root 或具有以下 capabilities:
- `CAP_NET_ADMIN`
- `CAP_BPF`(内核 5.8+)或 `CAP_SYS_ADMIN`
- `CAP_SYS_RESOURCE`(用于 RLIMIT_MEMLOCK)

开发期直接 `sudo` 即可。

### 12.3 与其他服务的关系

**零冲突承诺**:

| 服务 | 是否需要改配置 |
|-----|-----------|
| haproxy | ❌ 不需要 |
| nginx | ❌ 不需要 |
| v2ray / xray | ❌ 不需要 |
| OpenVPN | ❌ 不需要 |
| WireGuard | ❌ 不需要 |
| Warp | ❌ 不需要 |
| Docker 网络 | ❌ 不需要 |
| iptables / nftables | ❌ 不需要 |

**原理**:accel 不拦截流量、不改包、不改路由表、不改防火墙规则。它只是替换了内核 TCP 栈里"如何发包"的决策。

### 12.4 当前阶段的限制

- **第一步完成(已完成)**:基础设施就绪,无加速效果
- **2.1 完成**:链路通畅,等效 CUBIC,**无明显加速**
- **2.2 完成**:BBR 移植,**跨境场景开始有明显提升**
- **第三步完成**:激进算法,**高丢包场景显著提升**

---

## 13. 编码规范与工作指引

### 13.1 Rust 代码规范

- Rust 2021 edition
- 避免 `unsafe`,仅在 FFI 时使用(必须加注释说明为什么安全)
- 错误处理用 `anyhow::Result`(应用层)或 `thiserror`(库层)
- 避免 `.unwrap()`,除非测试代码或明确不会 panic(加注释说明)

### 13.2 eBPF C 代码规范

- 每个 eBPF 文件必须有:
  ```c
  // SPDX-License-Identifier: GPL-2.0

  char _license[] SEC("license") = "GPL";
  ```
- 参考 Linux 内核源码风格
- 基于 `tools/testing/selftests/bpf/progs/` 下的现成算法改造,不从零写

### 13.3 错误输出

错误直接打印到 stderr,**简洁、具体、可操作**:

```
✅ error: kernel 5.10.0 too old for struct_ops, need >= 6.1 (use backports kernel)

❌ Error occurred.
❌ Failed.
```

### 13.4 日志策略

- 错误:`eprintln!` 到 stderr
- 状态:`println!` 到 stdout
- 事件:追加到 `accel-incidents.log`
- **不引入** tracing/log 等框架(当前规模不需要)
- 调试信息通过 `ACCEL_DEBUG=1` 环境变量开启

### 13.5 代码风格

- `cargo fmt` 格式化
- **`cargo clippy -- -D warnings -D dead_code -D unused_imports` 必须无警告**
- 每个函数专注做一件事
- 单个文件规模参考 §4

### 13.6 工作节奏

**严格按阶段顺序工作**:

```
第一步已完成 → 2.1(迁移+cubic)→ 验收 → 2.2(bbr)→ 验收 → 第三步(brutal)→ 验收
```

每个阶段必须:
1. 写代码
2. cargo build 成功
3. `cargo clippy -D dead_code -D unused_imports` 无警告
4. 测试通过
5. 验收清单全部打勾
6. **然后才进入下一阶段**

**不要一次写完整个项目**。

### 13.7 参考项目

遇到不确定的细节,参考:

- **libbpf-rs**:https://github.com/libbpf/libbpf-rs
- **libbpf-cargo**:https://docs.rs/libbpf-cargo/
- **Linux 内核 bpf_cubic.c**:`tools/testing/selftests/bpf/progs/bpf_cubic.c`
- **Linux 内核 tcp_bbr.c**:`net/ipv4/tcp_bbr.c`
- **tcp-brutal 思想**:https://github.com/apernet/tcp-brutal

### 13.8 调试工具

- `cargo build --release` - 编译
- `sudo bpftool struct_ops show` - 查看已注册的 struct_ops
- `sudo bpftool struct_ops dump name accel_bbr` - dump 算法详情
- `sysctl net.ipv4.tcp_available_congestion_control` - 查看可用算法
- `ss -tni` - 查看每个连接的 TCP 详细信息
- `dmesg | tail` - 内核日志(BPF verifier 错误在这里)
- `cat /proc/sys/net/core/bpf_jit_enable` - 查看 JIT 状态

### 13.9 常见错误

| 错误 | 原因 | 修复 |
|-----|-----|-----|
| `failed to register struct_ops` | 算法名冲突 | 改 BPF 程序里的 name 字段 |
| `verifier rejected` | eBPF 代码不符合验证器 | 看 `dmesg` 的 verifier 日志 |
| `sysctl: invalid argument` | 算法没加载 | 先 `./accel algo list` 确认已注册 |
| `Permission denied` | 非 root 或缺 CAP | `sudo ./accel` |
| `JIT disabled` | bpf_jit_enable=0 | `sudo sysctl -w net.core.bpf_jit_enable=1` |
| `address already in use` | 前次没清理 socket | accel 启动会自动清理 stale socket |

### 13.10 不要做的事

❌ 不要改变架构(不要再回到用户态代理、AF_XDP、smoltcp)
❌ 不要加 README 未要求的功能
❌ 不要自行修改 README(发现歧义先询问用户)
❌ 不要引入重量级依赖(clap 等)
❌ 不要加日志文件(只有 incidents log)
❌ 不要加 daemon 模式(前台运行)
❌ 不要加运行时改配置 API
❌ **整体代码量超 2500 行必须停下来和用户研究确认**
❌ **发现 README 歧义必须先询问用户**

### 13.11 可以做的事

✅ 在 README 范围内优化代码质量
✅ 删除所有 dead code(强制执行)
✅ 添加必要注释(特别是 unsafe 块)
✅ 补充合理错误处理
✅ 写清晰的 commit message

### 13.12 Git 工作流

- main 分支:源代码
- binaries 孤儿分支:编译好的二进制 + acc.conf.example + 简短下载说明
- 每个阶段完成:main 合入 + binaries 分支更新 + 用户测试 → 再进下一阶段

---

## 附录 A:验收清单

### A.1 第一步迁移验收(aya → libbpf-rs)

- [ ] `cargo build --release` 成功
- [ ] `cargo clippy -- -D warnings -D dead_code -D unused_imports` 无警告
- [ ] `sudo ./accel` 启动成功(此阶段无算法可加载,仅管理框架跑起来)
- [ ] `./accel status` 显示正确框架信息
- [ ] `./accel stop` 优雅退出
- [ ] Ctrl+C 优雅退出
- [ ] 所有 Day 3B 的防半死不活机制工作正常
- [ ] `accel-incidents.log` 创建且有 startup/shutdown 记录
- [ ] 删除清单(§7.3)中的文件/代码确实被清理

### A.2 2.1 验收(首个 struct_ops 算法)

- [ ] `ebpf/algorithms/accel_cubic.bpf.c` 编译成功
- [ ] `sudo ./accel` 启动后自动加载 accel_cubic + 设置 sysctl
- [ ] `./accel algo list` 显示 accel_cubic (active)
- [ ] `./accel status` 显示 "connections using accel_cubic: N"
- [ ] TCP 基础功能:curl、ssh、scp 正常
- [ ] `./accel test` 通过所有 3 项检查
- [ ] `bpftool struct_ops show` 能看到 accel_cubic
- [ ] 外部 `bpftool struct_ops unregister` 后,health check 30s 内自动恢复
- [ ] 外部 `sysctl tcp_congestion_control=bbr` 后,health check 30s 内恢复
- [ ] `./accel stop` 自动卸载 struct_ops、清理 sysctl、清理 socket

### A.3 2.2 验收(accel_bbr)

- [ ] `accel_bbr` 算法编译 + 加载成功
- [ ] `./accel algo switch accel_bbr` 秒级切换(已有连接继续工作)
- [ ] `./accel test` 通过
- [ ] `./accel benchmark` 结果显示 accel_bbr > accel_cubic
- [ ] 跨境 VPS 实测:HTTP 下载速度 accel_bbr 比 accel_cubic 高 ≥ 50%
- [ ] status 显示完整 TCP_INFO 指标
- [ ] status 的 cwnd=0 异常连接计数为 0
- [ ] incident log 无异常

### A.4 第三步验收(accel_brutal)

- [ ] `accel_brutal` 算法加载成功
- [ ] `./accel benchmark` 高丢包场景显示 accel_brutal > accel_bbr
- [ ] 低丢包场景 accel_brutal 不劣于 accel_bbr
- [ ] 72 小时连续运行内存稳定无明显增长
- [ ] CPU 历史峰值 < 10%
- [ ] incident log 记录完整,无异常事件

---

## 附录 B:版本历史

| 版本 | 日期 | 说明 |
|-----|-----|-----|
| 0.1 | 2026-04 | 初版:AF_XDP + smoltcp 架构,第一步完成(eBPF 分流)|
| 0.2 | 2026-04 | 架构重构:转向 eBPF struct_ops,放弃 AF_XDP + smoltcp |
| 0.2.1 | 2026-04 | README §1.5 调整:明确 struct_ops.link 需内核 6.4+,Debian 12 必须 backports,Debian 11 不再支持 |

---

## 附录 C:许可证

**双许可证**:

- **用户态 Rust 代码(`src/*.rs`、`Cargo.toml`、`build.rs`)**:**MIT**
  - 允许商业使用、修改、私有化

- **eBPF C 代码(`ebpf/**/*.c`)**:**GPL-2.0**
  - Linux 内核要求 struct_ops 必须 GPL
  - 修改 eBPF 代码后的衍生作品必须 GPL

**用户角度的实际影响**:
- 使用 accel 本身:无任何限制(包括商业使用)
- 修改 accel 用户态代码:无开源要求(MIT)
- 修改 accel eBPF 算法代码:衍生作品必须 GPL(这是 Linux 内核的要求,非本项目定义)

**项目根目录**:
```
LICENSES/
  MIT.txt       ← 用户态代码许可证
  GPL-2.0.txt   ← eBPF 代码许可证
```

---

**本 README 是给 Claude Code 的开发圣经,请严格遵守其中的架构决策和工作指引**。
