# accel binaries

这个分支只放编译好的二进制 + 配置示例 + 验收脚本。源代码在 `main` 分支。

## 当前版本: 2.5-smart-D7 (FULLY STATIC build, fix7-static)

- **md5**: `60637b4dacea4b98735733f97aaf10b0` (3037064 bytes)
- **链接方式**: **全静态** —— `file accel` 报 statically linked,
  `ldd accel` 报 not a dynamic executable,binary 自带 glibc + libelf
  + libbpf + zlib + zstd。**不挑发行版,不挑 glibc 版本**,任何
  x86_64 Linux ≥ 6.4 都能跑。
- **2.5-D7 fix7-static (静态构建 — 解决 fix7 binary 在 Debian 12 VPS 上
  报 GLIBC_2.39 not found 的事故)**:
  - **背景**:fix7 binary 在 Ubuntu 24.04 / glibc 2.39 dev VM 上 build,
    Rust 1.94 std 引入了 `pidfd_getpid` / `pidfd_spawnp` 这两个
    GLIBC_2.39 弱符号。Debian 12 / glibc 2.36 VPS 的 ld.so 拒绝加载,
    systemd restart-loop 服务 100+ 次。
  - **根因**:**glibc 是用户态库,前向不兼容**(高版本 build 不能跑在
    低版本系统上)。跟内核版本无关 —— 用户 VPS 内核 6.12.74 完全 OK。
  - **修法**:源码加 `.cargo/config.toml` 锁死全静态参数(crt-static +
    -static + libelf.a/libz.a/libzstd.a 静态归档),加 `build-static.sh`
    一键 build + `file/ldd/objdump` 三重验证。生成 binary 自带所有 C
    库,运行时不查目标系统的 libc。
  - **不走 musl 的原因**:试过,Ubuntu apt 的 libelf-dev 是 glibc-ABI
    only,musl 的 elf.h 缺 `Elf64_Relr` typedef → libelf 编译失败,
    apt 没有 musl-libelf 替代。glibc 静态对我们够了 —— 不用 DNS / NSS
    / locale,所有 syscall 直走内核。
  - **算法行为不变**:fix7 的 first-ACK gate / `smart state:` 行无条件
    显示 / `display_count` 死代码删除等改动全部保留。这次 fix 只换
    binary 的链接方式。
  - **审计 PASS**:17/17 单元测试通过,clippy 全过,binary 三重验证全过。

## 历史版本: 2.5-smart-D7 (fix7, glibc 2.34 build — 已废弃,glibc 2.39 翻车)

- **md5**: `525350236166e0caac2cff43562c4f3e` (1330344 bytes)
- **教训**: 此 binary 在 dev VM 上 build,链接 GLIBC_2.39 弱符号,
  Debian 12 / glibc 2.36 跑不了。算法逻辑跟 fix7-static 完全一致,
  唯一差异是链接方式。**勿用,装机用 fix7-static**。

## 历史版本: 2.5-smart-D7 (fix6)

- **2.5-D7 fix6 (上限放宽 + 死代码清理)**:
  - **`duplicate_factor` 上限 8 → 100**。极端环境(卫星 / 严重退化的
    移动链路)允许设到 100 倍。BPF 端 `#pragma unroll` 静态展开,
    100 次循环 ~500 BPF 指令,远低于 1M verifier 上限。
  - **死代码清理**: 删除 `accel_brutal.bpf.c` 里定义但未引用的
    `max_t` 宏;修复 `cli.rs` 一处冗余 `clone()`;修复
    `incidents::path().unwrap()` 改用 `if let Some` 防御。
  - **审计 PASS**: 全部源码过 `clippy -D warnings -D dead_code -D
    unused_imports`,无警告。

## 历史版本: 2.5-smart-D7 (fix5)

- **2.5-D7 fix5 (smart 算法精简 + 多倍发包可配 + 计数显示稳健化)**:
  用户实测 VPN/4K 直播加速时 smart 表现远不如 brutal,status 显示
  CONGEST 占 83%。三处改动:
  - **(A) 删除 rtt_congest_pct 配置项 + RTT 判定逻辑**(死代码不留)。
    隧道场景 srtt 远大于 min_rtt(min_rtt 在握手时锁定不更新),
    导致 RTT 比例永远大,smart 永远误判 CONGEST → 主动降速 →
    跑不快。fix5 起 smart **完全靠丢包判定**:
       loss < lossy/2     → GOOD(brutal 行为,满速)
       lossy ≤ loss < congest → LOSSY(BDP+pacing+多倍发包)
       loss ≥ congest     → CONGEST(让路)
  - **(B) duplicate_factor 配置项**(默认 2,范围 1..=8)。
    LOSSY 状态下每个 TCP 包发几份,以前是固定 2 份,现在用户可调。
    丢包重的链路可设 3-5 倍补偿;1 = 关闭克隆退化为单纯算法。
    BPF 端 `#pragma unroll` 静态展开,verifier 风险固定。
  - **(C) status 显示稳健化**: smart sockets / smart state 显示了
    18446744073709551509 这种天文数字(跨 CPU init/release 不平衡导致
    sum 偏负 wrap)。新版本 `display_count` 把 `> u64::MAX/2` 的值
    显示为 `0 (likely cross-CPU drift; raw sum=0xXXXX)`,操作员不会
    被误导。**注意**:这是 UX 修复,不解决底层 drift,但生产环境看
    数字不再吓人。

## 历史版本: 2.5-smart-D7 (fix4)

- **2.5-D7 fix4 (生产关键 bug 修复 + LPM_TRIE 重构)**:
  - **(A) BPF 计数器下溢竞态**: D7 真业务流量下出现
    `smart sockets: 18446744073709549559` (≈ u64::MAX − 2057) — 不是
    一次性偏差,是 ARRAY map "check-then-decrement" 多核竞态累积下溢。
    **修**: `brutal_socket_count` / `smart_socket_count` /
    `smart_state_count` 全部从 `BPF_MAP_TYPE_ARRAY` 改成
    `BPF_MAP_TYPE_PERCPU_ARRAY`。每 CPU 一份 slot,无需原子前缀,
    单 CPU 内串行化。用户态 `lookup_percpu` + wrapping_add 求和恢复
    正确全局计数(u64 模 2^64 算术保证)。
  - **(B) skip_subnet 改用 LPM_TRIE**: 原"32-array + #pragma unroll"
    可能撞 BPF verifier path explosion(理论 64 路径组合)。
    **改用 BPF 内核为 CIDR 匹配设计的 `BPF_MAP_TYPE_LPM_TRIE`**。
    BPF 代码从 100 行减到 30 行 + verifier 风险结构性归零 +
    容量从 32 提升到 IPv4 256 + IPv6 256 + 性能 O(n) → O(log n)。
- **2.5-D7 fix3a (隐蔽 bug 修复)**: 修复 health.rs 在算法被外部 unregister
  自愈 reload 时,**没重写 accel_skip_config map** 的隐蔽 bug。
  外部 `bpftool struct_ops unregister` → health 30s 检测到 → 重新 load
  → BPF map 默认全零 → 所有 LAN/loopback 连接被 brutal/smart 错误限速,
  本机服务变慢(用户感知不到)。
  fix:State 加 `skip_rules: Vec<SkipRule>` 字段,health.rs reload_one
  exhaustively match 调每个变体的 set_skip。
- **2.5-D7 fix3**: 把固定 `skip_local = true/false` 改成用户自定义 CIDR
  列表 `skip_subnet`,生产可控。
  - **必填字段**:`skip_subnet = "127.0.0.0/8,10.0.0.0/8,..."`(默认含
    8 条覆盖 RFC1918 + 链路本地 + IPv6 loopback/link-local/ULA)
  - **支持 IPv4 和 IPv6 CIDR**,目的地址和源地址都查
  - **严格校验**:host bits 必须为零,`192.168.1.0/16` 启动失败并提示
    规范化形式(生产环境不容忍歧义)
  - 最多 32 条规则
  - 用户可加自定义网段(Tailscale CGNAT 100.64.0.0/10、自建 VPN 等)
- **2.5-D7 fix2 (历史)**: 早期版本叫 `skip_local`,固定列表,2.5 内被 fix3 取代
- **2.5-D7 fix1**: 修复客户端命令在 systemd 启动场景找不到 socket 的问题。
  systemd 启动的 daemon 把 socket 绑到 `/run/accel/accel.sock`,但用户从
  shell 跑 `./accel status` 时没继承 INVOCATION_ID 环境变量,旧版本会
  连 `./accel.sock` 失败。新版本客户端 (status / stop / algo) 会先探测
  `/run/accel/accel.sock`,找不到再回退到 `./accel.sock`。
  服务端逻辑不动。
- **2.5-D7 fix1**: 修复客户端命令在 systemd 启动场景找不到 socket 的问题。
  systemd 启动的 daemon 把 socket 绑到 `/run/accel/accel.sock`,但用户从
  shell 跑 `./accel status` 时没继承 INVOCATION_ID 环境变量,旧版本会
  连 `./accel.sock` 失败。新版本客户端 (status / stop / algo) 会先探测
  `/run/accel/accel.sock`,找不到再回退到 `./accel.sock`。
  服务端逻辑不动。
- **2.5-D7 阶段**: 生产部署 + 长跑观察。所有 Rust 接通和 BPF 程序都在
  D5/D6 已验收完成,**剩下只能跑真业务流量看实际行为**。
- **新增源码**:
  * `cli.rs::preflight()` — 启动时检查内核 ≥ 6.4 + BTF 存在,
    失败 bail 中文修复提示 (~35 行,无新子命令,符合"简单粗暴"原则)
  * LOSSY 升级:reno 加法增长 → BDP 估算 + 100% pacing
    (D6 暴露 reno 切换时 cwnd 慢爬,吞吐暴跌几分钟的问题)
  * `acc.conf.example` 加完整 `[smart]` 段示例 + 详细中文注释
- **新增工具**:
  * `d7-monitor.sh` — 部署 + 观察助手:
    md5 校验 → acc.conf 审查 → 启动 accel → T0 / T1(+5m) / T2(+1h)
    三个时间点抓 `./accel status` 快照 → 子命令 `snapshot` /
    `rollback` / `diag`
- **未变**: 2.3 的 cubic / brutal 行为完全不动。

### D7 部署快速开始

```bash
# 拉新版 binary + 配置示例 + 监控脚本
curl -LO https://github.com/123hehehe321/accel/raw/binaries/accel
curl -LO https://github.com/123hehehe321/accel/raw/binaries/acc.conf.example
curl -LO https://github.com/123hehehe321/accel/raw/binaries/d7-monitor.sh
curl -LO https://github.com/123hehehe321/accel/raw/binaries/d7-monitor.expected.md5
chmod +x accel d7-monitor.sh

# 配 acc.conf (按 acc.conf.example 里的 [smart] 段填):
mv acc.conf.example acc.conf
vim acc.conf
# 改: algorithm = "accel_smart", [smart] 段填 rate_mbps + interface
#     + duplicate_ports (强烈建议填业务端口,别让 SSH 也被克隆)

# 部署 + T0/T1/T2 快照 (~65 分钟)
sudo ./d7-monitor.sh

# 24 小时后再抓一个快照
sudo ./d7-monitor.sh snapshot

# 异常时一键回滚到 brutal
sudo ./d7-monitor.sh rollback
```

监控关注:
- `smart sockets:` 占 `total tcp:` 的比例(0 = 流量没进 smart)
- `smart state:` 三态分布合理性(常年 100% CONGEST 或 0% LOSSY 都可疑)
- `accel-incidents.log` 不该有 KernelPanic / OomKilled
- 业务体感(SSH / haproxy / nginx / v2ray 是否比 brutal 顺)

## 历史版本: 2.5-smart-D6 (集成测试)

- D6 用 netns + veth + netem 在零 SSH 风险下跑三状态 + 热切换;
  GOOD/CONGEST 分类 OK,LOSSY 在 veth 测不出(零 RTT 扭曲,详见
  README.md §12.11)。`verify-smart-d6.sh` 仍可用。

## 历史版本: 2.5-smart-D5 (端到端接通)

- D5 完成 Rust 端 cli/status/health 全接通,`verify-smart-d5.sh`
  仍可用作回归。

## 历史版本: 2.5-smart-D4 (kernel-side 验收)

- D4 阶段验证 reuse_fd 共享 smart_link_state map; tc-bpf 程序入 kernel
  但不 attach (D5 才接 attach)。`verify-smart-d4.sh` 仍可用作回归。

## 历史版本: 2.5-smart-D2 path A (glibc 2.34 build)

- **2.5-D2 阶段**: accel_smart 算法的 BPF 程序进入仓库,通过 accel binary
  自身的 libbpf-rs 加载器跑 kernel verifier 验收 (D4 集成的最小子集 —
  只接 loader, 不接 cli/status/health/config)。
- **D2 用 accel binary 而非 bpftool 的原因**: Debian 12 系统 bpftool 是
  v7.1 / libbpf 1.1, **不认识** `.struct_ops.link` ELF section
  (libbpf 1.2+ 才支持), 直接 skip 后报 -ENOTSUPP, verifier 一条指令
  都没跑。accel binary 内嵌 libbpf-rs 0.26.2 (libbpf 1.4+) 能正确解析,
  走的就是 D4 生产路径。
- **新增文件**:
  * `verify-smart-d2.sh` — D2 验收脚本: md5 校验 → 写 acc.conf → 后台
    启动 accel → 看 "loaded:" 行包不包含 accel_smart → 失败抓
    accel stdout + dmesg → 自动 stop。
- **accel binary 更新**: 启动时 `all_loaders()` 多了 accel_smart 这条,
  现在启动日志 "loaded:" 行包含三个算法。target sysctl 指向哪个不变 —
  默认仍是 acc.conf 里 `algorithm = "accel_xxx"` 的那个。
- **未变**: 2.3 的 cubic / brutal 行为完全不动。

## 历史版本: 2.3-D4 (glibc 2.34 build)

- **2.3 阶段**: 多算法并存架构 + accel_brutal 算法首次进入 binary
- **新增 (相对 2.1-D6.1)**:
  * **`accel_brutal` 算法**: 参考 apernet/tcp-brutal 思想,自写 BPF struct_ops 实现。
    跨境高丢包场景的激进算法,核心 80% ack_rate 钳制 ("绝不退让")。
    单 TCP 连接速率上限通过 acc.conf `[brutal] rate_mbps` 配置 (Mbps)。
  * **多算法并存**: 启动时 `accel_cubic` + `accel_brutal` 同时加载,
    内核 `tcp_available_congestion_control` 同时可见两者。
  * **真热切换**: `./accel algo switch NAME` 立即生效 (< 100ms),
    新连接用新算法,已有连接继续用旧算法 (kernel 行为)。
    支持切到 accel-loaded (cubic/brutal) 或 kernel 内置 (bbr/cubic/reno)。
  * **配置文件新格式**: 顶层 `algorithm = "accel_xxx"` 替代旧
    `[algorithm].default` 嵌套;`[brutal]` 段当 algorithm = "accel_brutal"
    时必填;无静默降级。
  * **status 新 connections 段**:
    ```
    connections:
      total tcp:         <total>      ← 系统所有 TCP (来自 /proc/net/tcp{,6})
      brutal sockets:    <count>      ← 仅 brutal 加载时,从 BPF map 读
    ```
- **保留 (从 2.1-D6.1 继承)**: 自愈 (algo unregistered → reload),
  sysctl 漂移检测,incident log,clean shutdown 恢复 sysctl。
- **加速效果**:
  * `accel_cubic`: 等效 CUBIC,无加速
  * `accel_brutal`: 跨境高丢包预期有提升 (待 2.4 性能调优期实测)

## ⚠️ 内核要求: Linux 6.4+

eBPF `struct_ops.link` API 需要内核 6.4+ 且 `CONFIG_DEBUG_INFO_BTF=y`
(`/sys/kernel/btf/vmlinux` 必须存在)。

- **Debian 13**: 默认内核即可 (6.12+) ✅
- **Debian 12**: 必须升级到 bookworm-backports (6.7+ 或 6.12):
  ```bash
  sudo sh -c 'echo "deb http://deb.debian.org/debian bookworm-backports main" > /etc/apt/sources.list.d/backports.list'
  sudo apt update
  sudo apt install -t bookworm-backports linux-image-amd64
  sudo reboot
  ```
- **Debian 11**: 不推荐 — backports 最高 6.1, 不满足 6.4+。

## 下载

```bash
curl -LO https://github.com/123hehehe321/accel/raw/binaries/accel
curl -LO https://github.com/123hehehe321/accel/raw/binaries/acc.conf.example
curl -LO https://github.com/123hehehe321/accel/raw/binaries/verify-2.3.sh
chmod +x accel verify-2.3.sh
mv acc.conf.example acc.conf
vim acc.conf      # 选 algorithm + 设 brutal rate_mbps (如选 brutal)
```

### 2.5-D6 验收 (集成测试: 三种状态 + 热切换)

```bash
curl -LO https://github.com/123hehehe321/accel/raw/binaries/verify-smart-d6.sh
chmod +x verify-smart-d6.sh

# 需要 iperf3:
sudo apt install -y iperf3

# 跑 D6 验收 (~90 秒, eth0/SSH 完全不动):
sudo ./verify-smart-d6.sh
```

D6 通过 **network namespace + veth pair** 隔离测试流量,绝对不动 eth0:

```
host netns                     accv0 ──veth── accv1   netns "accel-test"
  iperf3 -c                    │                       │
  accel sysctl=accel_smart     │ tc clsact (BPF 克隆) │
  acc.conf [smart].interface   │ tc root (netem)      │
    = "accv0"                  │                       │
                                                       └── iperf3 -s
```

测试三个状态 (每段 20 秒, 中间 6 秒采样):

| 阶段 | netem 设置 | 期望状态 | 期望 TX 包数 |
|---|---|---|---|
| GOOD | 无 | GOOD | 基线 |
| LOSSY | `loss 5%` | LOSSY | ≥ 1.3 × 基线 (BPF 克隆每包发 2 份) |
| CONGEST | `loss 20% delay 200ms` | CONGEST | 较低 (BDP 收敛 + drain) |

外加热切换测试: smart → cubic → brutal → smart, 验证 sysctl 跟着变。

**关键设计**: clsact 在 root qdisc 之前跑,所以 BPF 先克隆,netem 后随机
丢包/延迟。每个克隆独立丢包概率,真正能验证冗余补偿效果。

失败时 (⚠ 警告) 多半是 EWMA 窗口或采样时机问题,**重跑可能 fix**。
真正失败 (✗) 才需要定位代码,完整输出贴给架构师。

清理: 脚本退出时自动 trap cleanup (kill accel + 删 netns + 删 veth +
恢复原 acc.conf)。即使 ctrl+c 也安全。手动清理: `sudo ./verify-smart-d6.sh clean`。

### 2.5-D5 验收 (端到端接通: 配置 → tc attach → status)

```bash
# 替换旧 binary, 拿新脚本:
curl -LO https://github.com/123hehehe321/accel/raw/binaries/accel
curl -LO https://github.com/123hehehe321/accel/raw/binaries/verify-smart-d5.sh
chmod +x accel verify-smart-d5.sh

# 跑 D5 验收:
sudo ./verify-smart-d5.sh
```

D5 脚本检查 7 项:
1. binary md5
2. 内核 + BTF + bpftool + tc(iproute2) sanity, 自动检出默认路由网卡
3. **负向测试**: `algorithm = "accel_smart"` 但缺 `[smart]` 段 → 必须 bail
   (确认 cli.rs 验证生效)
4. **正向测试**: 写完整 [smart] 配置启动, 期望日志包含
   `smart config: 100 Mbps`, `smart thresholds: ...`,
   `smart dup ports: 5500-20000`, `tc-bpf attached: ifindex=...`
5. **tc 真挂上**: `tc filter show dev <iface> egress` 显示 smart_dup
   (D4 只 load 不 attach; D5 才真挂)
6. **status 输出**: `./accel status` 含 smart rate / thresholds /
   interface / dup ports / sockets / state 行
7. clean stop 后 tc filter 自动 detach (Drop 路径生效)

失败时脚本会抓 accel stdout + tc 输出 + warning, 完整贴给架构师。

### 2.5-D4 验收 (kernel-side: dup 程序 verifier + reuse_fd 验证)

`verify-smart-d4.sh` 仍可用作回归测试 (检查 dup BPF 程序 verifier + map 共享)。

### 2.5-D2 历史验收脚本 (仍可用)

`verify-smart-d2.sh` — 最小验收 (只看 accel_smart 在 loaded 列表)。
D5 是 D4 + D2 的超集。

## 启动 (cubic 默认)

```bash
sudo ./accel
```

期望启动日志:
```
hello accel (v0.2, 2.3-D3)
config loaded from: ./acc.conf
  algorithm = "accel_cubic"
incident log: ...
loading algorithms into kernel...
  loaded: accel_brutal, accel_cubic
  capturing pre-accel sysctl: bbr (will restore on clean stop)
  kernel sysctl set: tcp_congestion_control=accel_cubic (ipv4+ipv6)
listening on /run/accel/accel.sock
press ctrl+c to stop, or run './accel stop' from another terminal.
```

## 启动 (brutal)

修改 acc.conf:
```toml
algorithm = "accel_brutal"

[brutal]
rate_mbps = 100      # 单连接速率上限,根据链路带宽调整

[runtime]
socket = ""
```

启动同上,会多两行输出:
```
  brutal rate written: 100 Mbps (12500000 byte/s)
```

## 启动 (smart, 2.5 新增)

修改 acc.conf:
```toml
algorithm = "accel_smart"

[smart]
rate_mbps = 100                  # GOOD 状态下的单连接速率上限 (Mbps)
interface = "eth0"               # 网卡名,用 `ip link` 查
duplicate_ports = "5500-20000"   # 多倍发包的端口范围, "" = 不限
loss_lossy_bp = 100              # 丢包率 ≥ 1% → LOSSY (basis points)
loss_congest_bp = 1500           # 丢包率 ≥ 15% → CONGEST
rtt_congest_pct = 50             # RTT 膨胀 ≥ 50% → CONGEST

[runtime]
socket = ""
```

启动日志:
```
  loaded: accel_brutal, accel_cubic, accel_smart
  smart config: 100 Mbps, interface=eth0 (ifindex=2)
  smart thresholds: lossy=100bp congest=1500bp rtt=50%
  smart dup ports: 5500-20000
  tc-bpf attached: ifindex=2 egress
```

`./accel status` 多 smart 段:
```
  smart rate:        100 Mbps
  smart thresholds:  lossy=100bp congest=1500bp rtt=50%
  smart interface:   eth0 (tc-bpf attached)
  smart dup ports:   5500-20000

connections:
  smart sockets:     N
  smart state:       GOOD A (X%) | LOSSY B (Y%) | CONGEST C (Z%)
```

## 常用命令

```bash
./accel status                    # 完整状态 (algorithm / connections / reliability)
./accel algo list                 # 已加载算法 + 当前 target + kernel 可用列表
./accel algo switch accel_cubic   # 热切换 (秒级,旧连接不中断)
./accel algo switch accel_brutal
./accel algo switch bbr           # 切到 kernel 内置 (运维对照)
./accel stop                      # 优雅退出 + 自动恢复 sysctl
```

## 2.3-D4 验收 (强烈建议跑)

下载 `verify-2.3.sh` 跑 7 个场景:

```bash
# 顺序: reboot → A (关键) → B → C → D → E → reboot → F → reboot → G
sudo reboot
# SSH 重连后:
cd ~/accel-bin/
sudo ./verify-2.3.sh A     # brutal 加载 + Plan A pacing_status (关键风险点)
# A 通过 → 连续跑 B C D E
sudo ./verify-2.3.sh B     # brutal_sockets 计数准确性
sudo ./verify-2.3.sh C     # 多连接 + 80% 钳制
sudo ./verify-2.3.sh D     # 算法热切换 (brutal ↔ cubic)
sudo ./verify-2.3.sh E     # 切到 kernel 内置 (bbr)
sudo reboot
sudo ./verify-2.3.sh F     # stop 时 sysctl 恢复
sudo reboot
sudo ./verify-2.3.sh G     # cubic 回归
```

每个场景 PASS 才进下一个。**A 失败立即停**, 完整复制屏幕输出 +
`sudo dmesg | tail -50` 给架构师 (Plan A→B→C 流程触发)。

## 已知行为 (非 bug)

- `./accel stop` 后 `bpftool struct_ops show` 可能仍看到 `accel_cubic`
  / `accel_brutal` 几秒~几分钟,这是 kernel 对在用 struct_ops 算法的
  保护机制 (socket pinning, 详见 README §12.5)。
  当所有用该算法的 socket 关闭后, kernel 自动 GC。

## binary 信息

- **accel MD5**: `09f9d7cdac0428492279359b47d6a9a5`
- **accel 大小**: 1,322,936 字节
- **glibc 底线**: GLIBC_2.34
- **构建**: Ubuntu 22.04 docker 容器, Rust 1.94.1, clang 14
- **新增**: preflight 启动检查 + LOSSY BDP+pacing + 客户端 socket 自动探测 + skip_subnet 用 LPM_TRIE + 计数器 PERCPU_ARRAY 修下溢
