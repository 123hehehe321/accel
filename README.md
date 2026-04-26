# accel binaries

这个分支只放编译好的二进制 + 配置示例 + 验收脚本。源代码在 `main` 分支。

## 当前版本: 2.5-smart-D5 (glibc 2.34 build)

- **2.5-D5 阶段**: cli/status/health 接通 — `algorithm = "accel_smart"`
  端到端可用。启动时 cli.rs 解析 `[smart]` 段、写两个 BPF 配置 map、
  attach tc-bpf 到 egress；`./accel status` 多了 smart 段；
  health.rs 在外部 unregister 后能自愈重写 smart 配置 + 重 attach tc。
- **D5 验收脚本** `verify-smart-d5.sh`:
  * 负向测试: target=smart 但缺 [smart] 段 → 必须 bail
  * 正向测试: 启动日志含 "smart config / thresholds / dup ports / tc-bpf attached"
  * tc 真挂上: `tc filter show dev <iface> egress` 含 smart_dup
  * status 输出含 smart rate / thresholds / interface / sockets / state
  * stop 后 tc filter 干净卸载
- **accel binary 更新**: 完整接通后体积从 1.27 MB → 1.29 MB。
- **未变**: 2.3 的 cubic / brutal 行为完全不动。

## 历史版本: 2.5-smart-D4 (kernel-side 验收)

- D4 阶段只 load tc-bpf 程序进 kernel 但不 attach 到 egress hook;
  验证 reuse_fd 共享 smart_link_state map。`verify-smart-d4.sh` 仍可用
  作回归测试。

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

- **accel MD5**: `8d332b9353d036fe044f885935495e51`
- **accel 大小**: 1,290,912 字节
- **glibc 底线**: GLIBC_2.34
- **构建**: Ubuntu 22.04 docker 容器, Rust 1.94.1, clang 14
