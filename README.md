# accel binaries

这个分支只放编译好的二进制 + 配置示例 + 验收脚本。源代码在 `main` 分支。

## 当前版本: 2.5-smart-D4 (glibc 2.34 build)

- **2.5-D4 阶段**: Rust 端 LoadedSmart 完整 API 接通 (struct_ops 半边
  + tc-bpf 半边经由 reuse_fd 共享 smart_link_state map)。tc 程序
  loaded 进内核但**还没 attach** 到 egress hook —— attach 在 D5
  (cli.rs 解析 [smart] 段后调 attach_tc_egress)。
- **D4 验收脚本** `verify-smart-d4.sh`:
  * D2 回归 (accel_smart 仍在 loaded 列表)
  * 新增 `smart_dup` BPF 程序 verifier 通过 (D3 写的 BPF C 第一次
    进 kernel)
  * 新增 `smart_link_state` map 在内核里只有一份 (`reuse_fd` 真生效)
  * stop 后 dup 程序 + 共享 map 干净卸载
- **accel binary 更新**: `load_smart()` 现在 load 两个 BPF 对象 (smart
  struct_ops + smart_dup tc-bpf), `LoadedSmart` 加 5 个新方法 —
  `set_config / set_dup_config / attach_tc_egress / socket_count /
  state_counts`, 全部 D5 才有调用方。

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

### 2.5-D4 验收 (kernel-side: dup 程序 verifier + reuse_fd 验证)

```bash
# 已下 accel binary 的话替换一下:
curl -LO https://github.com/123hehehe321/accel/raw/binaries/accel
curl -LO https://github.com/123hehehe321/accel/raw/binaries/verify-smart-d4.sh
chmod +x accel verify-smart-d4.sh

# 跑 D4 验收:
sudo ./verify-smart-d4.sh
```

D4 脚本检查:
1. binary md5
2. 内核 + BTF + bpftool sanity
3. **D2 回归**: 启动 accel,`loaded:` 行仍含 accel_smart
4. **D3 verifier 验收**: `bpftool prog show | grep smart_dup` ≥ 1
   (BPF C 第一次进 kernel)
5. **reuse_fd 验证**: `bpftool map show name smart_link_state` 计数 = 1
   (struct_ops 和 tc-bpf 共用同一份 map; 计数 = 2 表示 reuse_fd 没生效,
   两边解耦,LOSSY 信号永远传不到 dup 程序)
6. clean stop 后 dup 程序 + 共享 map 全部卸载

失败时脚本会自动抓 accel 启动日志 + dmesg verifier 切片, 完整贴给架构师 ——
不要本地改 BPF 代码 (PROJECT_CONTEXT §5.4)。

### 2.5-D2 历史验收脚本 (仍可用)

```bash
curl -LO https://github.com/123hehehe321/accel/raw/binaries/verify-smart-d2.sh
chmod +x verify-smart-d2.sh
sudo ./verify-smart-d2.sh
```

D2 只校验 accel_smart struct_ops verifier 通过 (D4 是 D2 的超集)。

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

- **accel MD5**: `44dc6ce7b920531be115c8805d8874bc`
- **accel 大小**: 1,266,784 字节
- **glibc 底线**: GLIBC_2.34
- **构建**: Ubuntu 22.04 docker 容器, Rust 1.94.1, clang 14
