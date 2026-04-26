# accel binaries

这个分支只放编译好的二进制 + 配置示例 + 验收脚本。源代码在 `main` 分支。

## 当前版本: 2.5-smart-D2 (glibc 2.34 build)

- **2.5-D2 阶段**: accel_smart 算法的 BPF 程序进入仓库,用 bpftool 直接
  跑 verifier 验收 (Rust 端集成在 D4 完成,所以这一步只测 kernel 是否
  接受 BPF 程序)。
- **新增文件**:
  * `accel_smart.bpf.o` — 独立编译的 accel_smart struct_ops 对象 (clang
    编, glibc 无关), 用 `bpftool struct_ops register` 加载。
  * `verify-smart-d2.sh` — D2 验收脚本: md5 校验 → bpftool 注册 → 出错
    抓 dmesg → 通过则确认 sysctl 可见。
- **accel binary 也更新**: 内嵌 accel_smart skeleton (D4 才用), 当前
  启动行为和 2.3 相同 (只加载 accel_cubic + accel_brutal)。
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

### 2.5-D2 额外下载 (verifier 验收)

```bash
curl -LO https://github.com/123hehehe321/accel/raw/binaries/accel_smart.bpf.o
curl -LO https://github.com/123hehehe321/accel/raw/binaries/verify-smart-d2.sh
chmod +x verify-smart-d2.sh

# 跑 D2 验收 (kernel 6.4+, 必须 BTF):
sudo ./verify-smart-d2.sh
```

期望全程 PASS。失败时脚本会自动打印 dmesg 切片 (verifier 日志), 把
完整输出贴给架构师 — 不要本地改 BPF 代码 (PROJECT_CONTEXT §5.4)。

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

- **accel MD5**: `cf91f3d4ebe1fbb74da502ae45baf1b3`
- **accel 大小**: 1,194,616 字节
- **accel_smart.bpf.o MD5**: `b53402bd9e08d16b19265f4b5a81cd63`
- **accel_smart.bpf.o 大小**: 505,976 字节
- **glibc 底线**: GLIBC_2.34
- **构建**: Ubuntu 22.04 docker 容器, Rust 1.94.1, clang 14
