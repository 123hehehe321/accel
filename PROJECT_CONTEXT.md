# PROJECT_CONTEXT.md — accel 项目入口文档

**所有新对话(Claude / Claude Code / 任何 AI 协作者)开始前必读**。

---

## 1. 项目当前状态(2026-04-26)

- **版本**:v0.2 / **2.5 D1-D7 完成,等用户实际跨境流量反馈**
- **支持算法**:`accel_cubic`(基线) + `accel_brutal`(激进) + **`accel_smart`(2.5 新增,自适应)**
- **代码量**:~3700 行 / 3000 预算(用户拍板放宽,2.6+ 严控)
- **2.5 收尾源 commit**:`claude/accel-smart` 上的 preflight commit(待最终编号)
- **2.5 收尾 binaries commit**:见 binaries 分支 README

历史里程碑:
- 2.3 收官 commit: main `78b7680` / binaries `7617cf8` / binary md5 `f14594ac59d737df516a0dd32dacf8b3`

---

## 2. 项目核心原则(5 条,不可违反)

这 5 条原则**贯穿所有架构决策**,任何代码改动、新功能设计前必须对照检查:

### 原则 1:简单粗暴,简单是方法不是妥协

- 简单 = **对问题边界的清晰认识**,不是为难度妥协
- 拒绝**伪复杂度**(看起来更智能但实际无价值的参数/功能)
- 例子:删除 `loss_pct_bp` 参数(用户填不出准确值,算法用了等于没用)
- 反例:**禁止**为"显得智能"加入实际无价值的功能

### 原则 2:高效可靠

- **只展示 100% 准确数据**,不准的数字 = 误导用户 = 比不展示更糟
- 拒绝平均值这种"看起来有用实际混淆"的统计
- 例子:删除 `observed loss`(中转架构下不准)、`send rate`(过度设计)、`rtt avg`(每连接差异巨大)
- 保留:`brutal sockets`(BPF map 原子计数,100% 准确)、`total tcp`(/proc/net/tcp 行数,客观)

### 原则 3:大炮换弹药 + 热插拔

- **多算法并存**(HashMap<String, LoadedAlgo>),切换不重启
- **加新算法 = 加文件 + 注册一行**(开发者侧),用户侧 = 下载新 binary
- `./accel algo switch X` 是纯 sysctl 写,不 drop 算法
- 老连接保留旧算法,新连接用新算法(graceful)

### 原则 4:不越权

- accel **只做加速**,不管总带宽、不管 SLA、不替管理员决策
- 例子:brutal 的 `rate_mbps` 是单连接速率上限。多连接叠加打爆链路是管理员的事。
- 反例:**禁止**加"按连接数动态分配总带宽"逻辑(越权)

### 原则 5:未来 AI 调节铺路

- 配置走文件(启动初始值)
- 运行时 BPF map 可读写(AI 模块可动态调节)
- API 保留接口(未来 `./accel brutal set-rate` 等)
- 当前简单实现 = 未来扩展接口

---

## 3. 用户(项目所有者)的角色

**用户不写代码**,但是**架构师 + 产品 PM**:

- 拍板核心原则和方向
- 拒绝过度设计
- 拒绝命名混淆
- 拒绝越权
- 提出反向问题暴露设计缺陷

**Claude Code 的工作模式**:
- 写代码、做实现、推 binary
- **撞坑立刻停下汇报,不自作主张**
- 涉及架构变更,**先出设计文档,等用户拍板**
- 涉及生产 binary,**先验证 md5,再讨论代码**
- BPF/verifier 修复**必须经过用户 VPS 实测才算有效**(dev VM 没 BTF)

**架构师 Claude 的工作模式**(在普通 Claude.ai 会话):
- 审查 Claude Code 的设计和代码
- 帮用户(非程序员)理解工程权衡
- 用大白话解释技术问题
- 翻译用户的产品判断成给 Claude Code 的精确指令

---

## 4. 沟通规则(用户和 AI 之间)

- 用户用中文沟通
- AI 用大白话精简核心,**不堆砌**
- 涉及技术参数(BPF API、内核字段、库行为)**必须先 web_search 或查源码再回答**,不能凭印象
- 涉及 binary 升级问题,**先验证 md5,再讨论代码**
- 用户提"是否..."的问题,**先停下检查,不要假设**
- 发现表面矛盾时**主动承认**,不要硬解释

---

## 5. 工程教训(必读,避免重复踩坑)

### 5.1 编造参数 = 严重失职

历史失误:架构师编造了 `loss_pct_bp` 参数(实际 tcp-brutal 不存在)。

**规则**:涉及具体技术细节(参数名、API 签名、字段含义),**必须 grep 源码或 web_search 确认**。说"据我理解"是不专业的。

### 5.2 测试断言不能假设"VPS 静止"

历史失误:架构师建议测试脚本断言"启动后 brutal_sockets = 0"。

**规则**:生产 VPS 上 systemd / haproxy / 系统服务持续创建 TCP 连接。`sleep 4` 后 brutal_sockets > 0 是正常的。**断言"什么都没发生"在生产环境几乎不成立**。

### 5.3 BPF 修复必须 VPS 实测

dev VM 没 BTF → 跑不了 verifier → 修复有效性**只能信用户 VPS 反馈**。

**规则**:每次 BPF 改动 → 推 binary → 用户测 → 反馈 → 决定下一步。**dev VM 编译通过 ≠ 修复成功**。

### 5.4 verifier 撞坑层层剥洋葱

每次撞坑可能暴露下一个问题。**每次停下汇报,不要乱猜乱改**。

**规则**:
- 撞 verifier → 完整粘贴 dmesg 给架构师
- 等架构师判断
- 改一处,推一次,测一次
- 不 silently 切方案

### 5.5 binary md5 是真理来源

历史失误:架构师靠记忆判断 binary 版本,**记错了**。

**规则**:涉及 binary 行为问题,**先 `md5sum accel`,核对 GitHub commit message 里的 md5,确认版本对**,再讨论代码。

### 5.6 不要假设主机字节序

BPF map 读写必须用 `to_ne_bytes` / `from_ne_bytes` 显式声明。不要假设 native = little-endian。

### 5.7 BPF struct_ops 写 sock 字段在不同内核版本行为不同

具体例子:`sk->sk_pacing_status = SK_PACING_NEEDED` 在 v6.12 verifier 接受但运行时静默截断 init。

**规则**:写 sock 字段的代码,有 Plan A → B → C 预案,**优先依赖 kernel 自动行为**(brutal 在 cong_control 设 sk_pacing_rate,kernel 自动 promote pacing_status)。

### 5.8 算法常量代码审计验证,不在 VPS 跑动态测试

例子:`MIN_ACK_RATE_PERCENT = 80`。**只要源码里 grep 到这一行,就证明算法行为对**。VPS 用 tc netem 模拟丢包测试**风险大**(影响 SSH、影响所有出网),**不值得**。

### 5.9 系统 bpftool 版本和 libbpf 不同步

VPS 系统 bpftool 装的版本可能落后 libbpf-rs 内嵌的 libbpf。例如 Debian 12 backports
的 bpftool v7.1 用的是 libbpf 1.1,**不认识 `.struct_ops.link` ELF section**(libbpf 1.2+ 才支持)。
直接 `bpftool struct_ops register file.bpf.o` 会静默 skip 这个 section 然后报 -ENOTSUPP,
verifier 一条指令都没跑过。

**规则**:
- 测 struct_ops verifier 不要走系统 bpftool,走 accel binary(内嵌 libbpf-rs 0.26.2 / libbpf 1.4+)
- 看到 `processed 0 insns` 配合 `skipping unrecognized data section .struct_ops.link` 立即想到这是工具版本问题,不是 BPF 代码问题

### 5.10 BPF 对象名字 16 字节限制(含 NUL)

内核 `BPF_OBJ_NAME_LEN = 16` 包含末尾 null 终止符,**实际可用 15 字符**。源码里 16 字符的名字会被
kernel 截断,bpftool 输出的也是截断后的名字。例如:

  `smart_link_state` (16 chars) → kernel 存 `smart_link_stat` (15 chars)
  `smart_dup_config` (16 chars) → kernel 存 `smart_dup_confi`

**规则**:写 bpftool 解析脚本时,匹配 ≤ 14 字符的前缀(如 `smart_link_sta`),覆盖
"截断 + 完整"两种形态。否则 grep 完整名永远找不到 → 误判 reuse_fd 失败。

### 5.11 veth 零 RTT 环境扭曲 LOSSY 分类

D6 集成测试用 netns + veth,baseline RTT ≈ 50µs。施加 5% 丢包时,任何包丢失会触发
TCP RTO(最小 200ms),srtt 飙到 ~100ms。`srtt/min_rtt = 100ms / 50µs ≈ 2000×`,远超
50% 阈值 → 直接被分类成 CONGEST,**绕过 LOSSY**。

**规则**:LOSSY 状态在 veth 环境天然测不出来,需要真链路(100ms+ baseline RTT)。
D6 的 LOSSY 分支验证只是测试基础设施完整性,真实 LOSSY 分类必须在 D7 真业务环境观察。

### 5.12 LOSSY 不能用 reno 加法增长

D6 实测:GOOD→LOSSY 切换后,reno 加法 (`cwnd += acked_sacked / cwnd ≈ +1/RTT`) 太慢,
cwnd 从初始低位爬升需要几分钟。期间吞吐暴跌(8 Gbps → 49 Mbps)。

**规则**:LOSSY 分支用 BDP 估算 + 100% pacing。LOSSY 和 CONGEST 都用 BDP,但区别:
- LOSSY:`cwnd = BDP`(可升可降,跟随带宽);pacing = 100% bw
- CONGEST:`cwnd = min(cwnd, BDP)`(只降不升,主动让路);pacing = 50% drain → 90% cruise

### 5.13 编译期 + 运行期双重保护强制新算法做对的事

2.5-D7 后修 bug 时引入的范式: 给所有算法一个公共头文件
`ebpf/algorithms/accel_common.h`,声明一个公共 BPF map (`accel_skip_config`)
+ 内联函数 (`should_skip()`)。每个 BPF .c 文件 `#include` 它,每个
`LoadedXxx` 实现 `set_skip()` 方法,`cli.rs` 启动时 match 所有变体调一遍。

新算法忘了 include `accel_common.h`:
- 它的 skel.maps 没有 `accel_skip_config` 字段
- `LoadedXxx::set_skip()` 引用这个字段 → **rustc 编译报错**(根本不到运行)
- 即使 unsafe 绕过编译,运行期 cli.rs 调用 set_skip 失败 → bail → accel 不启动

把"忘记"从"silent loss of protection"变成"accel 直接无法启动"。
**适用范式**: 任何"所有算法都必须做的事"(类似公共安全策略)。

### 5.14 preflight 检查只覆盖硬故障,不做完整 doctor

环境检查机制设计权衡过(2.5-D7 阶段):全功能 `./accel doctor` 子命令是过度设计 ——
低发现率(用户记不住有这个命令)+ 维护成本(独立检查路径要和实际启动同步)+
代码量(200-300 行)。最终方案:`run_server()` 第一行调内联 `preflight()`,只检查
两个硬故障(内核 ≥ 6.4 + BTF 存在),失败 bail 中文修复提示。30 行实现。

**规则**:UX 改进要满足"高发现率 × 高使用频率 × 短代码"。不满足任意一项就考虑"是不是过度设计"。

---

## 6. 已知项目特征(非 bug)

### 6.1 内核 socket pinning

`./accel stop` 后 `bpftool struct_ops show` 可能仍看到 `accel_brutal` / `accel_cubic`,这是内核保护使用中的 TCP socket。等连接关闭后内核自动 GC。**这是正确行为,文档化在 README §12.5**。

### 6.2 IPv6 sysctl 不存在

Linux 内核没有独立 `/proc/sys/net/ipv6/tcp_congestion_control`。`net.ipv4.tcp_congestion_control` 同时控制 IPv4 + IPv6。accel 启动日志显示 `(ipv4)` 是对的,不是 bug。

### 6.3 SSH 断会让 accel 死

accel 收 SIGHUP 死掉(2.3 未处理 systemd 集成)。建议 `nohup ./accel &` + `disown`,或等 2.4 加 systemd unit。

---

## 7. 项目阶段历史

| 阶段 | 内容 | 关键 commit |
|---|---|---|
| **v0.1** | AF_XDP + smoltcp 探索(失败,放弃)| - |
| **v0.2 重构** | 决定走 eBPF struct_ops 路线 | - |
| **2.1** | accel_cubic 基线 + Bug 1/2 | main `adaf625` / binary `acc28784...` |
| **2.2 BBR** | 探索后放弃(用户洞察:用户可直接 sysctl bbr,不值得做)| WIP `7133987`(历史保留) |
| **2.3 brutal** | 自写 BPF struct_ops,5 轮 verifier 撞坑修复 | main `78b7680` / binary `f14594ac...` |
| **2.5 smart** | 自适应算法 + tc-bpf 多倍发包,D1-D7 完成 | claude/accel-smart 分支 |
| **2.6+** | **未启动**,等 2.5 真业务流量反馈 | - |

### 2.5 smart 阶段细分

| D 阶段 | 内容 | 关键 commit |
|---|---|---|
| D1 | accel_smart.bpf.c (struct_ops, 92B priv, 5 callbacks, 4 maps) | `abdfc56` |
| D2 | minimal load_smart() for verifier validation | `b32f763`(path A) |
| D3 | accel_smart_dup.bpf.c (tc/egress duplicator) | `6906207` |
| D4 | LoadedSmart full API + dup skel + reuse_fd + TcHook | `87f999c` |
| D5 | cli/status/health wire-up + SmartSavedCfg | `74831d5` |
| D6 | netns + veth + netem 集成测试 (PARTIAL: LOSSY 在 veth 测不出) | binaries `1fffd4d` |
| LOSSY 升级 | reno → BDP+pacing(D6 暴露的问题) | `ed36e3e` |
| D7 | preflight + acc.conf.example + 文档 + 部署脚本 | `0aec35f` |
| socket fix | client 自动探测 /run/accel/accel.sock | `efb8ba8` |
| skip_local | 内网/回环连接绕过限速 (accel_common.h 范式) | (本次 commit) |

### 2.5 smart 算法核心思路

3 状态自适应:
- **GOOD**(干净链路): brutal 行为(rate × cwnd_gain × 80% ack-rate clamp)
- **LOSSY**(噪音性丢包): BDP 估算 + 100% pacing + tc-bpf 多倍发包补偿
- **CONGEST**(真拥塞): BDP 收敛(只降不升)+ 50% drain pacing → 90% cruise pacing

分类信号:
- `loss_ewma_bp`(EWMA α=1/8 over 5 秒窗口聚合 acked/losses)
- `srtt/min_rtt` 比例(RTT 膨胀)
- 200ms 最小驻留(滞后区防抖)
- 双信号交叉:单个极强信号(loss ≥ 15% 或 RTT 膨胀 ≥ 50%)→ CONGEST

---

## 8. 验收脚本(binaries 分支)

### 2.3 brutal 验收 — `verify-2.3.sh`(7 场景全 PASS)

- A:brutal 加载 + Plan A pacing_status 验证
- B:brutal_sockets 计数准确性
- C:brutal 多连接 + 90s 清理
- D:algo switch 热切换
- E:切到内核 bbr + health 不误报
- F:stop 时 sysctl 恢复
- G:cubic 回归

### 2.5 smart 验收 — 5 个递进脚本(D2 → D6 全 PASS)

- `verify-smart-d2.sh`: 启动后 accel_smart 出现在 loaded 列表(verifier 接受)
- `verify-smart-d4.sh`: smart_dup 程序进 kernel + smart_link_state map count=1(reuse_fd 生效)
- `verify-smart-d5.sh`: 端到端接通 — 配置验证 + tc filter 真挂上 egress + status 输出
- `verify-smart-d6.sh`: netns + veth + netem 三状态测试(LOSSY 在 veth 测不出,见 §5.11)
- `d7-monitor.sh`: D7 部署 + 长跑监控(真业务流量,3 个时间点抓 status 快照)

---

## 9. 当前阻塞 / 下一步

**无阻塞**。当前(2.5-D7)等用户实际跨境业务流量反馈:
- `./accel status` 中 smart state 分布是否合理(GOOD 主导,LOSSY 偶现,CONGEST 罕见)
- `accel-incidents.log` 有无异常增长
- 业务体感(SSH / haproxy / nginx / v2ray)是否比 brutal 更顺(尤其丢包高峰期)
- `d7-monitor.sh` 跑 5 分钟 / 1 小时 / 24 小时三个快照

可能的 2.6 方向(优先级待定):
1. AI 调节接口(`smart_config_map` 已暴露给用户态,运行时可写)
2. systemd unit / 自动启动
3. status 输出补充(per-state cwnd / pacing 平均)
4. 多接口 tc-bpf 支持(当前只支持单 interface)

---

## 10. 不做的事(明确禁止,直到用户特别要求)

- ❌ 不实现"按连接数动态分配总带宽"(越权)
- ❌ 不展示不准的数据(send rate / loss / total sent / rtt avg)
- ❌ 不暴露 cwnd_gain 给用户(算法常量)
- ❌ 不暴露 80% 阈值(算法常量)
- ❌ 不实现"系统挑算法"降级(失败就 bail)
- ❌ 不在 D4 之前推 binary
- ❌ 不为通过 verifier 砍掉算法核心语义
- ❌ 不假设主机字节序
- ❌ 不为支持"用户运行时加载 .bpf.o"扩展
- ❌ 不写"推荐 default = X"之类引导(配置必填)
- ❌ 不引入 setsockopt path 给 brutal(2.3 简化为全局,未来再加)

---

## 11. 怎么开始新对话

### 新 Claude(架构师角色)会话

1. 读这份 PROJECT_CONTEXT.md
2. 读 README.md(项目细节)
3. 读最近的 git log(`git log --oneline -20`)看最近工作
4. 用户给具体任务/问题
5. **不要立刻动手**,先确认你理解了 5 条核心原则
6. 涉及架构决策 → 询问用户拍板
7. 涉及实施 → 出设计 → 用户审 → Claude Code 实现

### 新 Claude Code 会话

1. 读这份 PROJECT_CONTEXT.md
2. 读 ebpf/algorithms/VENDOR.md
3. 读 src/ 主要文件了解代码结构
4. 等架构师指令(用户转发架构师消息)
5. 撞坑停下汇报,**不自作主张**
6. 涉及生产 binary,先验证 md5

---

## 12. 联系

- 项目仓库:https://github.com/123hehehe321/accel
- 用户用 web 版 Claude.ai 沟通(没有本地开发环境)
- Claude Code 在用户提供的 dev VM 上工作

---

**最后更新**:2026-04-25(2.3 收官)

**下次更新触发**:2.4 启动 / 重大架构变更 / 核心原则调整
