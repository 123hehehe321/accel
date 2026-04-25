# PROJECT_CONTEXT.md — accel 项目入口文档

**所有新对话(Claude / Claude Code / 任何 AI 协作者)开始前必读**。

---

## 1. 项目当前状态(2026-04-25)

- **版本**:v0.2 / 2.3 收官
- **main 收尾 commit**:`78b7680`
- **binaries 收尾 commit**:`7617cf8`
- **binary md5**:`f14594ac59d737df516a0dd32dacf8b3`
- **代码量**:2450 行 / 2500 预算(98%,健康)
- **支持算法**:`accel_cubic`(基线) + `accel_brutal`(激进)
- **下一阶段**:**2.4 未启动,等用户实际使用反馈**

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
| **2.4+** | **未启动**,等用户实际使用反馈 | - |

---

## 8. 2.3 验收(7 场景,全 PASS)

`verify-2.3.sh` 在 binaries 分支,7 场景:

- A:brutal 加载 + Plan A pacing_status 验证
- B:brutal_sockets 计数准确性
- C:brutal 多连接 + 90s 清理
- D:algo switch 热切换
- E:切到内核 bbr + health 不误报
- F:stop 时 sysctl 恢复
- G:cubic 回归

---

## 9. 当前阻塞 / 下一步

**无阻塞**。当前等用户实际使用反馈。

可能的 2.4 方向(优先级待定):
1. 真实性能验证(iperf3 + 跨境数据)
2. AI 调节接口(brutal_rate_config 动态调节)
3. 系统集成(systemd unit / 自动启动)
4. 用户体验(status 输出 / config validation)

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
