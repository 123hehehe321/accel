# accel binaries

这个分支只放编译好的二进制。源代码在 `main` 分支。

## 当前版本:2.1-D6 (glibc 2.34 build)

- **Day 6 bug fix**:之前 `./accel stop` 后 sysctl 停留在 accel_cubic,
  新连接继续选不存在的 accel_cubic。现在启动时 capture 原 sysctl,
  clean shutdown 顺序 restore sysctl → drop Link → drop Skel,
  新连接立即回到原 CC 算法。status 新增 `will restore to: X` 字段。
- **阶段**:2.1 Day 5 — health 自愈 + incident 日志
- **新增(D4 → D5)**:
  * **自动恢复**:外部 `bpftool struct_ops unregister accel_cubic` 后,
    30s 内 health 检测到、自动 reload 并记一条 AlgoRelost。
  * **sysctl 漂移自动回写**:外部 `sysctl tcp_congestion_control=bbr`
    后,30s 内自动改回 target,记一条 SysctlReset。
  * **incident log**:`accel-incidents.log` 追加型文本文件,记录
    Startup/Shutdown/AlgoRelost/SysctlReset/JitDisabled/OomKilled。
    超 500 行自动截断末 250 行。
  * **上次 shutdown 原因**:启动时扫描 log,区分 first run / clean /
    crash(无 shutdown 记录就再 startup)。显示在启动输出和 status。
  * **启动时 OOM 扫描**:读 dmesg,如果发现前一次 accel 被 OOM 杀,
    记 OomKilled 并提醒。
  * **status 新增 reliability 段**:uptime / restarts / last shutdown /
    health check 最后成功时间 / log 路径。
- **加速效果**:仍然等效 CUBIC(就是抄的 CUBIC)。真实提升要等 2.2
  (`accel_bbr`)和第三步(`accel_brutal`)。
- **兼容性**:glibc 2.34 底线,覆盖 Debian 12 (glibc 2.36) / 
  Debian 13 / Ubuntu 22.04+ / 任何 glibc ≥ 2.34 的 x86_64 Linux。

## ⚠️ 内核要求:Linux 6.4+

本版本使用 eBPF `struct_ops.link` API,**需要 Linux 内核 6.4 或更高**,
并且 `CONFIG_DEBUG_INFO_BTF=y`(`/sys/kernel/btf/vmlinux` 必须存在)。

- **Debian 13**:默认内核即可(6.12+) ✅
- **Debian 12**:必须升级到 bookworm-backports(6.7+ 或 6.12):
  ```bash
  sudo sh -c 'echo "deb http://deb.debian.org/debian bookworm-backports main" > /etc/apt/sources.list.d/backports.list'
  sudo apt update
  sudo apt install -t bookworm-backports linux-image-amd64
  sudo reboot
  ```
  升级前直接跑 accel 会立即报 "struct_ops.link requires Linux 6.4+" 退出
  (不会造成任何副作用)。
- **Debian 11**:不推荐 — backports 最高 6.1,不满足。

## 下载

```bash
curl -LO https://github.com/123hehehe321/accel/raw/binaries/accel
curl -LO https://github.com/123hehehe321/accel/raw/binaries/acc.conf.example
chmod +x accel
mv acc.conf.example acc.conf
vim acc.conf     # 看一眼 algorithm.default;默认 accel_cubic,不用改
sudo ./accel
```

启动成功会看到:
```
hello accel (v0.2, 2.1-D5)
... 配置摘要 ...
incident log: ./accel-incidents.log
  kernel:        6.12.x...
  last shutdown: none (first run)  / clean / crash (...)

accel_cubic skeleton embedded (target x86_64, libbpf-rs 0.26.2)
loading accel_cubic into kernel...
  registered as struct_ops: accel_cubic
  kernel sysctl set: tcp_congestion_control=accel_cubic (ipv4+ipv6)
listening on ./accel.sock
press ctrl+c to stop, or run './accel stop' from another terminal.
```

另一个终端:
```bash
./accel status           # 含 reliability 段 (uptime / restarts / ...)
./accel algo list        # 已注册 CC + accel target
./accel algo switch bbr  # 自动被 health 30s 内改回 accel_cubic (记 SysctlReset)
./accel stop             # 优雅退出 + 记 Shutdown{reason=clean}
```

## 2.1 验收清单(VPS 建议跑一遍)

1. 启动 → log 里出现 Startup 行 ✓
2. `./accel status` 显示 reliability 段 ✓
3. `bpftool struct_ops unregister name accel_cubic` → 30s 内 health
   自愈,log 新增 AlgoRelost 行,sysctl 自动回到 accel_cubic ✓
4. `sysctl -w net.ipv4.tcp_congestion_control=bbr` → 30s 内 health
   改回 accel_cubic,log 新增 SysctlReset ✓
5. `./accel stop` 后再启动 → last_shutdown=clean ✓
6. `kill -9` 杀进程再启动 → last_shutdown=crash ✓
7. `./accel algo switch bbr` → 立即切,log 无 AlgoRelost/SysctlReset
   (这是用户主动操作,不是漂移)✓
8. 长时间运行 OK (≥ 1h),内存稳定
```
