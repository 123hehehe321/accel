# accel binaries

这个分支只放编译好的二进制。源代码在 `main` 分支。

## 当前版本:2.1-D4

- **阶段**:2.1 Day 4 — struct_ops 加载 + algo CLI + 完整 status
- **功能**:载入 `accel_cubic`(BPF CUBIC 移植)并设 sysctl;
  支持 `./accel algo list / switch`。
- **加速效果**:等效 CUBIC(就是抄的 CUBIC),**没有加速提升**。
  真实提升要等 2.2(`accel_bbr`)和第三步(`accel_brutal`)。

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
hello accel (v0.2, 2.1-D4)
... 配置摘要 ...
loading accel_cubic into kernel...
  registered as struct_ops: accel_cubic
  kernel sysctl set: tcp_congestion_control=accel_cubic (ipv4+ipv6)
listening on ./accel.sock
press ctrl+c to stop, or run './accel stop' from another terminal.
```

另一个终端:
```bash
./accel status           # 完整状态,含 algorithm 段和 kernel sysctl
./accel algo list        # 已注册 CC 算法 + accel 的 target
./accel algo switch bbr  # 切回内核 bbr (接受任何已注册算法名)
./accel algo switch accel_cubic
./accel stop             # 优雅退出:unregister struct_ops + 清 socket
```

## 验证加速算法真的在用

```bash
# 新建 TCP 连接后查它的 CC 算法
ss -tni | grep -A1 "<任何活动连接>"
# 应该看到 "cubic ..." 或 "accel_cubic" 而不是其他
```
