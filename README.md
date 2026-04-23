# accel binaries

这个分支只放编译好的二进制。源代码在 `main` 分支。

## 当前版本

- 阶段：第一步完成（eBPF 分流 + 管理接口）
- 功能：端口识别 + 计数，暂无加速效果（2.1+2.2 才真正加速）

## 下载

```bash
curl -LO https://github.com/123hehehe321/accel/raw/binaries/accel
curl -LO https://github.com/123hehehe321/accel/raw/binaries/acc.conf.example
chmod +x accel
mv acc.conf.example acc.conf
vim acc.conf   # 改 interface 和 ports
sudo ./accel
```
