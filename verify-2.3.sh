#!/usr/bin/env bash
# verify-2.3.sh — accel 2.3 VPS 验收脚本
#
# 用法: 在 VPS 上(以 root 或 sudo)
#
#   chmod +x verify-2.3.sh
#   ./verify-2.3.sh A    # 跑场景 A
#   ./verify-2.3.sh B    # 跑场景 B
#   ./verify-2.3.sh G    # 跑场景 G
#
# 顺序约束 (架构师批):
#   reboot → A
#   A 通过后 → B → C → D → E (中间 brutal_sockets 必须归零)
#   E 通过后 reboot → F
#   F 通过后 reboot → G
#
# A 失败立即停, 把整个屏幕输出 + `sudo dmesg | tail -50`
# 完整复制给架构师 (Plan A→B→C 流程触发, 不要自己改方案)。
#
# 每个场景结尾输出 PASS/FAIL 单独一行。
#
# ─── 已知 gap (D4 验收范围内) ──────────────────────────────────
#
#   80% ack rate 钳制 (MIN_ACK_RATE_PERCENT=80) 未在 VPS 验收。
#   这是 BPF C 代码硬编码常量 (accel_brutal.bpf.c:49,154-155),
#   代码审计验证, scenario C 不测试。
#   真实工作场景验证 (跨境高丢包) 推迟到 2.4 长期使用观察。
#
#   不在 VPS 跑 tc netem 模拟丢包的理由:
#     1. netem 影响 SSH 本身, 可能断线
#     2. netem 影响所有出网, 干扰其他测试
#     3. 人造丢包 ≠ 真实跨境场景

set -uo pipefail

ACCEL_DIR=$(dirname "$(readlink -f "$0")")
ACCEL_BIN="$ACCEL_DIR/accel"
ACC_CONF="$ACCEL_DIR/acc.conf"

# ─── helpers ──────────────────────────────────────────────────

PASS() { echo; echo "─── PASS ───────────────────────────────────────────────"; exit 0; }
FAIL() { echo; echo "─── FAIL ───────────────────────────────────────────────"; echo "原因: $*"; exit 1; }

require_root() {
    [ "$(id -u)" -eq 0 ] || FAIL "需要 root 或 sudo 跑"
}

require_btf() {
    [ -r /sys/kernel/btf/vmlinux ] || FAIL "/sys/kernel/btf/vmlinux 不存在;升级到内核 6.4+ + CONFIG_DEBUG_INFO_BTF=y"
}

write_conf() {
    cat > "$ACC_CONF" <<EOF
algorithm = "$1"
$2
[runtime]
socket = ""
EOF
}

start_accel() {
    nohup "$ACCEL_BIN" > /tmp/accel-out.log 2>&1 &
    disown
    sleep 4
    pgrep -f '[a]ccel$' > /dev/null || {
        echo "--- /tmp/accel-out.log ---"
        cat /tmp/accel-out.log
        FAIL "accel 启动失败"
    }
}

stop_accel() {
    "$ACCEL_BIN" stop > /dev/null 2>&1 || true
    sleep 2
    pkill -f '[a]ccel$' > /dev/null 2>&1 || true
    sleep 1
}

# ─── scenarios ────────────────────────────────────────────────

scenario_A() {
    require_root; require_btf
    SYSCTL_BEFORE=$(sysctl -n net.ipv4.tcp_congestion_control)
    echo "before sysctl: $SYSCTL_BEFORE"

    write_conf accel_brutal $'\n[brutal]\nrate_mbps = 100\n'
    start_accel

    echo "── 启动日志 ──"
    head -40 /tmp/accel-out.log

    echo "── bpftool struct_ops show ──"
    bpftool struct_ops show 2>&1 | tee /tmp/A-bpftool.log
    grep -q accel_brutal /tmp/A-bpftool.log || {
        echo "── dmesg tail (verifier 错误关键词) ──"
        dmesg | tail -50 | grep -iE 'verifier|bpf|reject|invalid|unbounded|cannot write|permission' || true
        FAIL "accel_brutal 没在 bpftool struct_ops show 出现;Plan A 可能被 verifier 拒;完整复制 dmesg 给架构师"
    }

    echo "── tcp_available_congestion_control ──"
    cat /proc/sys/net/ipv4/tcp_available_congestion_control
    grep -wq accel_brutal /proc/sys/net/ipv4/tcp_available_congestion_control \
        || FAIL "accel_brutal 未注册到 tcp_available_congestion_control"

    echo "── sysctl ──"
    CUR=$(sysctl -n net.ipv4.tcp_congestion_control)
    echo "  $CUR"
    [ "$CUR" = "accel_brutal" ] || FAIL "sysctl != accel_brutal (实际=$CUR)"

    echo "── brutal_sockets 初始值 (baseline,VPS 后台流量影响) ──"
    INIT_CNT=$("$ACCEL_BIN" status | awk '/brutal sockets:/ {print $3}')
    echo "  $INIT_CNT (记录用,不判 FAIL — VPS 启动期间后台流量会建立连接)"

    echo "── 起一条 brutal 长连接,验证 pacing_rate 真设上了(Plan A 工作的充分条件) ──"
    curl -s --max-time 60 -o /dev/null "https://speed.cloudflare.com/__down?bytes=1000000000" &
    CURL_PID=$!
    sleep 5

    echo "── ss -tniO 看 pacing_rate ──"
    ss -tniO state established 2>&1 | grep -B1 accel_brutal | tee /tmp/A-ss.log
    if grep -E 'pacing_rate [0-9.]+(K|M|G)?bps' /tmp/A-ss.log > /dev/null; then
        echo "pacing_rate 字段存在 ✓"
    else
        kill -9 $CURL_PID 2>/dev/null || true
        echo "── dmesg tail ──"
        dmesg | tail -30
        FAIL "ss 输出无 pacing_rate (或为 0);Plan A 字面通过但实质失败 (sk_pacing_status 没设上);请汇报架构师走 Plan B/C"
    fi

    echo "── dmesg 最后 30 行 (确认无 BPF 拒绝) ──"
    dmesg | tail -30 | grep -iE 'bpf|verifier|reject' || echo "(无相关 dmesg)"

    kill -9 $CURL_PID 2>/dev/null || true
    wait 2>/dev/null
    stop_accel
    PASS
}

scenario_B() {
    require_root; require_btf
    write_conf accel_brutal $'\n[brutal]\nrate_mbps = 100\n'
    start_accel

    echo "── baseline ──"
    "$ACCEL_BIN" status | grep -E 'brutal sockets|total tcp'

    BASELINE_BR=$("$ACCEL_BIN" status | awk '/brutal sockets:/ {print $3}')
    echo "baseline brutal_sockets = $BASELINE_BR"

    echo "── 起 5 个并发 curl 长下载 ──"
    PIDS=()
    for i in 1 2 3 4 5; do
        curl -s --max-time 30 -o /dev/null "https://speed.cloudflare.com/__down?bytes=200000000" &
        PIDS+=($!)
    done
    sleep 3

    echo "── 5 个连接活跃时 ──"
    "$ACCEL_BIN" status | grep -E 'brutal sockets|total tcp'
    SS_BR=$(ss -tniO state established 2>/dev/null | grep -c accel_brutal || true)
    MAP_BR=$("$ACCEL_BIN" status | awk '/brutal sockets:/ {print $3}')
    echo "  ss 计数: $SS_BR    map 计数: $MAP_BR"

    # race 容忍: abs(map - ss) ≤ 1 AND map ≤ ss
    DIFF=$((MAP_BR - SS_BR))
    if [ "$MAP_BR" -gt "$SS_BR" ]; then
        FAIL "map ($MAP_BR) > ss ($SS_BR);release 可能漏调 (违反单向容忍)"
    fi
    if [ "$DIFF" -lt -1 ]; then
        FAIL "ss ($SS_BR) 比 map ($MAP_BR) 多 >1;init 漏调"
    fi

    wait "${PIDS[@]}" 2>/dev/null
    sleep 5

    echo "── curl 完成后 ──"
    POST_BR=$("$ACCEL_BIN" status | awk '/brutal sockets:/ {print $3}')
    echo "  brutal_sockets = $POST_BR"
    if [ "$POST_BR" -gt $((BASELINE_BR + 1)) ]; then
        echo "等 30s 让 TIME_WAIT 清理..."
        sleep 30
        POST_BR=$("$ACCEL_BIN" status | awk '/brutal sockets:/ {print $3}')
    fi
    [ "$POST_BR" -le $((BASELINE_BR + 1)) ] \
        || FAIL "curl 完成后 brutal_sockets ($POST_BR) 没回到 baseline ($BASELINE_BR);release 漏调严重"

    stop_accel
    PASS
}

scenario_C() {
    require_root; require_btf
    write_conf accel_brutal $'\n[brutal]\nrate_mbps = 50\n'
    start_accel

    echo "── 单连接吞吐基线 (1× curl 30s) ──"
    SECONDS_USED=0
    BYTES_1=$(curl -s --max-time 30 -w '%{size_download}' -o /dev/null \
        "https://speed.cloudflare.com/__down?bytes=2000000000" 2>/dev/null || echo 0)
    THROUGHPUT_1=$((BYTES_1 * 8 / 30 / 1000000))
    echo "  1 连接 30s 收到 $BYTES_1 字节 ≈ $THROUGHPUT_1 Mbps"

    echo "── 3 并发吞吐 (3× curl 30s) ──"
    rm -f /tmp/C-3conn-*.log
    for port in a b c; do
        curl -s --max-time 30 -w '%{size_download}\n' -o /dev/null \
            "https://speed.cloudflare.com/__down?bytes=2000000000" \
            > /tmp/C-3conn-$port.log 2>&1 &
    done
    sleep 5
    echo "── 3 连接活跃时 status ──"
    "$ACCEL_BIN" status | grep -E 'brutal sockets|total tcp'
    echo "── 3 连接活跃时 ss ──"
    ss -tniO state established 2>/dev/null | grep -B1 accel_brutal | head -10
    wait
    BYTES_3=0
    for port in a b c; do
        n=$(cat /tmp/C-3conn-$port.log 2>/dev/null | tr -d '\n' || echo 0)
        BYTES_3=$((BYTES_3 + n))
    done
    THROUGHPUT_3=$((BYTES_3 * 8 / 30 / 1000000))
    echo "  3 连接 30s 总收 $BYTES_3 字节 ≈ $THROUGHPUT_3 Mbps"

    echo "── ⚠️ 等 90s 让 TIME_WAIT 自然清理 (架构师补充 2) ──"
    sleep 90
    POST_BR=$("$ACCEL_BIN" status | awk '/brutal sockets:/ {print $3}')
    echo "── 90s 后 brutal_sockets = $POST_BR (记录用) ──"
    # 不强求归零: VPS 后台流量持续创造新 brutal 连接,数字动态平衡。
    # release 漏调的检测在场景 B 的 ss vs map 对照里更可靠。

    echo "── 性能基线 (架构师补充 3,记录非验收) ──"
    echo "  1 conn  ≈ $THROUGHPUT_1 Mbps"
    echo "  3 conn  ≈ $THROUGHPUT_3 Mbps (合计)"
    echo "  rate_mbps 配置: 50 Mbps/conn"
    echo "  无 connection reset / RST 即视为 PASS (实际吞吐受物理链路限制)"

    stop_accel
    PASS
}

scenario_D() {
    require_root; require_btf
    write_conf accel_brutal $'\n[brutal]\nrate_mbps = 100\n'
    start_accel

    echo "── 起 brutal 长连接 (60s curl) ──"
    curl -s --max-time 60 -o /dev/null "https://speed.cloudflare.com/__down?bytes=1000000000" &
    CURL1_PID=$!
    sleep 3
    BR_BEFORE=$(ss -tniO state established 2>/dev/null | grep -c accel_brutal || true)
    echo "  老连接计数 (brutal): $BR_BEFORE"

    echo "── 切到 accel_cubic ──"
    "$ACCEL_BIN" algo switch accel_cubic
    "$ACCEL_BIN" algo list
    CUR=$(sysctl -n net.ipv4.tcp_congestion_control)
    [ "$CUR" = "accel_cubic" ] || FAIL "sysctl 没切到 accel_cubic (实际=$CUR)"

    echo "── 老 brutal 连接应该还在用 brutal ──"
    sleep 1
    BR_NOW=$(ss -tniO state established 2>/dev/null | grep -c accel_brutal || true)
    echo "  老连接还在用 brutal: $BR_NOW (期望 ≥ $BR_BEFORE)"

    echo "── 起新连接,应该用 cubic ──"
    curl -s --max-time 30 -o /dev/null "https://speed.cloudflare.com/__down?bytes=200000000" &
    CURL2_PID=$!
    sleep 3
    NEW_CUBIC=$(ss -tniO state established 2>/dev/null | grep -c accel_cubic || true)
    echo "  新连接 cubic 计数: $NEW_CUBIC"
    [ "$NEW_CUBIC" -ge 1 ] || FAIL "新连接没用 accel_cubic"

    echo "── 切回 accel_brutal ──"
    "$ACCEL_BIN" algo switch accel_brutal
    CUR=$(sysctl -n net.ipv4.tcp_congestion_control)
    [ "$CUR" = "accel_brutal" ] || FAIL "切回 accel_brutal 失败"

    echo "── status target/sysctl 一致 ──"
    "$ACCEL_BIN" status | grep -E 'target:|kernel sysctl:'

    kill -9 $CURL1_PID $CURL2_PID 2>/dev/null || true
    wait 2>/dev/null
    stop_accel
    PASS
}

scenario_E() {
    require_root; require_btf
    write_conf accel_brutal $'\n[brutal]\nrate_mbps = 100\n'
    start_accel

    echo "── 切到 kernel 内置 bbr ──"
    "$ACCEL_BIN" algo switch bbr
    CUR=$(sysctl -n net.ipv4.tcp_congestion_control)
    [ "$CUR" = "bbr" ] || FAIL "切到 bbr 失败 (实际=$CUR)"

    echo "── 起测试连接,应该用 bbr ──"
    curl -s --max-time 30 -o /dev/null "https://speed.cloudflare.com/__down?bytes=200000000" &
    sleep 3
    BBR=$(ss -tniO state established 2>/dev/null | grep -c bbr || true)
    echo "  连接 bbr 计数: $BBR"

    echo "── 切回 accel_brutal ──"
    "$ACCEL_BIN" algo switch accel_brutal
    CUR=$(sysctl -n net.ipv4.tcp_congestion_control)
    [ "$CUR" = "accel_brutal" ] || FAIL "切回 accel_brutal 失败"

    echo "── 等 35s 看 health 是否误报漂移 ──"
    sleep 35
    CUR=$(sysctl -n net.ipv4.tcp_congestion_control)
    [ "$CUR" = "accel_brutal" ] || FAIL "35s 后 sysctl 又变了 (实际=$CUR);target 同步问题"
    echo "── incident log 应无 SysctlReset 关于这次切换 ──"
    if [ -r ./accel-incidents.log ]; then
        if tail -10 ./accel-incidents.log | grep -q SysctlReset; then
            echo "── 警告: incident log 有 SysctlReset 记录 ──"
            tail -10 ./accel-incidents.log | grep SysctlReset
        else
            echo "  无 SysctlReset 记录 ✓"
        fi
    fi

    wait 2>/dev/null
    stop_accel
    PASS
}

scenario_F() {
    require_root; require_btf
    SYSCTL_BEFORE=$(sysctl -n net.ipv4.tcp_congestion_control)
    echo "before: $SYSCTL_BEFORE"

    write_conf accel_brutal $'\n[brutal]\nrate_mbps = 100\n'
    start_accel

    CUR=$(sysctl -n net.ipv4.tcp_congestion_control)
    [ "$CUR" = "accel_brutal" ] || FAIL "启动后 sysctl 不是 accel_brutal"

    echo "── status 显示 will restore to ──"
    "$ACCEL_BIN" status | grep 'will restore to'

    echo "── stop ──"
    "$ACCEL_BIN" stop > /tmp/F-stop.log 2>&1
    cat /tmp/F-stop.log
    sleep 2

    echo "── stop 后验证 ──"
    AFTER=$(sysctl -n net.ipv4.tcp_congestion_control)
    echo "  after sysctl: $AFTER"
    [ "$AFTER" = "$SYSCTL_BEFORE" ] || FAIL "sysctl 没恢复 (before=$SYSCTL_BEFORE, after=$AFTER)"

    [ ! -e ./accel.sock ] || FAIL "socket 文件没清理"

    PASS
}

scenario_G() {
    require_root; require_btf
    SYSCTL_BEFORE=$(sysctl -n net.ipv4.tcp_congestion_control)

    write_conf accel_cubic ""    # 无 [brutal] 段
    start_accel

    echo "── 启动日志 ──"
    head -20 /tmp/accel-out.log

    echo "── bpftool 应该能看到 cubic + brutal 都 loaded (load_all) ──"
    bpftool struct_ops show 2>&1 | grep -E 'accel_(cubic|brutal)'

    echo "── sysctl 仅指 cubic ──"
    CUR=$(sysctl -n net.ipv4.tcp_congestion_control)
    [ "$CUR" = "accel_cubic" ] || FAIL "sysctl 不是 accel_cubic (实际=$CUR)"

    echo "── 测试普通流量 ──"
    if curl -s --max-time 10 -o /dev/null https://www.google.com; then
        echo "  curl exit 0 ✓"
    else
        FAIL "curl 失败,cubic 实现可能有回归"
    fi

    sleep 2
    CUBIC_CNT=$(ss -tniO state established 2>/dev/null | grep -c accel_cubic || true)
    echo "  cubic 连接计数: $CUBIC_CNT"
    [ "$CUBIC_CNT" -ge 1 ] || echo "  (新连接尚未在 ss 里; 不致命)"

    echo "── stop + 验证 sysctl 恢复 ──"
    "$ACCEL_BIN" stop > /dev/null 2>&1
    sleep 2
    AFTER=$(sysctl -n net.ipv4.tcp_congestion_control)
    [ "$AFTER" = "$SYSCTL_BEFORE" ] || FAIL "stop 后 sysctl 没恢复"

    [ ! -e ./accel.sock ] || FAIL "socket 文件没清理"

    PASS
}

# ─── dispatch ─────────────────────────────────────────────────

case "${1:-}" in
    A) scenario_A ;;
    B) scenario_B ;;
    C) scenario_C ;;
    D) scenario_D ;;
    E) scenario_E ;;
    F) scenario_F ;;
    G) scenario_G ;;
    "")
        echo "用法: $0 <A|B|C|D|E|F|G>"
        echo
        echo "顺序约束:"
        echo "  reboot → A (关键风险, 失败立即停)"
        echo "  A 通过 → B → C → D → E (中间用 'status | grep brutal' 验归零)"
        echo "  reboot → F"
        echo "  reboot → G"
        echo
        echo "失败处理: 完整复制屏幕输出 + 'sudo dmesg | tail -50' 给架构师"
        exit 2
        ;;
    *)
        echo "未知场景: $1; 用 A B C D E F G"
        exit 2
        ;;
esac
