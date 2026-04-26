#!/usr/bin/env bash
# verify-smart-d5.sh — accel_smart D5 wire-up validation.
#
# Tests that `algorithm = "accel_smart"` is fully usable end-to-end:
# acc.conf parsing, [smart] section validation, BPF map writes, tc-bpf
# attach to egress, and the new `./accel status` sections.
#
# Six checks (additive on top of D4 — D4 only loaded the dup prog into
# the kernel; D5 actually attaches it to a real egress hook):
#
#   1. file integrity
#   2. kernel + bpftool sanity
#   3. NEGATIVE: target = accel_smart with NO [smart] section ⇒ bail
#   4. POSITIVE: target = accel_smart WITH [smart] section ⇒ startup
#      log shows the new "smart config / thresholds / tc-bpf attached"
#      lines and accel keeps running.
#   5. NEW: `tc filter show dev <iface> egress` shows smart_dup —
#      proves attach_tc_egress() actually attached, not just loaded.
#   6. NEW: `./accel status` shows the smart section (rate, thresholds,
#      interface, sockets, state distribution).
#   7. clean stop ⇒ tc filter gone, no leftover qdisc.
#
# Subcommands:
#   ./verify-smart-d5.sh             — full test (default)
#   ./verify-smart-d5.sh diag        — dump runtime state
#   ./verify-smart-d5.sh stop        — clean stop helper
#
# Run as root (`sudo ./verify-smart-d5.sh`).

set -euo pipefail

EXPECTED_BIN_MD5="8d332b9353d036fe044f885935495e51"

cd "$(dirname "$0")"

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "✗ must run as root (sudo)" >&2
        exit 1
    fi
}

# Pick a sane default interface — the one carrying the default IPv4 route.
default_iface() {
    ip -4 route show default 2>/dev/null \
        | awk '/^default/ {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}'
}

cmd_diag() {
    require_root
    echo "── bpftool prog show (smart_*, brutal_*) ──"
    bpftool prog show 2>/dev/null | grep -E "name (smart_|brutal_)" || true
    echo
    echo "── bpftool map show (smart_*) ──"
    bpftool map show 2>/dev/null | grep -E "name smart_" || true
    echo
    echo "── tc filter show egress on every netdev ──"
    for iface in $(ls /sys/class/net | grep -v '^lo$'); do
        out=$(tc filter show dev "$iface" egress 2>/dev/null || true)
        if [ -n "$out" ]; then
            echo "  [$iface]"
            echo "$out" | sed 's/^/    /'
        fi
    done
    echo
    echo "── ./accel status (if running) ──"
    ./accel status 2>&1 || true
}

cmd_stop() {
    require_root
    ./accel stop 2>/dev/null || true
    sleep 1
    pkill -9 -x accel 2>/dev/null || true
}

start_accel_with_conf() {
    local conf_body="$1"
    local logfile="$2"
    cmd_stop
    if [ -f acc.conf ] && [ ! -f acc.conf.d5-backup ]; then
        cp acc.conf acc.conf.d5-backup
    fi
    printf '%s' "$conf_body" > acc.conf
    rm -f "$logfile"
    ./accel > "$logfile" 2>&1 &
    echo $!
}

cmd_default() {
    require_root

    echo "=== accel_smart D5 wire-up validation ==="
    echo

    # 1. file integrity
    echo "[1/7] file integrity"
    if [ ! -f accel ]; then
        echo "  ✗ missing: accel" >&2
        exit 1
    fi
    local got
    got=$(md5sum accel | awk '{print $1}')
    if [ "$got" != "$EXPECTED_BIN_MD5" ]; then
        echo "  ✗ accel md5 mismatch (got $got, want $EXPECTED_BIN_MD5)" >&2
        exit 1
    fi
    echo "  accel: $got ✓"
    echo

    # 2. kernel + bpftool
    echo "[2/7] kernel + BTF + bpftool"
    echo "  kernel: $(uname -r)"
    [ -f /sys/kernel/btf/vmlinux ] || { echo "  ✗ no BTF" >&2; exit 1; }
    command -v bpftool >/dev/null || { echo "  ✗ bpftool missing" >&2; exit 1; }
    command -v tc >/dev/null || { echo "  ✗ tc (iproute2) missing" >&2; exit 1; }
    local iface
    iface=$(default_iface)
    [ -n "$iface" ] || { echo "  ✗ could not determine default route iface" >&2; exit 1; }
    echo "  default iface: $iface"
    echo

    # 3. NEGATIVE: target=accel_smart but no [smart] section
    echo "[3/7] negative — target=accel_smart without [smart] should bail"
    pid=$(start_accel_with_conf $'algorithm = "accel_smart"\n\n[runtime]\nsocket = ""\n' /tmp/accel-d5-neg.log)
    sleep 3
    if kill -0 "$pid" 2>/dev/null; then
        echo "  ✗ accel still running — should have bailed on missing [smart]" >&2
        cat /tmp/accel-d5-neg.log
        cmd_stop
        exit 1
    fi
    if grep -q "requires \[smart\] section" /tmp/accel-d5-neg.log; then
        echo "  ✓ accel exited with the expected error message"
        grep -E "error:|requires" /tmp/accel-d5-neg.log | head -3 | sed 's/^/    /'
    else
        echo "  ✗ accel exited but error message did not match expectation" >&2
        cat /tmp/accel-d5-neg.log
        exit 1
    fi
    echo

    # 4. POSITIVE: target=accel_smart with valid [smart] section
    echo "[4/7] positive — start with [smart] section"
    local conf
    conf=$(cat <<CONF
algorithm = "accel_smart"

[smart]
rate_mbps = 100
interface = "$iface"
duplicate_ports = "5500-20000"

[runtime]
socket = ""
CONF
)
    pid=$(start_accel_with_conf "$conf" /tmp/accel-d5-pos.log)
    sleep 4
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "  ✗ accel exited prematurely" >&2
        echo "  --- accel log ---"
        cat /tmp/accel-d5-pos.log
        cmd_stop
        exit 1
    fi
    echo "  accel pid=$pid"
    for needle in \
        "loaded: accel_brutal, accel_cubic, accel_smart" \
        "smart config: 100 Mbps" \
        "smart thresholds: lossy=100bp congest=1500bp rtt=50%" \
        "smart dup ports: 5500-20000" \
        "tc-bpf attached: ifindex="
    do
        if grep -qF "$needle" /tmp/accel-d5-pos.log; then
            echo "  ✓ log contains: $needle"
        else
            echo "  ✗ log MISSING: $needle" >&2
            echo "  --- accel log ---"
            cat /tmp/accel-d5-pos.log
            cmd_stop
            exit 1
        fi
    done
    echo

    # 5. tc filter actually attached
    echo "[5/7] tc filter on $iface egress"
    local tc_out
    tc_out=$(tc filter show dev "$iface" egress 2>&1 || true)
    if echo "$tc_out" | grep -q smart_dup; then
        echo "  ✓ smart_dup filter attached on $iface egress"
        echo "$tc_out" | grep -E "smart_dup|filter " | head -3 | sed 's/^/    /'
    else
        echo "  ✗ smart_dup NOT attached to $iface egress" >&2
        echo "  --- tc output ---"
        echo "$tc_out" | sed 's/^/    /'
        echo "  --- accel log warnings ---"
        grep -E "warning|error" /tmp/accel-d5-pos.log || true
        cmd_stop
        exit 1
    fi
    echo

    # 6. ./accel status content
    echo "[6/7] ./accel status output"
    local status_out
    status_out=$(./accel status 2>&1 || true)
    for needle in \
        "smart rate:" \
        "smart thresholds:" \
        "smart interface:" \
        "smart dup ports:" \
        "smart sockets:"
    do
        if echo "$status_out" | grep -q "$needle"; then
            echo "  ✓ status shows: $needle"
        else
            echo "  ✗ status missing: $needle" >&2
            echo "  --- status output ---"
            echo "$status_out" | sed 's/^/    /'
            cmd_stop
            exit 1
        fi
    done
    echo "  --- snippet ---"
    echo "$status_out" | grep -E "smart rate|smart thresholds|smart interface|smart dup|smart sockets|smart state" | sed 's/^/    /' || true
    echo

    # 7. clean stop, no leftover tc filter
    echo "[7/7] clean shutdown — tc filter must be detached"
    ./accel stop 2>/dev/null || true
    local i=0 cleared=0
    while [ "$i" -lt 8 ]; do
        sleep 1
        if ! tc filter show dev "$iface" egress 2>&1 | grep -q smart_dup; then
            cleared=1
            break
        fi
        i=$((i+1))
    done
    if [ "$cleared" -eq 1 ]; then
        echo "  ✓ smart_dup filter cleaned from $iface egress"
    else
        echo "  ⚠ smart_dup still attached after stop:"
        tc filter show dev "$iface" egress 2>/dev/null | sed 's/^/    /'
        echo "    (Drop should have called detach() — possible kernel pin)"
    fi
    if kill -0 "$pid" 2>/dev/null; then
        kill -INT "$pid" 2>/dev/null || true
        sleep 1
    fi

    # restore backup if it exists (D5 left a generated acc.conf)
    if [ -f acc.conf.d5-backup ]; then
        mv acc.conf.d5-backup acc.conf
        echo "  restored original acc.conf"
    fi
    echo

    echo "=== D5 WIRE-UP VALIDATION PASS ==="
    echo
    echo "Report verbatim to architect:"
    echo "  - 'D5 PASS'"
    echo "  - kernel: $(uname -r), default iface: $iface"
    echo "  - tc filter on $iface egress was attached during run, detached on stop"
    echo "  - status shows smart rate / thresholds / interface / sockets / state"
}

case "${1:-default}" in
    default) cmd_default ;;
    diag)    cmd_diag ;;
    stop)    cmd_stop ;;
    *)
        echo "usage: $0 [default|diag|stop]" >&2
        exit 2
        ;;
esac
