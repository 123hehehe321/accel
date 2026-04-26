#!/usr/bin/env bash
# d7-monitor.sh — accel_smart D7 production deployment + observation helper.
#
# This is NOT a pass/fail test. D7 is the long-running phase where smart
# runs on real cross-border business traffic and the operator observes
# how it behaves over time. The script:
#
#   1. Sanity-checks the deploy (binary md5, acc.conf, smart enabled)
#   2. Captures three timepoint snapshots of `./accel status`:
#        T0  immediately after start
#        T1  +5 minutes  (warm-up done, EWMA windows have data)
#        T2  +1 hour     (steady-state)
#      The 24h snapshot is your responsibility — re-invoke `./d7-monitor.sh
#      snapshot` at that point.
#   3. Watches `accel-incidents.log` for new entries between snapshots.
#   4. Provides a quick rollback: `./d7-monitor.sh rollback` switches to
#      brutal (or cubic) and stops accel.
#
# What you should look at after the run:
#   * `connections: smart sockets:` should be a non-trivial fraction of
#     `total tcp:` — if zero, your business traffic isn't going through
#     smart's cong_control (sysctl mismatch, or all connections opened
#     before accel started).
#   * `smart state:` distribution should make sense for your link:
#       cross-border with mild loss     → mostly GOOD, occasional LOSSY
#       lossy/congested cross-border    → meaningful LOSSY share
#       overloaded link                 → recurring CONGEST
#     Constant 100% CONGEST or constant 0% LOSSY is suspicious — feed it
#     back to the architect.
#   * incidents.log: AlgoRelost / SysctlReset are auto-healed (info);
#     anything else (KernelPanic / OomKilled) is a real concern.
#
# Subcommands:
#   ./d7-monitor.sh             — full deploy + 3 snapshots (~65 minutes)
#   ./d7-monitor.sh snapshot    — single status snapshot to stdout
#                                 (run this at +24h from a separate session)
#   ./d7-monitor.sh rollback    — switch sysctl to brutal + stop accel
#   ./d7-monitor.sh diag        — current smart kernel state dump

set -euo pipefail

EXPECTED_BIN_MD5_PLACEHOLDER="__SET_AT_BUILD_TIME__"
# The actual md5 is filled in by the binaries-branch builder. If the file
# `./d7-monitor.expected.md5` exists alongside the script, it overrides.
if [ -f d7-monitor.expected.md5 ]; then
    EXPECTED_BIN_MD5=$(cat d7-monitor.expected.md5)
else
    EXPECTED_BIN_MD5="$EXPECTED_BIN_MD5_PLACEHOLDER"
fi

cd "$(dirname "$0")"
SNAPSHOTS_DIR="./d7-snapshots"

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "✗ run as root (sudo)" >&2
        exit 1
    fi
}

snapshot_now() {
    local label="$1"
    local out="$SNAPSHOTS_DIR/$(date -u +%Y%m%dT%H%M%SZ)-$label.txt"
    mkdir -p "$SNAPSHOTS_DIR"
    {
        echo "=== d7 snapshot: $label ==="
        echo "timestamp:   $(date -u --iso-8601=seconds)"
        echo "kernel:      $(uname -r)"
        echo "uptime:      $(uptime -p)"
        echo
        echo "── ./accel status ──"
        ./accel status 2>&1 || echo "(accel not running)"
        echo
        echo "── /proc/sys/net/ipv4/tcp_congestion_control ──"
        cat /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null || echo "?"
        echo
        echo "── tc filter show ──"
        local iface
        iface=$(awk '/^[smart]/,/^\[/{ if ($1=="interface") {gsub("\"","",$3); print $3; exit} }' acc.conf 2>/dev/null || true)
        if [ -n "$iface" ]; then
            tc filter show dev "$iface" egress 2>/dev/null | sed 's/^/  /' || true
        fi
        echo
        echo "── recent incidents.log ──"
        for p in ./accel-incidents.log /run/accel/accel-incidents.log; do
            if [ -f "$p" ]; then
                tail -20 "$p" 2>/dev/null | sed 's/^/  /'
                break
            fi
        done
    } | tee "$out"
    echo
    echo "saved: $out"
}

cmd_snapshot() {
    require_root
    snapshot_now "manual"
}

cmd_rollback() {
    require_root
    echo "rolling back: smart → brutal (or cubic if brutal not loaded)"
    if ./accel algo switch accel_brutal 2>/dev/null; then
        echo "  switched sysctl to accel_brutal"
    elif ./accel algo switch accel_cubic 2>/dev/null; then
        echo "  switched sysctl to accel_cubic"
    fi
    sleep 1
    echo "stopping accel..."
    ./accel stop 2>/dev/null || pkill -INT -x accel 2>/dev/null || true
    sleep 2
    if pgrep -x accel >/dev/null; then
        echo "  ⚠ accel still running, sending SIGKILL"
        pkill -9 -x accel 2>/dev/null || true
    fi
    echo "  done. sysctl now: $(cat /proc/sys/net/ipv4/tcp_congestion_control)"
}

cmd_diag() {
    require_root
    echo "── ./accel status ──"
    ./accel status 2>&1 | head -40 || true
    echo
    echo "── bpftool prog show (smart_*) ──"
    bpftool prog show 2>/dev/null | grep -E "name (smart_|brutal_)" || echo "  (none)"
    echo
    echo "── bpftool struct_ops show ──"
    bpftool struct_ops show 2>/dev/null | grep accel_ || true
    echo
    local iface
    iface=$(awk '/^[smart]/,/^\[/{ if ($1=="interface") {gsub("\"","",$3); print $3; exit} }' acc.conf 2>/dev/null || true)
    if [ -n "$iface" ]; then
        echo "── tc filter show dev $iface egress ──"
        tc filter show dev "$iface" egress 2>/dev/null | sed 's/^/  /' || echo "  (none)"
    fi
}

cmd_default() {
    require_root

    echo "=== accel_smart D7 deployment + observation ==="
    echo

    # 1. binary sanity
    echo "[1/6] binary sanity"
    if [ ! -f accel ]; then
        echo "  ✗ missing: accel — download from binaries branch first" >&2
        exit 1
    fi
    local got
    got=$(md5sum accel | awk '{print $1}')
    echo "  accel md5: $got"
    if [ "$EXPECTED_BIN_MD5" = "__SET_AT_BUILD_TIME__" ]; then
        echo "  (expected md5 not embedded; can't verify — make sure README md5 matches)"
    elif [ "$got" != "$EXPECTED_BIN_MD5" ]; then
        echo "  ✗ md5 mismatch (expected $EXPECTED_BIN_MD5)" >&2
        exit 1
    else
        echo "  matches expected ✓"
    fi
    echo

    # 2. acc.conf review
    echo "[2/6] acc.conf review"
    if [ ! -f acc.conf ]; then
        echo "  ✗ missing acc.conf — copy from acc.conf.example and edit" >&2
        exit 1
    fi
    local algo
    algo=$(awk -F\" '/^algorithm = / {print $2}' acc.conf)
    echo "  algorithm = \"$algo\""
    if [ "$algo" != "accel_smart" ]; then
        echo "  ⚠ target is not accel_smart — D7 is for smart deployment" >&2
        echo "    (你可能是想监控 brutal? 那就直接跑 ./accel)" >&2
        exit 1
    fi
    if ! grep -q "^\[smart\]" acc.conf; then
        echo "  ✗ acc.conf missing [smart] section" >&2
        exit 1
    fi
    local rate iface ports
    rate=$(awk '/^\[smart\]/,/^\[/{ if ($1=="rate_mbps") print $3 }' acc.conf | head -1)
    iface=$(awk -F\" '/^\[smart\]/,/^\[/{ if ($1 ~ /^interface/) print $2 }' acc.conf | head -1)
    ports=$(awk -F\" '/^\[smart\]/,/^\[/{ if ($1 ~ /^duplicate_ports/) print $2 }' acc.conf | head -1)
    echo "  rate_mbps         = ${rate:-?}"
    echo "  interface         = ${iface:-?}"
    echo "  duplicate_ports   = ${ports:-(empty = all TCP)}"
    if [ -z "$iface" ]; then
        echo "  ✗ [smart].interface unset (will fail at startup)" >&2
        exit 1
    fi
    if ! ip link show "$iface" >/dev/null 2>&1; then
        echo "  ✗ interface $iface does not exist (run \`ip link\` to find your real iface)" >&2
        exit 1
    fi
    if [ -z "$ports" ]; then
        echo "  ⚠ duplicate_ports is empty — LOSSY state will clone EVERY TCP packet"
        echo "    (including SSH; safe in degraded sense, but wastes BW; consider filling)"
    fi
    echo

    # 3. start (or confirm running)
    echo "[3/6] starting accel"
    if pgrep -x accel >/dev/null; then
        echo "  accel already running (pid=$(pgrep -x accel))"
    else
        nohup ./accel >./accel-d7.log 2>&1 &
        disown
        sleep 4
        if ! pgrep -x accel >/dev/null; then
            echo "  ✗ accel failed to start. log:" >&2
            cat ./accel-d7.log
            exit 1
        fi
        echo "  accel pid=$(pgrep -x accel), log: ./accel-d7.log"
    fi
    echo

    # 4. T0 snapshot
    echo "[4/6] T0 snapshot (immediately after start)"
    sleep 1
    snapshot_now "T0-startup"
    echo

    # 5. T1 (+5 minutes) snapshot
    echo "[5/6] waiting 5 minutes for warm-up, then T1 snapshot"
    echo "  (you can ctrl+c here and resume manual snapshots later)"
    sleep 300
    snapshot_now "T1-5min"
    echo

    # 6. T2 (+1 hour) snapshot
    echo "[6/6] waiting 55 minutes more for steady-state, then T2 snapshot"
    sleep 3300
    snapshot_now "T2-1hour"
    echo

    echo "=== D7 immediate observations done ==="
    echo
    echo "Next:"
    echo "  * Re-run ./d7-monitor.sh snapshot at +24h from any session"
    echo "  * If anything is off, ./d7-monitor.sh rollback restores brutal/cubic"
    echo "  * Snapshots saved in $SNAPSHOTS_DIR/"
    echo
    echo "Report verbatim to architect:"
    echo "  - 'D7 deploy ok, monitoring T0/T1/T2 captured'"
    echo "  - paste contents of $SNAPSHOTS_DIR/*-T2-1hour.txt (smart state line + connections)"
    echo "  - paste any unfamiliar incidents.log entries"
}

case "${1:-default}" in
    default)  cmd_default ;;
    snapshot) cmd_snapshot ;;
    rollback) cmd_rollback ;;
    diag)     cmd_diag ;;
    *)
        echo "usage: $0 [default|snapshot|rollback|diag]" >&2
        exit 2
        ;;
esac
