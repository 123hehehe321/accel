#!/usr/bin/env bash
# verify-smart-d2.sh — accel_smart D2 verifier acceptance test
#
# What this script does:
#   1. Verifies binary + .bpf.o md5 against expected values.
#   2. Registers accel_smart.bpf.o into the kernel via `bpftool struct_ops
#      register`. The kernel BPF verifier runs at register time, so this is
#      the moment we'd hit any verifier rejection (the canonical D2 risk).
#   3. If verifier accepts: confirms accel_smart is visible in
#      tcp_available_congestion_control and dumps the struct_ops.
#   4. If verifier rejects: prints the dmesg slice covering the register
#      attempt (the verifier log lives there).
#
# Why bpftool (not `./accel`):
#   D2 only needs to prove the kernel verifier accepts accel_smart's BPF
#   programs. The accel binary's Rust loader integration for smart lands
#   in D4 — at D1 the binary still ships only `accel_cubic` + `accel_brutal`
#   loaders. So D2 uses bpftool to register the standalone .bpf.o, which
#   exercises exactly the verifier path D4's loader will go through.
#
# Subcommands:
#   ./verify-smart-d2.sh           — full verifier test (default)
#   ./verify-smart-d2.sh dump      — dump registered accel_smart maps/progs
#   ./verify-smart-d2.sh sysctl    — try `sysctl tcp_congestion_control=accel_smart`
#                                    (accel must NOT be running; this is a
#                                    standalone kernel-side check)
#   ./verify-smart-d2.sh clean     — unregister accel_smart and exit
#
# Run as root (`sudo ./verify-smart-d2.sh`).

set -euo pipefail

EXPECTED_BIN_MD5="cf91f3d4ebe1fbb74da502ae45baf1b3"
EXPECTED_OBJ_MD5="b53402bd9e08d16b19265f4b5a81cd63"

cd "$(dirname "$0")"

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "✗ must run as root (sudo)" >&2
        exit 1
    fi
}

check_md5() {
    local file="$1" expected="$2"
    [ -f "$file" ] || { echo "✗ missing: $file" >&2; exit 1; }
    local got
    got=$(md5sum "$file" | awk '{print $1}')
    if [ "$got" != "$expected" ]; then
        echo "✗ $file md5 mismatch" >&2
        echo "    got:      $got" >&2
        echo "    expected: $expected" >&2
        echo "    re-download from binaries branch." >&2
        exit 1
    fi
    echo "  $file: $got ✓"
}

cmd_dump() {
    require_root
    echo "── bpftool struct_ops show (filtered) ──"
    bpftool struct_ops show | grep -E "accel_smart|^[0-9]+: accel_" || {
        echo "  (no accel_smart registered)"
        exit 1
    }
    echo
    echo "── bpftool struct_ops dump name accel_smart ──"
    bpftool struct_ops dump name accel_smart || true
}

cmd_sysctl() {
    require_root
    if pgrep -x accel >/dev/null 2>&1; then
        echo "✗ accel is running — stop it first (./accel stop) so the test" >&2
        echo "  doesn't fight with the daemon over sysctl." >&2
        exit 1
    fi
    local prev
    prev=$(sysctl -n net.ipv4.tcp_congestion_control)
    echo "  current sysctl: $prev"
    echo "  switching to accel_smart…"
    sysctl -w net.ipv4.tcp_congestion_control=accel_smart
    echo "  active: $(sysctl -n net.ipv4.tcp_congestion_control)"
    echo
    echo "  restoring sysctl to: $prev"
    sysctl -w "net.ipv4.tcp_congestion_control=$prev"
}

cmd_clean() {
    require_root
    echo "── unregistering accel_smart ──"
    bpftool struct_ops show | awk '/accel_smart/{print $1}' | tr -d ':' | while read -r id; do
        echo "  unregister id=$id"
        bpftool struct_ops unregister id "$id" || true
    done
    bpftool struct_ops show | grep accel_smart && {
        echo "✗ accel_smart still registered (kernel may be pinning it via active socket)" >&2
        exit 1
    } || echo "  clean ✓"
}

cmd_default() {
    require_root

    echo "=== accel_smart D2 verifier test ==="
    echo

    # 1. file integrity
    echo "[1/5] file integrity"
    check_md5 accel              "$EXPECTED_BIN_MD5"
    check_md5 accel_smart.bpf.o  "$EXPECTED_OBJ_MD5"
    echo

    # 2. kernel sanity
    echo "[2/5] kernel + BTF"
    echo "  kernel: $(uname -r)"
    if [ ! -f /sys/kernel/btf/vmlinux ]; then
        echo "  ✗ no /sys/kernel/btf/vmlinux — CONFIG_DEBUG_INFO_BTF=y missing" >&2
        exit 1
    fi
    echo "  BTF: $(stat -c%s /sys/kernel/btf/vmlinux) bytes ✓"
    if ! command -v bpftool >/dev/null; then
        echo "  ✗ bpftool not found — apt install bpftool linux-tools-generic" >&2
        exit 1
    fi
    echo "  bpftool: $(bpftool version 2>&1 | head -1)"
    echo

    # 3. clean slate
    echo "[3/5] clean slate"
    if bpftool struct_ops show 2>/dev/null | grep -q accel_smart; then
        echo "  prior accel_smart found — unregistering first"
        cmd_clean
    else
        echo "  no prior accel_smart registration"
    fi
    echo

    # 4. register (verifier runs here)
    echo "[4/5] registering accel_smart.bpf.o — kernel verifier runs now"
    # Mark dmesg cursor so we can extract just this attempt's verifier log
    # if it fails. /dev/kmsg has a sequence number; falling back to
    # `dmesg | wc -l` works on systems without sequence access.
    local dmesg_before
    dmesg_before=$(dmesg | wc -l)

    if bpftool struct_ops register accel_smart.bpf.o; then
        echo "  ✓ register returned success"
    else
        rc=$?
        echo
        echo "  ✗ register failed (rc=$rc)" >&2
        echo "  ── dmesg slice (verifier log) ──" >&2
        dmesg | tail -n +"$((dmesg_before+1))" | tail -80
        echo "  ── end ──" >&2
        echo
        echo "  → copy the entire output above and report to architect." >&2
        echo "  → DO NOT modify accel_smart.bpf.c locally; verifier loops are" >&2
        echo "    layered (each fix can reveal the next), per project rule" >&2
        echo "    PROJECT_CONTEXT §5.4." >&2
        exit "$rc"
    fi
    echo

    # 5. confirm
    echo "[5/5] confirming kernel registration"
    if ! bpftool struct_ops show | grep -q accel_smart; then
        echo "  ✗ accel_smart not in 'bpftool struct_ops show'" >&2
        exit 1
    fi
    bpftool struct_ops show | grep accel_smart | sed 's/^/  show: /'

    if grep -qw accel_smart /proc/sys/net/ipv4/tcp_available_congestion_control; then
        echo "  ✓ accel_smart visible in tcp_available_congestion_control"
    else
        echo "  ⚠ accel_smart NOT in tcp_available_congestion_control" >&2
        echo "    (this is unexpected — kernel registered struct_ops but didn't expose CC)" >&2
        exit 1
    fi
    echo

    echo "=== D2 VERIFIER TEST PASS ==="
    echo
    echo "Next steps (optional):"
    echo "  sudo ./verify-smart-d2.sh dump      # inspect registered struct_ops"
    echo "  sudo ./verify-smart-d2.sh sysctl    # try setting tcp CC to accel_smart"
    echo "  sudo ./verify-smart-d2.sh clean     # unregister when done"
    echo
    echo "Report verbatim to architect:"
    echo "  - 'D2 PASS' (or paste the full output above if anything failed)"
    echo "  - 'kernel: $(uname -r)'"
}

case "${1:-default}" in
    default) cmd_default ;;
    dump)    cmd_dump ;;
    sysctl)  cmd_sysctl ;;
    clean)   cmd_clean ;;
    *)
        echo "usage: $0 [default|dump|sysctl|clean]" >&2
        exit 2
        ;;
esac
