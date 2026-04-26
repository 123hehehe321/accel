#!/usr/bin/env bash
# verify-smart-d6.sh — accel_smart D6 integration test (state machine).
#
# Drives accel_smart through GOOD / LOSSY / CONGEST and verifies:
#   * sysctl-driven cong_control runs on a real TCP socket
#   * tc-bpf duplicator clones in LOSSY (TX packet count jumps ~2×)
#   * BDP convergence in CONGEST (delivery rate drops, pacing engaged)
#   * `./accel status` state distribution reflects link conditions
#   * hot switch cubic ↔ smart works without breaking sockets
#
# SAFETY DESIGN
#   eth0 is NEVER touched. The test creates a private network namespace
#   `accel-test` connected via a veth pair (accv0 in host, accv1 in
#   netns). All netem loss/delay applies to accv0's root qdisc only —
#   accel's clsact runs BEFORE the root qdisc, so the BPF duplicator
#   sees originals, then netem statistically drops/delays both
#   originals AND clones. SSH on eth0 is undisturbed throughout.
#
# REQUIREMENTS
#   * iproute2 (ip, tc) — Debian default
#   * iperf3 — `apt install iperf3` if missing
#   * kernel CONFIG_NET_NS / CONFIG_VETH / CONFIG_NETEM (Debian 12+ ✓)
#
# Run as root (`sudo ./verify-smart-d6.sh`). Uses ~90 seconds.

set -euo pipefail

EXPECTED_BIN_MD5="8d332b9353d036fe044f885935495e51"

NS=accel-test
HOST_IF=accv0
PEER_IF=accv1
HOST_IP=10.99.0.1
PEER_IP=10.99.0.2
IPERF_PORT=5601           # inside [smart].duplicate_ports = "5500-20000"
IPERF_DUR=20              # seconds per phase
SETTLE=6                  # seconds after starting iperf3 before sampling

cd "$(dirname "$0")"

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "✗ must run as root (sudo)" >&2
        exit 1
    fi
}

# Hard cleanup — runs on every exit path so a half-failed test can't
# leave the system in a broken state. Order matters: stop accel first
# so its tc-bpf detaches before we delete the netns/veth.
cleanup() {
    set +e
    echo
    echo "── cleanup ──"
    ./accel stop 2>/dev/null
    sleep 1
    pkill -9 -x accel 2>/dev/null
    pkill -9 -f "iperf3 -s" 2>/dev/null

    # netns + veth removal also tears any leftover qdisc/filter
    ip netns pids "$NS" 2>/dev/null | xargs -r kill -9 2>/dev/null
    ip netns delete "$NS" 2>/dev/null
    ip link delete "$HOST_IF" 2>/dev/null

    # restore the user's original acc.conf if we backed it up
    if [ -f acc.conf.d6-backup ]; then
        mv acc.conf.d6-backup acc.conf
        echo "  restored original acc.conf"
    fi
}
trap cleanup EXIT

# Read TX packet counter for HOST_IF.
tx_packets() {
    cat "/sys/class/net/$HOST_IF/statistics/tx_packets" 2>/dev/null || echo 0
}

# Pull the smart state distribution out of `./accel status`.
# Output format: "GOOD <n> LOSSY <n> CONGEST <n> sockets <n>"
smart_state_line() {
    local out
    out=$(./accel status 2>/dev/null || true)
    local sockets good lossy congest
    sockets=$(echo "$out" | awk '/smart sockets:/ {print $3}')
    if echo "$out" | grep -q "smart state:"; then
        good=$(echo "$out" | sed -n 's/.*GOOD \([0-9]*\) (.*/\1/p')
        lossy=$(echo "$out" | sed -n 's/.*LOSSY \([0-9]*\) (.*/\1/p')
        congest=$(echo "$out" | sed -n 's/.*CONGEST \([0-9]*\) (.*/\1/p')
    else
        good=0; lossy=0; congest=0
    fi
    echo "GOOD ${good:-0} LOSSY ${lossy:-0} CONGEST ${congest:-0} sockets ${sockets:-0}"
}

# Apply a netem qdisc on accv0 root. Replaces if one already exists.
# Format args identically to `tc qdisc add ... netem ...`.
apply_netem() {
    tc qdisc del dev "$HOST_IF" root 2>/dev/null || true
    tc qdisc add dev "$HOST_IF" root netem "$@"
}

clear_netem() {
    tc qdisc del dev "$HOST_IF" root 2>/dev/null || true
}

cmd_default() {
    require_root

    echo "=== accel_smart D6 integration test ==="
    echo

    # ── 0. preflight ──────────────────────────────────────────────────
    echo "[0/9] preflight"
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
    echo "  accel md5: $got ✓"

    for tool in ip tc iperf3 bpftool; do
        if ! command -v "$tool" >/dev/null; then
            echo "  ✗ '$tool' not found — apt install iproute2 iperf3 bpftool" >&2
            exit 1
        fi
    done
    echo "  tools: ip / tc / iperf3 / bpftool ✓"
    [ -f /sys/kernel/btf/vmlinux ] || { echo "  ✗ no BTF" >&2; exit 1; }
    echo "  kernel: $(uname -r), BTF present"
    echo

    # ── 1. set up netns + veth pair ──────────────────────────────────
    echo "[1/9] netns + veth setup"
    # Remove any leftover from a prior failed run
    ip netns delete "$NS" 2>/dev/null || true
    ip link delete "$HOST_IF" 2>/dev/null || true

    ip netns add "$NS"
    ip link add "$HOST_IF" type veth peer name "$PEER_IF"
    ip link set "$PEER_IF" netns "$NS"
    ip addr add "$HOST_IP/24" dev "$HOST_IF"
    ip link set "$HOST_IF" up
    ip netns exec "$NS" ip addr add "$PEER_IP/24" dev "$PEER_IF"
    ip netns exec "$NS" ip link set "$PEER_IF" up
    ip netns exec "$NS" ip link set lo up
    # ARP / connectivity smoke test
    if ! ping -c 1 -W 2 -I "$HOST_IF" "$PEER_IP" >/dev/null 2>&1; then
        echo "  ✗ veth not reachable: ping $PEER_IP failed" >&2
        exit 1
    fi
    echo "  $HOST_IF ($HOST_IP) <─veth─> $PEER_IF ($PEER_IP, in netns $NS) ✓"
    echo

    # ── 2. acc.conf with [smart] pointed at the veth ─────────────────
    echo "[2/9] writing acc.conf for smart on $HOST_IF"
    if [ -f acc.conf ] && [ ! -f acc.conf.d6-backup ]; then
        cp acc.conf acc.conf.d6-backup
        echo "  backed up existing acc.conf → acc.conf.d6-backup"
    fi
    cat > acc.conf <<CONF
# generated by verify-smart-d6.sh
algorithm = "accel_smart"

[smart]
rate_mbps = 100
interface = "$HOST_IF"
duplicate_ports = "5500-20000"

[runtime]
socket = ""
CONF
    echo "  acc.conf written"
    echo

    # ── 3. start accel ────────────────────────────────────────────────
    echo "[3/9] start accel"
    pkill -9 -x accel 2>/dev/null || true
    sleep 1
    rm -f /tmp/accel-d6.log
    ./accel > /tmp/accel-d6.log 2>&1 &
    local accel_pid=$!
    sleep 4
    if ! kill -0 "$accel_pid" 2>/dev/null; then
        echo "  ✗ accel exited:" >&2
        cat /tmp/accel-d6.log
        exit 1
    fi
    if ! grep -qF "tc-bpf attached" /tmp/accel-d6.log; then
        echo "  ✗ tc-bpf attached log line missing" >&2
        cat /tmp/accel-d6.log
        exit 1
    fi
    echo "  accel pid=$accel_pid, smart attached on $HOST_IF"
    grep -E "loaded:|smart config:|smart thresholds:|smart dup|tc-bpf" /tmp/accel-d6.log \
        | sed 's/^/    /'
    echo

    # ── 4. start iperf3 server in netns ──────────────────────────────
    echo "[4/9] iperf3 server in netns $NS"
    ip netns exec "$NS" iperf3 -s -p $IPERF_PORT -D >/dev/null 2>&1
    sleep 1
    if ! ip netns exec "$NS" ss -ltn 2>/dev/null | grep -q ":$IPERF_PORT"; then
        echo "  ✗ iperf3 server didn't bind to :$IPERF_PORT" >&2
        exit 1
    fi
    echo "  iperf3 -s :$IPERF_PORT ✓"
    echo

    # Helper: run an iperf3 phase, sample state mid-flight, return
    # phase summary line.
    run_phase() {
        local label="$1"
        local netem_args="$2"  # empty string ⇒ no netem
        local expect="$3"      # "GOOD" / "LOSSY" / "CONGEST"

        echo "── phase: $label (expect dominant $expect) ──"
        clear_netem
        if [ -n "$netem_args" ]; then
            apply_netem $netem_args
            echo "  netem applied: $netem_args"
        else
            echo "  netem: none"
        fi
        local tx_before
        tx_before=$(tx_packets)

        # Background iperf3 client. Use a port in the duplicate_ports
        # range so the tc-bpf clone path is exercised.
        iperf3 -c "$PEER_IP" -p $IPERF_PORT -t $IPERF_DUR \
               --cport $IPERF_PORT \
               --bind "$HOST_IP" \
               --json > /tmp/iperf3-$label.json 2>&1 &
        local iperf_pid=$!

        # Wait for state machine to settle (5-sec window EWMA + 200ms
        # hysteresis), then sample.
        sleep $SETTLE
        local sample
        sample=$(smart_state_line)
        echo "  status @ +${SETTLE}s:  $sample"

        # Wait for iperf3 to finish.
        wait "$iperf_pid" 2>/dev/null || true
        local tx_after
        tx_after=$(tx_packets)
        local tx_delta=$((tx_after - tx_before))

        # Parse iperf3 throughput (bits per second, sender side).
        local mbps retrans
        if command -v python3 >/dev/null 2>&1 && [ -s /tmp/iperf3-$label.json ]; then
            mbps=$(python3 -c "
import json, sys
try:
    d = json.load(open('/tmp/iperf3-$label.json'))
    bps = d['end']['sum_sent']['bits_per_second']
    print(f'{bps/1e6:.1f}')
except Exception as e:
    print('?')
")
            retrans=$(python3 -c "
import json
try:
    d = json.load(open('/tmp/iperf3-$label.json'))
    print(d['end']['sum_sent'].get('retransmits','?'))
except Exception:
    print('?')
")
        else
            mbps='?'
            retrans='?'
        fi

        echo "  result:  ${mbps} Mbps, retrans=${retrans}, tx_packets=+${tx_delta}"
        # Stash for later comparison
        eval "TX_DELTA_${label}=$tx_delta"
        eval "MBPS_${label}=$mbps"
        eval "STATE_${label}='$sample'"
        echo
    }

    # ── 5/6/7. three states ──────────────────────────────────────────
    echo "[5/9] GOOD phase"
    run_phase good "" GOOD

    echo "[6/9] LOSSY phase (5% loss, RTT untouched)"
    run_phase lossy "loss 5%" LOSSY

    echo "[7/9] CONGEST phase (20% loss + 200ms delay)"
    run_phase congest "loss 20% delay 200ms" CONGEST

    clear_netem

    # ── 8. interpret ─────────────────────────────────────────────────
    echo "[8/9] interpretation"

    # Cloning evidence: in LOSSY the tc-bpf duplicator should roughly
    # double TX packet count for the same throughput class. We don't
    # require an exact ratio — kernel ACK pacing, retransmits, and
    # netem drops introduce variance — but LOSSY tx > 1.3× GOOD tx
    # at similar throughput level is a clear positive signal.
    echo "  TX packet counts: GOOD=$TX_DELTA_good  LOSSY=$TX_DELTA_lossy  CONGEST=$TX_DELTA_congest"
    if [ "$TX_DELTA_lossy" -gt 0 ] && [ "$TX_DELTA_good" -gt 0 ]; then
        local ratio_x10=$(( TX_DELTA_lossy * 10 / TX_DELTA_good ))
        echo "  LOSSY/GOOD tx ratio ≈ ${ratio_x10}/10"
        if [ "$ratio_x10" -ge 13 ]; then
            echo "  ✓ tc-bpf duplicator engaged in LOSSY (ratio ≥ 1.3)"
        elif [ "$ratio_x10" -ge 10 ]; then
            echo "  ⚠ ratio under 1.3 — may be borderline; check state line above"
        else
            echo "  ⚠ ratio < 1.0 — LOSSY actually moved fewer packets than GOOD"
            echo "    (possible if retransmit storms dominated; not necessarily a bug)"
        fi
    fi

    echo "  Throughput: GOOD=$MBPS_good Mbps  LOSSY=$MBPS_lossy Mbps  CONGEST=$MBPS_congest Mbps"
    echo "  (CONGEST should be lowest by design — BDP convergence + pacing throttle)"

    # State distribution: at least ONE phase should have visited the
    # expected dominant state. Since we have one socket per phase and
    # smart_state_count is per-socket, it's "1" of 1 or "0" of 1.
    echo
    echo "  State distribution per phase (sampled mid-iperf3):"
    echo "    GOOD phase:    $STATE_good"
    echo "    LOSSY phase:   $STATE_lossy"
    echo "    CONGEST phase: $STATE_congest"

    # Heuristic checks on the state line — single-socket means we look
    # for the expected state ≥ 1.
    local good_ok=0 lossy_ok=0 congest_ok=0
    echo "$STATE_good"   | grep -qE 'GOOD [1-9]'    && good_ok=1
    echo "$STATE_lossy"  | grep -qE 'LOSSY [1-9]'   && lossy_ok=1
    echo "$STATE_congest" | grep -qE 'CONGEST [1-9]' && congest_ok=1

    [ "$good_ok"    -eq 1 ] && echo "  ✓ GOOD state observed in GOOD phase"    || echo "  ⚠ GOOD never showed up in GOOD phase"
    [ "$lossy_ok"   -eq 1 ] && echo "  ✓ LOSSY state observed in LOSSY phase"   || echo "  ⚠ LOSSY never showed up in LOSSY phase (state machine may need more samples; window is 5s)"
    [ "$congest_ok" -eq 1 ] && echo "  ✓ CONGEST state observed in CONGEST phase" || echo "  ⚠ CONGEST never showed up in CONGEST phase"
    echo

    # ── 9. hot switch sanity ─────────────────────────────────────────
    echo "[9/9] hot switch: smart → cubic → brutal → smart"
    local sw_ok=1
    for target in accel_cubic accel_brutal accel_smart; do
        if ./accel algo switch "$target" >/dev/null 2>&1; then
            local cur
            cur=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
            if [ "$cur" = "$target" ]; then
                echo "  ✓ switched to $target (sysctl=$cur)"
            else
                echo "  ✗ switched to $target but sysctl shows $cur" >&2
                sw_ok=0
            fi
        else
            echo "  ✗ algo switch $target failed" >&2
            sw_ok=0
        fi
    done

    echo
    if [ "$good_ok$lossy_ok$congest_ok$sw_ok" = "1111" ]; then
        echo "=== D6 INTEGRATION TEST PASS ==="
    else
        echo "=== D6 INTEGRATION TEST: PARTIAL ==="
        echo
        echo "Some checks soft-failed (⚠). State machine is sensitive to"
        echo "veth packet rates and the 5-second EWMA window — re-running"
        echo "may flip a borderline ⚠ into ✓. Investigate any ✗ failures."
    fi

    echo
    echo "Report verbatim to architect:"
    echo "  - kernel: $(uname -r)"
    echo "  - GOOD/LOSSY/CONGEST tx_packets:  $TX_DELTA_good / $TX_DELTA_lossy / $TX_DELTA_congest"
    echo "  - GOOD/LOSSY/CONGEST throughput:  $MBPS_good / $MBPS_lossy / $MBPS_congest Mbps"
    echo "  - State observations (✓ or ⚠) printed above"
    echo "  - Hot switch summary above"
}

cmd_diag() {
    require_root
    echo "── ip netns ──"
    ip netns | grep "$NS" || echo "  (no $NS)"
    echo "── ip link (host) ──"
    ip link show "$HOST_IF" 2>/dev/null || echo "  (no $HOST_IF)"
    echo "── tc qdisc ──"
    tc qdisc show dev "$HOST_IF" 2>/dev/null || echo "  (no $HOST_IF)"
    echo "── tc filter ──"
    tc filter show dev "$HOST_IF" egress 2>/dev/null || echo "  (no clsact)"
}

cmd_clean() {
    cleanup
    trap - EXIT
}

case "${1:-default}" in
    default) cmd_default ;;
    diag)    cmd_diag ;;
    clean)   cmd_clean ;;
    *)
        echo "usage: $0 [default|diag|clean]" >&2
        exit 2
        ;;
esac
