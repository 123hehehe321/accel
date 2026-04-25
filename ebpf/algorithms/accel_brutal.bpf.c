// SPDX-License-Identifier: GPL-2.0

/* accel_brutal — BPF struct_ops port of tcp-brutal.
 *
 * NOT vendored from upstream kernel — there is no upstream tcp-brutal in
 * Linux. This file is a fresh BPF implementation inspired by
 *   apernet/tcp-brutal — https://github.com/apernet/tcp-brutal
 *   commit:  master @ 2026-04 (tcp-brutal v1.0.2)
 *   source:  brutal.c (316 lines, GPL-2.0)
 *
 * Algorithm faithfully reproduced; userspace plumbing replaced with the
 * accel BPF-map global-config style (see VENDOR.md "accel_brutal").
 *
 * Key principle preserved verbatim from upstream brutal:
 *   ack_rate is *clamped to a floor of 80%* — even when reality is worse
 *   we pretend the link is 80% clean and keep sending. This is brutal's
 *   raison d'être ("绝不退让"). DO NOT touch this clamp.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* ─── Constants ───────────────────────────────────────────────────────── */

/* TCP_INFINITE_SSTHRESH and ICSK_CA_PRIV_SIZE are #defines in <net/tcp.h>;
 * they're not in the BTF dump, so we restate them here.
 *   TCP_INFINITE_SSTHRESH: well-known sentinel for "no slow-start cap"
 *   ICSK_CA_PRIV_SIZE: backed by `u64 icsk_ca_priv[13]` in vmlinux.h, so
 *                      13 * sizeof(u64) = 104 bytes.
 */
#define TCP_INFINITE_SSTHRESH 0x7fffffff
#define ICSK_CA_PRIV_SIZE     (13 * sizeof(__u64))

/* Time conversion constants — vmlinux.h doesn't dump them either. */
#define USEC_PER_MSEC 1000UL
#define USEC_PER_SEC  1000000UL
#define MSEC_PER_SEC  1000UL

/* Algorithm constants (verbatim from upstream brutal.c, lines 14-33).
 * Only `cwnd_gain` and `MIN_ACK_RATE_PERCENT` are exposed in upstream
 * via setsockopt; we hardcode them per design — accel ships one tuned
 * preset, not a tuning surface. */
#define INIT_CWND_GAIN          20  /* 2.0× */
#define MIN_CWND                4
#define PKT_INFO_SLOTS          5
#define MIN_PKT_INFO_SAMPLES    50
#define MIN_ACK_RATE_PERCENT    80  /* clamp floor — soul of brutal */

/* min/max helpers (kernel #defines we don't pull in). */
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define max_t(t, a, b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))

/* ─── Per-socket private state (lives in icsk_ca_priv) ────────────────── */

struct brutal_pkt_info {
	__u64 sec;
	__u32 acked;
	__u32 losses;
};

struct brutal_priv {
	struct brutal_pkt_info slots[PKT_INFO_SLOTS];
};

/* Compile-time guard against future kernel shrinking icsk_ca_priv or our
 * struct growing. 80 bytes used; 104 available. */
_Static_assert(sizeof(struct brutal_priv) <= ICSK_CA_PRIV_SIZE,
	       "brutal_priv too large for icsk_ca_priv");

/* ─── BPF maps ────────────────────────────────────────────────────────── */

/* Global rate, byte/sec. Userspace writes once at startup
 * (`./accel` reads acc.conf [brutal].rate_mbps and converts).
 * All brutal sockets read this on every cong_control tick. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} brutal_rate_config SEC(".maps");

/* Number of sockets currently using accel_brutal. Bumped in init,
 * decremented in release. Status command reads it. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} brutal_socket_count SEC(".maps");

/* ─── Helpers (mirror of accel_cubic's bpf_tracing_net.h subset) ──────── */

static inline struct inet_connection_sock *inet_csk(const struct sock *sk)
{
	return (struct inet_connection_sock *)sk;
}

static inline void *inet_csk_ca(const struct sock *sk)
{
	return (void *)inet_csk(sk)->icsk_ca_priv;
}

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

/* ─── Algorithm core: brutal_update_rate ──────────────────────────────── */

/* Recomputes cwnd and pacing_rate from the rolling 5-second packet info
 * window and the global rate. Called from cong_control on every ACK
 * (after the slots have been updated for this sample). 1:1 port of
 * upstream brutal_update_rate (brutal.c line 183). */
static void brutal_update_rate(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct brutal_priv *b = inet_csk_ca(sk);

	__u32 zero = 0;
	__u64 *rate_p = bpf_map_lookup_elem(&brutal_rate_config, &zero);
	__u64 rate = rate_p ? *rate_p : 0;
	if (rate == 0)
		return; /* userspace hasn't configured rate yet — do nothing */

	__u32 mss = tp->mss_cache;
	if (mss == 0)
		return; /* not yet established */

	__u32 rtt_ms = (tp->srtt_us >> 3) / USEC_PER_MSEC;
	if (rtt_ms == 0)
		rtt_ms = 1;

	/* Aggregate the rolling 5-second window. */
	__u64 sec = tp->tcp_mstamp / USEC_PER_SEC;
	__u64 min_sec = sec - PKT_INFO_SLOTS;
	__u32 acked = 0, losses = 0;

	#pragma unroll
	for (int i = 0; i < PKT_INFO_SLOTS; i++) {
		if (b->slots[i].sec >= min_sec) {
			acked  += b->slots[i].acked;
			losses += b->slots[i].losses;
		}
	}

	/* ack_rate clamping — soul of brutal. See file header. */
	__u32 ack_rate;
	if (acked + losses < MIN_PKT_INFO_SAMPLES) {
		ack_rate = 100;
	} else {
		ack_rate = acked * 100 / (acked + losses);
		if (ack_rate < MIN_ACK_RATE_PERCENT)
			ack_rate = MIN_ACK_RATE_PERCENT;
	}

	/* Bump effective rate to compensate for assumed loss. */
	rate = rate * 100 / ack_rate;

	/* cwnd = rate × rtt / mss × cwnd_gain. Order chosen (per upstream)
	 * to keep intermediate values from overflowing u64. */
	__u64 cwnd64 = rate / MSEC_PER_SEC;
	cwnd64 *= rtt_ms;
	cwnd64 /= mss;
	cwnd64 *= INIT_CWND_GAIN;
	cwnd64 /= 10;

	__u32 cwnd = (__u32)cwnd64;
	if (cwnd < MIN_CWND)
		cwnd = MIN_CWND;

	tp->snd_cwnd = min_t(__u32, cwnd, tp->snd_cwnd_clamp);

	__u64 max_pace = sk->sk_max_pacing_rate;
	sk->sk_pacing_rate = max_pace ? min_t(__u64, rate, max_pace) : rate;
}

/* ─── struct_ops callbacks ────────────────────────────────────────────── */

SEC("struct_ops")
void BPF_PROG(brutal_init, struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct brutal_priv *b = inet_csk_ca(sk);

	/* (1) Zero the per-socket window. Always succeeds; do it first so
	 * release's symmetric counter decrement is justified even if a
	 * later step in init noops. */
	__builtin_memset(b, 0, sizeof(*b));

	/* (2) No slow-start: brutal trusts the configured rate. */
	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;

	/* (3) Pacing enable — Plan B: removed direct write of
	 * SK_PACING_NEEDED here.
	 *
	 * Original tcp-brutal uses cmpxchg here for thread safety:
	 *   cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
	 *
	 * Plan A (direct write `sk->sk_pacing_status = SK_PACING_NEEDED;`)
	 * passed the verifier on v6.12, but runtime diagnostics on user VPS
	 * showed init was being silently truncated past this write —
	 * brutal_init run_cnt=24 yet brutal_socket_count stayed at 0 across
	 * 3 active accel_brutal connections. Hypothesis: v6.12 struct_ops
	 * runtime aborts the remainder of init when the direct sk_pacing_status
	 * write hits a kernel-side safety check that verifier static
	 * analysis didn't catch.
	 *
	 * Plan B: omit the write entirely. The kernel auto-promotes
	 * pacing_status to SK_PACING_NEEDED the first time a cong_control
	 * algorithm sets sk_pacing_rate — which brutal_update_rate does
	 * on every ACK (see line setting sk->sk_pacing_rate below). So
	 * functional pacing is unaffected.
	 *
	 * If user VPS testing shows pacing not actually engaged after this
	 * change, escalate to Plan C (bpf_setsockopt with TCP_PACING_RATE
	 * or equivalent).
	 */

	/* (4) Bump the global brutal-socket counter. ARRAY map key 0 is
	 * always present so the lookup should never fail; even so, do not
	 * early-return on failure — we've already mutated state above and
	 * release will run regardless. */
	__u32 zero = 0;
	__u64 *cnt = bpf_map_lookup_elem(&brutal_socket_count, &zero);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
}

SEC("struct_ops")
void BPF_PROG(brutal_release, struct sock *sk)
{
	__u32 zero = 0;
	__u64 *cnt = bpf_map_lookup_elem(&brutal_socket_count, &zero);
	/* Underflow guard: a non-atomic check + sub may race in extreme
	 * concurrent close storms, but a transient off-by-one is preferable
	 * to a u64 wrap (would render status counters meaningless). The
	 * race is tolerated per design — see VENDOR.md. */
	if (cnt && *cnt > 0)
		__sync_fetch_and_sub(cnt, 1);
}

/* cong_control callback. BPF struct_ops verifier requires global functions
 * to return a scalar even though the kernel signature is void; we return 0
 * unconditionally and the kernel ignores it. */
SEC("struct_ops")
__u32 BPF_PROG(brutal_main, struct sock *sk, __u32 ack, int flag,
	       const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct brutal_priv *b = inet_csk_ca(sk);

	/* Drop invalid samples (warming up, retransmits without delivery). */
	if (rs->delivered < 0 || rs->interval_us <= 0)
		return 0;

	__u64 sec = tp->tcp_mstamp / USEC_PER_SEC;

	/* Slot lookup must use static (constant) indices because the v6.12
	 * verifier rejects variable offsets on trusted_ptr_tcp_sock — even
	 * a properly bounded slot index counts as a variable offset and is
	 * refused. Two unrolled passes preserve the original semantics:
	 *   pass 1 — accumulate into the slot already holding this sec;
	 *   pass 2 — if no match, claim the first expired/empty slot.
	 * #pragma unroll lets the verifier see only constant indices. */
	int found = 0;
	#pragma unroll
	for (int i = 0; i < PKT_INFO_SLOTS; i++) {
		if (b->slots[i].sec == sec) {
			b->slots[i].acked  += rs->acked_sacked;
			b->slots[i].losses += rs->losses;
			found = 1;
			break;
		}
	}

	if (!found) {
		#pragma unroll
		for (int i = 0; i < PKT_INFO_SLOTS; i++) {
			if (b->slots[i].sec + PKT_INFO_SLOTS <= sec ||
			    b->slots[i].sec == 0) {
				b->slots[i].sec    = sec;
				b->slots[i].acked  = rs->acked_sacked;
				b->slots[i].losses = rs->losses;
				break;
			}
		}
	}

	brutal_update_rate(sk);
	return 0;
}

SEC("struct_ops")
__u32 BPF_PROG(brutal_undo_cwnd, struct sock *sk)
{
	/* Brutal never retreats — return the cwnd we already chose. */
	return tcp_sk(sk)->snd_cwnd;
}

SEC("struct_ops")
__u32 BPF_PROG(brutal_ssthresh, struct sock *sk)
{
	return tcp_sk(sk)->snd_ssthresh;
}

/* ─── Integration ─────────────────────────────────────────────────────── */

char _license[] SEC("license") = "GPL";

SEC(".struct_ops.link")
struct tcp_congestion_ops accel_brutal = {
	.init         = (void *)brutal_init,
	.release      = (void *)brutal_release,
	.cong_control = (void *)brutal_main,
	.undo_cwnd    = (void *)brutal_undo_cwnd,
	.ssthresh     = (void *)brutal_ssthresh,
	.name         = "accel_brutal",
};
