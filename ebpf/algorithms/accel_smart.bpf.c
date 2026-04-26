// SPDX-License-Identifier: GPL-2.0

/* accel_smart — adaptive TCP congestion control (struct_ops half).
 *
 * Implements design 2.5-accel_smart-design.md v2.1 §4. Three link states
 * (GOOD / LOSSY / CONGEST) are inferred per-socket each ACK from a 5-second
 * pkt_info window plus an EWMA, and behaviour is dispatched accordingly:
 *
 *   GOOD    — brutal-style rate clamp (cwnd & pacing from cfg->rate).
 *   LOSSY   — additive-increase reno; tc-bpf egress (companion .bpf.c)
 *             handles redundancy. Pacing left to kernel default.
 *   CONGEST — BDP-converged cwnd + 2-RTT drain at 50% pacing + 90% cruise.
 *
 * The 5-second pkt_info slot layout, the unrolled-loop slot lookup pattern,
 * the use of __sync_fetch_and_{add,sub} for atomic counter maps, and the
 * "no direct sk_pacing_status write" rule are all carried over verbatim
 * from accel_brutal.bpf.c (see commits f0ada51 / 0edf01b / f17cf5d / 0ea3869
 * for the verifier history they earned).
 *
 * Companion file accel_smart_dup.bpf.c (D3, tc-bpf egress) reads the global
 * smart_link_state map written here and clones LOSSY-state TCP packets.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* ─── Constants ───────────────────────────────────────────────────────── */

/* Re-stated #defines (not in BTF dump). */
#define TCP_INFINITE_SSTHRESH 0x7fffffff
#define ICSK_CA_PRIV_SIZE     (13 * sizeof(__u64))

#define USEC_PER_MSEC 1000UL
#define USEC_PER_SEC  1000000UL
#define MSEC_PER_SEC  1000UL

/* brutal-borrowed window + clamp constants. cwnd_gain/MIN_ACK_RATE_PERCENT
 * keep the GOOD path bit-identical to accel_brutal. */
#define INIT_CWND_GAIN        20  /* 2.0× */
#define MIN_CWND              4
#define PKT_INFO_SLOTS        5
#define MIN_PKT_INFO_SAMPLES  50
#define MIN_ACK_RATE_PERCENT  80

/* HZ assumed 1000 (Debian 12/13 default). 200ms = 200 jiffies. */
#define SMART_HZ              1000
#define MIN_DWELL_JIFFIES     200

/* Link states — also keys into smart_state_count map. */
#define LINK_GOOD     0
#define LINK_LOSSY    1
#define LINK_CONGEST  2

/* min/max helpers. */
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define max_t(t, a, b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))

/* ─── Per-socket private state (lives in icsk_ca_priv) ────────────────── */

struct brutal_pkt_info {
	__u64 sec;
	__u32 acked;
	__u32 losses;
};

struct smart_priv {
	struct brutal_pkt_info slots[PKT_INFO_SLOTS]; /* 80 bytes */
	__u32 loss_ewma_bp;   /* loss rate EWMA, basis points (1bp = 0.01%) */
	__u32 state;          /* LINK_GOOD / LINK_LOSSY / LINK_CONGEST */
	__u32 last_change;    /* tcp_jiffies32 of last state transition */
};
/* 80 + 4 + 4 + 4 = 92 bytes ≤ 104 (ICSK_CA_PRIV_SIZE). */
_Static_assert(sizeof(struct smart_priv) <= ICSK_CA_PRIV_SIZE,
	       "smart_priv too large for icsk_ca_priv");

/* ─── BPF maps ────────────────────────────────────────────────────────── */

/* Global link state — written by struct_ops, read by tc-bpf companion. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} smart_link_state SEC(".maps");

/* Userspace-managed tunables. Read every ACK, written by Rust at startup
 * (and by future AI tuning paths — see design §14). */
struct smart_config {
	__u64 rate;            /* byte/sec */
	__u32 loss_lossy_bp;   /* default 100 (1%) */
	__u32 loss_congest_bp; /* default 1500 (15%) */
	__u32 rtt_congest_pct; /* default 50 */
	__u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct smart_config);
} smart_config_map SEC(".maps");

/* +1 in init, -1 in release. status reads. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} smart_socket_count SEC(".maps");

/* Per-state population. keys 0/1/2 = GOOD/LOSSY/CONGEST. status reads. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} smart_state_count SEC(".maps");

/* ─── Helpers ─────────────────────────────────────────────────────────── */

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

/* Mirror of include/net/tcp.h tcp_min_rtt() — a static inline that reads
 * minmax_get(&tp->rtt_min). minmax stores three samples; current min is
 * always s[0].v (microseconds). Not a kfunc, so we inline it ourselves. */
static inline __u32 tcp_min_rtt_us(const struct tcp_sock *tp)
{
	return tp->rtt_min.s[0].v;
}

#define tcp_jiffies32 ((__u32)bpf_jiffies64())

/* ─── Window update (5-second rolling pkt_info, brutal-equivalent) ────── */

static __always_inline void smart_update_window(struct tcp_sock *tp,
						struct smart_priv *p,
						const struct rate_sample *rs)
{
	__u64 sec = tp->tcp_mstamp / USEC_PER_SEC;

	/* Pass 1: bump the slot already holding this sec. */
	int found = 0;
	#pragma unroll
	for (int i = 0; i < PKT_INFO_SLOTS; i++) {
		if (p->slots[i].sec == sec) {
			p->slots[i].acked  += rs->acked_sacked;
			p->slots[i].losses += rs->losses;
			found = 1;
			break;
		}
	}

	/* Pass 2: claim the first expired/empty slot. */
	if (!found) {
		#pragma unroll
		for (int i = 0; i < PKT_INFO_SLOTS; i++) {
			if (p->slots[i].sec + PKT_INFO_SLOTS <= sec ||
			    p->slots[i].sec == 0) {
				p->slots[i].sec    = sec;
				p->slots[i].acked  = rs->acked_sacked;
				p->slots[i].losses = rs->losses;
				break;
			}
		}
	}
}

/* Aggregate the 5-second window into total acked / total losses. */
static __always_inline void smart_aggregate(const struct smart_priv *p,
					    __u64 sec,
					    __u32 *acked_total,
					    __u32 *losses_total)
{
	__u64 min_sec = sec - PKT_INFO_SLOTS;
	__u32 acked = 0, losses = 0;

	#pragma unroll
	for (int i = 0; i < PKT_INFO_SLOTS; i++) {
		if (p->slots[i].sec >= min_sec) {
			acked  += p->slots[i].acked;
			losses += p->slots[i].losses;
		}
	}
	*acked_total  = acked;
	*losses_total = losses;
}

/* EWMA, alpha = 1/8. Sample value is the window-aggregate loss rate in bp. */
static __always_inline void smart_update_ewma(struct smart_priv *p,
					      __u32 acked, __u32 losses)
{
	__u32 total = acked + losses;
	__u32 sample_bp = 0;
	if (total > 0)
		sample_bp = (__u32)((__u64)losses * 10000 / total);
	p->loss_ewma_bp = p->loss_ewma_bp
			- (p->loss_ewma_bp >> 3)
			+ (sample_bp >> 3);
}

/* ─── Classification ──────────────────────────────────────────────────── */

static __always_inline __u32 smart_classify(const struct smart_priv *p,
					    const struct smart_config *cfg,
					    __u32 srtt_us, __u32 min_rtt_us)
{
	/* RTT inflation: srtt / min_rtt − 1, expressed as (ratio × 100). */
	__u32 rtt_ratio = 100;
	if (min_rtt_us > 0)
		rtt_ratio = (__u32)((__u64)srtt_us * 100 / min_rtt_us);

	/* Single strong signal → CONGEST (safety first). */
	if (p->loss_ewma_bp >= cfg->loss_congest_bp)
		return LINK_CONGEST;
	if (rtt_ratio >= 100 + cfg->rtt_congest_pct)
		return LINK_CONGEST;

	/* Lossy but RTT stable → noise-style loss. */
	if (p->loss_ewma_bp >= cfg->loss_lossy_bp &&
	    rtt_ratio < 100 + cfg->rtt_congest_pct)
		return LINK_LOSSY;

	/* Definitely clean: well below LOSSY threshold (hysteresis floor). */
	if (p->loss_ewma_bp < cfg->loss_lossy_bp / 2)
		return LINK_GOOD;

	/* Hysteresis band — keep current state to avoid flapping. */
	return p->state;
}

/* ─── Behaviour: GOOD (brutal) ────────────────────────────────────────── */

/* Same algebra as accel_brutal.bpf.c brutal_update_rate(), but takes the
 * already-aggregated acked/losses (we only walk the window once per ACK)
 * and reads cfg->rate from smart_config_map instead of brutal_rate_config. */
static __always_inline void smart_apply_good(struct sock *sk,
					     struct tcp_sock *tp,
					     __u64 rate,
					     __u32 acked, __u32 losses)
{
	if (rate == 0)
		return;

	__u32 mss = tp->mss_cache;
	if (mss == 0)
		return;

	__u32 rtt_ms = (tp->srtt_us >> 3) / USEC_PER_MSEC;
	if (rtt_ms == 0)
		rtt_ms = 1;

	__u32 ack_rate;
	if (acked + losses < MIN_PKT_INFO_SAMPLES) {
		ack_rate = 100;
	} else {
		ack_rate = acked * 100 / (acked + losses);
		if (ack_rate < MIN_ACK_RATE_PERCENT)
			ack_rate = MIN_ACK_RATE_PERCENT;
	}

	rate = rate * 100 / ack_rate;

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

/* ─── Behaviour: LOSSY (reno-style additive increase) ─────────────────── */

static __always_inline void smart_apply_lossy(struct tcp_sock *tp,
					      const struct rate_sample *rs)
{
	/* No-loss window: cwnd += acked_sacked / cwnd (≈ +1 per RTT).
	 * Loss is left to the kernel's ssthresh / recovery machinery —
	 * we deliberately do not touch cwnd on losses here. tc-bpf egress
	 * compensates by cloning packets at the LOSSY threshold. */
	if (rs->losses == 0 && rs->acked_sacked > 0 && tp->snd_cwnd > 0) {
		__u32 incr = (__u32)rs->acked_sacked / tp->snd_cwnd;
		if (incr < 1)
			incr = 1;
		tp->snd_cwnd = min_t(__u32,
				     tp->snd_cwnd + incr,
				     tp->snd_cwnd_clamp);
	}
	/* Pacing: do not set sk_pacing_rate; let kernel default. */
}

/* ─── Behaviour: CONGEST (BDP convergence + drain + cruise) ───────────── */

static __always_inline void smart_apply_congest(struct sock *sk,
						struct tcp_sock *tp,
						struct smart_priv *p,
						const struct rate_sample *rs)
{
	/* delivery_rate = delivered × mss × 1e6 / interval_us  (byte/s). */
	__u64 bw = 0;
	if (rs->interval_us > 0 && rs->delivered > 0)
		bw = (__u64)rs->delivered * tp->mss_cache * USEC_PER_SEC
			/ (__u64)rs->interval_us;

	__u32 min_rtt = tcp_min_rtt_us(tp);

	if (bw > 0 && min_rtt > 0) {
		/* BDP = bw × min_rtt. cwnd packets = BDP / mss. */
		__u64 bdp = bw * min_rtt / USEC_PER_SEC;
		__u32 mss = tp->mss_cache;
		if (mss == 0)
			mss = 1; /* defensive; shouldn't happen post-handshake */

		__u32 target_cwnd = (__u32)(bdp / mss);
		if (target_cwnd < 4)
			target_cwnd = 4;

		/* Converge downward only — do not grow during congestion. */
		tp->snd_cwnd = min_t(__u32, tp->snd_cwnd, target_cwnd);

		/* Drain phase: first 2 RTTs after entering CONGEST, pace at
		 * 50% to flush the bottleneck queue and let min_rtt recover.
		 * Then cruise at 90%. */
		__u32 since = tcp_jiffies32 - p->last_change;
		__u32 two_rtt_jiffies =
			(__u32)((__u64)min_rtt * 2 * SMART_HZ / USEC_PER_SEC);
		if (two_rtt_jiffies < 2)
			two_rtt_jiffies = 2;

		__u64 pace;
		if (since <= two_rtt_jiffies)
			pace = bw / 2;          /* drain */
		else
			pace = bw * 9 / 10;     /* cruise */

		__u64 max_pace = sk->sk_max_pacing_rate;
		sk->sk_pacing_rate =
			max_pace ? min_t(__u64, pace, max_pace) : pace;
	} else {
		/* No usable delivery sample — fall back to a simple 70% cwnd
		 * cut so we still retreat under congestion. */
		tp->snd_cwnd = max_t(__u32, tp->snd_cwnd * 7 / 10, MIN_CWND);
	}
}

/* ─── struct_ops callbacks ────────────────────────────────────────────── */

SEC("struct_ops")
void BPF_PROG(smart_init, struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct smart_priv *p = inet_csk_ca(sk);

	__builtin_memset(p, 0, sizeof(*p));
	p->state = LINK_GOOD;
	p->last_change = tcp_jiffies32;

	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;

	/* Pacing: as in accel_brutal Plan B — do NOT write sk_pacing_status
	 * directly. The kernel auto-promotes to SK_PACING_NEEDED the first
	 * time cong_control sets sk_pacing_rate (which smart does in
	 * GOOD/CONGEST paths). LOSSY leaves pacing to the kernel default. */

	__u32 zero = 0;
	__u64 *cnt = bpf_map_lookup_elem(&smart_socket_count, &zero);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);

	__u64 *good = bpf_map_lookup_elem(&smart_state_count, &zero);
	if (good)
		__sync_fetch_and_add(good, 1);
}

SEC("struct_ops")
void BPF_PROG(smart_release, struct sock *sk)
{
	struct smart_priv *p = inet_csk_ca(sk);
	__u32 zero = 0;

	__u64 *cnt = bpf_map_lookup_elem(&smart_socket_count, &zero);
	if (cnt && *cnt > 0)
		__sync_fetch_and_sub(cnt, 1);

	__u32 state_key = p->state;
	if (state_key <= LINK_CONGEST) {
		__u64 *sc = bpf_map_lookup_elem(&smart_state_count, &state_key);
		if (sc && *sc > 0)
			__sync_fetch_and_sub(sc, 1);
	}
}

SEC("struct_ops")
__u32 BPF_PROG(smart_main, struct sock *sk, __u32 ack, int flag,
	       const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct smart_priv *p = inet_csk_ca(sk);

	if (rs->delivered < 0 || rs->interval_us <= 0)
		return 0;

	__u32 zero = 0;
	struct smart_config *cfg =
		bpf_map_lookup_elem(&smart_config_map, &zero);
	if (!cfg)
		return 0;

	/* 1. Update the 5-second window. */
	smart_update_window(tp, p, rs);

	/* 2. Aggregate, then update EWMA. */
	__u64 sec = tp->tcp_mstamp / USEC_PER_SEC;
	__u32 acked_total, losses_total;
	smart_aggregate(p, sec, &acked_total, &losses_total);
	smart_update_ewma(p, acked_total, losses_total);

	/* 3. Classify. */
	__u32 srtt_us = tp->srtt_us >> 3;
	__u32 min_rtt = tcp_min_rtt_us(tp);
	__u32 new_state = smart_classify(p, cfg, srtt_us, min_rtt);

	/* 4. Apply minimum-dwell hysteresis (200ms). On transition, swap the
	 *    per-state population counters and update the global link_state
	 *    map (which the tc-bpf companion reads). */
	__u32 now = tcp_jiffies32;
	if (new_state != p->state) {
		__u32 elapsed = now - p->last_change;
		if (elapsed >= MIN_DWELL_JIFFIES) {
			__u32 old_key = p->state;
			__u32 new_key = new_state;

			__u64 *old_sc = bpf_map_lookup_elem(&smart_state_count,
							    &old_key);
			if (old_sc && *old_sc > 0)
				__sync_fetch_and_sub(old_sc, 1);
			__u64 *new_sc = bpf_map_lookup_elem(&smart_state_count,
							    &new_key);
			if (new_sc)
				__sync_fetch_and_add(new_sc, 1);

			p->state = new_state;
			p->last_change = now;

			__u32 *link_state =
				bpf_map_lookup_elem(&smart_link_state, &zero);
			if (link_state)
				*link_state = new_state;
		}
	}

	/* 5. Apply the per-state behaviour. */
	if (p->state == LINK_GOOD) {
		smart_apply_good(sk, tp, cfg->rate, acked_total, losses_total);
	} else if (p->state == LINK_LOSSY) {
		smart_apply_lossy(tp, rs);
	} else { /* LINK_CONGEST */
		smart_apply_congest(sk, tp, p, rs);
	}

	return 0;
}

SEC("struct_ops")
__u32 BPF_PROG(smart_undo_cwnd, struct sock *sk)
{
	/* No retreat — return whatever cwnd we already chose. */
	return tcp_sk(sk)->snd_cwnd;
}

SEC("struct_ops")
__u32 BPF_PROG(smart_ssthresh, struct sock *sk)
{
	return tcp_sk(sk)->snd_ssthresh;
}

/* ─── Integration ─────────────────────────────────────────────────────── */

char _license[] SEC("license") = "GPL";

SEC(".struct_ops.link")
struct tcp_congestion_ops accel_smart = {
	.init         = (void *)smart_init,
	.release      = (void *)smart_release,
	.cong_control = (void *)smart_main,
	.undo_cwnd    = (void *)smart_undo_cwnd,
	.ssthresh     = (void *)smart_ssthresh,
	.name         = "accel_smart",
};
