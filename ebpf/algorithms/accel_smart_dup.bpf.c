// SPDX-License-Identifier: GPL-2.0

/* accel_smart_dup — tc clsact egress packet duplicator.
 *
 * Companion BPF program to accel_smart.bpf.c. Reads the global
 * smart_link_state map (written by the struct_ops half on every ACK)
 * and, when the link state is LOSSY, clones each outbound TCP packet
 * matching the configured port range. Cloned packets re-enter the
 * egress path on the same interface, providing redundancy against
 * noise-style packet loss without inflating cwnd (the struct_ops
 * half deliberately runs reno during LOSSY — see design v2.1 §2.3).
 *
 * GOOD / CONGEST states: this program returns TC_ACT_OK without
 * cloning, so the runtime cost is one map lookup per packet.
 *
 * Map sharing with accel_smart.bpf.c works via libbpf-rs reuse_fd():
 * the Rust loader (D4) opens accel_smart_dup's skeleton with the
 * struct_ops side's smart_link_state fd, so both BPF objects see the
 * same global state slot. There is no map pinning involved.
 *
 * D3 scope: this file alone. Rust-side TcHook attach + reuse_fd lands
 * in D4; until then the program builds (libbpf-cargo skeleton emitted
 * in build.rs) but is not loaded into any kernel.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ─── Constants (re-stated here; not in BTF dump) ─────────────────────── */

#define LINK_LOSSY  1
#define TC_ACT_OK   0
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define IPPROTO_TCP 6

/* ─── Maps ────────────────────────────────────────────────────────────── */

/* Shared with accel_smart.bpf.c via reuse_fd at load time. The struct_ops
 * half is the writer; we only read here. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} smart_link_state SEC(".maps");

/* Hard upper bound on packet multiplier: each LOSSY-state TCP packet
 * is sent up to MAX_DUP_FACTOR copies in total (1 = no clone, 2 =
 * original + 1 clone, ..., 8 = original + 7 clones). The BPF clone
 * loop is statically unrolled to MAX_DUP_FACTOR iterations so the
 * verifier sees a fixed instruction count regardless of user setting.
 *
 * 8 is chosen as a sane ceiling: more than 8× quickly saturates the
 * underlying link and triggers real congestion. If you legitimately
 * need more, raise this constant — the cost is just a few extra
 * unrolled BPF instructions. */
#define MAX_DUP_FACTOR 8

/* Duplication parameters. Userspace writes once at startup.
 *   ifindex     — egress interface to clone onto (must be the same
 *                 interface the tc-bpf is attached to).
 *   port_min/max— optional dport filter; 0 disables filtering.
 *   multiplier  — total copies per LOSSY-state TCP packet. Range
 *                 1..=MAX_DUP_FACTOR; 1 disables cloning (degrades
 *                 to a transparent fast path). */
struct dup_config {
	__u32 ifindex;
	__u16 port_min;
	__u16 port_max;
	__u32 multiplier;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dup_config);
} smart_dup_config SEC(".maps");

/* ─── Program ─────────────────────────────────────────────────────────── */

SEC("tc/egress")
int smart_dup(struct __sk_buff *skb)
{
	__u32 zero = 0;

	/* Fast path: only act when the link state is LOSSY. Other states
	 * (GOOD / CONGEST) bail after a single map lookup — typical cost
	 * is well under the budget for tc-bpf hooks (≈5ns / pkt). */
	__u32 *state = bpf_map_lookup_elem(&smart_link_state, &zero);
	if (!state || *state != LINK_LOSSY)
		return TC_ACT_OK;

	struct dup_config *cfg = bpf_map_lookup_elem(&smart_dup_config, &zero);
	if (!cfg || cfg->ifindex == 0)
		return TC_ACT_OK;

	/* Identify L3 + L4 protocol. skb->protocol is filled in by the
	 * stack regardless of whether L2 has been pushed yet, so it's the
	 * correct dispatch for tc/egress. */
	__u16 proto = skb->protocol;
	__u32 ip_hdr_len;

	if (proto == bpf_htons(ETH_P_IP)) {
		/* IPv4 IHL: low 4 bits of the first byte, in 32-bit words. */
		__u8 ihl_byte;
		if (bpf_skb_load_bytes(skb, 0, &ihl_byte, 1) < 0)
			return TC_ACT_OK;
		ip_hdr_len = (ihl_byte & 0x0F) * 4;

		__u8 ip_proto;
		if (bpf_skb_load_bytes(skb, 9, &ip_proto, 1) < 0)
			return TC_ACT_OK;
		if (ip_proto != IPPROTO_TCP)
			return TC_ACT_OK;
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		/* IPv6 fixed-length header. We do NOT walk extension headers
		 * — TCP without extensions is the >99% case and the benefit
		 * of cloning corner-case packets isn't worth the verifier
		 * complexity. */
		ip_hdr_len = 40;
		__u8 next_hdr;
		if (bpf_skb_load_bytes(skb, 6, &next_hdr, 1) < 0)
			return TC_ACT_OK;
		if (next_hdr != IPPROTO_TCP)
			return TC_ACT_OK;
	} else {
		/* Non-IP (ARP / VLAN-tagged on some setups / etc.). */
		return TC_ACT_OK;
	}

	/* Optional dport filter. port_min == 0 disables filtering (clone
	 * all TCP). Otherwise dport must be within [port_min, port_max]. */
	if (cfg->port_min > 0) {
		__u16 dport_be;
		if (bpf_skb_load_bytes(skb, ip_hdr_len + 2, &dport_be, 2) < 0)
			return TC_ACT_OK;
		__u16 dport = bpf_ntohs(dport_be);
		if (dport < cfg->port_min || dport > cfg->port_max)
			return TC_ACT_OK;
	}

	/* Send (multiplier - 1) clones in addition to the original packet.
	 * multiplier == 1: no clones (degenerate fast path; should normally
	 * be disabled by setting smart_link_state away from LOSSY upstream,
	 * but we honour it here for completeness). multiplier == N: original
	 * + (N-1) clones, total N copies on the wire.
	 *
	 * The loop is statically unrolled to MAX_DUP_FACTOR with a constant
	 * upper bound; verifier sees a fixed cost regardless of user-chosen
	 * multiplier. Each `bpf_clone_redirect()` invocation is independent.
	 */
	__u32 m = cfg->multiplier;
	if (m == 0) m = 1;
	if (m > MAX_DUP_FACTOR) m = MAX_DUP_FACTOR;

	#pragma unroll
	for (int i = 1; i < MAX_DUP_FACTOR; i++) {
		if ((__u32)i >= m)
			break;
		bpf_clone_redirect(skb, cfg->ifindex, 0);
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
