/* SPDX-License-Identifier: GPL-2.0 */

/* accel_common.h — shared infrastructure every accel algorithm pulls in.
 *
 * Two responsibilities:
 *
 *   1. Declare the per-algorithm `accel_skip_config` BPF map. Each
 *      algorithm gets its own copy (single-entry ARRAY, ~1.3 KB);
 *      Rust writes the same content to all of them at startup.
 *
 *   2. Provide `should_skip(sk)` that every algorithm's _init calls
 *      to decide whether this socket should bypass the algorithm
 *      (rate limiting, classification, pacing). Skipped sockets get
 *      kernel-default cong_control behaviour.
 *
 * SCOPE OF MATCHING
 *   * Both sk_daddr AND sk_rcv_saddr are checked against every rule.
 *     If EITHER matches, the connection is skipped. This catches
 *     client-side outbound (daddr is local), server accept sockets
 *     bound to 127.0.0.1 (saddr is local), and intra-host tunnels.
 *   * Both AF_INET and AF_INET6 supported. Rules carry the family
 *     and only match same-family sockets.
 *   * Masks are precomputed in Rust (one network-byte-order address
 *     and one bit-mask per word, both in host byte order on the wire),
 *     so the BPF program does only AND + equality compares — verifier
 *     friendly, no in-BPF conditional shifts.
 *
 * FORCED INCLUSION
 *   Every algorithm MUST `#include "accel_common.h"`. The Rust loader
 *   relies on each algo's skel exposing `accel_skip_config` (compile-
 *   time check via `LoadedXxx::set_skip`), and additionally `cli.rs`
 *   exhaustively matches every `LoadedAlgo` variant. A new algorithm
 *   that forgets the include cannot compile, let alone ship.
 */

#ifndef ACCEL_COMMON_H
#define ACCEL_COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ─── AF constants (not in BTF dump) ─────────────────────────────────── */

#ifndef AF_INET
#define AF_INET   2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/* ─── Skip-rule wire layout ──────────────────────────────────────────── */

#define MAX_SKIP_RULES 32

/* 40 bytes per rule. Layout matches the Rust serializer in
 * `ebpf_loader::write_skip_config()` — DO NOT REORDER without updating
 * both sides. Native byte order (kernel reads in host endianness;
 * we never serialize across machines). */
struct skip_rule {
	__u32 family;     /* AF_INET (2) or AF_INET6 (10) */
	__u32 _pad;
	__u32 addr[4];    /* host-byte-order; v4 only uses addr[0] */
	__u32 mask[4];    /* precomputed from CIDR prefix in Rust */
};

struct accel_skip_cfg {
	__u32 count;                              /* number of valid rules in [] */
	__u32 _pad;
	struct skip_rule rules[MAX_SKIP_RULES];   /* 32 × 40 = 1280 bytes */
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct accel_skip_cfg);
} accel_skip_config SEC(".maps");

/* ─── Match logic ────────────────────────────────────────────────────── */

/* Returns 1 iff `addr_h` (host byte order) falls inside the rule's
 * IPv4 subnet. The rule is assumed to have family == AF_INET. */
static __always_inline int match_v4_addr(__u32 addr_h, const struct skip_rule *r)
{
	return (addr_h & r->mask[0]) == (r->addr[0] & r->mask[0]);
}

/* Returns 1 iff the IPv6 address (4× host-byte-order words) falls
 * inside the rule's subnet. The rule is assumed to have family ==
 * AF_INET6. */
static __always_inline int match_v6_addr(const __u32 addr_h[4],
					 const struct skip_rule *r)
{
	return (addr_h[0] & r->mask[0]) == (r->addr[0] & r->mask[0])
	    && (addr_h[1] & r->mask[1]) == (r->addr[1] & r->mask[1])
	    && (addr_h[2] & r->mask[2]) == (r->addr[2] & r->mask[2])
	    && (addr_h[3] & r->mask[3]) == (r->addr[3] & r->mask[3]);
}

/* Check both daddr and saddr of `sk` against `r`. Returns 1 on hit. */
static __always_inline int rule_hits_socket(struct sock *sk,
					    const struct skip_rule *r)
{
	__u16 family = sk->__sk_common.skc_family;
	if ((__u32)family != r->family)
		return 0;

	if (family == AF_INET) {
		__u32 d = bpf_ntohl(sk->__sk_common.skc_daddr);
		__u32 s = bpf_ntohl(sk->__sk_common.skc_rcv_saddr);
		return match_v4_addr(d, r) || match_v4_addr(s, r);
	}

	if (family == AF_INET6) {
		const __be32 *d_be =
			sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32;
		const __be32 *s_be =
			sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32;
		__u32 d_h[4] = {
			bpf_ntohl(d_be[0]), bpf_ntohl(d_be[1]),
			bpf_ntohl(d_be[2]), bpf_ntohl(d_be[3]),
		};
		__u32 s_h[4] = {
			bpf_ntohl(s_be[0]), bpf_ntohl(s_be[1]),
			bpf_ntohl(s_be[2]), bpf_ntohl(s_be[3]),
		};
		return match_v6_addr(d_h, r) || match_v6_addr(s_h, r);
	}

	return 0;
}

/* The single entry-point each algorithm calls from its _init callback.
 * Returns 1 → caller should set its priv->skip flag and short-circuit
 * all per-ACK work. Returns 0 → algorithm proceeds normally.
 *
 * Iteration is statically unrolled with constant indices because v6.12
 * verifier rejects variable offsets on PTR_TO_MAP_VALUE. The `i >= count`
 * break gives early termination once all real rules have been checked.
 */
static __always_inline int should_skip(struct sock *sk)
{
	__u32 zero = 0;
	struct accel_skip_cfg *cfg =
		bpf_map_lookup_elem(&accel_skip_config, &zero);
	if (!cfg)
		return 0;

	__u32 count = cfg->count;
	if (count > MAX_SKIP_RULES)
		count = MAX_SKIP_RULES; /* defensive bound for verifier */

	#pragma unroll
	for (int i = 0; i < MAX_SKIP_RULES; i++) {
		if ((__u32)i >= count)
			break;
		if (rule_hits_socket(sk, &cfg->rules[i]))
			return 1;
	}
	return 0;
}

#endif /* ACCEL_COMMON_H */
