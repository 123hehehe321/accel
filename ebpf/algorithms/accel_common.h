/* SPDX-License-Identifier: GPL-2.0 */

/* accel_common.h — shared infrastructure every accel algorithm pulls in.
 *
 * Two responsibilities:
 *
 *   1. Declare two per-algorithm BPF maps of type LPM_TRIE
 *      (Longest-Prefix-Match Trie, BPF's purpose-built data structure
 *      for CIDR matching): `accel_skip_v4` and `accel_skip_v6`.
 *      Rust populates them at startup from the parsed `skip_subnet`.
 *
 *   2. Provide `should_skip(sk)` that every algorithm's _init calls
 *      to decide whether this socket should bypass the algorithm.
 *      Skipped sockets get kernel-default cong_control behaviour.
 *
 * WHY LPM_TRIE INSTEAD OF AN ARRAY + UNROLLED LOOP
 *   The earlier 2.5-D7 design used a 32-entry rule array with an
 *   `#pragma unroll` linear scan inside the BPF program. That has two
 *   structural problems:
 *
 *     * Verifier path explosion. Each unrolled iteration carries an
 *       `if (family == AF_INET) {...} else if (family == AF_INET6) {...}`
 *       branch; verifier must analyse 32 × 2 = 64 path combinations
 *       per call. Whether it fits under the 1M-insn limit depends on
 *       kernel-version-specific pruning behaviour — fragile.
 *     * Hard 32-rule cap and O(n) cost per socket.
 *
 *   LPM_TRIE replaces both: BPF does **two** map lookups (daddr, then
 *   saddr) — verifier sees a fixed-cost helper call. Kernel-side
 *   trie does the longest-prefix match in O(log n). Result:
 *
 *     * Verifier risk: structurally zero. should_skip compiles down
 *       to ~30 BPF insns regardless of how many rules the user
 *       configured.
 *     * Capacity: 256 v4 rules + 256 v6 rules (raise if needed).
 *     * Per-socket cost at runtime: 2 trie lookups instead of a
 *       32-iteration unrolled loop.
 *
 *   This is the pattern Cilium / Calico / production BPF firewalls
 *   use; it's the BPF idiom for "match CIDR against IP".
 *
 * MATCHING SCOPE
 *   Both sk_daddr AND sk_rcv_saddr are checked. If either side
 *   matches any rule (longest prefix wins inside LPM_TRIE), the
 *   connection is skipped.
 *
 * FORCED INCLUSION
 *   Every algorithm MUST `#include "accel_common.h"` so its skel
 *   exposes both `accel_skip_v4` and `accel_skip_v6`. The Rust
 *   loader's per-variant `set_skip()` references these fields by
 *   name; a future algorithm that forgets the include can't compile,
 *   and `cli.rs` further checks via match exhaustiveness over every
 *   `LoadedAlgo` variant.
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

/* ─── LPM_TRIE keys ──────────────────────────────────────────────────── */

/* The kernel LPM_TRIE map type expects a key whose first 4 bytes are a
 * `prefixlen` u32 (host byte order), followed by the address bytes in
 * network byte order (same order they're stored in `struct sock`).
 *
 * The prefixlen tells the trie how many MSBs of the address are the
 * network part. A lookup with prefixlen = 32 (v4) or 128 (v6) and the
 * full host address returns the most-specific stored CIDR that
 * contains that host, or NULL on no match.
 */
struct skip_v4_key {
	__u32  prefixlen;
	__be32 addr;
};

struct skip_v6_key {
	__u32 prefixlen;
	__u8  addr[16];
};

#define ACCEL_SKIP_MAX_V4 256
#define ACCEL_SKIP_MAX_V6 256

/* ─── BPF maps ───────────────────────────────────────────────────────── */

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, ACCEL_SKIP_MAX_V4);
	__type(key, struct skip_v4_key);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC); /* required for LPM_TRIE */
} accel_skip_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, ACCEL_SKIP_MAX_V6);
	__type(key, struct skip_v6_key);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} accel_skip_v6 SEC(".maps");

/* ─── Match logic ────────────────────────────────────────────────────── */

/* The single entry-point each algorithm calls from its _init callback.
 * Returns 1 → caller should set its priv->skip flag and short-circuit
 * all per-ACK work. Returns 0 → algorithm proceeds normally.
 *
 * NO LOOPS. NO UNROLLING. Up to 2 LPM_TRIE lookups (daddr then saddr)
 * per family. Verifier sees fixed-cost helper calls.
 */
static __always_inline int should_skip(struct sock *sk)
{
	__u16 family = sk->__sk_common.skc_family;

	if (family == AF_INET) {
		struct skip_v4_key key = {
			.prefixlen = 32,
			.addr      = sk->__sk_common.skc_daddr,
		};
		if (bpf_map_lookup_elem(&accel_skip_v4, &key))
			return 1;
		key.addr = sk->__sk_common.skc_rcv_saddr;
		if (bpf_map_lookup_elem(&accel_skip_v4, &key))
			return 1;
		return 0;
	}

	if (family == AF_INET6) {
		struct skip_v6_key key = { .prefixlen = 128 };
		__builtin_memcpy(
			key.addr,
			sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8,
			16);
		if (bpf_map_lookup_elem(&accel_skip_v6, &key))
			return 1;
		__builtin_memcpy(
			key.addr,
			sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8,
			16);
		if (bpf_map_lookup_elem(&accel_skip_v6, &key))
			return 1;
		return 0;
	}

	/* Other families (AF_UNIX etc.) shouldn't be running TCP cong
	 * control; defensively treat as non-local. */
	return 0;
}

#endif /* ACCEL_COMMON_H */
