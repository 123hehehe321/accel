/* SPDX-License-Identifier: GPL-2.0 */

/* accel_common.h — shared infrastructure every accel algorithm pulls in.
 *
 * Two responsibilities:
 *
 *   1. Declare the per-algorithm `accel_skip_config` BPF map (1 entry,
 *      written once by Rust at startup, read by `should_skip()` on every
 *      socket _init).
 *
 *   2. Provide `is_local_connection()` and `should_skip()` static inlines
 *      so each algorithm's _init can decide whether to opt out of rate
 *      limiting / state tracking for loopback and intranet connections.
 *
 * Forced inclusion: every algorithm MUST `#include "accel_common.h"`.
 * The Rust loader treats a missing `accel_skip_config` map on any
 * algorithm's skeleton as a hard failure (see `ebpf_loader.rs::load_*`)
 * — accel won't start. This makes "I forgot the include" a compile-time
 * (skel field absent → set_skip won't compile) AND runtime-time
 * (load-time bail) error, not a silent loss of protection.
 *
 * Why per-algorithm maps (not one shared via reuse_fd)?
 *   The shared-map pattern (cf. `smart_link_state` between smart and
 *   smart_dup) is overkill here — we only need one writer (Rust at
 *   startup) writing 4 bytes per algorithm. Three independent
 *   single-entry ARRAY maps cost 3×24 bytes total and avoid load-order
 *   coupling.
 */

#ifndef ACCEL_COMMON_H
#define ACCEL_COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ─── Skip-local config ──────────────────────────────────────────────── */

struct accel_skip_cfg {
	__u32 enabled;   /* 1 = skip local connections, 0 = treat them like any other */
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct accel_skip_cfg);
} accel_skip_config SEC(".maps");

/* ─── Address-family + AF constants (not in BTF dump) ────────────────── */

#ifndef AF_INET
#define AF_INET   2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/* ─── IP-range checks ────────────────────────────────────────────────── */

/* Returns 1 if `addr_be` (network byte order, as stored in struct sock)
 * falls inside one of the four "definitely not WAN" IPv4 ranges:
 *   127.0.0.0/8     loopback
 *   10.0.0.0/8      RFC1918 class A
 *   172.16.0.0/12   RFC1918 class B
 *   192.168.0.0/16  RFC1918 class C
 *   169.254.0.0/16  link-local (APIPA)
 *
 * Reasoning for "skip these in rate-limiting algorithms":
 * loopback is already at memory speed and gets nothing from pacing;
 * RFC1918 traffic is nearly always intra-data-center / intra-LAN where
 * the path is much faster and lower-latency than what the algorithm is
 * tuned for, and smart's classifier additionally misreads near-zero
 * min_rtt as CONGEST.
 */
static __always_inline int is_local_v4(__be32 addr_be)
{
	__u32 a = bpf_ntohl(addr_be);

	if ((a & 0xff000000) == 0x7f000000) return 1;  /* 127.0.0.0/8   */
	if ((a & 0xff000000) == 0x0a000000) return 1;  /* 10.0.0.0/8    */
	if ((a & 0xfff00000) == 0xac100000) return 1;  /* 172.16.0.0/12 */
	if ((a & 0xffff0000) == 0xc0a80000) return 1;  /* 192.168.0.0/16 */
	if ((a & 0xffff0000) == 0xa9fe0000) return 1;  /* 169.254.0.0/16 */
	return 0;
}

/* Returns 1 if the IPv6 address (4× __be32 words) falls inside:
 *   ::1/128       loopback
 *   fe80::/10     link-local
 *   fc00::/7      ULA (RFC4193 unique local addresses)
 *
 * IPv6 "carrier-grade NAT"-style transition prefixes (e.g. 64:ff9b::/96)
 * are NOT skipped — they're routed via the ISP and benefit from accel.
 */
static __always_inline int is_local_v6(const __be32 addr32[4])
{
	__u32 w0 = bpf_ntohl(addr32[0]);
	__u32 w1 = bpf_ntohl(addr32[1]);
	__u32 w2 = bpf_ntohl(addr32[2]);
	__u32 w3 = bpf_ntohl(addr32[3]);

	/* ::1 */
	if (w0 == 0 && w1 == 0 && w2 == 0 && w3 == 1) return 1;
	/* fe80::/10 — first 10 bits = 1111111010 = 0xfe80..0xfebf high16 */
	if ((w0 & 0xffc00000) == 0xfe800000) return 1;
	/* fc00::/7 — first 7 bits = 1111110, covers fc00::/8 and fd00::/8 */
	if ((w0 & 0xfe000000) == 0xfc000000) return 1;
	return 0;
}

/* Returns 1 if EITHER endpoint of the connection is local.
 * Both src and dst are checked because a server bound to 127.0.0.1
 * accepting a client from a public IP, or vice versa, should still
 * skip — there's at least one local hop.
 */
static __always_inline int is_local_connection(struct sock *sk)
{
	__u16 family = sk->__sk_common.skc_family;

	if (family == AF_INET) {
		__be32 daddr = sk->__sk_common.skc_daddr;
		__be32 saddr = sk->__sk_common.skc_rcv_saddr;
		return is_local_v4(daddr) || is_local_v4(saddr);
	}

	if (family == AF_INET6) {
		const __be32 *daddr =
			sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32;
		const __be32 *saddr =
			sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32;
		return is_local_v6(daddr) || is_local_v6(saddr);
	}

	/* Other families (AF_UNIX etc.) shouldn't even be running TCP
	 * congestion control, but be defensive: treat as non-local. */
	return 0;
}

/* The single entry-point each algorithm calls from its _init callback.
 * Returns 1 → caller should set its priv->skip flag and skip all per-ACK
 * work; returns 0 → algorithm proceeds normally.
 */
static __always_inline int should_skip(struct sock *sk)
{
	__u32 zero = 0;
	struct accel_skip_cfg *cfg =
		bpf_map_lookup_elem(&accel_skip_config, &zero);
	if (!cfg || !cfg->enabled)
		return 0;
	return is_local_connection(sk);
}

#endif /* ACCEL_COMMON_H */
