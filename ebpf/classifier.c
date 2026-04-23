// accel - Day 3A: port matching in XDP
//
// For each incoming TCP packet on the attached interface:
//   * parse eth -> ipv4 -> tcp, with early-exit fast paths
//   * look up dst_port in port_map (per-CPU bitmap)
//   * bump a per-CPU counter (0 = accel-match, 1 = pass-through)
//   * return XDP_PASS for now
//
// In stage 2.1 the match branch will change to bpf_redirect_map(&xsks_map ...).
// The xsks_map is declared here already so userspace doesn't need to be
// re-wired when 2.1 lands.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// port_map[port] == 1 means that port is accelerated.
// PERCPU_ARRAY: no cache-line bouncing between CPUs; userspace writes
// the same value on every CPU slot at startup.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 65536);
} port_map SEC(".maps");

// stats[0] = accelerated packets, stats[1] = passed-through packets.
// Total is computed as accel + pass in userspace.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} stats SEC(".maps");

// Declared now, populated in stage 2.1 when AF_XDP sockets come online.
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 64);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_classifier(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // eth header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    // ipv4 header (fixed 20-byte access; options are ignored but the
    // dst-port read below only needs the first 20 bytes of IP anyway).
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    // tcp header, located right after the fixed 20-byte IPv4 part.
    // If the packet uses IP options ip->ihl > 5 we still land in the
    // right place because we index off the real header length.
    struct tcphdr *tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    __u32 dst_port = bpf_ntohs(tcp->dest);
    // dst_port is a u16 ntohs result, always in [0, 65535], but the verifier
    // can't always prove that — the explicit compare makes the array access
    // unambiguously in-bounds.
    if (dst_port >= 65536) return XDP_PASS;

    __u8 *matched = bpf_map_lookup_elem(&port_map, &dst_port);
    __u32 slot;
    if (matched && *matched) {
        slot = 0;  // accel
    } else {
        slot = 1;  // pass
    }
    __u64 *ctr = bpf_map_lookup_elem(&stats, &slot);
    if (ctr) (*ctr)++;  // per-CPU, no atomic needed

    // Day 3A: both branches return XDP_PASS. Stage 2.1 will swap the accel
    // branch for bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0).
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
