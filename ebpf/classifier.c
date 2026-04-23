// accel - Day 2: minimal XDP classifier
//
// For every incoming packet on the attached interface, emit a debug line
// to the kernel trace_pipe and let the packet through to the normal stack.
//
// Day 3 will add port matching and the XSKMAP redirect for AF_XDP.

#include <linux/bpf.h>

// Minimal inlined helpers so we don't need libbpf-dev installed.
#define SEC(NAME) __attribute__((section(NAME), used))

// bpf_trace_printk: helper id 6. Writes to /sys/kernel/debug/tracing/trace_pipe.
static long (*bpf_trace_printk)(const char *fmt, unsigned int fmt_size, ...) =
    (void *)6;

SEC("xdp")
int xdp_classifier(struct xdp_md *ctx) {
    const char fmt[] = "accel-dbg: pkt len=%d\n";
    int len = (int)(ctx->data_end - ctx->data);
    bpf_trace_printk(fmt, sizeof(fmt), len);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
