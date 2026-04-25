# Vendored eBPF Algorithms

This directory vendors eBPF TCP congestion control algorithms from upstream
Linux sources. Each entry documents exact provenance and the local
modifications applied. These files ship under **GPL-2.0** (required by the
kernel for `struct_ops` programs).

Vendored lines **do not** count against the 2500-line soft warning in
README §2.1; the `cargo clippy -D dead_code` rule applies only to Rust code
and to accel's original C code.


## accel_cubic.bpf.c

- **Source path**: `tools/testing/selftests/bpf/progs/bpf_cubic.c`
- **Source repo**: https://github.com/torvalds/linux
- **Git tag**: `v6.12`
- **Commit SHA**: `adc218676eef25575469234709c2d87185ca223a`
- **Raw URL**: https://raw.githubusercontent.com/torvalds/linux/v6.12/tools/testing/selftests/bpf/progs/bpf_cubic.c
- **Copied on**: 2026-04-24

### Local modifications

1. **Header banner** — added a comment block identifying the vendor source
   and commit, plus a pointer to this file.
2. **Removed** `#include "bpf_tracing_net.h"` (that header is private to the
   kernel's BPF selftests tree and not available outside it).
3. **Added** `#include "vmlinux.h"`, `#include <bpf/bpf_helpers.h>`,
   `#include <bpf/bpf_core_read.h>` to replace what `bpf_tracing_net.h`
   transitively provided.
4. **Inlined** 6 symbols from `bpf_tracing_net.h` (verbatim copy, same
   semantics): `tcp_jiffies32`, `inet_csk`, `inet_csk_ca`, `tcp_sk`,
   `tcp_in_slow_start`, `tcp_is_cwnd_limited`. These are the only symbols
   from that header actually referenced by this file.
5. **Renamed** struct_ops external name: `.name = "bpf_cubic"` → `"accel_cubic"`
   (so it's registered alongside the kernel's built-in `cubic` without
   collision).
6. **Renamed** C struct variable: `struct tcp_congestion_ops cubic = {...}`
   → `accel_cubic = {...}` (matches external name; used by the Rust-side
   skeleton binding).
7. **Changed** `SEC(".struct_ops")` → `SEC(".struct_ops.link")` on the ops
   struct. The `.link` variant supports `attach_struct_ops()` returning a
   libbpf `Link` object; dropping the link unregisters cleanly. The plain
   `.struct_ops` variant does not give us this lifecycle handle.

### Unchanged

- **Algorithm logic** — not one instruction of the CUBIC computation touched.
- **Internal symbol names** — the per-program function names
  (`bpf_cubic_init`, `bpf_cubic_cong_avoid`, ...) and the debug global
  `bpf_cubic_acked_called` are kept so future `diff` against upstream stays
  readable.
- **SPDX line** — kept as upstream `GPL-2.0-only` (compatible with our
  GPL-2.0 declaration).

### Upgrade procedure

When a new Linux release is pinned:

1. `curl -fsSL https://raw.githubusercontent.com/torvalds/linux/<tag>/tools/testing/selftests/bpf/progs/bpf_cubic.c -o /tmp/bpf_cubic.c`
2. `diff` against the current `accel_cubic.bpf.c` after re-applying the
   7 local modifications above.
3. Update this file: new tag, new commit SHA, new copy date, note any
   new upstream changes merged in.
4. Run `cargo build` and the 2.1 verification suite.


## accel_brutal.bpf.c

**Status**: ⚠️ **Not vendored** — there is no upstream tcp-brutal in
Linux. This is a **fresh BPF struct_ops implementation inspired by**
[apernet/tcp-brutal](https://github.com/apernet/tcp-brutal) (kernel
module, GPL-2.0). Algorithm semantics faithfully reproduced; userspace
plumbing replaced with the accel BPF-map global-config style.

- **Reference repo**: https://github.com/apernet/tcp-brutal
- **Reference file**: `brutal.c` (316 lines)
- **Reference version**: tcp-brutal v1.0.2 (master at 2026-04)
- **Wrote on**: 2026-04-25

### Why "inspired by" vs "vendored from"

The algorithm core is small and its public API (per-socket setsockopt
via `TCP_BRUTAL_PARAMS`) doesn't fit the BPF struct_ops model — struct_ops
can't override `sk->sk_prot.setsockopt`. Instead of mechanically
transforming kernel-module C and then unwinding the parts that don't
fit, we wrote a clean BPF version from scratch using upstream as the
algorithm specification.

### Faithful to upstream

- The 5-second packet-info window aggregation
- `MIN_PKT_INFO_SAMPLES = 50` threshold below which `ack_rate = 100`
- **`MIN_ACK_RATE_PERCENT = 80` floor on `ack_rate` — the soul of brutal**
- `INIT_CWND_GAIN = 20` (= 2.0×) cwnd multiplier
- `MIN_CWND = 4` cwnd floor
- `TCP_INFINITE_SSTHRESH` — no slow start
- `undo_cwnd` returns current `snd_cwnd` unchanged ("never retreat")
- cwnd computation order chosen to avoid intermediate u64 overflow
  (per upstream comment at brutal.c:220)

### Deliberately changed for accel architecture

1. **Per-socket setsockopt → global BPF map**. Upstream lets each
   application pick its own bandwidth via `setsockopt(TCP_BRUTAL_PARAMS)`.
   accel exposes one knob (`acc.conf [brutal].rate_mbps`) shared by all
   `accel_brutal` sockets on the host. Per-socket variation can be added
   later if needed; documented as a known limitation in README §12.6.
2. **`cwnd_gain` no longer per-socket**. Upstream lets userspace tune
   it via the same `setsockopt`. accel hardcodes `INIT_CWND_GAIN = 20`
   based on tcp-brutal's recommended default. Not exposed to users.
3. **`cmpxchg(sk->sk_pacing_status, NONE, NEEDED)` → direct write**.
   Same observable effect; verifier-friendlier; safe because BPF
   struct_ops `init` runs in softirq with no concurrent writer for the
   per-socket data. Comment in code explains the reasoning so future
   maintainers don't worry about it.
4. **Added `release` callback**. Upstream has none. accel uses it to
   decrement the global socket-count map (informational, not algorithm).
5. **Underflow-guarded `release`**. Non-atomic `if (*cnt > 0)` before
   `__sync_fetch_and_sub` may race in extreme close storms but trades a
   transient off-by-one for not wrapping u64. Acceptable per design
   ("simple is method") — full atomicity would need a CAS loop the
   verifier may reject.
6. **`PKT_INFO_SLOTS = 5` hardcoded**. Upstream computes it dynamically
   from `ICSK_CA_PRIV_SIZE`, clamped to [3, 5]. We pick the upper bound
   and `_Static_assert` the resulting struct fits.

### Local symbol layout

- File header: SPDX, vendor note pointing here.
- Constants: `INIT_CWND_GAIN` etc., 1:1 from upstream.
- 6 inlined kernel helpers: `min_t`, `max_t`, `inet_csk`, `inet_csk_ca`,
  `tcp_sk`, plus `_Static_assert`.
- 2 BPF maps: `brutal_rate_config`, `brutal_socket_count`.
- 5 struct_ops callbacks: `brutal_init`, `brutal_release`, `brutal_main`,
  `brutal_undo_cwnd`, `brutal_ssthresh`.
- 1 internal helper: `brutal_update_rate` (1:1 port of upstream).
- Final `SEC(".struct_ops.link") struct tcp_congestion_ops accel_brutal`.

### Upgrade procedure

When tcp-brutal upstream changes its algorithm:

1. `curl -fsSL https://raw.githubusercontent.com/apernet/tcp-brutal/<commit>/brutal.c -o /tmp/brutal.c`
2. Diff the algorithm core (`brutal_init`, `brutal_main`, `brutal_update_rate`)
   against `accel_brutal.bpf.c`.
3. Apply changes by hand, preserving the 6 deliberate divergences listed
   above. Do **not** auto-port — the userspace plumbing differs.
4. Update this section with the new reference commit and date.
