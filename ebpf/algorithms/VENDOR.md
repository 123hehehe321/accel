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
