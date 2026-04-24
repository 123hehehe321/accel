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


## accel_bbr.bpf.c

- **Source path**: `net/ipv4/tcp_bbr.c`
- **Source repo**: https://github.com/torvalds/linux
- **Git tag**: `v6.12`
- **Commit SHA**: `adc218676eef25575469234709c2d87185ca223a`
- **Raw URL**: https://raw.githubusercontent.com/torvalds/linux/v6.12/net/ipv4/tcp_bbr.c
- **Copied on**: 2026-04-24

### Why this port is heavier than accel_cubic

`bpf_cubic.c` lived under `tools/testing/selftests/bpf/progs/` and was
already written in BPF style (`SEC()` decorators, `BPF_PROG()` macro,
`.struct_ops` section). `tcp_bbr.c` is a plain in-tree kernel module and
has to be **converted** to BPF struct_ops form: strip module
registration, decorate callback functions, inline kernel-only helpers.

### Local modifications (mechanical, done at vendor time)

1. **Header banner** — vendor source comment + pointer to this file.
2. **Removed** kernel-module machinery:
   - `#include <linux/module.h>`, `<linux/btf.h>`, `<linux/inet_diag.h>`, …
   - `BTF_KFUNCS_START` … `BTF_KFUNCS_END` block
   - `static int __init bbr_register()` / `bbr_unregister()` / `module_init` / `module_exit`
   - `MODULE_AUTHOR` / `MODULE_LICENSE` / `MODULE_DESCRIPTION`
3. **Replaced** kernel headers with the BPF-side equivalents:
   - `#include "vmlinux.h"`, `<bpf/bpf_helpers.h>`, `<bpf/bpf_tracing.h>`,
     `<bpf/bpf_core_read.h>`.
4. **Inlined** the six socket helpers reused from accel_cubic
   (`tcp_jiffies32`, `inet_csk`, `inet_csk_ca`, `tcp_sk`) plus
   `tcp_snd_cwnd`.
5. **Inlined** three `<linux/win_minmax.h>` helpers BBR needs
   (`minmax_get`, `minmax_reset`, `minmax_running_max` and their
   internal `minmax_subwin_update`). Bodies copied verbatim.
6. **Callback decoration**: every function originally marked
   `__bpf_kfunc static RET name(ARGS)` is rewritten as
   `SEC("struct_ops") RET BPF_PROG(name, ARGS)`. These are the 8 entry
   points that struct_ops binds to: `bbr_init`, `bbr_main`,
   `bbr_sndbuf_expand`, `bbr_undo_cwnd`, `bbr_cwnd_event`,
   `bbr_ssthresh`, `bbr_min_tso_segs`, `bbr_set_state`.
7. **Dropped** `bbr_get_info`: it's a debugging callback that fills a
   userspace-visible `union tcp_cc_info`. Not `__bpf_kfunc` upstream,
   and BPF struct_ops doesn't support it cleanly. Not critical —
   `ss -ti` still works via kernel-generic TCP_INFO.
8. **Replaced** the upstream `static struct tcp_congestion_ops
   tcp_bbr_cong_ops` definition with
   `SEC(".struct_ops.link") struct tcp_congestion_ops accel_bbr`
   (same `.link` semantics as accel_cubic for clean drop-via-Link).
   Set `.name = "accel_bbr"`. Dropped `.flags`, `.owner`, `.get_info`
   fields (kernel-only or not ported).

### Known unresolved at 2.2-D1 (to address in 2.2-D2 verifier爬坑)

The above is mechanical and gets us past the BPF *section* structure,
but the BBR body still references kernel-only helpers that may need
BPF-friendly replacements:
- `READ_ONCE` / `WRITE_ONCE` (6 call sites) — likely stripped to plain reads/writes.
- `do_div` / `div_u64` (3 call sites) — BPF supports u64 division natively.
- `get_random_u32()` (1 call site) — replace with `bpf_get_prandom_u32()`.
- `msecs_to_jiffies()` (1 call site) — convert inline.
- `__read_mostly` — BPF ignores / no-op.
- `sock_owned_by_me` / similar sanity asserts — likely strip.

D2 handles these as verifier & clang errors surface. The list above is
a starting hypothesis, not a fix plan.

### Unchanged

- **Algorithm logic** — every bbr_* function body is byte-for-byte
  upstream. No BBR decision changed.
- **Internal symbol names** — all `bbr_*` function and data symbols
  kept so future `diff` against upstream stays readable.
- **SPDX line** — upstream `GPL-2.0` preserved.

### Upgrade procedure

When a new Linux release is pinned:

1. `curl -fsSL https://raw.githubusercontent.com/torvalds/linux/<tag>/net/ipv4/tcp_bbr.c -o /tmp/tcp_bbr.c`
2. Run `/tmp/2.2-d1/port.py` equivalent (or re-apply the mechanical
   transforms listed above).
3. Rebuild, re-verify on a kernel-6.4+ host.
4. Update this file with the new tag + commit SHA + note any new
   upstream struct_ops callbacks that appeared.
