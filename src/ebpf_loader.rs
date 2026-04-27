//! eBPF struct_ops loader registry.
//!
//! 2.3-D3 generalises the loader from a single `load_accel_cubic()` to a
//! per-algorithm registry pattern. `all_loaders()` returns a static
//! slice of (name, loader_fn); `load_all()` calls every loader,
//! collecting successes into a HashMap keyed by name. A single loader's
//! failure (verifier rejection, kernel-too-old, etc.) does NOT abort
//! the others — each algorithm is independent.
//!
//! Adding a new algorithm requires five edits:
//!
//! 1. drop a new `.bpf.c` file under `ebpf/algorithms/`,
//! 2. add it to ALGORITHMS in build.rs,
//! 3. add a `mod xxx_skel { include!(...); }` block here,
//! 4. add a `LoadedAlgo::Xxx(LoadedXxx { ... })` variant + load_xxx fn,
//! 5. add a row to `all_loaders()`.
//!
//! The rest of the daemon (cli, health, status) needs no changes.

use std::collections::HashMap;
use std::mem::MaybeUninit;

use anyhow::{anyhow, bail, Context, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{Link, MapCore, MapFlags, OpenObject};

#[allow(dead_code, unused_imports, clippy::all)]
mod accel_cubic_skel {
    include!(concat!(env!("OUT_DIR"), "/accel_cubic.skel.rs"));
}

#[allow(dead_code, unused_imports, clippy::all)]
mod accel_brutal_skel {
    include!(concat!(env!("OUT_DIR"), "/accel_brutal.skel.rs"));
}

#[allow(dead_code, unused_imports, clippy::all)]
mod accel_smart_skel {
    include!(concat!(env!("OUT_DIR"), "/accel_smart.skel.rs"));
}

#[allow(dead_code, unused_imports, clippy::all)]
mod accel_smart_dup_skel {
    include!(concat!(env!("OUT_DIR"), "/accel_smart_dup.skel.rs"));
}

use accel_brutal_skel::{AccelBrutalSkel, AccelBrutalSkelBuilder};
use accel_cubic_skel::{AccelCubicSkel, AccelCubicSkelBuilder};
use accel_smart_dup_skel::{AccelSmartDupSkel, AccelSmartDupSkelBuilder};
use accel_smart_skel::{AccelSmartSkel, AccelSmartSkelBuilder};

/// Per-algorithm Skel + Link bundle for the cubic baseline. Dropping it
/// unregisters the struct_ops via Link::drop; closing all map fds via
/// Skel::drop. Field declaration order matters — `_link` drops first
/// (unregister), then `_skel` (close fds).
///
/// Algorithm name is the HashMap key in `state.algos`; not stored here
/// to avoid duplication.
pub struct LoadedCubic {
    _link: Link,
    skel: AccelCubicSkel<'static>,
}

impl LoadedCubic {
    /// Write the skip-local flag into the algorithm's `accel_skip_config`
    /// BPF map. Cubic doesn't actually rate-limit so this has no
    /// behavioural effect, but the method must exist (and the map must
    /// be present in the skeleton) — `cli::run_server` calls
    /// `set_skip()` on every variant of `LoadedAlgo`, exhaustively. A
    /// future algorithm that forgets `#include "accel_common.h"` won't
    /// have the map, won't compile here, and accel won't ship. See
    /// `ebpf/algorithms/accel_common.h` for the full rationale.
    pub fn set_skip(&mut self, rules: &SkipRules) -> Result<()> {
        write_skip_config(&mut self.skel.maps.accel_skip_v4, &mut self.skel.maps.accel_skip_v6, rules, "accel_cubic")
    }
}

/// Per-algorithm Skel + Link bundle for accel_brutal. We keep `skel`
/// (no underscore) because the daemon needs to read/write the global
/// rate-config and socket-count maps via `set_rate` / `socket_count`.
pub struct LoadedBrutal {
    _link: Link,
    skel: AccelBrutalSkel<'static>,
}

impl LoadedBrutal {
    /// Write the user-configured target rate (bytes/sec) into the
    /// `brutal_rate_config` global ARRAY map. All accel_brutal sockets
    /// will read this on the next ACK.
    pub fn set_rate(&mut self, rate_bytes_per_sec: u64) -> Result<()> {
        let key: u32 = 0;
        self.skel
            .maps
            .brutal_rate_config
            .update(
                &key.to_ne_bytes(),
                &rate_bytes_per_sec.to_ne_bytes(),
                MapFlags::ANY,
            )
            .with_context(|| {
                format!("writing rate {rate_bytes_per_sec} byte/s to brutal_rate_config")
            })
    }

    /// Write the skip-local flag into the algorithm's `accel_skip_config`
    /// BPF map. See `LoadedCubic::set_skip` doc.
    pub fn set_skip(&mut self, rules: &SkipRules) -> Result<()> {
        write_skip_config(&mut self.skel.maps.accel_skip_v4, &mut self.skel.maps.accel_skip_v6, rules, "accel_brutal")
    }

    /// Read the current count of accel_brutal-managed sockets from the
    /// `brutal_socket_count` per-CPU map. Sums every CPU's slot —
    /// individual slots may have wrapped past u64::MAX (a socket
    /// init'd on CPU A can release on CPU B), but the sum mod 2^64
    /// recovers the correct global count.
    pub fn socket_count(&self) -> Result<u64> {
        let key: u32 = 0;
        let percpu = self
            .skel
            .maps
            .brutal_socket_count
            .lookup_percpu(&key.to_ne_bytes(), MapFlags::ANY)
            .context("looking up brutal_socket_count")?
            .ok_or_else(|| anyhow!("brutal_socket_count missing key 0"))?;
        sum_percpu_u64(&percpu, "brutal_socket_count")
    }
}

/// Per-algorithm bundle for accel_smart. Holds the struct_ops half
/// (smart skel and Link) together with the tc-bpf egress half (dup
/// skel and optional TcHook); their lifetimes are coupled because the
/// two halves share the `smart_link_state` BPF map (smart writes, dup
/// reads) and the tc filter must be detached before the dup program's
/// fd is closed.
///
/// Field declaration order is the Drop order. Combined with
/// `Drop for LoadedSmart` (which runs before field drops), the cleanup
/// sequence is: tc detach (Drop body) then tc_hook field drop (no-op,
/// TcHook is Copy) then _link drops (struct_ops unregister) then
/// dup_skel drops (close dup fds, releasing the reused
/// smart_link_state ref) then skel drops (close smart fds;
/// smart_link_state refcount hits zero).
pub struct LoadedSmart {
    /// `None` until `attach_tc_egress` succeeds. Set by cli (D5) once
    /// the user-configured network interface has been resolved.
    tc_hook: Option<libbpf_rs::TcHook>,
    _link: Link,
    /// tc-bpf side. Held without underscore because we access
    /// `dup_skel.maps.smart_dup_config` and `dup_skel.progs.smart_dup`
    /// in the runtime API methods.
    dup_skel: AccelSmartDupSkel<'static>,
    /// struct_ops side. Held without underscore because we access
    /// `skel.maps.smart_config_map / smart_socket_count /
    /// smart_state_count`.
    skel: AccelSmartSkel<'static>,
}

impl Drop for LoadedSmart {
    fn drop(&mut self) {
        // Detach the egress filter so it doesn't outlive accel. We
        // intentionally do NOT call `destroy()` — that tears down the
        // entire clsact qdisc, which other tools (Cilium, tc CLI) may
        // share. `detach()` removes only our smart_dup filter.
        if let Some(hook) = self.tc_hook.as_mut() {
            let _ = hook.detach();
        }
    }
}

// SAFETY: LoadedSmart needs to live inside `Arc<Mutex<HashMap<String,
// LoadedAlgo>>>` (see `status::State::algos`), which requires
// `LoadedAlgo: Send`. The Skel and Link halves are already Send via
// libbpf-rs's own bounds; the only non-Send component is the inner
// `bpf_tc_hook` struct, which holds a `*const c_char qdisc` field
// (libbpf 1.4+ binding addition).
//
// In our usage:
//   1. `bpf_tc_hook::default()` zeros the struct, leaving qdisc = NULL.
//   2. We only call `.ifindex()` and `.attach_point(TC_EGRESS)` —
//      neither touches `qdisc`.
//   3. `TC_EGRESS` is a built-in attach point handled by clsact, so
//      libbpf never dereferences `qdisc` for our hooks.
//
// Hence the raw pointer is provably always NULL throughout the
// lifetime of any `TcHook` we hand out, and sending the LoadedSmart
// across thread boundaries is sound.
unsafe impl Send for LoadedSmart {}

impl LoadedSmart {
    /// Write the skip-local flag into the algorithm's `accel_skip_config`
    /// BPF map. See `LoadedCubic::set_skip` doc.
    pub fn set_skip(&mut self, rules: &SkipRules) -> Result<()> {
        write_skip_config(&mut self.skel.maps.accel_skip_v4, &mut self.skel.maps.accel_skip_v6, rules, "accel_smart")
    }

    /// Write the user-configured GOOD-state target rate (byte/s) and
    /// classification thresholds into `smart_config_map`. The BPF
    /// cong_control re-reads this on every ACK, so updates take
    /// effect within ~1 RTT.
    pub fn set_config(
        &mut self,
        rate_bytes_per_sec: u64,
        loss_lossy_bp: u32,
        loss_congest_bp: u32,
        rtt_congest_pct: u32,
    ) -> Result<()> {
        // Wire layout matches `struct smart_config` in
        // accel_smart.bpf.c (24 bytes, native endian — kernel reads in
        // host byte order; we never serialize across machines):
        //   __u64 rate;            // bytes 0..8
        //   __u32 loss_lossy_bp;   //       8..12
        //   __u32 loss_congest_bp; //      12..16
        //   __u32 rtt_congest_pct; //      16..20
        //   __u32 _pad;            //      20..24
        let mut buf = [0u8; 24];
        buf[0..8].copy_from_slice(&rate_bytes_per_sec.to_ne_bytes());
        buf[8..12].copy_from_slice(&loss_lossy_bp.to_ne_bytes());
        buf[12..16].copy_from_slice(&loss_congest_bp.to_ne_bytes());
        buf[16..20].copy_from_slice(&rtt_congest_pct.to_ne_bytes());

        let key: u32 = 0;
        self.skel
            .maps
            .smart_config_map
            .update(&key.to_ne_bytes(), &buf, MapFlags::ANY)
            .with_context(|| {
                format!(
                    "writing smart_config_map (rate={rate_bytes_per_sec} byte/s, \
                     lossy={loss_lossy_bp}bp, congest={loss_congest_bp}bp, \
                     rtt_pct={rtt_congest_pct})"
                )
            })
    }

    /// Write the duplicator parameters into `smart_dup_config`. Read
    /// by the tc-bpf program on every egress packet.
    pub fn set_dup_config(
        &mut self,
        ifindex: u32,
        port_min: u16,
        port_max: u16,
    ) -> Result<()> {
        // Wire layout matches `struct dup_config` in
        // accel_smart_dup.bpf.c (8 bytes, native endian):
        //   __u32 ifindex;   // bytes 0..4
        //   __u16 port_min;  //       4..6
        //   __u16 port_max;  //       6..8
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&ifindex.to_ne_bytes());
        buf[4..6].copy_from_slice(&port_min.to_ne_bytes());
        buf[6..8].copy_from_slice(&port_max.to_ne_bytes());

        let key: u32 = 0;
        self.dup_skel
            .maps
            .smart_dup_config
            .update(&key.to_ne_bytes(), &buf, MapFlags::ANY)
            .with_context(|| {
                format!(
                    "writing smart_dup_config (ifindex={ifindex}, \
                     port_min={port_min}, port_max={port_max})"
                )
            })
    }

    /// Attach the tc-bpf duplicator to `ifindex` egress. Creates the
    /// underlying clsact qdisc if absent (idempotent — succeeds even
    /// if a previous accel run left one behind). Stores the resulting
    /// filter handle so `Drop` can detach cleanly.
    ///
    /// Repeated calls are not supported; `attach_tc_egress` should be
    /// invoked exactly once per `LoadedSmart` lifetime.
    pub fn attach_tc_egress(&mut self, ifindex: u32) -> Result<()> {
        use std::os::fd::AsFd;

        let prog_fd = self.dup_skel.progs.smart_dup.as_fd();
        let mut hook = libbpf_rs::TcHook::new(prog_fd);
        hook.ifindex(ifindex as i32)
            .attach_point(libbpf_rs::TC_EGRESS);

        hook.create()
            .with_context(|| format!("creating tc clsact qdisc on ifindex={ifindex}"))?;

        let attached = hook
            .attach()
            .with_context(|| {
                format!("attaching smart_dup BPF prog to tc/egress on ifindex={ifindex}")
            })?;

        self.tc_hook = Some(attached);
        Ok(())
    }

    /// Total accel_smart-managed sockets currently alive. Sums the
    /// per-CPU `smart_socket_count` array.
    pub fn socket_count(&self) -> Result<u64> {
        let key: u32 = 0;
        let percpu = self
            .skel
            .maps
            .smart_socket_count
            .lookup_percpu(&key.to_ne_bytes(), MapFlags::ANY)
            .context("looking up smart_socket_count")?
            .ok_or_else(|| anyhow!("smart_socket_count missing key 0"))?;
        sum_percpu_u64(&percpu, "smart_socket_count")
    }

    /// Per-state population: `[GOOD, LOSSY, CONGEST]`. Each element is
    /// summed across CPUs from the `smart_state_count` per-CPU array.
    pub fn state_counts(&self) -> Result<[u64; 3]> {
        let mut out = [0u64; 3];
        for (i, slot) in out.iter_mut().enumerate() {
            let key: u32 = i as u32;
            let percpu = self
                .skel
                .maps
                .smart_state_count
                .lookup_percpu(&key.to_ne_bytes(), MapFlags::ANY)
                .with_context(|| format!("looking up smart_state_count[{i}]"))?
                .ok_or_else(|| anyhow!("smart_state_count missing key {i}"))?;
            *slot = sum_percpu_u64(&percpu, &format!("smart_state_count[{i}]"))?;
        }
        Ok(out)
    }
}

/// Type-erased wrapper. Each variant carries the algorithm-specific Skel
/// and any extra map handles. Match on the variant when an algorithm
/// has unique runtime API (only brutal does, for set_rate/socket_count).
///
/// Variant names mirror the algorithm names without the `accel_` prefix.
//
// `large_enum_variant` is allowed because Smart legitimately holds two
// skeletons + an optional TcHook, while Cubic/Brutal hold one. Boxing
// would just push the same allocation out of the enum without saving
// real memory (the HashMap value slot already pays for one Smart-sized
// allocation when smart is present), and would force an extra deref on
// every match arm.
#[allow(clippy::large_enum_variant)]
pub enum LoadedAlgo {
    /// Cubic has no per-algo runtime API — it's a pure Drop guard.
    /// `dead_code` allow needed because the field is matched-and-ignored
    /// in cli.rs but its value is never destructured.
    #[allow(dead_code)]
    Cubic(LoadedCubic),
    Brutal(LoadedBrutal),
    /// Smart's runtime API (D4) is not wired in D2; the variant body is
    /// only a Drop guard at this stage.
    #[allow(dead_code)]
    Smart(LoadedSmart),
}

/// Registry. Adding a new algorithm here is the only place outside its
/// own .bpf.c + load_xxx fn that needs to change.
pub type LoaderFn = fn() -> Result<LoadedAlgo>;

pub fn all_loaders() -> &'static [(&'static str, LoaderFn)] {
    &[
        ("accel_cubic", load_cubic),
        ("accel_brutal", load_brutal),
        ("accel_smart", load_smart),
    ]
}

/// Try every registered loader. Successes go into the returned map;
/// failures print a one-line warning and are skipped — the caller
/// decides whether the absence of a particular algo is fatal.
pub fn load_all() -> HashMap<String, LoadedAlgo> {
    let mut out = HashMap::new();
    for (name, loader) in all_loaders() {
        match loader() {
            Ok(a) => {
                out.insert((*name).to_string(), a);
            }
            Err(e) => eprintln!("warning: {name} did not load: {e:#}"),
        }
    }
    out
}

fn load_cubic() -> Result<LoadedAlgo> {
    let storage: &'static mut MaybeUninit<OpenObject> =
        Box::leak(Box::new(MaybeUninit::uninit()));
    let skel_builder = AccelCubicSkelBuilder::default();
    let open_skel = skel_builder
        .open(storage)
        .context("opening accel_cubic skeleton failed")?;
    let mut skel = open_skel.load().context(
        "loading accel_cubic into kernel failed — \
         struct_ops.link requires Linux 6.4+ with CONFIG_DEBUG_INFO_BTF=y",
    )?;
    let link = skel
        .maps
        .accel_cubic
        .attach_struct_ops()
        .context("registering accel_cubic struct_ops failed (check `dmesg | tail`)")?;
    Ok(LoadedAlgo::Cubic(LoadedCubic {
        _link: link,
        skel,
    }))
}

fn load_brutal() -> Result<LoadedAlgo> {
    let storage: &'static mut MaybeUninit<OpenObject> =
        Box::leak(Box::new(MaybeUninit::uninit()));
    let skel_builder = AccelBrutalSkelBuilder::default();
    let open_skel = skel_builder
        .open(storage)
        .context("opening accel_brutal skeleton failed")?;
    let mut skel = open_skel.load().context(
        "loading accel_brutal into kernel failed — \
         struct_ops.link requires Linux 6.4+ with CONFIG_DEBUG_INFO_BTF=y",
    )?;
    let link = skel
        .maps
        .accel_brutal
        .attach_struct_ops()
        .context("registering accel_brutal struct_ops failed (check `dmesg | tail`)")?;
    Ok(LoadedAlgo::Brutal(LoadedBrutal { _link: link, skel }))
}

/// Load and register both halves of accel_smart:
///
/// * the struct_ops half (cong_control on every ACK, writes
///   smart_link_state from the per-socket state machine), and
/// * the tc-bpf egress half (reads smart_link_state, clones outbound
///   TCP packets when LOSSY).
///
/// The two BPF objects share the smart_link_state map kernel-side via
/// `reuse_fd`: dup's open-skeleton entry is rebound to smart's loaded
/// map fd before dup is loaded, so both halves point at one and the
/// same single-entry ARRAY map.
///
/// The tc filter is NOT attached here — `attach_tc_egress(ifindex)`
/// is called separately by cli (D5) once the user-configured network
/// interface has been resolved. This keeps `load_smart()` callable
/// from the registry without requiring a `[smart]` section in
/// acc.conf when smart isn't the active algorithm.
fn load_smart() -> Result<LoadedAlgo> {
    use std::os::fd::AsFd;

    // 1. Smart struct_ops half.
    let smart_storage: &'static mut MaybeUninit<OpenObject> =
        Box::leak(Box::new(MaybeUninit::uninit()));
    let smart_builder = AccelSmartSkelBuilder::default();
    let open_smart = smart_builder
        .open(smart_storage)
        .context("opening accel_smart skeleton failed")?;
    let mut skel = open_smart.load().context(
        "loading accel_smart into kernel failed — \
         struct_ops.link requires Linux 6.4+ with CONFIG_DEBUG_INFO_BTF=y",
    )?;
    let link = skel
        .maps
        .accel_smart
        .attach_struct_ops()
        .context("registering accel_smart struct_ops failed (check `dmesg | tail`)")?;

    // 2. Smart-dup tc-bpf half. Open the skeleton, alias the
    //    smart_link_state map onto smart's loaded fd, then load —
    //    without the reuse_fd step the two skeletons would each
    //    create their own unrelated single-entry ARRAY map.
    let dup_storage: &'static mut MaybeUninit<OpenObject> =
        Box::leak(Box::new(MaybeUninit::uninit()));
    let dup_builder = AccelSmartDupSkelBuilder::default();
    let mut open_dup = dup_builder
        .open(dup_storage)
        .context("opening accel_smart_dup skeleton failed")?;

    let state_fd = skel.maps.smart_link_state.as_fd();
    open_dup
        .maps
        .smart_link_state
        .reuse_fd(state_fd)
        .context("reuse_fd smart_link_state into accel_smart_dup")?;

    let dup_skel = open_dup.load().context(
        "loading accel_smart_dup into kernel failed — \
         tc-bpf egress requires CAP_NET_ADMIN and a recent enough kernel \
         (CONFIG_NET_CLS_BPF=y, CONFIG_NET_SCH_INGRESS=y for clsact)",
    )?;

    Ok(LoadedAlgo::Smart(LoadedSmart {
        tc_hook: None,
        _link: link,
        dup_skel,
        skel,
    }))
}

/// IPv4 skip-list entry. `addr_be` is the network address in network
/// byte order (4 bytes); `prefixlen` is 0..=32. The pair forms the
/// LPM_TRIE key (with prefixlen as a u32 prefix).
#[derive(Clone, Copy, Debug)]
pub struct V4Rule {
    pub addr_be: [u8; 4],
    pub prefixlen: u32,
}

/// IPv6 skip-list entry. `addr_be` is the address in network byte order
/// (16 bytes); `prefixlen` is 0..=128.
#[derive(Clone, Copy, Debug)]
pub struct V6Rule {
    pub addr_be: [u8; 16],
    pub prefixlen: u32,
}

/// Parsed skip_subnet split by family. Both lists are pushed to
/// LPM_TRIE maps in the kernel; per-family separation matches the
/// `accel_skip_v4` / `accel_skip_v6` BPF map split (see
/// `ebpf/algorithms/accel_common.h`).
#[derive(Clone, Debug, Default)]
pub struct SkipRules {
    pub v4: Vec<V4Rule>,
    pub v6: Vec<V6Rule>,
}

/// Capacities mirror `ACCEL_SKIP_MAX_V4` / `ACCEL_SKIP_MAX_V6` in
/// `accel_common.h`.
pub const MAX_SKIP_V4: usize = 256;
pub const MAX_SKIP_V6: usize = 256;

/// Push the skip rules into one algorithm's `accel_skip_v4` and
/// `accel_skip_v6` LPM_TRIE maps. Called by every `LoadedXxx::set_skip()`.
///
/// LPM_TRIE doesn't have an atomic "replace all entries" primitive, so
/// the helper does:
///   1. enumerate every existing key in v4 map → delete each
///   2. insert each rule from `rules.v4`
///   3. same for v6
///
/// Iteration is safe because `keys()` snapshots key-by-key via
/// `bpf_map_get_next_key()`; we collect into a Vec first to avoid
/// invalidating the iterator while mutating.
///
/// The two map handles are plumbed in by name so that a future
/// algorithm without `accel_skip_v4` / `accel_skip_v6` (i.e. that
/// forgot to `#include "accel_common.h"`) is a Rust *compile* error.
fn write_skip_config(
    v4_map: &mut libbpf_rs::MapMut<'_>,
    v6_map: &mut libbpf_rs::MapMut<'_>,
    rules: &SkipRules,
    algo_name: &str,
) -> Result<()> {
    if rules.v4.len() > MAX_SKIP_V4 {
        bail!(
            "too many IPv4 skip rules ({}); max is {}",
            rules.v4.len(),
            MAX_SKIP_V4
        );
    }
    if rules.v6.len() > MAX_SKIP_V6 {
        bail!(
            "too many IPv6 skip rules ({}); max is {}",
            rules.v6.len(),
            MAX_SKIP_V6
        );
    }

    // ── v4: clear, then insert ─────────────────────────────────────
    let stale_v4: Vec<Vec<u8>> = v4_map.keys().collect();
    for key in stale_v4 {
        v4_map.delete(&key).with_context(|| {
            format!("clearing accel_skip_v4 entry for {algo_name}")
        })?;
    }
    for rule in &rules.v4 {
        // LPM_TRIE v4 key layout: u32 prefixlen (host order) + 4 bytes
        // addr (network order). Total 8 bytes. Wire layout matches
        // `struct skip_v4_key` in accel_common.h.
        let mut key = [0u8; 8];
        key[0..4].copy_from_slice(&rule.prefixlen.to_ne_bytes());
        key[4..8].copy_from_slice(&rule.addr_be);
        let value = [1u8; 1]; // value unused; presence indicates "skip"
        v4_map
            .update(&key, &value, MapFlags::ANY)
            .with_context(|| {
                format!(
                    "inserting v4 skip rule (prefixlen={}) for {algo_name}",
                    rule.prefixlen
                )
            })?;
    }

    // ── v6: clear, then insert ─────────────────────────────────────
    let stale_v6: Vec<Vec<u8>> = v6_map.keys().collect();
    for key in stale_v6 {
        v6_map.delete(&key).with_context(|| {
            format!("clearing accel_skip_v6 entry for {algo_name}")
        })?;
    }
    for rule in &rules.v6 {
        // LPM_TRIE v6 key layout: u32 prefixlen + 16 bytes addr (BE).
        let mut key = [0u8; 20];
        key[0..4].copy_from_slice(&rule.prefixlen.to_ne_bytes());
        key[4..20].copy_from_slice(&rule.addr_be);
        let value = [1u8; 1];
        v6_map
            .update(&key, &value, MapFlags::ANY)
            .with_context(|| {
                format!(
                    "inserting v6 skip rule (prefixlen={}) for {algo_name}",
                    rule.prefixlen
                )
            })?;
    }

    Ok(())
}

/// Sum a per-CPU u64 counter map's values across all online CPUs.
///
/// Modular-arithmetic note: a socket may be init'd on one CPU and
/// released on another, so any individual CPU's slot can drift past
/// u64::MAX (i.e. wrap around). The wrapping_add chain still recovers
/// the correct global count because (a + b) mod 2^64 across all
/// per-CPU contributions equals the true count whenever init/release
/// balance globally — which they do by construction (`if (b->skip)
/// return;` symmetry).
fn sum_percpu_u64(percpu: &[Vec<u8>], context_name: &str) -> Result<u64> {
    let mut total: u64 = 0;
    for (cpu, bytes) in percpu.iter().enumerate() {
        let arr: [u8; 8] = bytes.as_slice().try_into().map_err(|_| {
            anyhow!(
                "{context_name}[cpu {cpu}] value len {} (want 8)",
                bytes.len()
            )
        })?;
        total = total.wrapping_add(u64::from_ne_bytes(arr));
    }
    Ok(total)
}

/// Build-time probe printed during startup banner — confirms both
/// skeletons are embedded in the binary even before any kernel load.
pub fn skeleton_info() -> String {
    format!(
        "skeletons embedded: accel_cubic, accel_brutal, accel_smart \
         (target {}, libbpf-rs {})",
        std::env::consts::ARCH,
        libbpf_version(),
    )
}

fn libbpf_version() -> &'static str {
    "0.26.2"
}
