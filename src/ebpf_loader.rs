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

use anyhow::{anyhow, Context, Result};
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

use accel_brutal_skel::{AccelBrutalSkel, AccelBrutalSkelBuilder};
use accel_cubic_skel::{AccelCubicSkel, AccelCubicSkelBuilder};
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
    _skel: AccelCubicSkel<'static>,
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

    /// Read the current count of accel_brutal-managed sockets from the
    /// `brutal_socket_count` map. The map is bumped/decremented atomically
    /// by the BPF init/release callbacks.
    pub fn socket_count(&self) -> Result<u64> {
        let key: u32 = 0;
        let bytes = self
            .skel
            .maps
            .brutal_socket_count
            .lookup(&key.to_ne_bytes(), MapFlags::ANY)
            .context("looking up brutal_socket_count")?
            .ok_or_else(|| anyhow!("brutal_socket_count missing key 0"))?;
        let arr: [u8; 8] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("brutal_socket_count value len {} (want 8)", bytes.len()))?;
        Ok(u64::from_ne_bytes(arr))
    }
}

/// Drop guard for accel_smart. D2 ships only the loader plumbing — D4
/// will extend with set_config / socket_count / state_counts methods.
/// At D2 the variant exists purely to put the kernel verifier through
/// its paces at accel startup; no runtime API is consumed yet.
pub struct LoadedSmart {
    _link: Link,
    _skel: AccelSmartSkel<'static>,
}

/// Type-erased wrapper. Each variant carries the algorithm-specific Skel
/// and any extra map handles. Match on the variant when an algorithm
/// has unique runtime API (only brutal does, for set_rate/socket_count).
///
/// Variant names mirror the algorithm names without the `accel_` prefix.
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
        _skel: skel,
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

/// D2-minimal smart loader. Mirrors load_brutal's structure but without
/// any per-algo runtime methods on the returned LoadedSmart — D4 will
/// extend this with map handles for set_config / socket_count /
/// state_counts. The whole point at D2 is to drive accel_smart through
/// the same libbpf-rs → kernel-verifier path the production loader will
/// use, isolating the verifier risk before any cli/status/health/config
/// integration lands.
fn load_smart() -> Result<LoadedAlgo> {
    let storage: &'static mut MaybeUninit<OpenObject> =
        Box::leak(Box::new(MaybeUninit::uninit()));
    let skel_builder = AccelSmartSkelBuilder::default();
    let open_skel = skel_builder
        .open(storage)
        .context("opening accel_smart skeleton failed")?;
    let mut skel = open_skel.load().context(
        "loading accel_smart into kernel failed — \
         struct_ops.link requires Linux 6.4+ with CONFIG_DEBUG_INFO_BTF=y",
    )?;
    let link = skel
        .maps
        .accel_smart
        .attach_struct_ops()
        .context("registering accel_smart struct_ops failed (check `dmesg | tail`)")?;
    Ok(LoadedAlgo::Smart(LoadedSmart {
        _link: link,
        _skel: skel,
    }))
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
