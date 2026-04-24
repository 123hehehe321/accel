//! eBPF struct_ops loader.
//!
//! 2.1-D4 implements [`load_accel_cubic`], which opens the generated
//! skeleton, loads the `.bpf.o` into the kernel, and attaches it as a
//! TCP congestion-control `struct_ops`. The returned [`LoadedAlgo`] owns
//! the libbpf `Link` — dropping it calls `bpf_link__destroy()` and
//! unregisters the algorithm from `tcp_available_congestion_control`.

use std::mem::MaybeUninit;

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{Link, OpenObject};

// Silence all warnings / clippy lints emitted by the libbpf-cargo
// generated code. Scoped to the `mod` so accel's own ebpf_loader.rs code
// below still gets full lint coverage.
#[allow(dead_code, unused_imports, clippy::all)]
mod accel_cubic_skel {
    include!(concat!(env!("OUT_DIR"), "/accel_cubic.skel.rs"));
}

use accel_cubic_skel::{AccelCubicSkel, AccelCubicSkelBuilder};

/// A loaded-and-attached TCP congestion-control algorithm.
///
/// `_skel` owns the loaded BPF object (maps, programs); `_link` owns the
/// kernel-side registration. Dropping the struct unregisters the algorithm
/// and closes all fds.
pub struct LoadedAlgo {
    pub name: &'static str,
    // Fields kept only for Drop semantics. Order matters: `_link` drops
    // first (unregister from struct_ops), then `_skel` (close program/map
    // fds). Rust drops fields in declaration order, so `_link` before
    // `_skel`.
    _link: Link,
    _skel: AccelCubicSkel<'static>,
}

/// Open + load + register `accel_cubic` as a struct_ops TCP congestion
/// control algorithm. After this returns, the algorithm name appears in
/// `/proc/sys/net/ipv4/tcp_available_congestion_control` and can be set
/// via `sysctl net.ipv4.tcp_congestion_control=accel_cubic`.
///
/// Implementation note: the BPF `OpenObject` storage is [`Box::leak`]ed
/// so the `'static` lifetime required by the skeleton holds for the
/// program's lifetime. ~40 KB leaked per successful load; we only load
/// once at startup (2.1-D5 will reload on health-driven re-registration,
/// leaking another ~40 KB per reload — acceptable given the rarity of
/// this event and the memory budget).
pub fn load_accel_cubic() -> Result<LoadedAlgo> {
    let storage: &'static mut MaybeUninit<OpenObject> =
        Box::leak(Box::new(MaybeUninit::uninit()));

    let skel_builder = AccelCubicSkelBuilder::default();
    let open_skel = skel_builder
        .open(storage)
        .context("opening accel_cubic skeleton failed")?;
    let mut skel = open_skel
        .load()
        .context(
            "loading accel_cubic into kernel failed — \
             struct_ops.link requires Linux 6.4+ with CONFIG_DEBUG_INFO_BTF=y \
             (check /sys/kernel/btf/vmlinux exists and `uname -r` >= 6.4)",
        )?;

    let link = skel
        .maps
        .accel_cubic
        .attach_struct_ops()
        .context("registering accel_cubic struct_ops failed (check `dmesg | tail` for verifier output)")?;

    Ok(LoadedAlgo {
        name: "accel_cubic",
        _link: link,
        _skel: skel,
    })
}

/// Build-time probe: short descriptor printed during 2.1-D3 / D4 startup
/// banner.
pub fn skeleton_info() -> String {
    format!(
        "accel_cubic skeleton embedded (target {}, libbpf-rs {})",
        std::env::consts::ARCH,
        libbpf_version(),
    )
}

fn libbpf_version() -> &'static str {
    // libbpf-rs = "=0.26.2" is pinned in Cargo.toml; keep in sync.
    "0.26.2"
}
