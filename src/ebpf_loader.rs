//! eBPF loader skeleton.
//!
//! 2.1-D3 wires up the build-time skeleton (`build.rs` → `libbpf-cargo`)
//! and embeds the `.bpf.o` object into the binary. The skeleton module is
//! embedded via `include!` but nothing in it is called yet — 2.1-D4 will
//! implement `load_cubic()` / `unload()` on top of it. Scoped
//! `#[allow(dead_code)]` so the build-time generated code does not trip
//! the project-wide `-D dead_code` rule.

// Silence all warnings / clippy lints emitted by the libbpf-cargo
// generated code. Scoped to the `mod` so accel's own ebpf_loader.rs code
// below still gets full lint coverage.
#[allow(dead_code, unused_imports, clippy::all)]
mod accel_cubic_skel {
    include!(concat!(env!("OUT_DIR"), "/accel_cubic.skel.rs"));
}

/// Build-time probe: returns a short descriptor that accel prints at
/// startup, both as a human-visible signal and to force at least one
/// reference to the skeleton module so `cargo build` really does emit the
/// `.bpf.o` and generate the skeleton. 2.1-D4 replaces this with real
/// load/attach logic.
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
