use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "ebpf/algorithms/accel_cubic.bpf.c";

fn main() {
    let out_dir = PathBuf::from(
        env::var_os("OUT_DIR").expect("OUT_DIR must be set by cargo"),
    );
    let skel_out = out_dir.join("accel_cubic.skel.rs");

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set by cargo");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(&arch).as_os_str(),
        ])
        .build_and_generate(&skel_out)
        .unwrap_or_else(|e| {
            panic!("libbpf-cargo SkeletonBuilder failed for {SRC}: {e}");
        });

    println!("cargo:rerun-if-changed={SRC}");
}
