use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const ALGORITHMS: &[&str] = &["accel_cubic", "accel_brutal", "accel_smart"];

/// tc-bpf programs (non-struct_ops). Compiled identically to the
/// algorithm list above but kept separate because they are not
/// congestion-control algorithms and don't get registered through
/// `attach_struct_ops` — they're attached via TcHook in the loader.
const TC_PROGRAMS: &[&str] = &["accel_smart_dup"];

fn main() {
    let out_dir = PathBuf::from(
        env::var_os("OUT_DIR").expect("OUT_DIR must be set by cargo"),
    );
    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set by cargo");
    let vmlinux_inc = vmlinux::include_path_root().join(&arch);

    let sources = ALGORITHMS.iter().chain(TC_PROGRAMS.iter());
    for name in sources {
        let src = format!("ebpf/algorithms/{name}.bpf.c");
        let skel_out = out_dir.join(format!("{name}.skel.rs"));

        SkeletonBuilder::new()
            .source(&src)
            .clang_args([OsStr::new("-I"), vmlinux_inc.as_os_str()])
            .build_and_generate(&skel_out)
            .unwrap_or_else(|e| {
                panic!("libbpf-cargo SkeletonBuilder failed for {src}: {e}");
            });

        println!("cargo:rerun-if-changed={src}");
    }
}
