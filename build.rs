use std::env;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

const SOURCE: &str = "ebpf/classifier.c";

fn main() {
    println!("cargo:rerun-if-changed={SOURCE}");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set by cargo"));
    let output = out_dir.join("classifier.o");

    let mut cmd = Command::new("clang");
    // No -g: clang 18 emits BTF relocations that aya 0.13 rejects.
    // We don't need debug info for Day 2's minimal program.
    cmd.args(["-target", "bpf", "-O2"]);

    // <linux/bpf.h> pulls in <asm/types.h>, which on Debian/Ubuntu lives in
    // the multiarch include dir. Clang doesn't scan it by default when the
    // target is "bpf", so we add it explicitly for the host arch.
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH not set");
    let multiarch = format!("/usr/include/{arch}-linux-gnu");
    if Path::new(&multiarch).is_dir() {
        cmd.arg(format!("-I{multiarch}"));
    }

    cmd.args(["-c", SOURCE, "-o"]).arg(&output);

    let result = cmd.output();

    let out = match result {
        Ok(o) => o,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            fail("clang not found. install with: sudo apt install clang");
        }
        Err(e) => fail(&format!("failed to invoke clang: {e}")),
    };

    if out.status.success() {
        return;
    }

    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("unknown target") && stderr.contains("bpf") {
        fail("clang does not support -target bpf. upgrade clang to >= 10");
    }

    // Forward clang's own error output unchanged — it already points at the
    // offending line in classifier.c.
    eprintln!("error: failed to compile {SOURCE}");
    eprint!("{stderr}");
    std::process::exit(1);
}

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}
