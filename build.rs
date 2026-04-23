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
    // -g is required: libbpf-style map definitions (__uint/__type macros) are
    // encoded into the .BTF section. Without it aya fails with "no BTF parsed".
    // After compilation we strip .BTF.ext (CO-RE relocations aya 0.13 can't
    // handle) and DWARF debug sections.
    cmd.args(["-target", "bpf", "-O2", "-g"]);

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
        strip_unneeded_sections(&output);
        return;
    }

    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("unknown target") && stderr.contains("bpf") {
        fail("clang does not support -target bpf. upgrade clang to >= 10");
    }
    if stderr.contains("'bpf/bpf_helpers.h' file not found") {
        fail("bpf/bpf_helpers.h not found. install with: sudo apt install libbpf-dev");
    }

    // Forward clang's own error output unchanged — it already points at the
    // offending line in classifier.c.
    eprintln!("error: failed to compile {SOURCE}");
    eprint!("{stderr}");
    std::process::exit(1);
}

fn strip_unneeded_sections(obj: &Path) {
    let strip = Command::new("llvm-strip")
        .args(["--remove-section=.BTF.ext", "--strip-debug"])
        .arg(obj)
        .output();
    match strip {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            eprintln!(
                "error: llvm-strip failed: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            std::process::exit(1);
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            fail("llvm-strip not found. install with: sudo apt install llvm");
        }
        Err(e) => fail(&format!("failed to invoke llvm-strip: {e}")),
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}
