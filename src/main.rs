mod config;

use std::path::Path;
use std::thread;

use anyhow::{Context, Result};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;

const CONFIG_PATH: &str = "./acc.conf";
const PROGRAM_NAME: &str = "xdp_classifier";

// include_bytes! returns byte-aligned data, but the `object` crate used by
// aya to parse ELF requires 8-byte alignment for section headers. Wrap the
// bytes in a repr-aligned struct so the embedded blob is safely parseable.
#[repr(C, align(8))]
struct Aligned<T: ?Sized>(T);
static CLASSIFIER_OBJ: &Aligned<[u8]> =
    &Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/classifier.o")));

fn main() -> Result<()> {
    println!("hello accel");
    println!();

    let path = Path::new(CONFIG_PATH);
    let cfg = config::load(path)?;

    println!("config loaded from: {}", path.display());
    println!("  [network]");
    println!("    interface = {:?}", cfg.network.interface);
    println!("    ports     = {:?}", cfg.network.ports);
    println!("    mode      = {:?}", cfg.network.mode);
    println!("  [runtime]");
    let socket_display = if cfg.runtime.socket.is_empty() {
        "\"\" (auto-detect)".to_string()
    } else {
        format!("{:?}", cfg.runtime.socket)
    };
    println!("    socket    = {socket_display}");
    println!("  [forward]");
    println!("    backend   = {:?}", cfg.forward.backend);
    println!();

    let mut ebpf = Ebpf::load(&CLASSIFIER_OBJ.0).context("failed to parse classifier.o")?;

    let program: &mut Xdp = ebpf
        .program_mut(PROGRAM_NAME)
        .with_context(|| format!("eBPF program '{PROGRAM_NAME}' not found in classifier.o"))?
        .try_into()
        .context("program is not an XDP program")?;

    program
        .load()
        .context("failed to load XDP program into kernel (check dmesg for verifier errors)")?;

    // Day 2: hardcoded generic (SKB) mode. Day 3 will add auto/native detection.
    let iface = &cfg.network.interface;
    program.attach(iface, XdpFlags::SKB_MODE).with_context(|| {
        format!("failed to attach XDP to '{iface}' (check interface name and permissions)")
    })?;

    println!("xdp attached to {iface} (mode: generic / SKB_MODE)");
    println!("view packets with: sudo cat /sys/kernel/debug/tracing/trace_pipe");
    println!("press ctrl+c to stop (day 2: no graceful shutdown yet)");

    // Day 3 will replace this with a proper SIGINT/SIGTERM handler.
    thread::park();
    Ok(())
}
