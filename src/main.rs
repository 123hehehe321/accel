mod config;
mod ports;

use std::path::Path;
use std::sync::mpsc;

use anyhow::{anyhow, Context, Result};
use aya::maps::{PerCpuArray, PerCpuValues};
use aya::programs::{Xdp, XdpFlags};
use aya::util::online_cpus;
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

    let ports = ports::parse(&cfg.network.ports).context("parsing [network].ports failed")?;
    let port_count: usize = ports.iter_ports().count();
    println!(
        "parsed ports: {} single, {} range(s), {port_count} total",
        ports.singles.len(),
        ports.ranges.len()
    );

    check_jit_enabled();

    let mut ebpf = Ebpf::load(&CLASSIFIER_OBJ.0).context("failed to parse classifier.o")?;

    // Populate port_map (per-CPU bitmap). Same value on every CPU slot.
    let nr_cpus = online_cpus()
        .map_err(|(call, e)| anyhow!("failed to enumerate online CPUs via {call}: {e}"))?
        .len();
    let mut port_map: PerCpuArray<_, u8> = PerCpuArray::try_from(
        ebpf.map_mut("port_map")
            .ok_or_else(|| anyhow!("eBPF map 'port_map' not found"))?,
    )
    .context("'port_map' is not a PerCpuArray<u8>")?;
    for port in ports.iter_ports() {
        // PerCpuValues is not Clone, so rebuild each iteration — ~15k tiny
        // allocs at startup is negligible compared to eBPF load itself.
        let ones = PerCpuValues::try_from(vec![1u8; nr_cpus])
            .context("building PerCpuValues for port_map")?;
        port_map
            .set(port as u32, ones, 0)
            .with_context(|| format!("setting port {port} in port_map"))?;
    }

    let program: &mut Xdp = ebpf
        .program_mut(PROGRAM_NAME)
        .with_context(|| format!("eBPF program '{PROGRAM_NAME}' not found in classifier.o"))?
        .try_into()
        .context("program is not an XDP program")?;

    program
        .load()
        .context("failed to load XDP program into kernel (check dmesg for verifier errors)")?;

    // Day 3A: hardcoded generic (SKB) mode. Day 3B will add auto/native detection.
    let iface = &cfg.network.interface;
    program.attach(iface, XdpFlags::SKB_MODE).with_context(|| {
        format!("failed to attach XDP to '{iface}' (check interface name and permissions)")
    })?;

    println!("xdp attached to {iface} (mode: generic / SKB_MODE)");
    println!("press ctrl+c to stop.");

    let (tx, rx) = mpsc::channel::<()>();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .context("installing SIGINT/SIGTERM handler")?;
    let _ = rx.recv();

    println!("shutting down (eBPF program will auto-detach)...");
    Ok(())
}

fn check_jit_enabled() {
    match std::fs::read_to_string("/proc/sys/net/core/bpf_jit_enable") {
        Ok(value) => {
            let enabled: u32 = value.trim().parse().unwrap_or(0);
            if enabled == 0 {
                eprintln!("warning: bpf_jit_enable=0, eBPF runs in interpreter (5-10x slower)");
                eprintln!("         enable with: sudo sysctl -w net.core.bpf_jit_enable=1");
                eprintln!(
                    "         permanent:   echo 'net.core.bpf_jit_enable=1' | sudo tee -a /etc/sysctl.conf"
                );
            } else {
                println!("bpf_jit_enable: {enabled} (ok)");
            }
        }
        Err(e) => {
            eprintln!("note: cannot read /proc/sys/net/core/bpf_jit_enable ({e}), skipping jit check");
        }
    }
}
