use std::panic::{self, AssertUnwindSafe};
use std::path::Path;
use std::process::ExitCode;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use aya::maps::{MapData, PerCpuArray, PerCpuValues};
use aya::programs::Xdp;
use aya::util::nr_cpus;
use aya::Ebpf;

use crate::{config, mode, ports, socket, status};

const CONFIG_PATH: &str = "./acc.conf";
const PROGRAM_NAME: &str = "xdp_classifier";

pub fn dispatch() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let result: Result<()> = match args.get(1).map(String::as_str) {
        None => run_server(),
        Some("status") => run_status(),
        Some("stop") => run_stop(),
        Some("--help") | Some("-h") | Some("help") => {
            print_usage();
            Ok(())
        }
        Some(other) => {
            eprintln!("error: unknown command: {other}");
            print_usage();
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!("usage: accel [COMMAND]");
    eprintln!();
    eprintln!("commands:");
    eprintln!("  (no args)   run the accelerator daemon (needs root)");
    eprintln!("  status      query a running accel instance");
    eprintln!("  stop        ask a running accel instance to exit");
}

fn run_status() -> Result<()> {
    let cfg = config::load(Path::new(CONFIG_PATH))?;
    let sock = socket::resolve_path(&cfg.runtime.socket);
    socket::client_roundtrip(&sock, "status")
}

fn run_stop() -> Result<()> {
    let cfg = config::load(Path::new(CONFIG_PATH))?;
    let sock = socket::resolve_path(&cfg.runtime.socket);
    socket::client_roundtrip(&sock, "stop")
}

fn run_server() -> Result<()> {
    println!("hello accel");
    println!();

    let cfg = config::load(Path::new(CONFIG_PATH))?;

    println!("config loaded from: {CONFIG_PATH}");
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

    let parsed_ports =
        ports::parse(&cfg.network.ports).context("parsing [network].ports failed")?;
    let port_count: usize = parsed_ports.iter_ports().count();
    println!(
        "parsed ports: {} single, {} range(s), {port_count} total",
        parsed_ports.singles.len(),
        parsed_ports.ranges.len()
    );

    check_jit_enabled();

    // Resolve socket path and verify no other instance BEFORE any side effect.
    let socket_path = socket::resolve_path(&cfg.runtime.socket);
    socket::prepare_path(&socket_path)?;

    // Load eBPF, load program, populate port_map — nothing attached yet.
    let mut ebpf = Ebpf::load(&crate::CLASSIFIER_OBJ.0).context("failed to parse classifier.o")?;

    {
        // Per-CPU BPF maps are always sized by the kernel's NR_CPUS (possible
        // cpus), not just the online count — cores that hotplug in later use
        // the same pre-allocated slot. aya rejects vecs of the wrong length.
        let possible_cpus = nr_cpus()
            .map_err(|(call, e)| anyhow!("failed to read possible CPUs via {call}: {e}"))?;
        let mut port_map: PerCpuArray<_, u8> = PerCpuArray::try_from(
            ebpf.map_mut("port_map")
                .ok_or_else(|| anyhow!("eBPF map 'port_map' not found"))?,
        )
        .context("'port_map' is not a PerCpuArray<u8>")?;
        for port in parsed_ports.iter_ports() {
            let ones = PerCpuValues::try_from(vec![1u8; possible_cpus])
                .context("building PerCpuValues for port_map")?;
            port_map
                .set(port as u32, ones, 0)
                .with_context(|| format!("setting port {port} in port_map"))?;
        }
    }

    // Take stats map out so we can move it to the socket thread.
    let stats_map = ebpf
        .take_map("stats")
        .ok_or_else(|| anyhow!("eBPF map 'stats' not found"))?;
    let stats: PerCpuArray<MapData, u64> =
        PerCpuArray::try_from(stats_map).context("'stats' is not a PerCpuArray<u64>")?;

    // Program load (kernel fd created but not attached yet).
    let program: &mut Xdp = ebpf
        .program_mut(PROGRAM_NAME)
        .with_context(|| format!("eBPF program '{PROGRAM_NAME}' not found"))?
        .try_into()
        .context("program is not an XDP program")?;
    program
        .load()
        .context("failed to load XDP program (check dmesg for verifier errors)")?;

    // Attach — side effect 1: packets now flow through our classifier.
    let iface = cfg.network.interface.clone();
    let resolved_mode = mode::attach(program, &iface, &cfg.network.mode)?;
    println!("xdp attached to {iface} (mode: {resolved_mode})");

    // Bind socket — side effect 2.
    let listener = socket::bind(&socket_path)?;
    println!("listening on {}", socket_path.display());

    // Shared state for the socket thread.
    let state = Arc::new(status::State {
        pid: std::process::id(),
        started_at: Instant::now(),
        iface: iface.clone(),
        iface_driver: status::read_iface_driver(&iface),
        ports: cfg.network.ports.clone(),
        mode: resolved_mode,
        socket_path: socket_path.clone(),
        stats,
    });

    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    // Socket thread: panic guard so a server bug propagates to main shutdown
    // instead of leaving accel half-dead.
    let socket_shutdown_tx = shutdown_tx.clone();
    let socket_state = Arc::clone(&state);
    thread::Builder::new()
        .name("accel-socket".into())
        .spawn(move || {
            let guard_tx = socket_shutdown_tx.clone();
            let result = panic::catch_unwind(AssertUnwindSafe(|| {
                socket::serve(listener, socket_state, socket_shutdown_tx);
            }));
            if let Err(info) = result {
                eprintln!("error: socket thread panicked: {info:?}");
                let _ = guard_tx.send(());
            }
        })
        .context("spawning socket thread")?;

    // Ctrl+C / SIGTERM handler.
    let signal_tx = shutdown_tx.clone();
    ctrlc::set_handler(move || {
        let _ = signal_tx.send(());
    })
    .context("installing SIGINT/SIGTERM handler")?;

    println!("press ctrl+c to stop, or run './accel stop' from another terminal.");

    let _ = shutdown_rx.recv();

    println!("shutting down (eBPF program will auto-detach)...");
    let _ = std::fs::remove_file(&socket_path);
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
            eprintln!(
                "note: cannot read /proc/sys/net/core/bpf_jit_enable ({e}), skipping jit check"
            );
        }
    }
}
