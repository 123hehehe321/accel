use std::panic::{self, AssertUnwindSafe};
use std::path::Path;
use std::process::ExitCode;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};

use crate::{algo, config, ebpf_loader, socket, status};

const CONFIG_PATH: &str = "./acc.conf";

pub fn dispatch() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let result: Result<()> = match args.get(1).map(String::as_str) {
        None => run_server(),
        Some("status") => run_status(),
        Some("stop") => run_stop(),
        Some("algo") => run_algo(&args[2..]),
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
    eprintln!("  (no args)            run the accelerator daemon (needs root)");
    eprintln!("  status               query a running accel instance");
    eprintln!("  stop                 ask a running accel instance to exit");
    eprintln!("  algo list            list available and active congestion algorithms");
    eprintln!("  algo switch NAME     switch sysctl tcp_congestion_control to NAME");
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

fn run_algo(args: &[String]) -> Result<()> {
    let cfg = config::load(Path::new(CONFIG_PATH))?;
    let sock = socket::resolve_path(&cfg.runtime.socket);
    match args.first().map(String::as_str) {
        Some("list") => socket::client_roundtrip(&sock, "algo_list"),
        Some("switch") => {
            let name = args
                .get(1)
                .ok_or_else(|| anyhow!("missing algorithm name (usage: accel algo switch NAME)"))?;
            socket::client_roundtrip(&sock, &format!("algo_switch {name}"))
        }
        _ => {
            eprintln!("usage: accel algo <list|switch NAME>");
            Err(anyhow!("missing or invalid algo subcommand"))
        }
    }
}

fn run_server() -> Result<()> {
    println!("hello accel (v0.2, 2.1-D4)");
    println!();

    let cfg = config::load(Path::new(CONFIG_PATH))?;

    println!("config loaded from: {CONFIG_PATH}");
    println!("  [algorithm]");
    println!("    default  = {:?}", cfg.algorithm.default);
    println!("    algo_dir = {:?}", cfg.algorithm.algo_dir);
    println!("  [runtime]");
    let socket_display = if cfg.runtime.socket.is_empty() {
        "\"\" (auto-detect)".to_string()
    } else {
        format!("{:?}", cfg.runtime.socket)
    };
    println!("    socket   = {socket_display}");
    println!();

    println!("{}", ebpf_loader::skeleton_info());

    // Load + register the struct_ops algorithm BEFORE binding the socket,
    // so a kernel-too-old failure doesn't leave an orphan socket file.
    println!("loading accel_cubic into kernel...");
    let loaded = ebpf_loader::load_accel_cubic()?;
    println!("  registered as struct_ops: {}", loaded.name);

    // Apply sysctl so the kernel uses our algorithm for new connections.
    // `cfg.algorithm.default` must match a registered algorithm — for 2.1-D4
    // that's `accel_cubic` (the only one we load).
    let target_name = cfg.algorithm.default.clone();
    algo::set_cc_both(&target_name).with_context(|| {
        format!("setting sysctl tcp_congestion_control={target_name}")
    })?;
    println!(
        "  kernel sysctl set: tcp_congestion_control={target_name} (ipv4{})",
        if algo::current_cc_ipv6().is_some() {
            "+ipv6"
        } else {
            ""
        }
    );
    println!();

    // Resolve socket path and verify no other instance.
    let socket_path = socket::resolve_path(&cfg.runtime.socket);
    socket::prepare_path(&socket_path)?;
    let listener = socket::bind(&socket_path)?;
    println!("listening on {}", socket_path.display());

    let state = Arc::new(status::State {
        pid: std::process::id(),
        started_at: Instant::now(),
        socket_path: socket_path.clone(),
        algo: Arc::new(Mutex::new(Some(loaded))),
        target_algo: Arc::new(Mutex::new(target_name)),
    });

    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    // Socket thread — panic guard propagates to main shutdown.
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

    // SIGINT / SIGTERM handler.
    let signal_tx = shutdown_tx.clone();
    ctrlc::set_handler(move || {
        let _ = signal_tx.send(());
    })
    .context("installing SIGINT/SIGTERM handler")?;

    println!("press ctrl+c to stop, or run './accel stop' from another terminal.");

    let _ = shutdown_rx.recv();

    println!("shutting down...");
    // Explicitly drop the algo while state is reachable, so unregister-
    // related log lines land before socket removal. `take()` lets the
    // Drop fire at end of scope.
    if let Some(algo) = state.algo.lock().ok().and_then(|mut g| g.take()) {
        println!("unregistering struct_ops {}...", algo.name);
        drop(algo);
    }
    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}
