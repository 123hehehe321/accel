use std::panic::{self, AssertUnwindSafe};
use std::path::Path;
use std::process::ExitCode;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use anyhow::{Context, Result};

use crate::{config, ebpf_loader, socket, status};

const CONFIG_PATH: &str = "./acc.conf";

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
    println!("hello accel (v0.2, 2.1-D3 migration checkpoint)");
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
    println!();
    println!("⚠️  2.1-D3 checkpoint: skeleton embedded, loading lands in 2.1-D4.");
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
    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}
