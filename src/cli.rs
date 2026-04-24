use std::panic::{self, AssertUnwindSafe};
use std::path::Path;
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};

use crate::incidents::{self, Event};
use crate::{algo, config, ebpf_loader, health, socket, status};

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
    println!("hello accel (v0.2, 2.1-D6)");
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

    // Incident log initialization and startup record, *before* any side
    // effect so the startup row always makes it to disk.
    incidents::init(incidents::resolve_path());
    let kernel = incidents::read_kernel_release();
    let last_shutdown = incidents::last_shutdown_reason();
    incidents::append(Event::Startup {
        pid: std::process::id(),
        kernel: kernel.clone(),
        last_shutdown: last_shutdown.clone(),
    })
    .context("writing startup incident")?;
    println!("incident log: {}", incidents::path().unwrap().display());
    println!("  kernel:        {kernel}");
    println!("  last shutdown: {last_shutdown}");

    // Startup-time health probes that only fire once per process.
    if let Some(prev) = scan_dmesg_oom() {
        let _ = incidents::append(Event::OomKilled {
            previous_pid: Some(prev),
        });
        eprintln!("warning: dmesg shows a previous accel pid={prev} killed by OOM");
    }
    if !jit_enabled() {
        let _ = incidents::append(Event::JitDisabled);
    }
    println!();

    println!("{}", ebpf_loader::skeleton_info());

    // Load + register the struct_ops algorithm BEFORE binding the socket,
    // so a kernel-too-old failure doesn't leave an orphan socket file.
    println!("loading accel_cubic into kernel...");
    let loaded = ebpf_loader::load_accel_cubic()?;
    println!("  registered as struct_ops: {}", loaded.name);

    // Capture the kernel's CC algorithm BEFORE we overwrite it, so the
    // clean-shutdown path can restore sysctl to pre-accel state (bug fix
    // 2.1-D6: previously sysctl stayed pinned to accel_cubic after stop,
    // keeping new connections routed through a doomed-to-unregister algo).
    //
    // Edge case: if the captured value IS the algorithm we're about to
    // load (e.g. a prior accel run exited abnormally and left sysctl
    // pointing at accel_cubic, which is then still in-kernel because
    // lingering sockets held it), restoring to that same name at
    // shutdown would fail — by then our Link has dropped and the algo
    // is unregistered, so `sysctl -w = accel_cubic` gets EINVAL.
    // We coerce such captures to a built-in fallback (bbr → cubic →
    // reno, whichever is registered) at capture time, keeping the
    // shutdown restore path trivial.
    let target_name = cfg.algorithm.default.clone();
    let original_cc_ipv4 = capture_cc_with_fallback(algo::current_cc_ipv4().ok(), &target_name);
    let original_cc_ipv6 = capture_cc_with_fallback(algo::current_cc_ipv6(), &target_name);
    match &original_cc_ipv4 {
        Some(v4) => println!("  capturing pre-accel sysctl: {v4} (will restore on clean stop)"),
        None => eprintln!(
            "warning: could not read current sysctl tcp_congestion_control;\
             clean shutdown will skip sysctl restore"
        ),
    }

    // Apply sysctl so the kernel uses our algorithm for new connections.
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
        original_cc_ipv4,
        original_cc_ipv6,
        health_shutting_down: AtomicBool::new(false),
        health_last_ok: Mutex::new(None),
        jit_warned: AtomicBool::new(false),
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

    // Health thread.
    health::spawn(Arc::clone(&state)).context("spawning health thread")?;

    // SIGINT / SIGTERM handler.
    let signal_tx = shutdown_tx.clone();
    ctrlc::set_handler(move || {
        let _ = signal_tx.send(());
    })
    .context("installing SIGINT/SIGTERM handler")?;

    println!("press ctrl+c to stop, or run './accel stop' from another terminal.");

    let _ = shutdown_rx.recv();

    println!("shutting down...");
    // Stop the health thread before we tear down the algo it monitors.
    // Otherwise health could race with our cleanup: detect our
    // intentional sysctl restore as a "drift" and try to reconcile.
    state.health_shutting_down.store(true, Ordering::Relaxed);

    // Restore sysctl to pre-accel value FIRST, before dropping the algo.
    // Order matters:
    //   1. sysctl restored → new TCP connections use the original CC,
    //      NOT accel_cubic (which is about to be unregistered).
    //   2. Link dropped → kernel unregisters accel_cubic from
    //      tcp_available_congestion_control.
    //   3. Skel dropped → map fds closed, kernel GCs the map once all
    //      existing connections using accel_cubic release their refs.
    // If we did 2 before 1, a new connection in the microsecond gap
    // would try to look up accel_cubic right as it's disappearing.
    if let Some(orig_v4) = state.original_cc_ipv4.as_deref() {
        let orig_v6 = state.original_cc_ipv6.as_deref();
        match algo::set_cc(orig_v4, orig_v6) {
            Ok(()) => {
                let v6_note = orig_v6
                    .map(|v| format!(" / {v} (ipv6)"))
                    .unwrap_or_default();
                println!("sysctl restored: tcp_congestion_control={orig_v4}{v6_note}");
            }
            Err(e) => eprintln!("warning: could not restore sysctl to {orig_v4}: {e:#}"),
        }
    }

    // Explicitly drop the algo while state is reachable, so unregister-
    // related log lines land before socket removal.
    if let Some(algo) = state.algo.lock().ok().and_then(|mut g| g.take()) {
        println!("unregistering struct_ops {}...", algo.name);
        drop(algo);
    }
    let _ = std::fs::remove_file(&socket_path);
    let _ = incidents::append(Event::Shutdown { reason: "clean" });
    Ok(())
}

/// Scan `dmesg` for the most recent "Killed process <pid> (accel)" line,
/// indicating the previous run died to OOM. Returns the victim pid if
/// found. Best-effort: needs root and a recent ring buffer, silently
/// returns None if dmesg can't be read.
fn scan_dmesg_oom() -> Option<u32> {
    let out = Command::new("dmesg").output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines().rev() {
        let lower = line.to_lowercase();
        if lower.contains("killed process") && lower.contains("(accel") {
            // Pattern: "... Killed process 12345 (accel) ..."
            if let Some(tail) = lower.split("killed process").nth(1) {
                if let Some(pid_str) = tail.split_whitespace().next() {
                    return pid_str.parse().ok();
                }
            }
            return None;
        }
    }
    None
}

fn jit_enabled() -> bool {
    std::fs::read_to_string("/proc/sys/net/core/bpf_jit_enable")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .map(|v| v != 0)
        .unwrap_or(true)
}

/// If the captured sysctl value is the same algorithm we're about to
/// load (rare edge case: previous accel run crashed and left sysctl
/// pointing at accel_cubic), substitute a built-in fallback. Otherwise
/// return the value unchanged. `None` in → `None` out.
fn capture_cc_with_fallback(captured: Option<String>, target: &str) -> Option<String> {
    let captured = captured?;
    if captured != target {
        return Some(captured);
    }
    // Pick the most preferred fallback that's currently registered.
    // At startup (before we load target) every kernel built-in should be
    // registered, so the first candidate usually wins.
    for candidate in ["bbr", "cubic", "reno"] {
        if algo::is_registered(candidate).unwrap_or(false) {
            eprintln!(
                "note: pre-accel sysctl was already {captured}; will restore to {candidate} on exit"
            );
            return Some(candidate.to_string());
        }
    }
    // Last resort: cubic is always compiled into Linux.
    Some("cubic".to_string())
}
