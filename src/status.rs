use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::algo;
use crate::ebpf_loader::LoadedAlgo;

/// Shared state published to the socket server for status requests.
///
/// - `algo` holds the registered struct_ops link; dropping it
///   unregisters. `Option<_>` because 2.1-D5 health.rs takes / replaces
///   the inner value during reload.
/// - `target_algo` is the name accel *wants* active on IPv4+IPv6. It
///   changes on `./accel algo switch`; `health.rs` reconciles kernel
///   sysctl back to it on drift.
/// - `health_shutting_down` is flipped by main before cleanup so the
///   health thread exits its tick loop within 500 ms.
/// - `health_last_ok` is the wall-clock time of the last completed
///   health tick (None until the first tick).
/// - `jit_warned` suppresses JIT-disabled log spam across ticks.
pub struct State {
    pub pid: u32,
    pub started_at: Instant,
    pub socket_path: PathBuf,
    pub algo: Arc<Mutex<Option<LoadedAlgo>>>,
    pub target_algo: Arc<Mutex<String>>,
    pub health_shutting_down: AtomicBool,
    pub health_last_ok: Mutex<Option<Instant>>,
    pub jit_warned: AtomicBool,
}

pub fn render(state: &State) -> String {
    let uptime = state.started_at.elapsed();
    let cpu_pct = read_cpu_pct(uptime).unwrap_or(-1.0);
    let mem_mb = read_rss_mb().unwrap_or(0);

    let loaded_name = state
        .algo
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|a| a.name.to_string()));
    let target = state
        .target_algo
        .lock()
        .map(|g| g.clone())
        .unwrap_or_else(|_| "?".to_string());

    let available = algo::list_available()
        .map(|v| v.join(" "))
        .unwrap_or_else(|_| "?".to_string());
    let sysctl_v4 = algo::current_cc_ipv4().unwrap_or_else(|_| "?".to_string());
    let sysctl_v6 = algo::current_cc_ipv6();
    let jit = read_jit_state();

    let version = concat!(
        env!("CARGO_PKG_VERSION_MAJOR"),
        ".",
        env!("CARGO_PKG_VERSION_MINOR")
    );

    let mut s = String::new();
    let _ = writeln!(s, "accel status:");
    let _ = writeln!(s, "  version:       {version}");
    let _ = writeln!(s, "  running:       yes (pid={})", state.pid);
    let _ = writeln!(s, "  uptime:        {}", format_uptime(uptime));
    let _ = writeln!(s, "  socket:        {}", state.socket_path.display());
    let _ = writeln!(s);
    let _ = writeln!(s, "algorithm:");
    match &loaded_name {
        Some(n) => {
            let _ = writeln!(s, "  loaded:        {n}");
        }
        None => {
            let _ = writeln!(s, "  loaded:        none");
        }
    }
    let _ = writeln!(s, "  target:        {target}");
    match &sysctl_v6 {
        Some(v6) => {
            let _ = writeln!(
                s,
                "  kernel sysctl: {sysctl_v4} (ipv4) / {v6} (ipv6)"
            );
        }
        None => {
            let _ = writeln!(s, "  kernel sysctl: {sysctl_v4} (ipv4)");
        }
    }
    let _ = writeln!(s, "  available:     {available}");
    let _ = writeln!(s, "  jit:           {jit}");

    // Sysctl / target mismatch hint — 2.1-D5 health.rs will auto-reconcile;
    // D4 only reports.
    if sysctl_v4 != target {
        let _ = writeln!(
            s,
            "  WARNING:       kernel sysctl ({sysctl_v4}) differs from target ({target}); \
             2.1-D5 health check will reconcile, currently manual"
        );
    }

    let _ = writeln!(s);
    let _ = writeln!(s, "reliability:");
    render_reliability(state, &mut s);

    let _ = writeln!(s);
    if cpu_pct >= 0.0 {
        let _ = writeln!(s, "  cpu:           {cpu_pct:.1}%");
    } else {
        let _ = writeln!(s, "  cpu:           ?");
    }
    let _ = writeln!(s, "  mem:           {mem_mb} MB");
    s
}

fn render_reliability(state: &State, s: &mut String) {
    let uptime = state.started_at.elapsed();
    let _ = writeln!(s, "  current uptime:  {}", format_uptime(uptime));

    // Stats from the incident log.
    let (restarts, last_reason) = incident_history_summary();
    let _ = writeln!(s, "  restarts:        {restarts}");
    let _ = writeln!(s, "  last shutdown:   {last_reason}");

    // Health tick age.
    let hc = match state.health_last_ok.lock() {
        Ok(g) => g.map(|t| t.elapsed()),
        Err(_) => None,
    };
    match hc {
        Some(d) => {
            let secs = d.as_secs();
            let _ = writeln!(
                s,
                "  health check:    every 30s, last ok {secs}s ago"
            );
        }
        None => {
            let _ = writeln!(s, "  health check:    every 30s, first tick pending");
        }
    }

    // Path to the log so users know where to look.
    if let Some(p) = crate::incidents::path() {
        let _ = writeln!(s, "  incident log:    {}", p.display());
    }
}

/// Cheap one-pass scan of the incident log to produce two numbers:
/// number of `startup` records seen (= total restarts logged) and the
/// reason field of the most recent `shutdown` record. Anything fancier
/// (per-event-type counts, 7-day windows) can be added later if users
/// actually want it.
fn incident_history_summary() -> (usize, String) {
    let Some(path) = crate::incidents::path() else {
        return (0, "unknown".to_string());
    };
    let Ok(text) = fs::read_to_string(path) else {
        return (0, "none".to_string());
    };
    let mut restarts = 0usize;
    let mut last_reason: Option<String> = None;
    for line in text.lines() {
        if line.contains("| startup") {
            restarts += 1;
        } else if line.contains("| shutdown") {
            if let Some(r) = line.split("reason=").nth(1) {
                last_reason = Some(r.trim().to_string());
            }
        }
    }
    (
        restarts,
        last_reason.unwrap_or_else(|| "none".to_string()),
    )
}

fn read_rss_mb() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb / 1024);
        }
    }
    None
}

fn read_jit_state() -> &'static str {
    match fs::read_to_string("/proc/sys/net/core/bpf_jit_enable") {
        Ok(v) => match v.trim().parse::<u32>().unwrap_or(0) {
            0 => "disabled",
            _ => "enabled",
        },
        Err(_) => "?",
    }
}

/// Cumulative CPU% since process start. One-shot read, no sampling thread.
fn read_cpu_pct(uptime: Duration) -> Option<f64> {
    let stat = fs::read_to_string("/proc/self/stat").ok()?;
    // fields after the comm field in parens; comm can contain spaces so find
    // the last ')' and split from there.
    let after = stat.rsplit_once(')').map(|(_, r)| r)?;
    let fields: Vec<&str> = after.split_whitespace().collect();
    // post-')': state(0) ppid(1) pgrp(2) session(3) tty(4) tpgid(5) flags(6)
    // minflt(7) cminflt(8) majflt(9) cmajflt(10) utime(11) stime(12)
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
    if clk_tck <= 0.0 {
        return None;
    }
    let cpu_secs = (utime + stime) as f64 / clk_tck;
    let up_secs = uptime.as_secs_f64();
    if up_secs <= 0.0 {
        return Some(0.0);
    }
    Some(cpu_secs * 100.0 / up_secs)
}

fn format_uptime(d: Duration) -> String {
    let total = d.as_secs();
    let (h, rem) = (total / 3600, total % 3600);
    let (m, s) = (rem / 60, rem % 60);
    if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime_formats() {
        assert_eq!(format_uptime(Duration::from_secs(5)), "5s");
        assert_eq!(format_uptime(Duration::from_secs(125)), "2m 5s");
        assert_eq!(format_uptime(Duration::from_secs(3723)), "1h 2m");
    }
}
