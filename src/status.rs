use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::algo;
use crate::ebpf_loader::LoadedAlgo;

/// Resolved-form snapshot of `acc.conf [smart]` set at startup. The raw
/// `SmartConfig` (config.rs) holds user input; this struct holds the
/// post-validation runtime values: rate already converted to byte/s,
/// interface name resolved to ifindex, port range parsed. health.rs
/// consults it to re-apply settings if accel_smart is reloaded after
/// an external unregister; status.rs reads it for display.
#[derive(Clone)]
pub struct SmartSavedCfg {
    pub rate_bytes: u64,
    pub interface: String,
    pub ifindex: u32,
    pub loss_lossy_bp: u32,
    pub loss_congest_bp: u32,
    pub rtt_congest_pct: u32,
    pub port_min: u16,
    pub port_max: u16,
}

/// Shared state published to the socket server for status requests.
///
/// 2.3-D3 changed `algo: Option<LoadedAlgo>` (single-slot) to
/// `algos: HashMap<String, LoadedAlgo>` (multi-slot). All loaded
/// algorithms live concurrently in the kernel; the user picks one as
/// "target" via sysctl, but the others stay registered and can be
/// switched-to instantly via `./accel algo switch`.
pub struct State {
    pub pid: u32,
    pub started_at: Instant,
    pub socket_path: PathBuf,
    /// All algorithms successfully loaded at startup (cubic, brutal, …).
    /// health.rs may take/replace individual entries on reload.
    pub algos: Arc<Mutex<HashMap<String, LoadedAlgo>>>,
    /// The algorithm name accel *wants* the kernel to be using right now.
    /// Changes when `./accel algo switch` is called.
    pub target_algo: Arc<Mutex<String>>,
    /// Captured at startup; restored on clean shutdown.
    pub original_cc_ipv4: Option<String>,
    pub original_cc_ipv6: Option<String>,
    /// `Some(rate_mbps)` iff `accel_brutal` was loaded; consumed by
    /// health.rs to re-apply rate after a brutal reload.
    pub brutal_rate_mbps: Option<u32>,
    /// `Some(_)` iff accel_smart was the startup target and the
    /// `[smart]` section validated. Consumed by health.rs to re-apply
    /// config + dup_config + tc attach after a smart reload.
    pub smart_saved: Option<SmartSavedCfg>,
    pub health_shutting_down: AtomicBool,
    pub health_last_ok: Mutex<Option<Instant>>,
    pub jit_warned: AtomicBool,
}

pub fn render(state: &State) -> String {
    let uptime = state.started_at.elapsed();
    let cpu_pct = read_cpu_pct(uptime).unwrap_or(-1.0);
    let mem_mb = read_rss_mb().unwrap_or(0);

    let loaded_names = state
        .algos
        .lock()
        .ok()
        .map(|g| {
            let mut names: Vec<String> = g.keys().cloned().collect();
            names.sort();
            names
        })
        .unwrap_or_default();
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
    let _ = writeln!(s, "  version:           {version}");
    let _ = writeln!(s, "  running:           yes (pid={})", state.pid);
    let _ = writeln!(s, "  uptime:            {}", format_uptime(uptime));
    let _ = writeln!(s, "  socket:            {}", state.socket_path.display());
    let _ = writeln!(s);
    let _ = writeln!(s, "algorithm:");
    let loaded_str = if loaded_names.is_empty() {
        "none".to_string()
    } else {
        loaded_names.join(", ")
    };
    let _ = writeln!(s, "  loaded by accel:   {loaded_str}");
    let _ = writeln!(s, "  target:            {target}");
    match &sysctl_v6 {
        Some(v6) => {
            let _ = writeln!(
                s,
                "  kernel sysctl:     {sysctl_v4} (ipv4) / {v6} (ipv6)"
            );
        }
        None => {
            let _ = writeln!(s, "  kernel sysctl:     {sysctl_v4} (ipv4)");
        }
    }
    let _ = writeln!(s, "  available (kernel):{available}");
    let _ = writeln!(s, "  jit:               {jit}");
    if let Some(rate_mbps) = state.brutal_rate_mbps {
        let _ = writeln!(s, "  brutal rate:       {rate_mbps} Mbps");
    }
    if let Some(saved) = state.smart_saved.as_ref() {
        // 1 Mbps = 125_000 byte/s.
        let rate_mbps = saved.rate_bytes / 125_000;
        let _ = writeln!(s, "  smart rate:        {rate_mbps} Mbps");
        let _ = writeln!(
            s,
            "  smart thresholds:  lossy={}bp congest={}bp rtt={}%",
            saved.loss_lossy_bp, saved.loss_congest_bp, saved.rtt_congest_pct
        );
        let _ = writeln!(
            s,
            "  smart interface:   {} (tc-bpf attached)",
            saved.interface
        );
        if saved.port_min > 0 {
            let _ = writeln!(
                s,
                "  smart dup ports:   {}-{}",
                saved.port_min, saved.port_max
            );
        } else {
            let _ = writeln!(s, "  smart dup ports:   all TCP");
        }
    }
    if sysctl_v4 != target {
        let _ = writeln!(
            s,
            "  WARNING:           kernel sysctl ({sysctl_v4}) differs from target ({target}); \
             health check will reconcile"
        );
    }

    let _ = writeln!(s);
    let _ = writeln!(s, "connections:");
    render_connections(state, &mut s);

    let _ = writeln!(s);
    let _ = writeln!(s, "reliability:");
    render_reliability(state, &mut s);

    let _ = writeln!(s);
    if cpu_pct >= 0.0 {
        let _ = writeln!(s, "  cpu:               {cpu_pct:.1}%");
    } else {
        let _ = writeln!(s, "  cpu:               ?");
    }
    let _ = writeln!(s, "  mem:               {mem_mb} MB");
    s
}

/// Connections section (2.3-D3 new):
///   total tcp:        from /proc/net/tcp + tcp6 (line count - header)
///   brutal sockets:   from accel_brutal's BPF socket-count map
fn render_connections(state: &State, s: &mut String) {
    let total = read_total_tcp_sockets();
    let _ = match total {
        Some(n) => writeln!(s, "  total tcp:         {n}"),
        None => writeln!(s, "  total tcp:         ?"),
    };

    // brutal_sockets only when brutal is currently loaded
    let brutal_count = state.algos.lock().ok().and_then(|g| {
        g.get("accel_brutal").and_then(|a| match a {
            LoadedAlgo::Brutal(b) => b.socket_count().ok(),
            // Reachable only if a future variant aliases the name; defensive.
            _ => None,
        })
    });
    if let Some(n) = brutal_count {
        let _ = writeln!(s, "  brutal sockets:    {n}");
    }

    // smart_sockets + state distribution only when smart is currently loaded.
    let smart_info = state.algos.lock().ok().and_then(|g| {
        g.get("accel_smart").and_then(|a| match a {
            LoadedAlgo::Smart(sm) => {
                let count = sm.socket_count().ok()?;
                let states = sm.state_counts().ok()?;
                Some((count, states))
            }
            _ => None,
        })
    });
    if let Some((count, [good, lossy, congest])) = smart_info {
        let _ = writeln!(s, "  smart sockets:     {count}");
        let total = good + lossy + congest;
        if total > 0 {
            let _ = writeln!(
                s,
                "  smart state:       GOOD {} ({}%) | LOSSY {} ({}%) | CONGEST {} ({}%)",
                good,
                good * 100 / total,
                lossy,
                lossy * 100 / total,
                congest,
                congest * 100 / total
            );
        }
    }
}

/// Total TCP sockets across IPv4 and IPv6. Reads /proc/net/tcp and tcp6.
/// Each file's first line is a header; data lines = total entries.
fn read_total_tcp_sockets() -> Option<u64> {
    let mut total = 0u64;
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        match fs::read_to_string(path) {
            Ok(text) => {
                let lines = text.lines().count() as u64;
                total += lines.saturating_sub(1); // minus header
            }
            // /proc/net/tcp6 may be absent on CONFIG_IPV6=n kernels.
            Err(_) if path.ends_with("tcp6") => {}
            Err(_) => return None,
        }
    }
    Some(total)
}

fn render_reliability(state: &State, s: &mut String) {
    let uptime = state.started_at.elapsed();
    let _ = writeln!(s, "  current uptime:    {}", format_uptime(uptime));

    let restore = state
        .original_cc_ipv4
        .as_deref()
        .unwrap_or("(not captured)");
    let _ = writeln!(s, "  will restore to:   {restore}");

    let (restarts, last_reason) = incident_history_summary();
    let _ = writeln!(s, "  restarts:          {restarts}");
    let _ = writeln!(s, "  last shutdown:     {last_reason}");

    let hc = match state.health_last_ok.lock() {
        Ok(g) => g.map(|t| t.elapsed()),
        Err(_) => None,
    };
    match hc {
        Some(d) => {
            let secs = d.as_secs();
            let _ = writeln!(
                s,
                "  health check:      every 30s, last ok {secs}s ago"
            );
        }
        None => {
            let _ = writeln!(s, "  health check:      every 30s, first tick pending");
        }
    }

    if let Some(p) = crate::incidents::path() {
        let _ = writeln!(s, "  incident log:      {}", p.display());
    }
}

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
    (restarts, last_reason.unwrap_or_else(|| "none".to_string()))
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

fn read_cpu_pct(uptime: Duration) -> Option<f64> {
    let stat = fs::read_to_string("/proc/self/stat").ok()?;
    let after = stat.rsplit_once(')').map(|(_, r)| r)?;
    let fields: Vec<&str> = after.split_whitespace().collect();
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
