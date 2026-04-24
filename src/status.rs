use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Shared state published to the socket server for status requests.
///
/// Day 2 carries only the truly invariant fields. The algorithm / health
/// related fields land here in Day 4 as the real struct_ops loading goes in.
pub struct State {
    pub pid: u32,
    pub started_at: Instant,
    pub socket_path: PathBuf,
}

pub fn render(state: &State) -> String {
    let uptime = state.started_at.elapsed();
    let cpu_pct = read_cpu_pct(uptime).unwrap_or(-1.0);
    let mem_mb = read_rss_mb().unwrap_or(0);
    let kernel_cc = read_kernel_cc().unwrap_or_else(|| "?".into());

    let version = concat!(
        env!("CARGO_PKG_VERSION_MAJOR"),
        ".",
        env!("CARGO_PKG_VERSION_MINOR")
    );

    let mut s = String::new();
    let _ = writeln!(s, "accel status:");
    let _ = writeln!(s, "  version:     {version}");
    let _ = writeln!(s, "  running:     yes (pid={})", state.pid);
    let _ = writeln!(s, "  uptime:      {}", format_uptime(uptime));
    let _ = writeln!(s, "  socket:      {}", state.socket_path.display());
    let _ = writeln!(s);
    let _ = writeln!(s, "algorithm:");
    let _ = writeln!(s, "  loaded:      none (migration in progress, 2.1-D2 checkpoint)");
    let _ = writeln!(s, "  active:      {kernel_cc} (kernel default)");
    let _ = writeln!(s, "  note:        accel framework ready, algorithm will load in 2.1-D4");
    let _ = writeln!(s);
    if cpu_pct >= 0.0 {
        let _ = writeln!(s, "  cpu:         {cpu_pct:.1}%");
    } else {
        let _ = writeln!(s, "  cpu:         ?");
    }
    let _ = writeln!(s, "  mem:         {mem_mb} MB");
    s
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

fn read_kernel_cc() -> Option<String> {
    fs::read_to_string("/proc/sys/net/ipv4/tcp_congestion_control")
        .ok()
        .map(|s| s.trim().to_string())
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
