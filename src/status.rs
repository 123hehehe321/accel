use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use aya::maps::{MapData, PerCpuArray};

use crate::mode::ResolvedMode;

/// Shared state published to the socket server for status requests.
/// All fields here are cheap to access; fields that can change at runtime
/// (iface_state, jit, cpu/mem, stats) are re-read fresh on every status call
/// inside `render()`.
pub struct State {
    pub pid: u32,
    pub started_at: Instant,
    pub iface: String,
    pub iface_driver: Option<String>,
    pub ports: String,
    pub mode: ResolvedMode,
    pub socket_path: PathBuf,
    pub stats: PerCpuArray<MapData, u64>,
}

pub fn render(state: &State) -> String {
    let uptime = state.started_at.elapsed();
    let iface_state = read_iface_state(&state.iface);
    let jit = read_jit_state();
    let cpu_pct = read_cpu_pct(uptime).unwrap_or(-1.0);
    let mem_mb = read_rss_mb().unwrap_or(0);

    let (accel, pass) = match (
        state.stats.get(&0, 0).map(|v| v.iter().sum::<u64>()),
        state.stats.get(&1, 0).map(|v| v.iter().sum::<u64>()),
    ) {
        (Ok(a), Ok(p)) => (a, p),
        _ => (0, 0),
    };
    let total = accel + pass;
    let ratio = if total > 0 {
        accel as f64 * 100.0 / total as f64
    } else {
        0.0
    };

    let driver = state.iface_driver.as_deref().unwrap_or("?");
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
    let _ = writeln!(s);
    let _ = writeln!(s, "  iface:       {} ({driver})", state.iface);
    let _ = writeln!(s, "  iface_state: {iface_state}");
    let _ = writeln!(s, "  mode:        {}", state.mode);
    let _ = writeln!(s, "  jit:         {jit}");
    let _ = writeln!(s, "  ports:       {}", state.ports);
    let _ = writeln!(s, "  socket:      {}", state.socket_path.display());
    let _ = writeln!(s);
    if cpu_pct >= 0.0 {
        let _ = writeln!(s, "  cpu:         {cpu_pct:.1}%");
    } else {
        let _ = writeln!(s, "  cpu:         ?");
    }
    let _ = writeln!(s, "  mem:         {mem_mb} MB");
    let _ = writeln!(s);
    let _ = writeln!(s, "  stats:");
    let _ = writeln!(s, "    pkt_total:    {:>15}", thousands(total));
    let _ = writeln!(s, "    pkt_accel:    {:>15}", thousands(accel));
    let _ = writeln!(s, "    accel_ratio:  {:>14.1}%", ratio);
    s
}

pub fn read_iface_driver(iface: &str) -> Option<String> {
    let link = fs::read_link(format!("/sys/class/net/{iface}/device/driver")).ok()?;
    link.file_name()?.to_str().map(|s| s.to_string())
}

fn read_iface_state(iface: &str) -> String {
    fs::read_to_string(format!("/sys/class/net/{iface}/operstate"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".to_string())
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

fn thousands(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thousands_basic() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(12), "12");
        assert_eq!(thousands(1234), "1,234");
        assert_eq!(thousands(1234567), "1,234,567");
        assert_eq!(thousands(1000), "1,000");
    }

    #[test]
    fn uptime_formats() {
        assert_eq!(format_uptime(Duration::from_secs(5)), "5s");
        assert_eq!(format_uptime(Duration::from_secs(125)), "2m 5s");
        assert_eq!(format_uptime(Duration::from_secs(3723)), "1h 2m");
    }
}
