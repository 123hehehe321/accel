//! Append-only text log of operational incidents.
//!
//! Events go to either `./accel-incidents.log` (manual start) or
//! `/run/accel/accel-incidents.log` (systemd start). The file grows to
//! at most ~500 lines before being truncated to the newest ~250.
//!
//! Format: one event per line —
//!     `2026-04-24T10:15:32Z | event_name       | key=value key=value`
//!
//! No external logging crate, no daemons: just serialized appends behind
//! a process-wide `Mutex`.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, Context, Result};

static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();
static APPEND_LOCK: Mutex<()> = Mutex::new(());

const ROTATE_HIGH: usize = 500;
const ROTATE_KEEP: usize = 250;

#[derive(Debug)]
pub enum Event {
    Startup {
        pid: u32,
        kernel: String,
        last_shutdown: String,
    },
    Shutdown {
        reason: &'static str,
    },
    AlgoRelost {
        name: String,
    },
    SysctlReset {
        from: String,
        to: String,
    },
    JitDisabled,
    OomKilled {
        previous_pid: Option<u32>,
    },
}

pub fn resolve_path() -> PathBuf {
    if std::env::var_os("INVOCATION_ID").is_some() {
        let dir = PathBuf::from("/run/accel");
        if fs::create_dir_all(&dir).is_ok() {
            return dir.join("accel-incidents.log");
        }
    }
    PathBuf::from("./accel-incidents.log")
}

pub fn init(path: PathBuf) {
    let _ = LOG_PATH.set(path);
}

pub fn path() -> Option<&'static Path> {
    LOG_PATH.get().map(|p| p.as_path())
}

pub fn append(event: Event) -> Result<()> {
    let path = LOG_PATH
        .get()
        .ok_or_else(|| anyhow!("incident log path not initialized"))?;
    let _lock = APPEND_LOCK
        .lock()
        .map_err(|e| anyhow!("append lock poisoned: {e}"))?;
    let line = format!("{} | {}\n", utc_now_rfc3339(), render(&event));
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    f.write_all(line.as_bytes())
        .with_context(|| format!("writing to {}", path.display()))?;
    drop(f);
    rotate_if_large(path)?;
    Ok(())
}

fn render(e: &Event) -> String {
    match e {
        Event::Startup { pid, kernel, last_shutdown } => format!(
            "startup          | pid={pid} kernel={kernel} last_shutdown={last_shutdown}"
        ),
        Event::Shutdown { reason } => format!("shutdown         | reason={reason}"),
        Event::AlgoRelost { name } => format!("algo_relost      | name={name}"),
        Event::SysctlReset { from, to } => format!("sysctl_reset     | from={from} to={to}"),
        Event::JitDisabled => "jit_disabled     | detected".to_string(),
        Event::OomKilled { previous_pid } => {
            let pid = previous_pid.map_or_else(|| "?".to_string(), |p| p.to_string());
            format!("oom_killed       | previous_pid={pid}")
        }
    }
}

fn rotate_if_large(path: &Path) -> Result<()> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Ok(()),
    };
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() <= ROTATE_HIGH {
        return Ok(());
    }
    let start = lines.len().saturating_sub(ROTATE_KEEP);
    let kept = lines[start..].join("\n") + "\n";
    fs::write(path, kept).with_context(|| format!("rotating {}", path.display()))?;
    Ok(())
}

/// Inspect the log to figure out how the previous run ended. Scans from
/// newest to oldest: the first `shutdown` row gives the reason; if we
/// hit a `startup` without a prior `shutdown` the previous run crashed.
pub fn last_shutdown_reason() -> String {
    let Some(p) = LOG_PATH.get() else {
        return "unknown (log not initialized)".into();
    };
    let Ok(text) = fs::read_to_string(p) else {
        return "none (first run)".into();
    };
    for line in text.lines().rev() {
        if line.contains("| shutdown") {
            if let Some(reason) = line.split("reason=").nth(1) {
                return reason.trim().to_string();
            }
        }
        if line.contains("| startup") {
            return "crash (startup without preceding shutdown)".into();
        }
    }
    "none (first run)".into()
}

pub fn read_kernel_release() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn utc_now_rfc3339() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: gmtime_r is thread-safe; we pass a stack-allocated, zeroed
    // tm that libc fully overwrites. No pointers returned out.
    unsafe { libc::gmtime_r(&now, &mut tm) };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}
