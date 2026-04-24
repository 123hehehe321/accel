//! TCP congestion-control sysctl helpers.
//!
//! No state, no daemon state: every function is a direct read/write on
//! `/proc/sys/net/ipv{4,6}/tcp_*`. `bpftool` is NOT called — once a
//! struct_ops algorithm is registered via libbpf-rs, the kernel exposes
//! it through `tcp_available_congestion_control` just like its built-in
//! algorithms.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

const AVAILABLE: &str = "/proc/sys/net/ipv4/tcp_available_congestion_control";
const SYSCTL_V4: &str = "/proc/sys/net/ipv4/tcp_congestion_control";
const SYSCTL_V6: &str = "/proc/sys/net/ipv6/tcp_congestion_control";

/// All congestion-control algorithms the kernel currently knows about
/// (built-in `cubic` / `bbr` / `reno` plus anything registered via
/// struct_ops, including our `accel_*`).
pub fn list_available() -> Result<Vec<String>> {
    let raw = fs::read_to_string(AVAILABLE)
        .with_context(|| format!("reading {AVAILABLE}"))?;
    Ok(raw.split_whitespace().map(String::from).collect())
}

pub fn is_registered(name: &str) -> Result<bool> {
    Ok(list_available()?.iter().any(|n| n == name))
}

/// The CC algorithm the IPv4 stack is currently using.
pub fn current_cc_ipv4() -> Result<String> {
    fs::read_to_string(SYSCTL_V4)
        .map(|s| s.trim().to_string())
        .with_context(|| format!("reading {SYSCTL_V4}"))
}

/// The CC algorithm the IPv6 stack is currently using. Returns `None` if
/// the v6 sysctl doesn't exist (some CONFIG_IPV6=n kernels).
pub fn current_cc_ipv6() -> Option<String> {
    fs::read_to_string(SYSCTL_V6)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Set both IPv4 and IPv6 sysctls to `name`. Fails fast if `name` is not
/// a registered algorithm (the kernel would reject the write with EINVAL
/// anyway, but we give a nicer error). IPv6 is best-effort: if the sysctl
/// is absent we silently skip.
pub fn set_cc_both(name: &str) -> Result<()> {
    set_cc(name, Some(name))
}

/// Like [`set_cc_both`] but lets the caller pass distinct IPv4 and IPv6
/// names — used at shutdown to restore whatever the kernel had *before*
/// accel started (v4 and v6 may differ in principle, though in practice
/// they track one another).
pub fn set_cc(v4: &str, v6: Option<&str>) -> Result<()> {
    if !is_registered(v4)? {
        bail!(
            "algorithm '{v4}' is not registered in {AVAILABLE} (load it first via './accel'; \
             currently available: {})",
            list_available()?.join(" ")
        );
    }
    fs::write(SYSCTL_V4, v4)
        .with_context(|| format!("writing '{v4}' to {SYSCTL_V4}"))?;
    if let Some(v6_name) = v6 {
        if Path::new(SYSCTL_V6).exists() {
            // Best-effort: v6 may fail on some weird configs; don't abort.
            let _ = fs::write(SYSCTL_V6, v6_name);
        }
    }
    Ok(())
}
