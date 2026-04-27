use std::collections::HashMap;
use std::ffi::CString;
use std::panic::{self, AssertUnwindSafe};
use std::path::Path;
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};

use crate::ebpf_loader::LoadedAlgo;
use crate::incidents::{self, Event};
use crate::status::SmartSavedCfg;
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
    let sock = socket::resolve_client_path(&cfg.runtime.socket);
    socket::client_roundtrip(&sock, "status")
}

fn run_stop() -> Result<()> {
    let cfg = config::load(Path::new(CONFIG_PATH))?;
    let sock = socket::resolve_client_path(&cfg.runtime.socket);
    socket::client_roundtrip(&sock, "stop")
}

fn run_algo(args: &[String]) -> Result<()> {
    let cfg = config::load(Path::new(CONFIG_PATH))?;
    let sock = socket::resolve_client_path(&cfg.runtime.socket);
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
    println!("hello accel (v0.2, 2.3-D3)");
    println!();

    preflight()?;

    let cfg = config::load(Path::new(CONFIG_PATH))?;

    println!("config loaded from: {CONFIG_PATH}");
    println!("  algorithm = {:?}", cfg.algorithm);
    if let Some(b) = &cfg.brutal {
        println!("  [brutal]");
        println!("    rate_mbps = {}", b.rate_mbps);
    }
    println!("  [runtime]");
    let socket_display = if cfg.runtime.socket.is_empty() {
        "\"\" (auto-detect)".to_string()
    } else {
        format!("{:?}", cfg.runtime.socket)
    };
    println!("    socket    = {socket_display}");
    println!();

    // Incident log + startup record before any kernel side-effect.
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

    // Load every algorithm we can. Individual failures are warnings, not
    // fatal — only the user-chosen `cfg.algorithm` is required to load.
    println!("loading algorithms into kernel...");
    let mut loaded_algos = ebpf_loader::load_all();
    if loaded_algos.is_empty() {
        bail!(
            "no algorithms loaded — check `dmesg | tail` for verifier errors. \
             struct_ops.link requires Linux 6.4+ with CONFIG_DEBUG_INFO_BTF=y."
        );
    }
    let mut names: Vec<String> = loaded_algos.keys().cloned().collect();
    names.sort();
    println!("  loaded: {}", names.join(", "));

    // Skip-subnet handling. Required field — production safety: no
    // silent default. Empty string ⇒ zero rules (every connection
    // accelerated, including loopback). Non-empty ⇒ strict CIDR list,
    // host bits beyond prefix MUST be zero.
    let skip_spec = cfg
        .skip_subnet
        .as_deref()
        .ok_or_else(|| {
            anyhow!(
                "acc.conf: skip_subnet is required. Set to \"\" if you genuinely \
                 want every connection accelerated; otherwise list CIDRs to bypass \
                 (e.g. \"127.0.0.0/8,10.0.0.0/8,192.168.0.0/16,::1/128\"). See \
                 acc.conf.example for a sensible default."
            )
        })?;
    let skip_rules = parse_skip_subnet(skip_spec)?;
    if skip_rules.len() > ebpf_loader::MAX_SKIP_RULES {
        bail!(
            "acc.conf: skip_subnet has {} rules; max is {}",
            skip_rules.len(),
            ebpf_loader::MAX_SKIP_RULES
        );
    }

    // Push the rule list into every algorithm's accel_skip_config map.
    // Match exhaustiveness here is the *compile-time* guarantee that a
    // future LoadedAlgo variant has implemented set_skip — which in
    // turn forces its BPF .c to `#include "accel_common.h"` (no map
    // declaration ⇒ no compilable set_skip ⇒ no compiling accel). See
    // ebpf/algorithms/accel_common.h header comment for full rationale.
    for (name, algo) in loaded_algos.iter_mut() {
        let result = match algo {
            LoadedAlgo::Cubic(c) => c.set_skip(&skip_rules),
            LoadedAlgo::Brutal(b) => b.set_skip(&skip_rules),
            LoadedAlgo::Smart(s) => s.set_skip(&skip_rules),
        };
        if let Err(e) = result {
            bail!("set_skip({name}) failed: {e:#}");
        }
    }
    if skip_rules.is_empty() {
        println!("  skip_subnet:       (empty — every connection accelerated)");
    } else {
        println!("  skip_subnet:       {} rule(s):", skip_rules.len());
        for s in skip_spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            println!("                       {s}");
        }
    }

    // The user-chosen algorithm must be among the loaded set.
    let target_name = cfg.algorithm.clone();
    if !loaded_algos.contains_key(&target_name) {
        bail!(
            "algorithm '{target_name}' specified in acc.conf failed to load. \
             Loaded: {:?}. Check dmesg for the specific verifier error.",
            names
        );
    }

    // If brutal is the target, [brutal] section is mandatory + write rate.
    let brutal_rate_mbps: Option<u32> = if target_name == "accel_brutal" {
        let brutal_cfg = cfg
            .brutal
            .as_ref()
            .ok_or_else(|| anyhow!("acc.conf: algorithm = \"accel_brutal\" requires [brutal] section"))?;
        if brutal_cfg.rate_mbps == 0 || brutal_cfg.rate_mbps > 100_000 {
            bail!(
                "acc.conf: [brutal].rate_mbps must be in 1..=100000, got {}",
                brutal_cfg.rate_mbps
            );
        }
        let rate_bytes = brutal_cfg.rate_mbps as u64 * 1_000_000 / 8;
        // SAFETY: we just verified target_name == "accel_brutal" and
        // loaded_algos.contains_key(&target_name); load_brutal()
        // produces LoadedAlgo::Brutal by construction; other variants
        // are impossible here.
        match loaded_algos
            .get_mut(&target_name)
            .expect("just verified loaded")
        {
            LoadedAlgo::Brutal(b) => b.set_rate(rate_bytes)?,
            LoadedAlgo::Cubic(_) | LoadedAlgo::Smart(_) => unreachable!(
                "accel_brutal name must map to LoadedAlgo::Brutal by ebpf_loader construction"
            ),
        }
        println!(
            "  brutal rate written: {} Mbps ({} byte/s)",
            brutal_cfg.rate_mbps, rate_bytes
        );
        Some(brutal_cfg.rate_mbps)
    } else {
        None
    };

    // If smart is the target, [smart] section is mandatory + write
    // smart_config_map / smart_dup_config / attach tc-bpf egress.
    let smart_saved: Option<SmartSavedCfg> = if target_name == "accel_smart" {
        let smart_cfg = cfg.smart.as_ref().ok_or_else(|| {
            anyhow!("acc.conf: algorithm = \"accel_smart\" requires [smart] section")
        })?;
        if smart_cfg.rate_mbps == 0 || smart_cfg.rate_mbps > 100_000 {
            bail!(
                "acc.conf: [smart].rate_mbps must be in 1..=100000, got {}",
                smart_cfg.rate_mbps
            );
        }
        let ifindex = read_ifindex(&smart_cfg.interface)?;
        let (port_min, port_max) = parse_port_range(&smart_cfg.duplicate_ports)?;
        let rate_bytes = smart_cfg.rate_mbps as u64 * 1_000_000 / 8;

        match loaded_algos
            .get_mut(&target_name)
            .expect("just verified loaded")
        {
            LoadedAlgo::Smart(sm) => {
                sm.set_config(
                    rate_bytes,
                    smart_cfg.loss_lossy_bp,
                    smart_cfg.loss_congest_bp,
                    smart_cfg.rtt_congest_pct,
                )?;
                sm.set_dup_config(ifindex, port_min, port_max)?;
                sm.attach_tc_egress(ifindex)?;
            }
            LoadedAlgo::Cubic(_) | LoadedAlgo::Brutal(_) => unreachable!(
                "accel_smart name must map to LoadedAlgo::Smart by ebpf_loader construction"
            ),
        }
        println!(
            "  smart config: {} Mbps, interface={} (ifindex={})",
            smart_cfg.rate_mbps, smart_cfg.interface, ifindex
        );
        println!(
            "  smart thresholds: lossy={}bp congest={}bp rtt={}%",
            smart_cfg.loss_lossy_bp, smart_cfg.loss_congest_bp, smart_cfg.rtt_congest_pct
        );
        if port_min > 0 {
            println!("  smart dup ports: {port_min}-{port_max}");
        } else {
            println!("  smart dup ports: all TCP");
        }
        println!("  tc-bpf attached: ifindex={ifindex} egress");
        Some(SmartSavedCfg {
            rate_bytes,
            interface: smart_cfg.interface.clone(),
            ifindex,
            loss_lossy_bp: smart_cfg.loss_lossy_bp,
            loss_congest_bp: smart_cfg.loss_congest_bp,
            rtt_congest_pct: smart_cfg.rtt_congest_pct,
            port_min,
            port_max,
        })
    } else {
        None
    };

    // Capture pre-accel sysctl, coercing away from any accel-loaded name
    // (we'd lose ability to restore once we drop those algos at shutdown).
    let original_cc_ipv4 =
        capture_cc_with_fallback(algo::current_cc_ipv4().ok(), &loaded_algos);
    let original_cc_ipv6 = capture_cc_with_fallback(algo::current_cc_ipv6(), &loaded_algos);
    match &original_cc_ipv4 {
        Some(v4) => println!("  capturing pre-accel sysctl: {v4} (will restore on clean stop)"),
        None => eprintln!(
            "warning: could not read current sysctl tcp_congestion_control;\
             clean shutdown will skip sysctl restore"
        ),
    }

    algo::set_cc_both(&target_name)
        .with_context(|| format!("setting sysctl tcp_congestion_control={target_name}"))?;
    println!(
        "  kernel sysctl set: tcp_congestion_control={target_name} (ipv4{})",
        if algo::current_cc_ipv6().is_some() {
            "+ipv6"
        } else {
            ""
        }
    );
    println!();

    let socket_path = socket::resolve_path(&cfg.runtime.socket);
    socket::prepare_path(&socket_path)?;
    let listener = socket::bind(&socket_path)?;
    println!("listening on {}", socket_path.display());

    let state = Arc::new(status::State {
        pid: std::process::id(),
        started_at: Instant::now(),
        socket_path: socket_path.clone(),
        algos: Arc::new(Mutex::new(loaded_algos)),
        target_algo: Arc::new(Mutex::new(target_name)),
        original_cc_ipv4,
        original_cc_ipv6,
        brutal_rate_mbps,
        smart_saved,
        skip_rules,
        health_shutting_down: AtomicBool::new(false),
        health_last_ok: Mutex::new(None),
        jit_warned: AtomicBool::new(false),
    });

    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

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

    health::spawn(Arc::clone(&state)).context("spawning health thread")?;

    let signal_tx = shutdown_tx.clone();
    ctrlc::set_handler(move || {
        let _ = signal_tx.send(());
    })
    .context("installing SIGINT/SIGTERM handler")?;

    println!("press ctrl+c to stop, or run './accel stop' from another terminal.");

    let _ = shutdown_rx.recv();

    println!("shutting down...");
    state.health_shutting_down.store(true, Ordering::Relaxed);

    // 1. Restore sysctl FIRST so new connections use the original CC.
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

    // 2. Drop all algorithms. HashMap::clear runs each LoadedAlgo's Drop,
    //    which fires Link::drop (unregister) then Skel::drop (close fds).
    //    Order across algorithms doesn't matter since each is independent
    //    in the kernel.
    if let Ok(mut g) = state.algos.lock() {
        let names: Vec<String> = g.keys().cloned().collect();
        if !names.is_empty() {
            println!("unregistering struct_ops: {}", names.join(", "));
        }
        g.clear();
    }

    let _ = std::fs::remove_file(&socket_path);
    let _ = incidents::append(Event::Shutdown { reason: "clean" });
    Ok(())
}

fn scan_dmesg_oom() -> Option<u32> {
    let out = Command::new("dmesg").output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines().rev() {
        let lower = line.to_lowercase();
        if lower.contains("killed process") && lower.contains("(accel") {
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

/// If the captured sysctl value is one of the algorithms accel itself
/// loaded (rare edge case: previous accel run crashed and left sysctl
/// pointing at accel_cubic / accel_brutal), substitute a built-in
/// fallback. Otherwise return the value unchanged.
///
/// Reasoning: at shutdown we'll drop our algorithms, after which
/// `sysctl -w tcp_congestion_control=accel_xxx` would EINVAL. A built-in
/// (bbr / cubic / reno) is always available regardless of accel state.
fn capture_cc_with_fallback(
    captured: Option<String>,
    accel_loaded: &HashMap<String, LoadedAlgo>,
) -> Option<String> {
    let captured = captured?;
    if !accel_loaded.contains_key(&captured) {
        return Some(captured); // already a kernel built-in
    }
    for candidate in ["bbr", "cubic", "reno"] {
        if algo::is_registered(candidate).unwrap_or(false) {
            eprintln!(
                "note: pre-accel sysctl was already {captured}; will restore to {candidate} on exit"
            );
            return Some(candidate.to_string());
        }
    }
    Some("cubic".to_string())
}

/// Pre-flight environment check. Runs before any kernel side-effect.
///
/// Catches the two failure modes that produce inscrutable libbpf errors:
///   1. Kernel < 6.4 (struct_ops.link not supported)
///   2. /sys/kernel/btf/vmlinux missing (CO-RE relocations impossible)
///
/// Other potential failures (no CAP_NET_ADMIN, JIT disabled, clsact
/// already owned, missing CONFIG_NET_CLS_BPF) bubble up as libbpf
/// errors with reasonably clear messages, so we don't add a check
/// for each — the maintenance cost outweighs the UX gain.
fn preflight() -> Result<()> {
    // Kernel version. /proc/sys/kernel/osrelease is the canonical source
    // (uname(2) reads it). Format: "6.12.74+deb12-amd64" — only the first
    // two integers ("6.12") are needed.
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .context("reading /proc/sys/kernel/osrelease")?;
    let release = release.trim();
    let mut parts = release.split('.');
    let major: u32 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("cannot parse kernel major from {release:?}"))?;
    let minor: u32 = parts
        .next()
        .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("cannot parse kernel minor from {release:?}"))?;
    let kver = (major, minor);
    if kver < (6, 4) {
        bail!(
            "preflight: 内核版本 {release} 不支持 struct_ops.link (需要 ≥ 6.4)\n  \
             Debian 12 修复: sudo apt install -t bookworm-backports linux-image-amd64 + reboot\n  \
             Debian 13: 默认内核已满足 (6.12+)"
        );
    }

    // BTF must be present for CO-RE. CONFIG_DEBUG_INFO_BTF=y enables this.
    if !Path::new("/sys/kernel/btf/vmlinux").exists() {
        bail!(
            "preflight: /sys/kernel/btf/vmlinux 不存在 (需要 CONFIG_DEBUG_INFO_BTF=y)\n  \
             绝大多数 Debian/Ubuntu 默认/backports 内核都启用; 若缺失多半是自编内核或精简发行版.\n  \
             需重装支持 BTF 的内核包."
        );
    }

    println!("preflight: kernel {release}, BTF present ✓");
    Ok(())
}

/// Resolve a network interface name (e.g. "eth0") to its kernel
/// ifindex. Wraps `if_nametoindex(3)`. Errors with a helpful message
/// when the interface doesn't exist — we can't proceed without an
/// ifindex to attach the tc/egress filter to.
fn read_ifindex(name: &str) -> Result<u32> {
    let cstr = CString::new(name)
        .with_context(|| format!("interface name {name:?} contains a NUL byte"))?;
    // SAFETY: `cstr` outlives the call; if_nametoindex reads only via
    // the pointer for the duration of the call. Returns 0 on failure
    // (unknown interface) and sets errno; we map 0 to a typed error.
    let idx = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
    if idx == 0 {
        let err = std::io::Error::last_os_error();
        bail!("interface {name:?} not found ({err}); set [smart].interface to an existing device (try `ip link`)");
    }
    Ok(idx)
}

/// Parse a port range string of the form `"min-max"`. An empty
/// string disables filtering and is encoded as `(0, 0)` — the
/// tc-bpf program treats `port_min == 0` as "clone every TCP packet
/// during LOSSY".
fn parse_port_range(s: &str) -> Result<(u16, u16)> {
    let s = s.trim();
    if s.is_empty() {
        return Ok((0, 0));
    }
    let (lo, hi) = s.split_once('-').ok_or_else(|| {
        anyhow!(
            "[smart].duplicate_ports must be either empty or \"min-max\", got {s:?}"
        )
    })?;
    let lo: u16 = lo
        .trim()
        .parse()
        .with_context(|| format!("[smart].duplicate_ports lower bound: {:?}", lo.trim()))?;
    let hi: u16 = hi
        .trim()
        .parse()
        .with_context(|| format!("[smart].duplicate_ports upper bound: {:?}", hi.trim()))?;
    if lo == 0 || hi == 0 {
        bail!("[smart].duplicate_ports endpoints must be > 0 (use \"\" to disable filtering)");
    }
    if lo > hi {
        bail!("[smart].duplicate_ports invalid: {lo} > {hi}");
    }
    Ok((lo, hi))
}

/// Parse the comma-separated CIDR list from `[runtime].skip_subnet`
/// into ready-to-ship `SkipRule`s. Strict mode: every entry must be
/// canonical (host bits beyond the prefix MUST be zero) and the
/// prefix length must be in range for the address family. Empty
/// input ⇒ zero rules (caller decides what that means).
fn parse_skip_subnet(spec: &str) -> Result<Vec<ebpf_loader::SkipRule>> {
    let mut out = Vec::new();
    for raw in spec.split(',') {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        out.push(parse_one_cidr(entry)?);
    }
    Ok(out)
}

/// Parse and validate a single CIDR entry. Strict semantics:
///   * exactly one '/' separator
///   * IP parses as Ipv4Addr or Ipv6Addr
///   * prefix is in 0..=32 (v4) or 0..=128 (v6)
///   * (ip & ~mask) == 0 — i.e. all host bits zero
fn parse_one_cidr(entry: &str) -> Result<ebpf_loader::SkipRule> {
    let (ip_str, prefix_str) = entry
        .split_once('/')
        .ok_or_else(|| anyhow!("CIDR {entry:?} missing '/' (e.g. \"10.0.0.0/8\")"))?;
    let ip_str = ip_str.trim();
    let prefix_str = prefix_str.trim();

    if let Ok(ip4) = ip_str.parse::<std::net::Ipv4Addr>() {
        let prefix: u32 = prefix_str
            .parse()
            .with_context(|| format!("CIDR {entry:?}: cannot parse prefix"))?;
        if prefix > 32 {
            bail!("CIDR {entry:?}: IPv4 prefix must be 0..=32 (got {prefix})");
        }
        let addr_h: u32 = u32::from(ip4);
        let mask = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix) };
        if addr_h & !mask != 0 {
            let canonical = std::net::Ipv4Addr::from(addr_h & mask);
            bail!(
                "CIDR {entry:?}: host bits beyond prefix /{prefix} are set. \
                 Did you mean \"{canonical}/{prefix}\"?"
            );
        }
        Ok(ebpf_loader::SkipRule {
            family: libc::AF_INET as u32,
            addr: [addr_h, 0, 0, 0],
            mask: [mask, 0, 0, 0],
        })
    } else if let Ok(ip6) = ip_str.parse::<std::net::Ipv6Addr>() {
        let prefix: u32 = prefix_str
            .parse()
            .with_context(|| format!("CIDR {entry:?}: cannot parse prefix"))?;
        if prefix > 128 {
            bail!("CIDR {entry:?}: IPv6 prefix must be 0..=128 (got {prefix})");
        }
        // Decompose the 128-bit address into 4 host-byte-order u32 words.
        let words: [u32; 4] = ip6.segments().chunks(2).map(|pair| {
            ((pair[0] as u32) << 16) | (pair[1] as u32)
        }).collect::<Vec<_>>().try_into().expect("4 chunks");
        // Build per-word mask from the 0..128 prefix.
        let mut mask = [0u32; 4];
        let mut remaining = prefix;
        for slot in mask.iter_mut() {
            if remaining >= 32 {
                *slot = !0u32;
                remaining -= 32;
            } else if remaining > 0 {
                *slot = (!0u32) << (32 - remaining);
                remaining = 0;
            } else {
                *slot = 0;
            }
        }
        for (w, &word) in words.iter().enumerate() {
            if word & !mask[w] != 0 {
                let canonical_words = [
                    words[0] & mask[0],
                    words[1] & mask[1],
                    words[2] & mask[2],
                    words[3] & mask[3],
                ];
                let canonical = std::net::Ipv6Addr::new(
                    (canonical_words[0] >> 16) as u16,
                    (canonical_words[0] & 0xFFFF) as u16,
                    (canonical_words[1] >> 16) as u16,
                    (canonical_words[1] & 0xFFFF) as u16,
                    (canonical_words[2] >> 16) as u16,
                    (canonical_words[2] & 0xFFFF) as u16,
                    (canonical_words[3] >> 16) as u16,
                    (canonical_words[3] & 0xFFFF) as u16,
                );
                bail!(
                    "CIDR {entry:?}: host bits beyond prefix /{prefix} are set. \
                     Did you mean \"{canonical}/{prefix}\"?"
                );
            }
        }
        Ok(ebpf_loader::SkipRule {
            family: libc::AF_INET6 as u32,
            addr: words,
            mask,
        })
    } else {
        bail!("CIDR {entry:?}: cannot parse \"{ip_str}\" as IPv4 or IPv6 address")
    }
}

#[cfg(test)]
mod tests {
    use super::parse_port_range;

    #[test]
    fn port_range_empty_is_no_filter() {
        assert_eq!(parse_port_range("").unwrap(), (0, 0));
        assert_eq!(parse_port_range("   ").unwrap(), (0, 0));
    }

    #[test]
    fn port_range_basic() {
        assert_eq!(parse_port_range("5500-20000").unwrap(), (5500, 20000));
        assert_eq!(parse_port_range(" 80 - 443 ").unwrap(), (80, 443));
    }

    #[test]
    fn port_range_rejects_bad_input() {
        assert!(parse_port_range("100").is_err());
        assert!(parse_port_range("100-50").is_err()); // lo > hi
        assert!(parse_port_range("0-100").is_err()); // zero endpoint
        assert!(parse_port_range("abc-100").is_err());
    }

    use super::{parse_one_cidr, parse_skip_subnet};

    #[test]
    fn cidr_v4_basic() {
        let r = parse_one_cidr("127.0.0.0/8").unwrap();
        assert_eq!(r.family, libc::AF_INET as u32);
        assert_eq!(r.addr[0], 0x7F00_0000);
        assert_eq!(r.mask[0], 0xFF00_0000);
        assert_eq!(r.addr[1..], [0, 0, 0]);
        assert_eq!(r.mask[1..], [0, 0, 0]);
    }

    #[test]
    fn cidr_v4_canonical_192_168() {
        let r = parse_one_cidr("192.168.0.0/16").unwrap();
        assert_eq!(r.addr[0], 0xC0A8_0000);
        assert_eq!(r.mask[0], 0xFFFF_0000);
    }

    #[test]
    fn cidr_v4_strict_rejects_host_bits() {
        // 192.168.1.0/16 has host bits → should be rejected with helpful msg.
        let err = parse_one_cidr("192.168.1.0/16").unwrap_err().to_string();
        assert!(err.contains("192.168.0.0/16"), "msg = {err}");
        // 10.5.5.5/8 likewise.
        let err = parse_one_cidr("10.5.5.5/8").unwrap_err().to_string();
        assert!(err.contains("10.0.0.0/8"), "msg = {err}");
    }

    #[test]
    fn cidr_v4_prefix_bounds() {
        assert!(parse_one_cidr("10.0.0.0/33").is_err());
        // /0 is allowed (matches everything), addr must be 0.0.0.0
        assert!(parse_one_cidr("0.0.0.0/0").is_ok());
        assert!(parse_one_cidr("1.2.3.4/0").is_err()); // host bits set under /0
        // /32 means single host
        let r = parse_one_cidr("8.8.8.8/32").unwrap();
        assert_eq!(r.mask[0], 0xFFFF_FFFF);
    }

    #[test]
    fn cidr_v6_loopback() {
        let r = parse_one_cidr("::1/128").unwrap();
        assert_eq!(r.family, libc::AF_INET6 as u32);
        assert_eq!(r.addr, [0, 0, 0, 1]);
        assert_eq!(r.mask, [0xFFFF_FFFF; 4]);
    }

    #[test]
    fn cidr_v6_link_local_fe80_10() {
        // fe80::/10: top 10 bits = 1111111010 → first word mask = 0xFFC0_0000
        let r = parse_one_cidr("fe80::/10").unwrap();
        assert_eq!(r.family, libc::AF_INET6 as u32);
        assert_eq!(r.addr[0], 0xFE80_0000);
        assert_eq!(r.mask[0], 0xFFC0_0000);
        assert_eq!(r.mask[1..], [0, 0, 0]);
    }

    #[test]
    fn cidr_v6_ula_fc00_7() {
        // fc00::/7: top 7 bits = 1111110 → first word mask = 0xFE00_0000
        let r = parse_one_cidr("fc00::/7").unwrap();
        assert_eq!(r.addr[0], 0xFC00_0000);
        assert_eq!(r.mask[0], 0xFE00_0000);
    }

    #[test]
    fn cidr_v6_strict_rejects_host_bits() {
        // ::abcd/64 has host bits below the /64
        let err = parse_one_cidr("::abcd/64").unwrap_err().to_string();
        assert!(err.contains("Did you mean"), "msg = {err}");
        // fe80::1/10 (last word non-zero) likewise
        let err = parse_one_cidr("fe80::1/10").unwrap_err().to_string();
        assert!(err.contains("fe80::/10"), "msg = {err}");
    }

    #[test]
    fn cidr_v6_prefix_bounds() {
        assert!(parse_one_cidr("::1/129").is_err());
        assert!(parse_one_cidr("::/0").is_ok());
    }

    #[test]
    fn cidr_malformed() {
        assert!(parse_one_cidr("abc").is_err());           // no slash
        assert!(parse_one_cidr("10.0.0.0").is_err());      // no slash
        assert!(parse_one_cidr("10.0.0.0/").is_err());     // empty prefix
        assert!(parse_one_cidr("10.0.0.0/x").is_err());    // non-numeric prefix
        assert!(parse_one_cidr("999.0.0.0/8").is_err());   // bad ipv4 octet
    }

    #[test]
    fn skip_subnet_list() {
        let v = parse_skip_subnet(
            "127.0.0.0/8, 10.0.0.0/8 ,192.168.0.0/16,::1/128,fe80::/10",
        )
        .unwrap();
        assert_eq!(v.len(), 5);
        assert_eq!(v[0].family, libc::AF_INET as u32);
        assert_eq!(v[3].family, libc::AF_INET6 as u32);
    }

    #[test]
    fn skip_subnet_empty_is_zero_rules() {
        assert_eq!(parse_skip_subnet("").unwrap().len(), 0);
        assert_eq!(parse_skip_subnet("   ").unwrap().len(), 0);
        assert_eq!(parse_skip_subnet(",,,").unwrap().len(), 0);
    }

    #[test]
    fn skip_subnet_bails_on_any_bad_entry() {
        // First entry is fine, second has host bits set → entire parse fails.
        let err = parse_skip_subnet("10.0.0.0/8,192.168.1.0/16")
            .unwrap_err()
            .to_string();
        assert!(err.contains("192.168.0.0/16"), "msg = {err}");
    }
}
