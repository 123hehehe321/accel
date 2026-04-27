//! Background health-check thread.
//!
//! Runs on a fixed 30s tick, checks three things, records an incident +
//! self-heals where possible. No dependency on signals or channels: main
//! flips `state.health_shutting_down` when it wants the loop to exit.
//! The thread wakes every 500 ms to poll that flag so shutdown is
//! snappy despite the coarse tick.
//!
//! 2.3-D3 multi-algo upgrade: every loaded algorithm is checked
//! independently. If one is unregistered externally, only that one is
//! reloaded (the others are unaffected).

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::ebpf_loader::{self, LoadedAlgo};
use crate::incidents::{self, Event};
use crate::status::State;
use crate::algo;

const TICK: Duration = Duration::from_secs(30);
const WAKE: Duration = Duration::from_millis(500);

pub fn spawn(state: Arc<State>) -> Result<()> {
    thread::Builder::new()
        .name("accel-health".into())
        .spawn(move || loop {
            let deadline = Instant::now() + TICK;
            while Instant::now() < deadline {
                if state.health_shutting_down.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(WAKE);
            }
            tick(&state);
        })?;
    Ok(())
}

fn tick(state: &State) {
    check_all_algos_registered(state);
    check_sysctl_drift(state);
    check_jit(state);
    if let Ok(mut g) = state.health_last_ok.lock() {
        *g = Some(Instant::now());
    }
}

/// Iterate over every algorithm accel loaded; if the kernel no longer
/// has it registered (e.g. someone ran `bpftool struct_ops unregister`),
/// reload that single algorithm. Other algorithms are untouched.
fn check_all_algos_registered(state: &State) {
    let names: Vec<String> = match state.algos.lock() {
        Ok(g) => g.keys().cloned().collect(),
        Err(_) => return,
    };
    for name in &names {
        match algo::is_registered(name) {
            Ok(true) => {}
            Ok(false) => reload_one(state, name),
            Err(e) => eprintln!("health: is_registered({name}) failed: {e:#}"),
        }
    }
}

/// Drop the existing entry for `name`, run its loader to register fresh,
/// and on success re-apply any per-algo runtime config (currently only
/// brutal's rate). Failures log + record but don't bail — the next tick
/// will retry.
fn reload_one(state: &State, name: &str) {
    eprintln!("health: {name} unregistered externally, reloading...");

    let loader = ebpf_loader::all_loaders()
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, f)| *f);
    let Some(loader) = loader else {
        eprintln!("health: no loader registered for {name} (table out of sync?)");
        return;
    };

    let Ok(mut algos) = state.algos.lock() else {
        eprintln!("health: algos lock poisoned, skipping reload");
        return;
    };
    algos.remove(name); // drop old (already kernel-side gone)
    let new_algo = match loader() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("health: reload {name} failed: {e:#}");
            return;
        }
    };

    // For brutal, restore the user's rate after reload (the new BPF map
    // starts at zero). state.brutal_rate_mbps is set at startup if and
    // only if brutal was loaded with a configured rate.
    let new_algo = if name == "accel_brutal" {
        if let Some(rate_mbps) = state.brutal_rate_mbps {
            let rate_bytes = rate_mbps as u64 * 1_000_000 / 8;
            let mut a = new_algo;
            // SAFETY: load_brutal() always returns LoadedAlgo::Brutal;
            // other variants are impossible here.
            match &mut a {
                LoadedAlgo::Brutal(b) => {
                    if let Err(e) = b.set_rate(rate_bytes) {
                        eprintln!("health: re-apply brutal rate after reload failed: {e:#}");
                    }
                }
                _ => unreachable!("load_brutal must return LoadedAlgo::Brutal"),
            }
            a
        } else {
            new_algo
        }
    } else {
        new_algo
    };

    // For smart, restore the saved [smart] config: re-write smart_config_map
    // and smart_dup_config (their backing kernel maps are recreated on
    // reload, so they're zero by default), then re-attach the tc-bpf egress
    // filter (the old hook was detached when the prior LoadedSmart dropped).
    // state.smart_saved is set at startup iff target was accel_smart.
    let mut new_algo = if name == "accel_smart" {
        if let Some(saved) = state.smart_saved.as_ref() {
            let mut a = new_algo;
            match &mut a {
                LoadedAlgo::Smart(sm) => {
                    if let Err(e) = sm.set_config(
                        saved.rate_bytes,
                        saved.loss_lossy_bp,
                        saved.loss_congest_bp,
                    ) {
                        eprintln!("health: re-apply smart config after reload failed: {e:#}");
                    }
                    if let Err(e) = sm.set_dup_config(
                        saved.ifindex,
                        saved.port_min,
                        saved.port_max,
                        saved.duplicate_factor,
                    ) {
                        eprintln!("health: re-apply smart dup_config after reload failed: {e:#}");
                    }
                    if let Err(e) = sm.attach_tc_egress(saved.ifindex) {
                        eprintln!("health: re-attach smart tc/egress after reload failed: {e:#}");
                    }
                }
                _ => unreachable!("load_smart must return LoadedAlgo::Smart"),
            }
            a
        } else {
            new_algo
        }
    } else {
        new_algo
    };

    // CRITICAL: re-apply the skip-subnet rules. The newly-loaded BPF
    // map is empty (count=0), which means should_skip() returns 0 for
    // every socket, which means LOCAL/INTRANET connections would be
    // rate-limited until the next acc.conf reload. Production safety:
    // every algo reload reapplies these rules, exhaustively over every
    // LoadedAlgo variant (compile-time check that new variants don't
    // skip this step).
    let skip_result = match &mut new_algo {
        LoadedAlgo::Cubic(c) => c.set_skip(&state.skip_rules),
        LoadedAlgo::Brutal(b) => b.set_skip(&state.skip_rules),
        LoadedAlgo::Smart(s) => s.set_skip(&state.skip_rules),
    };
    if let Err(e) = skip_result {
        eprintln!("health: re-apply skip_subnet after {name} reload failed: {e:#}");
    }

    algos.insert(name.to_string(), new_algo);
    drop(algos); // release before sysctl side-effect

    // After reloading, sysctl may have fallen back to a kernel default
    // when our algo disappeared. Re-apply target if it matches the algo
    // we just reloaded (the user-chosen default).
    if let Ok(target) = state.target_algo.lock() {
        if *target == name {
            if let Err(e) = algo::set_cc_both(&target) {
                eprintln!("health: set_cc_both({target}) after reload failed: {e:#}");
            }
        }
    }

    let _ = incidents::append(Event::AlgoRelost {
        name: name.to_string(),
    });
}

fn check_sysctl_drift(state: &State) {
    let Ok(current) = algo::current_cc_ipv4() else {
        return;
    };
    let target = match state.target_algo.lock() {
        Ok(g) => g.clone(),
        Err(_) => return,
    };
    if current == target {
        return;
    }
    eprintln!("health: sysctl drifted ({current} != target {target}), resetting");
    if let Err(e) = algo::set_cc_both(&target) {
        eprintln!("health: set_cc_both({target}) failed: {e:#}");
        return;
    }
    let _ = incidents::append(Event::SysctlReset {
        from: current,
        to: target,
    });
}

fn check_jit(state: &State) {
    let enabled = std::fs::read_to_string("/proc/sys/net/core/bpf_jit_enable")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .map(|v| v != 0)
        .unwrap_or(true);
    if enabled {
        state.jit_warned.store(false, Ordering::Relaxed);
        return;
    }
    if state
        .jit_warned
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        eprintln!("health: bpf_jit_enable=0, eBPF runs in interpreter (5-10x slower)");
        let _ = incidents::append(Event::JitDisabled);
    }
}
