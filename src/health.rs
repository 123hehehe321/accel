//! Background health-check thread.
//!
//! Runs on a fixed 30s tick, checks three things, records an incident +
//! self-heals where possible. No dependency on signals or channels: main
//! flips `state.health_shutting_down` when it wants the loop to exit.
//! The thread wakes every 500 ms to poll that flag so shutdown is
//! snappy despite the coarse tick.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::incidents::{self, Event};
use crate::status::State;
use crate::{algo, ebpf_loader};

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
    check_algo_registered(state);
    check_sysctl_drift(state);
    check_jit(state);
    if let Ok(mut g) = state.health_last_ok.lock() {
        *g = Some(Instant::now());
    }
}

fn check_algo_registered(state: &State) {
    let Some(name) = current_algo_name(state) else {
        return;
    };
    match algo::is_registered(&name) {
        Ok(true) => {}
        Ok(false) => reload(state, &name),
        Err(e) => eprintln!("health: is_registered({name}) failed: {e:#}"),
    }
}

fn reload(state: &State, name: &str) {
    eprintln!("health: {name} unregistered externally, reloading...");
    let Ok(mut guard) = state.algo.lock() else {
        eprintln!("health: algo lock poisoned, cannot reload");
        return;
    };
    guard.take(); // drop old Link (no-op at kernel level — already gone)
    match ebpf_loader::load_accel_cubic() {
        Ok(new) => *guard = Some(new),
        Err(e) => {
            eprintln!("health: reload failed: {e:#}");
            return;
        }
    }
    drop(guard); // release lock before side-effects below

    // Re-apply sysctl; kernel reverts to cubic when our struct_ops drops.
    let target = state
        .target_algo
        .lock()
        .map(|g| g.clone())
        .unwrap_or_else(|_| name.to_string());
    if let Err(e) = algo::set_cc_both(&target) {
        eprintln!("health: set_cc_both({target}) after reload failed: {e:#}");
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
        .unwrap_or(true); // unknown → assume OK, don't spam
    if enabled {
        state.jit_warned.store(false, Ordering::Relaxed);
        return;
    }
    // Only log the first time we see it disabled since process start or
    // the last time it was enabled — avoid spamming every 30s.
    if state
        .jit_warned
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        eprintln!("health: bpf_jit_enable=0, eBPF runs in interpreter (5-10x slower)");
        let _ = incidents::append(Event::JitDisabled);
    }
}

fn current_algo_name(state: &State) -> Option<String> {
    state
        .algo
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|a| a.name.to_string()))
}
