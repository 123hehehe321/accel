use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Top-level: name of the CC algorithm to make active. Must match
    /// one of the algorithms compiled into this binary (see
    /// `ebpf_loader::all_loaders`). 2.3-D3 flattened this from the old
    /// `[algorithm].default` nested form.
    pub algorithm: String,

    /// Skip rate-limiting / classification on local + intranet TCP
    /// connections (loopback, RFC1918, IPv6 ULA, link-local). Default
    /// `true` — these paths are nearly always faster than what brutal /
    /// smart are tuned for, and smart's classifier additionally
    /// misreads near-zero min_rtt as CONGEST. Written once at startup
    /// into every algorithm's `accel_skip_config` BPF map; each
    /// algorithm's `_init` consults it to set a per-socket skip flag.
    #[serde(default = "default_skip_local")]
    pub skip_local: bool,

    /// Required only when `algorithm = "accel_brutal"`. Validated at
    /// startup in `cli::run_server`.
    pub brutal: Option<BrutalConfig>,

    /// Required only when `algorithm = "accel_smart"`. Validated at
    /// startup in `cli::run_server`.
    pub smart: Option<SmartConfig>,

    pub runtime: Runtime,
}

fn default_skip_local() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrutalConfig {
    /// Target send rate per accel_brutal-managed socket, in megabits per
    /// second. Range 1..=100000 (100 Gbps). Converted to byte/s and
    /// written into the BPF `brutal_rate_config` map at startup.
    pub rate_mbps: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmartConfig {
    /// GOOD-state target send rate per accel_smart-managed socket, in
    /// megabits per second. Same semantics as BrutalConfig::rate_mbps —
    /// range 1..=100000, converted to byte/s and written to the BPF
    /// `smart_config_map` at startup.
    pub rate_mbps: u32,

    /// Network interface to attach the tc/egress duplicator to. Resolved
    /// to ifindex at startup via `if_nametoindex`.
    pub interface: String,

    /// Optional dport range "min-max" for which the LOSSY-state
    /// duplicator clones outbound TCP packets. Empty string ⇒ no port
    /// filter (every TCP packet eligible for cloning during LOSSY).
    #[serde(default)]
    pub duplicate_ports: String,

    /// Loss-rate threshold above which the link is classified as LOSSY
    /// (basis points; 100 = 1%). Default tuned for typical cross-border
    /// links per design §7.
    #[serde(default = "default_loss_lossy_bp")]
    pub loss_lossy_bp: u32,

    /// Loss-rate threshold above which the link is classified as
    /// CONGEST (basis points; 1500 = 15%).
    #[serde(default = "default_loss_congest_bp")]
    pub loss_congest_bp: u32,

    /// RTT-inflation threshold (percent over min_rtt) above which the
    /// link is classified as CONGEST. Default 50 (= srtt ≥ 1.5 × min).
    #[serde(default = "default_rtt_congest_pct")]
    pub rtt_congest_pct: u32,
}

fn default_loss_lossy_bp() -> u32 {
    100
}
fn default_loss_congest_bp() -> u32 {
    1500
}
fn default_rtt_congest_pct() -> u32 {
    50
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    pub socket: String,
}

pub fn load(path: &Path) -> Result<Config> {
    let display = path.display();
    let text =
        fs::read_to_string(path).with_context(|| format!("cannot read config file: {display}"))?;
    let cfg: Config = toml::from_str(&text)
        .with_context(|| format!("failed to parse {display} as TOML"))?;
    Ok(cfg)
}
