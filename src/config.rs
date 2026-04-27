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

    /// Comma-separated list of CIDR subnets to skip (rate-limit and
    /// classification bypass). Both IPv4 and IPv6 are supported. Each
    /// entry is matched against the connection's destination AND source
    /// addresses — either side hitting any rule causes the socket to
    /// bypass the algorithm. Required field (production safety: no
    /// silent default behaviour).
    ///
    /// Examples (all canonical — host bits beyond the prefix MUST be
    /// zero, otherwise startup bails):
    ///     "127.0.0.0/8"
    ///     "10.0.0.0/8,192.168.0.0/16"
    ///     "::1/128,fe80::/10,fc00::/7"
    ///     ""                     (empty: no rules; everything goes through accel)
    ///
    /// Hard cap: 32 rules total (BPF map sized for that). Parser bails
    /// past 32. acc.conf.example ships an 8-rule default covering RFC1918
    /// + loopback + link-local + IPv6 ULA.
    pub skip_subnet: Option<String>,

    /// Required only when `algorithm = "accel_brutal"`. Validated at
    /// startup in `cli::run_server`.
    pub brutal: Option<BrutalConfig>,

    /// Required only when `algorithm = "accel_smart"`. Validated at
    /// startup in `cli::run_server`.
    pub smart: Option<SmartConfig>,

    pub runtime: Runtime,
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

    /// LOSSY-state packet multiplier — total copies per outbound TCP
    /// packet (1 = original only / no clone, 2 = original + 1 clone,
    /// up to 8). Hard upper bound 8 because higher factors saturate
    /// the link and trigger real congestion. Default 2.
    #[serde(default = "default_duplicate_factor")]
    pub duplicate_factor: u32,

    /// Loss-rate threshold above which the link is classified as LOSSY
    /// (basis points; 100 = 1%). Default tuned for typical cross-border
    /// links.
    #[serde(default = "default_loss_lossy_bp")]
    pub loss_lossy_bp: u32,

    /// Loss-rate threshold above which the link is classified as
    /// CONGEST (basis points; 1500 = 15%).
    #[serde(default = "default_loss_congest_bp")]
    pub loss_congest_bp: u32,
}

fn default_loss_lossy_bp() -> u32 {
    100
}
fn default_loss_congest_bp() -> u32 {
    1500
}
fn default_duplicate_factor() -> u32 {
    2
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
