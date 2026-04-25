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

    /// Required only when `algorithm = "accel_brutal"`. Validated at
    /// startup in `cli::run_server`.
    pub brutal: Option<BrutalConfig>,

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
