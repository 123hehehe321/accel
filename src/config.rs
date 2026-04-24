use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub algorithm: Algorithm,
    pub runtime: Runtime,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Algorithm {
    pub default: String,
    pub algo_dir: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    pub socket: String,
}

pub fn load(path: &Path) -> Result<Config> {
    let display = path.display();
    let text = fs::read_to_string(path)
        .with_context(|| format!("cannot read config file: {display}"))?;
    let cfg: Config = toml::from_str(&text)
        .with_context(|| format!("failed to parse {display} as TOML"))?;
    Ok(cfg)
}
