use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub network: Network,
    pub runtime: Runtime,
    pub forward: Forward,
}

#[derive(Debug, Deserialize)]
pub struct Network {
    pub interface: String,
    pub ports: String,
    pub mode: Mode,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Auto,
    Native,
    Generic,
}

#[derive(Debug, Deserialize)]
pub struct Runtime {
    pub socket: String,
}

#[derive(Debug, Deserialize)]
pub struct Forward {
    pub backend: String,
}

pub fn load(path: &Path) -> Result<Config> {
    let display = path.display();
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "cannot open {display} — file not found\n\
             hint: accel expects acc.conf in the same directory as the binary"
        )
    })?;
    let cfg: Config = toml::from_str(&text)
        .with_context(|| format!("failed to parse {display} as TOML"))?;
    Ok(cfg)
}
