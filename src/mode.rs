use std::fmt;

use anyhow::{Context, Result};
use aya::programs::{Xdp, XdpFlags};

use crate::config::Mode;

/// The XDP attach mode that actually succeeded. Reported in status.
#[derive(Debug, Clone, Copy)]
pub enum ResolvedMode {
    Native,
    Generic,
}

impl fmt::Display for ResolvedMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ResolvedMode::Native => "native",
            ResolvedMode::Generic => "generic",
        })
    }
}

pub fn attach(program: &mut Xdp, iface: &str, cfg: &Mode) -> Result<ResolvedMode> {
    match cfg {
        Mode::Native => {
            program
                .attach(iface, XdpFlags::DRV_MODE)
                .with_context(|| format!("failed to attach XDP to '{iface}' in native mode"))?;
            Ok(ResolvedMode::Native)
        }
        Mode::Generic => {
            program
                .attach(iface, XdpFlags::SKB_MODE)
                .with_context(|| format!("failed to attach XDP to '{iface}' in generic mode"))?;
            Ok(ResolvedMode::Generic)
        }
        Mode::Auto => match program.attach(iface, XdpFlags::DRV_MODE) {
            Ok(_) => Ok(ResolvedMode::Native),
            Err(native_err) => {
                eprintln!("note: native XDP unavailable ({native_err}), falling back to generic");
                program.attach(iface, XdpFlags::SKB_MODE).with_context(|| {
                    format!("failed to attach XDP to '{iface}' in generic mode (after native failed)")
                })?;
                Ok(ResolvedMode::Generic)
            }
        },
    }
}
