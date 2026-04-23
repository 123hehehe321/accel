mod config;

use std::path::Path;

use anyhow::Result;

const CONFIG_PATH: &str = "./acc.conf";

fn main() -> Result<()> {
    println!("hello accel");
    println!();

    let path = Path::new(CONFIG_PATH);
    let cfg = config::load(path)?;

    println!("config loaded from: {}", path.display());
    println!("  [network]");
    println!("    interface = {:?}", cfg.network.interface);
    println!("    ports     = {:?}", cfg.network.ports);
    println!("    mode      = {:?}", cfg.network.mode);
    println!("  [runtime]");
    let socket_display = if cfg.runtime.socket.is_empty() {
        "\"\" (auto-detect)".to_string()
    } else {
        format!("{:?}", cfg.runtime.socket)
    };
    println!("    socket    = {socket_display}");
    println!("  [forward]");
    println!("    backend   = {:?}", cfg.forward.backend);

    Ok(())
}
