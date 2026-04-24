mod algo;
mod cli;
mod config;
mod ebpf_loader;
mod health;
mod incidents;
mod socket;
mod status;

use std::process::ExitCode;

fn main() -> ExitCode {
    cli::dispatch()
}
