mod cli;
mod config;
mod ebpf_loader;
mod socket;
mod status;

use std::process::ExitCode;

fn main() -> ExitCode {
    cli::dispatch()
}
