mod cli;
mod config;
mod socket;
mod status;

use std::process::ExitCode;

fn main() -> ExitCode {
    cli::dispatch()
}
