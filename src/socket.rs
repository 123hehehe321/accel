use std::io::{self, BufRead, BufReader, ErrorKind, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::algo;
use crate::status::{self, State};

const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub fn resolve_path(cfg_socket: &str) -> PathBuf {
    if !cfg_socket.is_empty() {
        return PathBuf::from(cfg_socket);
    }
    if std::env::var_os("INVOCATION_ID").is_some() {
        let dir = PathBuf::from("/run/accel");
        if std::fs::create_dir_all(&dir).is_ok() {
            return dir.join("accel.sock");
        }
        eprintln!("warning: cannot create /run/accel/, falling back to ./accel.sock");
    }
    PathBuf::from("./accel.sock")
}

/// Client-side socket resolver. Same `cfg_socket` precedence as
/// `resolve_path`, but when the user left `socket = ""` we cannot rely
/// on INVOCATION_ID — that env var is set on the daemon by systemd, not
/// inherited by an interactive `./accel status` started later from the
/// shell. Fall back to probing /run/accel/accel.sock first (where the
/// systemd-launched daemon binds), then to ./accel.sock (manual launch
/// in the binary's directory).
pub fn resolve_client_path(cfg_socket: &str) -> PathBuf {
    if !cfg_socket.is_empty() {
        return PathBuf::from(cfg_socket);
    }
    let run_path = PathBuf::from("/run/accel/accel.sock");
    if run_path.exists() {
        return run_path;
    }
    PathBuf::from("./accel.sock")
}

/// Startup-time check: if the socket file exists and a listener is there,
/// another accel is already running. If the file exists but connect fails,
/// it's stale — we unlink so bind can succeed.
pub fn prepare_path(path: &Path) -> Result<()> {
    match UnixStream::connect(path) {
        Ok(_) => bail!(
            "another accel is already running on {} (use './accel stop' first)",
            path.display()
        ),
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
            // stale socket file
            std::fs::remove_file(path).ok();
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("checking existing socket at {}", path.display())),
    }
}

pub fn bind(path: &Path) -> Result<UnixListener> {
    let listener = UnixListener::bind(path)
        .with_context(|| format!("binding Unix socket at {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 on {}", path.display()))?;
    Ok(listener)
}

/// Blocking accept loop. Runs in the dedicated socket thread. On fatal
/// accept errors, signals the main thread to shut down and returns.
pub fn serve(listener: UnixListener, state: Arc<State>, shutdown_tx: Sender<()>) {
    loop {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                let stop_requested = handle(stream, &state);
                if stop_requested {
                    let _ = shutdown_tx.send(());
                    return;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => {
                eprintln!("error: socket accept failed: {e}, shutting down accel");
                let _ = shutdown_tx.send(());
                return;
            }
        }
    }
}

/// Handle one client. Returns true iff the client issued `stop`.
fn handle(stream: UnixStream, state: &State) -> bool {
    let reader_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("warning: socket try_clone failed: {e}, dropping client");
            return false;
        }
    };
    let mut reader = BufReader::new(reader_stream);
    let mut writer = stream;
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return false;
    }
    let cmd = line.trim();
    match cmd {
        "status" => {
            let text = status::render(state);
            let _ = writer.write_all(text.as_bytes());
            false
        }
        "stop" => {
            let _ = writer.write_all(b"stopping\n");
            true
        }
        "algo_list" => {
            let _ = writer.write_all(render_algo_list(state).as_bytes());
            false
        }
        other if other.starts_with("algo_switch ") => {
            let name = other["algo_switch ".len()..].trim();
            match handle_algo_switch(name, state) {
                Ok(()) => {
                    let _ = writeln!(writer, "ok: switched to {name}");
                }
                Err(e) => {
                    let _ = writeln!(writer, "error: {e:#}");
                }
            }
            false
        }
        other => {
            let _ = writeln!(writer, "error: unknown command: {other}");
            false
        }
    }
}

fn render_algo_list(state: &State) -> String {
    let available = algo::list_available()
        .map(|v| v.join(" "))
        .unwrap_or_else(|e| format!("? ({e})"));
    let target = state
        .target_algo
        .lock()
        .map(|g| g.clone())
        .unwrap_or_else(|_| "?".to_string());
    let active_v4 = algo::current_cc_ipv4().unwrap_or_else(|_| "?".to_string());
    let loaded = state
        .algos
        .lock()
        .ok()
        .map(|g| {
            let mut names: Vec<String> = g.keys().cloned().collect();
            names.sort();
            if names.is_empty() {
                "none".to_string()
            } else {
                names.join(", ")
            }
        })
        .unwrap_or_else(|| "?".to_string());
    format!(
        "loaded by accel:    {loaded}\n\
         target:             {target}\n\
         active (ipv4):      {active_v4}\n\
         available (kernel): {available}\n"
    )
}

/// Algo switch is now a pure sysctl write. Allowed targets are either
/// an algorithm accel itself loaded (members of `state.algos`) or any
/// kernel built-in present in `tcp_available_congestion_control`.
/// `algo::set_cc_both` already validates name is registered, so this
/// function just forwards plus updates the daemon's `target_algo` so
/// health.rs sysctl-drift detection keeps it locked in.
fn handle_algo_switch(name: &str, state: &State) -> Result<()> {
    if name.is_empty() {
        bail!("missing algorithm name (usage: algo_switch NAME)");
    }
    algo::set_cc_both(name)?;
    if let Ok(mut t) = state.target_algo.lock() {
        *t = name.to_string();
    }
    Ok(())
}

/// Client side: connect to the socket and write one command, then stream
/// the response to stdout. Returns the exit code for the CLI.
pub fn client_roundtrip(path: &Path, cmd: &str) -> Result<()> {
    let mut stream = UnixStream::connect(path).with_context(|| {
        format!(
            "cannot connect to {} — is accel running?",
            path.display()
        )
    })?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    writeln!(stream, "{cmd}")?;
    let mut stdout = io::stdout().lock();
    io::copy(&mut stream, &mut stdout)?;
    Ok(())
}
