use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};

use crate::report::MachineFingerprint;

pub struct CommandOutput {
    pub status_ok: bool,
    pub stdout: String,
    pub stderr: String,
    pub elapsed: Duration,
}

pub fn run_command(
    cmd: &str,
    args: &[&str],
    cwd: Option<&Path>,
    envs: &[(&str, &str)],
) -> Result<CommandOutput> {
    let mut command = Command::new(cmd);
    command.args(args);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    for (k, v) in envs {
        command.env(k, v);
    }

    let started = Instant::now();
    let output = command
        .output()
        .with_context(|| format!("run command: {} {}", cmd, args.join(" ")))?;
    let elapsed = started.elapsed();

    Ok(CommandOutput {
        status_ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        elapsed,
    })
}

pub fn command_exists(name: &str) -> bool {
    run_command(
        "/bin/sh",
        &["-lc", &format!("command -v {name} >/dev/null 2>&1")],
        None,
        &[],
    )
    .map(|o| o.status_ok)
    .unwrap_or(false)
}

pub fn ensure_parent_dir(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Err(anyhow!("path has no parent: {}", path.display()));
    };
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))
}

pub fn default_report_path(profile: &str) -> PathBuf {
    PathBuf::from(format!("../artifacts/sp1/reports/sp1_{profile}.json"))
}

pub fn machine_fingerprint() -> MachineFingerprint {
    let hostname = env::var("HOSTNAME").unwrap_or_else(|_| {
        run_command("/bin/sh", &["-lc", "hostname"], None, &[])
            .map(|o| o.stdout.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    });

    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    MachineFingerprint {
        os: env::consts::OS.to_string(),
        arch: env::consts::ARCH.to_string(),
        hostname,
        cpus,
    }
}
