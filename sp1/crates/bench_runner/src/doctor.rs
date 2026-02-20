use anyhow::{anyhow, Result};

use crate::util::{command_exists, run_command};

pub fn run_doctor() -> Result<()> {
    let checks = [
        ("rustc", true),
        ("cargo", true),
        ("forge", true),
        ("node", true),
        ("npm", true),
        ("nargo", false),
        ("bb", false),
        ("cargo-prove", false),
        ("sp1up", false),
    ];

    let mut missing_critical = Vec::new();

    println!("SP1 doctor checks:");
    for (tool, critical) in checks {
        let exists = command_exists(tool);
        let status = if exists { "ok" } else { "missing" };
        let level = if critical { "critical" } else { "optional" };
        println!("- {tool:12} {status:8} ({level})");

        if critical && !exists {
            missing_critical.push(tool);
        }

        if exists {
            let version_output = if tool == "cargo-prove" {
                run_command("cargo", &["prove", "--version"], None, &[])
            } else {
                run_command(tool, &["--version"], None, &[])
            };
            if let Ok(output) = version_output {
                let line = output
                    .stdout
                    .lines()
                    .next()
                    .or_else(|| output.stderr.lines().next())
                    .unwrap_or("");
                println!("  version: {line}");
            }
        }
    }

    if !missing_critical.is_empty() {
        return Err(anyhow!(
            "missing critical tools: {}",
            missing_critical.join(", ")
        ));
    }

    println!("doctor passed");

    if command_exists("rustup") {
        if let Ok(output) = run_command("rustup", &["toolchain", "list"], None, &[]) {
            let has_succinct = output.stdout.lines().any(|line| line.contains("succinct"));
            if has_succinct {
                println!("- succinct toolchain: installed");
            } else {
                println!("- succinct toolchain: missing (run `cargo prove install-toolchain`)");
            }
        }
    }

    Ok(())
}
