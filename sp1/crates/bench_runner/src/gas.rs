use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::pricing::estimate_usd;
use crate::util::{default_report_path, ensure_parent_dir, run_command};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasCommandReport {
    pub generated_at: String,
    pub proof_system: String,
    pub verify_gas: u64,
    pub gas_gwei: f64,
    pub eth_usd: f64,
    pub estimated_usd: f64,
    pub forge_output: String,
}

pub fn run_gas_command(proof_system: String, out: Option<PathBuf>) -> Result<()> {
    let proof_system = proof_system.to_ascii_lowercase();
    if proof_system != "groth16" && proof_system != "plonk" {
        return Err(anyhow!("proof-system must be groth16 or plonk"));
    }

    let contracts_dir = PathBuf::from("contracts");
    if !contracts_dir.exists() {
        return Err(anyhow!("sp1/contracts not found; run from sp1 workspace"));
    }

    let test_name = match proof_system.as_str() {
        "groth16" => "testVerifyGroth16",
        "plonk" => "testVerifyPlonk",
        _ => unreachable!(),
    };

    let output = run_command(
        "forge",
        &["test", "--gas-report", "--match-test", test_name],
        Some(Path::new("contracts")),
        &[],
    )
    .context("run forge gas report")?;

    if !output.status_ok {
        return Err(anyhow!(
            "forge gas report failed:\n{}\n{}",
            output.stdout,
            output.stderr
        ));
    }

    let verify_gas = parse_verify_gas(&output.stdout, &proof_system)?;

    let eth_usd = 2727.36;
    let gas_gwei = 5.0;
    let estimated_usd = estimate_usd(verify_gas, gas_gwei, eth_usd);

    let report = GasCommandReport {
        generated_at: Utc::now().to_rfc3339(),
        proof_system,
        verify_gas,
        gas_gwei,
        eth_usd,
        estimated_usd,
        forge_output: output.stdout,
    };

    let out_path = out.unwrap_or_else(|| default_report_path("gas"));
    ensure_parent_dir(&out_path)?;
    fs::write(&out_path, serde_json::to_vec_pretty(&report)?)
        .with_context(|| format!("write gas report {}", out_path.display()))?;

    println!("sp1 gas report written to {}", out_path.display());
    Ok(())
}

fn parse_verify_gas(raw: &str, proof_system: &str) -> Result<u64> {
    let function_name = match proof_system {
        "groth16" => "verifyGroth16",
        "plonk" => "verifyPlonk",
        _ => return Err(anyhow!("unsupported proof system {proof_system}")),
    };

    for line in raw.lines() {
        if !line.contains(function_name) {
            continue;
        }
        let pieces: Vec<String> = line
            .split('|')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if pieces.len() < 3 {
            continue;
        }
        if let Ok(gas) = pieces[1].replace(',', "").parse::<u64>() {
            return Ok(gas);
        }
    }

    Err(anyhow!(
        "unable to parse {} gas from forge output",
        function_name
    ))
}

#[cfg(test)]
mod tests {
    use super::parse_verify_gas;

    #[test]
    fn parses_groth16_gas_line() {
        let output = "| verifyGroth16 | 270000 | 270000 | 270000 | 270000 | 1 |";
        let gas = parse_verify_gas(output, "groth16").unwrap();
        assert_eq!(gas, 270000);
    }
}
