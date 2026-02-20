use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::report::MatrixDescriptor;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ProofMode {
    Compressed,
    Groth16,
    Plonk,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecursionMode {
    Chain,
    BinaryTree,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursionConfig {
    pub enabled: Vec<RecursionMode>,
    pub chain_depths: Vec<u32>,
    pub binary_tree_leaves: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadCase {
    pub label: String,
    pub leaves: Option<usize>,
    pub rounds: Option<u32>,
    pub batch_size: Option<usize>,
    pub steps: Option<usize>,
    pub loops: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadConfig {
    pub name: String,
    pub tier: String,
    pub cases: Vec<WorkloadCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingConfig {
    pub mode: String,
    pub eth_usd: f64,
    pub gas_gwei: f64,
    pub groth16_verify_gas: u64,
    pub plonk_verify_gas: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunConfig {
    pub profile: String,
    pub repeats: u32,
    pub cleanup_policy: String,
    pub proof_modes: Vec<ProofMode>,
    pub recursion: RecursionConfig,
    pub workloads: Vec<WorkloadConfig>,
    pub pricing: PricingConfig,
}

impl RunConfig {
    pub fn from_file(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        toml::from_str(&raw).with_context(|| format!("parse {}", path.display()))
    }

    pub fn validate(&self) -> Result<()> {
        if self.repeats == 0 {
            return Err(anyhow!("repeats must be >= 1"));
        }
        if self.cleanup_policy != "strict_ephemeral" {
            return Err(anyhow!("cleanup_policy must be strict_ephemeral"));
        }
        if self.proof_modes.is_empty() {
            return Err(anyhow!("proof_modes cannot be empty"));
        }
        if self.workloads.is_empty() {
            return Err(anyhow!("workloads cannot be empty"));
        }

        for workload in &self.workloads {
            if workload.cases.is_empty() {
                return Err(anyhow!("workload {} has no cases", workload.name));
            }
            for case in &workload.cases {
                validate_workload_case(&workload.name, case)?;
            }
        }

        if self.recursion.enabled.contains(&RecursionMode::Chain)
            && self.recursion.chain_depths.is_empty()
        {
            return Err(anyhow!("recursion.chain enabled but chain_depths is empty"));
        }
        if self.recursion.enabled.contains(&RecursionMode::BinaryTree)
            && self.recursion.binary_tree_leaves.is_empty()
        {
            return Err(anyhow!(
                "recursion.binary_tree enabled but binary_tree_leaves is empty"
            ));
        }

        Ok(())
    }

    pub fn to_matrix_descriptor(&self) -> MatrixDescriptor {
        MatrixDescriptor {
            repeats: self.repeats,
            proof_modes: self.proof_modes.clone(),
            recursion_modes: self.recursion.enabled.clone(),
            chain_depths: self.recursion.chain_depths.clone(),
            binary_tree_leaves: self.recursion.binary_tree_leaves.clone(),
            workload_count: self.workloads.len(),
        }
    }
}

fn validate_workload_case(workload_name: &str, case: &WorkloadCase) -> Result<()> {
    match workload_name {
        "hash_merkle" => {
            if case.leaves.is_none() || case.rounds.is_none() {
                return Err(anyhow!(
                    "hash_merkle case {} requires leaves and rounds",
                    case.label
                ));
            }
        }
        "sig_batch" => {
            if case.batch_size.is_none() || case.rounds.is_none() {
                return Err(anyhow!(
                    "sig_batch case {} requires batch_size and rounds",
                    case.label
                ));
            }
        }
        "vm_stress" => {
            if case.steps.is_none() || case.loops.is_none() {
                return Err(anyhow!(
                    "vm_stress case {} requires steps and loops",
                    case.label
                ));
            }
        }
        _ => return Err(anyhow!("unsupported workload {}", workload_name)),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::RunConfig;

    #[test]
    fn parses_and_validates_quick_config() {
        let raw = r#"
profile = "quick"
repeats = 3
cleanup_policy = "strict_ephemeral"
proof_modes = ["compressed", "groth16", "plonk"]

[recursion]
enabled = ["chain", "binary_tree"]
chain_depths = [2]
binary_tree_leaves = [4]

[pricing]
mode = "static"
eth_usd = 2000.0
gas_gwei = 5.0
groth16_verify_gas = 270000
plonk_verify_gas = 300000

[[workloads]]
name = "hash_merkle"
tier = "micro"
[[workloads.cases]]
label = "s"
leaves = 32
rounds = 8
"#;
        let cfg: RunConfig = toml::from_str(raw).unwrap();
        cfg.validate().unwrap();
    }
}
