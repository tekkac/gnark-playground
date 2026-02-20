use serde::{Deserialize, Serialize};

use crate::config::{ProofMode, RecursionMode};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMetadata {
    pub run_id: String,
    pub profile: String,
    pub execution_engine: String,
    pub generated_at: String,
    pub started_at: String,
    pub cleanup_policy: String,
    pub machine: MachineFingerprint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineFingerprint {
    pub os: String,
    pub arch: String,
    pub hostname: String,
    pub cpus: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixDescriptor {
    pub repeats: u32,
    pub proof_modes: Vec<ProofMode>,
    pub recursion_modes: Vec<RecursionMode>,
    pub chain_depths: Vec<u32>,
    pub binary_tree_leaves: Vec<u32>,
    pub workload_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadMetric {
    pub workload: String,
    pub tier: String,
    pub case_label: String,
    pub proof_mode: ProofMode,
    pub repeats: u32,
    pub avg_prove_ms: f64,
    pub avg_verify_ms: f64,
    pub avg_memory_peak_bytes: u64,
    pub proof_size_bytes: u64,
    pub proof_hash: String,
    pub samples: Vec<IterationSample>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IterationSample {
    pub index: u32,
    pub prove_ms: f64,
    pub verify_ms: f64,
    pub memory_peak_bytes: u64,
    pub proof_size_bytes: u64,
    pub proof_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursionMetric {
    pub proof_mode: ProofMode,
    pub topology: RecursionMode,
    pub size: u32,
    pub prove_ms: f64,
    pub verify_ms: f64,
    pub memory_peak_bytes: u64,
    pub proof_size_bytes: u64,
    pub proof_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasEstimate {
    pub proof_mode: ProofMode,
    pub verify_gas: Option<u64>,
    pub gas_gwei: f64,
    pub eth_usd: f64,
    pub estimated_usd: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingSnapshot {
    pub mode: String,
    pub eth_usd: f64,
    pub gas_gwei: f64,
    pub captured_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSummary {
    pub sources: Vec<BaselineSource>,
}

impl BaselineSummary {
    pub fn empty() -> Self {
        Self {
            sources: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSource {
    pub name: String,
    pub status: String,
    pub notes: String,
    pub metrics: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    pub metadata: RunMetadata,
    pub matrix: MatrixDescriptor,
    pub workloads: Vec<WorkloadMetric>,
    pub recursions: Vec<RecursionMetric>,
    pub gas_table: Vec<GasEstimate>,
    pub pricing: PricingSnapshot,
    pub baseline: BaselineSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompareReport {
    pub generated_at: String,
    pub sp1: CompareSummary,
    pub baselines: Vec<BaselineSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompareSummary {
    pub avg_prove_ms_by_mode: serde_json::Value,
    pub gas_by_mode: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProofMode, RecursionMode};

    #[test]
    fn serialized_report_has_no_raw_proof_field() {
        let report = RunReport {
            metadata: RunMetadata {
                run_id: "x".into(),
                profile: "quick".into(),
                execution_engine: "deterministic_local".into(),
                generated_at: "now".into(),
                started_at: "now".into(),
                cleanup_policy: "strict_ephemeral".into(),
                machine: MachineFingerprint {
                    os: "macos".into(),
                    arch: "arm64".into(),
                    hostname: "host".into(),
                    cpus: 8,
                },
            },
            matrix: MatrixDescriptor {
                repeats: 1,
                proof_modes: vec![ProofMode::Groth16],
                recursion_modes: vec![RecursionMode::Chain],
                chain_depths: vec![2],
                binary_tree_leaves: vec![],
                workload_count: 1,
            },
            workloads: vec![WorkloadMetric {
                workload: "hash_merkle".into(),
                tier: "micro".into(),
                case_label: "s".into(),
                proof_mode: ProofMode::Groth16,
                repeats: 1,
                avg_prove_ms: 1.0,
                avg_verify_ms: 1.0,
                avg_memory_peak_bytes: 1,
                proof_size_bytes: 1,
                proof_hash: "abc".into(),
                samples: vec![IterationSample {
                    index: 0,
                    prove_ms: 1.0,
                    verify_ms: 1.0,
                    memory_peak_bytes: 1,
                    proof_size_bytes: 1,
                    proof_hash: "abc".into(),
                }],
            }],
            recursions: vec![RecursionMetric {
                proof_mode: ProofMode::Groth16,
                topology: RecursionMode::Chain,
                size: 2,
                prove_ms: 2.0,
                verify_ms: 1.0,
                memory_peak_bytes: 1,
                proof_size_bytes: 1,
                proof_hash: "abc".into(),
            }],
            gas_table: vec![GasEstimate {
                proof_mode: ProofMode::Groth16,
                verify_gas: Some(1),
                gas_gwei: 1.0,
                eth_usd: 1.0,
                estimated_usd: Some(1.0),
            }],
            pricing: PricingSnapshot {
                mode: "static".into(),
                eth_usd: 1.0,
                gas_gwei: 1.0,
                captured_at: "now".into(),
            },
            baseline: BaselineSummary::empty(),
        };

        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains("proofBytes"));
    }
}
