use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::report::{BaselineSource, CompareReport, CompareSummary, RunReport};
use crate::util::{command_exists, default_report_path, ensure_parent_dir, run_command};

pub fn run_compare_command(
    sp1: PathBuf,
    include_baselines: String,
    out: Option<PathBuf>,
) -> Result<()> {
    let sp1_raw = fs::read_to_string(&sp1).with_context(|| format!("read {}", sp1.display()))?;
    let sp1_report: RunReport = serde_json::from_str(&sp1_raw).context("parse sp1 report")?;

    let summary = summarize_sp1(&sp1_report);

    let mut baselines = Vec::new();
    for source in include_baselines
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
    {
        if source.is_empty() {
            continue;
        }
        let baseline = match source.as_str() {
            "gnark" => collect_gnark_baseline(),
            "circom" => collect_circom_baseline(),
            "noir" => collect_noir_baseline(),
            other => Err(anyhow!("unsupported baseline source: {other}")),
        }
        .unwrap_or_else(|e| BaselineSource {
            name: source,
            status: "error".to_string(),
            notes: e.to_string(),
            metrics: json!({}),
        });
        baselines.push(baseline);
    }

    let compare = CompareReport {
        generated_at: Utc::now().to_rfc3339(),
        sp1: summary,
        baselines,
    };

    let out_path = out.unwrap_or_else(|| default_report_path("compare"));
    ensure_parent_dir(&out_path)?;
    fs::write(&out_path, serde_json::to_vec_pretty(&compare)?)
        .with_context(|| format!("write compare report {}", out_path.display()))?;

    println!("sp1 compare report written to {}", out_path.display());
    Ok(())
}

fn summarize_sp1(report: &RunReport) -> CompareSummary {
    let mut prove_by_mode: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for item in &report.workloads {
        let key = format!("{:?}", item.proof_mode).to_ascii_lowercase();
        prove_by_mode
            .entry(key)
            .or_default()
            .push(item.avg_prove_ms);
    }

    let avg_prove_ms_by_mode: BTreeMap<String, f64> = prove_by_mode
        .into_iter()
        .map(|(k, v)| {
            let mean = if v.is_empty() {
                0.0
            } else {
                v.iter().sum::<f64>() / v.len() as f64
            };
            (k, mean)
        })
        .collect();

    let gas_by_mode: BTreeMap<String, Value> = report
        .gas_table
        .iter()
        .map(|g| {
            (
                format!("{:?}", g.proof_mode).to_ascii_lowercase(),
                json!({
                    "verifyGas": g.verify_gas,
                    "estimatedUsd": g.estimated_usd,
                }),
            )
        })
        .collect();

    CompareSummary {
        avg_prove_ms_by_mode: serde_json::to_value(avg_prove_ms_by_mode).unwrap_or(json!({})),
        gas_by_mode: serde_json::to_value(gas_by_mode).unwrap_or(json!({})),
    }
}

fn collect_gnark_baseline() -> Result<BaselineSource> {
    let path = PathBuf::from("../artifacts/bench/prove_bench.json");
    if !path.exists() {
        return Ok(BaselineSource {
            name: "gnark".to_string(),
            status: "skipped".to_string(),
            notes: format!("missing {}", path.display()),
            metrics: json!({}),
        });
    }

    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let value: Value = serde_json::from_str(&raw).context("parse gnark bench json")?;

    let workloads = value
        .get("workloads")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut summary = BTreeMap::new();
    for w in workloads {
        let name = w.get("name").and_then(Value::as_str).unwrap_or("unknown");
        let prove = w.get("avgProveMs").and_then(Value::as_f64).unwrap_or(0.0);
        let verify = w.get("avgVerifyMs").and_then(Value::as_f64).unwrap_or(0.0);
        summary.insert(
            name.to_string(),
            json!({"avgProveMs": prove, "avgVerifyMs": verify}),
        );
    }

    Ok(BaselineSource {
        name: "gnark".to_string(),
        status: "ok".to_string(),
        notes: "parsed artifacts/bench/prove_bench.json".to_string(),
        metrics: serde_json::to_value(summary).unwrap_or(json!({})),
    })
}

fn collect_circom_baseline() -> Result<BaselineSource> {
    let circom_dir = Path::new("../circom");
    if !circom_dir.exists() {
        return Ok(BaselineSource {
            name: "circom".to_string(),
            status: "skipped".to_string(),
            notes: "../circom not found".to_string(),
            metrics: json!({}),
        });
    }

    let prove_result = run_command("npm", &["run", "-s", "prove"], Some(circom_dir), &[])?;
    let prove_ms = prove_result.elapsed.as_secs_f64() * 1000.0;

    let mut metrics = json!({
        "proveMs": prove_ms,
        "proveStatus": if prove_result.status_ok {"ok"} else {"error"},
    });

    if let Some(m) = metrics.as_object_mut() {
        m.insert(
            "proofFiles".to_string(),
            json!({
                "mulA": file_size("../circom/build/mul_a/default/groth16_proof.json"),
                "mulB": file_size("../circom/build/mul_b/default/groth16_proof.json"),
            }),
        );
    }

    let gas = extract_forge_gas(
        Path::new("../onchain"),
        "testCircomVerifyProof",
        "verifyProof",
    )
    .ok();
    if let Some(m) = metrics.as_object_mut() {
        m.insert("verifyGas".to_string(), json!(gas));
    }

    Ok(BaselineSource {
        name: "circom".to_string(),
        status: if prove_result.status_ok {
            "ok"
        } else {
            "error"
        }
        .to_string(),
        notes: if prove_result.status_ok {
            "timed npm run -s prove".to_string()
        } else {
            format!("prove failed: {}", prove_result.stderr)
        },
        metrics,
    })
}

fn collect_noir_baseline() -> Result<BaselineSource> {
    if !command_exists("nargo") || !command_exists("bb") {
        return Ok(BaselineSource {
            name: "noir".to_string(),
            status: "skipped".to_string(),
            notes: "nargo or bb missing".to_string(),
            metrics: json!({}),
        });
    }

    let root = PathBuf::from(format!("/tmp/noir-bench-{}", Uuid::new_v4().simple()));
    fs::create_dir_all(&root)?;
    let created = run_command("nargo", &["new", "noir_cost"], Some(&root), &[])?;
    if !created.status_ok {
        let _ = fs::remove_dir_all(&root);
        return Ok(BaselineSource {
            name: "noir".to_string(),
            status: "error".to_string(),
            notes: format!("nargo new failed: {}", created.stderr),
            metrics: json!({}),
        });
    }

    let project = root.join("noir_cost");
    fs::write(
        project.join("src/main.nr"),
        "fn main(x: Field, y: pub Field, z: pub Field) { assert(x * y == z); }\n",
    )?;
    fs::write(
        project.join("Prover.toml"),
        "x = \"3\"\ny = \"11\"\nz = \"33\"\n",
    )?;
    fs::create_dir_all(project.join(".home"))?;
    fs::create_dir_all(project.join("target/crs"))?;
    let home = project.join(".home");
    let home_s = home.to_string_lossy().to_string();

    let compile = run_command("nargo", &["compile"], Some(&project), &[("HOME", &home_s)])?;
    if !compile.status_ok {
        let _ = fs::remove_dir_all(&root);
        return Ok(BaselineSource {
            name: "noir".to_string(),
            status: "error".to_string(),
            notes: format!("nargo compile failed: {}", compile.stderr),
            metrics: json!({}),
        });
    }

    let execute = run_command("nargo", &["execute"], Some(&project), &[("HOME", &home_s)])?;
    if !execute.status_ok {
        let _ = fs::remove_dir_all(&root);
        return Ok(BaselineSource {
            name: "noir".to_string(),
            status: "error".to_string(),
            notes: format!("nargo execute failed: {}", execute.stderr),
            metrics: json!({}),
        });
    }

    let write_vk = run_command(
        "bb",
        &[
            "write_vk",
            "-s",
            "ultra_honk",
            "-b",
            "target/noir_cost.json",
            "-o",
            "target",
            "--oracle_hash",
            "keccak",
            "-c",
            "target/crs",
        ],
        Some(&project),
        &[("HOME", &home_s)],
    )?;
    if !write_vk.status_ok {
        let _ = fs::remove_dir_all(&root);
        return Ok(BaselineSource {
            name: "noir".to_string(),
            status: "error".to_string(),
            notes: format!("bb write_vk failed: {}", write_vk.stderr),
            metrics: json!({}),
        });
    }

    let mut prove_runs = Vec::new();
    let mut prove_status = true;
    let mut error = String::new();
    for _ in 0..3 {
        let prove = run_command(
            "bb",
            &[
                "prove",
                "-s",
                "ultra_honk",
                "-b",
                "target/noir_cost.json",
                "-w",
                "target/noir_cost.gz",
                "-o",
                "target",
                "--oracle_hash",
                "keccak",
                "-k",
                "target/vk",
                "-c",
                "target/crs",
            ],
            Some(&project),
            &[("HOME", &home_s)],
        )?;

        if !prove.status_ok {
            prove_status = false;
            error = prove.stderr;
            break;
        }
        prove_runs.push(prove.elapsed.as_secs_f64() * 1000.0);
    }

    let _ = fs::remove_dir_all(&root);

    if !prove_status {
        return Ok(BaselineSource {
            name: "noir".to_string(),
            status: "error".to_string(),
            notes: format!("bb prove failed: {error}"),
            metrics: json!({}),
        });
    }

    let avg = if prove_runs.is_empty() {
        0.0
    } else {
        prove_runs.iter().sum::<f64>() / prove_runs.len() as f64
    };

    Ok(BaselineSource {
        name: "noir".to_string(),
        status: "ok".to_string(),
        notes: "timed bb prove (3 runs)".to_string(),
        metrics: json!({
            "avgProveMs": avg,
            "runsMs": prove_runs,
            "verifyGas": Value::Null,
        }),
    })
}

fn file_size(path: &str) -> Option<u64> {
    fs::metadata(path).ok().map(|m| m.len())
}

fn extract_forge_gas(dir: &Path, test_name: &str, function_name: &str) -> Result<u64> {
    if !dir.exists() {
        return Err(anyhow!("{} missing", dir.display()));
    }

    let out = run_command(
        "forge",
        &["test", "--gas-report", "--match-test", test_name],
        Some(dir),
        &[],
    )?;
    if !out.status_ok {
        return Err(anyhow!("forge gas run failed"));
    }

    for line in out.stdout.lines() {
        if !line.contains(function_name) {
            continue;
        }
        let cols: Vec<String> = line
            .split('|')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if cols.len() < 3 {
            continue;
        }
        if let Ok(v) = cols[1].replace(',', "").parse::<u64>() {
            return Ok(v);
        }
    }

    Err(anyhow!("no gas row found for {function_name}"))
}

#[cfg(test)]
mod tests {
    use super::summarize_sp1;
    use crate::config::{ProofMode, RecursionMode};
    use crate::report::{
        BaselineSummary, GasEstimate, MatrixDescriptor, PricingSnapshot, RecursionMetric,
        RunMetadata, RunReport, WorkloadMetric,
    };
    use crate::report::{IterationSample, MachineFingerprint};

    #[test]
    fn summarize_collects_mode_means() {
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
                avg_prove_ms: 12.0,
                avg_verify_ms: 3.0,
                avg_memory_peak_bytes: 10,
                proof_size_bytes: 20,
                proof_hash: "abc".into(),
                samples: vec![IterationSample {
                    index: 0,
                    prove_ms: 12.0,
                    verify_ms: 3.0,
                    memory_peak_bytes: 10,
                    proof_size_bytes: 20,
                    proof_hash: "abc".into(),
                }],
            }],
            recursions: vec![RecursionMetric {
                proof_mode: ProofMode::Groth16,
                topology: RecursionMode::Chain,
                size: 2,
                prove_ms: 24.0,
                verify_ms: 5.0,
                memory_peak_bytes: 100,
                proof_size_bytes: 300,
                proof_hash: "abc".into(),
            }],
            gas_table: vec![GasEstimate {
                proof_mode: ProofMode::Groth16,
                verify_gas: Some(270000),
                gas_gwei: 5.0,
                eth_usd: 2000.0,
                estimated_usd: Some(2.7),
            }],
            pricing: PricingSnapshot {
                mode: "static".into(),
                eth_usd: 2000.0,
                gas_gwei: 5.0,
                captured_at: "now".into(),
            },
            baseline: BaselineSummary::empty(),
        };

        let summary = summarize_sp1(&report);
        assert!(
            summary
                .avg_prove_ms_by_mode
                .get("groth16")
                .and_then(|v| v.as_f64())
                .unwrap()
                > 0.0
        );
    }
}
