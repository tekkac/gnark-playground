mod cli;
mod compare;
mod config;
mod doctor;
mod engine;
mod gas;
mod pricing;
mod report;
mod util;
mod workspace;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use clap::Parser;
use config::{ProofMode, RecursionMode, RunConfig};
use engine::{run_recursion_matrix, run_workload_matrix, ExecutionEngine};
use pricing::build_gas_table;
use report::{BaselineSummary, PricingSnapshot, RunMetadata, RunReport};
use util::{default_report_path, ensure_parent_dir, machine_fingerprint};
use workspace::RunWorkspace;

fn main() {
    if let Err(err) = real_main() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let args = cli::Cli::parse();
    match args.command {
        cli::Commands::Doctor => doctor::run_doctor(),
        cli::Commands::Run {
            profile,
            engine,
            proof_modes,
            recursion,
            repeats,
            out,
        } => run_command(profile, engine, proof_modes, recursion, repeats, out),
        cli::Commands::Gas { proof_system, out } => gas::run_gas_command(proof_system, out),
        cli::Commands::Compare {
            sp1,
            include_baselines,
            out,
        } => compare::run_compare_command(sp1, include_baselines, out),
    }
}

fn run_command(
    profile: String,
    engine: String,
    proof_modes: Option<String>,
    recursion: Option<String>,
    repeats: Option<u32>,
    out: Option<PathBuf>,
) -> Result<()> {
    let config_path = PathBuf::from(format!("config/{profile}.toml"));
    let mut cfg = RunConfig::from_file(&config_path)
        .with_context(|| format!("load config from {}", config_path.display()))?;

    if let Some(modes) = proof_modes {
        cfg.proof_modes = parse_proof_modes(&modes)?;
    }
    if let Some(rec) = recursion {
        cfg.recursion.enabled = parse_recursions(&rec)?;
    }
    if let Some(r) = repeats {
        cfg.repeats = r;
    }
    cfg.validate()?;
    let engine = ExecutionEngine::parse(&engine)?;

    let run_id = format!("{}-{}", profile, uuid::Uuid::new_v4().simple());
    let mut workspace = RunWorkspace::new(&run_id)?;
    workspace.install_signal_handler()?;

    let started_at = Utc::now();
    let workload_metrics = run_workload_matrix(&cfg, workspace.path(), engine)?;
    let recursion_metrics =
        run_recursion_matrix(&cfg, &workload_metrics, workspace.path(), engine)?;

    let pricing = PricingSnapshot {
        mode: cfg.pricing.mode.clone(),
        eth_usd: cfg.pricing.eth_usd,
        gas_gwei: cfg.pricing.gas_gwei,
        captured_at: Utc::now().to_rfc3339(),
    };
    let gas_table = build_gas_table(&cfg, &pricing);

    let report = RunReport {
        metadata: RunMetadata {
            run_id,
            profile: cfg.profile.clone(),
            execution_engine: engine.as_str().to_string(),
            generated_at: Utc::now().to_rfc3339(),
            started_at: started_at.to_rfc3339(),
            cleanup_policy: cfg.cleanup_policy.clone(),
            machine: machine_fingerprint(),
        },
        matrix: cfg.to_matrix_descriptor(),
        workloads: workload_metrics,
        recursions: recursion_metrics,
        gas_table,
        pricing,
        baseline: BaselineSummary::empty(),
    };

    workspace
        .cleanup_strict()
        .context("workspace cleanup failed (fail-closed)")?;

    let out_path = out.unwrap_or_else(|| default_report_path(&cfg.profile));
    ensure_parent_dir(&out_path)?;

    let encoded = serde_json::to_vec_pretty(&report).context("serialize report")?;
    fs::write(&out_path, encoded).with_context(|| format!("write {}", out_path.display()))?;

    println!("sp1 benchmark report written to {}", out_path.display());
    Ok(())
}

fn parse_proof_modes(raw: &str) -> Result<Vec<ProofMode>> {
    let mut out = Vec::new();
    for part in raw.split(',') {
        let p = part.trim().to_ascii_lowercase();
        let mode = match p.as_str() {
            "compressed" => ProofMode::Compressed,
            "groth16" => ProofMode::Groth16,
            "plonk" => ProofMode::Plonk,
            _ => return Err(anyhow!("unsupported proof mode: {p}")),
        };
        if !out.contains(&mode) {
            out.push(mode);
        }
    }
    if out.is_empty() {
        return Err(anyhow!("no proof modes selected"));
    }
    Ok(out)
}

fn parse_recursions(raw: &str) -> Result<Vec<RecursionMode>> {
    let mut out = Vec::new();
    for part in raw.split(',') {
        let p = part.trim().to_ascii_lowercase();
        let mode = match p.as_str() {
            "chain" => RecursionMode::Chain,
            "binary_tree" | "tree" => RecursionMode::BinaryTree,
            _ => return Err(anyhow!("unsupported recursion mode: {p}")),
        };
        if !out.contains(&mode) {
            out.push(mode);
        }
    }
    if out.is_empty() {
        return Err(anyhow!("no recursion modes selected"));
    }
    Ok(out)
}

#[allow(dead_code)]
fn file_exists(path: impl AsRef<Path>) -> bool {
    path.as_ref().exists()
}
