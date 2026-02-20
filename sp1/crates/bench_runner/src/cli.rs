use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "bench_runner")]
#[command(about = "SP1 privacy-first benchmark orchestrator")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Doctor,
    Run {
        #[arg(long, default_value = "quick")]
        profile: String,
        #[arg(long, default_value = "sp1")]
        engine: String,
        #[arg(long)]
        proof_modes: Option<String>,
        #[arg(long)]
        recursion: Option<String>,
        #[arg(long)]
        repeats: Option<u32>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Gas {
        #[arg(long, default_value = "groth16")]
        proof_system: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Compare {
        #[arg(long)]
        sp1: PathBuf,
        #[arg(long, default_value = "gnark,circom,noir")]
        include_baselines: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}
