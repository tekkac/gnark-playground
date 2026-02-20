use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use sp1_sdk::blocking::{CpuProver, ProveRequest, Prover, ProverClient};
use sp1_sdk::{
    Elf, HashableKey, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin,
    SP1VerifyingKey,
};

use crate::config::{ProofMode, RecursionMode, RunConfig, WorkloadCase, WorkloadConfig};
use crate::report::{IterationSample, RecursionMetric, WorkloadMetric};
use crate::util::run_command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionEngine {
    Deterministic,
    Sp1,
}

impl ExecutionEngine {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "deterministic" | "deterministic_local" => Ok(Self::Deterministic),
            "sp1" => Ok(Self::Sp1),
            other => Err(anyhow!("unsupported engine: {other}")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deterministic => "deterministic_local",
            Self::Sp1 => "sp1_local_cpu",
        }
    }
}

pub fn run_workload_matrix(
    cfg: &RunConfig,
    workspace: &Path,
    engine: ExecutionEngine,
) -> Result<Vec<WorkloadMetric>> {
    match engine {
        ExecutionEngine::Deterministic => run_workload_matrix_deterministic(cfg, workspace),
        ExecutionEngine::Sp1 => run_workload_matrix_sp1(cfg),
    }
}

pub fn run_recursion_matrix(
    cfg: &RunConfig,
    workload_metrics: &[WorkloadMetric],
    workspace: &Path,
    engine: ExecutionEngine,
) -> Result<Vec<RecursionMetric>> {
    match engine {
        ExecutionEngine::Deterministic => {
            run_recursion_matrix_deterministic(cfg, workload_metrics, workspace)
        }
        ExecutionEngine::Sp1 => run_recursion_matrix_sp1(cfg),
    }
}

fn run_workload_matrix_sp1(cfg: &RunConfig) -> Result<Vec<WorkloadMetric>> {
    let mut harness = Sp1Harness::new()?;
    let mut out = Vec::new();

    for workload in &cfg.workloads {
        let pk = harness.ensure_program(&workload.name)?.pk.clone();
        for case in &workload.cases {
            for mode in &cfg.proof_modes {
                let mut samples = Vec::new();
                for i in 0..cfg.repeats {
                    let stdin = build_workload_stdin(workload, case)?;

                    let start_prove = Instant::now();
                    let proof = harness.prove_with_mode(&pk, stdin, mode)?;
                    let prove_ms = start_prove.elapsed().as_secs_f64() * 1000.0;

                    let start_verify = Instant::now();
                    harness
                        .prover
                        .verify(&proof, pk.verifying_key(), None)
                        .map_err(|e| anyhow!("verify failed for {}: {e}", workload.name))?;
                    let verify_ms = start_verify.elapsed().as_secs_f64() * 1000.0;

                    let (proof_size_bytes, proof_hash) = proof_artifact(mode, &proof)?;
                    let memory_peak_bytes =
                        estimate_memory_peak(workload, case, mode, proof_size_bytes);

                    samples.push(IterationSample {
                        index: i,
                        prove_ms,
                        verify_ms,
                        memory_peak_bytes,
                        proof_size_bytes,
                        proof_hash,
                    });
                }

                let avg_prove_ms = mean(samples.iter().map(|s| s.prove_ms));
                let avg_verify_ms = mean(samples.iter().map(|s| s.verify_ms));
                let avg_memory_peak_bytes =
                    mean(samples.iter().map(|s| s.memory_peak_bytes as f64)) as u64;

                let final_sample = samples
                    .last()
                    .ok_or_else(|| anyhow!("missing sample for {}", workload.name))?;

                out.push(WorkloadMetric {
                    workload: workload.name.clone(),
                    tier: workload.tier.clone(),
                    case_label: case.label.clone(),
                    proof_mode: mode.clone(),
                    repeats: cfg.repeats,
                    avg_prove_ms,
                    avg_verify_ms,
                    avg_memory_peak_bytes,
                    proof_size_bytes: final_sample.proof_size_bytes,
                    proof_hash: final_sample.proof_hash.clone(),
                    samples,
                });
            }
        }
    }

    Ok(out)
}

fn run_recursion_matrix_sp1(cfg: &RunConfig) -> Result<Vec<RecursionMetric>> {
    let base_workload = cfg
        .workloads
        .first()
        .ok_or_else(|| anyhow!("at least one workload is required for recursion runs"))?;
    let base_case = base_workload
        .cases
        .first()
        .ok_or_else(|| anyhow!("workload {} has no cases", base_workload.name))?;

    let mut harness = Sp1Harness::new()?;
    let mut out = Vec::new();

    for mode in &cfg.proof_modes {
        if cfg.recursion.enabled.contains(&RecursionMode::Chain) {
            for depth in &cfg.recursion.chain_depths {
                out.push(harness.benchmark_chain(mode, *depth, base_workload, base_case)?);
            }
        }
        if cfg.recursion.enabled.contains(&RecursionMode::BinaryTree) {
            for leaves in &cfg.recursion.binary_tree_leaves {
                out.push(harness.benchmark_binary_tree(mode, *leaves, base_workload, base_case)?);
            }
        }
    }

    Ok(out)
}

#[derive(Clone)]
struct ProgramHandle {
    pk: SP1ProvingKey,
}

#[derive(Clone)]
struct DeferredProofItem {
    proof: SP1ProofWithPublicValues,
    vk: SP1VerifyingKey,
    vk_digest: [u32; 8],
    pv_digest: [u8; 32],
}

impl DeferredProofItem {
    fn from_bundle(proof: SP1ProofWithPublicValues, vk: SP1VerifyingKey) -> Result<Self> {
        if !matches!(proof.proof, SP1Proof::Compressed(_)) {
            return Err(anyhow!(
                "expected compressed proof for deferred recursion input"
            ));
        }
        let pv_hash = proof.public_values.hash();
        let pv_digest: [u8; 32] = pv_hash
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("invalid public values hash length"))?;
        Ok(Self {
            proof,
            vk_digest: vk.hash_u32(),
            vk,
            pv_digest,
        })
    }

    fn write_to_stdin(&self, stdin: &mut SP1Stdin) -> Result<()> {
        let deferred = match &self.proof.proof {
            SP1Proof::Compressed(p) => p.as_ref().clone(),
            _ => return Err(anyhow!("deferred input expected compressed proof")),
        };
        stdin.write_proof(deferred, self.vk.vk.clone());
        Ok(())
    }
}

struct NodeOutcome {
    proof: SP1ProofWithPublicValues,
    prove_ms: f64,
    verify_ms: f64,
}

struct Sp1Harness {
    workspace_root: PathBuf,
    prover: CpuProver,
    programs: HashMap<String, ProgramHandle>,
}

impl Sp1Harness {
    fn new() -> Result<Self> {
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .context("resolve SP1 workspace root")?;

        Ok(Self {
            workspace_root,
            prover: ProverClient::builder().cpu().build(),
            programs: HashMap::new(),
        })
    }

    fn ensure_program(&mut self, name: &str) -> Result<&ProgramHandle> {
        if !self.programs.contains_key(name) {
            let handle = self.compile_and_setup_program(name)?;
            self.programs.insert(name.to_string(), handle);
        }
        self.programs
            .get(name)
            .ok_or_else(|| anyhow!("failed to initialize program {name}"))
    }

    fn compile_and_setup_program(&self, name: &str) -> Result<ProgramHandle> {
        let program_dir = self.workspace_root.join("programs").join(name);
        if !program_dir.exists() {
            return Err(anyhow!(
                "program directory missing: {}",
                program_dir.display()
            ));
        }

        let elf_dir = program_dir.join("elf");
        let elf_path = elf_dir.join(name);
        fs::create_dir_all(&elf_dir).with_context(|| format!("create {}", elf_dir.display()))?;

        if !elf_path.exists() {
            let output_dir = elf_dir.display().to_string();
            let args = [
                "prove",
                "build",
                "--output-directory",
                output_dir.as_str(),
                "--elf-name",
                name,
            ];
            let output = run_command("cargo", &args, Some(&program_dir), &[])
                .with_context(|| format!("compile SP1 program {name} with cargo prove build"))?;

            if !output.status_ok {
                return Err(anyhow!(
                    "SP1 build failed for {name}: {}",
                    output.stderr.trim()
                ));
            }
        }

        let elf = Elf::from(
            fs::read(&elf_path)
                .with_context(|| format!("read compiled ELF {}", elf_path.display()))?,
        );
        let pk = self
            .prover
            .setup(elf)
            .map_err(|e| anyhow!("setup failed for program {name}: {e}"))?;
        Ok(ProgramHandle { pk })
    }

    fn prove_with_mode(
        &self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        mode: &ProofMode,
    ) -> Result<SP1ProofWithPublicValues> {
        let request = self.prover.prove(pk, stdin);
        let proof = match mode {
            ProofMode::Compressed => request.compressed().run(),
            ProofMode::Groth16 => request.groth16().run(),
            ProofMode::Plonk => request.plonk().run(),
        }
        .map_err(|e| anyhow!("prove failed in {} mode: {e}", mode_name(mode)))?;
        Ok(proof)
    }

    fn generate_base_deferreds(
        &mut self,
        workload: &WorkloadConfig,
        case: &WorkloadCase,
        count: usize,
        total_prove_ms: &mut f64,
    ) -> Result<Vec<DeferredProofItem>> {
        let pk = self.ensure_program(&workload.name)?.pk.clone();
        let base_vk = pk.verifying_key().clone();

        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let stdin = build_workload_stdin(workload, case)?;
            let started = Instant::now();
            let proof = self.prove_with_mode(&pk, stdin, &ProofMode::Compressed)?;
            *total_prove_ms += started.elapsed().as_secs_f64() * 1000.0;
            out.push(DeferredProofItem::from_bundle(proof, base_vk.clone())?);
        }
        Ok(out)
    }

    fn prove_aggregate_node(
        &mut self,
        children: &[DeferredProofItem],
        mode: &ProofMode,
    ) -> Result<NodeOutcome> {
        let recursion_pk = self.ensure_program("recursion_verify")?.pk.clone();

        let mut stdin = SP1Stdin::new();
        let digests: Vec<([u32; 8], [u8; 32])> = children
            .iter()
            .map(|p| (p.vk_digest, p.pv_digest))
            .collect();
        stdin.write(&digests);
        for child in children {
            child.write_to_stdin(&mut stdin)?;
        }

        let start_prove = Instant::now();
        let proof = self.prove_with_mode(&recursion_pk, stdin, mode)?;
        let prove_ms = start_prove.elapsed().as_secs_f64() * 1000.0;

        let start_verify = Instant::now();
        self.prover
            .verify(&proof, recursion_pk.verifying_key(), None)
            .map_err(|e| anyhow!("recursive proof verification failed: {e}"))?;
        let verify_ms = start_verify.elapsed().as_secs_f64() * 1000.0;

        Ok(NodeOutcome {
            proof,
            prove_ms,
            verify_ms,
        })
    }

    fn benchmark_chain(
        &mut self,
        mode: &ProofMode,
        depth: u32,
        base_workload: &WorkloadConfig,
        base_case: &WorkloadCase,
    ) -> Result<RecursionMetric> {
        let statement_count = depth as usize;
        if statement_count < 2 {
            return Err(anyhow!("chain depth must be >= 2"));
        }

        let recursion_vk = self
            .ensure_program("recursion_verify")?
            .pk
            .verifying_key()
            .clone();

        let mut prove_ms = 0.0;
        let mut leaves =
            self.generate_base_deferreds(base_workload, base_case, statement_count, &mut prove_ms)?;

        let mut current = leaves
            .drain(..1)
            .next()
            .ok_or_else(|| anyhow!("missing first leaf proof"))?;
        let mut final_proof: Option<SP1ProofWithPublicValues> = None;
        let mut final_verify_ms = 0.0;

        for (idx, leaf) in leaves.into_iter().enumerate() {
            let is_last = idx + 1 == statement_count - 1;
            let node_mode = if is_last {
                mode.clone()
            } else {
                ProofMode::Compressed
            };

            let outcome = self.prove_aggregate_node(&[current.clone(), leaf], &node_mode)?;
            prove_ms += outcome.prove_ms;
            if is_last {
                final_verify_ms = outcome.verify_ms;
                final_proof = Some(outcome.proof);
            } else {
                current = DeferredProofItem::from_bundle(outcome.proof, recursion_vk.clone())?;
            }
        }

        let final_proof = final_proof.ok_or_else(|| anyhow!("missing chain final proof"))?;
        let (proof_size_bytes, proof_hash) = proof_artifact(mode, &final_proof)?;

        let complexity = workload_complexity(base_workload, base_case) as u64;
        let node_count = statement_count as u64 - 1;
        let memory_peak_bytes = 256 * 1024 * 1024 + complexity * 128 + node_count * 1024;

        Ok(RecursionMetric {
            proof_mode: mode.clone(),
            topology: RecursionMode::Chain,
            size: depth,
            prove_ms,
            verify_ms: final_verify_ms,
            memory_peak_bytes,
            proof_size_bytes,
            proof_hash,
        })
    }

    fn benchmark_binary_tree(
        &mut self,
        mode: &ProofMode,
        leaves: u32,
        base_workload: &WorkloadConfig,
        base_case: &WorkloadCase,
    ) -> Result<RecursionMetric> {
        let leaf_count = leaves as usize;
        if leaf_count < 2 {
            return Err(anyhow!("binary_tree leaves must be >= 2"));
        }
        if !leaf_count.is_power_of_two() {
            return Err(anyhow!("binary_tree leaves must be power-of-two"));
        }

        let recursion_vk = self
            .ensure_program("recursion_verify")?
            .pk
            .verifying_key()
            .clone();

        let mut prove_ms = 0.0;
        let mut level =
            self.generate_base_deferreds(base_workload, base_case, leaf_count, &mut prove_ms)?;
        let mut final_proof: Option<SP1ProofWithPublicValues> = None;
        let mut final_verify_ms = 0.0;

        while level.len() > 1 {
            if level.len() % 2 != 0 {
                return Err(anyhow!("binary tree level has odd node count"));
            }

            let is_last_level = level.len() == 2;
            let mut next = Vec::with_capacity(level.len() / 2);

            for pair in level.chunks(2) {
                let node_mode = if is_last_level {
                    mode.clone()
                } else {
                    ProofMode::Compressed
                };
                let outcome =
                    self.prove_aggregate_node(&[pair[0].clone(), pair[1].clone()], &node_mode)?;
                prove_ms += outcome.prove_ms;

                if is_last_level {
                    final_verify_ms = outcome.verify_ms;
                    final_proof = Some(outcome.proof);
                } else {
                    next.push(DeferredProofItem::from_bundle(
                        outcome.proof,
                        recursion_vk.clone(),
                    )?);
                }
            }

            level = next;
        }

        let final_proof = final_proof.ok_or_else(|| anyhow!("missing binary tree final proof"))?;
        let (proof_size_bytes, proof_hash) = proof_artifact(mode, &final_proof)?;

        let complexity = workload_complexity(base_workload, base_case) as u64;
        let node_count = leaf_count as u64 - 1;
        let memory_peak_bytes = 256 * 1024 * 1024 + complexity * 128 + node_count * 1024;

        Ok(RecursionMetric {
            proof_mode: mode.clone(),
            topology: RecursionMode::BinaryTree,
            size: leaves,
            prove_ms,
            verify_ms: final_verify_ms,
            memory_peak_bytes,
            proof_size_bytes,
            proof_hash,
        })
    }
}

fn build_workload_stdin(workload: &WorkloadConfig, case: &WorkloadCase) -> Result<SP1Stdin> {
    let mut stdin = SP1Stdin::new();
    match workload.name.as_str() {
        "hash_merkle" => {
            stdin.write(&case.leaves.ok_or_else(|| anyhow!("missing leaves"))?);
            stdin.write(&case.rounds.ok_or_else(|| anyhow!("missing rounds"))?);
        }
        "sig_batch" => {
            stdin.write(
                &case
                    .batch_size
                    .ok_or_else(|| anyhow!("missing batch_size"))?,
            );
            stdin.write(&case.rounds.ok_or_else(|| anyhow!("missing rounds"))?);
        }
        "vm_stress" => {
            stdin.write(&case.steps.ok_or_else(|| anyhow!("missing steps"))?);
            stdin.write(&case.loops.ok_or_else(|| anyhow!("missing loops"))?);
        }
        _ => return Err(anyhow!("unsupported workload {}", workload.name)),
    }
    Ok(stdin)
}

fn proof_artifact(mode: &ProofMode, proof: &SP1ProofWithPublicValues) -> Result<(u64, String)> {
    let bytes = proof_bytes(mode, proof)?;
    Ok((bytes.len() as u64, sha256_hex(&bytes)))
}

fn proof_bytes(mode: &ProofMode, proof: &SP1ProofWithPublicValues) -> Result<Vec<u8>> {
    match (mode, &proof.proof) {
        (ProofMode::Compressed, SP1Proof::Compressed(_)) => {
            bincode::serialize(proof).context("serialize compressed proof")
        }
        (ProofMode::Groth16, SP1Proof::Groth16(_)) => Ok(proof.bytes()),
        (ProofMode::Plonk, SP1Proof::Plonk(_)) => Ok(proof.bytes()),
        _ => Err(anyhow!(
            "proof mode mismatch: expected {}, got {}",
            mode_name(mode),
            match &proof.proof {
                SP1Proof::Core(_) => "core",
                SP1Proof::Compressed(_) => "compressed",
                SP1Proof::Groth16(_) => "groth16",
                SP1Proof::Plonk(_) => "plonk",
            }
        )),
    }
}

fn run_workload_matrix_deterministic(
    cfg: &RunConfig,
    workspace: &Path,
) -> Result<Vec<WorkloadMetric>> {
    let proofs_dir = workspace.join("proofs");
    fs::create_dir_all(&proofs_dir).with_context(|| format!("create {}", proofs_dir.display()))?;

    let mut out = Vec::new();

    for workload in &cfg.workloads {
        for case in &workload.cases {
            for mode in &cfg.proof_modes {
                let mut samples = Vec::new();
                for i in 0..cfg.repeats {
                    samples.push(run_one_iteration_deterministic(
                        workload,
                        case,
                        mode,
                        i,
                        &proofs_dir,
                    )?);
                }

                let avg_prove_ms = mean(samples.iter().map(|s| s.prove_ms));
                let avg_verify_ms = mean(samples.iter().map(|s| s.verify_ms));
                let avg_memory_peak_bytes =
                    mean(samples.iter().map(|s| s.memory_peak_bytes as f64)) as u64;

                let final_sample = samples
                    .last()
                    .ok_or_else(|| anyhow!("missing sample for {}", workload.name))?;

                out.push(WorkloadMetric {
                    workload: workload.name.clone(),
                    tier: workload.tier.clone(),
                    case_label: case.label.clone(),
                    proof_mode: mode.clone(),
                    repeats: cfg.repeats,
                    avg_prove_ms,
                    avg_verify_ms,
                    avg_memory_peak_bytes,
                    proof_size_bytes: final_sample.proof_size_bytes,
                    proof_hash: final_sample.proof_hash.clone(),
                    samples,
                });
            }
        }
    }

    Ok(out)
}

fn run_recursion_matrix_deterministic(
    cfg: &RunConfig,
    workload_metrics: &[WorkloadMetric],
    workspace: &Path,
) -> Result<Vec<RecursionMetric>> {
    let rec_dir = workspace.join("recursion");
    fs::create_dir_all(&rec_dir).with_context(|| format!("create {}", rec_dir.display()))?;

    let mut base_by_mode: HashMap<ProofMode, f64> = HashMap::new();
    for mode in &cfg.proof_modes {
        let values: Vec<f64> = workload_metrics
            .iter()
            .filter(|w| &w.proof_mode == mode)
            .map(|w| w.avg_prove_ms)
            .collect();
        if !values.is_empty() {
            base_by_mode.insert(mode.clone(), mean(values.into_iter()));
        }
    }

    let mut out = Vec::new();

    for mode in &cfg.proof_modes {
        let Some(base) = base_by_mode.get(mode).copied() else {
            continue;
        };

        if cfg.recursion.enabled.contains(&RecursionMode::Chain) {
            for depth in &cfg.recursion.chain_depths {
                out.push(simulate_recursion(
                    mode,
                    RecursionMode::Chain,
                    *depth,
                    base,
                    &rec_dir,
                )?);
            }
        }

        if cfg.recursion.enabled.contains(&RecursionMode::BinaryTree) {
            for leaves in &cfg.recursion.binary_tree_leaves {
                out.push(simulate_recursion(
                    mode,
                    RecursionMode::BinaryTree,
                    *leaves,
                    base,
                    &rec_dir,
                )?);
            }
        }
    }

    Ok(out)
}

fn run_one_iteration_deterministic(
    workload: &WorkloadConfig,
    case: &WorkloadCase,
    mode: &ProofMode,
    index: u32,
    proofs_dir: &Path,
) -> Result<IterationSample> {
    let start_prove = Instant::now();
    let workload_digest = execute_workload(workload, case)?;

    let proof_size = proof_size_for(mode, workload, case);
    let proof_bytes = synthesize_proof_bytes(&workload_digest, proof_size as usize, index);

    let proof_file = proofs_dir.join(format!(
        "{}_{}_{}_{}.bin",
        workload.name,
        case.label,
        mode_name(mode),
        index
    ));
    fs::write(&proof_file, &proof_bytes)
        .with_context(|| format!("write {}", proof_file.display()))?;

    let prove_ms = start_prove.elapsed().as_secs_f64() * 1000.0;

    let start_verify = Instant::now();
    let verified_hash = sha256_hex(&proof_bytes);
    for _ in 0..verify_rounds(mode) {
        let _ = sha256_hex(verified_hash.as_bytes());
    }
    let verify_ms = start_verify.elapsed().as_secs_f64() * 1000.0;

    let memory_peak_bytes = estimate_memory_peak(workload, case, mode, proof_size);

    Ok(IterationSample {
        index,
        prove_ms,
        verify_ms,
        memory_peak_bytes,
        proof_size_bytes: proof_size,
        proof_hash: verified_hash,
    })
}

fn execute_workload(workload: &WorkloadConfig, case: &WorkloadCase) -> Result<[u8; 32]> {
    match workload.name.as_str() {
        "hash_merkle" => {
            let params = hash_merkle::HashMerkleParams {
                leaves: case.leaves.ok_or_else(|| anyhow!("missing leaves"))?,
                rounds: case.rounds.ok_or_else(|| anyhow!("missing rounds"))?,
            };
            let leaves = hash_merkle::deterministic_leaves(params);
            Ok(hash_merkle::merkle_root(leaves))
        }
        "sig_batch" => {
            let params = sig_batch::SigBatchParams {
                batch_size: case
                    .batch_size
                    .ok_or_else(|| anyhow!("missing batch_size"))?,
                rounds: case.rounds.ok_or_else(|| anyhow!("missing rounds"))?,
            };
            let messages = sig_batch::deterministic_messages(params);
            let pubkeys = sig_batch::deterministic_pubkeys(params);
            Ok(sig_batch::simulated_verify(
                &messages,
                &pubkeys,
                params.rounds,
            ))
        }
        "vm_stress" => {
            let params = vm_stress::VmStressParams {
                steps: case.steps.ok_or_else(|| anyhow!("missing steps"))?,
                loops: case.loops.ok_or_else(|| anyhow!("missing loops"))?,
            };
            Ok(vm_stress::execute(params))
        }
        _ => Err(anyhow!("unsupported workload {}", workload.name)),
    }
}

fn simulate_recursion(
    mode: &ProofMode,
    topology: RecursionMode,
    size: u32,
    base: f64,
    rec_dir: &Path,
) -> Result<RecursionMetric> {
    let (prove_scale, verify_base, memory_scale) = match topology {
        RecursionMode::Chain => (size as f64, 1.0, size as u64),
        RecursionMode::BinaryTree => ((size.saturating_sub(1)) as f64, 1.2, size as u64 / 2 + 1),
    };

    let mode_factor = match mode {
        ProofMode::Compressed => 1.0,
        ProofMode::Groth16 => 1.25,
        ProofMode::Plonk => 1.45,
    };

    let prove_ms = (base * prove_scale * mode_factor) / 3.0;
    let verify_ms = verify_base
        + match mode {
            ProofMode::Compressed => 2.0,
            ProofMode::Groth16 => 5.5,
            ProofMode::Plonk => 8.0,
        };

    let proof_size_bytes = match mode {
        ProofMode::Compressed => 64 * 1024,
        ProofMode::Groth16 => 272,
        ProofMode::Plonk => 768,
    } + (size as u64 * 3);

    let mut h = Sha256::new();
    h.update(mode_name(mode));
    h.update(format!("{:?}", topology));
    h.update(size.to_le_bytes());
    let digest = h.finalize();
    let proof_hash = hex::encode(digest);

    let path = rec_dir.join(format!(
        "{}_{}_{}.meta",
        mode_name(mode),
        match topology {
            RecursionMode::Chain => "chain",
            RecursionMode::BinaryTree => "binary_tree",
        },
        size
    ));
    fs::write(&path, proof_hash.as_bytes()).with_context(|| format!("write {}", path.display()))?;

    Ok(RecursionMetric {
        proof_mode: mode.clone(),
        topology,
        size,
        prove_ms,
        verify_ms,
        memory_peak_bytes: 128 * 1024 * 1024 + memory_scale * 1024,
        proof_size_bytes,
        proof_hash,
    })
}

fn proof_size_for(mode: &ProofMode, workload: &WorkloadConfig, case: &WorkloadCase) -> u64 {
    let complexity = workload_complexity(workload, case) as u64;
    match mode {
        ProofMode::Compressed => 48 * 1024 + complexity,
        ProofMode::Groth16 => 256 + complexity / 128,
        ProofMode::Plonk => 704 + complexity / 96,
    }
}

fn workload_complexity(workload: &WorkloadConfig, case: &WorkloadCase) -> usize {
    match workload.name.as_str() {
        "hash_merkle" => case.leaves.unwrap_or(1) * case.rounds.unwrap_or(1) as usize,
        "sig_batch" => case.batch_size.unwrap_or(1) * case.rounds.unwrap_or(1) as usize,
        "vm_stress" => case.steps.unwrap_or(1) * case.loops.unwrap_or(1),
        _ => 1,
    }
}

fn estimate_memory_peak(
    workload: &WorkloadConfig,
    case: &WorkloadCase,
    mode: &ProofMode,
    proof_size: u64,
) -> u64 {
    let complexity = workload_complexity(workload, case) as u64;
    let mode_overhead = match mode {
        ProofMode::Compressed => 256 * 1024 * 1024,
        ProofMode::Groth16 => 384 * 1024 * 1024,
        ProofMode::Plonk => 448 * 1024 * 1024,
    };
    mode_overhead + complexity * 512 + proof_size
}

fn synthesize_proof_bytes(seed: &[u8; 32], size: usize, index: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(size);
    let mut block = seed.to_vec();
    while out.len() < size {
        let mut h = Sha256::new();
        h.update(&block);
        h.update(index.to_le_bytes());
        block = h.finalize().to_vec();
        out.extend_from_slice(&block);
    }
    out.truncate(size);
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn mode_name(mode: &ProofMode) -> &'static str {
    match mode {
        ProofMode::Compressed => "compressed",
        ProofMode::Groth16 => "groth16",
        ProofMode::Plonk => "plonk",
    }
}

fn verify_rounds(mode: &ProofMode) -> u32 {
    match mode {
        ProofMode::Compressed => 2,
        ProofMode::Groth16 => 4,
        ProofMode::Plonk => 6,
    }
}

fn mean<I>(iter: I) -> f64
where
    I: IntoIterator<Item = f64>,
{
    let mut sum = 0.0;
    let mut count = 0u64;
    for v in iter {
        sum += v;
        count += 1;
    }
    if count == 0 {
        0.0
    } else {
        sum / count as f64
    }
}

#[cfg(test)]
mod tests {
    use super::{run_workload_matrix, ExecutionEngine};
    use crate::config::{
        PricingConfig, ProofMode, RecursionConfig, RecursionMode, RunConfig, WorkloadCase,
        WorkloadConfig,
    };
    use tempfile::TempDir;

    #[test]
    fn builds_expected_matrix_rows() {
        let cfg = RunConfig {
            profile: "quick".into(),
            repeats: 2,
            cleanup_policy: "strict_ephemeral".into(),
            proof_modes: vec![ProofMode::Compressed, ProofMode::Groth16],
            recursion: RecursionConfig {
                enabled: vec![RecursionMode::Chain],
                chain_depths: vec![2],
                binary_tree_leaves: vec![],
            },
            workloads: vec![WorkloadConfig {
                name: "hash_merkle".into(),
                tier: "micro".into(),
                cases: vec![WorkloadCase {
                    label: "s".into(),
                    leaves: Some(16),
                    rounds: Some(4),
                    batch_size: None,
                    steps: None,
                    loops: None,
                }],
            }],
            pricing: PricingConfig {
                mode: "static".into(),
                eth_usd: 2000.0,
                gas_gwei: 5.0,
                groth16_verify_gas: 270000,
                plonk_verify_gas: 300000,
            },
        };

        let tmp = TempDir::new().unwrap();
        let rows = run_workload_matrix(&cfg, tmp.path(), ExecutionEngine::Deterministic).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].samples.len(), 2);
    }
}
