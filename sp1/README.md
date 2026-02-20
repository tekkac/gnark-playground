# SP1 Benchmark Workspace

Privacy-first benchmark harness for recursion and settlement comparisons.

## Commands

From repo root:

```bash
make sp1-doctor
make sp1-bench-smoke
make sp1-bench-quick
make sp1-bench-full
make sp1-gas PROOF_SYSTEM=groth16
make sp1-compare SP1_REPORT=artifacts/sp1/reports/sp1_quick.json
```

Or from this folder:

```bash
cargo run -p bench_runner -- doctor
cargo run -p bench_runner -- run --profile smoke
cargo run -p bench_runner -- run --profile quick
cargo run -p bench_runner -- run --profile quick --engine deterministic
cargo run -p bench_runner -- gas --proof-system groth16
cargo run -p bench_runner -- compare --sp1 ../artifacts/sp1/reports/sp1_quick.json
```

## Privacy model

- Local-only execution.
- Run-scoped workspace under `/tmp/sp1-bench/<run_id>`.
- Strict cleanup before final report is written.
- No witness/proof bytes persisted in reports.

## Notes

- `programs/*` are SP1 zkVM guest programs compiled via `cargo prove build`; compiled ELFs are cached under each `programs/*/elf/`.
- `bench_runner run` defaults to real local SP1 proving (`execution_engine: sp1_local_cpu`) and supports `--engine deterministic` for fast smoke tests.
- recursion benchmarks use a dedicated `programs/recursion_verify` guest that verifies deferred compressed proofs and benchmarks both chain and binary-tree aggregation topologies.
- `contracts/` contains Foundry tests used by the gas report extractor.
- Pricing is static by default and timestamped in reports.
