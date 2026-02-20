# gnark-playground

Playground split into three trees:

- `circom/`: Circom + Circomkit proof generation
- `zk/`: Go + gnark proving/recursion
- `onchain/`: Foundry verifier tests
- `artifacts/`: shared outputs

## Prerequisites

- Go (tested with 1.26.0)
- Foundry (`forge`)
- Node.js + npm
- `circom` binary

## Layout

```text
.
├── circom/
├── sp1/
├── zk/
├── onchain/
└── artifacts/
```

## SP1 benchmark flow

Run from repo root:

```bash
make sp1-doctor
make sp1-bench-smoke
make sp1-bench-quick
make sp1-bench-full
make sp1-gas PROOF_SYSTEM=groth16
make sp1-compare SP1_REPORT=artifacts/sp1/reports/sp1_quick.json
make sp1-ci-quick
```

Notes:

- all intermediate benchmark artifacts are written under `/tmp/sp1-bench/<run_id>` and removed before report persistence,
- persisted reports go under `artifacts/sp1/reports/`,
- proof bytes/witnesses are not stored in reports; only hashes/sizes/metrics are recorded.
- `bench_runner` defaults to real local SP1 proving (`sp1_local_cpu`), with `--engine deterministic` available for fast CI smoke tests.

## Basic gnark + onchain flow

1. Generate BN254 proof + Solidity verifier + fixture:

```bash
make generate
```

2. Verify onchain in Foundry:

```bash
make test-solidity
```

3. Run gnark recursion demo:

```bash
make recursive
```

4. Measure proving times (basic, recursive, aggregate):

```bash
make bench-prove
```

Report path:

- `artifacts/bench/prove_bench.json`

Notes:

- setup is reused per workload (compile/setup once, then multiple prove+verify runs),
- default benchmark runs 3 prove iterations per workload.
- compile/setup artifacts are cached under `artifacts/bench/cache/` and reused on later runs.
- override example: `make bench-prove BENCH_ITERS=5 BENCH_WORKLOADS=basic,recursive`
- disable cache for fresh rebuild: `make bench-prove BENCH_CACHE=false`

## Circom to gnark recursion (two proofs)

1. Generate two Circom proofs:

```bash
make circom-install
make circom-prove
```

2. Convert/validate both proofs and aggregate recursively in gnark:

```bash
make aggregate-circom
```

This command:

- validates both Circom proofs as Groth16 on BN254,
- converts them to gnark-native and recursion types,
- writes raw gnark artifacts under `artifacts/circom/`,
- creates and verifies one outer gnark proof that verifies both inner proofs.

## Notes

- Solidity verifier export in gnark is BN254-only.
- `groth16.Setup` here is for experimentation only; production requires trusted setup/MPC ceremony practices.
