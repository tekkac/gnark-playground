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
├── zk/
├── onchain/
└── artifacts/
```

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
