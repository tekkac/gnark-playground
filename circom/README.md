# Circom Workspace

This folder is a `circomkit` workspace that generates BN254/Groth16 proofs
for gnark recursion experiments in `/Users/user0/Code/tk/gnark-playground/zk`.

## Prerequisites

- Node.js + npm
- `circom` binary available in your PATH

## Generate two sample proofs

```bash
cd /Users/user0/Code/tk/gnark-playground/circom
npm install
npm run all
```

Expected outputs include:

- `build/mul_a/default/groth16_proof.json`
- `build/mul_a/default/public.json`
- `build/mul_a/groth16_vkey.json`
- `build/mul_b/default/groth16_proof.json`
- `build/mul_b/default/public.json`
- `build/mul_b/groth16_vkey.json`

These are consumed by:

`/Users/user0/Code/tk/gnark-playground/zk/cmd/circom-aggregate/main.go`
