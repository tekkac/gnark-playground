# zk (gnark)

Go module for gnark experiments.

## Commands

- `go run ./cmd/gnark-basic`: build local proof, verify, export Solidity verifier + fixture
- `go run ./cmd/gnark-recursive`: recursive gnark proof demo
- `go run ./cmd/circom-aggregate`: convert two Circom proofs and aggregate recursively
- `go run ./cmd/bench-prove -iterations 3`: benchmark timings with setup reuse and averaged prove/verify runs (uses cache by default, disable with `-cache=false`)
