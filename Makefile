.PHONY: tidy generate recursive bench-prove circom-install circom-prove aggregate-circom test-go test-solidity test sp1-doctor sp1-bench-smoke sp1-bench-quick sp1-bench-full sp1-gas sp1-compare sp1-ci-quick

BENCH_ITERS ?= 3
BENCH_WORKLOADS ?= basic,recursive,aggregate
BENCH_OUT ?= ../artifacts/bench/prove_bench.json
BENCH_CACHE ?= true
SP1_REPORT ?= artifacts/sp1/reports/sp1_quick.json
SP1_COMPARE_OUT ?= artifacts/sp1/reports/sp1_compare.json
PROOF_SYSTEM ?= groth16

tidy:
	cd zk && go mod tidy

generate:
	cd zk && go run ./cmd/gnark-basic

recursive:
	cd zk && go run ./cmd/gnark-recursive

bench-prove:
	cd zk && go run ./cmd/bench-prove -iterations $(BENCH_ITERS) -workloads "$(BENCH_WORKLOADS)" -out "$(BENCH_OUT)" -cache=$(BENCH_CACHE)

circom-install:
	cd circom && npm install

circom-prove:
	cd circom && npm run all

aggregate-circom:
	cd zk && go run ./cmd/circom-aggregate

test-go:
	cd zk && go test ./...

test-solidity:
	cd onchain && forge test

test: generate test-go test-solidity

sp1-doctor:
	cd sp1 && cargo run -p bench_runner -- doctor

sp1-bench-smoke:
	cd sp1 && cargo run -p bench_runner -- run --profile smoke

sp1-bench-quick:
	cd sp1 && cargo run -p bench_runner -- run --profile quick

sp1-bench-full:
	cd sp1 && cargo run -p bench_runner -- run --profile full

sp1-gas:
	cd sp1 && cargo run -p bench_runner -- gas --proof-system $(PROOF_SYSTEM)

sp1-compare:
	cd sp1 && cargo run -p bench_runner -- compare --sp1 ../$(SP1_REPORT) --out ../$(SP1_COMPARE_OUT)

sp1-ci-quick:
	cd sp1 && cargo test -p bench_runner
	cd sp1 && cargo run -p bench_runner -- run --profile quick --engine deterministic --proof-modes groth16 --recursion chain --repeats 1
