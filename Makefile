.PHONY: tidy generate recursive bench-prove circom-install circom-prove aggregate-circom test-go test-solidity test

BENCH_ITERS ?= 3
BENCH_WORKLOADS ?= basic,recursive,aggregate
BENCH_OUT ?= ../artifacts/bench/prove_bench.json
BENCH_CACHE ?= true

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
