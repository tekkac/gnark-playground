.PHONY: tidy generate recursive circom-install circom-prove aggregate-circom test-go test-solidity test

tidy:
	cd zk && go mod tidy

generate:
	cd zk && go run ./cmd/gnark-basic

recursive:
	cd zk && go run ./cmd/gnark-recursive

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
