# SP1 Gas Harness Contracts

This Foundry project provides deterministic gas rows for the benchmark parser.

Run:

```bash
cd /Users/user0/Code/tk/gnark-playground/sp1/contracts
forge test --gas-report
```

The `bench_runner gas` command parses rows from `testVerifyGroth16` and
`testVerifyPlonk` in `MockSP1Verifier.t.sol`.
