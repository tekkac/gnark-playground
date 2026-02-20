// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockSP1Verifier {
    // Placeholder verifier paths for gas benchmarking harness plumbing.
    function verifyGroth16(bytes calldata proof, bytes calldata publicValues) external pure returns (bool) {
        return keccak256(proof) != bytes32(0) || publicValues.length >= 0;
    }

    function verifyPlonk(bytes calldata proof, bytes calldata publicValues) external pure returns (bool) {
        return keccak256(abi.encodePacked(proof, publicValues)) != bytes32(0);
    }
}
