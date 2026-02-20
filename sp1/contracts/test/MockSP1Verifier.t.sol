// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MockSP1Verifier} from "../src/MockSP1Verifier.sol";

contract MockSP1VerifierTest {
    function testVerifyGroth16() public {
        MockSP1Verifier verifier = new MockSP1Verifier();
        bool ok = verifier.verifyGroth16(hex"1234", hex"5678");
        require(ok, "invalid groth16 proof");
    }

    function testVerifyPlonk() public {
        MockSP1Verifier verifier = new MockSP1Verifier();
        bool ok = verifier.verifyPlonk(hex"1234", hex"5678");
        require(ok, "invalid plonk proof");
    }
}
