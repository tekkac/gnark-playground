pragma solidity ^0.8.20;

import {Verifier} from "../contracts/Verifier.sol";
import {GnarkFixture} from "./GnarkFixture.sol";

contract GnarkVerifierTest {
    function testVerifyProof() public {
        Verifier verifier = new Verifier();
        uint256[8] memory proof = GnarkFixture.proof();
        uint256[1] memory publicInputs = GnarkFixture.publicInputs();
        verifier.verifyProof(proof, publicInputs);
    }
}
