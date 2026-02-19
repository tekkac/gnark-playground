package main

import (
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// InnerCircuit proves knowledge of P and Q such that P*Q == N.
type InnerCircuit struct {
	P frontend.Variable
	Q frontend.Variable
	N frontend.Variable `gnark:",public"`
}

func (c *InnerCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.P, c.Q), c.N)
	api.AssertIsDifferent(c.P, 1)
	api.AssertIsDifferent(c.Q, 1)
	return nil
}

// OuterCircuit verifies an inner Groth16 proof inside another circuit.
type OuterCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        stdgroth16.Proof[G1El, G2El]
	VerifyingKey stdgroth16.VerifyingKey[G1El, G2El, GtEl]
	InnerWitness stdgroth16.Witness[FR]
}

func (c *OuterCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new recursion verifier: %w", err)
	}
	return verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("recursive proof flow succeeded")
}

func run() error {
	innerCCS, innerVK, innerPublicWitness, innerProof, err := computeInnerProof(ecc.BN254.ScalarField())
	if err != nil {
		return err
	}

	circuitVK, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVK)
	if err != nil {
		return fmt.Errorf("convert verifying key for outer circuit: %w", err)
	}
	circuitWitness, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](innerPublicWitness)
	if err != nil {
		return fmt.Errorf("convert inner witness for outer circuit: %w", err)
	}
	circuitProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	if err != nil {
		return fmt.Errorf("convert proof for outer circuit: %w", err)
	}

	outerAssignment := &OuterCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVK,
	}

	outerCircuit := &OuterCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCCS),
		VerifyingKey: stdgroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCCS),
	}

	outerCCS, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, outerCircuit)
	if err != nil {
		return fmt.Errorf("compile outer circuit: %w", err)
	}

	outerPK, outerVK, err := groth16.Setup(outerCCS)
	if err != nil {
		return fmt.Errorf("outer setup: %w", err)
	}

	outerWitness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("outer full witness: %w", err)
	}
	outerPublicWitness, err := outerWitness.Public()
	if err != nil {
		return fmt.Errorf("outer public witness: %w", err)
	}

	outerProof, err := groth16.Prove(outerCCS, outerPK, outerWitness)
	if err != nil {
		return fmt.Errorf("outer prove: %w", err)
	}
	if err := groth16.Verify(outerProof, outerVK, outerPublicWitness); err != nil {
		return fmt.Errorf("outer verify: %w", err)
	}
	return nil
}

func computeInnerProof(field *big.Int) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof, error) {
	innerCCS, err := frontend.Compile(field, r1cs.NewBuilder, &InnerCircuit{})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("compile inner circuit: %w", err)
	}

	innerPK, innerVK, err := groth16.Setup(innerCCS)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("inner setup: %w", err)
	}

	innerAssignment := &InnerCircuit{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("inner full witness: %w", err)
	}
	innerProof, err := groth16.Prove(innerCCS, innerPK, innerWitness)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("inner prove: %w", err)
	}
	innerPublicWitness, err := innerWitness.Public()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("inner public witness: %w", err)
	}
	if err := groth16.Verify(innerProof, innerVK, innerPublicWitness); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("inner verify: %w", err)
	}

	return innerCCS, innerVK, innerPublicWitness, innerProof, nil
}
