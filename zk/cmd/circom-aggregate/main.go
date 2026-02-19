package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/circom2gnark/parser"
)

type proofInput struct {
	Name   string
	Proof  string
	Public string
	VKey   string
}

type convertedProof struct {
	Input               proofInput
	CircomPublicSignals []string
	RecursionProof      *parser.GnarkRecursionProof
	Placeholders        *parser.GnarkRecursionPlaceholders
	ProofRawPath        string
	VKRawPath           string
	PublicSignalsPath   string
}

type report struct {
	OuterConstraints int `json:"outerConstraints"`
	Proof1           struct {
		Name             string `json:"name"`
		ProofRawPath     string `json:"proofRawPath"`
		VerifyingKeyPath string `json:"verifyingKeyRawPath"`
		PublicSignals    string `json:"publicSignalsPath"`
	} `json:"proof1"`
	Proof2 struct {
		Name             string `json:"name"`
		ProofRawPath     string `json:"proofRawPath"`
		VerifyingKeyPath string `json:"verifyingKeyRawPath"`
		PublicSignals    string `json:"publicSignalsPath"`
	} `json:"proof2"`
}

// AggregateTwoCircomProofsCircuit verifies two BN254 Groth16 proofs in one outer circuit.
type AggregateTwoCircomProofsCircuit struct {
	Proof1        stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VerifyingKey1 stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	PublicInputs1 stdgroth16.Witness[sw_bn254.ScalarField] `gnark:",public"`

	Proof2        stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VerifyingKey2 stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	PublicInputs2 stdgroth16.Witness[sw_bn254.ScalarField] `gnark:",public"`
}

func (c *AggregateTwoCircomProofsCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new recursion verifier: %w", err)
	}
	if err := verifier.AssertProof(c.VerifyingKey1, c.Proof1, c.PublicInputs1, stdgroth16.WithCompleteArithmetic()); err != nil {
		return fmt.Errorf("verify proof1 in-circuit: %w", err)
	}
	if err := verifier.AssertProof(c.VerifyingKey2, c.Proof2, c.PublicInputs2, stdgroth16.WithCompleteArithmetic()); err != nil {
		return fmt.Errorf("verify proof2 in-circuit: %w", err)
	}
	return nil
}

func main() {
	var (
		proof1Path  = flag.String("proof1", filepath.Join("..", "circom", "build", "mul_a", "default", "groth16_proof.json"), "path to first circom proof json")
		public1Path = flag.String("public1", filepath.Join("..", "circom", "build", "mul_a", "default", "public.json"), "path to first circom public.json")
		vkey1Path   = flag.String("vkey1", filepath.Join("..", "circom", "build", "mul_a", "groth16_vkey.json"), "path to first circom verification key json")
		name1       = flag.String("name1", "proof1", "label for first proof artifacts")

		proof2Path  = flag.String("proof2", filepath.Join("..", "circom", "build", "mul_b", "default", "groth16_proof.json"), "path to second circom proof json")
		public2Path = flag.String("public2", filepath.Join("..", "circom", "build", "mul_b", "default", "public.json"), "path to second circom public.json")
		vkey2Path   = flag.String("vkey2", filepath.Join("..", "circom", "build", "mul_b", "groth16_vkey.json"), "path to second circom verification key json")
		name2       = flag.String("name2", "proof2", "label for second proof artifacts")

		reportPath = flag.String("out", filepath.Join("..", "artifacts", "circom", "aggregate_report.json"), "path to write aggregation report")
	)
	flag.Parse()

	p1 := proofInput{Name: *name1, Proof: *proof1Path, Public: *public1Path, VKey: *vkey1Path}
	p2 := proofInput{Name: *name2, Proof: *proof2Path, Public: *public2Path, VKey: *vkey2Path}

	if err := run(p1, p2, *reportPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("circom proofs converted and recursively aggregated")
}

func run(p1, p2 proofInput, reportPath string) error {
	outDir := filepath.Join("..", "artifacts", "circom")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create artifacts dir: %w", err)
	}

	c1, err := convertProof(p1, outDir)
	if err != nil {
		return err
	}
	c2, err := convertProof(p2, outDir)
	if err != nil {
		return err
	}

	placeholderCircuit := &AggregateTwoCircomProofsCircuit{
		Proof1:        c1.Placeholders.Proof,
		VerifyingKey1: c1.Placeholders.Vk,
		PublicInputs1: c1.Placeholders.Witness,
		Proof2:        c2.Placeholders.Proof,
		VerifyingKey2: c2.Placeholders.Vk,
		PublicInputs2: c2.Placeholders.Witness,
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, placeholderCircuit)
	if err != nil {
		return fmt.Errorf("compile outer aggregation circuit: %w", err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return fmt.Errorf("setup outer aggregation circuit: %w", err)
	}

	assignment := &AggregateTwoCircomProofsCircuit{
		Proof1:        c1.RecursionProof.Proof,
		VerifyingKey1: c1.RecursionProof.Vk,
		PublicInputs1: c1.RecursionProof.PublicInputs,
		Proof2:        c2.RecursionProof.Proof,
		VerifyingKey2: c2.RecursionProof.Vk,
		PublicInputs2: c2.RecursionProof.PublicInputs,
	}

	wFull, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("create outer full witness: %w", err)
	}
	wPublic, err := wFull.Public()
	if err != nil {
		return fmt.Errorf("create outer public witness: %w", err)
	}

	outerProof, err := groth16.Prove(ccs, pk, wFull)
	if err != nil {
		return fmt.Errorf("prove outer aggregation circuit: %w", err)
	}
	if err := groth16.Verify(outerProof, vk, wPublic); err != nil {
		return fmt.Errorf("verify outer aggregation proof: %w", err)
	}

	rep := report{
		OuterConstraints: ccs.GetNbConstraints(),
	}
	rep.Proof1.Name = c1.Input.Name
	rep.Proof1.ProofRawPath = c1.ProofRawPath
	rep.Proof1.VerifyingKeyPath = c1.VKRawPath
	rep.Proof1.PublicSignals = c1.PublicSignalsPath
	rep.Proof2.Name = c2.Input.Name
	rep.Proof2.ProofRawPath = c2.ProofRawPath
	rep.Proof2.VerifyingKeyPath = c2.VKRawPath
	rep.Proof2.PublicSignals = c2.PublicSignalsPath

	if err := writeJSON(reportPath, rep); err != nil {
		return err
	}
	return nil
}

func convertProof(in proofInput, outDir string) (*convertedProof, error) {
	proofJSON, err := os.ReadFile(in.Proof)
	if err != nil {
		return nil, fmt.Errorf("read proof file %s: %w", in.Proof, err)
	}
	publicJSON, err := os.ReadFile(in.Public)
	if err != nil {
		return nil, fmt.Errorf("read public file %s: %w", in.Public, err)
	}
	vkJSON, err := os.ReadFile(in.VKey)
	if err != nil {
		return nil, fmt.Errorf("read verification key file %s: %w", in.VKey, err)
	}

	circomProof, err := parser.UnmarshalCircomProofJSON(proofJSON)
	if err != nil {
		return nil, fmt.Errorf("%s: parse proof json: %w", in.Name, err)
	}
	circomPublic, err := parser.UnmarshalCircomPublicSignalsJSON(publicJSON)
	if err != nil {
		return nil, fmt.Errorf("%s: parse public signals json: %w", in.Name, err)
	}
	circomVK, err := parser.UnmarshalCircomVerificationKeyJSON(vkJSON)
	if err != nil {
		return nil, fmt.Errorf("%s: parse verification key json: %w", in.Name, err)
	}
	if err := validateCircomArtifacts(circomProof.Protocol, circomVK.Protocol, circomVK.Curve); err != nil {
		return nil, fmt.Errorf("%s: %w", in.Name, err)
	}

	gnarkProof, err := parser.ConvertCircomToGnark(circomProof, circomVK, circomPublic)
	if err != nil {
		return nil, fmt.Errorf("%s: convert circom to gnark: %w", in.Name, err)
	}
	ok, err := parser.VerifyProof(gnarkProof)
	if err != nil {
		return nil, fmt.Errorf("%s: converted proof did not verify natively: %w", in.Name, err)
	}
	if !ok {
		return nil, fmt.Errorf("%s: converted proof verification returned false", in.Name)
	}

	recProof, placeholders, err := parser.ConvertCircomToGnarkRecursion(circomProof, circomVK, circomPublic)
	if err != nil {
		return nil, fmt.Errorf("%s: convert circom to gnark recursion: %w", in.Name, err)
	}

	base := sanitizeName(in.Name)
	proofRawPath := filepath.Join(outDir, base+".proof.raw")
	vkRawPath := filepath.Join(outDir, base+".vk.raw")
	publicSignalsPath := filepath.Join(outDir, base+".public.json")
	proofRawPathDisplay := filepath.Join("artifacts", "circom", base+".proof.raw")
	vkRawPathDisplay := filepath.Join("artifacts", "circom", base+".vk.raw")
	publicSignalsPathDisplay := filepath.Join("artifacts", "circom", base+".public.json")

	if err := writeRawTo(proofRawPath, gnarkProof.Proof); err != nil {
		return nil, fmt.Errorf("%s: write proof raw file: %w", in.Name, err)
	}
	if err := writeRawTo(vkRawPath, gnarkProof.VerifyingKey); err != nil {
		return nil, fmt.Errorf("%s: write verifying key raw file: %w", in.Name, err)
	}
	if err := writeJSON(publicSignalsPath, circomPublic); err != nil {
		return nil, fmt.Errorf("%s: write public signals json: %w", in.Name, err)
	}

	return &convertedProof{
		Input:               in,
		CircomPublicSignals: circomPublic,
		RecursionProof:      recProof,
		Placeholders:        placeholders,
		ProofRawPath:        proofRawPathDisplay,
		VKRawPath:           vkRawPathDisplay,
		PublicSignalsPath:   publicSignalsPathDisplay,
	}, nil
}

func validateCircomArtifacts(proofProtocol, vkProtocol, curve string) error {
	pp := strings.ToLower(strings.TrimSpace(proofProtocol))
	vp := strings.ToLower(strings.TrimSpace(vkProtocol))
	c := strings.ToLower(strings.TrimSpace(curve))

	if pp != "" && pp != "groth16" {
		return fmt.Errorf("proof protocol must be groth16, got %q", proofProtocol)
	}
	if vp != "" && vp != "groth16" {
		return fmt.Errorf("verification key protocol must be groth16, got %q", vkProtocol)
	}
	if c != "" && c != "bn128" && c != "bn254" {
		return fmt.Errorf("curve must be bn128/bn254 for gnark bn254 recursion, got %q", curve)
	}
	return nil
}

func writeRawTo(path string, v interface {
	WriteRawTo(io.Writer) (int64, error)
}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create output file %s: %w", path, err)
	}
	defer f.Close()
	if _, err := v.WriteRawTo(f); err != nil {
		return fmt.Errorf("write raw data to %s: %w", path, err)
	}
	return nil
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write file %s: %w", path, err)
	}
	return nil
}

func sanitizeName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return "proof"
	}
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}
