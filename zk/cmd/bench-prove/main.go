package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/circom2gnark/parser"

	"gnark-playground/internal/circuit"
)

type benchmarkConfig struct {
	iterations int
	workloads  []string
	outPath    string
	useCache   bool
}

type phaseBenchmark struct {
	Name        string    `json:"name"`
	Constraints int       `json:"constraints,omitempty"`
	CompileOnce float64   `json:"compileOnceMs,omitempty"`
	SetupOnce   float64   `json:"setupOnceMs,omitempty"`
	CacheHit    bool      `json:"cacheHit,omitempty"`
	ProveMS     []float64 `json:"proveMs"`
	VerifyMS    []float64 `json:"verifyMs"`
	AvgProveMS  float64   `json:"avgProveMs"`
	AvgVerifyMS float64   `json:"avgVerifyMs"`
}

type workloadBenchmark struct {
	Name        string           `json:"name"`
	Iterations  int              `json:"iterations"`
	OneTimeMS   float64          `json:"oneTimeMs"`
	AvgProveMS  float64          `json:"avgProveMs"`
	AvgVerifyMS float64          `json:"avgVerifyMs"`
	AvgRunMS    float64          `json:"avgRunMs"`
	Phases      []phaseBenchmark `json:"phases,omitempty"`
	Skipped     bool             `json:"skipped,omitempty"`
	SkipCause   string           `json:"skipCause,omitempty"`
}

type benchmarkReport struct {
	GeneratedAt  string              `json:"generatedAt"`
	Iterations   int                 `json:"iterations"`
	SetupReuse   bool                `json:"setupReuse"`
	CacheEnabled bool                `json:"cacheEnabled"`
	Workloads    []workloadBenchmark `json:"workloads"`
}

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

type circomProofInput struct {
	ProofPath  string
	PublicPath string
	VKeyPath   string
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	report, err := runBenchmarks(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := writeJSON(cfg.outPath, report); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	printSummary(report)
	fmt.Printf("benchmark report written to %s\n", cfg.outPath)
}

func parseFlags() (benchmarkConfig, error) {
	var (
		iterations = flag.Int("iterations", 3, "number of prove+verify runs per workload (setup reused)")
		workloads  = flag.String("workloads", "basic,recursive,aggregate", "comma-separated workloads: basic,recursive,aggregate")
		outPath    = flag.String("out", filepath.Join("..", "artifacts", "bench", "prove_bench.json"), "output JSON path")
		useCache   = flag.Bool("cache", true, "reuse cached compile/setup artifacts when available")
	)
	flag.Parse()

	if *iterations < 1 {
		return benchmarkConfig{}, fmt.Errorf("iterations must be >= 1")
	}

	parts := strings.Split(*workloads, ",")
	seen := map[string]bool{}
	normalized := make([]string, 0, len(parts))
	for _, p := range parts {
		w := strings.ToLower(strings.TrimSpace(p))
		if w == "" || seen[w] {
			continue
		}
		switch w {
		case "basic", "recursive", "aggregate":
			seen[w] = true
			normalized = append(normalized, w)
		default:
			return benchmarkConfig{}, fmt.Errorf("unsupported workload %q", w)
		}
	}
	if len(normalized) == 0 {
		return benchmarkConfig{}, fmt.Errorf("no valid workloads selected")
	}

	return benchmarkConfig{
		iterations: *iterations,
		workloads:  normalized,
		outPath:    *outPath,
		useCache:   *useCache,
	}, nil
}

func runBenchmarks(cfg benchmarkConfig) (benchmarkReport, error) {
	report := benchmarkReport{
		GeneratedAt:  time.Now().Format(time.RFC3339),
		Iterations:   cfg.iterations,
		SetupReuse:   true,
		CacheEnabled: cfg.useCache,
		Workloads:    make([]workloadBenchmark, 0, len(cfg.workloads)),
	}

	for _, w := range cfg.workloads {
		switch w {
		case "basic":
			bw, err := benchBasic(cfg.iterations, cfg.useCache)
			if err != nil {
				return benchmarkReport{}, err
			}
			report.Workloads = append(report.Workloads, bw)
		case "recursive":
			bw, err := benchRecursive(cfg.iterations, cfg.useCache)
			if err != nil {
				return benchmarkReport{}, err
			}
			report.Workloads = append(report.Workloads, bw)
		case "aggregate":
			bw, err := benchAggregate(cfg.iterations, cfg.useCache)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					report.Workloads = append(report.Workloads, workloadBenchmark{
						Name:       "aggregate",
						Iterations: cfg.iterations,
						Skipped:    true,
						SkipCause:  "Circom artifacts not found. Run `make circom-prove` first.",
					})
					continue
				}
				return benchmarkReport{}, err
			}
			report.Workloads = append(report.Workloads, bw)
		}
	}

	return report, nil
}

func benchBasic(iterations int, useCache bool) (workloadBenchmark, error) {
	w := workloadBenchmark{Name: "basic", Iterations: iterations}
	p := phaseBenchmark{
		Name:     "basic",
		ProveMS:  make([]float64, 0, iterations),
		VerifyMS: make([]float64, 0, iterations),
	}

	ccs, pk, vk, compileMS, setupMS, cacheHit, err := buildOrLoadSetup("basic/basic", useCache, func() (constraint.ConstraintSystem, error) {
		return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.MulCircuit{})
	})
	if err != nil {
		return workloadBenchmark{}, fmt.Errorf("basic compile/setup: %w", err)
	}
	p.CompileOnce = compileMS
	p.SetupOnce = setupMS
	p.CacheHit = cacheHit
	p.Constraints = ccs.GetNbConstraints()

	assignment := &circuit.MulCircuit{A: 6, B: 7, C: 42}
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return workloadBenchmark{}, fmt.Errorf("basic full witness: %w", err)
	}
	publicWitness, err := fullWitness.Public()
	if err != nil {
		return workloadBenchmark{}, fmt.Errorf("basic public witness: %w", err)
	}

	for i := 0; i < iterations; i++ {
		startProve := time.Now()
		proof, err := groth16.Prove(ccs, pk, fullWitness)
		if err != nil {
			return workloadBenchmark{}, fmt.Errorf("basic prove: %w", err)
		}
		p.ProveMS = append(p.ProveMS, durationMS(time.Since(startProve)))

		startVerify := time.Now()
		if err := groth16.Verify(proof, vk, publicWitness); err != nil {
			return workloadBenchmark{}, fmt.Errorf("basic verify: %w", err)
		}
		p.VerifyMS = append(p.VerifyMS, durationMS(time.Since(startVerify)))
	}

	finalizePhase(&p)
	w.Phases = append(w.Phases, p)
	finalizeWorkload(&w)
	return w, nil
}

func benchRecursive(iterations int, useCache bool) (workloadBenchmark, error) {
	w := workloadBenchmark{Name: "recursive", Iterations: iterations}

	inner := phaseBenchmark{
		Name:     "recursive-inner",
		ProveMS:  make([]float64, 0, iterations),
		VerifyMS: make([]float64, 0, iterations),
	}

	innerCCS, innerPK, innerVK, innerCompileMS, innerSetupMS, innerCacheHit, err := buildOrLoadSetup("recursive/inner", useCache, func() (constraint.ConstraintSystem, error) {
		return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &InnerCircuit{})
	})
	if err != nil {
		return workloadBenchmark{}, fmt.Errorf("recursive inner compile/setup: %w", err)
	}
	inner.CompileOnce = innerCompileMS
	inner.SetupOnce = innerSetupMS
	inner.CacheHit = innerCacheHit
	inner.Constraints = innerCCS.GetNbConstraints()

	innerAssignment := &InnerCircuit{P: 3, Q: 5, N: 15}
	innerWitness, err := frontend.NewWitness(innerAssignment, ecc.BN254.ScalarField())
	if err != nil {
		return workloadBenchmark{}, fmt.Errorf("recursive inner full witness: %w", err)
	}
	innerPublicWitness, err := innerWitness.Public()
	if err != nil {
		return workloadBenchmark{}, fmt.Errorf("recursive inner public witness: %w", err)
	}

	var firstInnerProof groth16.Proof
	for i := 0; i < iterations; i++ {
		startProve := time.Now()
		proof, err := groth16.Prove(innerCCS, innerPK, innerWitness)
		if err != nil {
			return workloadBenchmark{}, fmt.Errorf("recursive inner prove: %w", err)
		}
		if i == 0 {
			firstInnerProof = proof
		}
		inner.ProveMS = append(inner.ProveMS, durationMS(time.Since(startProve)))

		startVerify := time.Now()
		if err := groth16.Verify(proof, innerVK, innerPublicWitness); err != nil {
			return workloadBenchmark{}, fmt.Errorf("recursive inner verify: %w", err)
		}
		inner.VerifyMS = append(inner.VerifyMS, durationMS(time.Since(startVerify)))
	}
	finalizePhase(&inner)

	circuitVK, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVK)
	if err != nil {
		return workloadBenchmark{}, fmt.Errorf("recursive convert inner verifying key: %w", err)
	}
	circuitWitness, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](innerPublicWitness)
	if err != nil {
		return workloadBenchmark{}, fmt.Errorf("recursive convert inner witness: %w", err)
	}
	circuitProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](firstInnerProof)
	if err != nil {
		return workloadBenchmark{}, fmt.Errorf("recursive convert inner proof: %w", err)
	}

	outer := phaseBenchmark{
		Name:     "recursive-outer",
		ProveMS:  make([]float64, 0, iterations),
		VerifyMS: make([]float64, 0, iterations),
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

	outerCCS, outerPK, outerVK, outerCompileMS, outerSetupMS, outerCacheHit, err := buildOrLoadSetup("recursive/outer", useCache, func() (constraint.ConstraintSystem, error) {
		return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, outerCircuit)
	})
	if err != nil {
		return workloadBenchmark{}, fmt.Errorf("recursive outer compile/setup: %w", err)
	}
	outer.CompileOnce = outerCompileMS
	outer.SetupOnce = outerSetupMS
	outer.CacheHit = outerCacheHit
	outer.Constraints = outerCCS.GetNbConstraints()

	outerWitness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	if err != nil {
		return workloadBenchmark{}, fmt.Errorf("recursive outer full witness: %w", err)
	}
	outerPublicWitness, err := outerWitness.Public()
	if err != nil {
		return workloadBenchmark{}, fmt.Errorf("recursive outer public witness: %w", err)
	}

	for i := 0; i < iterations; i++ {
		startProve := time.Now()
		outerProof, err := groth16.Prove(outerCCS, outerPK, outerWitness)
		if err != nil {
			return workloadBenchmark{}, fmt.Errorf("recursive outer prove: %w", err)
		}
		outer.ProveMS = append(outer.ProveMS, durationMS(time.Since(startProve)))

		startVerify := time.Now()
		if err := groth16.Verify(outerProof, outerVK, outerPublicWitness); err != nil {
			return workloadBenchmark{}, fmt.Errorf("recursive outer verify: %w", err)
		}
		outer.VerifyMS = append(outer.VerifyMS, durationMS(time.Since(startVerify)))
	}
	finalizePhase(&outer)

	w.Phases = append(w.Phases, inner, outer)
	finalizeWorkload(&w)
	return w, nil
}

func benchAggregate(iterations int, useCache bool) (workloadBenchmark, error) {
	w := workloadBenchmark{Name: "aggregate", Iterations: iterations}
	p := phaseBenchmark{
		Name:     "aggregate-outer",
		ProveMS:  make([]float64, 0, iterations),
		VerifyMS: make([]float64, 0, iterations),
	}

	input1 := circomProofInput{
		ProofPath:  filepath.Join("..", "circom", "build", "mul_a", "default", "groth16_proof.json"),
		PublicPath: filepath.Join("..", "circom", "build", "mul_a", "default", "public.json"),
		VKeyPath:   filepath.Join("..", "circom", "build", "mul_a", "groth16_vkey.json"),
	}
	input2 := circomProofInput{
		ProofPath:  filepath.Join("..", "circom", "build", "mul_b", "default", "groth16_proof.json"),
		PublicPath: filepath.Join("..", "circom", "build", "mul_b", "default", "public.json"),
		VKeyPath:   filepath.Join("..", "circom", "build", "mul_b", "groth16_vkey.json"),
	}

	rec1, ph1, err := loadCircomAsRecursion(input1)
	if err != nil {
		return workloadBenchmark{}, err
	}
	rec2, ph2, err := loadCircomAsRecursion(input2)
	if err != nil {
		return workloadBenchmark{}, err
	}

	outerCircuit := &AggregateTwoCircomProofsCircuit{
		Proof1:        ph1.Proof,
		VerifyingKey1: ph1.Vk,
		PublicInputs1: ph1.Witness,
		Proof2:        ph2.Proof,
		VerifyingKey2: ph2.Vk,
		PublicInputs2: ph2.Witness,
	}
	outerAssignment := &AggregateTwoCircomProofsCircuit{
		Proof1:        rec1.Proof,
		VerifyingKey1: rec1.Vk,
		PublicInputs1: rec1.PublicInputs,
		Proof2:        rec2.Proof,
		VerifyingKey2: rec2.Vk,
		PublicInputs2: rec2.PublicInputs,
	}

	ccs, pk, vk, compileMS, setupMS, cacheHit, err := buildOrLoadSetup("aggregate/outer", useCache, func() (constraint.ConstraintSystem, error) {
		return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, outerCircuit)
	})
	if err != nil {
		return workloadBenchmark{}, fmt.Errorf("aggregate compile/setup: %w", err)
	}
	p.CompileOnce = compileMS
	p.SetupOnce = setupMS
	p.CacheHit = cacheHit
	p.Constraints = ccs.GetNbConstraints()

	wFull, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	if err != nil {
		return workloadBenchmark{}, fmt.Errorf("aggregate full witness: %w", err)
	}
	wPublic, err := wFull.Public()
	if err != nil {
		return workloadBenchmark{}, fmt.Errorf("aggregate public witness: %w", err)
	}

	for i := 0; i < iterations; i++ {
		startProve := time.Now()
		proof, err := groth16.Prove(ccs, pk, wFull)
		if err != nil {
			return workloadBenchmark{}, fmt.Errorf("aggregate prove: %w", err)
		}
		p.ProveMS = append(p.ProveMS, durationMS(time.Since(startProve)))

		startVerify := time.Now()
		if err := groth16.Verify(proof, vk, wPublic); err != nil {
			return workloadBenchmark{}, fmt.Errorf("aggregate verify: %w", err)
		}
		p.VerifyMS = append(p.VerifyMS, durationMS(time.Since(startVerify)))
	}

	finalizePhase(&p)
	w.Phases = append(w.Phases, p)
	finalizeWorkload(&w)
	return w, nil
}

func loadCircomAsRecursion(in circomProofInput) (
	*parser.GnarkRecursionProof,
	*parser.GnarkRecursionPlaceholders,
	error,
) {
	proofJSON, err := os.ReadFile(in.ProofPath)
	if err != nil {
		return nil, nil, err
	}
	publicJSON, err := os.ReadFile(in.PublicPath)
	if err != nil {
		return nil, nil, err
	}
	vkJSON, err := os.ReadFile(in.VKeyPath)
	if err != nil {
		return nil, nil, err
	}

	circomProof, err := parser.UnmarshalCircomProofJSON(proofJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("parse circom proof json: %w", err)
	}
	circomPublic, err := parser.UnmarshalCircomPublicSignalsJSON(publicJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("parse circom public json: %w", err)
	}
	circomVK, err := parser.UnmarshalCircomVerificationKeyJSON(vkJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("parse circom verification key json: %w", err)
	}

	gnarkProof, err := parser.ConvertCircomToGnark(circomProof, circomVK, circomPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("convert circom to gnark: %w", err)
	}
	ok, err := parser.VerifyProof(gnarkProof)
	if err != nil {
		return nil, nil, fmt.Errorf("verify converted circom proof natively: %w", err)
	}
	if !ok {
		return nil, nil, fmt.Errorf("converted circom proof verification returned false")
	}

	recProof, placeholders, err := parser.ConvertCircomToGnarkRecursion(circomProof, circomVK, circomPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("convert circom to recursion types: %w", err)
	}
	return recProof, placeholders, nil
}

func buildOrLoadSetup(
	cacheKey string,
	useCache bool,
	compileFn func() (constraint.ConstraintSystem, error),
) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, float64, float64, bool, error) {
	if useCache {
		ccs, pk, vk, err := loadSetupArtifacts(cacheKey)
		if err == nil {
			return ccs, pk, vk, 0, 0, true, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil, 0, 0, false, fmt.Errorf("load cache %s: %w", cacheKey, err)
		}
	}

	startCompile := time.Now()
	ccs, err := compileFn()
	if err != nil {
		return nil, nil, nil, 0, 0, false, err
	}
	compileMS := durationMS(time.Since(startCompile))

	startSetup := time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, nil, 0, 0, false, err
	}
	setupMS := durationMS(time.Since(startSetup))

	if useCache {
		if err := saveSetupArtifacts(cacheKey, ccs, pk, vk); err != nil {
			return nil, nil, nil, 0, 0, false, fmt.Errorf("save cache %s: %w", cacheKey, err)
		}
	}

	return ccs, pk, vk, compileMS, setupMS, false, nil
}

func saveSetupArtifacts(cacheKey string, ccs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) error {
	dir := cacheDir(cacheKey)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}

	if err := writeWriterTo(cachePath(cacheKey, "ccs.bin"), ccs); err != nil {
		return err
	}
	if err := writeWriterTo(cachePath(cacheKey, "pk.bin"), pk); err != nil {
		return err
	}
	if err := writeWriterTo(cachePath(cacheKey, "vk.bin"), vk); err != nil {
		return err
	}
	return nil
}

func loadSetupArtifacts(cacheKey string) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	ccsPath := cachePath(cacheKey, "ccs.bin")
	pkPath := cachePath(cacheKey, "pk.bin")
	vkPath := cachePath(cacheKey, "vk.bin")

	if err := requireFiles(ccsPath, pkPath, vkPath); err != nil {
		return nil, nil, nil, err
	}

	ccs := groth16.NewCS(ecc.BN254)
	if err := readReaderFrom(ccsPath, ccs); err != nil {
		return nil, nil, nil, err
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if err := readReaderFrom(pkPath, pk); err != nil {
		return nil, nil, nil, err
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err := readReaderFrom(vkPath, vk); err != nil {
		return nil, nil, nil, err
	}
	return ccs, pk, vk, nil
}

func cacheDir(cacheKey string) string {
	return filepath.Join("..", "artifacts", "bench", "cache", cacheKey)
}

func cachePath(cacheKey, file string) string {
	return filepath.Join(cacheDir(cacheKey), file)
}

func requireFiles(paths ...string) error {
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return os.ErrNotExist
			}
			return err
		}
	}
	return nil
}

func writeWriterTo(path string, v interface {
	WriteTo(io.Writer) (int64, error)
}) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	if _, err := v.WriteTo(f); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func readReaderFrom(path string, v interface {
	ReadFrom(io.Reader) (int64, error)
}) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	if _, err := v.ReadFrom(f); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return nil
}

func finalizePhase(p *phaseBenchmark) {
	p.AvgProveMS = avg(p.ProveMS)
	p.AvgVerifyMS = avg(p.VerifyMS)
}

func finalizeWorkload(w *workloadBenchmark) {
	for _, p := range w.Phases {
		w.OneTimeMS += p.CompileOnce + p.SetupOnce
		w.AvgProveMS += p.AvgProveMS
		w.AvgVerifyMS += p.AvgVerifyMS
	}
	w.AvgRunMS = w.AvgProveMS + w.AvgVerifyMS
}

func avg(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func durationMS(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
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
		return fmt.Errorf("write json report: %w", err)
	}
	return nil
}

func printSummary(report benchmarkReport) {
	fmt.Printf("prove benchmark (%d runs/workload, setup reused: %v, cache: %v)\n", report.Iterations, report.SetupReuse, report.CacheEnabled)
	for _, w := range report.Workloads {
		if w.Skipped {
			fmt.Printf("- %s: skipped (%s)\n", w.Name, w.SkipCause)
			continue
		}
		fmt.Printf("- %s: one_time=%.3fms avg_prove=%.3fms avg_verify=%.3fms avg_run=%.3fms\n",
			w.Name, w.OneTimeMS, w.AvgProveMS, w.AvgVerifyMS, w.AvgRunMS)
		for _, p := range w.Phases {
			cacheState := "miss"
			if p.CacheHit {
				cacheState = "hit"
			}
			fmt.Printf("  phase=%s constraints=%d cache=%s setup_once=%.3fms avg_prove=%.3fms avg_verify=%.3fms\n",
				p.Name, p.Constraints, cacheState, p.SetupOnce, p.AvgProveMS, p.AvgVerifyMS)
		}
	}
}
