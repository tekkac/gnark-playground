package circuit

import "github.com/consensys/gnark/frontend"

// MulCircuit proves knowledge of A and B such that A * B == C.
type MulCircuit struct {
	A frontend.Variable
	B frontend.Variable
	C frontend.Variable `gnark:",public"`
}

func (c *MulCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.A, c.B), c.C)
	return nil
}
