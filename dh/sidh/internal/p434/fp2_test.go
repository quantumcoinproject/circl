// Code generated by go generate; DO NOT EDIT.
// This file was generated by robots.

package p434

import (
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"

	"github.com/quantumcoinproject/circl/dh/sidh/internal/common"
)

type testParams struct {
	Point   common.ProjectivePoint
	Cparam  common.ProjectiveCurveParameters
	ExtElem common.Fp2
}

// Returns true if lhs = rhs.  Takes variable time.
func vartimeEqFp2(lhs, rhs *common.Fp2) bool {
	a := *lhs
	b := *rhs

	modP434(&a.A)
	modP434(&a.B)
	modP434(&b.A)
	modP434(&b.B)

	eq := true
	for i := 0; i < FpWords && eq; i++ {
		eq = eq && (a.A[i] == b.A[i])
		eq = eq && (a.B[i] == b.B[i])
	}
	return eq
}

func (testParams) generateFp2(rand *rand.Rand) common.Fp2 {
	// Generation strategy: low limbs taken from [0,2^64); high limb
	// taken from smaller range
	//
	// Size hint is ignored since all elements are fixed size.
	//
	// Field elements taken in range [0,2p).  Emulate this by capping
	// the high limb by the top digit of 2*p-1:
	//
	// sage: (2*p-1).digits(2^64)[-1]
	//
	// This still allows generating values >= 2p, but hopefully that
	// excess is OK (and if it's not, we'll find out, because it's for
	// testing...)
	highLimb := rand.Uint64() % P434x2[FpWords-1]
	fpElementGen := func() (fp common.Fp) {
		for i := 0; i < (FpWords - 1); i++ {
			fp[i] = rand.Uint64()
		}
		fp[FpWords-1] = highLimb
		return fp
	}
	return common.Fp2{A: fpElementGen(), B: fpElementGen()}
}

func (c testParams) Generate(rand *rand.Rand, size int) reflect.Value {
	return reflect.ValueOf(
		testParams{
			common.ProjectivePoint{
				X: c.generateFp2(rand),
				Z: c.generateFp2(rand),
			},
			common.ProjectiveCurveParameters{
				A: c.generateFp2(rand),
				C: c.generateFp2(rand),
			},
			c.generateFp2(rand),
		})
}

func TestOne(t *testing.T) {
	var tmp common.Fp2

	mul(&tmp, &params.OneFp2, &params.A.AffineP)
	if !vartimeEqFp2(&tmp, &params.A.AffineP) {
		t.Error("Not equal 1")
	}
}

func TestFp2ToBytesRoundTrip(t *testing.T) {
	roundTrips := func(x testParams) bool {
		xBytes := make([]byte, 2*params.Bytelen)
		var xPrime common.Fp2

		common.Fp2ToBytes(xBytes[:], &x.ExtElem, params.Bytelen)
		common.BytesToFp2(&xPrime, xBytes[:], params.Bytelen)
		return vartimeEqFp2(&xPrime, &x.ExtElem)
	}

	if err := quick.Check(roundTrips, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func TestFp2MulDistributesOverAdd(t *testing.T) {
	mulDistributesOverAdd := func(x, y, z testParams) bool {
		// Compute t1 = (x+y)*z
		t1 := new(common.Fp2)
		add(t1, &x.ExtElem, &y.ExtElem)
		mul(t1, t1, &z.ExtElem)

		// Compute t2 = x*z + y*z
		t2 := new(common.Fp2)
		t3 := new(common.Fp2)
		mul(t2, &x.ExtElem, &z.ExtElem)
		mul(t3, &y.ExtElem, &z.ExtElem)
		add(t2, t2, t3)

		return vartimeEqFp2(t1, t2)
	}

	if err := quick.Check(mulDistributesOverAdd, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func TestFp2MulIsAssociative(t *testing.T) {
	isAssociative := func(x, y, z testParams) bool {
		// Compute t1 = (x*y)*z
		t1 := new(common.Fp2)
		mul(t1, &x.ExtElem, &y.ExtElem)
		mul(t1, t1, &z.ExtElem)

		// Compute t2 = (y*z)*x
		t2 := new(common.Fp2)
		mul(t2, &y.ExtElem, &z.ExtElem)
		mul(t2, t2, &x.ExtElem)

		return vartimeEqFp2(t1, t2)
	}

	if err := quick.Check(isAssociative, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func TestFp2SquareMatchesMul(t *testing.T) {
	sqrMatchesMul := func(x testParams) bool {
		// Compute t1 = (x*x)
		t1 := new(common.Fp2)
		mul(t1, &x.ExtElem, &x.ExtElem)

		// Compute t2 = x^2
		t2 := new(common.Fp2)
		sqr(t2, &x.ExtElem)

		return vartimeEqFp2(t1, t2)
	}

	if err := quick.Check(sqrMatchesMul, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func TestFp2Inv(t *testing.T) {
	inverseIsCorrect := func(x testParams) bool {
		z := new(common.Fp2)
		inv(z, &x.ExtElem)

		// Now z = (1/x), so (z * x) * x == x
		mul(z, z, &x.ExtElem)
		mul(z, z, &x.ExtElem)

		return vartimeEqFp2(z, &x.ExtElem)
	}

	// This is more expensive; run fewer tests
	fasterCheckConfig := &quick.Config{MaxCount: (1 << 11)}
	if err := quick.Check(inverseIsCorrect, fasterCheckConfig); err != nil {
		t.Error(err)
	}
}

func TestFp2Batch3Inv(t *testing.T) {
	batchInverseIsCorrect := func(x1, x2, x3 testParams) bool {
		var x1Inv, x2Inv, x3Inv common.Fp2
		inv(&x1Inv, &x1.ExtElem)
		inv(&x2Inv, &x2.ExtElem)
		inv(&x3Inv, &x3.ExtElem)

		var y1, y2, y3 common.Fp2
		Fp2Batch3Inv(&x1.ExtElem, &x2.ExtElem, &x3.ExtElem, &y1, &y2, &y3)

		return (vartimeEqFp2(&x1Inv, &y1) && vartimeEqFp2(&x2Inv, &y2) && vartimeEqFp2(&x3Inv, &y3))
	}

	// This is more expensive; run fewer tests
	fasterCheckConfig := &quick.Config{MaxCount: (1 << 8)}
	if err := quick.Check(batchInverseIsCorrect, fasterCheckConfig); err != nil {
		t.Error(err)
	}
}

func BenchmarkFp2Mul(b *testing.B) {
	z := &common.Fp2{A: bench_x, B: bench_y}
	w := new(common.Fp2)

	for n := 0; n < b.N; n++ {
		mul(w, z, z)
	}
}

func BenchmarkFp2Inv(b *testing.B) {
	z := &common.Fp2{A: bench_x, B: bench_y}
	w := new(common.Fp2)

	for n := 0; n < b.N; n++ {
		inv(w, z)
	}
}

func BenchmarkFp2Square(b *testing.B) {
	z := &common.Fp2{A: bench_x, B: bench_y}
	w := new(common.Fp2)

	for n := 0; n < b.N; n++ {
		sqr(w, z)
	}
}

func BenchmarkFp2Add(b *testing.B) {
	z := &common.Fp2{A: bench_x, B: bench_y}
	w := new(common.Fp2)

	for n := 0; n < b.N; n++ {
		add(w, z, z)
	}
}

func BenchmarkFp2Sub(b *testing.B) {
	z := &common.Fp2{A: bench_x, B: bench_y}
	w := new(common.Fp2)

	for n := 0; n < b.N; n++ {
		sub(w, z, z)
	}
}
