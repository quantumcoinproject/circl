// Code generated from ./templates/poly.go.tmpl. DO NOT EDIT.

package fp128

import "github.com/quantumcoinproject/circl/math"

type Poly []Fp

func (p Poly) AddAssign(x Poly) { Vec(p).AddAssign(Vec(x)) }
func (p Poly) SubAssign(x Poly) { Vec(p).SubAssign(Vec(x)) }
func (p Poly) Mul(x, y Poly) {
	const thresholdPolyMul = 128
	if len(x)+len(y)-1 < thresholdPolyMul {
		p.MulNSquare(x, y)
	} else {
		p.MulNlogN(x, y)
	}
}

func (p Poly) MulNSquare(x, y Poly) {
	mustSumLen(p, x, y)
	clear(p)
	var xiyj Fp
	for i := range x {
		for j := range y {
			xiyj.Mul(&x[i], &y[j])
			p[i+j].AddAssign(&xiyj)
		}
	}
}

func (p Poly) MulNlogN(x, y Poly) {
	mustSumLen(p, x, y)
	N, logN := math.NextPow2(uint(len(x) + len(y) - 1))
	buf := make(Vec, 2*N)
	lx, ly := buf[:N], buf[N:]
	lx.NTT(Vec(x), N)
	ly.NTT(Vec(y), N)
	for i := range lx {
		lx[i].MulAssign(&ly[i])
	}

	ly.InvNTT(lx, N)
	var invN Fp
	invN.InvTwoN(logN)
	copy(p, ly)
	Vec(p).ScalarMul(&invN)
}

func (p Poly) Sqr(x Poly) {
	mustSumLen(p, x, x)
	clear(p)
	for i := range x {
		p[2*i].Sqr(&x[i])
	}

	var xixj Fp
	for i := 0; i < len(x); i++ {
		for j := i + 1; j < len(x); j++ {
			xixj.Mul(&x[i], &x[j])
			xixj.AddAssign(&xixj)
			p[i+j].AddAssign(&xixj)
		}
	}
}

func (p Poly) Evaluate(x *Fp) (px Fp) {
	if l := len(p); l != 0 {
		px = p[l-1]
		for i := l - 2; i >= 0; i-- {
			px.MulAssign(x)
			px.AddAssign(&p[i])
		}
	}

	return
}

func (p Poly) Strip() Poly {
	for i := len(p) - 1; i >= 0; i-- {
		if !p[i].IsZero() {
			return p[:i+1]
		}
	}

	return p[:0]
}
