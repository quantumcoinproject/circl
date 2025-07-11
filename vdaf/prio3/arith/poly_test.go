package arith

import (
	"slices"
	"testing"

	"github.com/quantumcoinproject/circl/internal/test"
	"github.com/quantumcoinproject/circl/math"
)

const Degree = 1024

func testPoly[P Poly[P, E], V Vec[V, E], E EltTest, F Fp[E]](t *testing.T) {
	t.Run("interpolate", interpolate[P, V, E, F])
	t.Run("strip", strip[P, E, F])
	t.Run("mulSqr", mulSqrPoly[P, V, E, F])
	t.Run("mulNTT", mulNTT[P, V, E, F])
}

func mulSqrPoly[P Poly[P, E], V Vec[V, E], E EltTest, F Fp[E]](t *testing.T) {
	const Deg = 4
	x := NewPoly[P](Deg)
	y := NewPoly[P](Deg)
	l0 := NewPoly[P](Deg)
	l1 := NewPoly[P](Deg)
	l2 := NewPoly[P](2 * Deg)
	r0 := NewPoly[P](2 * Deg)
	r1 := NewPoly[P](2 * Deg)

	for i := 0; i < testTimes; i++ {
		mustRead(t, V(x))
		mustRead(t, V(y))

		// (x+y)(x-y) = (x^2-y^2)
		copy(l0, x)
		copy(l1, x)
		l0.AddAssign(y)
		l1.SubAssign(y)
		l2.Mul(l0, l1)

		r0.Sqr(x)
		r1.Sqr(y)
		r0.SubAssign(r1)
		got := l2
		want := r0
		if !slices.Equal(got, want) {
			test.ReportError(t, got, want, x, y)
		}
	}
}

func evalRootsUnity[P Poly[P, E], V Vec[V, E], E Elt, F Fp[E]](p P, n uint) V {
	// evaluate p on the powers of the root of unity.
	// p(w^0), p(w^1), p(w^2), ...
	N, logN := math.NextPow2(n)
	var wi, wn F = new(E), new(E)
	wi.SetOne()
	wn.SetRootOfUnityTwoN(logN)
	values := NewVec[V](N)

	for i := range values {
		values[i] = p.Evaluate(wi)
		wi.MulAssign(wn)
	}

	return values
}

func interpolate[P Poly[P, E], V Vec[V, E], E EltTest, F Fp[E]](t *testing.T) {
	const Max = 10
	for logN := range Max {
		N := uint(1) << logN
		p := NewPoly[P](N - 1)
		mustRead(t, V(p))
		values := evalRootsUnity[P, V, E, F](p, N)

		y := NewVec[V](N)
		y.NTT(V(p), N)
		if !slices.Equal(y, values) {
			test.ReportError(t, y, values)
		}

		var invN F = new(E)
		invN.InvTwoN(uint(logN))

		p2 := NewPoly[P](N - 1)
		V(p2).InvNTT(values, N)
		V(p2).ScalarMul(invN)
		if !slices.Equal(p, p2) {
			test.ReportError(t, p, p2)
		}
	}
}

func strip[P Poly[P, E], E Elt, F Fp[E]](t *testing.T) {
	N := 4
	p := NewPoly[P](uint(N))
	p = p.Strip()
	test.CheckOk(len(p) == 0, "strip failed", t)

	for i := range N + 1 {
		p := NewPoly[P](uint(N))
		F(&p[i]).SetOne()
		p = p.Strip()
		test.CheckOk(len(p) == i+1, "strip failed", t)
	}
}

type polyTest[P any] interface {
	MulNlogN(x, y P)
	MulNSquare(x, y P)
}

func mulNTT[P Poly[P, E], V Vec[V, E], E EltTest, F Fp[E]](t *testing.T) {
	const DegX uint = 16
	const DegY uint = 16

	for degX := range DegX {
		for degY := range DegY {
			degZ := degX + degY
			x := NewPoly[P](degX)
			y := NewPoly[P](degY)
			got := NewPoly[P](degZ)
			want := NewPoly[P](degZ)

			mustRead(t, V(x))
			mustRead(t, V(y))

			any(got).(polyTest[P]).MulNlogN(x, y)
			any(want).(polyTest[P]).MulNSquare(x, y)

			if !slices.EqualFunc(got, want,
				func(x, y E) bool { return F(&x).IsEqual(&y) },
			) {
				test.ReportError(t, got, want, degX, degY)
			}
		}
	}
}

func benchmarkPoly[P Poly[P, E], V Vec[V, E], E Elt, F Fp[E]](b *testing.B) {
	x := F(new(E))
	p := NewPoly[P](Degree)
	q := NewPoly[P](Degree)
	pq := NewPoly[P](2 * Degree)
	mustRead(b, x)
	mustRead(b, V(p))
	mustRead(b, V(q))

	N, _ := math.NextPow2(Degree)
	pol := NewPoly[P](N - 1)
	mustRead(b, V(pol))
	values := evalRootsUnity[P, V, E, F](pol, N)

	b.Run("AddAssign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			q.AddAssign(p)
		}
	})
	b.Run("Sqr", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			pq.Sqr(p)
		}
	})
	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			pq.Mul(p, q)
		}
	})
	b.Run("Evaluate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = p.Evaluate(x)
		}
	})
	b.Run("NTT", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			V(p).NTT(values, N)
		}
	})
	b.Run("InvNTT", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			V(p).InvNTT(values, N)
		}
	})
}
