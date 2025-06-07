package slhdsa

import (
	"testing"

	"github.com/quantumcoinproject/circl/internal/test"
)

func testInternal(t *testing.T, p *params) {
	skSeed := mustRead(t, p.n)
	skPrf := mustRead(t, p.n)
	pkSeed := mustRead(t, p.n)
	msg := mustRead(t, p.m)
	addRand := mustRead(t, p.n)

	pk, sk := slhKeyGenInternal(p, skSeed, skPrf, pkSeed)
	sig, err := slhSignInternal(&sk, msg, addRand)
	test.CheckNoErr(t, err, "slhSignInternal failed")

	valid := slhVerifyInternal(&pk, msg, sig)
	test.CheckOk(valid, "slhVerifyInternal failed", t)
}

func benchmarkInternal(b *testing.B, p *params) {
	skSeed := mustRead(b, p.n)
	skPrf := mustRead(b, p.n)
	pkSeed := mustRead(b, p.n)
	msg := mustRead(b, p.m)
	addRand := mustRead(b, p.n)

	pk, sk := slhKeyGenInternal(p, skSeed, skPrf, pkSeed)
	sig, err := slhSignInternal(&sk, msg, addRand)
	test.CheckNoErr(b, err, "slhSignInternal failed")

	b.Run("Keygen", func(b *testing.B) {
		for range b.N {
			_, _ = slhKeyGenInternal(p, skSeed, skPrf, pkSeed)
		}
	})
	b.Run("Sign", func(b *testing.B) {
		for range b.N {
			_, _ = slhSignInternal(&sk, msg, addRand)
		}
	})
	b.Run("Verify", func(b *testing.B) {
		for range b.N {
			_ = slhVerifyInternal(&pk, msg, sig)
		}
	})
}
