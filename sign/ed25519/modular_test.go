package ed25519

import (
	"crypto/rand"
	"testing"

	"github.com/quantumcoinproject/circl/internal/conv"
	"github.com/quantumcoinproject/circl/internal/test"
)

func TestCalculateS(t *testing.T) {
	const testTimes = 1 << 10
	s := make([]byte, paramB)
	k := make([]byte, paramB)
	r := make([]byte, paramB)
	a := make([]byte, paramB)
	orderBig := conv.BytesLe2BigInt(order[:])

	for i := 0; i < testTimes; i++ {
		_, _ = rand.Read(k[:])
		_, _ = rand.Read(r[:])
		_, _ = rand.Read(a[:])
		bigK := conv.BytesLe2BigInt(k[:])
		bigR := conv.BytesLe2BigInt(r[:])
		bigA := conv.BytesLe2BigInt(a[:])

		calculateS(s, r, k, a)
		got := conv.BytesLe2BigInt(s[:])

		bigK.Mul(bigK, bigA).Add(bigK, bigR)
		want := bigK.Mod(bigK, orderBig)

		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, k, r, a)
		}
	}
}

func TestReduction(t *testing.T) {
	const testTimes = 1 << 10
	var x, y [paramB * 2]byte
	orderBig := conv.BytesLe2BigInt(order[:])

	for i := 0; i < testTimes; i++ {
		for _, j := range []int{paramB, 2 * paramB} {
			_, _ = rand.Read(x[:j])
			bigX := conv.BytesLe2BigInt(x[:j])
			copy(y[:j], x[:j])

			reduceModOrder(y[:j], true)
			got := conv.BytesLe2BigInt(y[:])

			want := bigX.Mod(bigX, orderBig)

			if got.Cmp(want) != 0 {
				test.ReportError(t, got, want, x)
			}
		}
	}
}

func TestRangeOrder(t *testing.T) {
	aboveOrder := [...][paramB]byte{
		{ // order
			0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
			0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
		},
		{ // order+1
			0xed + 1, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
			0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
		},
		{ // all-ones
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		},
	}

	for i := range aboveOrder {
		got := isLessThanOrder(aboveOrder[i][:])
		want := false
		if got != want {
			test.ReportError(t, got, want, i, aboveOrder[i])
		}
	}
}
