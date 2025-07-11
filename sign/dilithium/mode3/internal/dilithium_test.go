package internal

import (
	"encoding/binary"
	"io"
	"testing"

	common "github.com/quantumcoinproject/circl/sign/internal/dilithium"
)

// Checks whether p is normalized.  Only used in tests.
func PolyNormalized(p *common.Poly) bool {
	p2 := *p
	p2.Normalize()
	return p2 == *p
}

func BenchmarkSkUnpack(b *testing.B) {
	var buf [PrivateKeySize]byte
	var sk PrivateKey
	for i := 0; i < b.N; i++ {
		sk.Unpack(&buf)
	}
}

func BenchmarkPkUnpack(b *testing.B) {
	var buf [PublicKeySize]byte
	var pk PublicKey
	for i := 0; i < b.N; i++ {
		pk.Unpack(&buf)
	}
}

func BenchmarkVerify(b *testing.B) {
	// Note that the expansion of the matrix A is done at Unpacking/Keygen
	// instead of at the moment of verification (as in the reference
	// implementation.)
	var (
		seed [32]byte
		msg  [8]byte
		sig  [SignatureSize]byte
		rnd  [32]byte
	)
	pk, sk := NewKeyFromSeed(&seed)
	SignTo(sk, func(w io.Writer) { _, _ = w.Write(msg[:]) }, rnd, sig[:])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// We should generate a new signature for every verify attempt,
		// as this influences the time a little bit.  This difference, however,
		// is small and generating a new signature in between creates a lot
		// pressure on the allocator which makes an accurate measurement hard.
		Verify(pk, func(w io.Writer) { _, _ = w.Write(msg[:]) }, sig[:])
	}
}

func BenchmarkSign(b *testing.B) {
	// Note that the expansion of the matrix A is done at Unpacking/Keygen
	// instead of at the moment of signing (as in the reference implementation.)
	var (
		seed [32]byte
		msg  [8]byte
		sig  [SignatureSize]byte
		rnd  [32]byte
	)
	_, sk := NewKeyFromSeed(&seed)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint64(msg[:], uint64(i))
		SignTo(sk, func(w io.Writer) { _, _ = w.Write(msg[:]) }, rnd, sig[:])
	}
}

func BenchmarkGenerateKey(b *testing.B) {
	var seed [32]byte
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint64(seed[:], uint64(i))
		NewKeyFromSeed(&seed)
	}
}

func BenchmarkPublicFromPrivate(b *testing.B) {
	var seed [32]byte
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		binary.LittleEndian.PutUint64(seed[:], uint64(i))
		_, sk := NewKeyFromSeed(&seed)
		b.StartTimer()
		sk.Public()
	}
}

func TestSignThenVerifyAndPkSkPacking(t *testing.T) {
	var (
		seed [common.SeedSize]byte
		sig  [SignatureSize]byte
		msg  [8]byte
		pkb  [PublicKeySize]byte
		skb  [PrivateKeySize]byte
		pk2  PublicKey
		sk2  PrivateKey
		rnd  [32]byte
	)
	for i := uint64(0); i < 100; i++ {
		binary.LittleEndian.PutUint64(seed[:], i)
		pk, sk := NewKeyFromSeed(&seed)
		if !sk.Equal(sk) {
			t.Fatal()
		}
		for j := uint64(0); j < 10; j++ {
			binary.LittleEndian.PutUint64(msg[:], j)
			SignTo(sk, func(w io.Writer) { _, _ = w.Write(msg[:]) }, rnd, sig[:])
			if !Verify(pk, func(w io.Writer) { _, _ = w.Write(msg[:]) }, sig[:]) {
				t.Fatal()
			}
		}
		pk.Pack(&pkb)
		pk2.Unpack(&pkb)
		if !pk.Equal(&pk2) {
			t.Fatal()
		}
		sk.Pack(&skb)
		sk2.Unpack(&skb)
		if !sk.Equal(&sk2) {
			t.Fatal()
		}
	}
}

func TestPublicFromPrivate(t *testing.T) {
	var seed [common.SeedSize]byte
	for i := uint64(0); i < 100; i++ {
		binary.LittleEndian.PutUint64(seed[:], i)
		pk, sk := NewKeyFromSeed(&seed)
		pk2 := sk.Public()
		if !pk.Equal(pk2) {
			t.Fatal()
		}
	}
}

func TestGamma1Size(t *testing.T) {
	var expected int
	switch Gamma1Bits {
	case 17:
		expected = 576
	case 19:
		expected = 640
	}
	if expected != PolyLeGamma1Size {
		t.Fatal()
	}
}
