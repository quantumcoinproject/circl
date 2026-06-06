package schemes_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/quantumcoinproject/circl/kem/schemes"
)

func TestCaseSensitivity(t *testing.T) {
	if schemes.ByName("ml-kem-512") != schemes.ByName("ML-KEM-512") {
		t.Fatal()
	}
}

func BenchmarkGenerateKeyPair(b *testing.B) {
	allSchemes := schemes.All()
	for _, scheme := range allSchemes {
		b.Run(scheme.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, _ = scheme.GenerateKeyPair()
			}
		})
	}
}

func BenchmarkEncapsulate(b *testing.B) {
	allSchemes := schemes.All()
	for _, scheme := range allSchemes {
		pk, _, _ := scheme.GenerateKeyPair()
		b.Run(scheme.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, _ = scheme.Encapsulate(pk)
			}
		})
	}
}

func BenchmarkDecapsulate(b *testing.B) {
	allSchemes := schemes.All()
	for _, scheme := range allSchemes {
		pk, sk, _ := scheme.GenerateKeyPair()
		ct, _, _ := scheme.Encapsulate(pk)
		b.Run(scheme.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = scheme.Decapsulate(sk, ct)
			}
		})
	}
}

func TestApi(t *testing.T) {
	allSchemes := schemes.All()
	for _, scheme := range allSchemes {
		t.Run(scheme.Name(), func(t *testing.T) {
			if scheme == nil {
				t.Fatal()
			}

			_ = scheme.SeedSize()
			_ = scheme.EncapsulationSeedSize()

			pk, sk, err := scheme.GenerateKeyPair()
			if err != nil {
				t.Fatal()
			}

			packedPk, err := pk.MarshalBinary()
			if err != nil {
				t.Fatal()
			}

			if len(packedPk) != scheme.PublicKeySize() {
				t.Fatal()
			}

			packedSk, err := sk.MarshalBinary()
			if err != nil {
				t.Fatal()
			}

			if len(packedSk) != scheme.PrivateKeySize() {
				t.Fatal()
			}

			pk2, err := scheme.UnmarshalBinaryPublicKey(packedPk)
			if err != nil {
				t.Fatal()
			}

			sk2, err := scheme.UnmarshalBinaryPrivateKey(packedSk)
			if err != nil {
				t.Fatal()
			}

			if !sk.Equal(sk2) {
				t.Fatal()
			}

			if !pk.Equal(pk2) {
				t.Fatal()
			}

			ct, ss, err := scheme.Encapsulate(pk2)
			if err != nil {
				t.Fatal(err)
			}
			if len(ct) != scheme.CiphertextSize() {
				t.Fatal()
			}
			if len(ss) != scheme.SharedKeySize() {
				t.Fatal()
			}

			ct3, ss3, err := scheme.Encapsulate(pk2)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(ss3, ss) {
				t.Fatal()
			}
			if bytes.Equal(ct3, ct) {
				t.Fatal()
			}

			ss2, err := scheme.Decapsulate(sk2, ct)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ss, ss2) {
				t.Fatal()
			}
		})
	}
}

func Example_schemes() {
	// import "github.com/quantumcoinproject/circl/kem/schemes"

	for _, sch := range schemes.All() {
		fmt.Println(sch.Name())
	}
	// Output:
	// ML-KEM-512
	// ML-KEM-768
	// ML-KEM-1024
	// X25519MLKEM768
}
