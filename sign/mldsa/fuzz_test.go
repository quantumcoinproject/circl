package mldsa_test

import (
	"testing"

	"github.com/quantumcoinproject/circl/sign/mldsa/mldsa44"
	"github.com/quantumcoinproject/circl/sign/mldsa/mldsa65"
	"github.com/quantumcoinproject/circl/sign/mldsa/mldsa87"
)

// FuzzVerify exercises all three ML-DSA verification and public-key decoding
// surfaces with arbitrary inputs. The mode byte selects the parameter set.
func FuzzVerify(f *testing.F) {
	message := []byte("ML-DSA fuzz seed")
	context := []byte("circl-fuzz")

	seed44 := [mldsa44.SeedSize]byte{}
	public44, private44 := mldsa44.NewKeyFromSeed(&seed44)
	signature44 := make([]byte, mldsa44.SignatureSize)
	if err := mldsa44.SignTo(private44, message, context, false, signature44); err != nil {
		f.Fatalf("failed to create ML-DSA-44 seed signature: %v", err)
	}
	f.Add(uint8(44), public44.Bytes(), message, context, signature44)

	seed65 := [mldsa65.SeedSize]byte{}
	public65, private65 := mldsa65.NewKeyFromSeed(&seed65)
	signature65 := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(private65, message, context, false, signature65); err != nil {
		f.Fatalf("failed to create ML-DSA-65 seed signature: %v", err)
	}
	f.Add(uint8(65), public65.Bytes(), message, context, signature65)

	seed87 := [mldsa87.SeedSize]byte{}
	public87, private87 := mldsa87.NewKeyFromSeed(&seed87)
	signature87 := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(private87, message, context, false, signature87); err != nil {
		f.Fatalf("failed to create ML-DSA-87 seed signature: %v", err)
	}
	f.Add(uint8(87), public87.Bytes(), message, context, signature87)

	f.Add(uint8(0), []byte{}, []byte{}, []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, mode uint8, public, message, context, signature []byte) {
		switch mode {
		case 44:
			key, err := mldsa44.UnmarshalPublicKey(public)
			if err == nil {
				_ = mldsa44.Verify(key, message, context, signature)
			}
		case 65:
			var key mldsa65.PublicKey
			if err := key.UnmarshalBinary(public); err == nil {
				_ = mldsa65.Verify(&key, message, context, signature)
			}
		case 87:
			key, err := mldsa87.UnmarshalPublicKey(public)
			if err == nil {
				_ = mldsa87.Verify(key, message, context, signature)
			}
		}
	})
}
