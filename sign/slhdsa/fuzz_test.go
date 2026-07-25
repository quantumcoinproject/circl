package slhdsa_test

import (
	"bytes"
	"testing"

	"github.com/quantumcoinproject/circl/sign/slhdsa"
)

// FuzzVerify exercises SLH-DSA public-key parsing, message construction, and
// verification with attacker-controlled inputs. SHAKE-128f is used to keep the
// fuzz target practical while still traversing the complete verification path.
func FuzzVerify(f *testing.F) {
	const id = slhdsa.SHAKE_128f
	seed := make([]byte, id.Scheme().SeedSize())
	publicKey, privateKey, err := slhdsa.GenerateKey(bytes.NewReader(seed), id)
	if err != nil {
		f.Fatalf("failed to create SLH-DSA seed key: %v", err)
	}
	message := []byte("SLH-DSA fuzz seed")
	context := []byte("circl-fuzz")
	signature, err := slhdsa.SignDeterministic(
		&privateKey,
		slhdsa.NewMessage(message),
		context,
	)
	if err != nil {
		f.Fatalf("failed to create SLH-DSA seed signature: %v", err)
	}
	publicBytes, err := publicKey.MarshalBinary()
	if err != nil {
		f.Fatalf("failed to marshal SLH-DSA seed key: %v", err)
	}

	f.Add(publicBytes, message, context, signature)
	f.Add([]byte{}, []byte{}, []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, public, message, context, signature []byte) {
		key := slhdsa.PublicKey{ID: id}
		if err := key.UnmarshalBinary(public); err != nil {
			return
		}
		_ = slhdsa.Verify(&key, slhdsa.NewMessage(message), signature, context)
	})
}
