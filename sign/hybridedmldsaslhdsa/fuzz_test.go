package hybridedmldsaslhdsa

import (
	"bytes"
	"testing"
)

// FuzzVerifyCompact exercises the production compact verifier with arbitrary
// public keys, messages, and signatures. The valid corpus entry ensures fuzzing
// reaches both Ed25519 and ML-DSA verification rather than only length checks.
func FuzzVerifyCompact(f *testing.F) {
	seed := [SeedSize]byte{}
	publicKey, privateKey, err := NewKeyFromSeed(&seed)
	if err != nil {
		f.Fatalf("failed to create hybrid seed key: %v", err)
	}
	message := make([]byte, CRYPTO_MSG_LENGTH)
	signature, err := SignCompact(privateKey, bytes.NewReader(make([]byte, 32)), message)
	if err != nil {
		f.Fatalf("failed to create hybrid seed signature: %v", err)
	}
	publicBytes, err := publicKey.MarshalBinary()
	if err != nil {
		f.Fatalf("failed to marshal hybrid seed key: %v", err)
	}

	f.Add(publicBytes, message, signature)
	f.Add([]byte{}, []byte{}, []byte{})
	f.Add(make([]byte, PublicKeySize), make([]byte, CRYPTO_MSG_LENGTH), make([]byte, CompactSigLength))

	f.Fuzz(func(t *testing.T, public, message, signature []byte) {
		key, err := UnmarshalPublicKey(public)
		if err != nil {
			return
		}
		_ = VerifyCompact(key, message, signature)
	})
}

// FuzzUnmarshalPrivateKey checks composite key-import consistency validation
// against malformed or corrupted private-key blobs.
func FuzzUnmarshalPrivateKey(f *testing.F) {
	seed := [SeedSize]byte{}
	_, privateKey, err := NewKeyFromSeed(&seed)
	if err != nil {
		f.Fatalf("failed to create hybrid seed key: %v", err)
	}
	privateBytes, err := privateKey.MarshalBinary()
	if err != nil {
		f.Fatalf("failed to marshal hybrid seed key: %v", err)
	}

	f.Add(privateBytes)
	f.Add([]byte{})
	f.Add(make([]byte, PrivateKeySize))

	f.Fuzz(func(t *testing.T, encoded []byte) {
		key, err := UnmarshalPrivateKey(encoded)
		if err != nil {
			return
		}
		marshaled, err := key.MarshalBinary()
		if err != nil {
			t.Fatalf("accepted private key failed to marshal: %v", err)
		}
		if len(marshaled) != PrivateKeySize {
			t.Fatalf("accepted private key marshaled to %d bytes, want %d", len(marshaled), PrivateKeySize)
		}
	})
}
