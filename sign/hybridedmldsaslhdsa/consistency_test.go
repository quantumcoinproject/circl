package hybridedmldsaslhdsa

import (
	"crypto/rand"
	"testing"

	"github.com/quantumcoinproject/circl/sign/ed25519"
	"github.com/quantumcoinproject/circl/sign/mldsa/mldsa44"
)

func TestUnmarshalPrivateKeyRejectsTampered(t *testing.T) {
	_, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := priv.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalPrivateKey(raw); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	// Flip a byte in the Ed25519 seed -> derived Ed25519 pub no longer matches.
	bad := append([]byte{}, raw...)
	bad[0] ^= 0xff
	if _, err := UnmarshalPrivateKey(bad); err == nil {
		t.Error("tampered Ed25519 seed accepted")
	}
	// Flip a byte in the embedded ML-DSA public key region.
	off := ed25519.PrivateKeySize + mldsa44.PrivateKeySize
	bad2 := append([]byte{}, raw...)
	bad2[off] ^= 0xff
	if _, err := UnmarshalPrivateKey(bad2); err == nil {
		t.Error("tampered ML-DSA public key accepted")
	}
}
