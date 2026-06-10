package ed25519_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/quantumcoinproject/circl/sign/ed25519"
)

// TestUnmarshalPrivateKeyValid checks that a well-formed private key round-trips.
func TestUnmarshalPrivateKeyValid(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ed25519.UnmarshalPrivateKey(priv)
	if err != nil {
		t.Fatalf("valid private key rejected: %v", err)
	}
	if !bytes.Equal(*got, priv) {
		t.Fatal("round-tripped private key differs from input")
	}
}

// TestUnmarshalPrivateKeyRejectsMismatchedPublicHalf is the regression test for
// the deterministic-nonce fault issue: a private key whose stored public half
// does not match the seed must be rejected, because signing such a key would
// reuse the nonce R across distinct public halves and leak the secret scalar.
func TestUnmarshalPrivateKeyRejectsMismatchedPublicHalf(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Flip a bit in the public-key half (bytes [SeedSize:]); the seed is intact.
	bad := append([]byte{}, priv...)
	bad[ed25519.SeedSize] ^= 0x01
	if _, err := ed25519.UnmarshalPrivateKey(bad); err == nil {
		t.Error("UnmarshalPrivateKey accepted a private key with a public half inconsistent with the seed")
	}

	// Splicing the seed of one key with the public half of another (a different
	// but individually valid public key) must also be rejected.
	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spliced := append([]byte{}, priv[:ed25519.SeedSize]...)
	spliced = append(spliced, priv2[ed25519.SeedSize:]...)
	if _, err := ed25519.UnmarshalPrivateKey(spliced); err == nil {
		t.Error("UnmarshalPrivateKey accepted a seed spliced with a foreign public key")
	}
}

// TestUnmarshalPrivateKeyWrongLength checks the length guard still holds.
func TestUnmarshalPrivateKeyWrongLength(t *testing.T) {
	for _, n := range []int{0, ed25519.SeedSize, ed25519.PrivateKeySize - 1, ed25519.PrivateKeySize + 1} {
		if _, err := ed25519.UnmarshalPrivateKey(make([]byte, n)); err == nil {
			t.Errorf("UnmarshalPrivateKey accepted input of length %d", n)
		}
	}
}

// TestSchemeUnmarshalBinaryPrivateKeyRejectsMismatch checks that the
// sign.Scheme entry point applies the same validation.
func TestSchemeUnmarshalBinaryPrivateKeyRejectsMismatch(t *testing.T) {
	sch := ed25519.Scheme()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sch.UnmarshalBinaryPrivateKey(priv); err != nil {
		t.Fatalf("valid private key rejected by scheme: %v", err)
	}

	bad := append([]byte{}, priv...)
	bad[ed25519.SeedSize] ^= 0x01
	if _, err := sch.UnmarshalBinaryPrivateKey(bad); err == nil {
		t.Error("scheme.UnmarshalBinaryPrivateKey accepted a private key with a mismatched public half")
	}
}

// TestMismatchedKeyWouldLeakScalar documents the attack the validation prevents:
// two signatures over the same message under the same seed but different public
// halves share R, which (with the standard Ed25519 equations) reveals the
// secret scalar. Here we only assert the precondition (identical R), confirming
// why such keys must never be accepted for signing.
func TestMismatchedKeyWouldLeakScalar(t *testing.T) {
	_, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Build a second 64-byte private key with the same seed but a different
	// (here, zeroed) public half. UnmarshalPrivateKey would reject it, so we
	// assemble it directly to exercise the raw signer.
	priv2 := append([]byte{}, priv1...)
	for i := ed25519.SeedSize; i < ed25519.PrivateKeySize; i++ {
		priv2[i] = 0x00
	}

	msg := []byte("same message signed twice")
	sig1 := ed25519.Sign(ed25519.PrivateKey(priv1), msg)
	sig2 := ed25519.Sign(ed25519.PrivateKey(priv2), msg)

	// R is the first 32 bytes of each signature; it depends only on seed+msg.
	if !bytes.Equal(sig1[:32], sig2[:32]) {
		t.Fatal("expected identical R for same seed+message (nonce-reuse precondition)")
	}
	// The S halves differ because the challenge binds the (different) public
	// halves; this difference is exactly what leaks the scalar.
	if bytes.Equal(sig1[32:], sig2[32:]) {
		t.Fatal("expected differing S halves for differing public halves")
	}
}
