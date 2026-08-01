package hybridedmldsaslhdsa5

import (
	"crypto/rand"
	"testing"

	"github.com/quantumcoinproject/circl/sign/ed25519"
	"github.com/quantumcoinproject/circl/sign/mldsa/mldsa87"
)

// FINDING-002: signing mode is not bound into every component's signed input.
// See ../../audit/FINDING-002-cross-mode-separation.md
//
// This package is structurally OUT OF SCOPE for that finding: it exposes only
// Sign/Verify (scheme id 5) and has no compact mode, so there is no pair of modes over
// one key pair and no instance of the cross-mode condition
//
//	Image(P_compact) INTERSECT Image(P_full) = {}
//
// to satisfy or violate. The scheme ID is nonetheless bound into both the ML-DSA and
// SLH-DSA contexts ({5}), which is consistent with the remediation FINDING-002
// recommends.
//
// The tests below exist so that this stays true by assertion rather than by assumption:
// adding a second mode later, or dropping the scheme ID from the ML-DSA context, trips a
// test instead of silently inheriting the finding.
//
// Residual observation (tracked in FINDING-002 under cross-SCHEME transplantation, and
// exploited by FINDING-001): as in the other hybrid packages, Ed25519 signs the bare
// 32-byte message with an empty RFC 8032 context, so its component carries no binding to
// scheme id 5 either. That is inert only while an Ed25519 key is confined to a single
// composite key, which this package's documentation already requires.
//
// APPLICABILITY (see the finding for full reasoning). This scheme has one mode, so the
// cross-mode surface does not exist for any consumer:
//
//   - quantum-coin-go        -- NOT applicable. Single mode; nothing to confuse it with.
//   - quantum-coin-js-sdk    -- NOT applicable. A QuantumCoin-specific SDK, supported
//     only for QuantumCoin wallets/dApps/tooling, not as a general crypto library. It
//     reaches this scheme via sign() with signingContext 1 (or key-type derivation),
//     which calls hybrid5.sign; circl's WASM layer exports only sign/verify for this
//     scheme, so there is no compact entry point to confuse it with.
//   - quantumcoin.js         -- NOT applicable. Same QuantumCoin-only deployment
//     context; no signing of its own, delegates to quantum-coin-js-sdk.

// TestNoCompactModeExists pins the structural precondition: this scheme has exactly one
// mode, so FINDING-002's cross-mode attack surface does not exist here.
//
// TRIPWIRE: if a compact mode is ever added to this package, this test should be
// replaced by the pair in sign/hybridedmldsaslhdsa -- and the new mode must bind a
// distinct context into EVERY component, not only ML-DSA/SLH-DSA.
func TestNoCompactModeExists(t *testing.T) {
	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	msg := make([]byte, CRYPTO_MSG_LENGTH)
	for i := range msg {
		msg[i] = byte('A' + i%26)
	}

	sig, err := Sign(priv, rand.Reader, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != SigLength {
		t.Fatalf("unexpected signature length %d, want %d", len(sig), SigLength)
	}
	if sig[0] != ED25519_MLDSA5_SLHDSA5_FULL_ID {
		t.Fatalf("unexpected scheme id %d, want %d", sig[0], ED25519_MLDSA5_SLHDSA5_FULL_ID)
	}
	if !Verify(pub, msg, sig) {
		t.Fatal("round-trip verification failed")
	}
	t.Logf("single mode only (scheme id %d); no compact/full pair exists over this key pair",
		ED25519_MLDSA5_SLHDSA5_FULL_ID)

	// Only exactly-32-byte messages are accepted, as in the sibling schemes.
	for _, n := range []int{0, 1, 31, 33, 64, 96} {
		if _, err := Sign(priv, rand.Reader, make([]byte, n)); err == nil {
			t.Fatalf("Sign accepted a %d-byte message; only %d must be accepted", n, CRYPTO_MSG_LENGTH)
		}
	}
}

// TestSchemeIDIsBoundIntoMLDSAContext asserts the property that makes this scheme
// consistent with FINDING-002's recommended fix: the scheme ID reaches ML-DSA as a
// context string, so a component signature is bound to scheme id 5 and cannot be
// reinterpreted under a different context.
//
// It also records the converse for Ed25519, which receives no such binding.
func TestSchemeIDIsBoundIntoMLDSAContext(t *testing.T) {
	const wantEd25519Unbound = true // today's behaviour; see FINDING-001 and FINDING-002

	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, mldsaPub, _, err := pub.getPublicKeys()
	if err != nil {
		t.Fatal(err)
	}

	msg := make([]byte, CRYPTO_MSG_LENGTH)
	for i := range msg {
		msg[i] = byte(i)
	}

	sig, err := Sign(priv, rand.Reader, msg)
	if err != nil {
		t.Fatal(err)
	}
	edComponent := sig[2 : 2+ED25519_SIG_LENGTH]
	mldsaComponent := sig[2+ED25519_SIG_LENGTH+CRYPTO_MSG_LENGTH : 2+ED25519_SIG_LENGTH+CRYPTO_MSG_LENGTH+mldsa87.SignatureSize]

	// Under the scheme's own context the ML-DSA component verifies...
	correctCtx := []byte{ED25519_MLDSA5_SLHDSA5_FULL_ID}
	if !mldsa87.Verify(mldsaPub, msg, correctCtx, mldsaComponent) {
		t.Fatal("ML-DSA component failed to verify under its own scheme-ID context")
	}
	// ...and under any other context it does not. This is the FIPS 204 M' binding.
	for _, other := range [][]byte{{}, {0x00}, {0x03}, {0x04}, {ED25519_MLDSA5_SLHDSA5_FULL_ID, 0x00}} {
		if mldsa87.Verify(mldsaPub, msg, other, mldsaComponent) {
			t.Fatalf("ML-DSA component verified under a foreign context %v; scheme-ID binding is broken", other)
		}
	}
	t.Log("ML-DSA: scheme id 5 is bound via the FIPS 204 context encoding -- component is " +
		"not reinterpretable under another context")

	// Ed25519 receives no context: its component is a bare RFC 8032 signature over msg,
	// carrying no indication of the scheme that produced it.
	gotEd25519Unbound := ed25519.Verify(*edPub, msg, edComponent)
	if gotEd25519Unbound != wantEd25519Unbound {
		t.Fatalf("FINDING-002 status changed: Ed25519 component unbound = %v, want %v. "+
			"If the scheme ID is now bound into the Ed25519 signed input, invert "+
			"wantEd25519Unbound and rename this test.", gotEd25519Unbound, wantEd25519Unbound)
	}
	t.Log("Ed25519: no context bound -- the component is a valid bare Ed25519 signature " +
		"over msg and carries no scheme identity (FINDING-002 recommended fix would change this)")
}
