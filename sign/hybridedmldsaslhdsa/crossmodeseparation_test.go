package hybridedmldsaslhdsa

import (
	"crypto/rand"
	"testing"

	"github.com/quantumcoinproject/circl/sign/ed25519"
	"github.com/quantumcoinproject/circl/sign/mldsa/mldsa44"
)

// FINDING-002: signing mode is not bound into every component's signed input.
// See ../../audit/FINDING-002-cross-mode-separation.md
//
// This package exposes compact (id 3) and full (id 4) over ONE key pair. Unlike
// sign/hybrideds, cross-mode separation here IS cryptographic: the ML-DSA context
// differs by mode -- {FULL_ID} versus {COMPACT_ID || pk_slhdsa} -- and FIPS 204 binds
// ctx into M' = 0x00 || len(ctx) || ctx || msg, so an ML-DSA component produced in one
// mode is not a valid ML-DSA component in the other. Writing P_m for the payload map,
//
//	Image(P_compact) INTERSECT Image(P_full) = {}
//
// holds by construction and does not depend on any length invariant.
//
// The gap this finding records is that the separation is single-layered. For the
// Ed25519 component both modes sign the bare 32-byte message with an empty RFC 8032
// context, so P_compact = P_full = identity at that layer: the Ed25519 component is
// bit-for-bit interchangeable between modes. ALL mode separation is therefore carried
// by ML-DSA (and, for full mode, SLH-DSA), and none by Ed25519.
//
// This is not itself a forgery. Completing a full signature additionally requires
// ML-DSA under ctx={4} and SLH-DSA under ctx={4} beneath the victim's key, which the
// adversary does not hold. Nor does it materially weaken compact mode, where ML-DSA is
// already the sole source of post-quantum unforgeability -- an adversary who defeats
// ML-DSA has broken compact mode outright. The objection is structural: binding the
// mode in all three components is free, and concentrating the property in one is
// avoidable. Composed with FINDING-001 -- where the adversary supplies their OWN
// ML-DSA and SLH-DSA keys -- Ed25519 mode-agnosticism becomes a usable primitive; that
// composition is tracked in FINDING-001.
//
// APPLICABILITY (see the finding for full reasoning). Cross-mode separation here is
// cryptographic, so no consumer depends on a length invariant for it:
//
//   - quantum-coin-go        -- NOT exploitable. Signs 32-byte Keccak-256 digests; the
//     ML-DSA context blocks any lift between modes irrespective of message bytes.
//   - quantum-coin-js-sdk    -- NOT exploitable. A QuantumCoin-specific SDK, supported
//     only for QuantumCoin wallets/dApps/tooling, not as a general crypto library. Both
//     modes of this scheme ARE reachable through its API -- sign() selects
//     signCompact (id 3) for signingContext 0 and sign (id 4) for signingContext 2 --
//     but the ML-DSA context makes the components non-interchangeable, so exposing both
//     is safe. Only the unbound Ed25519 component (below) is transplantable, and on its
//     own it forges nothing.
//   - quantumcoin.js         -- NOT exploitable. Same QuantumCoin-only deployment
//     context; no signing of its own, delegates to quantum-coin-js-sdk. Its
//     Wallet.signMessage/signMessageSync path reduces the message to a 32-byte digest
//     and signs through the SDK's sign().
//
// Convention: characterization tests (see FINDING-001) -- they assert current behaviour
// and act as tripwires when the fix lands.

// TestCrossModeSeparationIsCarriedSolelyByMLDSAContext performs the lift and then
// attributes the rejection to a specific layer.
func TestCrossModeSeparationIsCarriedSolelyByMLDSAContext(t *testing.T) {
	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	msg := make([]byte, CRYPTO_MSG_LENGTH)
	for i := range msg {
		msg[i] = byte('A' + i%26)
	}

	fullSig, err := Sign(priv, rand.Reader, msg)
	if err != nil {
		t.Fatal(err)
	}

	// full   : [id=4][len][ed25519 64][msg 32][mldsa 2420][slhdsa]
	// compact: [id=3][len][ed25519 64][mldsa 2420][msg 32]
	edFromFull := fullSig[2 : 2+ED25519_SIG_LENGTH]
	mldsaFromFull := fullSig[2+ED25519_SIG_LENGTH+CRYPTO_MSG_LENGTH : 2+ED25519_SIG_LENGTH+CRYPTO_MSG_LENGTH+mldsa44.SignatureSize]

	forged := make([]byte, CompactSigLength)
	forged[0] = ED25519_MLDSA_SLHDSA_COMPACT_ID
	forged[1] = CRYPTO_MSG_LENGTH
	copy(forged[2:], edFromFull)
	copy(forged[2+ED25519_SIG_LENGTH:], mldsaFromFull)
	copy(forged[2+ED25519_SIG_LENGTH+mldsa44.SignatureSize:], msg)

	if VerifyCompact(pub, msg, forged) {
		t.Fatal("FORGERY: full-mode components verified as a compact signature")
	}

	// Attribute the rejection. The ML-DSA context is the only thing that refused.
	edPub, mldsaPub, slhPub, err := pub.getPublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	slhPubBytes, err := slhPub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	compactCtx := make([]byte, 1+len(slhPubBytes))
	compactCtx[0] = ED25519_MLDSA_SLHDSA_COMPACT_ID
	copy(compactCtx[1:], slhPubBytes)

	if mldsa44.Verify(mldsaPub, msg, compactCtx, mldsaFromFull) {
		t.Fatal("FORGERY: full-mode ML-DSA component verified under the compact context; " +
			"the sole cross-mode separator has failed")
	}
	t.Log("ML-DSA layer: full-mode component rejected under the compact context -- this is " +
		"the only layer providing cross-mode separation")

	if !ed25519.Verify(*edPub, msg, edFromFull) {
		t.Fatal("expected the full-mode Ed25519 component to verify over msg")
	}
	t.Log("Ed25519 layer: full-mode component is valid in compact mode -- contributes no " +
		"mode binding (empty RFC 8032 context, identical payload in both modes)")
}

// TestEd25519ComponentIsModeAgnostic isolates the structural gap: P_compact = P_full for
// the Ed25519 component, so its signature is interchangeable between modes in both
// directions. Verified against signatures actually produced in each mode.
//
// TRIPWIRE: binding the mode into the Ed25519 signed input (Ed25519ctx, or signing
// H(bind || msg)) makes the cross-checks below fail. Invert wantModeAgnostic and rename
// this test when that lands.
func TestEd25519ComponentIsModeAgnostic(t *testing.T) {
	const wantModeAgnostic = true // today's behaviour

	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, _, err := pub.getPublicKeys()
	if err != nil {
		t.Fatal(err)
	}

	msg := make([]byte, CRYPTO_MSG_LENGTH)
	for i := range msg {
		msg[i] = byte(i)
	}

	fullSig, err := Sign(priv, rand.Reader, msg)
	if err != nil {
		t.Fatal(err)
	}
	compactSig, err := SignCompact(priv, rand.Reader, msg)
	if err != nil {
		t.Fatal(err)
	}

	edFromFull := fullSig[2 : 2+ED25519_SIG_LENGTH]
	edFromCompact := compactSig[2 : 2+ED25519_SIG_LENGTH]

	// Both components verify against the bare message under the same key: neither
	// carries any indication of the mode that produced it.
	gotModeAgnostic := ed25519.Verify(*edPub, msg, edFromFull) &&
		ed25519.Verify(*edPub, msg, edFromCompact)

	if gotModeAgnostic != wantModeAgnostic {
		t.Fatalf("FINDING-002 status changed: Ed25519 component mode-agnostic = %v, want %v. "+
			"If the mode is now bound into the Ed25519 signed input, invert wantModeAgnostic "+
			"and rename this test.", gotModeAgnostic, wantModeAgnostic)
	}
	t.Log("FINDING-002 present: the Ed25519 component of a compact signature is a valid " +
		"Ed25519 component of a full signature over the same message, and vice versa")
	t.Log("=> Ed25519 provides zero cross-mode separation; ML-DSA/SLH-DSA carry all of it")
}
