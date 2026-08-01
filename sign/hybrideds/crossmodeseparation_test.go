package hybrideds

import (
	"crypto/rand"
	"testing"

	"github.com/quantumcoinproject/circl/sign/ed25519"
	"github.com/quantumcoinproject/circl/sign/mldsa/mldsa44"
	"golang.org/x/crypto/sha3"
)

// FINDING-002: signing mode is not bound into any component's signed input.
// See ../../audit/FINDING-002-cross-mode-separation.md
//
// This package exposes two modes -- compact (id 1) and full (id 2) -- over ONE key
// pair. Neither passes a domain separator to any component: Ed25519 signs with an
// empty RFC 8032 context, and both ML-DSA and SLH-DSA are invoked through
// SignNoContext/SignRandomizedNoContext (ML-DSA Sign_internal, which omits the
// FIPS 204 M' = 0x00 || len(ctx) || ctx || msg encoding).
//
// Writing P_m for the payload map of mode m -- the exact byte string handed to the
// component signers -- cross-mode separation requires
//
//	Image(P_compact) INTERSECT Image(P_full) = {}                          (dagger)
//
// If (dagger) fails reachably, one query to a full-mode signing oracle yields
// components that the compact verifier accepts on a message never submitted to the
// oracle: an existential forgery under chosen-message attack.
//
// Here:
//
//	P_full(msg)    = msg                                  |msg| = 32 (enforced)
//	P_compact(msg) = SHA3-512(nonce || msg || pk_slhdsa)   always 64 bytes
//
// (dagger) holds -- but only because 32 != 64. It is an arithmetic property of two
// constants chosen for unrelated reasons, NOT domain separation. The two tests below
// assert both halves of that claim: separation holds today, and it collapses the
// moment the lengths coincide.
//
// APPLICABILITY (see the finding for full reasoning). The attack needs a full-mode
// SIGNING ORACLE over caller-chosen bytes. No supported consumer exposes one for this
// scheme, independently of message length:
//
//   - quantum-coin-go        -- NOT exploitable. Signs 32-byte Keccak-256 digests;
//     IsSignatureTypeAllowedForTxn never admits scheme id 2 for a transaction in any
//     block regime; SignWithContext additionally binds the scheme ID at the wrapper.
//   - quantum-coin-js-sdk    -- NOT exploitable. A QuantumCoin-specific SDK, supported
//     only for QuantumCoin wallets/dApps/tooling, not as a general crypto library. It
//     never calls hybrideds full-mode signing anywhere: the only hybrideds entry points
//     it uses are signCompact, verifyCompact and verify. Its generic sign() routes
//     exclusively to the ML-DSA schemes (ids 3/4/5), so the only "full" mode reachable
//     through the SDK is id 4, whose separation is cryptographic rather than
//     length-based. circl's WASM layer does export circl.hybrideds.sign on the global
//     namespace with no length check at the binding layer, but reaching it requires
//     bypassing the SDK API -- outside the supported QuantumCoin context -- and circl's
//     internal 32-byte check still refuses the 64-byte payload the attack needs.
//   - quantumcoin.js         -- NOT exploitable. Same QuantumCoin-only deployment
//     context; no signing of its own, delegates to quantum-coin-js-sdk. Its
//     arbitrary-message API (Wallet.signMessage/signMessageSync) reduces the message to
//     a 32-byte digest and signs via the SDK's sign(), which never selects hybrideds
//     full mode.
//
// Convention: these are characterization tests (see FINDING-001). They assert current
// behaviour so CI stays green, and act as tripwires -- when domain separation lands,
// TestShrinkingCompactDigestWouldReintroduceForgery should be inverted and renamed.

// TestCrossModeSeparationRestsOnPayloadLength documents that (dagger) holds for the
// shipped parameters, and pins down exactly which property is doing the work.
func TestCrossModeSeparationRestsOnPayloadLength(t *testing.T) {
	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Attacker picks the target message and the nonce; both are attacker-controlled
	// inputs to P_compact, and pk_slhdsa is public.
	target := make([]byte, CRYPTO_MSG_LENGTH)
	for i := range target {
		target[i] = byte('A' + i%26)
	}
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(0x11 * (i % 16))
	}

	_, _, slhPub, err := pub.getPublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	slhPubBytes, err := slhPub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	// H = P_compact(target): what the compact verifier recomputes and checks against.
	h := sha3.New512()
	h.Write(nonce)
	h.Write(target)
	h.Write(slhPubBytes)
	H := h.Sum(nil)

	if len(H) == CRYPTO_MSG_LENGTH {
		t.Fatalf("(dagger) VIOLATED: |P_compact| = |P_full| = %d; the images coincide "+
			"and a full-mode signature is liftable into a compact one -- see FINDING-002", len(H))
	}
	t.Logf("|P_full| = %d, |P_compact| = %d -> images disjoint by length alone",
		CRYPTO_MSG_LENGTH, len(H))

	// The load-bearing check: the adversary cannot obtain a full-mode signature over H,
	// because Sign refuses any message that is not exactly CRYPTO_MSG_LENGTH bytes.
	// This is enforced inside the library, so it holds regardless of caller behaviour.
	if _, err := Sign(priv, rand.Reader, H); err == nil {
		t.Fatal("full Sign accepted a 64-byte message: the lift precondition is satisfied")
	}
	for _, n := range []int{0, 1, 31, 33, 63, 64, 96} {
		if _, err := Sign(priv, rand.Reader, make([]byte, n)); err == nil {
			t.Fatalf("full Sign accepted a %d-byte message; only %d must be accepted", n, CRYPTO_MSG_LENGTH)
		}
		if _, err := SignCompact(priv, rand.Reader, make([]byte, n)); err == nil {
			t.Fatalf("SignCompact accepted a %d-byte message; only %d must be accepted", n, CRYPTO_MSG_LENGTH)
		}
	}

	// End to end: components lifted out of a genuine full signature are rejected by the
	// compact verifier, because they were produced over a 32-byte payload, not over H.
	fullSig, err := Sign(priv, rand.Reader, target)
	if err != nil {
		t.Fatal(err)
	}
	edFromFull := fullSig[2 : 2+ED25519_SIG_LENGTH]
	mldsaFromFull := fullSig[2+ED25519_SIG_LENGTH+CRYPTO_MSG_LENGTH : 2+ED25519_SIG_LENGTH+CRYPTO_MSG_LENGTH+MLDSA44_SIG_LENGTH]

	forged := make([]byte, CompactSigLength)
	forged[0] = DILITHIUM_ED25519_SPHINCS_COMPACT_ID
	forged[1] = CRYPTO_MSG_LENGTH
	copy(forged[2:], edFromFull)
	copy(forged[2+ED25519_SIG_LENGTH:], mldsaFromFull)
	copy(forged[2+ED25519_SIG_LENGTH+MLDSA44_SIG_LENGTH:], nonce)
	copy(forged[2+ED25519_SIG_LENGTH+MLDSA44_SIG_LENGTH+NonceSize:], target)

	if VerifyCompact(pub, target, forged) {
		t.Fatal("FORGERY: full-mode components verified as a compact signature")
	}
	t.Log("cross-mode lift rejected -- but by payload disjointness, not domain separation")
}

// TestShrinkingCompactDigestWouldReintroduceForgery is the counterfactual that shows the
// defence above is length-based rather than cryptographic.
//
// It does not modify the library. It reproduces exactly the checks a hypothetical
// 32-byte-digest VerifyCompact would perform -- ed25519.Verify(pk, H32, sig1) and
// mldsa44.VerifyNoContext(pk, H32, sig2) -- against components lifted from a genuine
// FULL signature. Both pass, so such a compact mode would be existentially forgeable:
// the victim signed H32 as an ordinary 32-byte message and never authorised `target`.
//
// This is the executable form of the invariant in FINDING-002: shortening the compact
// digest to 32 bytes (SHA3-256 or truncation), or raising CRYPTO_MSG_LENGTH to 64,
// collapses Image(P_compact) into Image(P_full).
//
// TRIPWIRE: once the mode is bound into every component's signed input, the lift below
// stops verifying. Invert this assertion and rename the test at that point.
func TestShrinkingCompactDigestWouldReintroduceForgery(t *testing.T) {
	const wantForgeryAccepted = true // today's (vulnerable-if-shortened) behaviour

	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	target := make([]byte, CRYPTO_MSG_LENGTH)
	for i := range target {
		target[i] = byte('A' + i%26)
	}
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(0x11 * (i % 16))
	}

	edPub, mldsaPub, slhPub, err := pub.getPublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	slhPubBytes, err := slhPub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	// The hypothetical 32-byte compact digest: H32 = P_compact'(target).
	h := sha3.New256()
	h.Write(nonce)
	h.Write(target)
	h.Write(slhPubBytes)
	H32 := h.Sum(nil)
	if len(H32) != CRYPTO_MSG_LENGTH {
		t.Fatalf("expected a %d-byte digest, got %d", CRYPTO_MSG_LENGTH, len(H32))
	}

	// H32 is now a legal full-mode message -- indistinguishable from any other 32-byte
	// digest -- so the victim signs it. This is the query the real parameters forbid.
	fullSig, err := Sign(priv, rand.Reader, H32)
	if err != nil {
		t.Fatalf("full Sign rejected the 32-byte digest, attack blocked: %v", err)
	}
	edFromFull := fullSig[2 : 2+ED25519_SIG_LENGTH]
	mldsaFromFull := fullSig[2+ED25519_SIG_LENGTH+CRYPTO_MSG_LENGTH : 2+ED25519_SIG_LENGTH+CRYPTO_MSG_LENGTH+MLDSA44_SIG_LENGTH]

	edOK := ed25519.Verify(*edPub, H32, edFromFull)
	mldsaOK := mldsa44.VerifyNoContext(mldsaPub, H32, mldsaFromFull)
	gotForgeryAccepted := edOK && mldsaOK

	if gotForgeryAccepted != wantForgeryAccepted {
		t.Fatalf("FINDING-002 status changed: lifted components accepted = %v (ed25519=%v, mldsa=%v), want %v. "+
			"If domain separation has landed, invert wantForgeryAccepted and rename this test.",
			gotForgeryAccepted, edOK, mldsaOK, wantForgeryAccepted)
	}
	t.Log("FINDING-002 present: with a 32-byte compact digest, Ed25519 and ML-DSA components " +
		"lifted from a full signature satisfy the compact verifier over an unauthorised message")
	t.Log("=> today's safety is |P_full| = 32 != 64 = |P_compact|, not domain separation")
}
