package hybridedmldsaslhdsa

// Demonstration of FINDING-001: the composite public key is not bound into the
// input signed by any component, so the scheme is SEPARABLE -- a component
// signature can be transplanted into a valid composite signature under a
// different composite public key.
//
// Full write-up, formal treatment, impact analysis and per-consumer
// applicability: audit/FINDING-001-key-substitution.md
//
// -----------------------------------------------------------------------------
// SCOPE -- WHAT THIS IS AND IS NOT
// -----------------------------------------------------------------------------
// NOT broken by this finding:
//   - EUF-CMA / SUF-CMA of the composite scheme. No new signature can be
//     produced under the victim's public key pk.
//   - Any component primitive (Ed25519, ML-DSA-44, SLH-DSA) -- each is used as
//     specified and none is attacked here.
//   - Confidentiality of any private key. Nothing is recovered.
//
// Broken: exclusive ownership. A (message, signature) pair is not bound to a
// unique public key. Formally the verification predicate
//
//	Verify(pk, m, sigma) = AND_i Verify_i(pk_i, mu_i(m), sigma_i)
//
// factorises, because no mu_i depends on the whole pk. Independently valid
// (pk_i, sigma_i) pairs therefore compose regardless of provenance.
//
// The adversary's substituted key pk' is PARASITIC, not a usable identity: it
// does not know sk_1, so it cannot sign any message the victim has not already
// signed. Because sigma' != sigma, this is strictly weaker than an S-CEO break.
//
// NO IMPACT ON THE INTENDED CONSUMERS -- no action required. quantum-coin-go,
// quantum-coin-js-sdk and quantumcoin.js all derive identity from a hash of the
// COMPLETE composite public key (addresses, transaction sender, node identity,
// validator identity). Since pk' != pk, a substituted key yields a different
// address that belongs to the adversary. No funds, accounts, node identities or
// consensus messages are at risk. This is a planned hardening item, not an
// incident.
//
// -----------------------------------------------------------------------------
// WHAT THESE TESTS ASSERT
// -----------------------------------------------------------------------------
// These are CHARACTERIZATION tests: they assert the behaviour the code has
// TODAY, so CI stays green and the finding stays executable rather than
// prose-only.
//
// They are also TRIPWIRES. Applying the fix (the BUFF transform: absorb
// H(pk_1 || pk_2 || pk_3) into every component's signed input) WILL make these
// tests fail. That is the intended signal, not a regression. At that point,
// invert each `wantForgeryAccepted` constant to false and rename the tests to
// assert the secure property directly.
// -----------------------------------------------------------------------------

import (
	"crypto/rand"
	"testing"

	"github.com/quantumcoinproject/circl/sign/ed25519"
	"github.com/quantumcoinproject/circl/sign/mldsa/mldsa44"
	"github.com/quantumcoinproject/circl/sign/slhdsa"
)

// testMessage returns the fixed 32-byte message these tests sign. The scheme
// only accepts messages of exactly CRYPTO_MSG_LENGTH.
func testMessage() []byte {
	msg := make([]byte, CRYPTO_MSG_LENGTH)
	for i := range msg {
		msg[i] = byte(i)
	}
	return msg
}

// attackerComponents generates an ML-DSA-44 and an SLH-DSA-SHAKE-256f keypair
// under the attacker's own control, and signs msg with each using ctx.
//
// This models the attacker's true capability: they cannot forge anything under
// the victim's keys, they simply generate their own keys honestly. The entire
// attack rests on being able to pair those honest signatures with a component
// signature lifted from the victim.
func attackerComponents(t *testing.T, msg, ctx []byte) (
	mlPub *mldsa44.PublicKey, mlSig []byte,
	slhPubBytes, slhSig []byte,
) {
	t.Helper()

	mlPub, mlPriv, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("attacker ML-DSA keygen: %v", err)
	}
	var mlSigArr [mldsa44.SignatureSize]byte
	if err := mldsa44.Sign(mlPriv, msg, ctx, rand.Reader, mlSigArr[:]); err != nil {
		t.Fatalf("attacker ML-DSA sign: %v", err)
	}
	mlSig = mlSigArr[:]

	slhPub, slhPriv, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHAKE_256f)
	if err != nil {
		t.Fatalf("attacker SLH-DSA keygen: %v", err)
	}
	slhPubBytes, err = slhPub.MarshalBinary()
	if err != nil {
		t.Fatalf("attacker SLH-DSA marshal: %v", err)
	}
	slhSig, err = slhdsa.SignRandomized(&slhPriv, rand.Reader, slhdsa.NewMessage(msg), ctx)
	if err != nil {
		t.Fatalf("attacker SLH-DSA sign: %v", err)
	}
	return
}

// forgeCompositePublicKey assembles a composite public key from the victim's
// Ed25519 half and attacker-controlled ML-DSA and SLH-DSA halves.
//
// Note there is nothing to "break" here: UnmarshalPublicKey only length-checks,
// because a composite public key carries no internal binding between its three
// component keys.
func forgeCompositePublicKey(t *testing.T, victimEd25519Pub, mldsaPub, slhdsaPub []byte) *PublicKey {
	t.Helper()

	forged := make([]byte, 0, PublicKeySize)
	forged = append(forged, victimEd25519Pub...)
	forged = append(forged, mldsaPub...)
	forged = append(forged, slhdsaPub...)
	if len(forged) != PublicKeySize {
		t.Fatalf("forged public key is %d bytes, want %d", len(forged), PublicKeySize)
	}
	pk, err := UnmarshalPublicKey(forged)
	if err != nil {
		t.Fatalf("forged composite public key rejected at unmarshal: %v", err)
	}
	return pk
}

// TestKeySubstitutionFullMode demonstrates the attack against FULL (3-of-3)
// signatures.
//
// Attack:
//  1. The victim publishes an ordinary full signature. Nothing is compromised.
//  2. The attacker extracts the 64-byte Ed25519 component from it. In full mode
//     Ed25519 signs the bare 32-byte message with an empty RFC 8032 context, so
//     that component is a standalone Ed25519 signature over msg and carries no
//     reference whatsoever to the other two component keys.
//  3. The attacker generates their OWN ML-DSA and SLH-DSA keypairs and signs the
//     same message with context {4} -- exactly what an honest signer does.
//  4. The attacker assembles a signature and a composite public key that mixes
//     the victim's Ed25519 key with their own ML-DSA and SLH-DSA keys.
//
// Verify() accepts: Verify(pk', m, sigma') = 1 with pk' != pk and sigma' != sigma.
//
// The adversary never obtains the victim's Ed25519 private key. It therefore
// cannot sign any message outside the set the victim has already signed -- pk'
// is parasitic, usable only to re-present this one message. The victim's own key
// is entirely unaffected; this is not a forgery under pk.
//
// Classification: a failure of non-separability for combined signature schemes
// (Bindel-Herath-McKague-Stebila, PQCrypto 2017), in the duplicate-signature
// key selection family (Blake-Wilson-Menezes 1999; Pornin-Stern 2005). The
// standard remedy is the BUFF transform (Cremers et al., IEEE S&P 2021).
func TestKeySubstitutionFullMode(t *testing.T) {
	const wantForgeryAccepted = true // flip to false once FINDING-001 is fixed

	msg := testMessage()

	victimPub, victimPriv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("victim keygen: %v", err)
	}
	victimSig, err := Sign(victimPriv, rand.Reader, msg)
	if err != nil {
		t.Fatalf("victim sign: %v", err)
	}
	if !Verify(victimPub, msg, victimSig) {
		t.Fatal("sanity: victim's own signature failed to verify")
	}

	// Step 2: lift the victim's Ed25519 component out of the published signature.
	// Layout: [0]=scheme id, [1]=msg len, [2:66]=Ed25519 sig, ...
	stolenEd25519Sig := make([]byte, ED25519_SIG_LENGTH)
	copy(stolenEd25519Sig, victimSig[2:2+ED25519_SIG_LENGTH])

	// Step 3: the attacker's own honest component signatures, full-mode context.
	ctx := []byte{ED25519_MLDSA_SLHDSA_FULL_ID}
	mlPub, mlSig, slhPubBytes, slhSig := attackerComponents(t, msg, ctx)

	// Step 4: assemble the forged full signature.
	// Layout: id | msgLen | ed25519Sig | msg | mldsaSig | slhdsaSig
	forgedSig := make([]byte, 0, SigLength)
	forgedSig = append(forgedSig, ED25519_MLDSA_SLHDSA_FULL_ID, byte(CRYPTO_MSG_LENGTH))
	forgedSig = append(forgedSig, stolenEd25519Sig...)
	forgedSig = append(forgedSig, msg...)
	forgedSig = append(forgedSig, mlSig...)
	forgedSig = append(forgedSig, slhSig...)
	if len(forgedSig) != SigLength {
		t.Fatalf("forged signature is %d bytes, want %d", len(forgedSig), SigLength)
	}

	victimPubBytes, err := victimPub.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal victim public key: %v", err)
	}
	forgedPub := forgeCompositePublicKey(t,
		victimPubBytes[:ed25519.PublicKeySize], mlPub.Bytes(), slhPubBytes)

	got := Verify(forgedPub, msg, forgedSig)
	if got != wantForgeryAccepted {
		t.Errorf("Verify(forged) = %v, want %v", got, wantForgeryAccepted)
	}
	if got {
		t.Logf("FINDING-001 present (expected): Verify(pk', m, sigma') = 1 where pk' " +
			"retains the victim's Ed25519 public key and substitutes adversary-generated " +
			"ML-DSA and SLH-DSA keys. Not a forgery under the victim's key pk, and not " +
			"exploitable in quantum-coin-go / quantum-coin-js-sdk / quantumcoin.js, all " +
			"of which key identity on a hash of the complete composite public key. " +
			"See audit/FINDING-001-key-substitution.md")
	}
}

// TestKeySubstitutionCompactMode demonstrates the same attack against COMPACT
// (2-of-3) signatures.
//
// Compact mode binds the SLH-DSA public key into the ML-DSA context
// (ctx = {3} || slhdsaPubKey) as a breakglass anchor. That does NOT prevent this
// attack, because the attacker supplies their own SLH-DSA public key and simply
// computes the matching context themselves. The Ed25519 component still signs
// the bare message and so remains freely transplantable.
func TestKeySubstitutionCompactMode(t *testing.T) {
	const wantForgeryAccepted = true // flip to false once FINDING-001 is fixed

	msg := testMessage()

	victimPub, victimPriv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("victim keygen: %v", err)
	}
	victimSig, err := SignCompact(victimPriv, rand.Reader, msg)
	if err != nil {
		t.Fatalf("victim sign compact: %v", err)
	}
	if !VerifyCompact(victimPub, msg, victimSig) {
		t.Fatal("sanity: victim's own compact signature failed to verify")
	}

	stolenEd25519Sig := make([]byte, ED25519_SIG_LENGTH)
	copy(stolenEd25519Sig, victimSig[2:2+ED25519_SIG_LENGTH])

	// The attacker generates their own SLH-DSA key first, because the compact
	// ML-DSA context commits to it -- and the attacker controls that value.
	slhPub, _, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHAKE_256f)
	if err != nil {
		t.Fatalf("attacker SLH-DSA keygen: %v", err)
	}
	slhPubBytes, err := slhPub.MarshalBinary()
	if err != nil {
		t.Fatalf("attacker SLH-DSA marshal: %v", err)
	}

	ctx := make([]byte, 1+len(slhPubBytes))
	ctx[0] = ED25519_MLDSA_SLHDSA_COMPACT_ID
	copy(ctx[1:], slhPubBytes)

	mlPub, mlPriv, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("attacker ML-DSA keygen: %v", err)
	}
	var mlSig [mldsa44.SignatureSize]byte
	if err := mldsa44.Sign(mlPriv, msg, ctx, rand.Reader, mlSig[:]); err != nil {
		t.Fatalf("attacker ML-DSA sign: %v", err)
	}

	// Layout: id | msgLen | ed25519Sig | mldsaSig | msg
	forgedSig := make([]byte, 0, CompactSigLength)
	forgedSig = append(forgedSig, ED25519_MLDSA_SLHDSA_COMPACT_ID, byte(CRYPTO_MSG_LENGTH))
	forgedSig = append(forgedSig, stolenEd25519Sig...)
	forgedSig = append(forgedSig, mlSig[:]...)
	forgedSig = append(forgedSig, msg...)
	if len(forgedSig) != CompactSigLength {
		t.Fatalf("forged compact signature is %d bytes, want %d", len(forgedSig), CompactSigLength)
	}

	victimPubBytes, err := victimPub.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal victim public key: %v", err)
	}
	forgedPub := forgeCompositePublicKey(t,
		victimPubBytes[:ed25519.PublicKeySize], mlPub.Bytes(), slhPubBytes)

	got := VerifyCompact(forgedPub, msg, forgedSig)
	if got != wantForgeryAccepted {
		t.Errorf("VerifyCompact(forged) = %v, want %v", got, wantForgeryAccepted)
	}
}

// TestEd25519ComponentIsCrossModeTransplantable shows WHY the attack works in
// both modes at once: the Ed25519 component carries no domain separation, so the
// exact same 64 bytes are produced whether the signer called Sign or SignCompact.
//
// Consequence: a single compact signature -- the cheap, default mode -- yields an
// Ed25519 component that can be transplanted into a forged FULL signature. The
// attacker does not need the victim to have ever produced a full signature.
//
// This is also why the scheme-ID byte does not help. It separates the two modes
// in the ML-DSA and SLH-DSA contexts, but never reaches Ed25519.
func TestEd25519ComponentIsCrossModeTransplantable(t *testing.T) {
	const wantIdentical = true // flip to false once Ed25519 carries a context

	msg := testMessage()

	_, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	fullSig, err := Sign(priv, rand.Reader, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	compactSig, err := SignCompact(priv, rand.Reader, msg)
	if err != nil {
		t.Fatalf("sign compact: %v", err)
	}

	edFromFull := fullSig[2 : 2+ED25519_SIG_LENGTH]
	edFromCompact := compactSig[2 : 2+ED25519_SIG_LENGTH]

	got := string(edFromFull) == string(edFromCompact)
	if got != wantIdentical {
		t.Errorf("Ed25519 component identical across modes = %v, want %v", got, wantIdentical)
	}
}
