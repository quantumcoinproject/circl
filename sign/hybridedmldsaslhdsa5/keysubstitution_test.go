package hybridedmldsaslhdsa5

// Demonstration of FINDING-001 for the level-5 scheme (Ed25519 + ML-DSA-87 +
// SLH-DSA-SHAKE-256s).
//
// Full write-up, formal treatment and per-consumer applicability:
// audit/FINDING-001-key-substitution.md
//
// This scheme is the "corrected sibling" in most respects -- full-only (3-of-3),
// FIPS-conformant, and it binds the scheme ID {5} into the ML-DSA and SLH-DSA
// contexts. It is nonetheless separable, because a constant scheme identifier
// does not identify WHICH composite key produced the signature: no component's
// signed input depends on the composite public key.
//
// SCOPE: this does NOT break EUF-CMA/SUF-CMA of the composite scheme, nor any
// component primitive, nor key confidentiality. What fails is exclusive
// ownership -- a (message, signature) pair is not bound to a unique public key.
// The substituted key pk' is parasitic: the adversary does not hold sk_1 and so
// cannot sign anything the victim has not already signed.
//
// NO IMPACT ON THE INTENDED CONSUMERS -- no action required. quantum-coin-go,
// quantum-coin-js-sdk and quantumcoin.js all derive identity from a hash of the
// COMPLETE composite public key, so a substituted key yields a different address
// belonging to the adversary. Planned hardening item, not an incident.
//
// These are CHARACTERIZATION tests asserting today's behaviour, and TRIPWIRES
// that will fail once the composite key is bound in (BUFF transform). See the
// header of sign/hybridedmldsaslhdsa/keysubstitution_test.go for the full
// convention.

import (
	"crypto/rand"
	"testing"

	"github.com/quantumcoinproject/circl/sign/ed25519"
	"github.com/quantumcoinproject/circl/sign/mldsa/mldsa87"
	"github.com/quantumcoinproject/circl/sign/slhdsa"
)

// TestKeySubstitutionFullMode lifts the victim's Ed25519 component out of a
// published level-5 signature and pairs it with attacker-generated ML-DSA-87 and
// SLH-DSA-SHAKE-256s keys.
//
// The scheme-ID context {5} does not help: it is a constant that every signer
// uses, so the attacker simply uses it too. What is missing is any commitment to
// WHICH ML-DSA and SLH-DSA keys accompany the Ed25519 key.
func TestKeySubstitutionFullMode(t *testing.T) {
	const wantForgeryAccepted = true // flip to false once FINDING-001 is fixed

	msg := make([]byte, CRYPTO_MSG_LENGTH)
	for i := range msg {
		msg[i] = byte(i)
	}

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

	// The Ed25519 component signs the bare message with an empty context, so it
	// is a standalone signature over msg with no tie to the other components.
	stolenEd25519Sig := make([]byte, ED25519_SIG_LENGTH)
	copy(stolenEd25519Sig, victimSig[2:2+ED25519_SIG_LENGTH])

	ctx := []byte{ED25519_MLDSA5_SLHDSA5_FULL_ID}

	mlPub, mlPriv, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("attacker ML-DSA-87 keygen: %v", err)
	}
	var mlSig [mldsa87.SignatureSize]byte
	if err := mldsa87.Sign(mlPriv, msg, ctx, rand.Reader, mlSig[:]); err != nil {
		t.Fatalf("attacker ML-DSA-87 sign: %v", err)
	}

	slhPub, slhPriv, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHAKE_256s)
	if err != nil {
		t.Fatalf("attacker SLH-DSA keygen: %v", err)
	}
	slhPubBytes, err := slhPub.MarshalBinary()
	if err != nil {
		t.Fatalf("attacker SLH-DSA marshal: %v", err)
	}
	slhSig, err := slhdsa.SignRandomized(&slhPriv, rand.Reader, slhdsa.NewMessage(msg), ctx)
	if err != nil {
		t.Fatalf("attacker SLH-DSA sign: %v", err)
	}

	// Layout: id | msgLen | ed25519Sig | msg | mldsaSig | slhdsaSig
	forgedSig := make([]byte, 0, SigLength)
	forgedSig = append(forgedSig, ED25519_MLDSA5_SLHDSA5_FULL_ID, byte(CRYPTO_MSG_LENGTH))
	forgedSig = append(forgedSig, stolenEd25519Sig...)
	forgedSig = append(forgedSig, msg...)
	forgedSig = append(forgedSig, mlSig[:]...)
	forgedSig = append(forgedSig, slhSig...)
	if len(forgedSig) != SigLength {
		t.Fatalf("forged signature is %d bytes, want %d", len(forgedSig), SigLength)
	}

	victimPubBytes, err := victimPub.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal victim public key: %v", err)
	}
	forgedPubBytes := make([]byte, 0, PublicKeySize)
	forgedPubBytes = append(forgedPubBytes, victimPubBytes[:ed25519.PublicKeySize]...)
	forgedPubBytes = append(forgedPubBytes, mlPub.Bytes()...)
	forgedPubBytes = append(forgedPubBytes, slhPubBytes...)
	if len(forgedPubBytes) != PublicKeySize {
		t.Fatalf("forged public key is %d bytes, want %d", len(forgedPubBytes), PublicKeySize)
	}
	forgedPub, err := UnmarshalPublicKey(forgedPubBytes)
	if err != nil {
		t.Fatalf("forged composite public key rejected at unmarshal: %v", err)
	}

	got := Verify(forgedPub, msg, forgedSig)
	if got != wantForgeryAccepted {
		t.Errorf("Verify(forged) = %v, want %v", got, wantForgeryAccepted)
	}
}
