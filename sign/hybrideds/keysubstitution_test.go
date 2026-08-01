package hybrideds

// Demonstration of FINDING-001 for the legacy scheme, which realizes the NIST
// PQC Round 3 drafts: Ed25519 + Dilithium2 (CRYSTALS-Dilithium v3.1) +
// SPHINCS+-SHAKE-256f-simple (SPHINCS+ v3.1). The Go identifiers mldsa44 and
// slhdsa are reused as code via their Internal / NoContext entry points; the
// finalized ML-DSA-44 (FIPS 204) and SLH-DSA-SHAKE-256f (FIPS 205) appear only
// in the sibling packages.
//
// Full write-up, formal treatment and per-consumer applicability:
// audit/FINDING-001-key-substitution.md
//
// Full mode is the most exposed of the three siblings: it applies no domain
// separation whatsoever. All three components sign the raw 32-byte message with
// no context, no scheme identifier, and no public-key binding.
//
// Compact mode is PARTIALLY resistant, and the contrast is the most useful
// evidence in this finding -- see TestKeySubstitutionCompactMode below, which
// includes a control assertion showing that the one component that IS bound into
// the signed input cannot be substituted.
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
// belonging to the adversary. Planned hardening item, not an incident. This
// package is in any case legacy and frozen for backward compatibility; the
// realistic remediation is to bind the composite key in the ML-DSA/SLH-DSA
// schemes under new scheme identifiers and leave this one documented as-is.
//
// These are CHARACTERIZATION tests asserting today's behaviour, and TRIPWIRES
// that will fail once the composite key is bound in (BUFF transform). See the
// header of sign/hybridedmldsaslhdsa/keysubstitution_test.go for the full
// convention.

import (
	"crypto/rand"
	"crypto/sha3"
	"testing"

	"github.com/quantumcoinproject/circl/sign/ed25519"
	"github.com/quantumcoinproject/circl/sign/mldsa/mldsa44"
	"github.com/quantumcoinproject/circl/sign/slhdsa"
)

func edsTestMessage() []byte {
	msg := make([]byte, CRYPTO_MSG_LENGTH)
	for i := range msg {
		msg[i] = byte(i)
	}
	return msg
}

// TestKeySubstitutionFullMode demonstrates the attack against legacy FULL
// signatures.
//
// Full mode here uses SignNoContext / SignRandomizedNoContext, i.e. the raw
// message with no domain separation whatsoever. Every component signature is
// therefore a standalone signature over msg under its own component key, and any
// two of the three can be replaced with attacker-generated keys.
func TestKeySubstitutionFullMode(t *testing.T) {
	const wantForgeryAccepted = true // flip to false once FINDING-001 is fixed

	msg := edsTestMessage()

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

	stolenEd25519Sig := make([]byte, ED25519_SIG_LENGTH)
	copy(stolenEd25519Sig, victimSig[2:2+ED25519_SIG_LENGTH])

	// Attacker's own ML-DSA key. Note GenerateKeyInternal(_, false) matches what
	// this legacy scheme uses (pre-FIPS round-3 Dilithium keygen).
	mlPub, mlPriv, err := mldsa44.GenerateKeyInternal(rand.Reader, false)
	if err != nil {
		t.Fatalf("attacker ML-DSA keygen: %v", err)
	}
	var mlRnd [MLDSA44_SIG_RAND_LENGTH]byte
	if _, err := rand.Read(mlRnd[:]); err != nil {
		t.Fatalf("read randomness: %v", err)
	}
	mlSig := mldsa44.SignNoContext(mlPriv, msg, mlRnd)

	slhPub, slhPriv, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHAKE_256f)
	if err != nil {
		t.Fatalf("attacker SLH-DSA keygen: %v", err)
	}
	slhPubBytes, err := slhPub.MarshalBinary()
	if err != nil {
		t.Fatalf("attacker SLH-DSA marshal: %v", err)
	}
	slhSig, err := slhdsa.SignRandomizedNoContext(&slhPriv, rand.Reader, msg)
	if err != nil {
		t.Fatalf("attacker SLH-DSA sign: %v", err)
	}

	// Layout: id | msgLen | ed25519Sig | msg | mldsaSig | slhdsaSig
	forgedSig := make([]byte, 0, SigLength)
	forgedSig = append(forgedSig, DILITHIUM_ED25519_SPHINCS_FULL_ID, byte(CRYPTO_MSG_LENGTH))
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
	forgedPubBytes := make([]byte, 0, PublicKeySize)
	forgedPubBytes = append(forgedPubBytes, victimPubBytes[:ed25519.PublicKeySize]...)
	forgedPubBytes = append(forgedPubBytes, mlPub.Bytes()...)
	forgedPubBytes = append(forgedPubBytes, slhPubBytes...)
	forgedPub, err := UnmarshalPublicKey(forgedPubBytes)
	if err != nil {
		t.Fatalf("forged composite public key rejected at unmarshal: %v", err)
	}

	got := Verify(forgedPub, msg, forgedSig)
	if got != wantForgeryAccepted {
		t.Errorf("Verify(forged) = %v, want %v", got, wantForgeryAccepted)
	}
}

// TestKeySubstitutionCompactMode shows that legacy COMPACT mode is PARTIALLY
// resistant, and exactly how far that partial protection goes.
//
// Compact mode does not sign msg directly. Both components sign
//
//	hybridMsgHash = SHA3-512(nonce || msg || slhdsaPubKey)
//
// so mu_1 and mu_2 both depend on pk_3. The verification predicate therefore
// does NOT factorise with respect to the third component: substituting pk_3
// changes what sigma_1 and sigma_2 were computed over, and both fail. The
// control assertion at the end of this test confirms that rejection.
//
// This is exactly the mitigation FINDING-001 recommends -- binding a public key
// into the signed input -- applied to one component instead of all three.
//
// The binding is incomplete: pk_2 is committed to nowhere, so the predicate
// still factorises with respect to the ML-DSA component. The adversary can
// substitute that half and obtain a composite key
// (pk_1_victim || pk_2_adversary || pk_3_victim) that verifies the victim's
// message. Partial binding yields exactly partial protection, which is the
// argument for binding all of pk.
func TestKeySubstitutionCompactMode(t *testing.T) {
	const wantForgeryAccepted = true // flip to false once FINDING-001 is fixed

	msg := edsTestMessage()

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

	// Reuse the victim's Ed25519 signature AND the victim's nonce, because both
	// feed the hash the Ed25519 component actually signed.
	// Layout: id | msgLen | ed25519Sig | mldsaSig | nonce | msg
	const nonceOff = 2 + ED25519_SIG_LENGTH + MLDSA44_SIG_LENGTH
	stolenEd25519Sig := make([]byte, ED25519_SIG_LENGTH)
	copy(stolenEd25519Sig, victimSig[2:2+ED25519_SIG_LENGTH])
	stolenNonce := make([]byte, NonceSize)
	copy(stolenNonce, victimSig[nonceOff:nonceOff+NonceSize])

	// The attacker must keep the victim's SLH-DSA public key: it is inside the
	// signed hash. Only the ML-DSA half is substitutable.
	victimPubBytes, err := victimPub.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal victim public key: %v", err)
	}
	victimSlhPubBytes := victimPubBytes[ed25519.PublicKeySize+mldsa44.PublicKeySize:]

	// Recompute the hash the victim's Ed25519 component signed, so the attacker's
	// ML-DSA signature covers the same value.
	hybridMsg := make([]byte, 0, NonceSize+CRYPTO_MSG_LENGTH+SlhDsaPublicKeySize)
	hybridMsg = append(hybridMsg, stolenNonce...)
	hybridMsg = append(hybridMsg, msg...)
	hybridMsg = append(hybridMsg, victimSlhPubBytes...)
	hasher := sha3.New512()
	if _, err := hasher.Write(hybridMsg); err != nil {
		t.Fatalf("hash hybrid message: %v", err)
	}
	hybridMsgHash := hasher.Sum(nil)

	mlPub, mlPriv, err := mldsa44.GenerateKeyInternal(rand.Reader, false)
	if err != nil {
		t.Fatalf("attacker ML-DSA keygen: %v", err)
	}
	var mlRnd [MLDSA44_SIG_RAND_LENGTH]byte
	if _, err := rand.Read(mlRnd[:]); err != nil {
		t.Fatalf("read randomness: %v", err)
	}
	mlSig := mldsa44.SignNoContext(mlPriv, hybridMsgHash, mlRnd)

	forgedSig := make([]byte, 0, CompactSigLength)
	forgedSig = append(forgedSig, DILITHIUM_ED25519_SPHINCS_COMPACT_ID, byte(CRYPTO_MSG_LENGTH))
	forgedSig = append(forgedSig, stolenEd25519Sig...)
	forgedSig = append(forgedSig, mlSig...)
	forgedSig = append(forgedSig, stolenNonce...)
	forgedSig = append(forgedSig, msg...)
	if len(forgedSig) != CompactSigLength {
		t.Fatalf("forged compact signature is %d bytes, want %d", len(forgedSig), CompactSigLength)
	}

	forgedPubBytes := make([]byte, 0, PublicKeySize)
	forgedPubBytes = append(forgedPubBytes, victimPubBytes[:ed25519.PublicKeySize]...)
	forgedPubBytes = append(forgedPubBytes, mlPub.Bytes()...)
	forgedPubBytes = append(forgedPubBytes, victimSlhPubBytes...)
	forgedPub, err := UnmarshalPublicKey(forgedPubBytes)
	if err != nil {
		t.Fatalf("forged composite public key rejected at unmarshal: %v", err)
	}

	got := VerifyCompact(forgedPub, msg, forgedSig)
	if got != wantForgeryAccepted {
		t.Errorf("VerifyCompact(forged, ML-DSA half substituted) = %v, want %v",
			got, wantForgeryAccepted)
	}

	// Control: substituting the SLH-DSA half instead MUST fail, because that half
	// is committed to inside the hash the Ed25519 component signed. This is the
	// positive evidence that public-key binding is what stops the attack.
	otherSlhPub, _, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHAKE_256f)
	if err != nil {
		t.Fatalf("attacker second SLH-DSA keygen: %v", err)
	}
	otherSlhPubBytes, err := otherSlhPub.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal second SLH-DSA public key: %v", err)
	}
	swappedPubBytes := make([]byte, 0, PublicKeySize)
	swappedPubBytes = append(swappedPubBytes, victimPubBytes[:ed25519.PublicKeySize]...)
	swappedPubBytes = append(swappedPubBytes, mlPub.Bytes()...)
	swappedPubBytes = append(swappedPubBytes, otherSlhPubBytes...)
	swappedPub, err := UnmarshalPublicKey(swappedPubBytes)
	if err != nil {
		t.Fatalf("unmarshal swapped public key: %v", err)
	}
	if VerifyCompact(swappedPub, msg, forgedSig) {
		t.Error("substituting the SLH-DSA half was accepted; the hash binding that " +
			"makes compact mode partially resistant has been lost")
	}
}
