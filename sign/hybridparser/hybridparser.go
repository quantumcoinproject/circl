// Package hybridparser provides verification and parsing of hybrid signatures
// for audit, security research, and developer understanding only.
//
// PURPOSE (AUDIT AND UNDERSTANDING ONLY)
//
// This package is intended for:
//   - Auditors and security researchers: to obtain a per-component breakdown of
//     hybrid signatures and to verify that each component is validated in line
//     with the relevant standardization specifications.
//   - AI systems and developers: to inspect and reason about hybrid signature
//     structure (message, component public keys, and component signatures)
//     without relying on production verification paths.
//
// This code must NOT be used for any production use case. It is provided solely
// to support auditing and to help understand hybrid signature composition.
// Production verification MUST use the hybrid scheme APIs directly (e.g.
// hybrideds.Verify, hybridedmldsaslhdsa.Verify, etc.).
//
// NIST AND STANDARDS ALIGNMENT
//
// Component verification in this package aligns with the following specifications
// for post-quantum and classical schemes:
//
//   - ML-DSA: FIPS 204, Module-Lattice-Based Digital Signature Standard (NIST finalized).
//     https://doi.org/10.6028/NIST.FIPS.204
//     Applies to hybrid schemes 3, 4, 5.
//   - SLH-DSA: FIPS 205, Stateless Hash-Based Digital Signature Standard (NIST finalized).
//     https://doi.org/10.6028/NIST.FIPS.205
//     Applies to hybrid schemes 3, 4, 5.
//   - Ed25519 (EdDSA): FIPS 186-5, Digital Signature Standard (DSS).
//     https://csrc.nist.gov/pubs/fips/186-5/final
//     Applies to hybrid schemes 3, 4, 5.
//
//   The HybridEds package (SchemeID 1 and 2) uses Dilithium and SPHINCS+, which are
//   based on the pre-final draft standards; implementations may differ slightly from
//   finalized ML-DSA and SLH-DSA.
//
// HOW TO USE ParseHybrid FOR INDEPENDENT AUDIT AND VALIDATION
//
// AI and human auditors, security professionals, and engineers can use ParseHybrid
// to obtain a component-level breakdown and then verify each component with their
// own tooling or reference implementations:
//
//  1. Call ParseHybrid(signature, publicKey, message) with the raw hybrid signature,
//     hybrid public key, and message bytes. On success you receive a *HybridSignature.
//
//  2. All component data in HybridSignature is hex-encoded. Decode to []byte for
//     use with other libraries:
//
//       msg, _ := hex.DecodeString(parsed.Message)
//       ed25519Pub, _ := hex.DecodeString(parsed.PublicKeys[hybridparser.ComponentEd25519])
//       ed25519Sig, _ := hex.DecodeString(parsed.Signatures[hybridparser.ComponentEd25519])
//       // Similarly for ComponentDilithium, ComponentSphincsSHAKE256f, ComponentMLDSA44,
//       // ComponentMLDSA87, ComponentSLHDSA_SHAKE256f, ComponentSLHDSA_SHAKE256s as applicable.
//
//  3. Use parsed.SchemeID (1–5) to determine which components are present and which
//     parameter set each uses (e.g. ML-DSA-44 vs ML-DSA-87, SLH-DSA SHAKE-256f vs SHAKE-256s).
//
//  4. Pass the decoded message, public key, and signature for each component to an
//     independent implementation of that algorithm—e.g. PQClean, liboqs, or another
//     language’s native library—and run that implementation’s verify function. This
//     allows you to:
//     - Cross-check results against multiple implementations.
//     - Validate behavior against NIST FIPS 204, FIPS 205, FIPS 186-5, or draft
//       specifications as appropriate for the scheme.
//     - Perform differential testing or conformance audits without relying solely
//       on this codebase’s verifiers.
//
//  5. For scheme 1 (compact), the value actually signed by the Ed25519 and Dilithium
//     components is SHA3-512(nonce || message || SPHINCS+ public key). Use parsed.AdditionalData["Scheme1Nonce"]
//     (hex) and the SPHINCS+ public key from parsed.PublicKeys to reconstruct that
//     digest when verifying those two components with external implementations.
//
// The ParseHybrid and CheckHybrid functions call the same underlying component
// verifiers (ed25519.Verify, mldsa44.Verify/VerifyNoContext, mldsa87.Verify,
// slhdsa.Verify/VerifyNoContext) that the production hybrid schemes use, so
// audit checks match the same NIST (and RFC) behavior as production.
//
// The top-level sign package cannot re-export this API due to import cycles
// with ed25519; use this package directly for audit tooling.
package hybridparser

import (
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/quantumcoinproject/circl/sign/ed25519"
	"github.com/quantumcoinproject/circl/sign/hybrideds"
	"github.com/quantumcoinproject/circl/sign/hybridedmldsaslhdsa"
	"github.com/quantumcoinproject/circl/sign/hybridedmldsaslhdsa5"
	"github.com/quantumcoinproject/circl/sign/mldsa/mldsa44"
	"github.com/quantumcoinproject/circl/sign/mldsa/mldsa87"
	"github.com/quantumcoinproject/circl/sign/slhdsa"
)

// ErrNotHybrid is returned by ParseHybrid when the signature's first byte is not
// a supported hybrid scheme ID (1-5). Used only in audit/tooling code.
var ErrNotHybrid = errors.New("hybridparser: not a supported hybrid signature type")

// ErrVerificationFailed is returned when hybrid or component signature verification
// fails in ParseHybrid or CheckHybrid. Used only in audit/tooling code.
var ErrVerificationFailed = errors.New("hybridparser: hybrid signature verification failed")

// Component name constants for the PublicKeys and Signatures maps in HybridSignature.
// Use these when reading or writing parsed component data for audit tooling.
//
// The names are spelled as the standard that defines each algorithm spells
// them, so that anything quoting them -- an explorer, a CLI, an audit report --
// matches the specification a reader would look it up in:
//
//	ML-DSA-44, ML-DSA-87           FIPS 204, which names parameter sets ML-DSA-{44,65,87}
//	SLH-DSA-SHAKE-256{f,s}         FIPS 205, SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f}
//	Ed25519                        RFC 8032 (capital E, lowercase d)
//	SPHINCS+-SHAKE-256f            the SPHINCS+ submission
//	Dilithium                      CRYSTALS-Dilithium, the pre-standardisation name
//
// These strings appear in SchemeName and as map keys, so changing them is a
// visible API change for callers that match on the text.
const (
	ComponentEd25519          = "Ed25519"
	ComponentDilithium        = "Dilithium"
	ComponentSphincsSHAKE256f = "SPHINCS+-SHAKE-256f"
	ComponentMLDSA44          = "ML-DSA-44"
	ComponentMLDSA87          = "ML-DSA-87"
	ComponentSLHDSA_SHAKE256f = "SLH-DSA-SHAKE-256f"
	ComponentSLHDSA_SHAKE256s = "SLH-DSA-SHAKE-256s"
)

// Keys for the AdditionalData map (scheme 1 only). Use when reading or writing
// scheme-1-specific fields for audit tooling.
const (
	AdditionalDataScheme1Nonce  = "Scheme1Nonce"
	AdditionalDataScheme1Mu     = "Scheme1Mu"
	AdditionalDataScheme1Digest = "Scheme1Digest"
)

// HybridSignature holds the result of verifying and parsing a hybrid signature,
// for audit and understanding only (see package documentation).
//
// All string fields are hex-encoded. Use the Component* constants as keys when
// reading from PublicKeys and Signatures. This struct is not for production use;
// it exists to support inspection and NIST-aligned component verification during
// audits.
type HybridSignature struct {
	// SchemeID is the hybrid scheme identifier from the first byte of the raw signature.
	// It identifies which hybrid construction was used and how to interpret the components:
	//   - 1: hybrideds compact  (Ed25519 + Dilithium; SPHINCS+ key present but not signed in compact)
	//   - 2: hybrideds full    (Ed25519 + Dilithium + SPHINCS+ SHAKE-256f)
	//   - 3: hybrid Ed25519-ML-DSA-SLH-DSA compact (Ed25519 + ML-DSA-44; SLH-DSA SHAKE-256f key present)
	//   - 4: hybrid Ed25519-ML-DSA-SLH-DSA full   (Ed25519 + ML-DSA-44 + SLH-DSA SHAKE-256f)
	//   - 5: hybrid Ed25519-ML-DSA87-SLH-DSA5 full (Ed25519 + ML-DSA-87 + SLH-DSA SHAKE-256s)
	// Use this field in audit logic to dispatch to the correct NIST/FIPS component checks.
	SchemeID byte

	// SchemeName is the component names in order (mldsa, slhdsa, ed25519), separated by " + ".
	// For older schemes (1 and 2), Dilithium and SPHINCS+ names are used respectively.
	SchemeName string

	// Context is the hex-encoded context string used during verification.
	// For ML-DSA and SLH-DSA components, this is the context parameter.
	Context string

	// AdditionalData holds scheme-specific extra fields. For scheme 1 (compact) only,
	// it contains keys Scheme1Nonce, Scheme1Mu, and Scheme1Digest (use AdditionalData*
	// constants). Nil or empty for all other schemes.
	AdditionalData map[string]string

	// Message is the hex-encoded message that was signed (common to all components).
	// For scheme 1 (compact), the value signed by Ed25519 and Dilithium is
	// SHA3-512(nonce||message||SPHINCS+ public key); this field holds the original message.
	Message string

	// PublicKeys maps component name (use Component* constants) to hex-encoded
	// public key bytes for that component. Enables per-component audit and
	// re-verification against FIPS 204 / FIPS 205 / FIPS 186-5 as applicable.
	PublicKeys map[string]string

	// Signatures maps component name (use Component* constants) to hex-encoded
	// signature bytes. Compact schemes (1 and 3) have two entries; full schemes
	// have three. Enables audit of each component signature in isolation.
	Signatures map[string]string

}

const (
	ed25519PubSize = 32
	ed25519SigSize = 64
)

// ParseHybrid verifies the hybrid signature with the given public key and message,
// then extracts per-component public keys and signatures for audit and understanding.
//
// This function is for audit and tooling only; do not use in production. The message
// is provided explicitly by the caller and is passed to the underlying verify function.
// Returns an error if the signature type is not a supported hybrid (first byte not
// in {1,2,3,4,5}), or if verification fails.
func ParseHybrid(signature, publicKey, message []byte) (*HybridSignature, error) {
	if len(signature) < 1 {
		return nil, fmt.Errorf("hybridparser: signature too short")
	}
	id := signature[0]
	switch id {
	case hybrideds.DILITHIUM_ED25519_SPHINCS_COMPACT_ID:
		return parseHybridEDSCompact(signature, publicKey, message)
	case hybrideds.DILITHIUM_ED25519_SPHINCS_FULL_ID:
		return parseHybridEDSFull(signature, publicKey, message)
	case hybridedmldsaslhdsa.ED25519_MLDSA_SLHDSA_COMPACT_ID:
		return parseHybridEDMLDSACompact(signature, publicKey, message)
	case hybridedmldsaslhdsa.ED25519_MLDSA_SLHDSA_FULL_ID:
		return parseHybridEDMLDSAFull(signature, publicKey, message)
	case hybridedmldsaslhdsa5.ED25519_MLDSA5_SLHDSA5_FULL_ID:
		return parseHybridEDMLDSA5Full(signature, publicKey, message)
	default:
		return nil, ErrNotHybrid
	}
}

func parseHybridEDSCompact(signature, publicKey, message []byte) (*HybridSignature, error) {
	pk, err := hybrideds.UnmarshalPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	if !hybrideds.VerifyCompact(pk, message, signature) {
		return nil, ErrVerificationFailed
	}
	out := &HybridSignature{
		SchemeID:    signature[0],
		SchemeName:  strings.Join([]string{ComponentDilithium, ComponentSphincsSHAKE256f, ComponentEd25519}, " + ") + " (compact)",
		Message:     hex.EncodeToString(message),
		PublicKeys:  make(map[string]string),
		Signatures:  make(map[string]string),
	}
	out.PublicKeys[ComponentEd25519] = hex.EncodeToString(publicKey[0:ed25519PubSize])
	out.PublicKeys[ComponentDilithium] = hex.EncodeToString(publicKey[ed25519PubSize : ed25519PubSize+mldsa44.PublicKeySize])
	sphPub := publicKey[ed25519PubSize+mldsa44.PublicKeySize:]
	out.PublicKeys[ComponentSphincsSHAKE256f] = hex.EncodeToString(sphPub)
	out.Signatures[ComponentEd25519] = hex.EncodeToString(signature[2 : 2+ed25519SigSize])
	out.Signatures[ComponentDilithium] = hex.EncodeToString(signature[2+ed25519SigSize : 2+ed25519SigSize+hybrideds.MLDSA44_SIG_LENGTH])
	nonceOff := 2 + ed25519SigSize + hybrideds.MLDSA44_SIG_LENGTH
	nonce := signature[nonceOff : nonceOff+hybrideds.NonceSize]

	// In scheme 1 (compact), the value signed by components is the digest SHA3-512(μ), where μ = nonce||message||SPHINCS+ public key.
	hybridMsg := make([]byte, 0, hybrideds.NonceSize+len(message)+len(sphPub))
	hybridMsg = append(hybridMsg, nonce...)
	hybridMsg = append(hybridMsg, message...)
	hybridMsg = append(hybridMsg, sphPub...)
	hasher := sha3.New512()
	_, _ = hasher.Write(hybridMsg)
	digest := hasher.Sum(nil)

	out.AdditionalData = map[string]string{
		AdditionalDataScheme1Nonce:  hex.EncodeToString(nonce),
		AdditionalDataScheme1Mu:     hex.EncodeToString(hybridMsg),
		AdditionalDataScheme1Digest: hex.EncodeToString(digest),
	}
	return out, nil
}

func parseHybridEDSFull(signature, publicKey, message []byte) (*HybridSignature, error) {
	pk, err := hybrideds.UnmarshalPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	if !hybrideds.Verify(pk, message, signature) {
		return nil, ErrVerificationFailed
	}
	msgLen := len(message)
	out := &HybridSignature{
		SchemeID:    signature[0],
		SchemeName: strings.Join([]string{ComponentDilithium, ComponentSphincsSHAKE256f, ComponentEd25519}, " + "),
		Message:     hex.EncodeToString(message),
		PublicKeys:  make(map[string]string),
		Signatures:  make(map[string]string),
	}
	out.PublicKeys[ComponentEd25519] = hex.EncodeToString(publicKey[0:ed25519PubSize])
	out.PublicKeys[ComponentDilithium] = hex.EncodeToString(publicKey[ed25519PubSize : ed25519PubSize+mldsa44.PublicKeySize])
	out.PublicKeys[ComponentSphincsSHAKE256f] = hex.EncodeToString(publicKey[ed25519PubSize+mldsa44.PublicKeySize:])
	out.Signatures[ComponentEd25519] = hex.EncodeToString(signature[2 : 2+ed25519SigSize])
	out.Signatures[ComponentDilithium] = hex.EncodeToString(signature[2+ed25519SigSize+msgLen : 2+ed25519SigSize+msgLen+hybrideds.MLDSA44_SIG_LENGTH])
	out.Signatures[ComponentSphincsSHAKE256f] = hex.EncodeToString(signature[2+ed25519SigSize+msgLen+hybrideds.MLDSA44_SIG_LENGTH:])
	return out, nil
}

func parseHybridEDMLDSACompact(signature, publicKey, message []byte) (*HybridSignature, error) {
	pk, err := hybridedmldsaslhdsa.UnmarshalPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	if !hybridedmldsaslhdsa.VerifyCompact(pk, message, signature) {
		return nil, ErrVerificationFailed
	}
	slhPub := publicKey[ed25519PubSize+mldsa44.PublicKeySize:]
	out := &HybridSignature{
		SchemeID:    signature[0],
		SchemeName:  strings.Join([]string{ComponentMLDSA44, ComponentSLHDSA_SHAKE256f, ComponentEd25519}, " + ") + " (compact)",
		Message:     hex.EncodeToString(message),
		PublicKeys:  make(map[string]string),
		Signatures:  make(map[string]string),
	}
	out.PublicKeys[ComponentEd25519] = hex.EncodeToString(publicKey[0:ed25519PubSize])
	out.PublicKeys[ComponentMLDSA44] = hex.EncodeToString(publicKey[ed25519PubSize : ed25519PubSize+mldsa44.PublicKeySize])
	out.PublicKeys[ComponentSLHDSA_SHAKE256f] = hex.EncodeToString(slhPub)
	out.Signatures[ComponentEd25519] = hex.EncodeToString(signature[2 : 2+ed25519SigSize])
	out.Signatures[ComponentMLDSA44] = hex.EncodeToString(signature[2+ed25519SigSize : 2+ed25519SigSize+mldsa44.SignatureSize])

	// In compact scheme 3, the ML-DSA context is SchemeID (3) + SLH-DSA public key.
	context := make([]byte, 1+len(slhPub))
	context[0] = signature[0]
	copy(context[1:], slhPub)
	out.Context = hex.EncodeToString(context)

	return out, nil
}

func parseHybridEDMLDSAFull(signature, publicKey, message []byte) (*HybridSignature, error) {
	pk, err := hybridedmldsaslhdsa.UnmarshalPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	if !hybridedmldsaslhdsa.Verify(pk, message, signature) {
		return nil, ErrVerificationFailed
	}
	msgLen := len(message)
	out := &HybridSignature{
		SchemeID:    signature[0],
		SchemeName: strings.Join([]string{ComponentMLDSA44, ComponentSLHDSA_SHAKE256f, ComponentEd25519}, " + "),
		Message:     hex.EncodeToString(message),
		PublicKeys:  make(map[string]string),
		Signatures:  make(map[string]string),
	}
	out.PublicKeys[ComponentEd25519] = hex.EncodeToString(publicKey[0:ed25519PubSize])
	out.PublicKeys[ComponentMLDSA44] = hex.EncodeToString(publicKey[ed25519PubSize : ed25519PubSize+mldsa44.PublicKeySize])
	out.PublicKeys[ComponentSLHDSA_SHAKE256f] = hex.EncodeToString(publicKey[ed25519PubSize+mldsa44.PublicKeySize:])
	out.Signatures[ComponentEd25519] = hex.EncodeToString(signature[2 : 2+ed25519SigSize])
	out.Signatures[ComponentMLDSA44] = hex.EncodeToString(signature[2+ed25519SigSize+msgLen : 2+ed25519SigSize+msgLen+mldsa44.SignatureSize])
	out.Signatures[ComponentSLHDSA_SHAKE256f] = hex.EncodeToString(signature[2+ed25519SigSize+msgLen+mldsa44.SignatureSize:])

	// In full scheme 4, the context is just the SchemeID (4).
	out.Context = hex.EncodeToString([]byte{signature[0]})

	return out, nil
}

func parseHybridEDMLDSA5Full(signature, publicKey, message []byte) (*HybridSignature, error) {
	pk, err := hybridedmldsaslhdsa5.UnmarshalPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	if !hybridedmldsaslhdsa5.Verify(pk, message, signature) {
		return nil, ErrVerificationFailed
	}
	msgLen := len(message)
	out := &HybridSignature{
		SchemeID:    signature[0],
		SchemeName: strings.Join([]string{ComponentMLDSA87, ComponentSLHDSA_SHAKE256s, ComponentEd25519}, " + "),
		Message:     hex.EncodeToString(message),
		PublicKeys:  make(map[string]string),
		Signatures:  make(map[string]string),
	}
	out.PublicKeys[ComponentEd25519] = hex.EncodeToString(publicKey[0:ed25519PubSize])
	out.PublicKeys[ComponentMLDSA87] = hex.EncodeToString(publicKey[ed25519PubSize : ed25519PubSize+mldsa87.PublicKeySize])
	out.PublicKeys[ComponentSLHDSA_SHAKE256s] = hex.EncodeToString(publicKey[ed25519PubSize+mldsa87.PublicKeySize:])
	out.Signatures[ComponentEd25519] = hex.EncodeToString(signature[2 : 2+ed25519SigSize])
	out.Signatures[ComponentMLDSA87] = hex.EncodeToString(signature[2+ed25519SigSize+msgLen : 2+ed25519SigSize+msgLen+mldsa87.SignatureSize])
	out.Signatures[ComponentSLHDSA_SHAKE256s] = hex.EncodeToString(signature[2+ed25519SigSize+msgLen+mldsa87.SignatureSize:])

	// In full scheme 5, the context is just the SchemeID (5).
	out.Context = hex.EncodeToString([]byte{signature[0]})

	return out, nil
}

// getHex decodes a hex string from the map and returns the bytes, or error if missing/invalid.
func getHex(m map[string]string, key string) ([]byte, error) {
	s, ok := m[key]
	if !ok || s == "" {
		return nil, fmt.Errorf("hybridparser: missing or empty component %q", key)
	}
	return hex.DecodeString(s)
}

// CheckHybrid reconstructs the signature and public key from h, then runs the
// hybrid scheme's Verify (or VerifyCompact for compact schemes) and each
// component's verify (ed25519, ML-DSA, SLH-DSA) so auditors can confirm alignment
// with NIST FIPS 204, FIPS 205, and FIPS 186-5.
//
// For audit use only; do not use in production. Returns nil if all verifications
// succeed, or ErrVerificationFailed (or another error) otherwise.
func CheckHybrid(h *HybridSignature) error {
	if h == nil || h.PublicKeys == nil || h.Signatures == nil {
		return fmt.Errorf("hybridparser: nil HybridSignature or maps")
	}
	msg, err := hex.DecodeString(h.Message)
	if err != nil || len(msg) == 0 {
		return fmt.Errorf("hybridparser: invalid or empty message")
	}
	if len(msg) > hybrideds.CRYPTO_MSG_LENGTH {
		return fmt.Errorf("hybridparser: message too long")
	}
	msgLen := byte(len(msg))

	switch h.SchemeID {
	case hybrideds.DILITHIUM_ED25519_SPHINCS_COMPACT_ID:
		return checkHybridEDSCompact(h, msg, msgLen)
	case hybrideds.DILITHIUM_ED25519_SPHINCS_FULL_ID:
		return checkHybridEDSFull(h, msg, msgLen)
	case hybridedmldsaslhdsa.ED25519_MLDSA_SLHDSA_COMPACT_ID:
		return checkHybridEDMLDSACompact(h, msg, msgLen)
	case hybridedmldsaslhdsa.ED25519_MLDSA_SLHDSA_FULL_ID:
		return checkHybridEDMLDSAFull(h, msg, msgLen)
	case hybridedmldsaslhdsa5.ED25519_MLDSA5_SLHDSA5_FULL_ID:
		return checkHybridEDMLDSA5Full(h, msg, msgLen)
	default:
		return ErrNotHybrid
	}
}

func checkHybridEDSCompact(h *HybridSignature, msg []byte, msgLen byte) error {
	edPub, err := getHex(h.PublicKeys, ComponentEd25519)
	if err != nil {
		return err
	}
	dilPub, err := getHex(h.PublicKeys, ComponentDilithium)
	if err != nil {
		return err
	}
	sphPub, err := getHex(h.PublicKeys, ComponentSphincsSHAKE256f)
	if err != nil {
		return err
	}
	edSig, err := getHex(h.Signatures, ComponentEd25519)
	if err != nil {
		return err
	}
	dilSig, err := getHex(h.Signatures, ComponentDilithium)
	if err != nil {
		return err
	}
	if h.AdditionalData == nil {
		return fmt.Errorf("hybridparser: missing AdditionalData for scheme 1")
	}
	nonce, err := getHex(h.AdditionalData, AdditionalDataScheme1Nonce)
	if err != nil {
		return err
	}
	if len(nonce) != hybrideds.NonceSize {
		return fmt.Errorf("hybridparser: invalid nonce length for scheme 1")
	}
	pubKey := make([]byte, 0, len(edPub)+len(dilPub)+len(sphPub))
	pubKey = append(pubKey, edPub...)
	pubKey = append(pubKey, dilPub...)
	pubKey = append(pubKey, sphPub...)
	sig := make([]byte, 0, 2+len(edSig)+len(dilSig)+len(nonce)+len(msg))
	sig = append(sig, h.SchemeID, msgLen)
	sig = append(sig, edSig...)
	sig = append(sig, dilSig...)
	sig = append(sig, nonce...)
	sig = append(sig, msg...)
	pk, err := hybrideds.UnmarshalPublicKey(pubKey)
	if err != nil {
		return err
	}
	if !hybrideds.VerifyCompact(pk, msg, sig) {
		return ErrVerificationFailed
	}
	// Verify each component individually (ed25519 and Dilithium sign hybridMsgHash in compact).
	hybridMsg := make([]byte, 0, hybrideds.NonceSize+len(msg)+len(sphPub))
	hybridMsg = append(hybridMsg, nonce...)
	hybridMsg = append(hybridMsg, msg...)
	hybridMsg = append(hybridMsg, sphPub...)
	if h.AdditionalData[AdditionalDataScheme1Mu] != hex.EncodeToString(hybridMsg) {
		return fmt.Errorf("hybridparser: AdditionalData[Scheme1Mu] does not match expected (Scheme1Nonce||message||SPHINCS+ public key)")
	}
	hasher := sha3.New512()
	_, _ = hasher.Write(hybridMsg)
	hybridMsgHash := hasher.Sum(nil)
	if h.AdditionalData[AdditionalDataScheme1Digest] != hex.EncodeToString(hybridMsgHash) {
		return fmt.Errorf("hybridparser: AdditionalData[Scheme1Digest] does not match SHA3-512(μ)")
	}
	edPk, err := ed25519.UnmarshalPublicKey(edPub)
	if err != nil {
		return err
	}
	if !ed25519.Verify(*edPk, hybridMsgHash, edSig) {
		return ErrVerificationFailed
	}
	dilPk, err := mldsa44.UnmarshalPublicKey(dilPub)
	if err != nil {
		return err
	}
	if !mldsa44.VerifyNoContext(dilPk, hybridMsgHash, dilSig) {
		return ErrVerificationFailed
	}
	return nil
}

func checkHybridEDSFull(h *HybridSignature, msg []byte, msgLen byte) error {
	edPub, err := getHex(h.PublicKeys, ComponentEd25519)
	if err != nil {
		return err
	}
	dilPub, err := getHex(h.PublicKeys, ComponentDilithium)
	if err != nil {
		return err
	}
	sphPub, err := getHex(h.PublicKeys, ComponentSphincsSHAKE256f)
	if err != nil {
		return err
	}
	edSig, err := getHex(h.Signatures, ComponentEd25519)
	if err != nil {
		return err
	}
	dilSig, err := getHex(h.Signatures, ComponentDilithium)
	if err != nil {
		return err
	}
	sphSig, err := getHex(h.Signatures, ComponentSphincsSHAKE256f)
	if err != nil {
		return err
	}
	pubKey := make([]byte, 0, len(edPub)+len(dilPub)+len(sphPub))
	pubKey = append(pubKey, edPub...)
	pubKey = append(pubKey, dilPub...)
	pubKey = append(pubKey, sphPub...)
	sig := make([]byte, 0, 2+len(edSig)+int(msgLen)+len(dilSig)+len(sphSig))
	sig = append(sig, h.SchemeID, msgLen)
	sig = append(sig, edSig...)
	sig = append(sig, msg...)
	sig = append(sig, dilSig...)
	sig = append(sig, sphSig...)
	pk, err := hybrideds.UnmarshalPublicKey(pubKey)
	if err != nil {
		return err
	}
	if !hybrideds.Verify(pk, msg, sig) {
		return ErrVerificationFailed
	}
	// Verify each component individually.
	edPk, err := ed25519.UnmarshalPublicKey(edPub)
	if err != nil {
		return err
	}
	if !ed25519.Verify(*edPk, msg, edSig) {
		return ErrVerificationFailed
	}
	dilPk, err := mldsa44.UnmarshalPublicKey(dilPub)
	if err != nil {
		return err
	}
	if !mldsa44.VerifyNoContext(dilPk, msg, dilSig) {
		return ErrVerificationFailed
	}
	var sphPk slhdsa.PublicKey
	sphPk.ID = slhdsa.SHAKE_256f
	if err := sphPk.UnmarshalBinary(sphPub); err != nil {
		return err
	}
	if !slhdsa.VerifyNoContext(&sphPk, msg, sphSig) {
		return ErrVerificationFailed
	}
	return nil
}

func checkHybridEDMLDSACompact(h *HybridSignature, msg []byte, msgLen byte) error {
	edPub, err := getHex(h.PublicKeys, ComponentEd25519)
	if err != nil {
		return err
	}
	mldsaPub, err := getHex(h.PublicKeys, ComponentMLDSA44)
	if err != nil {
		return err
	}
	slhPub, err := getHex(h.PublicKeys, ComponentSLHDSA_SHAKE256f)
	if err != nil {
		return err
	}
	edSig, err := getHex(h.Signatures, ComponentEd25519)
	if err != nil {
		return err
	}
	mldsaSig, err := getHex(h.Signatures, ComponentMLDSA44)
	if err != nil {
		return err
	}
	pubKey := make([]byte, 0, len(edPub)+len(mldsaPub)+len(slhPub))
	pubKey = append(pubKey, edPub...)
	pubKey = append(pubKey, mldsaPub...)
	pubKey = append(pubKey, slhPub...)
	sig := make([]byte, 0, 2+len(edSig)+len(mldsaSig)+len(msg))
	sig = append(sig, h.SchemeID, msgLen)
	sig = append(sig, edSig...)
	sig = append(sig, mldsaSig...)
	sig = append(sig, msg...)
	pk, err := hybridedmldsaslhdsa.UnmarshalPublicKey(pubKey)
	if err != nil {
		return err
	}
	if !hybridedmldsaslhdsa.VerifyCompact(pk, msg, sig) {
		return ErrVerificationFailed
	}
	// Verify each component individually (ML-DSA uses context = id + slhdsa pub in compact).
	edPk, err := ed25519.UnmarshalPublicKey(edPub)
	if err != nil {
		return err
	}
	if !ed25519.Verify(*edPk, msg, edSig) {
		return ErrVerificationFailed
	}
	mldsaPk, err := mldsa44.UnmarshalPublicKey(mldsaPub)
	if err != nil {
		return err
	}
	context := make([]byte, 1+len(slhPub))
	context[0] = hybridedmldsaslhdsa.ED25519_MLDSA_SLHDSA_COMPACT_ID
	copy(context[1:], slhPub)
	if h.Context != hex.EncodeToString(context) {
		return fmt.Errorf("hybridparser: Context does not match expected (SchemeID || SLH-DSA public key)")
	}
	if !mldsa44.Verify(mldsaPk, msg, context, mldsaSig) {
		return ErrVerificationFailed
	}
	return nil
}

func checkHybridEDMLDSAFull(h *HybridSignature, msg []byte, msgLen byte) error {
	edPub, err := getHex(h.PublicKeys, ComponentEd25519)
	if err != nil {
		return err
	}
	mldsaPub, err := getHex(h.PublicKeys, ComponentMLDSA44)
	if err != nil {
		return err
	}
	slhPub, err := getHex(h.PublicKeys, ComponentSLHDSA_SHAKE256f)
	if err != nil {
		return err
	}
	edSig, err := getHex(h.Signatures, ComponentEd25519)
	if err != nil {
		return err
	}
	mldsaSig, err := getHex(h.Signatures, ComponentMLDSA44)
	if err != nil {
		return err
	}
	slhSig, err := getHex(h.Signatures, ComponentSLHDSA_SHAKE256f)
	if err != nil {
		return err
	}
	pubKey := make([]byte, 0, len(edPub)+len(mldsaPub)+len(slhPub))
	pubKey = append(pubKey, edPub...)
	pubKey = append(pubKey, mldsaPub...)
	pubKey = append(pubKey, slhPub...)
	sig := make([]byte, 0, 2+len(edSig)+int(msgLen)+len(mldsaSig)+len(slhSig))
	sig = append(sig, h.SchemeID, msgLen)
	sig = append(sig, edSig...)
	sig = append(sig, msg...)
	sig = append(sig, mldsaSig...)
	sig = append(sig, slhSig...)
	pk, err := hybridedmldsaslhdsa.UnmarshalPublicKey(pubKey)
	if err != nil {
		return err
	}
	if !hybridedmldsaslhdsa.Verify(pk, msg, sig) {
		return ErrVerificationFailed
	}
	// Verify each component individually.
	edPk, err := ed25519.UnmarshalPublicKey(edPub)
	if err != nil {
		return err
	}
	if !ed25519.Verify(*edPk, msg, edSig) {
		return ErrVerificationFailed
	}
	mldsaPk, err := mldsa44.UnmarshalPublicKey(mldsaPub)
	if err != nil {
		return err
	}
	context := []byte{hybridedmldsaslhdsa.ED25519_MLDSA_SLHDSA_FULL_ID}
	if h.Context != hex.EncodeToString(context) {
		return fmt.Errorf("hybridparser: Context does not match expected (SchemeID)")
	}
	if !mldsa44.Verify(mldsaPk, msg, context, mldsaSig) {
		return ErrVerificationFailed
	}
	var slhPk slhdsa.PublicKey
	slhPk.ID = slhdsa.SHAKE_256f
	if err := slhPk.UnmarshalBinary(slhPub); err != nil {
		return err
	}
	if !slhdsa.Verify(&slhPk, slhdsa.NewMessage(msg), slhSig, context) {
		return ErrVerificationFailed
	}
	return nil
}

func checkHybridEDMLDSA5Full(h *HybridSignature, msg []byte, msgLen byte) error {
	edPub, err := getHex(h.PublicKeys, ComponentEd25519)
	if err != nil {
		return err
	}
	mldsaPub, err := getHex(h.PublicKeys, ComponentMLDSA87)
	if err != nil {
		return err
	}
	slhPub, err := getHex(h.PublicKeys, ComponentSLHDSA_SHAKE256s)
	if err != nil {
		return err
	}
	edSig, err := getHex(h.Signatures, ComponentEd25519)
	if err != nil {
		return err
	}
	mldsaSig, err := getHex(h.Signatures, ComponentMLDSA87)
	if err != nil {
		return err
	}
	slhSig, err := getHex(h.Signatures, ComponentSLHDSA_SHAKE256s)
	if err != nil {
		return err
	}
	pubKey := make([]byte, 0, len(edPub)+len(mldsaPub)+len(slhPub))
	pubKey = append(pubKey, edPub...)
	pubKey = append(pubKey, mldsaPub...)
	pubKey = append(pubKey, slhPub...)
	sig := make([]byte, 0, 2+len(edSig)+int(msgLen)+len(mldsaSig)+len(slhSig))
	sig = append(sig, h.SchemeID, msgLen)
	sig = append(sig, edSig...)
	sig = append(sig, msg...)
	sig = append(sig, mldsaSig...)
	sig = append(sig, slhSig...)
	pk, err := hybridedmldsaslhdsa5.UnmarshalPublicKey(pubKey)
	if err != nil {
		return err
	}
	if !hybridedmldsaslhdsa5.Verify(pk, msg, sig) {
		return ErrVerificationFailed
	}
	// Verify each component individually.
	edPk, err := ed25519.UnmarshalPublicKey(edPub)
	if err != nil {
		return err
	}
	if !ed25519.Verify(*edPk, msg, edSig) {
		return ErrVerificationFailed
	}
	mldsaPk, err := mldsa87.UnmarshalPublicKey(mldsaPub)
	if err != nil {
		return err
	}
	context := []byte{hybridedmldsaslhdsa5.ED25519_MLDSA5_SLHDSA5_FULL_ID}
	if h.Context != hex.EncodeToString(context) {
		return fmt.Errorf("hybridparser: Context does not match expected (SchemeID)")
	}
	if !mldsa87.Verify(mldsaPk, msg, context, mldsaSig) {
		return ErrVerificationFailed
	}
	var slhPk slhdsa.PublicKey
	slhPk.ID = slhdsa.SHAKE_256s
	if err := slhPk.UnmarshalBinary(slhPub); err != nil {
		return err
	}
	if !slhdsa.Verify(&slhPk, slhdsa.NewMessage(msg), slhSig, context) {
		return ErrVerificationFailed
	}
	return nil
}
