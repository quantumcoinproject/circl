package hybridparser

import (
	"bytes"
	"testing"

	"github.com/quantumcoinproject/circl/sign/hybridedmldsaslhdsa"
	"github.com/quantumcoinproject/circl/sign/hybridedmldsaslhdsa5"
	"github.com/quantumcoinproject/circl/sign/hybrideds"
)

// FuzzParseHybrid exercises the audit parser with arbitrary encoded hybrid
// inputs. Any successfully parsed value must also survive component-level
// reconstruction and verification.
func FuzzParseHybrid(f *testing.F) {
	seed := [hybridedmldsaslhdsa.SeedSize]byte{}
	publicKey, privateKey, err := hybridedmldsaslhdsa.NewKeyFromSeed(&seed)
	if err != nil {
		f.Fatalf("failed to create hybrid parser seed key: %v", err)
	}
	message := make([]byte, hybridedmldsaslhdsa.CRYPTO_MSG_LENGTH)
	signature, err := hybridedmldsaslhdsa.SignCompact(
		privateKey,
		bytes.NewReader(make([]byte, 32)),
		message,
	)
	if err != nil {
		f.Fatalf("failed to create hybrid parser seed signature: %v", err)
	}
	publicBytes, err := publicKey.MarshalBinary()
	if err != nil {
		f.Fatalf("failed to marshal hybrid parser seed key: %v", err)
	}

	f.Add(signature, publicBytes, message)
	f.Add([]byte{}, []byte{}, []byte{})
	addMalformed := func(id byte, signatureSize, publicKeySize int) {
		signature := make([]byte, signatureSize)
		signature[0] = id
		signature[1] = hybridedmldsaslhdsa.CRYPTO_MSG_LENGTH
		f.Add(
			signature,
			make([]byte, publicKeySize),
			make([]byte, hybridedmldsaslhdsa.CRYPTO_MSG_LENGTH),
		)
	}
	addMalformed(hybrideds.DILITHIUM_ED25519_SPHINCS_COMPACT_ID, hybrideds.CompactSigLength, hybrideds.PublicKeySize)
	addMalformed(hybrideds.DILITHIUM_ED25519_SPHINCS_FULL_ID, hybrideds.SigLength, hybrideds.PublicKeySize)
	addMalformed(hybridedmldsaslhdsa.ED25519_MLDSA_SLHDSA_COMPACT_ID, hybridedmldsaslhdsa.CompactSigLength, hybridedmldsaslhdsa.PublicKeySize)
	addMalformed(hybridedmldsaslhdsa.ED25519_MLDSA_SLHDSA_FULL_ID, hybridedmldsaslhdsa.SigLength, hybridedmldsaslhdsa.PublicKeySize)
	addMalformed(hybridedmldsaslhdsa5.ED25519_MLDSA5_SLHDSA5_FULL_ID, hybridedmldsaslhdsa5.SigLength, hybridedmldsaslhdsa5.PublicKeySize)

	f.Fuzz(func(t *testing.T, signature, public, message []byte) {
		parsed, err := ParseHybrid(signature, public, message)
		if err != nil {
			return
		}
		if err := CheckHybrid(parsed); err != nil {
			t.Fatalf("successfully parsed hybrid failed reconstruction: %v", err)
		}
	})
}
