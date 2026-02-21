//go:build !js
// +build !js

package wasm

import (
	"bytes"
	"crypto/rand"
	"testing"

	hybrid "github.com/quantumcoinproject/circl/sign/hybridedmldsaslhdsa"
	hybrid5 "github.com/quantumcoinproject/circl/sign/hybridedmldsaslhdsa5"
)

// These tests run only when not building for JS (see build tags). They exercise
// the same constants and crypto operations that wasm.go exposes to JavaScript,
// using the underlying hybrid and hybrid5 packages directly.

func TestHybridConstantsMatchWasmDoc(t *testing.T) {
	// Documented in wasm.go package doc for circl.hybrid
	if hybrid.PublicKeySize != 1408 {
		t.Errorf("hybrid.PublicKeySize = %d, want 1408", hybrid.PublicKeySize)
	}
	if hybrid.PrivateKeySize != 4064 {
		t.Errorf("hybrid.PrivateKeySize = %d, want 4064", hybrid.PrivateKeySize)
	}
	if hybrid.SeedSize != 160 {
		t.Errorf("hybrid.SeedSize = %d, want 160", hybrid.SeedSize)
	}
	if hybrid.BaseSeedSize != 64 {
		t.Errorf("hybrid.BaseSeedSize = %d, want 64", hybrid.BaseSeedSize)
	}
	if hybrid.SigLength != 52374 {
		t.Errorf("hybrid.SigLength = %d, want 52374", hybrid.SigLength)
	}
	// CompactSigLength is 1+1+64+mldsa44.SignatureSize+32 (actual value from package)
	if hybrid.CompactSigLength != 2518 {
		t.Errorf("hybrid.CompactSigLength = %d, want 2518", hybrid.CompactSigLength)
	}
	if hybrid.CRYPTO_MSG_LENGTH != 32 {
		t.Errorf("hybrid.CRYPTO_MSG_LENGTH = %d, want 32", hybrid.CRYPTO_MSG_LENGTH)
	}
}

func TestHybrid5ConstantsMatchWasmDoc(t *testing.T) {
	// Documented in wasm.go package doc for circl.hybrid5
	if hybrid5.PublicKeySize != 2688 {
		t.Errorf("hybrid5.PublicKeySize = %d, want 2688", hybrid5.PublicKeySize)
	}
	if hybrid5.PrivateKeySize != 7680 {
		t.Errorf("hybrid5.PrivateKeySize = %d, want 7680", hybrid5.PrivateKeySize)
	}
	if hybrid5.SeedSize != 160 {
		t.Errorf("hybrid5.SeedSize = %d, want 160", hybrid5.SeedSize)
	}
	if hybrid5.BaseSeedSize != 72 {
		t.Errorf("hybrid5.BaseSeedSize = %d, want 72", hybrid5.BaseSeedSize)
	}
	// SigLength from package (actual implementation value)
	if hybrid5.SigLength != 34517 {
		t.Errorf("hybrid5.SigLength = %d, want 34517", hybrid5.SigLength)
	}
	if hybrid5.CRYPTO_MSG_LENGTH != 32 {
		t.Errorf("hybrid5.CRYPTO_MSG_LENGTH = %d, want 32", hybrid5.CRYPTO_MSG_LENGTH)
	}
}

func TestHybridGenerateKeyAndSignVerify(t *testing.T) {
	pub, priv, err := hybrid.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := pub.MarshalBinary()
	privBytes, _ := priv.MarshalBinary()
	if len(pubBytes) != hybrid.PublicKeySize {
		t.Errorf("public key length = %d, want %d", len(pubBytes), hybrid.PublicKeySize)
	}
	if len(privBytes) != hybrid.PrivateKeySize {
		t.Errorf("private key length = %d, want %d", len(privBytes), hybrid.PrivateKeySize)
	}

	var msg [hybrid.CRYPTO_MSG_LENGTH]byte
	if _, err := rand.Read(msg[:]); err != nil {
		t.Fatal(err)
	}
	sig, err := hybrid.Sign(priv, rand.Reader, msg[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != hybrid.SigLength {
		t.Errorf("signature length = %d, want %d", len(sig), hybrid.SigLength)
	}
	if !hybrid.Verify(pub, msg[:], sig) {
		t.Error("Verify failed")
	}
}

func TestHybridNewKeyFromSeed(t *testing.T) {
	var seed [hybrid.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	pub, priv, err := hybrid.NewKeyFromSeed(&seed)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := pub.MarshalBinary()
	privBytes, _ := priv.MarshalBinary()
	if len(pubBytes) != hybrid.PublicKeySize || len(privBytes) != hybrid.PrivateKeySize {
		t.Errorf("key sizes: pub %d, priv %d", len(pubBytes), len(privBytes))
	}
	// Same seed must yield same keys
	pub2, priv2, err := hybrid.NewKeyFromSeed(&seed)
	if err != nil {
		t.Fatal(err)
	}
	pub2Bytes, _ := pub2.MarshalBinary()
	priv2Bytes, _ := priv2.MarshalBinary()
	if !bytes.Equal(pubBytes, pub2Bytes) || !bytes.Equal(privBytes, priv2Bytes) {
		t.Error("deterministic key from seed: keys differ on second call")
	}
}

func TestHybridSignCompactVerifyCompact(t *testing.T) {
	pub, priv, err := hybrid.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var msg [hybrid.CRYPTO_MSG_LENGTH]byte
	if _, err := rand.Read(msg[:]); err != nil {
		t.Fatal(err)
	}
	sig, err := hybrid.SignCompact(priv, rand.Reader, msg[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != hybrid.CompactSigLength {
		t.Errorf("compact signature length = %d, want %d", len(sig), hybrid.CompactSigLength)
	}
	if !hybrid.VerifyCompact(pub, msg[:], sig) {
		t.Error("VerifyCompact failed")
	}
}

func TestHybridGetPublicKey(t *testing.T) {
	_, priv, err := hybrid.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.GetPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(pubBytes) != hybrid.PublicKeySize {
		t.Errorf("getPublicKey length = %d, want %d", len(pubBytes), hybrid.PublicKeySize)
	}
}

func TestHybridExpandSeed(t *testing.T) {
	var baseSeed [hybrid.BaseSeedSize]byte
	if _, err := rand.Read(baseSeed[:]); err != nil {
		t.Fatal(err)
	}
	expanded, err := hybrid.ExpandSeed(baseSeed)
	if err != nil {
		t.Fatal(err)
	}
	if len(expanded) != hybrid.SeedSize {
		t.Errorf("expandSeed length = %d, want %d", len(expanded), hybrid.SeedSize)
	}
}

func TestHybrid5GenerateKeyAndSignVerify(t *testing.T) {
	pub, priv, err := hybrid5.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := pub.MarshalBinary()
	privBytes, _ := priv.MarshalBinary()
	if len(pubBytes) != hybrid5.PublicKeySize {
		t.Errorf("public key length = %d, want %d", len(pubBytes), hybrid5.PublicKeySize)
	}
	if len(privBytes) != hybrid5.PrivateKeySize {
		t.Errorf("private key length = %d, want %d", len(privBytes), hybrid5.PrivateKeySize)
	}

	var msg [hybrid5.CRYPTO_MSG_LENGTH]byte
	if _, err := rand.Read(msg[:]); err != nil {
		t.Fatal(err)
	}
	sig, err := hybrid5.Sign(priv, rand.Reader, msg[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != hybrid5.SigLength {
		t.Errorf("signature length = %d, want %d", len(sig), hybrid5.SigLength)
	}
	if !hybrid5.Verify(pub, msg[:], sig) {
		t.Error("Verify failed")
	}
}

func TestHybrid5NewKeyFromSeed(t *testing.T) {
	var seed [hybrid5.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	pub, priv, err := hybrid5.NewKeyFromSeed(&seed)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := pub.MarshalBinary()
	privBytes, _ := priv.MarshalBinary()
	if len(pubBytes) != hybrid5.PublicKeySize || len(privBytes) != hybrid5.PrivateKeySize {
		t.Errorf("key sizes: pub %d, priv %d", len(pubBytes), len(privBytes))
	}
}

func TestHybrid5ExpandSeed(t *testing.T) {
	var baseSeed [hybrid5.BaseSeedSize]byte
	if _, err := rand.Read(baseSeed[:]); err != nil {
		t.Fatal(err)
	}
	expanded, err := hybrid5.ExpandSeed(baseSeed)
	if err != nil {
		t.Fatal(err)
	}
	if len(expanded) != hybrid5.SeedSize {
		t.Errorf("expandSeed length = %d, want %d", len(expanded), hybrid5.SeedSize)
	}
}

func TestHybridUnmarshalRoundTrip(t *testing.T) {
	pub, priv, err := hybrid.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := pub.MarshalBinary()
	privBytes, _ := priv.MarshalBinary()

	pub2, err := hybrid.UnmarshalPublicKey(pubBytes)
	if err != nil {
		t.Fatal(err)
	}
	pub2Bytes, _ := pub2.MarshalBinary()
	if !bytes.Equal(pubBytes, pub2Bytes) {
		t.Error("UnmarshalPublicKey round-trip failed")
	}

	priv2, err := hybrid.UnmarshalPrivateKey(privBytes)
	if err != nil {
		t.Fatal(err)
	}
	priv2Bytes, _ := priv2.MarshalBinary()
	if !bytes.Equal(privBytes, priv2Bytes) {
		t.Error("UnmarshalPrivateKey round-trip failed")
	}
}

func TestHybrid5UnmarshalRoundTrip(t *testing.T) {
	pub, priv, err := hybrid5.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := pub.MarshalBinary()
	privBytes, _ := priv.MarshalBinary()

	pub2, err := hybrid5.UnmarshalPublicKey(pubBytes)
	if err != nil {
		t.Fatal(err)
	}
	pub2Bytes, _ := pub2.MarshalBinary()
	if !bytes.Equal(pubBytes, pub2Bytes) {
		t.Error("UnmarshalPublicKey round-trip failed")
	}

	priv2, err := hybrid5.UnmarshalPrivateKey(privBytes)
	if err != nil {
		t.Fatal(err)
	}
	priv2Bytes, _ := priv2.MarshalBinary()
	if !bytes.Equal(privBytes, priv2Bytes) {
		t.Error("UnmarshalPrivateKey round-trip failed")
	}
}
