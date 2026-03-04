package hybridedmldsaslhdsa5

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/quantumcoinproject/circl/sign/ed25519"
	"github.com/quantumcoinproject/circl/sign/mldsa/mldsa87"
	"github.com/quantumcoinproject/circl/sign/slhdsa"
)

/*
This hybrid signature scheme is designed for use in blockchain protocols where
the composite key pair is the signer's sole cryptographic identity. Individual
component keys (Ed25519, ML-DSA-87, SLH-DSA) MUST NOT be reused in any other
signing context -- whether standalone, in a different hybrid combination, or
across protocol boundaries.

Secret Key Length = 64 + 4896 + 2592 + 128 = 7680
==================================================
Layout of secret key:

64 bytes                               4896 bytes             2592 bytes             128 bytes
ed25519 secret key with public key   | ml-dsa secret key    | ml-dsa public key    | slh-dsa secret key with public key

The following signature length includes implementation output, in addition to actual algorithm output.

Layout of Public Key (2688 bytes)
==================================
32 bytes           | 2592 bytes            | 64 bytes
ed25519 public key | ml-dsa public key     | slh-dsa public key

Full Signature
==================
==================

Hybrid Signature Length (full) = 1 + 1 + 64 + 32 + 4627 + 29792
=======================================================================================================================
Layout of signature:

1 byte                  | 1 byte            | 64 bytes          | 32 bytes          | 4627 bytes          | 29792
signature id (always 5) | length of message | ed25519 signature | original message  | ml-dsa signature    | slh-dsa signature

Message is fixed length of 32 bytes
*/

const (
	SlhDsaPublicKeySize  = 64
	SlhDsaPrivateKeySize = 128
	PublicKeySize        = ed25519.PublicKeySize + mldsa87.PublicKeySize + SlhDsaPublicKeySize
	PrivateKeySize       = ed25519.PrivateKeySize + mldsa87.PrivateKeySize + mldsa87.PublicKeySize + SlhDsaPrivateKeySize

	SeedSizeSlhDsa                 = 96
	SeedSize                       = ed25519.SeedSize + mldsa87.SeedSize + SeedSizeSlhDsa
	CRYPTO_MSG_LENGTH              = 32
	ED25519_MLDSA5_SLHDSA5_FULL_ID = byte(5)

	ED25519_SIG_LENGTH = 64
	SLHDSA_SIG_LENGTH  = 29792

	SigLength = 1 + 1 + ED25519_SIG_LENGTH + CRYPTO_MSG_LENGTH + mldsa87.SignatureSize + SLHDSA_SIG_LENGTH
)

type PublicKey struct {
	key []byte
}

type PrivateKey struct {
	key []byte
}

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	if pk.key == nil || len(pk.key) != PublicKeySize {
		return nil, errors.New("invalid public key")
	}
	tmp := make([]byte, PublicKeySize)
	copy(tmp, pk.key)
	return tmp, nil
}

func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	if sk.key == nil || len(sk.key) != PrivateKeySize {
		return nil, errors.New("invalid private key")
	}
	tmp := make([]byte, PrivateKeySize)
	copy(tmp, sk.key)
	return tmp, nil
}

// Unpacks the public key from data.
func UnmarshalPublicKey(data []byte) (*PublicKey, error) {
	if len(data) != PublicKeySize {
		return nil, errors.New(fmt.Sprintf("packed public key must be of %d bytes", PublicKeySize))
	}
	var pub PublicKey

	pub.key = make([]byte, PublicKeySize)
	copy(pub.key, data)

	return &pub, nil
}

// Unpacks the private key from data.
func UnmarshalPrivateKey(data []byte) (*PrivateKey, error) {
	if len(data) != PrivateKeySize {
		return nil, errors.New(fmt.Sprintf("packed private key must be of %d bytes", PrivateKeySize))
	}
	var priv PrivateKey

	priv.key = make([]byte, PrivateKeySize)
	copy(priv.key, data)

	return &priv, nil
}

func (sk *PrivateKey) getPrivateKeys() (edPriKey *ed25519.PrivateKey, mldsaPriKey *mldsa87.PrivateKey, slhdsaPriKey *slhdsa.PrivateKey, err error) {
	if len(sk.key) != PrivateKeySize {
		return nil, nil, nil, errors.New(fmt.Sprintf("packed private key must be of %d bytes", PrivateKeySize))
	}
	sk1 := make([]byte, ed25519.PrivateKeySize)
	copy(sk1[:], sk.key[:ed25519.PrivateKeySize])

	sk2 := make([]byte, mldsa87.PrivateKeySize)
	copy(sk2[:], sk.key[ed25519.PrivateKeySize:ed25519.PrivateKeySize+mldsa87.PrivateKeySize])

	sk3 := make([]byte, SlhDsaPrivateKeySize)
	copy(sk3[:], sk.key[ed25519.PrivateKeySize+mldsa87.PrivateKeySize+mldsa87.PublicKeySize:])

	edPriKey, err = ed25519.UnmarshalPrivateKey(sk1)
	if err != nil {
		return nil, nil, nil, err
	}

	mldsaPriKey, err = mldsa87.UnmarshalPrivateKey(sk2)
	if err != nil {
		return nil, nil, nil, err
	}

	var skey slhdsa.PrivateKey
	skey.ID = slhdsa.SHAKE_256s
	err = skey.UnmarshalBinary(sk3)
	if err != nil {
		return nil, nil, nil, err
	}
	slhdsaPriKey = &skey

	return
}

func (sk *PrivateKey) GetPublicKey() (edsPubKey *PublicKey, err error) {
	if len(sk.key) != PrivateKeySize {
		return nil, errors.New(fmt.Sprintf("packed private key must be of %d bytes", PrivateKeySize))
	}

	pubKeyBytes := make([]byte, PublicKeySize)
	copy(pubKeyBytes, sk.key[(ed25519.PrivateKeySize-ed25519.PublicKeySize):ed25519.PrivateKeySize])
	copy(pubKeyBytes[ed25519.PublicKeySize:], sk.key[ed25519.PrivateKeySize+mldsa87.PrivateKeySize:ed25519.PrivateKeySize+mldsa87.PrivateKeySize+mldsa87.PublicKeySize])
	copy(pubKeyBytes[ed25519.PublicKeySize+mldsa87.PublicKeySize:], sk.key[ed25519.PrivateKeySize+mldsa87.PrivateKeySize+mldsa87.PublicKeySize+(SlhDsaPrivateKeySize-SlhDsaPublicKeySize):])

	edsPubKey = &PublicKey{
		key: make([]byte, PublicKeySize),
	}
	copy(edsPubKey.key, pubKeyBytes)

	return edsPubKey, nil
}

func (pk *PublicKey) getPublicKeys() (edPubKey *ed25519.PublicKey, mldsaPubKey *mldsa87.PublicKey, slhdsaPubKey *slhdsa.PublicKey, err error) {
	if len(pk.key) != PublicKeySize {
		return nil, nil, nil, errors.New(fmt.Sprintf("packed public key must be of %d bytes", PublicKeySize))
	}
	sk1 := make([]byte, ed25519.PublicKeySize)
	copy(sk1[:], pk.key[:ed25519.PublicKeySize])

	sk2 := make([]byte, mldsa87.PublicKeySize)
	copy(sk2[:], pk.key[ed25519.PublicKeySize:ed25519.PublicKeySize+mldsa87.PublicKeySize])

	sk3 := make([]byte, SlhDsaPublicKeySize)
	copy(sk3[:], pk.key[ed25519.PublicKeySize+mldsa87.PublicKeySize:])

	edPubKey, err = ed25519.UnmarshalPublicKey(sk1)
	if err != nil {
		return nil, nil, nil, err
	}

	mldsaPubKey, err = mldsa87.UnmarshalPublicKey(sk2)
	if err != nil {
		return nil, nil, nil, err
	}

	var skey slhdsa.PublicKey
	skey.ID = slhdsa.SHAKE_256s
	err = skey.UnmarshalBinary(sk3)
	if err != nil {
		return nil, nil, nil, err
	}
	slhdsaPubKey = &skey

	return
}

func GenerateKey(random io.Reader) (pub *PublicKey, priv *PrivateKey, err error) {
	eddsaPubKey, eddsaPriKey, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, nil, err
	}

	mldsaPubKey, mlDsaPriKey, err := mldsa87.GenerateKey(random)
	if err != nil {
		return nil, nil, err
	}

	slhdsaPubKey, slhdsaPriKey, err := slhdsa.GenerateKey(random, slhdsa.SHAKE_256s)
	if err != nil {
		return nil, nil, err
	}

	slhdsaPubKeyBytes, err := slhdsaPubKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	slhdsaPriKeyBytes, err := slhdsaPriKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	pub = &PublicKey{
		key: make([]byte, PublicKeySize),
	}
	copy(pub.key[:], eddsaPubKey)
	copy(pub.key[ed25519.PublicKeySize:], mldsaPubKey.Bytes())
	copy(pub.key[ed25519.PublicKeySize+mldsa87.PublicKeySize:], slhdsaPubKeyBytes)

	priv = &PrivateKey{
		key: make([]byte, PrivateKeySize),
	}
	copy(priv.key[:], eddsaPriKey)
	copy(priv.key[ed25519.PrivateKeySize:], mlDsaPriKey.Bytes())
	copy(priv.key[ed25519.PrivateKeySize+mldsa87.PrivateKeySize:], mldsaPubKey.Bytes())
	copy(priv.key[ed25519.PrivateKeySize+mldsa87.PrivateKeySize+mldsa87.PublicKeySize:], slhdsaPriKeyBytes)

	return pub, priv, nil
}

func NewKeyFromSeed(seed *[SeedSize]byte) (*PublicKey, *PrivateKey, error) {
	seedBuff := bytes.NewReader(seed[:])
	return GenerateKey(seedBuff)
}

func Sign(priv *PrivateKey, rand io.Reader, msg []byte) (signature []byte, err error) {
	if msg == nil || len(msg) != CRYPTO_MSG_LENGTH {
		return signature, errors.New("invalid message")
	}
	if priv == nil {
		return signature, errors.New("private key is nil")
	}
	key1, key2, key3, err := priv.getPrivateKeys()
	if err != nil {
		return signature, err
	}

	sig1 := ed25519.Sign(*key1, msg)
	context := []byte{ED25519_MLDSA5_SLHDSA5_FULL_ID}

	var sig2 [mldsa87.SignatureSize]byte
	err = mldsa87.Sign(key2, msg, context, rand, sig2[:])
	if err != nil {
		return nil, err
	}

	sig3, err := slhdsa.SignRandomized(key3, rand, slhdsa.NewMessage(msg), context)

	if err != nil {
		return signature, err
	}

	if sig1 == nil || sig3 == nil {
		return signature, errors.New("invalid signature")
	}

	if len(sig1) != ED25519_SIG_LENGTH || len(sig3) != SLHDSA_SIG_LENGTH {
		return signature, errors.New("invalid signature length")
	}

	signature = make([]byte, SigLength)
	signature[0] = ED25519_MLDSA5_SLHDSA5_FULL_ID
	signature[1] = CRYPTO_MSG_LENGTH
	copy(signature[2:], sig1)
	copy(signature[2+len(sig1):], msg)
	copy(signature[2+len(sig1)+len(msg):], sig2[:])
	copy(signature[2+len(sig1)+len(msg)+len(sig2):], sig3)

	return signature, nil
}

func Verify(pk *PublicKey, msg []byte, signature []byte) bool {
	if pk == nil || msg == nil || len(msg) != CRYPTO_MSG_LENGTH || len(signature) != SigLength {
		return false
	}

	if signature[0] != ED25519_MLDSA5_SLHDSA5_FULL_ID {
		return false
	}

	if signature[1] != byte(len(msg)) {
		return false
	}

	//first verify msg from signature
	if bytes.Equal(signature[2+ED25519_SIG_LENGTH:2+ED25519_SIG_LENGTH+CRYPTO_MSG_LENGTH], msg) == false {
		return false
	}

	key1, key2, key3, err := pk.getPublicKeys()
	if err != nil {
		return false
	}
	if key1 == nil || key2 == nil || key3 == nil {
		return false
	}

	sig1 := signature[2 : 2+ED25519_SIG_LENGTH]
	if ed25519.Verify(*key1, msg, sig1) == false {
		return false
	}

	context := []byte{ED25519_MLDSA5_SLHDSA5_FULL_ID}
	sig2 := signature[2+ED25519_SIG_LENGTH+len(msg) : 2+ED25519_SIG_LENGTH+len(msg)+mldsa87.SignatureSize]
	if mldsa87.Verify(key2, msg, context, sig2) == false {
		return false
	}

	sig3 := signature[2+ED25519_SIG_LENGTH+len(msg)+mldsa87.SignatureSize:]
	if slhdsa.Verify(key3, slhdsa.NewMessage(msg), sig3, context) == false {
		return false
	}

	return true
}
