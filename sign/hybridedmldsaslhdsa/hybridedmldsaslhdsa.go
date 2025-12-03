package hybridedmldsaslhdsa

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/quantumcoinproject/circl/sign/ed25519"
	"github.com/quantumcoinproject/circl/sign/mldsa/mldsa44"
	"github.com/quantumcoinproject/circl/sign/slhdsa"
)

/*
Secret Key Length = 64 + 2560 + 1312 + 128 = 4064
==================================================
Layout of secret key:

64 bytes                             2560 bytes             1312 bytes             128 bytes
ed25519 secret key with public key   | ml-dsa secret key    | ml-dsa public key    | slh-dsa secret key with public key

The following signature length includes implementation output, in addition to actual algorithm output.

Layout of Public Key
=====================
32 bytes           | 1312 bytes            | 64 bytes
ed25519 public key | ml-dsa public key     | slh-dsa public key


Compact Signature
==================
==================
The compact signature scheme does not sign the message using slh-dsa, but only using ed25519 and ml-dsa. During any emergency event, such as if both ed25519 and ml-dsa are broken or potential attacks found,
the slh-dsa key can be used to prove authenticity of signatures signed earlier or enabled for newer signatures with the same key pair.

In the compact signature mode, (signature id + slh-dsa public key) is used as the context string for ml-dsa signing. Randomized version is used for signing using ml-dsa.

Hybrid Signature Length (compact mode) = 1 + 1 + 64 + 2420 + {1 to 64}
=======================================================================================================================
Layout of signature:

1 byte                  | 1 byte            | 64 bytes          | 2420 bytes       | {1 to 64 bytes}
signature id (always 3) | length of message | ed25519 signature | ml-dsa signature | original message

Full Signature
==================
==================

Unlike the contact mode, the full signature mode uses all the three schemes to sign. Randomized version is used for signing using ml-dsa and slh-dsa. The signature id is used as the context string for ml-dsa and slh-dsa.

Hybrid Signature Length (full, used during breakglass) = 1 + 1 + 64 + {1 to 64} + 2420 + 49856
=======================================================================================================================
Layout of signature:

1 byte                  | 1 byte            | 64 bytes          | {1 to 64 bytes}   | 2420 bytes          | 49856
signature id (always 4) | length of message | ed25519 signature | original message  | ml-dsa signature    | slh-dsa signature

Message is variable length, between 1 to 64 bytes
*/

const (
	SlhDsaPublicKeySize  = 64
	SlhDsaPrivateKeySize = 128
	PublicKeySize        = ed25519.PublicKeySize + mldsa44.PublicKeySize + SlhDsaPublicKeySize
	PrivateKeySize       = ed25519.PrivateKeySize + mldsa44.PrivateKeySize + mldsa44.PublicKeySize + SlhDsaPrivateKeySize

	SeedSizeSlhDsda                 = 96
	SeedSize                        = ed25519.SeedSize + mldsa44.SeedSize + SeedSizeSlhDsda
	CRYPTO_MSG_LENGTH               = 32
	ED25519_MLDSA_SLHDSA_COMPACT_ID = byte(3)
	ED25519_MLDSA_SLHDSA_FULL_ID    = byte(4)

	ED25519_SIG_LENGTH = 64
	SLHDSA_SIG_LENGTH  = 49856

	CompactSigLength = 1 + 1 + ED25519_SIG_LENGTH + mldsa44.SignatureSize + CRYPTO_MSG_LENGTH
	SigLength        = 1 + 1 + ED25519_SIG_LENGTH + CRYPTO_MSG_LENGTH + mldsa44.SignatureSize + SLHDSA_SIG_LENGTH
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

func (sk *PrivateKey) getPrivateKeys() (edPriKey *ed25519.PrivateKey, mldsaPriKey *mldsa44.PrivateKey, slhdsaPriKey *slhdsa.PrivateKey, err error) {
	if len(sk.key) != PrivateKeySize || len(sk.key) != PrivateKeySize {
		return nil, nil, nil, errors.New(fmt.Sprintf("packed private key must be of %d bytes", PrivateKeySize))
	}
	sk1 := make([]byte, ed25519.PrivateKeySize)
	copy(sk1[:], sk.key[:ed25519.PrivateKeySize])

	sk2 := make([]byte, mldsa44.PrivateKeySize)
	copy(sk2[:], sk.key[ed25519.PrivateKeySize:ed25519.PrivateKeySize+mldsa44.PrivateKeySize+mldsa44.PublicKeySize])

	sk3 := make([]byte, SlhDsaPrivateKeySize)
	copy(sk3[:], sk.key[ed25519.PrivateKeySize+mldsa44.PrivateKeySize+mldsa44.PublicKeySize:])

	edPriKey, err = ed25519.UnmarshalPrivateKey(sk1)
	if err != nil {
		return nil, nil, nil, err
	}

	mldsaPriKey, err = mldsa44.UnmarshalPrivateKey(sk2)
	if err != nil {
		return nil, nil, nil, err
	}

	var skey slhdsa.PrivateKey
	skey.ID = slhdsa.SHAKE_256f
	err = skey.UnmarshalBinary(sk3)
	if err != nil {
		return nil, nil, nil, err
	}
	slhdsaPriKey = &skey

	return
}

func (sk *PrivateKey) GetPublicKey() (edsPubKey *PublicKey, err error) {
	if len(sk.key) != PrivateKeySize || len(sk.key) != PrivateKeySize {
		return nil, errors.New(fmt.Sprintf("packed private key must be of %d bytes", PrivateKeySize))
	}

	pubKeyBytes := make([]byte, PublicKeySize)
	copy(pubKeyBytes, sk.key[(ed25519.PrivateKeySize-ed25519.PublicKeySize):ed25519.PrivateKeySize])
	copy(pubKeyBytes[ed25519.PublicKeySize:], sk.key[ed25519.PrivateKeySize+mldsa44.PrivateKeySize:ed25519.PrivateKeySize+mldsa44.PrivateKeySize+mldsa44.PublicKeySize])
	copy(pubKeyBytes[ed25519.PublicKeySize+mldsa44.PublicKeySize:], sk.key[ed25519.PrivateKeySize+mldsa44.PrivateKeySize+mldsa44.PublicKeySize+(SlhDsaPrivateKeySize-SlhDsaPublicKeySize):])

	edsPubKey = &PublicKey{
		key: make([]byte, PublicKeySize),
	}
	copy(edsPubKey.key, pubKeyBytes)

	return edsPubKey, nil
}

func (pk *PublicKey) getPublicKeys() (edPubKey *ed25519.PublicKey, mldsaPubKey *mldsa44.PublicKey, slhdsaPubKey *slhdsa.PublicKey, err error) {
	if len(pk.key) != PublicKeySize || len(pk.key) != PublicKeySize {
		return nil, nil, nil, errors.New(fmt.Sprintf("packed public key must be of %d bytes", PublicKeySize))
	}
	sk1 := make([]byte, ed25519.PublicKeySize)
	copy(sk1[:], pk.key[:ed25519.PublicKeySize])

	sk2 := make([]byte, mldsa44.PublicKeySize)
	copy(sk2[:], pk.key[ed25519.PublicKeySize:ed25519.PublicKeySize+mldsa44.PublicKeySize])

	sk3 := make([]byte, SlhDsaPublicKeySize)
	copy(sk3[:], pk.key[ed25519.PublicKeySize+mldsa44.PublicKeySize:])

	edPubKey, err = ed25519.UnmarshalPublicKey(sk1)
	if err != nil {
		return nil, nil, nil, err
	}

	mldsaPubKey, err = mldsa44.UnmarshalPublicKey(sk2)
	if err != nil {
		return nil, nil, nil, err
	}

	var skey slhdsa.PublicKey
	skey.ID = slhdsa.SHAKE_256f
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

	mldsaPubKey, mlDsaPriKey, err := mldsa44.GenerateKey(random)
	if err != nil {
		return nil, nil, err
	}

	slhdsaPubKey, slhdsaPriKey, err := slhdsa.GenerateKey(random, slhdsa.SHAKE_256f)
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
	copy(pub.key[ed25519.PublicKeySize+mldsa44.PublicKeySize:], slhdsaPubKeyBytes)

	priv = &PrivateKey{
		key: make([]byte, PrivateKeySize),
	}
	copy(priv.key[:], eddsaPriKey)
	copy(priv.key[ed25519.PrivateKeySize:], mlDsaPriKey.Bytes())
	copy(priv.key[ed25519.PrivateKeySize+mldsa44.PrivateKeySize:], mldsaPubKey.Bytes())
	copy(priv.key[ed25519.PrivateKeySize+mldsa44.PrivateKeySize+mldsa44.PublicKeySize:], slhdsaPriKeyBytes)

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
	context := []byte{ED25519_MLDSA_SLHDSA_FULL_ID}

	var sig2 [mldsa44.SignatureSize]byte
	err = mldsa44.Sign(key2, msg, context, rand, sig2[:])
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
	signature[0] = ED25519_MLDSA_SLHDSA_FULL_ID
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

	if signature[0] != ED25519_MLDSA_SLHDSA_FULL_ID {
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

	context := []byte{ED25519_MLDSA_SLHDSA_FULL_ID}
	sig2 := signature[2+ED25519_SIG_LENGTH+len(msg) : 2+ED25519_SIG_LENGTH+len(msg)+mldsa44.SignatureSize]
	if mldsa44.Verify(key2, msg, context, sig2) == false {
		return false
	}

	sig3 := signature[2+ED25519_SIG_LENGTH+len(msg)+mldsa44.SignatureSize:]
	if slhdsa.Verify(key3, slhdsa.NewMessage(msg), sig3, context) == false {
		return false
	}

	return true
}

func SignCompact(priv *PrivateKey, rand io.Reader, msg []byte) (signature []byte, err error) {
	if msg == nil || len(msg) != CRYPTO_MSG_LENGTH {
		return signature, errors.New("invalid message")
	}
	if priv == nil {
		return signature, errors.New("private key is nil")
	}
	key1, key2, _, err := priv.getPrivateKeys()
	if err != nil {
		return signature, err
	}

	//Get SLH DSA public key
	pubKey, err := priv.GetPublicKey()
	if err != nil {
		return signature, err
	}
	_, _, slhdsaPubKey, err := pubKey.getPublicKeys()
	if err != nil {
		return signature, err
	}
	slhdsaPubKeyBytes, err := slhdsaPubKey.MarshalBinary()
	if err != nil {
		return signature, err
	}

	sig1 := ed25519.Sign(*key1, msg)

	var sig2 [mldsa44.SignatureSize]byte

	context := make([]byte, 1+len(slhdsaPubKeyBytes))
	context[0] = ED25519_MLDSA_SLHDSA_COMPACT_ID
	copy(context[1:], slhdsaPubKeyBytes)

	err = mldsa44.Sign(key2, msg, context, rand, sig2[:])
	if err != nil {
		return nil, err
	}

	if sig1 == nil {
		return signature, errors.New("invalid signature")
	}

	if len(sig1) != ED25519_SIG_LENGTH {
		return signature, errors.New("invalid signature length")
	}

	signature = make([]byte, CompactSigLength)
	signature[0] = ED25519_MLDSA_SLHDSA_COMPACT_ID
	signature[1] = CRYPTO_MSG_LENGTH
	copy(signature[2:], sig1)
	copy(signature[2+len(sig1):], sig2[:])
	copy(signature[2+len(sig1)+len(sig2):], msg)

	return signature, nil
}

func VerifyCompact(pk *PublicKey, msg []byte, signature []byte) bool {
	if pk == nil || msg == nil || signature == nil || len(msg) != CRYPTO_MSG_LENGTH || len(signature) != CompactSigLength {
		return false
	}

	if signature[0] != ED25519_MLDSA_SLHDSA_COMPACT_ID {
		return false
	}

	if signature[1] != byte(len(msg)) {
		return false
	}

	//first verify msg from signature
	if bytes.Equal(signature[2+ED25519_SIG_LENGTH+mldsa44.SignatureSize:2+ED25519_SIG_LENGTH+mldsa44.SignatureSize+CRYPTO_MSG_LENGTH], msg) == false {
		return false
	}

	key1, key2, slhdsaPubKey, err := pk.getPublicKeys()
	if err != nil {
		return false
	}
	if key1 == nil || key2 == nil || slhdsaPubKey == nil {
		return false
	}
	slhdsaPubKeyBytes, err := slhdsaPubKey.MarshalBinary()
	if err != nil {
		return false
	}

	sig1 := signature[2 : 2+ED25519_SIG_LENGTH]
	if ed25519.Verify(*key1, msg, sig1) == false {
		return false
	}

	context := make([]byte, 1+len(slhdsaPubKeyBytes))
	context[0] = ED25519_MLDSA_SLHDSA_COMPACT_ID
	copy(context[1:], slhdsaPubKeyBytes)

	sig2 := signature[2+ED25519_SIG_LENGTH : 2+ED25519_SIG_LENGTH+mldsa44.SignatureSize]
	if mldsa44.Verify(key2, msg, context, sig2) == false {
		return false
	}

	return true
}
