package hybridedsfull

import (
	"errors"
	"github.com/quantumcoinproject/circl/sign/ed25519"
	"github.com/quantumcoinproject/circl/sign/mldsa/mldsa44"
	"github.com/quantumcoinproject/circl/sign/slhdsa"
	"io"
)

/*
Secret Key Length = 64 + 2560 + 1312 + 128 = 4064
==================================================
Layout of secret key:

64 bytes                             2560 bytes             1312 bytes             128 bytes
ed25519 secret key with public key | dilithium secret key | dilithium public key | sphincs secret key with public key

The following signature length includes implementation output, in addition to actual algorithm output.

Layout of ED25519 signature
============================

64 bytes          | {1 to 64 bytes}
ed25519 Signature | Message

Layout of Dilithium signature
==============================
2420 bytes
dilithium signature

Layout of Sphincs signature
==============================
49856 bytes
dilithium signature

Layout of Public Key
==============================
32 bytes           | 1312 bytes            | 64 bytes
ed25519 public key | dilithium public key  | sphincs public key


Compact Signature
==================
==================
The compact signature scheme does not sign the message using sphincs+, but only using ed25519 and dilithium. During any emergency event, such as if both ed25519 and dilithium are broken or potential attacks found,
the SPHINCS+ key can be used to prove authenticity of signatures signed earlier or enabled for newer signatures with the same key pair.

In the compact signature mode, a new message digest is created from the original message digest and then hashed using sha3-512. This new message is signed by ed25519 and dilithium

Hybrid Signature Message (compact mode)
=========================================

40 bytes      | {0 to 64 bytes}  | 64 bytes
random nonce  | original message | sphincs public key

hybrid-message-hash = SHA3-512(compact-mode-message)

Hybrid Signature Length (compact mode) = 1 + 1 + 64 + 2420 + 40 + {1 to 64}
=======================================================================================================================
Layout of signature:

1 byte                  | 1 byte            | 64 bytes          | 2420 bytres         | 40 bytes     | {1 to 64 bytes}
signature id (always 1) | length of message | ed25519 signature | dilithium signature | random nonce | original message

Full Signature
==================
==================

Hybrid Signature Length (full, used during breakglass) = 1 + 1 + 64 + {1 to 64} + 2420 + 49856
=======================================================================================================================
Layout of signature:

1 byte                  | 1 byte            | 64 bytes          | {1 to 64 bytes}   | 2420 bytes          | 49856
signature id (always 2) | length of message | ed25519 signature | original message  | dilithium signature | sphincs signature

Message is variable length, between 1 to 64 bytes
*/

const (
	SlhDsaPublicKeySize  = 64
	SlhDsaPrivateKeySize = 128
	PublicKeySize        = ed25519.PublicKeySize + mldsa44.PublicKeySize + SlhDsaPublicKeySize
	SecretKeySize        = ed25519.PrivateKeySize + mldsa44.PrivateKeySize + mldsa44.PublicKeySize + SlhDsaPrivateKeySize
)

type PublicKey struct {
	key []byte
}

type PrivateKey struct {
	key []byte
}

func (k PublicKey) MarshalBinary() ([]byte, error) {
	return k.key[:], nil
}

func (k PrivateKey) MarshalBinary() ([]byte, error) {
	return k.key[:], nil
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

	pubKeyBytes := append(eddsaPubKey[:], mldsaPubKey.Bytes()...)
	pubKeyBytes = append(pubKeyBytes, slhdsaPubKeyBytes...)

	if len(pubKeyBytes) != PublicKeySize {
		return nil, nil, errors.New("invalid public key size")
	}

	priKeyBytes := append(eddsaPriKey[:], mlDsaPriKey.Bytes()...)
	priKeyBytes = append(priKeyBytes, mldsaPubKey.Bytes()...)
	priKeyBytes = append(priKeyBytes, slhdsaPriKeyBytes...)

	if len(priKeyBytes) != SecretKeySize {
		return nil, nil, errors.New("invalid private key size")
	}

	pub = &PublicKey{
		key: make([]byte, PublicKeySize),
	}
	priv = &PrivateKey{
		key: make([]byte, SecretKeySize),
	}

	copy(pub.key, pubKeyBytes)
	copy(priv.key, priKeyBytes)

	return pub, priv, nil
}
