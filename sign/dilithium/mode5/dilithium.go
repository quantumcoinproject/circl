// Code generated from pkg.templ.go. DO NOT EDIT.

// mode5 implements the CRYSTALS-Dilithium signature scheme Dilithium5
// as submitted to round3 of the NIST PQC competition and described in
//
// https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf
package mode5

import (
	"crypto"
	"errors"
	"io"

	"github.com/quantumcoinproject/circl/sign"
	"github.com/quantumcoinproject/circl/sign/dilithium/mode5/internal"
	common "github.com/quantumcoinproject/circl/sign/internal/dilithium"
)

const (
	// Size of seed for NewKeyFromSeed
	SeedSize = common.SeedSize

	// Size of a packed PublicKey
	PublicKeySize = internal.PublicKeySize

	// Size of a packed PrivateKey
	PrivateKeySize = internal.PrivateKeySize

	// Size of a signature
	SignatureSize = internal.SignatureSize
)

// PublicKey is the type of Dilithium5 public key
type PublicKey internal.PublicKey

// PrivateKey is the type of Dilithium5 private key
type PrivateKey internal.PrivateKey

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (*PublicKey, *PrivateKey, error) {
	pk, sk, err := internal.GenerateKey(rand)
	return (*PublicKey)(pk), (*PrivateKey)(sk), err
}

// NewKeyFromSeed derives a public/private key pair using the given seed.
func NewKeyFromSeed(seed *[SeedSize]byte) (*PublicKey, *PrivateKey) {
	pk, sk := internal.NewKeyFromSeed(seed)
	return (*PublicKey)(pk), (*PrivateKey)(sk)
}

// SignTo signs the given message and writes the signature into signature.
// It will panic if signature is not of length at least SignatureSize.
func SignTo(sk *PrivateKey, msg, sig []byte) {
	var rnd [32]byte

	internal.SignTo(
		(*internal.PrivateKey)(sk),
		func(w io.Writer) {
			w.Write(msg)
		},
		rnd,
		sig,
	)
}

// Verify checks whether the given signature by pk on msg is valid.
func Verify(pk *PublicKey, msg, sig []byte) bool {
	return internal.Verify(
		(*internal.PublicKey)(pk),
		func(w io.Writer) {
			_, _ = w.Write(msg)
		},
		sig,
	)
}

// Sets pk to the public key encoded in buf.
func (pk *PublicKey) Unpack(buf *[PublicKeySize]byte) {
	(*internal.PublicKey)(pk).Unpack(buf)
}

// Sets sk to the private key encoded in buf.
func (sk *PrivateKey) Unpack(buf *[PrivateKeySize]byte) {
	(*internal.PrivateKey)(sk).Unpack(buf)
}

// Packs the public key into buf.
func (pk *PublicKey) Pack(buf *[PublicKeySize]byte) {
	(*internal.PublicKey)(pk).Pack(buf)
}

// Packs the private key into buf.
func (sk *PrivateKey) Pack(buf *[PrivateKeySize]byte) {
	(*internal.PrivateKey)(sk).Pack(buf)
}

// Packs the public key.
func (pk *PublicKey) Bytes() []byte {
	var buf [PublicKeySize]byte
	pk.Pack(&buf)
	return buf[:]
}

// Packs the private key.
func (sk *PrivateKey) Bytes() []byte {
	var buf [PrivateKeySize]byte
	sk.Pack(&buf)
	return buf[:]
}

// Packs the public key.
func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	return pk.Bytes(), nil
}

// Packs the private key.
func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	return sk.Bytes(), nil
}

// Unpacks the public key from data.
func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	if len(data) != PublicKeySize {
		return errors.New("packed public key must be of mode5.PublicKeySize bytes")
	}
	var buf [PublicKeySize]byte
	copy(buf[:], data)
	pk.Unpack(&buf)
	return nil
}

// Unpacks the private key from data.
func (sk *PrivateKey) UnmarshalBinary(data []byte) error {
	if len(data) != PrivateKeySize {
		return errors.New("packed private key must be of mode5.PrivateKeySize bytes")
	}
	var buf [PrivateKeySize]byte
	copy(buf[:], data)
	sk.Unpack(&buf)
	return nil
}

// Sign signs the given message.
//
// opts.HashFunc() must return zero, which can be achieved by passing
// crypto.Hash(0) for opts.  rand is ignored.  Will only return an error
// if opts.HashFunc() is non-zero.
//
// This function is used to make PrivateKey implement the crypto.Signer
// interface.  The package-level SignTo function might be more convenient
// to use.
func (sk *PrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (
	sig []byte, err error) {
	var ret [SignatureSize]byte

	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("dilithium: cannot sign hashed message")
	}
	SignTo(sk, msg, ret[:])

	return ret[:], nil
}

// Computes the public key corresponding to this private key.
//
// Returns a *PublicKey.  The type crypto.PublicKey is used to make
// PrivateKey implement the crypto.Signer interface.
func (sk *PrivateKey) Public() crypto.PublicKey {
	return (*PublicKey)((*internal.PrivateKey)(sk).Public())
}

// Equal returns whether the two private keys equal.
func (sk *PrivateKey) Equal(other crypto.PrivateKey) bool {
	castOther, ok := other.(*PrivateKey)
	if !ok {
		return false
	}
	return (*internal.PrivateKey)(sk).Equal((*internal.PrivateKey)(castOther))
}

// Equal returns whether the two public keys equal.
func (pk *PublicKey) Equal(other crypto.PublicKey) bool {
	castOther, ok := other.(*PublicKey)
	if !ok {
		return false
	}
	return (*internal.PublicKey)(pk).Equal((*internal.PublicKey)(castOther))
}

// Boilerplate for generic signatures API

type scheme struct{}

var sch sign.Scheme = &scheme{}

// Scheme returns a generic signature interface for Dilithium5.
func Scheme() sign.Scheme { return sch }

func (*scheme) Name() string        { return "Dilithium5" }
func (*scheme) PublicKeySize() int  { return PublicKeySize }
func (*scheme) PrivateKeySize() int { return PrivateKeySize }
func (*scheme) SignatureSize() int  { return SignatureSize }
func (*scheme) SeedSize() int       { return SeedSize }

// TODO TLSIdentifier()

func (*scheme) SupportsContext() bool {
	return false
}

func (*scheme) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	return GenerateKey(nil)
}

func (*scheme) Sign(
	sk sign.PrivateKey,
	msg []byte,
	opts *sign.SignatureOpts,
) []byte {
	sig := make([]byte, SignatureSize)

	priv, ok := sk.(*PrivateKey)
	if !ok {
		panic(sign.ErrTypeMismatch)
	}
	if opts != nil && opts.Context != "" {
		panic(sign.ErrContextNotSupported)
	}
	SignTo(priv, msg, sig)

	return sig
}

func (*scheme) Verify(
	pk sign.PublicKey,
	msg, sig []byte,
	opts *sign.SignatureOpts,
) bool {
	pub, ok := pk.(*PublicKey)
	if !ok {
		panic(sign.ErrTypeMismatch)
	}
	if opts != nil && opts.Context != "" {
		panic(sign.ErrContextNotSupported)
	}
	return Verify(pub, msg, sig)
}

func (*scheme) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	if len(seed) != SeedSize {
		panic(sign.ErrSeedSize)
	}
	var seed2 [SeedSize]byte
	copy(seed2[:], seed)
	return NewKeyFromSeed(&seed2)
}

func (*scheme) UnmarshalBinaryPublicKey(buf []byte) (sign.PublicKey, error) {
	if len(buf) != PublicKeySize {
		return nil, sign.ErrPubKeySize
	}

	var (
		buf2 [PublicKeySize]byte
		ret  PublicKey
	)

	copy(buf2[:], buf)
	ret.Unpack(&buf2)
	return &ret, nil
}

func (*scheme) UnmarshalBinaryPrivateKey(buf []byte) (sign.PrivateKey, error) {
	if len(buf) != PrivateKeySize {
		return nil, sign.ErrPrivKeySize
	}

	var (
		buf2 [PrivateKeySize]byte
		ret  PrivateKey
	)

	copy(buf2[:], buf)
	ret.Unpack(&buf2)
	return &ret, nil
}

func (sk *PrivateKey) Scheme() sign.Scheme {
	return sch
}

func (sk *PublicKey) Scheme() sign.Scheme {
	return sch
}
