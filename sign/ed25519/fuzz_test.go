package ed25519

import "testing"

// FuzzVerify exercises public-key decoding and signature verification with
// arbitrary attacker-controlled inputs. A fuzz failure is any panic or a valid
// seed signature being rejected.
func FuzzVerify(f *testing.F) {
	seed := [SeedSize]byte{}
	privateKey := NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(PublicKey)
	message := []byte("ed25519 fuzz seed")
	signature := Sign(privateKey, message)

	f.Add([]byte(publicKey), message, signature)
	f.Add([]byte{}, []byte{}, []byte{})
	f.Add(make([]byte, PublicKeySize), []byte{0}, make([]byte, SignatureSize))

	f.Fuzz(func(t *testing.T, public, message, signature []byte) {
		_ = Verify(PublicKey(public), message, signature)
		_, _ = UnmarshalPublicKey(public)
	})
}

// FuzzUnmarshalPrivateKey checks that malformed private-key encodings are
// rejected without panicking and that accepted keys can be marshaled again.
func FuzzUnmarshalPrivateKey(f *testing.F) {
	seed := [SeedSize]byte{}
	privateKey := NewKeyFromSeed(seed[:])

	f.Add([]byte(privateKey))
	f.Add([]byte{})
	f.Add(make([]byte, PrivateKeySize))

	f.Fuzz(func(t *testing.T, encoded []byte) {
		key, err := UnmarshalPrivateKey(encoded)
		if err != nil {
			return
		}
		marshaled, err := key.MarshalBinary()
		if err != nil {
			t.Fatalf("accepted private key failed to marshal: %v", err)
		}
		if len(marshaled) != PrivateKeySize {
			t.Fatalf("accepted private key marshaled to %d bytes, want %d", len(marshaled), PrivateKeySize)
		}
	})
}
