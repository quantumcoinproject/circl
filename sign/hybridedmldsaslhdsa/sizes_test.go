package hybridedmldsaslhdsa

import "testing"

// TestDocumentedSizes pins the size constants that are documented for JS callers
// in sign/wasm/wasm.go. If a parameter change alters any of these, this test
// fails so the WASM doc comments (and any hardcoded JS buffer sizes) are updated
// in lockstep.
func TestDocumentedSizes(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"PublicKeySize", PublicKeySize, 1408},
		{"PrivateKeySize", PrivateKeySize, 4064},
		{"SeedSize", SeedSize, 160},
		{"SigLength", SigLength, 52374},
		{"CompactSigLength", CompactSigLength, 2518},
		{"CryptoMsgLength", CRYPTO_MSG_LENGTH, 32},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, documented value is %d (update sign/wasm/wasm.go docs)", c.name, c.got, c.want)
		}
	}
}
