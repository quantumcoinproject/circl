package mldsa44

import (
	"encoding/json"
	"testing"

	"github.com/quantumcoinproject/circl/internal/test"
)

// Wycheproof ML-DSA signature-verification vectors from the C2SP/wycheproof
// project (testvectors_v1/mldsa_44_verify_test.json). These exercise edge and
// negative cases such as malleated hint encodings, infinity-norm violations,
// incorrect public-key/signature lengths and over-long contexts.
func TestWycheproofVerify(t *testing.T) {
	buf, err := test.ReadGzip("../testdata/mldsa_44_verify_test.json.gz")
	if err != nil {
		t.Fatal(err)
	}

	var vectors struct {
		Algorithm  string `json:"algorithm"`
		TestGroups []struct {
			Type      string        `json:"type"`
			PublicKey test.HexBytes `json:"publicKey"`
			Tests     []struct {
				TcID    int           `json:"tcId"`
				Comment string        `json:"comment"`
				Msg     test.HexBytes `json:"msg"`
				Ctx     test.HexBytes `json:"ctx"`
				Sig     test.HexBytes `json:"sig"`
				Result  string        `json:"result"`
				Flags   []string      `json:"flags"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	if err := json.Unmarshal(buf, &vectors); err != nil {
		t.Fatal(err)
	}

	total := 0
	for _, group := range vectors.TestGroups {
		// A group can carry an intentionally malformed public key (e.g. wrong
		// length). When it cannot be unpacked, verification must fail for every
		// vector in the group, which all carry result "invalid".
		var pk *PublicKey
		if len(group.PublicKey) == PublicKeySize {
			var p PublicKey
			if err := p.UnmarshalBinary(group.PublicKey); err == nil {
				pk = &p
			}
		}

		for _, tc := range group.Tests {
			total++
			want := tc.Result == "valid"
			got := false
			if pk != nil {
				got = Verify(pk, tc.Msg, tc.Ctx, tc.Sig)
			}
			if got != want {
				t.Errorf("tcId %d (%s) flags=%v: got valid=%v, want valid=%v",
					tc.TcID, tc.Comment, tc.Flags, got, want)
			}
		}
	}

	if total == 0 {
		t.Fatal("no Wycheproof test vectors were loaded")
	}
	t.Logf("ran %d Wycheproof ML-DSA-44 verify vectors", total)
}
