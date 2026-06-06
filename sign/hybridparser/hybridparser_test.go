package hybridparser

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/quantumcoinproject/circl/sign/hybrideds"
	"github.com/quantumcoinproject/circl/sign/hybridedmldsaslhdsa"
	"github.com/quantumcoinproject/circl/sign/hybridedmldsaslhdsa5"
)

// Fixed seeds and message for deterministic test vectors.
var (
	seedEDS      = [hybrideds.SeedSize]byte{}
	seedEDMLDSA  = [hybridedmldsaslhdsa.SeedSize]byte{}
	seedEDMLDSA5 = [hybridedmldsaslhdsa5.SeedSize]byte{}
	testMsg      [32]byte
)

func init() {
	for i := range seedEDS {
		seedEDS[i] = byte(i)
	}
	for i := range seedEDMLDSA {
		seedEDMLDSA[i] = byte(i)
	}
	for i := range seedEDMLDSA5 {
		seedEDMLDSA5[i] = byte(i)
	}
	for i := range testMsg {
		testMsg[i] = byte(i)
	}
}

func TestParseHybrid_NotHybrid(t *testing.T) {
	msg := testMsg[:]
	_, err := ParseHybrid([]byte{0}, make([]byte, hybrideds.PublicKeySize), msg)
	if err != ErrNotHybrid {
		t.Errorf("first byte 0: got err %v, want ErrNotHybrid", err)
	}
	_, err = ParseHybrid([]byte{6}, make([]byte, hybrideds.PublicKeySize), msg)
	if err != ErrNotHybrid {
		t.Errorf("first byte 6: got err %v, want ErrNotHybrid", err)
	}
	_, err = ParseHybrid([]byte{255}, make([]byte, hybrideds.PublicKeySize), msg)
	if err != ErrNotHybrid {
		t.Errorf("first byte 255: got err %v, want ErrNotHybrid", err)
	}
	_, err = ParseHybrid(nil, nil, msg)
	if err == nil {
		t.Error("nil signature: expected error")
	}
}

func TestParseHybrid_Scheme1_Compact(t *testing.T) {
	pub, priv, err := hybrideds.NewKeyFromSeed(&seedEDS)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hybrideds.SignCompact(priv, deterministicReader(0), testMsg[:])
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := pub.MarshalBinary()

	parsed, err := ParseHybrid(sig, pubBytes, testMsg[:])
	if err != nil {
		t.Fatalf("ParseHybrid: %v", err)
	}
	if parsed.SchemeID != 1 {
		t.Errorf("SchemeID = %d, want 1", parsed.SchemeID)
	}
	wantMsgHex := hex.EncodeToString(testMsg[:])
	if parsed.Message != wantMsgHex {
		t.Errorf("Message = %q, want %q", parsed.Message, wantMsgHex)
	}
	checkComponent(t, parsed.PublicKeys, []string{ComponentEd25519, ComponentDilithium, ComponentSphincsSHAKE256f})
	checkComponent(t, parsed.Signatures, []string{ComponentEd25519, ComponentDilithium})
	if parsed.AdditionalData == nil || parsed.AdditionalData[AdditionalDataScheme1Nonce] == "" {
		t.Error("scheme 1: expected AdditionalData[Scheme1Nonce] to be set")
	}
}

func TestParseHybrid_Scheme2_Full(t *testing.T) {
	pub, priv, err := hybrideds.NewKeyFromSeed(&seedEDS)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hybrideds.Sign(priv, deterministicReader(0), testMsg[:])
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := pub.MarshalBinary()

	parsed, err := ParseHybrid(sig, pubBytes, testMsg[:])
	if err != nil {
		t.Fatalf("ParseHybrid: %v", err)
	}
	if parsed.SchemeID != 2 {
		t.Errorf("SchemeID = %d, want 2", parsed.SchemeID)
	}
	wantMsgHex := hex.EncodeToString(testMsg[:])
	if parsed.Message != wantMsgHex {
		t.Errorf("Message = %q, want %q", parsed.Message, wantMsgHex)
	}
	checkComponent(t, parsed.PublicKeys, []string{ComponentEd25519, ComponentDilithium, ComponentSphincsSHAKE256f})
	checkComponent(t, parsed.Signatures, []string{ComponentEd25519, ComponentDilithium, ComponentSphincsSHAKE256f})
}

func TestParseHybrid_Scheme3_Compact(t *testing.T) {
	pub, priv, err := hybridedmldsaslhdsa.NewKeyFromSeed(&seedEDMLDSA)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hybridedmldsaslhdsa.SignCompact(priv, deterministicReader(0), testMsg[:])
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := pub.MarshalBinary()

	parsed, err := ParseHybrid(sig, pubBytes, testMsg[:])
	if err != nil {
		t.Fatalf("ParseHybrid: %v", err)
	}
	if parsed.SchemeID != 3 {
		t.Errorf("SchemeID = %d, want 3", parsed.SchemeID)
	}
	wantMsgHex := hex.EncodeToString(testMsg[:])
	if parsed.Message != wantMsgHex {
		t.Errorf("Message = %q, want %q", parsed.Message, wantMsgHex)
	}
	checkComponent(t, parsed.PublicKeys, []string{ComponentEd25519, ComponentMLDSA44, ComponentSLHDSA_SHAKE256f})
	checkComponent(t, parsed.Signatures, []string{ComponentEd25519, ComponentMLDSA44})
}

func TestParseHybrid_Scheme4_Full(t *testing.T) {
	pub, priv, err := hybridedmldsaslhdsa.NewKeyFromSeed(&seedEDMLDSA)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hybridedmldsaslhdsa.Sign(priv, deterministicReader(0), testMsg[:])
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := pub.MarshalBinary()

	parsed, err := ParseHybrid(sig, pubBytes, testMsg[:])
	if err != nil {
		t.Fatalf("ParseHybrid: %v", err)
	}
	if parsed.SchemeID != 4 {
		t.Errorf("SchemeID = %d, want 4", parsed.SchemeID)
	}
	wantMsgHex := hex.EncodeToString(testMsg[:])
	if parsed.Message != wantMsgHex {
		t.Errorf("Message = %q, want %q", parsed.Message, wantMsgHex)
	}
	checkComponent(t, parsed.PublicKeys, []string{ComponentEd25519, ComponentMLDSA44, ComponentSLHDSA_SHAKE256f})
	checkComponent(t, parsed.Signatures, []string{ComponentEd25519, ComponentMLDSA44, ComponentSLHDSA_SHAKE256f})
}

func TestParseHybrid_Scheme5_Full(t *testing.T) {
	pub, priv, err := hybridedmldsaslhdsa5.NewKeyFromSeed(&seedEDMLDSA5)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hybridedmldsaslhdsa5.Sign(priv, deterministicReader(0), testMsg[:])
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := pub.MarshalBinary()

	parsed, err := ParseHybrid(sig, pubBytes, testMsg[:])
	if err != nil {
		t.Fatalf("ParseHybrid: %v", err)
	}
	if parsed.SchemeID != 5 {
		t.Errorf("SchemeID = %d, want 5", parsed.SchemeID)
	}
	wantMsgHex := hex.EncodeToString(testMsg[:])
	if parsed.Message != wantMsgHex {
		t.Errorf("Message = %q, want %q", parsed.Message, wantMsgHex)
	}
	checkComponent(t, parsed.PublicKeys, []string{ComponentEd25519, ComponentMLDSA87, ComponentSLHDSA_SHAKE256s})
	checkComponent(t, parsed.Signatures, []string{ComponentEd25519, ComponentMLDSA87, ComponentSLHDSA_SHAKE256s})
}

func TestCheckHybrid(t *testing.T) {
	schemes := []struct {
		name string
		run  func() (*HybridSignature, error)
	}{
		{"scheme1", func() (*HybridSignature, error) {
			pub, priv, _ := hybrideds.NewKeyFromSeed(&seedEDS)
			sig, err := hybrideds.SignCompact(priv, deterministicReader(0), testMsg[:])
			if err != nil {
				return nil, err
			}
			pubBytes, _ := pub.MarshalBinary()
			return ParseHybrid(sig, pubBytes, testMsg[:])
		}},
		{"scheme2", func() (*HybridSignature, error) {
			pub, priv, _ := hybrideds.NewKeyFromSeed(&seedEDS)
			sig, err := hybrideds.Sign(priv, deterministicReader(0), testMsg[:])
			if err != nil {
				return nil, err
			}
			pubBytes, _ := pub.MarshalBinary()
			return ParseHybrid(sig, pubBytes, testMsg[:])
		}},
		{"scheme3", func() (*HybridSignature, error) {
			pub, priv, _ := hybridedmldsaslhdsa.NewKeyFromSeed(&seedEDMLDSA)
			sig, err := hybridedmldsaslhdsa.SignCompact(priv, deterministicReader(0), testMsg[:])
			if err != nil {
				return nil, err
			}
			pubBytes, _ := pub.MarshalBinary()
			return ParseHybrid(sig, pubBytes, testMsg[:])
		}},
		{"scheme4", func() (*HybridSignature, error) {
			pub, priv, _ := hybridedmldsaslhdsa.NewKeyFromSeed(&seedEDMLDSA)
			sig, err := hybridedmldsaslhdsa.Sign(priv, deterministicReader(0), testMsg[:])
			if err != nil {
				return nil, err
			}
			pubBytes, _ := pub.MarshalBinary()
			return ParseHybrid(sig, pubBytes, testMsg[:])
		}},
		{"scheme5", func() (*HybridSignature, error) {
			pub, priv, _ := hybridedmldsaslhdsa5.NewKeyFromSeed(&seedEDMLDSA5)
			sig, err := hybridedmldsaslhdsa5.Sign(priv, deterministicReader(0), testMsg[:])
			if err != nil {
				return nil, err
			}
			pubBytes, _ := pub.MarshalBinary()
			return ParseHybrid(sig, pubBytes, testMsg[:])
		}},
	}
	for _, tc := range schemes {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := tc.run()
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if err := CheckHybrid(parsed); err != nil {
				t.Fatalf("CheckHybrid: %v", err)
			}
		})
	}
}

func TestCheckHybrid_InvalidFails(t *testing.T) {
	parsed, err := func() (*HybridSignature, error) {
		pub, priv, _ := hybrideds.NewKeyFromSeed(&seedEDS)
		sig, _ := hybrideds.Sign(priv, deterministicReader(0), testMsg[:])
		pubBytes, _ := pub.MarshalBinary()
		return ParseHybrid(sig, pubBytes, testMsg[:])
	}()
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt message in struct
	parsed.Message = hex.EncodeToString([]byte("wrong message"))
	if err := CheckHybrid(parsed); err != ErrVerificationFailed {
		t.Errorf("CheckHybrid with wrong message: got %v, want ErrVerificationFailed", err)
	}
}

// flipHexChar returns a copy of s with one hex character flipped at index idx
// to a different valid hex digit, so decoded bytes change.
func flipHexChar(s string, idx int) string {
	if idx < 0 || idx >= len(s) {
		return s
	}
	b := []byte(s)
	switch b[idx] {
	case '0':
		b[idx] = '1'
	case '1':
		b[idx] = '0'
	default:
		b[idx] = '0'
	}
	return string(b)
}

func TestCheckHybrid_FlipPubSigMessageFails(t *testing.T) {
	parsed, err := func() (*HybridSignature, error) {
		pub, priv, _ := hybrideds.NewKeyFromSeed(&seedEDS)
		sig, _ := hybrideds.Sign(priv, deterministicReader(0), testMsg[:])
		pubBytes, _ := pub.MarshalBinary()
		return ParseHybrid(sig, pubBytes, testMsg[:])
	}()
	if err != nil {
		t.Fatal(err)
	}

	// 1) Flip one byte in a public key component -> CheckHybrid must fail
	t.Run("flip_public_key", func(t *testing.T) {
		bad := cloneHybridSignature(parsed)
		// Flip a character in the ed25519 public key (first component)
		bad.PublicKeys[ComponentEd25519] = flipHexChar(bad.PublicKeys[ComponentEd25519], 4)
		if err := CheckHybrid(bad); err != ErrVerificationFailed {
			t.Errorf("CheckHybrid with flipped pub key: got %v, want ErrVerificationFailed", err)
		}
	})

	// 2) Flip one byte in a signature component -> CheckHybrid must fail
	t.Run("flip_signature", func(t *testing.T) {
		bad := cloneHybridSignature(parsed)
		bad.Signatures[ComponentEd25519] = flipHexChar(bad.Signatures[ComponentEd25519], 8)
		if err := CheckHybrid(bad); err != ErrVerificationFailed {
			t.Errorf("CheckHybrid with flipped signature: got %v, want ErrVerificationFailed", err)
		}
	})

	// 3) Flip one byte in the message -> CheckHybrid must fail
	t.Run("flip_message", func(t *testing.T) {
		bad := cloneHybridSignature(parsed)
		bad.Message = flipHexChar(bad.Message, 2)
		if err := CheckHybrid(bad); err != ErrVerificationFailed {
			t.Errorf("CheckHybrid with flipped message: got %v, want ErrVerificationFailed", err)
		}
	})
}

func cloneHybridSignature(h *HybridSignature) *HybridSignature {
	if h == nil {
		return nil
	}
	dup := &HybridSignature{
		SchemeID:   h.SchemeID,
		Message:    h.Message,
		PublicKeys: make(map[string]string),
		Signatures: make(map[string]string),
	}
	for k, v := range h.PublicKeys {
		dup.PublicKeys[k] = v
	}
	for k, v := range h.Signatures {
		dup.Signatures[k] = v
	}
	if h.AdditionalData != nil {
		dup.AdditionalData = make(map[string]string)
		for k, v := range h.AdditionalData {
			dup.AdditionalData[k] = v
		}
	}
	return dup
}

func TestParseHybrid_VerificationFails(t *testing.T) {
	pub, priv, err := hybrideds.NewKeyFromSeed(&seedEDS)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hybrideds.Sign(priv, deterministicReader(0), testMsg[:])
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := pub.MarshalBinary()

	badSig := make([]byte, len(sig))
	copy(badSig, sig)
	if len(badSig) > 100 {
		badSig[100] ^= 1
	}
	_, err = ParseHybrid(badSig, pubBytes, testMsg[:])
	if err != ErrVerificationFailed {
		t.Errorf("corrupted signature: got err %v, want ErrVerificationFailed", err)
	}

	_, err = ParseHybrid(sig, pubBytes[:len(pubBytes)-1], testMsg[:])
	if err == nil {
		t.Error("wrong public key length: expected error")
	}

	// Wrong message should fail verification
	wrongMsg := make([]byte, len(testMsg))
	copy(wrongMsg, testMsg[:])
	wrongMsg[0] ^= 1
	_, err = ParseHybrid(sig, pubBytes, wrongMsg)
	if err != ErrVerificationFailed {
		t.Errorf("wrong message: got err %v, want ErrVerificationFailed", err)
	}
}

func checkComponent(t *testing.T, m map[string]string, names []string) {
	t.Helper()
	for _, name := range names {
		v, ok := m[name]
		if !ok {
			t.Errorf("missing component %q", name)
			continue
		}
		if v == "" {
			t.Errorf("component %q has empty value", name)
		}
		_, err := hex.DecodeString(v)
		if err != nil {
			t.Errorf("component %q is not valid hex: %v", name, err)
		}
	}
	if len(m) != len(names) {
		t.Errorf("map has %d entries, want %d", len(m), len(names))
	}
}

// truncHex returns s if len(s) <= max, else s[:max]+"...".
func truncHex(s string, max int) string {
	if max <= 0 {
		max = 32
	}
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// jsonOutput is a display-friendly copy of HybridSignature with truncated hex fields.
type jsonOutput struct {
	SchemeID       byte              `json:"SchemeID"`
	SchemeName     string            `json:"SchemeName"`
	Context        string            `json:"Context"`
	AdditionalData map[string]string `json:"AdditionalData"`
	Message        string            `json:"Message"`
	PublicKeys     map[string]string `json:"PublicKeys"`
	Signatures     map[string]string `json:"Signatures"`
}

func hybridSignatureToJSONOutput(h *HybridSignature, hexLen int) jsonOutput {
	out := jsonOutput{
		SchemeID:       h.SchemeID,
		SchemeName:     h.SchemeName,
		Context:        truncHex(h.Context, hexLen),
		AdditionalData: make(map[string]string),
		Message:        truncHex(h.Message, hexLen),
		PublicKeys:     make(map[string]string),
		Signatures:     make(map[string]string),
	}
	for k, v := range h.AdditionalData {
		out.AdditionalData[k] = truncHex(v, hexLen)
	}
	for k, v := range h.PublicKeys {
		out.PublicKeys[k] = truncHex(v, hexLen)
	}
	for k, v := range h.Signatures {
		out.Signatures[k] = truncHex(v, hexLen)
	}
	return out
}

// TestParseHybrid_JSONOutput logs the JSON form of HybridSignature for each scheme.
// Long hex strings are truncated so output is readable. Run: go test -v -run TestParseHybrid_JSONOutput ./sign/hybridparser/
func TestParseHybrid_JSONOutput(t *testing.T) {
	schemes := []struct {
		name string
		run  func() (*HybridSignature, error)
	}{
		{"scheme1", func() (*HybridSignature, error) {
			pub, priv, _ := hybrideds.NewKeyFromSeed(&seedEDS)
			// Use deterministicReader(1) so AdditionalData Scheme1Nonce and Scheme1Mu are not all zeros.
			sig, err := hybrideds.SignCompact(priv, deterministicReader(1), testMsg[:])
			if err != nil {
				return nil, err
			}
			pubBytes, _ := pub.MarshalBinary()
			return ParseHybrid(sig, pubBytes, testMsg[:])
		}},
		{"scheme2", func() (*HybridSignature, error) {
			pub, priv, _ := hybrideds.NewKeyFromSeed(&seedEDS)
			sig, err := hybrideds.Sign(priv, deterministicReader(0), testMsg[:])
			if err != nil {
				return nil, err
			}
			pubBytes, _ := pub.MarshalBinary()
			return ParseHybrid(sig, pubBytes, testMsg[:])
		}},
		{"scheme3", func() (*HybridSignature, error) {
			pub, priv, _ := hybridedmldsaslhdsa.NewKeyFromSeed(&seedEDMLDSA)
			sig, err := hybridedmldsaslhdsa.SignCompact(priv, deterministicReader(0), testMsg[:])
			if err != nil {
				return nil, err
			}
			pubBytes, _ := pub.MarshalBinary()
			return ParseHybrid(sig, pubBytes, testMsg[:])
		}},
		{"scheme4", func() (*HybridSignature, error) {
			pub, priv, _ := hybridedmldsaslhdsa.NewKeyFromSeed(&seedEDMLDSA)
			sig, err := hybridedmldsaslhdsa.Sign(priv, deterministicReader(0), testMsg[:])
			if err != nil {
				return nil, err
			}
			pubBytes, _ := pub.MarshalBinary()
			return ParseHybrid(sig, pubBytes, testMsg[:])
		}},
		{"scheme5", func() (*HybridSignature, error) {
			pub, priv, _ := hybridedmldsaslhdsa5.NewKeyFromSeed(&seedEDMLDSA5)
			sig, err := hybridedmldsaslhdsa5.Sign(priv, deterministicReader(0), testMsg[:])
			if err != nil {
				return nil, err
			}
			pubBytes, _ := pub.MarshalBinary()
			return ParseHybrid(sig, pubBytes, testMsg[:])
		}},
	}
	const hexLen = 48 // show first 48 hex chars for readability
	for _, tc := range schemes {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := tc.run()
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			disp := hybridSignatureToJSONOutput(parsed, hexLen)
			b, err := json.MarshalIndent(disp, "", "  ")
			if err != nil {
				t.Fatalf("json.MarshalIndent: %v", err)
			}
			t.Logf("\n%s", string(b))
		})
	}
}

type deterministicReader byte

func (r deterministicReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

// TestCheckHybridRejectsOverlongMessage ensures the message-length guard is not
// bypassed by byte() truncation: a message longer than CRYPTO_MSG_LENGTH (which
// previously wrapped, e.g. 256 -> 0) must be rejected.
func TestCheckHybridRejectsOverlongMessage(t *testing.T) {
	for _, n := range []int{hybrideds.CRYPTO_MSG_LENGTH + 1, 256} {
		h := &HybridSignature{
			SchemeID:   hybrideds.DILITHIUM_ED25519_SPHINCS_FULL_ID,
			Message:    hex.EncodeToString(make([]byte, n)),
			PublicKeys: map[string]string{},
			Signatures: map[string]string{},
		}
		err := CheckHybrid(h)
		if err == nil || err.Error() != "hybridparser: message too long" {
			t.Errorf("message length %d: got err %v, want \"message too long\"", n, err)
		}
	}
}
