package mldsa44

import "testing"

// TestRejectTrailingBytes ensures a signature with extra trailing bytes is
// rejected (non-malleability): Unpack requires the buffer to be exactly
// SignatureSize bytes.
func TestRejectTrailingBytes(t *testing.T) {
	pk, sk, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("message")
	sig := make([]byte, SignatureSize)
	if err := SignTo(sk, msg, nil, false, sig); err != nil {
		t.Fatal(err)
	}
	if !Verify(pk, msg, nil, sig) {
		t.Fatal("valid signature rejected")
	}
	if Verify(pk, msg, nil, append(append([]byte{}, sig...), 0x00)) {
		t.Error("signature with trailing byte accepted")
	}
}
