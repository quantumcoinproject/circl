package wasm

import "testing"

func TestCheckExactLen(t *testing.T) {
	for _, n := range []int{0, 159, 161} { // empty, short, overlong
		if _, ok := checkExactLen("fn", "seed", n, 160); ok {
			t.Errorf("len %d accepted, want rejected", n)
		}
	}
	if _, ok := checkExactLen("fn", "seed", 160, 160); !ok {
		t.Error("exact length rejected")
	}
}

func FuzzCheckExactLen(f *testing.F) {
	f.Add("hybrid.verify", "signature", 2518, 2518)
	f.Add("", "", 0, 1)
	f.Add("fn", "key", -1, 0)

	f.Fuzz(func(t *testing.T, fnName, argName string, got, want int) {
		message, ok := checkExactLen(fnName, argName, got, want)
		if ok != (got == want) {
			t.Fatalf("length result mismatch: got=%d want=%d ok=%v", got, want, ok)
		}
		if ok && message != "" {
			t.Fatalf("successful validation returned an error message: %q", message)
		}
		if !ok && message == "" {
			t.Fatal("failed validation returned an empty error message")
		}
	})
}
