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
