package wasm

import "fmt"

// checkExactLen returns an error message and false if got != want. It is kept
// in its own file without a build tag so the length-validation logic can be
// unit-tested on the host (wasm.go only compiles for GOOS=js GOARCH=wasm).
func checkExactLen(fnName, argName string, got, want int) (string, bool) {
	if got != want {
		return fmt.Sprintf("%s: %s must be exactly %d bytes, got %d", fnName, argName, want, got), false
	}
	return "", true
}
