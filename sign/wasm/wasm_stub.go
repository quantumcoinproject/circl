//go:build !js
// +build !js

// Package wasm stub for non-JS builds. The real implementation is in wasm.go
// (build tag: js,wasm). This file allows the package to build and tests to run
// when the build target is not GOOS=js GOARCH=wasm.
package wasm
