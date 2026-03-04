//go:build js && wasm
// +build js,wasm

// Package wasm exposes post-quantum hybrid signature schemes to JavaScript
// via WebAssembly. It wraps three underlying Go packages:
//
//   - hybridedmldsaslhdsa  (Ed25519 + ML-DSA-44 + SLH-DSA-SHAKE-256f) — "hybridedmldsaslhdsa"
//   - hybridedmldsaslhdsa5 (Ed25519 + ML-DSA-87 + SLH-DSA-SHAKE-256s) — "hybridedmldsaslhds5"
//   - hybrideds            (Ed25519 + ML-DSA-44 + SLH-DSA-SHAKE-256f) — "hybrideds"
//
// All schemes combine a classical signature (Ed25519) with two post-quantum
// signatures (ML-DSA and SLH-DSA). The "hybrideds" variant uses the same
// algorithms as hybridedmldsaslhdsa with a different key layout and seed expander.
//
// # Build
//
// This file only compiles for GOOS=js GOARCH=wasm:
//
//	GOOS=js GOARCH=wasm go build -o main.wasm ./cmd/wasm
//
// # Integration
//
// A Go main package should call [Register] at startup to bind every function
// and constant onto globalThis.circl, then block forever so the WASM instance
// stays alive:
//
//	package main
//
//	import "github.com/quantumcoinproject/circl/sign/wasm"
//
//	func main() {
//	    wasm.Register()
//	    select {} // block forever
//	}
//
// On the JavaScript side, load the WASM module with Go's wasm_exec.js glue,
// then use the circl namespace:
//
//	const go = new Go();
//	const result = await WebAssembly.instantiateStreaming(fetch("main.wasm"), go.importObject);
//	await go.run(result.instance);
//
//	// --- circl.hybrid (Ed25519 + ML-DSA-44 + SLH-DSA-SHAKE-256f) ---
//	const res = circl.hybrid.generateKey();
//	if (res.error) { console.error(res.error); return; }
//	const keys = res.result; // {publicKey: Uint8Array, privateKey: Uint8Array}
//
//	const sigRes = circl.hybrid.sign(keys.privateKey, msg);
//	if (sigRes.error) { console.error(sigRes.error); return; }
//	const sig = sigRes.result; // Uint8Array
//
//	const verRes = circl.hybrid.verify(keys.publicKey, msg, sig);
//	if (verRes.error) { console.error(verRes.error); return; }
//	const ok = verRes.result; // boolean
//
//	// Compact mode (Ed25519 + ML-DSA only, SLH-DSA key retained for breakglass):
//	const csigRes = circl.hybrid.signCompact(keys.privateKey, msg);
//	const cverRes = circl.hybrid.verifyCompact(keys.publicKey, msg, csigRes.result);
//
//	// --- circl.hybrid5 (Ed25519 + ML-DSA-87 + SLH-DSA-SHAKE-256s) ---
//	const res5 = circl.hybrid5.generateKey();
//	if (res5.error) { console.error(res5.error); return; }
//	const keys5 = res5.result;
//
// # Data format conventions
//
// All keys, signatures, and messages are exchanged as JavaScript Uint8Array.
// Key-pair-returning functions return {publicKey: Uint8Array, privateKey: Uint8Array}
// inside the result field.
//
// Messages MUST be exactly 32 bytes (CryptoMsgLength). Passing a message of
// any other length will return an error.
//
// # Error handling
//
// Every function returns a JS object with two fields:
//
//	{ result: <value>, error: null }   // on success
//	{ result: null,    error: "msg" }  // on failure
//
// The JS caller should always check .error before using .result:
//
//	const res = circl.hybrid.sign(privKey, msg);
//	if (res.error) {
//	    console.error("sign failed:", res.error);
//	} else {
//	    useSignature(res.result);
//	}
//
// # Constants
//
// Each namespace also exposes numeric constants for buffer sizing:
//
//	circl.hybrid.PublicKeySize      // 1408 — byte length of a hybrid public key
//	circl.hybrid.PrivateKeySize     // 4064 — byte length of a hybrid private key
//	circl.hybrid.SeedSize           // 160  — byte length of expanded seed for newKeyFromSeed
//	circl.hybrid.BaseSeedSize       // 64   — byte length of base seed for expandSeed
//	circl.hybrid.SigLength          // 52374 — byte length of a full signature
//	circl.hybrid.CompactSigLength   // 2517 — byte length of a compact signature
//	circl.hybrid.CryptoMsgLength    // 32   — required message length
//
//	circl.hybrid5.PublicKeySize     // 2688 — byte length of a hybrid5 public key
//	circl.hybrid5.PrivateKeySize    // 7680 — byte length of a hybrid5 private key
//	circl.hybrid5.SeedSize          // 160  — byte length of expanded seed for newKeyFromSeed
//	circl.hybrid5.BaseSeedSize      // 72   — byte length of base seed for expandSeed
//	circl.hybrid5.SigLength         // 34486 — byte length of a full signature
//	circl.hybrid5.CryptoMsgLength   // 32   — required message length
package wasm

import (
	"crypto/rand"
	"fmt"
	"syscall/js"

	hybrid "github.com/quantumcoinproject/circl/sign/hybridedmldsaslhdsa"
	hybrid5 "github.com/quantumcoinproject/circl/sign/hybridedmldsaslhdsa5"
	hybrideds "github.com/quantumcoinproject/circl/sign/hybrideds"
)

// uint8ArrayToBytes converts a JavaScript Uint8Array (js.Value) into a Go []byte.
func uint8ArrayToBytes(v js.Value) []byte {
	buf := make([]byte, v.Get("length").Int())
	js.CopyBytesToGo(buf, v)
	return buf
}

// bytesToUint8Array converts a Go []byte into a JavaScript Uint8Array (js.Value).
func bytesToUint8Array(b []byte) js.Value {
	a := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(a, b)
	return a
}

// jsResult wraps a successful value into {result: val, error: null}.
func jsResult(val any) any {
	obj := js.Global().Get("Object").New()
	obj.Set("result", val)
	obj.Set("error", js.Null())
	return obj
}

// jsError wraps an error into {result: null, error: "message"}.
func jsError(err error) any {
	obj := js.Global().Get("Object").New()
	obj.Set("result", js.Null())
	obj.Set("error", err.Error())
	return obj
}

// jsErrorStr wraps an error string into {result: null, error: "message"}.
func jsErrorStr(msg string) any {
	obj := js.Global().Get("Object").New()
	obj.Set("result", js.Null())
	obj.Set("error", msg)
	return obj
}

// checkArgs returns a jsErrorStr result if args is nil or has fewer than n
// elements, or nil if the check passes. fnName is included in the error
// message for easy JS-side debugging.
func checkArgs(fnName string, args []js.Value, n int) any {
	if args == nil || len(args) < n {
		got := 0
		if args != nil {
			got = len(args)
		}
		return jsErrorStr(fmt.Sprintf("%s: expected %d argument(s), got %d", fnName, n, got))
	}
	return nil
}

// marshalKeyPair serializes a public/private key pair into a JS object
// {publicKey: Uint8Array, privateKey: Uint8Array}. Works for both hybrid and
// hybrid5 key types via the MarshalBinary interface.
func marshalKeyPair(pubKey, privKey interface {
	MarshalBinary() ([]byte, error)
}) (js.Value, error) {
	pubBytes, err := pubKey.MarshalBinary()
	if err != nil {
		return js.Undefined(), err
	}
	privBytes, err := privKey.MarshalBinary()
	if err != nil {
		return js.Undefined(), err
	}
	result := js.Global().Get("Object").New()
	result.Set("publicKey", bytesToUint8Array(pubBytes))
	result.Set("privateKey", bytesToUint8Array(privBytes))
	return result, nil
}

// ===========================================================================
// hybridedmldsaslhdsa — Ed25519 + ML-DSA-44 + SLH-DSA-SHAKE-256f
//
// Provides two signing modes:
//   - Full:    signs with all three algorithms (Ed25519, ML-DSA-44, SLH-DSA).
//   - Compact: signs with Ed25519 + ML-DSA-44 only; the SLH-DSA key is kept
//     as a breakglass fallback if Ed25519/ML-DSA are ever compromised.
// ===========================================================================

// hybridGenerateKey generates a random key pair using crypto/rand.
//
// JS: circl.hybrid.generateKey() -> {result: {publicKey, privateKey}, error: null}
//
// No arguments. Returns error result on internal RNG failure.
func hybridGenerateKey(_ js.Value, _ []js.Value) any {
	pub, priv, err := hybrid.GenerateKey(rand.Reader)
	if err != nil {
		return jsError(err)
	}
	kp, err := marshalKeyPair(pub, priv)
	if err != nil {
		return jsError(err)
	}
	return jsResult(kp)
}

// hybridNewKeyFromSeed derives a deterministic key pair from a seed.
//
// JS: circl.hybrid.newKeyFromSeed(seed: Uint8Array) -> {result: {publicKey, privateKey}, error: null}
//
// seed must be exactly hybrid.SeedSize bytes (160). The same seed always
// produces the same key pair. Returns error result if the seed is the wrong
// length.
func hybridNewKeyFromSeed(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrid.newKeyFromSeed", args, 1); errResult != nil {
		return errResult
	}
	seedBytes := uint8ArrayToBytes(args[0])
	var seed [hybrid.SeedSize]byte
	copy(seed[:], seedBytes)
	pub, priv, err := hybrid.NewKeyFromSeed(&seed)
	if err != nil {
		return jsError(err)
	}
	kp, err := marshalKeyPair(pub, priv)
	if err != nil {
		return jsError(err)
	}
	return jsResult(kp)
}

// hybridSign produces a full hybrid signature (Ed25519 + ML-DSA-44 + SLH-DSA)
// over a 32-byte message.
//
// JS: circl.hybrid.sign(privateKey: Uint8Array, message: Uint8Array) -> {result: Uint8Array, error: null}
//
// privateKey must be hybrid.PrivateKeySize bytes. message must be exactly 32
// bytes. Returns a signature of hybrid.SigLength bytes in result. Returns
// error result on any validation or signing error.
func hybridSign(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrid.sign", args, 2); errResult != nil {
		return errResult
	}
	privKeyBytes := uint8ArrayToBytes(args[0])
	msg := uint8ArrayToBytes(args[1])
	priv, err := hybrid.UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return jsError(err)
	}
	sig, err := hybrid.Sign(priv, rand.Reader, msg)
	if err != nil {
		return jsError(err)
	}
	return jsResult(bytesToUint8Array(sig))
}

// hybridVerify checks a full hybrid signature against a public key and message.
//
// JS: circl.hybrid.verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) -> {result: boolean, error: null}
//
// publicKey must be hybrid.PublicKeySize bytes. message must be exactly 32
// bytes. signature must be hybrid.SigLength bytes. Returns boolean in result.
// Returns error result if publicKey cannot be parsed.
func hybridVerify(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrid.verify", args, 3); errResult != nil {
		return errResult
	}
	pubKeyBytes := uint8ArrayToBytes(args[0])
	msg := uint8ArrayToBytes(args[1])
	sig := uint8ArrayToBytes(args[2])
	pub, err := hybrid.UnmarshalPublicKey(pubKeyBytes)
	if err != nil {
		return jsError(err)
	}
	return jsResult(hybrid.Verify(pub, msg, sig))
}

// hybridSignCompact produces a compact signature (Ed25519 + ML-DSA-44 only,
// no SLH-DSA component). Smaller and faster than a full signature.
//
// JS: circl.hybrid.signCompact(privateKey: Uint8Array, message: Uint8Array) -> {result: Uint8Array, error: null}
//
// privateKey must be hybrid.PrivateKeySize bytes. message must be exactly 32
// bytes. Returns a signature of hybrid.CompactSigLength bytes in result.
// Returns error result on error.
func hybridSignCompact(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrid.signCompact", args, 2); errResult != nil {
		return errResult
	}
	privKeyBytes := uint8ArrayToBytes(args[0])
	msg := uint8ArrayToBytes(args[1])
	priv, err := hybrid.UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return jsError(err)
	}
	sig, err := hybrid.SignCompact(priv, rand.Reader, msg)
	if err != nil {
		return jsError(err)
	}
	return jsResult(bytesToUint8Array(sig))
}

// hybridVerifyCompact checks a compact signature (Ed25519 + ML-DSA-44 only).
//
// JS: circl.hybrid.verifyCompact(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) -> {result: boolean, error: null}
//
// publicKey must be hybrid.PublicKeySize bytes. message must be exactly 32
// bytes. signature must be hybrid.CompactSigLength bytes. Returns boolean in
// result. Returns error result if publicKey cannot be parsed.
func hybridVerifyCompact(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrid.verifyCompact", args, 3); errResult != nil {
		return errResult
	}
	pubKeyBytes := uint8ArrayToBytes(args[0])
	msg := uint8ArrayToBytes(args[1])
	sig := uint8ArrayToBytes(args[2])
	pub, err := hybrid.UnmarshalPublicKey(pubKeyBytes)
	if err != nil {
		return jsError(err)
	}
	return jsResult(hybrid.VerifyCompact(pub, msg, sig))
}

// hybridGetPublicKey extracts the public key from a private key.
//
// JS: circl.hybrid.getPublicKey(privateKey: Uint8Array) -> {result: Uint8Array, error: null}
//
// privateKey must be hybrid.PrivateKeySize bytes. Returns hybrid.PublicKeySize
// bytes in result. Returns error result if the private key is malformed.
func hybridGetPublicKey(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrid.getPublicKey", args, 1); errResult != nil {
		return errResult
	}
	privKeyBytes := uint8ArrayToBytes(args[0])
	priv, err := hybrid.UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return jsError(err)
	}
	pub, err := priv.GetPublicKey()
	if err != nil {
		return jsError(err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return jsError(err)
	}
	return jsResult(bytesToUint8Array(pubBytes))
}

// hybridUnmarshalPublicKey validates and round-trips a raw public key.
//
// JS: circl.hybrid.unmarshalPublicKey(data: Uint8Array) -> {result: Uint8Array, error: null}
//
// data must be exactly hybrid.PublicKeySize bytes. Returns error result if
// invalid. Returns the validated key bytes (same content, freshly allocated)
// in result.
func hybridUnmarshalPublicKey(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrid.unmarshalPublicKey", args, 1); errResult != nil {
		return errResult
	}
	data := uint8ArrayToBytes(args[0])
	pub, err := hybrid.UnmarshalPublicKey(data)
	if err != nil {
		return jsError(err)
	}
	result, err := pub.MarshalBinary()
	if err != nil {
		return jsError(err)
	}
	return jsResult(bytesToUint8Array(result))
}

// hybridUnmarshalPrivateKey validates and round-trips a raw private key.
//
// JS: circl.hybrid.unmarshalPrivateKey(data: Uint8Array) -> {result: Uint8Array, error: null}
//
// data must be exactly hybrid.PrivateKeySize bytes. Returns error result if
// invalid. Returns the validated key bytes (same content, freshly allocated)
// in result.
func hybridUnmarshalPrivateKey(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrid.unmarshalPrivateKey", args, 1); errResult != nil {
		return errResult
	}
	data := uint8ArrayToBytes(args[0])
	priv, err := hybrid.UnmarshalPrivateKey(data)
	if err != nil {
		return jsError(err)
	}
	result, err := priv.MarshalBinary()
	if err != nil {
		return jsError(err)
	}
	return jsResult(bytesToUint8Array(result))
}

// hybridExpandSeed expands a short base seed into a full-length seed suitable
// for hybridNewKeyFromSeed, using SHAKE-256 with domain separation string
// "hybrid-ed-ml44-slhshake256f-64-160-v1".
//
// JS: circl.hybrid.expandSeed(baseSeed: Uint8Array) -> {result: Uint8Array, error: null}
//
// baseSeed must be exactly hybrid.BaseSeedSize bytes (64). Returns
// hybrid.SeedSize bytes (160) in result. The base seed MUST originate from a
// CSPRNG. Returns error result on error.
func hybridExpandSeed(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrid.expandSeed", args, 1); errResult != nil {
		return errResult
	}
	baseSeedBytes := uint8ArrayToBytes(args[0])
	var baseSeed [hybrid.BaseSeedSize]byte
	copy(baseSeed[:], baseSeedBytes)
	expanded, err := hybrid.ExpandSeed(baseSeed)
	if err != nil {
		return jsError(err)
	}
	return jsResult(bytesToUint8Array(expanded[:]))
}

// ===========================================================================
// hybridedmldsaslhdsa5 — Ed25519 + ML-DSA-87 + SLH-DSA-SHAKE-256s
//
// Higher-security variant (NIST level 5). Full signing mode only — no compact
// mode is available. Key and signature sizes are larger than the hybrid variant.
// ===========================================================================

// hybrid5GenerateKey generates a random key pair using crypto/rand.
//
// JS: circl.hybrid5.generateKey() -> {result: {publicKey, privateKey}, error: null}
//
// No arguments. Returns error result on internal RNG failure.
func hybrid5GenerateKey(_ js.Value, _ []js.Value) any {
	pub, priv, err := hybrid5.GenerateKey(rand.Reader)
	if err != nil {
		return jsError(err)
	}
	kp, err := marshalKeyPair(pub, priv)
	if err != nil {
		return jsError(err)
	}
	return jsResult(kp)
}

// hybrid5NewKeyFromSeed derives a deterministic key pair from a seed.
//
// JS: circl.hybrid5.newKeyFromSeed(seed: Uint8Array) -> {result: {publicKey, privateKey}, error: null}
//
// seed must be exactly hybrid5.SeedSize bytes (160). The same seed always
// produces the same key pair. Returns error result if the seed is the wrong
// length.
func hybrid5NewKeyFromSeed(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrid5.newKeyFromSeed", args, 1); errResult != nil {
		return errResult
	}
	seedBytes := uint8ArrayToBytes(args[0])
	var seed [hybrid5.SeedSize]byte
	copy(seed[:], seedBytes)
	pub, priv, err := hybrid5.NewKeyFromSeed(&seed)
	if err != nil {
		return jsError(err)
	}
	kp, err := marshalKeyPair(pub, priv)
	if err != nil {
		return jsError(err)
	}
	return jsResult(kp)
}

// hybrid5Sign produces a full hybrid5 signature (Ed25519 + ML-DSA-87 + SLH-DSA)
// over a 32-byte message.
//
// JS: circl.hybrid5.sign(privateKey: Uint8Array, message: Uint8Array) -> {result: Uint8Array, error: null}
//
// privateKey must be hybrid5.PrivateKeySize bytes. message must be exactly 32
// bytes. Returns a signature of hybrid5.SigLength bytes in result. Returns
// error result on error.
func hybrid5Sign(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrid5.sign", args, 2); errResult != nil {
		return errResult
	}
	privKeyBytes := uint8ArrayToBytes(args[0])
	msg := uint8ArrayToBytes(args[1])
	priv, err := hybrid5.UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return jsError(err)
	}
	sig, err := hybrid5.Sign(priv, rand.Reader, msg)
	if err != nil {
		return jsError(err)
	}
	return jsResult(bytesToUint8Array(sig))
}

// hybrid5Verify checks a full hybrid5 signature against a public key and message.
//
// JS: circl.hybrid5.verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) -> {result: boolean, error: null}
//
// publicKey must be hybrid5.PublicKeySize bytes. message must be exactly 32
// bytes. signature must be hybrid5.SigLength bytes. Returns boolean in result.
// Returns error result if publicKey cannot be parsed.
func hybrid5Verify(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrid5.verify", args, 3); errResult != nil {
		return errResult
	}
	pubKeyBytes := uint8ArrayToBytes(args[0])
	msg := uint8ArrayToBytes(args[1])
	sig := uint8ArrayToBytes(args[2])
	pub, err := hybrid5.UnmarshalPublicKey(pubKeyBytes)
	if err != nil {
		return jsError(err)
	}
	return jsResult(hybrid5.Verify(pub, msg, sig))
}

// hybrid5GetPublicKey extracts the public key from a private key.
//
// JS: circl.hybrid5.getPublicKey(privateKey: Uint8Array) -> {result: Uint8Array, error: null}
//
// privateKey must be hybrid5.PrivateKeySize bytes. Returns
// hybrid5.PublicKeySize bytes in result. Returns error result if the private
// key is malformed.
func hybrid5GetPublicKey(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrid5.getPublicKey", args, 1); errResult != nil {
		return errResult
	}
	privKeyBytes := uint8ArrayToBytes(args[0])
	priv, err := hybrid5.UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return jsError(err)
	}
	pub, err := priv.GetPublicKey()
	if err != nil {
		return jsError(err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return jsError(err)
	}
	return jsResult(bytesToUint8Array(pubBytes))
}

// hybrid5UnmarshalPublicKey validates and round-trips a raw public key.
//
// JS: circl.hybrid5.unmarshalPublicKey(data: Uint8Array) -> {result: Uint8Array, error: null}
//
// data must be exactly hybrid5.PublicKeySize bytes. Returns error result if
// invalid. Returns the validated key bytes (same content, freshly allocated)
// in result.
func hybrid5UnmarshalPublicKey(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrid5.unmarshalPublicKey", args, 1); errResult != nil {
		return errResult
	}
	data := uint8ArrayToBytes(args[0])
	pub, err := hybrid5.UnmarshalPublicKey(data)
	if err != nil {
		return jsError(err)
	}
	result, err := pub.MarshalBinary()
	if err != nil {
		return jsError(err)
	}
	return jsResult(bytesToUint8Array(result))
}

// hybrid5UnmarshalPrivateKey validates and round-trips a raw private key.
//
// JS: circl.hybrid5.unmarshalPrivateKey(data: Uint8Array) -> {result: Uint8Array, error: null}
//
// data must be exactly hybrid5.PrivateKeySize bytes. Returns error result if
// invalid. Returns the validated key bytes (same content, freshly allocated)
// in result.
func hybrid5UnmarshalPrivateKey(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrid5.unmarshalPrivateKey", args, 1); errResult != nil {
		return errResult
	}
	data := uint8ArrayToBytes(args[0])
	priv, err := hybrid5.UnmarshalPrivateKey(data)
	if err != nil {
		return jsError(err)
	}
	result, err := priv.MarshalBinary()
	if err != nil {
		return jsError(err)
	}
	return jsResult(bytesToUint8Array(result))
}

// hybrid5ExpandSeed expands a short base seed into a full-length seed suitable
// for hybrid5NewKeyFromSeed, using SHAKE-256 with domain separation string
// "hybrid-ed-ml87-slhshake256s-72-160-v1".
//
// JS: circl.hybrid5.expandSeed(baseSeed: Uint8Array) -> {result: Uint8Array, error: null}
//
// baseSeed must be exactly hybrid5.BaseSeedSize bytes (72). Returns
// hybrid5.SeedSize bytes (160) in result. The base seed MUST originate from a
// CSPRNG. Returns error result on error.
func hybrid5ExpandSeed(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrid5.expandSeed", args, 1); errResult != nil {
		return errResult
	}
	baseSeedBytes := uint8ArrayToBytes(args[0])
	var baseSeed [hybrid5.BaseSeedSize]byte
	copy(baseSeed[:], baseSeedBytes)
	expanded, err := hybrid5.ExpandSeed(baseSeed)
	if err != nil {
		return jsError(err)
	}
	return jsResult(bytesToUint8Array(expanded[:]))
}

// ===========================================================================
// hybrideds — Ed25519 + ML-DSA-44 + SLH-DSA-SHAKE-256f (same algorithms as
// hybridedmldsaslhdsa, different key layout and seed expander)
//
// Provides full and compact signing modes like the hybrid namespace.
// ===========================================================================

// hybridedsGenerateKey generates a random key pair using crypto/rand.
//
// JS: circl.hybrideds.generateKey() -> {result: {publicKey, privateKey}, error: null}
func hybridedsGenerateKey(_ js.Value, _ []js.Value) any {
	pub, priv, err := hybrideds.GenerateKey(rand.Reader)
	if err != nil {
		return jsError(err)
	}
	kp, err := marshalKeyPair(pub, priv)
	if err != nil {
		return jsError(err)
	}
	return jsResult(kp)
}

// hybridedsNewKeyFromSeed derives a deterministic key pair from a seed.
//
// JS: circl.hybrideds.newKeyFromSeed(seed: Uint8Array) -> {result: {publicKey, privateKey}, error: null}
func hybridedsNewKeyFromSeed(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrideds.newKeyFromSeed", args, 1); errResult != nil {
		return errResult
	}
	seedBytes := uint8ArrayToBytes(args[0])
	var seed [hybrideds.SeedSize]byte
	copy(seed[:], seedBytes)
	pub, priv, err := hybrideds.NewKeyFromSeed(&seed)
	if err != nil {
		return jsError(err)
	}
	kp, err := marshalKeyPair(pub, priv)
	if err != nil {
		return jsError(err)
	}
	return jsResult(kp)
}

// hybridedsSign produces a full hybrideds signature over a 32-byte message.
//
// JS: circl.hybrideds.sign(privateKey: Uint8Array, message: Uint8Array) -> {result: Uint8Array, error: null}
func hybridedsSign(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrideds.sign", args, 2); errResult != nil {
		return errResult
	}
	privKeyBytes := uint8ArrayToBytes(args[0])
	msg := uint8ArrayToBytes(args[1])
	priv, err := hybrideds.UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return jsError(err)
	}
	sig, err := hybrideds.Sign(priv, rand.Reader, msg)
	if err != nil {
		return jsError(err)
	}
	return jsResult(bytesToUint8Array(sig))
}

// hybridedsVerify checks a full hybrideds signature.
//
// JS: circl.hybrideds.verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) -> {result: boolean, error: null}
func hybridedsVerify(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrideds.verify", args, 3); errResult != nil {
		return errResult
	}
	pubKeyBytes := uint8ArrayToBytes(args[0])
	msg := uint8ArrayToBytes(args[1])
	sig := uint8ArrayToBytes(args[2])
	pub, err := hybrideds.UnmarshalPublicKey(pubKeyBytes)
	if err != nil {
		return jsError(err)
	}
	return jsResult(hybrideds.Verify(pub, msg, sig))
}

// hybridedsSignCompact produces a compact signature (Ed25519 + ML-DSA-44 only).
//
// JS: circl.hybrideds.signCompact(privateKey: Uint8Array, message: Uint8Array) -> {result: Uint8Array, error: null}
func hybridedsSignCompact(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrideds.signCompact", args, 2); errResult != nil {
		return errResult
	}
	privKeyBytes := uint8ArrayToBytes(args[0])
	msg := uint8ArrayToBytes(args[1])
	priv, err := hybrideds.UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return jsError(err)
	}
	sig, err := hybrideds.SignCompact(priv, rand.Reader, msg)
	if err != nil {
		return jsError(err)
	}
	return jsResult(bytesToUint8Array(sig))
}

// hybridedsVerifyCompact checks a compact hybrideds signature.
//
// JS: circl.hybrideds.verifyCompact(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) -> {result: boolean, error: null}
func hybridedsVerifyCompact(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrideds.verifyCompact", args, 3); errResult != nil {
		return errResult
	}
	pubKeyBytes := uint8ArrayToBytes(args[0])
	msg := uint8ArrayToBytes(args[1])
	sig := uint8ArrayToBytes(args[2])
	pub, err := hybrideds.UnmarshalPublicKey(pubKeyBytes)
	if err != nil {
		return jsError(err)
	}
	return jsResult(hybrideds.VerifyCompact(pub, msg, sig))
}

// hybridedsGetPublicKey extracts the public key from a private key.
//
// JS: circl.hybrideds.getPublicKey(privateKey: Uint8Array) -> {result: Uint8Array, error: null}
func hybridedsGetPublicKey(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrideds.getPublicKey", args, 1); errResult != nil {
		return errResult
	}
	privKeyBytes := uint8ArrayToBytes(args[0])
	priv, err := hybrideds.UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return jsError(err)
	}
	pub, err := priv.GetPublicKey()
	if err != nil {
		return jsError(err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return jsError(err)
	}
	return jsResult(bytesToUint8Array(pubBytes))
}

// hybridedsUnmarshalPublicKey validates and round-trips a raw public key.
//
// JS: circl.hybrideds.unmarshalPublicKey(data: Uint8Array) -> {result: Uint8Array, error: null}
func hybridedsUnmarshalPublicKey(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrideds.unmarshalPublicKey", args, 1); errResult != nil {
		return errResult
	}
	data := uint8ArrayToBytes(args[0])
	pub, err := hybrideds.UnmarshalPublicKey(data)
	if err != nil {
		return jsError(err)
	}
	result, err := pub.MarshalBinary()
	if err != nil {
		return jsError(err)
	}
	return jsResult(bytesToUint8Array(result))
}

// hybridedsUnmarshalPrivateKey validates and round-trips a raw private key.
//
// JS: circl.hybrideds.unmarshalPrivateKey(data: Uint8Array) -> {result: Uint8Array, error: null}
func hybridedsUnmarshalPrivateKey(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrideds.unmarshalPrivateKey", args, 1); errResult != nil {
		return errResult
	}
	data := uint8ArrayToBytes(args[0])
	priv, err := hybrideds.UnmarshalPrivateKey(data)
	if err != nil {
		return jsError(err)
	}
	result, err := priv.MarshalBinary()
	if err != nil {
		return jsError(err)
	}
	return jsResult(bytesToUint8Array(result))
}

// hybridedsExpandSeed expands a base seed into a full-length seed for newKeyFromSeed.
//
// JS: circl.hybrideds.expandSeed(baseSeed: Uint8Array) -> {result: Uint8Array, error: null}
func hybridedsExpandSeed(_ js.Value, args []js.Value) any {
	if errResult := checkArgs("hybrideds.expandSeed", args, 1); errResult != nil {
		return errResult
	}
	baseSeedBytes := uint8ArrayToBytes(args[0])
	var baseSeed [hybrideds.BaseSeedSize]byte
	copy(baseSeed[:], baseSeedBytes)
	expanded, err := hybrideds.ExpandSeed(baseSeed)
	if err != nil {
		return jsError(err)
	}
	return jsResult(bytesToUint8Array(expanded[:]))
}

// ---------------------------------------------------------------------------
// Register exposes all functions and constants to JavaScript.
//
// After calling Register(), the following namespace is available on
// globalThis.circl. Every function returns {result, error} — see package doc.
//
//	circl.hybrid.generateKey()                          -> {result: {publicKey, privateKey}, error}
//	circl.hybrid.newKeyFromSeed(seed)                   -> {result: {publicKey, privateKey}, error}
//	circl.hybrid.sign(privateKey, message)              -> {result: Uint8Array, error}
//	circl.hybrid.verify(publicKey, message, sig)        -> {result: boolean, error}
//	circl.hybrid.signCompact(privateKey, message)       -> {result: Uint8Array, error}
//	circl.hybrid.verifyCompact(publicKey, message, sig) -> {result: boolean, error}
//	circl.hybrid.getPublicKey(privateKey)               -> {result: Uint8Array, error}
//	circl.hybrid.unmarshalPublicKey(data)               -> {result: Uint8Array, error}
//	circl.hybrid.unmarshalPrivateKey(data)              -> {result: Uint8Array, error}
//	circl.hybrid.expandSeed(baseSeed)                   -> {result: Uint8Array, error}
//	circl.hybrid.PublicKeySize                          (number)
//	circl.hybrid.PrivateKeySize                         (number)
//	circl.hybrid.SeedSize                               (number)
//	circl.hybrid.BaseSeedSize                           (number)
//	circl.hybrid.SigLength                              (number)
//	circl.hybrid.CompactSigLength                       (number)
//	circl.hybrid.CryptoMsgLength                        (number)
//
//	circl.hybrid5.generateKey()                         -> {result: {publicKey, privateKey}, error}
//	circl.hybrid5.newKeyFromSeed(seed)                  -> {result: {publicKey, privateKey}, error}
//	circl.hybrid5.sign(privateKey, message)             -> {result: Uint8Array, error}
//	circl.hybrid5.verify(publicKey, message, sig)       -> {result: boolean, error}
//	circl.hybrid5.getPublicKey(privateKey)              -> {result: Uint8Array, error}
//	circl.hybrid5.unmarshalPublicKey(data)              -> {result: Uint8Array, error}
//	circl.hybrid5.unmarshalPrivateKey(data)             -> {result: Uint8Array, error}
//	circl.hybrid5.expandSeed(baseSeed)                  -> {result: Uint8Array, error}
//	circl.hybrid5.PublicKeySize                         (number)
//	circl.hybrid5.PrivateKeySize                        (number)
//	circl.hybrid5.SeedSize                              (number)
//	circl.hybrid5.BaseSeedSize                          (number)
//	circl.hybrid5.SigLength                             (number)
//	circl.hybrid5.CryptoMsgLength                       (number)
//
//	circl.hybrideds.generateKey()                       -> {result: {publicKey, privateKey}, error}
//	circl.hybrideds.newKeyFromSeed(seed)                -> {result: {publicKey, privateKey}, error}
//	circl.hybrideds.sign(privateKey, message)           -> {result: Uint8Array, error}
//	circl.hybrideds.verify(publicKey, message, sig)     -> {result: boolean, error}
//	circl.hybrideds.signCompact(privateKey, message)   -> {result: Uint8Array, error}
//	circl.hybrideds.verifyCompact(publicKey, message, sig) -> {result: boolean, error}
//	circl.hybrideds.getPublicKey(privateKey)           -> {result: Uint8Array, error}
//	circl.hybrideds.unmarshalPublicKey(data)            -> {result: Uint8Array, error}
//	circl.hybrideds.unmarshalPrivateKey(data)          -> {result: Uint8Array, error}
//	circl.hybrideds.expandSeed(baseSeed)               -> {result: Uint8Array, error}
//	circl.hybrideds.PublicKeySize, .PrivateKeySize, .SeedSize, .BaseSeedSize
//	circl.hybrideds.SigLength, .CompactSigLength, .CryptoMsgLength          (number)
//
// # Utilities
//
//	circl.cryptoRandom(size) -> {result: Uint8Array, error}  — CSPRNG bytes from crypto/rand
// ---------------------------------------------------------------------------

// cryptoRandom fills a byte array of the given size with cryptographically secure
// random bytes from crypto/rand.
//
// JS: circl.cryptoRandom(size: number) -> {result: Uint8Array, error: null}
//
// size must be a non-negative integer. Returns error if size is invalid or
// crypto/rand fails. Maximum allowed size is 1048576 (1 MiB).
func cryptoRandom(_ js.Value, args []js.Value) any {
	const maxSize = 1048576
	if errResult := checkArgs("cryptoRandom", args, 1); errResult != nil {
		return errResult
	}
	n := args[0].Int()
	if n < 0 {
		return jsErrorStr("cryptoRandom: size must be non-negative")
	}
	if n > maxSize {
		return jsErrorStr(fmt.Sprintf("cryptoRandom: size must be at most %d", maxSize))
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return jsError(err)
	}
	return jsResult(bytesToUint8Array(b))
}

func Register() {
	hybridNS := js.Global().Get("Object").New()
	hybridNS.Set("generateKey", js.FuncOf(hybridGenerateKey))
	hybridNS.Set("newKeyFromSeed", js.FuncOf(hybridNewKeyFromSeed))
	hybridNS.Set("sign", js.FuncOf(hybridSign))
	hybridNS.Set("verify", js.FuncOf(hybridVerify))
	hybridNS.Set("signCompact", js.FuncOf(hybridSignCompact))
	hybridNS.Set("verifyCompact", js.FuncOf(hybridVerifyCompact))
	hybridNS.Set("getPublicKey", js.FuncOf(hybridGetPublicKey))
	hybridNS.Set("unmarshalPublicKey", js.FuncOf(hybridUnmarshalPublicKey))
	hybridNS.Set("unmarshalPrivateKey", js.FuncOf(hybridUnmarshalPrivateKey))
	hybridNS.Set("expandSeed", js.FuncOf(hybridExpandSeed))
	hybridNS.Set("PublicKeySize", hybrid.PublicKeySize)
	hybridNS.Set("PrivateKeySize", hybrid.PrivateKeySize)
	hybridNS.Set("SeedSize", hybrid.SeedSize)
	hybridNS.Set("SigLength", hybrid.SigLength)
	hybridNS.Set("CompactSigLength", hybrid.CompactSigLength)
	hybridNS.Set("BaseSeedSize", hybrid.BaseSeedSize)
	hybridNS.Set("CryptoMsgLength", hybrid.CRYPTO_MSG_LENGTH)

	hybrid5NS := js.Global().Get("Object").New()
	hybrid5NS.Set("generateKey", js.FuncOf(hybrid5GenerateKey))
	hybrid5NS.Set("newKeyFromSeed", js.FuncOf(hybrid5NewKeyFromSeed))
	hybrid5NS.Set("sign", js.FuncOf(hybrid5Sign))
	hybrid5NS.Set("verify", js.FuncOf(hybrid5Verify))
	hybrid5NS.Set("getPublicKey", js.FuncOf(hybrid5GetPublicKey))
	hybrid5NS.Set("unmarshalPublicKey", js.FuncOf(hybrid5UnmarshalPublicKey))
	hybrid5NS.Set("unmarshalPrivateKey", js.FuncOf(hybrid5UnmarshalPrivateKey))
	hybrid5NS.Set("expandSeed", js.FuncOf(hybrid5ExpandSeed))
	hybrid5NS.Set("PublicKeySize", hybrid5.PublicKeySize)
	hybrid5NS.Set("PrivateKeySize", hybrid5.PrivateKeySize)
	hybrid5NS.Set("SeedSize", hybrid5.SeedSize)
	hybrid5NS.Set("SigLength", hybrid5.SigLength)
	hybrid5NS.Set("BaseSeedSize", hybrid5.BaseSeedSize)
	hybrid5NS.Set("CryptoMsgLength", hybrid5.CRYPTO_MSG_LENGTH)

	hybridedsNS := js.Global().Get("Object").New()
	hybridedsNS.Set("generateKey", js.FuncOf(hybridedsGenerateKey))
	hybridedsNS.Set("newKeyFromSeed", js.FuncOf(hybridedsNewKeyFromSeed))
	hybridedsNS.Set("sign", js.FuncOf(hybridedsSign))
	hybridedsNS.Set("verify", js.FuncOf(hybridedsVerify))
	hybridedsNS.Set("signCompact", js.FuncOf(hybridedsSignCompact))
	hybridedsNS.Set("verifyCompact", js.FuncOf(hybridedsVerifyCompact))
	hybridedsNS.Set("getPublicKey", js.FuncOf(hybridedsGetPublicKey))
	hybridedsNS.Set("unmarshalPublicKey", js.FuncOf(hybridedsUnmarshalPublicKey))
	hybridedsNS.Set("unmarshalPrivateKey", js.FuncOf(hybridedsUnmarshalPrivateKey))
	hybridedsNS.Set("expandSeed", js.FuncOf(hybridedsExpandSeed))
	hybridedsNS.Set("PublicKeySize", hybrideds.PublicKeySize)
	hybridedsNS.Set("PrivateKeySize", hybrideds.PrivateKeySize)
	hybridedsNS.Set("SeedSize", hybrideds.SeedSize)
	hybridedsNS.Set("BaseSeedSize", hybrideds.BaseSeedSize)
	hybridedsNS.Set("SigLength", hybrideds.SigLength)
	hybridedsNS.Set("CompactSigLength", hybrideds.CompactSigLength)
	hybridedsNS.Set("CryptoMsgLength", hybrideds.CRYPTO_MSG_LENGTH)

	circlNS := js.Global().Get("Object").New()
	circlNS.Set("hybridedmldsaslhdsa", hybridNS)
	circlNS.Set("hybridedmldsaslhds5", hybrid5NS)
	circlNS.Set("hybrideds", hybridedsNS)
	circlNS.Set("cryptoRandom", js.FuncOf(cryptoRandom))
	js.Global().Set("circl", circlNS)
}
