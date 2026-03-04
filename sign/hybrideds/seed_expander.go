package hybrideds

import (
	"github.com/quantumcoinproject/circl/internal/sha3"
	"github.com/quantumcoinproject/circl/sign/ed25519"
	"github.com/quantumcoinproject/circl/sign/mldsa/mldsa44"
)

const (
	AbsorbSize         = 64      // bytes fed to SHAKE256 (32 entropy bytes at even indices, interleaved with zeros)
	SqueezeSize        = 128     // bytes squeezed from SHAKE256; must be >= ed25519.SeedSize + SeedSizeSlhDsa
	SeedExpanderDomain = byte(2) // ad-hoc domain separation byte appended after the absorb block (not cSHAKE)
	BaseSeedSize       = 96      // input seed length: 64 (XOF material) + 32 (ML-DSA-44 pass-through)
)

// ExpandSeed derives a 160-byte hybrid seed from a 96-byte base seed for
// ML-DSA-44 + Ed25519 + SLH-DSA-SHAKE-256f key generation.
//
// Blockchain use only: this expander is intended solely for expanding an input
// seed (typically mapped from mnemonics or seed phrases) into an output seed
// used to generate hybrid-signature wallet keypairs. The expansion is
// deterministic and domain-separated. Do not use for other purposes; the
// construction has not been analyzed for use outside this blockchain
// key-derivation workflow.
//
// Use only when a shorter seed is needed (e.g., derived from a mnemonic);
// otherwise generate a full 160-byte seed directly from a CSPRNG.
//
// Input (baseSeed, 96 bytes):
//
//	baseSeed[0:64]  — XOF source material. CAUTION: only the 32 bytes at
//	                  even indices (0, 2, …, 62) enter the XOF; the 32 bytes
//	                  at odd indices are silently discarded. This is legacy
//	                  behavior retained for backward compatibility.
//	baseSeed[64:96] — Copied verbatim as the ML-DSA-44 sub-seed (not
//	                  processed through the XOF).
//
// Expansion (SHAKE256):
//
//  1. Build a 64-byte absorb block: seedInput[i] = baseSeed[i] for
//     i ∈ {0, 2, …, 62}; all other bytes are 0x00.
//  2. Absorb into SHAKE256: seedInput ‖ 0x02 (ad-hoc domain separator).
//  3. Squeeze 128 bytes.
//
// Output layout (expandedSeed, 160 bytes):
//
//	[  0: 32) = squeezed[ 0: 32] — Ed25519 seed
//	[ 32: 64) = baseSeed[64: 96] — ML-DSA-44 seed (pass-through)
//	[ 64:160) = squeezed[32:128] — SLH-DSA seed (SK.seed ‖ SK.prf ‖ PK.seed)
//
// Design notes:
//   - ML-DSA-44 uses a pass-through seed so that one post-quantum component
//     retains full security even if SHAKE256 is weakened.
//   - Ed25519 and SLH-DSA seeds are both derived from the same SHAKE256
//     instance. Under the random-oracle model the two outputs are
//     computationally independent; a non-RO structural weakness in SHAKE256
//     could, in principle, correlate them.
//   - SLH-DSA exposes PK.seed in the public key. Deriving it through the
//     XOF prevents leaking raw baseSeed bytes.
//
// Security:
//   - baseSeed MUST originate from a CSPRNG (or a KDF with >= 256 bits of
//     min-entropy).
//   - Effective entropy into the XOF is 256 bits (32 bytes), matching
//     SHAKE256's 256-bit security level.
//   - 32 of the 64 XOF-source bytes (odd indices) are discarded — callers
//     must not assume all 96 input bytes influence the output.
//   - Sensitive intermediates are zeroized in a deferred closure. Go does
//     not formally guarantee that dead stores survive optimization; in
//     practice gc and gccgo retain writes inside deferred closures.
func ExpandSeed(baseSeed [BaseSeedSize]byte) (expandedSeed [SeedSize]byte, err error) {
	var squeezed [SqueezeSize]byte
	var seedInput [AbsorbSize]byte

	h := sha3.NewShake256()

	// Zeroize sensitive intermediates on return (baseSeed is a value-copy).
	defer func() {
		h.Reset()
		for i := range baseSeed {
			baseSeed[i] = 0
		}
		for i := range squeezed {
			squeezed[i] = 0
		}
		for i := range seedInput {
			seedInput[i] = 0
		}
	}()

	// Legacy interleaving: copy baseSeed[0], [2], …, [62] into even positions;
	// odd positions remain 0x00. Absorbs 32 bytes of entropy in 64 bytes of input.
	for i := 0; i < AbsorbSize; i += 2 {
		seedInput[i] = baseSeed[i]
	}

	_, err = h.Write(seedInput[:])
	if err != nil {
		return expandedSeed, err
	}

	_, err = h.Write([]byte{SeedExpanderDomain})
	if err != nil {
		return expandedSeed, err
	}

	_, err = h.Read(squeezed[:])
	if err != nil {
		// Zero out partially filled expandedSeed on error
		for i := range expandedSeed {
			expandedSeed[i] = 0
		}
		return expandedSeed, err
	}

	copy(expandedSeed[:ed25519.SeedSize], squeezed[:ed25519.SeedSize])                  // [0:32)   ← squeezed[0:32]   (Ed25519)
	copy(expandedSeed[ed25519.SeedSize:], baseSeed[AbsorbSize:])                        // [32:64)  ← baseSeed[64:96]  (ML-DSA-44 pass-through)
	copy(expandedSeed[ed25519.SeedSize+mldsa44.SeedSize:], squeezed[ed25519.SeedSize:]) // [64:160) ← squeezed[32:128] (SLH-DSA)

	return expandedSeed, nil
}
