package internal

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	common "github.com/quantumcoinproject/circl/sign/internal/dilithium"
)

// TestExpandMaskNoRepeatStructure guards the masking-vector (y / "nonce")
// expansion against the bug classes in Bernstein, "Exploiting ML-DSA bugs"
// (2026-06-01): the AABBCC, A0B0C0 and ABABCDCD coefficient patterns that a
// copy/paste typo in PolyUnpackLeGamma1 (the gamma1 BitUnpack) can produce, plus
// any other low-entropy/cleared expansion. Such a bug yields signatures that
// still verify and interoperate, yet leak the long-term secret because a
// signature reveals z = c*s + y: structure or repetition in y turns this into
// solvable linear equations for s.
//
// Two independent layers:
//  1. Structural assertions on the security property itself (range; no excess
//     equal coefficients at lag 1 or lag 2; no single value dominating). These
//     hold regardless of reference vectors, so they still fire even if someone
//     regenerates a known-answer vector after introducing a bug.
//  2. A pinned checksum of the full ExpandMask output, so any change to the
//     expansion is caught (mirrors the deterministic ACVP sigGen KATs, which
//     the paper identifies as the defense most libraries lack).
func TestExpandMaskNoRepeatStructure(t *testing.T) {
	var seed [64]byte
	for i := range seed {
		seed[i] = byte(i)
	}

	var v VecL
	VecLDeriveUniformLeGamma1(&v, &seed, 0)

	for li := 0; li < L; li++ {
		p := &v[li]

		// (1) range: every centered coefficient satisfies |y| <= gamma1.
		for j := 0; j < common.N; j++ {
			c := int64(p[j])
			if c >= int64(common.Q) {
				t.Fatalf("poly %d coeff %d not normalized: %d", li, j, c)
			}
			if c > int64(common.Q)/2 {
				c -= int64(common.Q)
			}
			if c < -int64(Gamma1) || c > int64(Gamma1) {
				t.Fatalf("poly %d coeff %d outside (-gamma1,gamma1]: %d", li, j, c)
			}
		}

		// (2) lag-1 equal pairs catch AABBCC (and A0B0C0's adjacent equalities);
		// lag-2 equal pairs catch ABABCDCD. For correct output the expected
		// count is ~N/(2*gamma1) << 1; the buggy patterns produce ~128. The
		// threshold 16 is far above statistical noise and far below an attack.
		lag1, lag2 := 0, 0
		for j := 0; j+1 < common.N; j++ {
			if p[j] == p[j+1] {
				lag1++
			}
		}
		for j := 0; j+2 < common.N; j++ {
			if p[j] == p[j+2] {
				lag2++
			}
		}
		if lag1 > 16 {
			t.Fatalf("poly %d: %d equal adjacent coefficients (AABBCC-like); want few", li, lag1)
		}
		if lag2 > 16 {
			t.Fatalf("poly %d: %d equal lag-2 coefficients (ABABCDCD-like); want few", li, lag2)
		}

		// (3) no single value dominates (A0B0C0 / cleared expansion repeat one
		// constant ~128 times). For correct output the max multiplicity is ~2.
		counts := make(map[uint32]int, common.N)
		maxMult := 0
		for j := 0; j < common.N; j++ {
			counts[p[j]]++
			if counts[p[j]] > maxMult {
				maxMult = counts[p[j]]
			}
		}
		if maxMult > 16 {
			t.Fatalf("poly %d: a coefficient value repeats %d times (A0B0C0/cleared-like); want few", li, maxMult)
		}
	}

	// (4) pinned checksum of the whole expansion. If this changes, either a bug
	// was introduced or the expansion was intentionally altered; in the latter
	// case verify against FIPS 204 / ACVP sigGen and update want.
	h := sha256.New()
	var b [4]byte
	for li := 0; li < L; li++ {
		for j := 0; j < common.N; j++ {
			binary.LittleEndian.PutUint32(b[:], v[li][j])
			_, _ = h.Write(b[:])
		}
	}
	got := hex.EncodeToString(h.Sum(nil))
	const want = "90d2b12d54f631dce496d2dba4bbf3683d97909b1cca73fbe02f8a50bf24a526"
	if got != want {
		t.Fatalf("ExpandMask checksum mismatch: got %s want %s", got, want)
	}
}
