package hybrideds

// Demonstration of FINDING-000: ExpandSeed silently discards 32 of its 96 input
// bytes, so the base-seed -> key map is not injective and the stated entropy
// precondition is necessary but not sufficient.
//
// Full write-up, entropy accounting and standards assessment:
// audit/FINDING-000-seed-expander-entropy.md
//
// NAMING: this package implements scheme IDs 1-2, which are wire-compatible with
// the NIST PQC Round 3 DRAFTS -- Dilithium2 (CRYSTALS-Dilithium v3.1) and
// SPHINCS+-SHAKE-256f-simple (SPHINCS+ v3.1) -- NOT with the finalized ML-DSA-44
// (FIPS 204) and SLH-DSA-SHAKE-256f (FIPS 205). The Go identifiers mldsa44 and
// slhdsa are reused as code via their Internal / NoContext entry points, which
// reproduce the pre-final wire format. Comments below use the draft names.
//
// SCOPE: this is NOT a break. Assuming a uniformly random base seed -- which is
// what every consumer supplies -- each component still receives seed entropy at
// or above its target security strength, per SP 800-133r2 §5.1 read with the
// security-strength definition in SP 800-57 Pt.1 r5 §5.6.1. No FIPS conformance
// claim is made or available: these are draft algorithms and this is not a
// CMVP-validated module. What the tests below pin down is the exact influence
// map, because the strongest component lands exactly on its target with no headroom
// above it (SPHINCS+-SHAKE-256f-simple is PQC category 5 -- a 256-bit target --
// and receives exactly 256 bits), and because the precondition that actually
// matters is per-position, not aggregate.
//
// NO IMPACT ON THE INTENDED CONSUMERS -- no action required. quantum-coin-go,
// quantum-coin-js-sdk and quantumcoin.js all source base seeds from a CSPRNG
// (crypto/rand, or circl.cryptoRandom which wraps it), which is uniform and
// therefore satisfies the per-position requirement. Planned documentation and
// hardening item, not an incident.
//
// These are CHARACTERIZATION tests asserting today's behaviour, and TRIPWIRES:
// this expander is frozen for wallet backward compatibility, so a failure here
// means the derivation changed and every existing seed phrase would derive a
// different wallet. See the header of
// sign/hybridedmldsaslhdsa/keysubstitution_test.go for the full convention.

import (
	"bytes"
	"testing"
)

// baseSeedPattern returns a 96-byte base seed with every byte distinct enough to
// make positional effects visible.
func baseSeedPattern() [BaseSeedSize]byte {
	var s [BaseSeedSize]byte
	for i := range s {
		s[i] = byte(i + 1)
	}
	return s
}

// TestExpandSeedInfluenceMap establishes exactly which input positions affect the
// output, by flipping one bit in each of the 96 base-seed bytes and recording
// whether the 160-byte expanded seed changes.
//
// Expected: exactly 64 of 96 positions influence the output.
//
//	[0:64) even indices -> 32 positions, absorbed into SHAKE256
//	[0:64) odd  indices -> 32 positions, DISCARDED
//	[64:96)             -> 32 positions, passed through to Dilithium2
//
// 96 input bytes = 768 bits, of which 512 bits reach the construction and 256
// bits are discarded.
func TestExpandSeedInfluenceMap(t *testing.T) {
	const (
		wantInfluencing = 64
		wantDiscarded   = 32
	)

	base := baseSeedPattern()
	ref, err := ExpandSeed(base)
	if err != nil {
		t.Fatalf("ExpandSeed(base): %v", err)
	}

	var influencing, discarded []int
	for i := 0; i < BaseSeedSize; i++ {
		mutated := baseSeedPattern()
		mutated[i] ^= 0x01
		got, err := ExpandSeed(mutated)
		if err != nil {
			t.Fatalf("ExpandSeed(mutated at %d): %v", i, err)
		}
		if bytes.Equal(got[:], ref[:]) {
			discarded = append(discarded, i)
		} else {
			influencing = append(influencing, i)
		}
	}

	if len(influencing) != wantInfluencing || len(discarded) != wantDiscarded {
		t.Fatalf("influence map: %d influencing / %d discarded, want %d / %d",
			len(influencing), len(discarded), wantInfluencing, wantDiscarded)
	}

	// The discarded positions must be exactly the odd indices below AbsorbSize.
	for _, i := range discarded {
		if i >= AbsorbSize || i%2 == 0 {
			t.Errorf("unexpected discarded position %d; expected only odd indices < %d",
				i, AbsorbSize)
		}
	}
	t.Logf("FINDING-000 (expected): %d of %d base-seed bytes reach the construction; "+
		"the %d bytes at odd indices below %d are discarded (%d bits)",
		len(influencing), BaseSeedSize, len(discarded), AbsorbSize, len(discarded)*8)
}

// TestExpandSeedIsNotInjective shows the direct consequence: two DISTINCT base
// seeds produce byte-identical expanded seeds, hence identical wallets.
//
// The seed space therefore collapses by a factor of 2^256: every derived key has
// 2^256 base-seed preimages. This is benign for security under a uniform base
// seed, but it matters for any tooling that treats a base seed as a unique
// wallet identifier, de-duplicates on seed bytes, or round-trips seed -> key ->
// seed expecting to recover the original.
func TestExpandSeedIsNotInjective(t *testing.T) {
	a := baseSeedPattern()

	b := baseSeedPattern()
	for i := 1; i < AbsorbSize; i += 2 { // every discarded position
		b[i] ^= 0xff
	}
	if bytes.Equal(a[:], b[:]) {
		t.Fatal("test setup: seeds should differ")
	}

	expA, err := ExpandSeed(a)
	if err != nil {
		t.Fatalf("ExpandSeed(a): %v", err)
	}
	expB, err := ExpandSeed(b)
	if err != nil {
		t.Fatalf("ExpandSeed(b): %v", err)
	}
	if !bytes.Equal(expA[:], expB[:]) {
		t.Fatal("expanded seeds differ; ExpandSeed has become injective over these " +
			"positions, which would be a WIRE-FORMAT CHANGE breaking every existing " +
			"seed phrase -- see FINDING-000 before changing this")
	}

	// And therefore the same wallet: distinct backups, one set of funds.
	pubA, _, err := NewKeyFromSeed(&expA)
	if err != nil {
		t.Fatalf("NewKeyFromSeed(a): %v", err)
	}
	pubB, _, err := NewKeyFromSeed(&expB)
	if err != nil {
		t.Fatalf("NewKeyFromSeed(b): %v", err)
	}
	rawA, err := pubA.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal a: %v", err)
	}
	rawB, err := pubB.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal b: %v", err)
	}
	if !bytes.Equal(rawA, rawB) {
		t.Error("colliding seeds produced different public keys")
	}
}

// TestExpandSeedBranchIndependence documents the entropy split across the two
// derivation branches, which is what the conformance argument rests on.
//
//	XOF branch      base[0:64) even indices -> Ed25519 seed AND all SPHINCS+ seed
//	                material (SK.seed || SK.prf || PK.seed).  256 bits, SHARED.
//	pass-through    base[64:96)             -> Dilithium2 seed. 256 bits, independent.
//
// The security-relevant consequence is the sharing: a single 256-bit value
// determines two of the three components. Recovering it degrades the hybrid to
// Dilithium2 alone (PQC category 2). That requires 2^256 work under a uniform
// base seed, so it is a margin observation rather than an attack -- but it does
// mean the three components are not independently seeded, which is the premise a
// hybrid construction is usually sold on.
func TestExpandSeedBranchIndependence(t *testing.T) {
	const (
		ed25519Seed = 32 // expanded[0:32)
		mldsaSeed   = 32 // expanded[32:64)
	)
	base := baseSeedPattern()
	ref, err := ExpandSeed(base)
	if err != nil {
		t.Fatalf("ExpandSeed: %v", err)
	}

	// Perturbing the XOF branch must change the Ed25519 and SPHINCS+ regions and
	// leave the Dilithium2 pass-through untouched.
	xofMutated := baseSeedPattern()
	xofMutated[0] ^= 0x01 // an even, absorbed index
	gotXOF, err := ExpandSeed(xofMutated)
	if err != nil {
		t.Fatalf("ExpandSeed(xofMutated): %v", err)
	}
	if bytes.Equal(gotXOF[:ed25519Seed], ref[:ed25519Seed]) {
		t.Error("Ed25519 seed unchanged after perturbing the XOF branch")
	}
	if bytes.Equal(gotXOF[ed25519Seed+mldsaSeed:], ref[ed25519Seed+mldsaSeed:]) {
		t.Error("SPHINCS+ seed unchanged after perturbing the XOF branch")
	}
	if !bytes.Equal(gotXOF[ed25519Seed:ed25519Seed+mldsaSeed], ref[ed25519Seed:ed25519Seed+mldsaSeed]) {
		t.Error("Dilithium2 pass-through changed after perturbing only the XOF branch")
	}

	// Perturbing the pass-through must change ONLY the Dilithium2 region.
	ptMutated := baseSeedPattern()
	ptMutated[AbsorbSize] ^= 0x01
	gotPT, err := ExpandSeed(ptMutated)
	if err != nil {
		t.Fatalf("ExpandSeed(ptMutated): %v", err)
	}
	if !bytes.Equal(gotPT[:ed25519Seed], ref[:ed25519Seed]) {
		t.Error("Ed25519 seed changed after perturbing only the pass-through branch")
	}
	if !bytes.Equal(gotPT[ed25519Seed+mldsaSeed:], ref[ed25519Seed+mldsaSeed:]) {
		t.Error("SPHINCS+ seed changed after perturbing only the pass-through branch")
	}
	if bytes.Equal(gotPT[ed25519Seed:ed25519Seed+mldsaSeed], ref[ed25519Seed:ed25519Seed+mldsaSeed]) {
		t.Error("Dilithium2 pass-through unchanged after perturbing it")
	}
}
