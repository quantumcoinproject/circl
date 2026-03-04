package hybridedmldsaslhdsa

import (
	"github.com/quantumcoinproject/circl/internal/sha3"
)

const (
	BaseSeedSize       = 64
	SeedExpanderDomain = "hybrid-ed-ml44-slhshake256f-64-160-v1"
)

// ExpandSeed expands a short input seed into the scheme's full seed for
// hybrid key generation.
//
// Blockchain use only: this expander is intended solely for expanding an input
// seed (typically mapped from mnemonics or seed phrases) into an output seed
// used to generate hybrid-signature wallet keypairs. The expansion is
// deterministic and domain-separated. Do not use for other purposes; the
// construction has not been analyzed for use outside this blockchain
// key-derivation workflow.
//
// The input seed MUST be from a CSPRNG (or a KDF with sufficient min-entropy).
func ExpandSeed(baseSeed [BaseSeedSize]byte) (expandedSeed [SeedSize]byte, err error) {
	h := sha3.NewShake256()

	// Ensure sensitive data is zeroed out on return.
	defer func() {
		h.Reset()
		for i := range baseSeed {
			baseSeed[i] = 0
		}
	}()

	// Domain separation
	_, err = h.Write([]byte(SeedExpanderDomain))
	if err != nil {
		return expandedSeed, err
	}

	// Absorb the base seed
	_, err = h.Write(baseSeed[:])
	if err != nil {
		return expandedSeed, err
	}

	// Squeeze the expanded seed
	_, err = h.Read(expandedSeed[:])
	if err != nil {
		// Zero out partially filled expandedSeed on error
		for i := range expandedSeed {
			expandedSeed[i] = 0
		}
		return expandedSeed, err
	}

	return expandedSeed, nil
}
