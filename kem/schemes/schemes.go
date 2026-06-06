// Package schemes contains a register of KEM schemes.
//
// # Schemes Implemented
//
// Post-quantum kems:
//
//	ML-KEM-512, ML-KEM-768, ML-KEM-1024
//
// Hybrid kems:
//
//	X25519MLKEM768
package schemes

import (
	"strings"

	"github.com/quantumcoinproject/circl/kem"
	"github.com/quantumcoinproject/circl/kem/hybrid"
	"github.com/quantumcoinproject/circl/kem/mlkem/mlkem1024"
	"github.com/quantumcoinproject/circl/kem/mlkem/mlkem512"
	"github.com/quantumcoinproject/circl/kem/mlkem/mlkem768"
)

var allSchemes = [...]kem.Scheme{
	mlkem512.Scheme(),
	mlkem768.Scheme(),
	mlkem1024.Scheme(),
	hybrid.X25519MLKEM768(),
}

var allSchemeNames map[string]kem.Scheme

func init() {
	allSchemeNames = make(map[string]kem.Scheme)
	for _, scheme := range allSchemes {
		allSchemeNames[strings.ToLower(scheme.Name())] = scheme
	}
}

// ByName returns the scheme with the given name and nil if it is not
// supported.
//
// Names are case insensitive.
func ByName(name string) kem.Scheme {
	return allSchemeNames[strings.ToLower(name)]
}

// All returns all KEM schemes supported.
func All() []kem.Scheme { a := allSchemes; return a[:] }
