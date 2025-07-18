package hybridedsfull

import (
	"bytes"
	"fmt"
	"github.com/quantumcoinproject/circl/sign/ed25519"
	"github.com/quantumcoinproject/circl/sign/mldsa/mldsa44"
	"testing"
)
import "crypto/rand"

func TestGenKey(t *testing.T) {
	pubKey, priKey, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed")
	}
	fmt.Println("pubKey:", pubKey, "priKey:", priKey)

	var seed1 [SeedSize]byte
	var seed3 [SeedSize]byte
	for i := 0; i < SeedSize; i++ {
		seed1[i] = byte(i)
		seed3[i] = byte(i + 1)
	}
	pubKey1, priKey1, err := NewKeyFromSeed(&seed1)
	if err != nil {
		t.Fatalf("failed")
	}
	pubKey2, priKey2, err := NewKeyFromSeed(&seed1)
	if err != nil {
		t.Fatalf("failed")
	}
	pubKey3, priKey3, err := NewKeyFromSeed(&seed3)
	if err != nil {
		t.Fatalf("failed")
	}

	fmt.Println("pubKey1:", pubKey1, "priKey1:", priKey1)
	fmt.Println("pubKey2:", pubKey2, "priKey2:", priKey2)
	fmt.Println("pubKey3:", pubKey3, "priKey3:", priKey3)

	if bytes.Compare(pubKey1.key, pubKey2.key) != 0 {
		t.Fatalf("public keys do not match")
	}
	if bytes.Compare(priKey2.key, priKey2.key) != 0 {
		t.Fatalf("private keys do not match")
	}
	if bytes.Compare(pubKey1.key, pubKey3.key) == 0 {
		t.Fatalf("public keys match")
	}
	if bytes.Compare(priKey2.key, priKey3.key) == 0 {
		t.Fatalf("private keys match")
	}
	seed4 := [SeedSize]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159}
	pubKey4, priKey4, err := NewKeyFromSeed(&seed4)
	if err != nil {
		t.Fatalf("failed")
	}
	if bytes.Compare(pubKey1.key, pubKey4.key) != 0 {
		t.Fatalf("public keys do not match")
	}
	if bytes.Compare(priKey2.key, priKey4.key) != 0 {
		t.Fatalf("private keys do not match")
	}
}

func TestSign(t *testing.T) {
	seed := make([]byte, 160)
	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
	}
	for i := 32; i < 32+32; i++ {
		seed[i] = byte(i)
	}
	for i := 32 + 32; i < 160; i++ {
		seed[i] = byte(i)
	}
	var ed25519Seed [ed25519.SeedSize]byte
	var mldsaSeed [mldsa44.SeedSize]byte
	var slhdsaSeed [SeedSizeSlhDsda]byte

	copy(ed25519Seed[:], seed[0:ed25519.SeedSize])
	copy(mldsaSeed[:], seed[ed25519.SeedSize:ed25519.SeedSize+mldsa44.SeedSize])
	copy(slhdsaSeed[:], seed[ed25519.SeedSize+mldsa44.SeedSize:])

	fmt.Println("ar:", seed)
	fmt.Println("arr a:", ed25519Seed, len(ed25519Seed))
	fmt.Println("arr b:", mldsaSeed, len(mldsaSeed))
	fmt.Println("arr c:", slhdsaSeed, len(slhdsaSeed))

}
