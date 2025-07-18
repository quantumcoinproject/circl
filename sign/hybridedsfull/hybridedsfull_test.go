package hybridedsfull

import (
	"bytes"
	"fmt"
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

func TestSeedExpansion(t *testing.T) {
	var seed1 [BaseSeedSize]byte
	var seed2 [BaseSeedSize]byte
	for i := 0; i < BaseSeedSize; i++ {
		seed1[i] = byte(i)
		seed2[i] = byte(i + 1)
	}
	expandedSeed1, err := ExpandSeed(&seed1)
	if err != nil {
		t.Fatalf("failed")
	}

	expandedSeed2, err := ExpandSeed(&seed2)
	if err != nil {
		t.Fatalf("failed")
	}

	expandedSeed3, err := ExpandSeed(&seed1)
	if err != nil {
		t.Fatalf("failed")
	}

	if bytes.Equal(expandedSeed1[:], expandedSeed3[:]) == false {
		t.Fatalf("expanded seeds do not match")
	}

	if bytes.Equal(expandedSeed1[:], expandedSeed2[:]) == true {
		t.Fatalf("expanded seeds match")
	}

	pubKey1, priKey1, err := NewKeyFromSeed(expandedSeed1)
	if err != nil {
		t.Fatalf("failed")
	}

	pubKey3, priKey3, err := NewKeyFromSeed(expandedSeed3)
	if err != nil {
		t.Fatalf("failed")
	}
	if bytes.Compare(pubKey1.key, pubKey3.key) != 0 {
		t.Fatalf("public keys do not match")
	}
	if bytes.Compare(priKey1.key, priKey3.key) != 0 {
		t.Fatalf("private keys do not match")
	}

}

func TestSeedExpansionDet(t *testing.T) {
	seedDet := []byte{172, 225, 248, 155, 203, 184, 25, 30, 170, 234, 120, 74, 108, 34, 234, 163, 96, 243, 133, 251, 141, 191, 247, 182, 13, 106, 56, 164, 214, 179, 143, 188, 253, 182, 185, 124, 21, 89, 72, 245, 198, 128, 37, 144, 170, 127, 227, 74, 207, 38, 218, 180, 9, 3, 70, 186, 30, 164, 224, 215, 225, 70, 242, 170, 223, 41, 220, 205, 23, 89, 21, 10, 35, 47, 200, 207, 80, 239, 219, 143, 117, 90, 17, 81, 123, 238, 48, 187, 49, 28, 23, 95, 251, 233, 247, 76}
	expandedSeedDet := []byte{164, 112, 179, 200, 61, 89, 69, 78, 1, 89, 229, 44, 54, 201, 107, 104, 54, 62, 47, 58, 160, 249, 241, 178, 162, 136, 246, 83, 253, 89, 108, 138, 223, 41, 220, 205, 23, 89, 21, 10, 35, 47, 200, 207, 80, 239, 219, 143, 117, 90, 17, 81, 123, 238, 48, 187, 49, 28, 23, 95, 251, 233, 247, 76, 162, 119, 56, 52, 120, 78, 179, 99, 38, 91, 246, 87, 201, 159, 152, 122, 94, 47, 110, 203, 200, 250, 99, 9, 172, 241, 11, 195, 231, 177, 73, 250, 221, 22, 173, 39, 38, 112, 212, 31, 61, 97, 206, 203, 168, 175, 253, 161, 189, 135, 204, 75, 56, 65, 107, 240, 239, 158, 180, 155, 254, 171, 213, 115, 94, 105, 96, 63, 162, 43, 34, 135, 20, 255, 183, 35, 18, 9, 210, 230, 214, 185, 23, 134, 137, 205, 183, 208, 118, 1, 84, 200, 204, 130, 143, 241}
	var seedDet1 [BaseSeedSize]byte
	copy(seedDet1[:], seedDet)
	expandedResult, err := ExpandSeed(&seedDet1)
	if err != nil {
		t.Fatalf("failed")
	}
	fmt.Println("expandedSeedDet", "len", len(expandedSeedDet), expandedSeedDet)
	fmt.Println("expandedResult", "len", len(*expandedResult), *expandedResult)
	if bytes.Compare(expandedSeedDet, expandedResult[:]) != 0 {
		t.Fatalf("expanded seeds do not match")
	}
}
