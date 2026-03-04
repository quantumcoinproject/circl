package hybrideds

import (
	"bytes"
	"testing"
)

func TestSeedExpansion(t *testing.T) {
	var seed1 [BaseSeedSize]byte
	var seed2 [BaseSeedSize]byte
	for i := 0; i < BaseSeedSize; i++ {
		seed1[i] = byte(i)
		seed2[i] = byte(i + 1)
	}
	expandedSeed1, err := ExpandSeed(seed1)
	if err != nil {
		t.Fatalf("failed")
	}

	expandedSeed2, err := ExpandSeed(seed2)
	if err != nil {
		t.Fatalf("failed")
	}

	expandedSeed3, err := ExpandSeed(seed1)
	if err != nil {
		t.Fatalf("failed")
	}

	if bytes.Equal(expandedSeed1[:], expandedSeed3[:]) == false {
		t.Fatalf("expanded seeds do not match")
	}

	if bytes.Equal(expandedSeed1[:], expandedSeed2[:]) == true {
		t.Fatalf("expanded seeds match")
	}

	pubKey1, priKey1, err := NewKeyFromSeed(&expandedSeed1)
	if err != nil {
		t.Fatalf("failed")
	}

	pubKey3, priKey3, err := NewKeyFromSeed(&expandedSeed3)
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
	copy(seedDet1[:], seedDet[:BaseSeedSize])
	expandedResult, err := ExpandSeed(seedDet1)
	if err != nil {
		t.Fatalf("failed")
	}
	if bytes.Compare(expandedSeedDet, expandedResult[:]) != 0 {
		t.Fatalf("expanded seeds do not match")
	}
}
