package hybridedsfull

import (
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
}
