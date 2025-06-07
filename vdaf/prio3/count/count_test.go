package count

import (
	"testing"

	"github.com/quantumcoinproject/circl/vdaf/prio3/internal/flp_test"
)

func TestCount(t *testing.T) {
	t.Run("Query", func(t *testing.T) {
		c := newFlpCount()
		flp_test.TestInvalidQuery(t, &c.FLP)
	})
}
