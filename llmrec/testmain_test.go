package llmrec

import (
	"os"
	"testing"

	"github.com/Autumn-27/artex/internal/testdb"
)

func TestMain(m *testing.M) {
	testdb.Configure()
	os.Exit(m.Run())
}
