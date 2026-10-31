// Package testdb prevents database-backed tests from ever falling back to a
// developer's runtime config or ARTEX_PG_DSN. Test suites must opt in with the
// dedicated ARTEX_TEST_PG_DSN variable, which should point at a disposable DB.
package testdb

import (
	"os"
	"path/filepath"
	"strings"
)

const Env = "ARTEX_TEST_PG_DSN"

// Configure maps the explicit test DSN to the runtime variable consumed by the
// application. When no test DSN exists, it removes any runtime DSN and points
// config loading at a guaranteed-missing file so tests cannot discover a local
// production/preview database by accident.
func Configure() string {
	dsn := strings.TrimSpace(os.Getenv(Env))
	if dsn != "" {
		_ = os.Setenv("ARTEX_PG_DSN", dsn)
		return dsn
	}
	_ = os.Unsetenv("ARTEX_PG_DSN")
	_ = os.Setenv("ARTEX_CONFIG", filepath.Join(os.TempDir(), "artex-tests-no-database-config.json"))
	return ""
}
