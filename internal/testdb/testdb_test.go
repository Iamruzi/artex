package testdb

import (
	"os"
	"testing"
)

func TestConfigureRefusesRuntimeDatabase(t *testing.T) {
	t.Setenv(Env, "")
	t.Setenv("ARTEX_PG_DSN", "postgres://runtime/live")
	t.Setenv("ARTEX_CONFIG", "runtime-config.json")
	if got := Configure(); got != "" {
		t.Fatalf("Configure()=%q, want empty without %s", got, Env)
	}
	if got := os.Getenv("ARTEX_PG_DSN"); got != "" {
		t.Fatalf("runtime DSN survived test isolation: %q", got)
	}
	if got := os.Getenv("ARTEX_CONFIG"); got == "runtime-config.json" || got == "" {
		t.Fatalf("runtime config was not isolated: %q", got)
	}
}

func TestConfigureUsesExplicitTestDatabase(t *testing.T) {
	const dsn = "postgres://test/isolated"
	t.Setenv(Env, dsn)
	t.Setenv("ARTEX_PG_DSN", "postgres://runtime/live")
	if got := Configure(); got != dsn {
		t.Fatalf("Configure()=%q, want %q", got, dsn)
	}
	if got := os.Getenv("ARTEX_PG_DSN"); got != dsn {
		t.Fatalf("ARTEX_PG_DSN=%q, want isolated test DSN", got)
	}
}
