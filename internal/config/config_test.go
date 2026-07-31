package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("db: file.db\nprofile: standard\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CINDERPATH_DB", "env.db")
	cfg, err := Load(path, Overrides{DBPath: "cli.db", Set: map[string]bool{"db": true}})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DBPath != "cli.db" {
		t.Fatalf("got %q", cfg.DBPath)
	}
	if cfg.Profile != ProfileStandard {
		t.Fatalf("profile got %q", cfg.Profile)
	}
}
