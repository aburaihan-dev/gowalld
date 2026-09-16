package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	// No --config path and no real /etc/gowalld/config.yaml on this (Windows)
	// test machine, so Load should fall through to built-in defaults.
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OutputFormat != "table" || !cfg.Confirm || !cfg.SSHLockoutGuard {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadExplicitPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := "backend: ufw\ndefault_zone: dmz\nconfirm: false\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Backend != "ufw" || cfg.DefaultZone != "dmz" {
		t.Errorf("file values not applied: %+v", cfg)
	}
	if cfg.Confirm {
		t.Error("confirm: false in file should override the true default")
	}
	// Untouched keys still get their built-in default.
	if cfg.OutputFormat != "table" {
		t.Errorf("OutputFormat = %q, want default table", cfg.OutputFormat)
	}
}

func TestLoadEnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("backend: ufw\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GOWALLD_BACKEND", "firewalld")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Backend != "firewalld" {
		t.Errorf("Backend = %q, want env override firewalld", cfg.Backend)
	}
}
