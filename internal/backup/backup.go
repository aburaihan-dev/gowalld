// Package backup reads and writes gowalld's snapshot files: the YAML
// serialization of a firewall.Snapshot, plus the naming/location convention
// used when no explicit path is given.
package backup

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

// DefaultDir is where backups live when no --output-dir/config override is
// given. It's under /var/lib rather than $HOME because gowalld always runs
// as root and /var/lib/<app>/ is the FHS-correct spot for root-owned
// persistent state (it's also where ufw itself keeps /var/lib/ufw).
const DefaultDir = "/var/lib/gowalld/backups"

// Write serializes snap as YAML to dir/name (name defaults to a
// hostname_backend_timestamp[_slug].yaml pattern when empty) and returns the
// path written.
func Write(snap *firewall.Snapshot, dir, name string) (string, error) {
	if dir == "" {
		dir = DefaultDir
	}
	if name == "" {
		name = defaultFileName(snap)
	}
	if filepath.Ext(name) != ".yaml" && filepath.Ext(name) != ".yml" {
		name += ".yaml"
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating backup dir %q: %w", dir, err)
	}
	path := filepath.Join(dir, name)

	data, err := yaml.Marshal(snap)
	if err != nil {
		return "", fmt.Errorf("encoding snapshot: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("writing backup %q: %w", path, err)
	}
	return path, nil
}

func defaultFileName(snap *firewall.Snapshot) string {
	host := snap.Metadata.Hostname
	if host == "" {
		host = "host"
	}
	ts := snap.Metadata.CreatedAt.UTC().Format("20060102T150405Z")
	return fmt.Sprintf("%s_%s_%s.yaml", host, snap.Metadata.Backend, ts)
}

// Read loads a snapshot previously written by Write.
func Read(path string) (*firewall.Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading backup %q: %w", path, err)
	}
	var snap firewall.Snapshot
	if err := yaml.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parsing backup %q: %w", path, err)
	}
	return &snap, nil
}
