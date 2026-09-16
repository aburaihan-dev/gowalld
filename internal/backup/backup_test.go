package backup

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

func TestWriteReadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	snap := &firewall.Snapshot{
		Metadata: firewall.SnapshotMetadata{
			GowalldVersion: "test",
			Backend:        firewall.UFW,
			Hostname:       "web01",
			CreatedAt:      time.Date(2026, 9, 16, 10, 22, 31, 0, time.UTC),
		},
		Status: firewall.Status{Backend: firewall.UFW, Enabled: true, DefaultIn: firewall.Deny, DefaultOut: firewall.Allow},
		Rules: []firewall.Rule{
			{ID: "abc123", Action: firewall.Allow, Direction: firewall.In, Protocol: firewall.TCP, Port: "22"},
		},
	}

	path, err := Write(snap, dir, "")
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	wantName := "web01_ufw_20260916T102231Z.yaml"
	if filepath.Base(path) != wantName {
		t.Errorf("file name = %q, want %q", filepath.Base(path), wantName)
	}

	got, err := Read(path)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if got.Metadata.Hostname != "web01" || got.Metadata.Backend != firewall.UFW {
		t.Errorf("metadata mismatch: %+v", got.Metadata)
	}
	if len(got.Rules) != 1 || got.Rules[0].ID != "abc123" {
		t.Errorf("rules mismatch: %+v", got.Rules)
	}
	if got.Status.DefaultIn != firewall.Deny {
		t.Errorf("status mismatch: %+v", got.Status)
	}
}

func TestWriteExplicitName(t *testing.T) {
	dir := t.TempDir()
	snap := &firewall.Snapshot{Metadata: firewall.SnapshotMetadata{Backend: firewall.UFW}}

	path, err := Write(snap, dir, "pre-change")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "pre-change.yaml" {
		t.Errorf("file name = %q, want pre-change.yaml", filepath.Base(path))
	}
}
