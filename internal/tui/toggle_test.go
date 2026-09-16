package tui

import (
	"testing"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

func TestResolvePortFindsExistingAllow(t *testing.T) {
	rules := []firewall.Rule{
		{ID: "a", Action: firewall.Allow, Port: "22", Protocol: firewall.TCP, Source: "10.0.0.0/8"},
		{ID: "b", Action: firewall.Deny, Port: "23"},
	}

	toggle := newPortToggle("public")
	toggle.port.SetValue("22/tcp")
	toggle.resolvePort(rules)

	if toggle.err != nil {
		t.Fatalf("unexpected error: %v", toggle.err)
	}
	if toggle.match == nil || toggle.match.ID != "a" {
		t.Fatalf("expected match on rule a, got %+v", toggle.match)
	}
}

func TestResolvePortIgnoresDenyRule(t *testing.T) {
	rules := []firewall.Rule{
		{ID: "b", Action: firewall.Deny, Port: "23", Protocol: firewall.TCP},
	}

	toggle := newPortToggle("public")
	toggle.port.SetValue("23/tcp")
	toggle.resolvePort(rules)

	if toggle.err != nil {
		t.Fatalf("unexpected error: %v", toggle.err)
	}
	if toggle.match != nil {
		t.Fatalf("expected no match (deny rules don't count as open), got %+v", toggle.match)
	}
}

func TestResolvePortMatchesByServiceName(t *testing.T) {
	rules := []firewall.Rule{
		{ID: "c", Action: firewall.Allow, ServiceName: "OpenSSH"},
	}

	toggle := newPortToggle("public")
	toggle.port.SetValue("OpenSSH")
	toggle.resolvePort(rules)

	if toggle.match == nil || toggle.match.ID != "c" {
		t.Fatalf("expected match on rule c, got %+v", toggle.match)
	}
}

func TestResolvePortNoMatchWhenClosed(t *testing.T) {
	toggle := newPortToggle("public")
	toggle.port.SetValue("9999/tcp")
	toggle.resolvePort(nil)

	if toggle.err != nil {
		t.Fatalf("unexpected error: %v", toggle.err)
	}
	if toggle.match != nil {
		t.Fatalf("expected no match, got %+v", toggle.match)
	}
	if toggle.summary() != "9999/tcp" {
		t.Errorf("summary() = %q, want 9999/tcp", toggle.summary())
	}
}

func TestResolvePortInvalidInput(t *testing.T) {
	toggle := newPortToggle("public")
	toggle.port.SetValue("22/sctp")
	toggle.resolvePort(nil)

	if toggle.err == nil {
		t.Fatal("expected an error for an invalid protocol")
	}
}
