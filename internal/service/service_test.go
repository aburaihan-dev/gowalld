package service

import (
	"context"
	"testing"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
	"github.com/aburaihan-dev/gowalld/internal/safety"
)

// fakeFirewall is a minimal in-memory firewall.Firewall for exercising
// Service orchestration (confirm/lockout-guard wiring) without a real
// backend or subprocess.
type fakeFirewall struct {
	status  firewall.Status
	rules   []firewall.Rule
	deleted []firewall.RuleRef
	added   []firewall.Rule
}

func (f *fakeFirewall) Backend() firewall.BackendType { return firewall.UFW }
func (f *fakeFirewall) Status(context.Context) (*firewall.Status, error) {
	s := f.status
	return &s, nil
}
func (f *fakeFirewall) ListRules(context.Context, firewall.ListOptions) ([]firewall.Rule, error) {
	return f.rules, nil
}
func (f *fakeFirewall) AddRule(_ context.Context, r firewall.Rule) error {
	f.added = append(f.added, r)
	return nil
}
func (f *fakeFirewall) DeleteRule(_ context.Context, ref firewall.RuleRef) error {
	f.deleted = append(f.deleted, ref)
	return nil
}
func (f *fakeFirewall) EditRule(context.Context, firewall.RuleRef, firewall.Rule) error { return nil }
func (f *fakeFirewall) Reload(context.Context) error                                    { return nil }
func (f *fakeFirewall) Snapshot(context.Context) (*firewall.Snapshot, error)            { return nil, nil }
func (f *fakeFirewall) Restore(context.Context, *firewall.Snapshot, firewall.RestoreOptions) (*firewall.RestorePlan, error) {
	return nil, nil
}

type testInspector struct {
	ip, port string
}

func (t testInspector) CurrentSession(context.Context) (*safety.Session, bool) {
	return &safety.Session{ClientIP: t.ip, ServerPort: t.port}, true
}

type denyConfirmer struct{}

func (denyConfirmer) Confirm(context.Context, RiskLevel, string) (bool, error) { return false, nil }

func TestDeleteRuleBlockedByLockoutGuard(t *testing.T) {
	fw := &fakeFirewall{
		status: firewall.Status{DefaultIn: firewall.Deny},
		rules: []firewall.Rule{
			{ID: "ssh-rule", Action: firewall.Allow, Direction: firewall.In, Port: "22"},
		},
	}
	svc := New(fw, AutoConfirmer{}, testInspector{ip: "203.0.113.5", port: "22"}, Options{})

	err := svc.DeleteRule(context.Background(), firewall.RuleRef{ID: "ssh-rule"})
	if err != ErrLockoutRisk {
		t.Fatalf("err = %v, want ErrLockoutRisk", err)
	}
	if len(fw.deleted) != 0 {
		t.Error("DeleteRule should not have reached the backend")
	}
}

func TestDeleteRuleForceLockoutRiskProceeds(t *testing.T) {
	fw := &fakeFirewall{
		status: firewall.Status{DefaultIn: firewall.Deny},
		rules: []firewall.Rule{
			{ID: "ssh-rule", Action: firewall.Allow, Direction: firewall.In, Port: "22"},
		},
	}
	svc := New(fw, AutoConfirmer{}, testInspector{ip: "203.0.113.5", port: "22"}, Options{ForceLockoutRisk: true})

	if err := svc.DeleteRule(context.Background(), firewall.RuleRef{ID: "ssh-rule"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fw.deleted) != 1 {
		t.Error("expected DeleteRule to reach the backend")
	}
}

func TestDeleteRuleNotFound(t *testing.T) {
	fw := &fakeFirewall{}
	svc := New(fw, AutoConfirmer{}, nil, Options{})
	err := svc.DeleteRule(context.Background(), firewall.RuleRef{ID: "missing"})
	if err != firewall.ErrRuleNotFound {
		t.Fatalf("err = %v, want ErrRuleNotFound", err)
	}
}

func TestAddRuleDeclinedConfirmation(t *testing.T) {
	fw := &fakeFirewall{}
	svc := New(fw, denyConfirmer{}, nil, Options{})
	err := svc.AddRule(context.Background(), firewall.Rule{Action: firewall.Allow, Port: "8080"})
	if err != ErrCancelled {
		t.Fatalf("err = %v, want ErrCancelled", err)
	}
	if len(fw.added) != 0 {
		t.Error("AddRule should not have reached the backend")
	}
}
