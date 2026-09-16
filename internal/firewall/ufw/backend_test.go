package ufw

import (
	"context"
	"testing"

	gexec "github.com/aburaihan-dev/gowalld/internal/exec"
	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

func TestDeleteRuleResolvesIDToCurrentIndex(t *testing.T) {
	mock := gexec.NewMock()
	mock.Expect(binary, []string{"status", "numbered"}, statusNumberedFixture, nil)
	mock.Expect(binary, []string{"--force", "delete", "4"}, "Rule deleted", nil)

	b := New(mock)
	// Rule [4] in the fixture: 22/tcp ALLOW IN from 10.0.0.0/8, comment "SSH admin".
	ref := firewall.RuleRef{ID: firewall.ComputeID(firewall.Rule{
		Action: firewall.Allow, Direction: firewall.In, Protocol: firewall.TCP,
		Port: "22", Source: "10.0.0.0/8",
	})}

	if err := b.DeleteRule(context.Background(), ref); err != nil {
		t.Fatalf("DeleteRule() error = %v", err)
	}

	if len(mock.Calls) != 2 {
		t.Fatalf("expected 2 calls, got %d: %+v", len(mock.Calls), mock.Calls)
	}
	del := mock.Calls[1]
	if del.Kind != gexec.Write || del.Args[len(del.Args)-1] != "4" {
		t.Errorf("expected delete of index 4, got %+v", del)
	}
}

func TestDeleteRuleNotFound(t *testing.T) {
	mock := gexec.NewMock()
	mock.Expect(binary, []string{"status", "numbered"}, statusNumberedFixture, nil)

	b := New(mock)
	err := b.DeleteRule(context.Background(), firewall.RuleRef{ID: "does-not-exist"})
	if err != firewall.ErrRuleNotFound {
		t.Errorf("err = %v, want ErrRuleNotFound", err)
	}
}

func TestRestoreDryRunDoesNotMutate(t *testing.T) {
	mock := gexec.NewMock()
	mock.Expect(binary, []string{"status", "numbered"}, statusNumberedFixture, nil)

	b := New(mock)
	snap := &firewall.Snapshot{
		Metadata: firewall.SnapshotMetadata{Backend: firewall.UFW},
		Rules: []firewall.Rule{
			{Action: firewall.Allow, Protocol: firewall.TCP, Port: "9999"},
		},
	}
	plan, err := b.Restore(context.Background(), snap, firewall.RestoreOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.ToAdd) != 1 {
		t.Errorf("ToAdd = %d, want 1", len(plan.ToAdd))
	}
	if len(plan.ToRemove) == 0 {
		t.Errorf("expected ToRemove to be non-empty (live fixture has rules absent from snapshot)")
	}
	// Only the read call should have happened — no mutating calls under dry-run.
	for _, c := range mock.Calls {
		if c.Kind == gexec.Write {
			t.Errorf("unexpected write call under DryRun: %+v", c)
		}
	}
}

func TestRestoreRejectsCrossBackendSnapshot(t *testing.T) {
	b := New(gexec.NewMock())
	snap := &firewall.Snapshot{Metadata: firewall.SnapshotMetadata{Backend: firewall.Firewalld}}
	_, err := b.Restore(context.Background(), snap, firewall.RestoreOptions{})
	if err != firewall.ErrCrossBackendRestore {
		t.Errorf("err = %v, want ErrCrossBackendRestore", err)
	}
}
