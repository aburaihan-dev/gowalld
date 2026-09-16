package firewalld

import (
	"context"
	"testing"

	gexec "github.com/aburaihan-dev/gowalld/internal/exec"
	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

func TestAddRuleAppliesRuntimeAndPermanent(t *testing.T) {
	mock := gexec.NewMock()
	mock.Expect(binary, []string{"--zone=public", "--add-port=22/tcp"}, "success", nil)
	mock.Expect(binary, []string{"--permanent", "--zone=public", "--add-port=22/tcp"}, "success", nil)

	b := New(mock)
	rule := firewall.Rule{Action: firewall.Allow, Protocol: firewall.TCP, Port: "22", Zone: "public"}
	if err := b.AddRule(context.Background(), rule); err != nil {
		t.Fatalf("AddRule() error = %v", err)
	}
	if len(mock.Calls) != 2 {
		t.Fatalf("expected 2 calls (runtime + permanent), got %d: %+v", len(mock.Calls), mock.Calls)
	}
}

func TestAddRuleUsesDefaultZoneWhenUnset(t *testing.T) {
	mock := gexec.NewMock()
	mock.Expect(binary, []string{"--get-default-zone"}, "public\n", nil)
	mock.Expect(binary, []string{"--zone=public", "--add-service=http"}, "success", nil)
	mock.Expect(binary, []string{"--permanent", "--zone=public", "--add-service=http"}, "success", nil)

	b := New(mock)
	rule := firewall.Rule{Action: firewall.Allow, ServiceName: "http"}
	if err := b.AddRule(context.Background(), rule); err != nil {
		t.Fatalf("AddRule() error = %v", err)
	}
}

func TestDeleteRuleResolvesFromPermanentListing(t *testing.T) {
	mock := gexec.NewMock()
	mock.Expect(binary, []string{"--permanent", "--zone=public", "--list-all"}, listAllFixture, nil)

	target := firewall.Rule{Action: firewall.Allow, Direction: firewall.In, ServiceName: "ssh", Zone: "public", Permanent: true}
	target.ID = firewall.ComputeID(target)

	mock.Expect(binary, []string{"--zone=public", "--remove-service=ssh"}, "success", nil)
	mock.Expect(binary, []string{"--permanent", "--zone=public", "--remove-service=ssh"}, "success", nil)

	b := New(mock)
	if err := b.DeleteRule(context.Background(), firewall.RuleRef{ID: target.ID, Zone: "public"}); err != nil {
		t.Fatalf("DeleteRule() error = %v", err)
	}
}

func TestDeleteRuleNotFound(t *testing.T) {
	mock := gexec.NewMock()
	mock.Expect(binary, []string{"--permanent", "--zone=public", "--list-all"}, listAllFixture, nil)

	b := New(mock)
	err := b.DeleteRule(context.Background(), firewall.RuleRef{ID: "nonexistent", Zone: "public"})
	if err != firewall.ErrRuleNotFound {
		t.Fatalf("err = %v, want ErrRuleNotFound", err)
	}
}

func TestRestoreRejectsCrossBackendSnapshot(t *testing.T) {
	b := New(gexec.NewMock())
	snap := &firewall.Snapshot{Metadata: firewall.SnapshotMetadata{Backend: firewall.UFW}}
	_, err := b.Restore(context.Background(), snap, firewall.RestoreOptions{})
	if err != firewall.ErrCrossBackendRestore {
		t.Errorf("err = %v, want ErrCrossBackendRestore", err)
	}
}

func TestRestoreDryRunDoesNotMutate(t *testing.T) {
	mock := gexec.NewMock()
	mock.Expect(binary, []string{"--state"}, "running\n", nil)
	mock.Expect(binary, []string{"--get-default-zone"}, "public\n", nil)
	mock.Expect(binary, []string{"--zone=public", "--list-all"}, listAllFixture, nil)
	mock.Expect(binary, []string{"--get-active-zones"}, "public\n  interfaces: eth0\n", nil)
	mock.Expect(binary, []string{"--permanent", "--zone=public", "--list-all"}, listAllFixture, nil)

	b := New(mock)
	snap := &firewall.Snapshot{
		Metadata: firewall.SnapshotMetadata{Backend: firewall.Firewalld},
		Rules: []firewall.Rule{
			{Action: firewall.Allow, Protocol: firewall.TCP, Port: "9999", Zone: "public"},
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
		t.Error("expected ToRemove to be non-empty (live fixture has rules absent from snapshot)")
	}
	for _, c := range mock.Calls {
		if c.Kind == gexec.Write {
			t.Errorf("unexpected write call under DryRun: %+v", c)
		}
	}
}
