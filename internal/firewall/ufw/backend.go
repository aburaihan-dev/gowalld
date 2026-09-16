// Package ufw implements firewall.Firewall by shelling out to the `ufw`
// binary and parsing its text output — there is no structured/JSON output
// mode or stable API, so this backend is inherently a best-effort text
// scraper, same as every other ufw automation tool.
package ufw

import (
	"context"
	"fmt"
	"strconv"
	"time"

	gexec "github.com/aburaihan-dev/gowalld/internal/exec"
	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

const binary = "ufw"

var _ firewall.Firewall = (*Backend)(nil)

type Backend struct {
	runner gexec.Runner
}

func New(runner gexec.Runner) *Backend {
	return &Backend{runner: runner}
}

func (b *Backend) Backend() firewall.BackendType { return firewall.UFW }

func (b *Backend) Status(ctx context.Context) (*firewall.Status, error) {
	res, err := b.runner.Run(ctx, gexec.Read, binary, "status", "verbose")
	if err != nil {
		return nil, err
	}
	return parseStatus(res.Stdout)
}

func (b *Backend) ListRules(ctx context.Context, opts firewall.ListOptions) ([]firewall.Rule, error) {
	numbered, err := b.listNumbered(ctx)
	if err != nil {
		return nil, err
	}
	rules := make([]firewall.Rule, 0, len(numbered))
	for _, nr := range numbered {
		if !matches(nr.Rule, opts) {
			continue
		}
		rules = append(rules, nr.Rule)
	}
	return rules, nil
}

func matches(r firewall.Rule, opts firewall.ListOptions) bool {
	if opts.Protocol != "" && r.Protocol != opts.Protocol {
		return false
	}
	if opts.Action != "" && r.Action != opts.Action {
		return false
	}
	// opts.Zone is firewalld-only; ufw has no zones, so it's ignored here.
	return true
}

func (b *Backend) listNumbered(ctx context.Context) ([]numberedRule, error) {
	res, err := b.runner.Run(ctx, gexec.Read, binary, "status", "numbered")
	if err != nil {
		return nil, err
	}
	return listNumbered(res.Stdout)
}

func (b *Backend) AddRule(ctx context.Context, rule firewall.Rule) error {
	_, err := b.runner.Run(ctx, gexec.Write, binary, buildAddArgs(rule)...)
	return err
}

func (b *Backend) DeleteRule(ctx context.Context, ref firewall.RuleRef) error {
	idx, err := b.resolveIndex(ctx, ref)
	if err != nil {
		return err
	}
	// --force skips ufw's own interactive confirmation prompt: gowalld's
	// service layer already owns confirmation, and an unanswered prompt
	// here would just hang non-interactive/dry-run invocations.
	_, err = b.runner.Run(ctx, gexec.Write, binary, "--force", "delete", strconv.Itoa(idx))
	return err
}

func (b *Backend) resolveIndex(ctx context.Context, ref firewall.RuleRef) (int, error) {
	if ref.ID == "" && ref.Index > 0 {
		return ref.Index, nil
	}
	numbered, err := b.listNumbered(ctx)
	if err != nil {
		return 0, err
	}
	for _, nr := range numbered {
		if nr.Rule.ID == ref.ID {
			return nr.Index, nil
		}
	}
	return 0, firewall.ErrRuleNotFound
}

func (b *Backend) EditRule(ctx context.Context, ref firewall.RuleRef, updated firewall.Rule) error {
	if err := b.DeleteRule(ctx, ref); err != nil {
		return err
	}
	return b.AddRule(ctx, updated)
}

func (b *Backend) Reload(ctx context.Context) error {
	_, err := b.runner.Run(ctx, gexec.Write, binary, "reload")
	return err
}

func (b *Backend) Snapshot(ctx context.Context) (*firewall.Snapshot, error) {
	status, err := b.Status(ctx)
	if err != nil {
		return nil, err
	}
	rules, err := b.ListRules(ctx, firewall.ListOptions{})
	if err != nil {
		return nil, err
	}
	return &firewall.Snapshot{
		Metadata: firewall.SnapshotMetadata{
			Backend:   firewall.UFW,
			CreatedAt: time.Now().UTC(),
		},
		Status: *status,
		Rules:  rules,
	}, nil
}

func (b *Backend) Restore(ctx context.Context, snap *firewall.Snapshot, opts firewall.RestoreOptions) (*firewall.RestorePlan, error) {
	if snap.Metadata.Backend != firewall.UFW {
		return nil, firewall.ErrCrossBackendRestore
	}
	live, err := b.ListRules(ctx, firewall.ListOptions{})
	if err != nil {
		return nil, err
	}
	plan := firewall.Diff(live, snap.Rules)
	if opts.DryRun {
		return plan, nil
	}

	// Removals first, highest ufw index first within each call (resolveIndex
	// re-lists live state per call so indices already reflect prior deletes).
	for _, r := range plan.ToRemove {
		if err := b.DeleteRule(ctx, firewall.RuleRef{ID: r.ID}); err != nil {
			return plan, fmt.Errorf("removing rule %s: %w", r.ID, err)
		}
	}
	for _, r := range plan.ToAdd {
		if err := b.AddRule(ctx, r); err != nil {
			return plan, fmt.Errorf("adding rule %s: %w", r.ID, err)
		}
	}
	return plan, nil
}
