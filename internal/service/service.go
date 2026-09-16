// Package service is the orchestration layer between presentation (cobra
// commands, later the TUI) and a firewall.Firewall backend. It is the single
// place confirmation prompts, the SSH lockout guard, and dry-run reporting
// are wired up, so neither the CLI nor the TUI has to re-implement them.
package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
	"github.com/aburaihan-dev/gowalld/internal/safety"
)

// ErrCancelled is returned when a confirmation prompt was declined.
var ErrCancelled = errors.New("cancelled")

// ErrLockoutRisk is returned when an operation would cut off the current SSH
// session and Options.ForceLockoutRisk was not set.
var ErrLockoutRisk = errors.New("this change would remove firewall access for the current SSH session; re-run with --force-lockout-risk to proceed anyway")

// RiskLevel escalates how strictly Confirmer must gate an action.
type RiskLevel int

const (
	Low RiskLevel = iota
	Destructive
	LockoutRisk
)

// Confirmer asks the user to approve an action. The CLI implementation reads
// stdin (or auto-approves under --yes); a future TUI implementation would
// show a modal instead — both satisfy this same interface.
type Confirmer interface {
	Confirm(ctx context.Context, level RiskLevel, message string) (bool, error)
}

// AutoConfirmer always approves; used for --yes and for read-only paths that
// never need to prompt.
type AutoConfirmer struct{}

func (AutoConfirmer) Confirm(context.Context, RiskLevel, string) (bool, error) { return true, nil }

// Options controls how the Service applies actions.
type Options struct {
	// Yes auto-approves every confirmation (maps to --yes/-y).
	Yes bool
	// ForceLockoutRisk allows a change through even if it would cut off the
	// current SSH session.
	ForceLockoutRisk bool
}

// Service wraps a firewall.Firewall with the shared safety/UX layer.
type Service struct {
	fw        firewall.Firewall
	confirmer Confirmer
	inspector safety.SessionInspector
	opts      Options
}

func New(fw firewall.Firewall, confirmer Confirmer, inspector safety.SessionInspector, opts Options) *Service {
	return &Service{fw: fw, confirmer: confirmer, inspector: inspector, opts: opts}
}

func (s *Service) Backend() firewall.BackendType { return s.fw.Backend() }

func (s *Service) Status(ctx context.Context) (*firewall.Status, error) {
	return s.fw.Status(ctx)
}

func (s *Service) List(ctx context.Context, opts firewall.ListOptions) ([]firewall.Rule, error) {
	return s.fw.ListRules(ctx, opts)
}

func (s *Service) AddRule(ctx context.Context, rule firewall.Rule) error {
	ok, err := s.confirm(ctx, Low, fmt.Sprintf("Add rule: %s", describeRule(rule)))
	if err != nil || !ok {
		return cancelledOr(err)
	}
	return s.fw.AddRule(ctx, rule)
}

func (s *Service) DeleteRule(ctx context.Context, ref firewall.RuleRef) error {
	target, remaining, err := s.resolveAndRemove(ctx, ref)
	if err != nil {
		return err
	}
	if err := s.guardLockout(ctx, remaining); err != nil {
		return err
	}
	ok, err := s.confirm(ctx, Destructive, fmt.Sprintf("Delete rule: %s", describeRule(target)))
	if err != nil || !ok {
		return cancelledOr(err)
	}
	return s.fw.DeleteRule(ctx, ref)
}

func (s *Service) EditRule(ctx context.Context, ref firewall.RuleRef, updated firewall.Rule) error {
	_, remaining, err := s.resolveAndRemove(ctx, ref)
	if err != nil {
		return err
	}
	if err := s.guardLockout(ctx, append(remaining, updated)); err != nil {
		return err
	}
	ok, err := s.confirm(ctx, Destructive, fmt.Sprintf("Edit rule to: %s", describeRule(updated)))
	if err != nil || !ok {
		return cancelledOr(err)
	}
	return s.fw.EditRule(ctx, ref, updated)
}

func (s *Service) Reload(ctx context.Context) error {
	ok, err := s.confirm(ctx, Low, "Reload firewall")
	if err != nil || !ok {
		return cancelledOr(err)
	}
	return s.fw.Reload(ctx)
}

func (s *Service) Snapshot(ctx context.Context) (*firewall.Snapshot, error) {
	return s.fw.Snapshot(ctx)
}

// Restore always computes the plan; it only applies it (and only then
// prompts/guards) when opts.DryRun is false — callers wanting a preview
// should pass RestoreOptions{DryRun: true} and print the plan themselves.
func (s *Service) Restore(ctx context.Context, snap *firewall.Snapshot, opts firewall.RestoreOptions) (*firewall.RestorePlan, error) {
	if opts.DryRun {
		return s.fw.Restore(ctx, snap, opts)
	}

	preview, err := s.fw.Restore(ctx, snap, firewall.RestoreOptions{DryRun: true})
	if err != nil {
		return nil, err
	}
	if err := s.guardLockout(ctx, append(preview.Unchanged, preview.ToAdd...)); err != nil {
		return preview, err
	}
	ok, err := s.confirm(ctx, Destructive, fmt.Sprintf("Restore: +%d -%d rules", len(preview.ToAdd), len(preview.ToRemove)))
	if err != nil || !ok {
		return preview, cancelledOr(err)
	}
	return s.fw.Restore(ctx, snap, opts)
}

func (s *Service) resolveAndRemove(ctx context.Context, ref firewall.RuleRef) (target firewall.Rule, remaining []firewall.Rule, err error) {
	rules, err := s.fw.ListRules(ctx, firewall.ListOptions{})
	if err != nil {
		return firewall.Rule{}, nil, err
	}
	found := false
	for i, r := range rules {
		matches := false
		switch {
		case ref.ID != "":
			matches = r.ID == ref.ID
		case ref.Index > 0:
			// ListRules returns rules in the backend's own display order, so
			// a 1-based position match mirrors ufw's own numbering when no
			// content-hash ID was given.
			matches = i+1 == ref.Index
		}
		if matches {
			target = r
			found = true
			continue
		}
		remaining = append(remaining, r)
	}
	if !found {
		return firewall.Rule{}, nil, firewall.ErrRuleNotFound
	}
	return target, remaining, nil
}

func (s *Service) guardLockout(ctx context.Context, resultingRules []firewall.Rule) error {
	if s.opts.ForceLockoutRisk || s.inspector == nil {
		return nil
	}
	sess, ok := s.inspector.CurrentSession(ctx)
	if !ok {
		return nil
	}
	status, err := s.fw.Status(ctx)
	if err != nil {
		return err
	}
	if safety.WouldLockout(sess, status.DefaultIn, resultingRules) {
		return ErrLockoutRisk
	}
	return nil
}

func (s *Service) confirm(ctx context.Context, level RiskLevel, message string) (bool, error) {
	if s.opts.Yes {
		return true, nil
	}
	return s.confirmer.Confirm(ctx, level, message)
}

func cancelledOr(err error) error {
	if err != nil {
		return err
	}
	return ErrCancelled
}

func describeRule(r firewall.Rule) string {
	target := r.Port
	if r.ServiceName != "" {
		target = r.ServiceName
	}
	if r.Protocol != "" && r.Port != "" {
		target = target + "/" + string(r.Protocol)
	}
	from := r.Source
	if from == "" {
		from = "any"
	}
	return fmt.Sprintf("%s %s %s from %s", r.Action, r.Direction, target, from)
}
