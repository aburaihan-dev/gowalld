// Package firewalld implements firewall.Firewall by shelling out to the
// `firewall-cmd` binary and parsing its text output — kept symmetric with
// the ufw backend (subprocess + text parsing) rather than talking to
// firewalld's D-Bus API directly.
package firewalld

import (
	"context"
	"fmt"
	"strings"
	"time"

	gexec "github.com/aburaihan-dev/gowalld/internal/exec"
	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

const binary = "firewall-cmd"

var _ firewall.Firewall = (*Backend)(nil)

type Backend struct {
	runner gexec.Runner
}

func New(runner gexec.Runner) *Backend {
	return &Backend{runner: runner}
}

func (b *Backend) Backend() firewall.BackendType { return firewall.Firewalld }

func (b *Backend) zoneOrDefault(ctx context.Context, zone string) (string, error) {
	if zone != "" {
		return zone, nil
	}
	res, err := b.runner.Run(ctx, gexec.Read, binary, "--get-default-zone")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(res.Stdout), nil
}

func (b *Backend) Status(ctx context.Context) (*firewall.Status, error) {
	// --state exits non-zero when firewalld isn't running; that's a valid
	// "disabled" reading, not a tool failure, so its error is swallowed here.
	stateRes, _ := b.runner.Run(ctx, gexec.Read, binary, "--state")

	zone, err := b.zoneOrDefault(ctx, "")
	if err != nil {
		return nil, err
	}
	listRes, err := b.runner.Run(ctx, gexec.Read, binary, "--zone="+zone, "--list-all")
	if err != nil {
		return nil, err
	}
	listing := parseListAll(listRes.Stdout, zone, false)

	return &firewall.Status{
		Backend:    firewall.Firewalld,
		Enabled:    isRunning(stateRes.Stdout),
		DefaultIn:  mapTarget(listing.Target),
		DefaultOut: firewall.Allow, // firewalld zones don't filter egress out of the box
		ActiveZone: zone,
		Raw:        listRes.Stdout,
	}, nil
}

func (b *Backend) ListRules(ctx context.Context, opts firewall.ListOptions) ([]firewall.Rule, error) {
	zone, err := b.zoneOrDefault(ctx, opts.Zone)
	if err != nil {
		return nil, err
	}
	rules, err := b.listZone(ctx, zone)
	if err != nil {
		return nil, err
	}
	out := make([]firewall.Rule, 0, len(rules))
	for _, r := range rules {
		if !matches(r, opts) {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// listZone reads the permanent config for zone: gowalld always writes to
// both runtime and permanent (see AddRule), so the permanent view is what
// stays accurate across a reload and is what Snapshot/backup should capture.
func (b *Backend) listZone(ctx context.Context, zone string) ([]firewall.Rule, error) {
	res, err := b.runner.Run(ctx, gexec.Read, binary, "--permanent", "--zone="+zone, "--list-all")
	if err != nil {
		return nil, err
	}
	return parseListAll(res.Stdout, zone, true).Rules, nil
}

func matches(r firewall.Rule, opts firewall.ListOptions) bool {
	if opts.Protocol != "" && r.Protocol != opts.Protocol {
		return false
	}
	if opts.Action != "" && r.Action != opts.Action {
		return false
	}
	return true
}

func (b *Backend) AddRule(ctx context.Context, rule firewall.Rule) error {
	zone, err := b.zoneOrDefault(ctx, rule.Zone)
	if err != nil {
		return err
	}
	base, err := buildMutationArgs(rule, zone, "add")
	if err != nil {
		return err
	}
	return b.applyBoth(ctx, base)
}

func (b *Backend) DeleteRule(ctx context.Context, ref firewall.RuleRef) error {
	zone, err := b.zoneOrDefault(ctx, ref.Zone)
	if err != nil {
		return err
	}
	rules, err := b.listZone(ctx, zone)
	if err != nil {
		return err
	}
	var target *firewall.Rule
	for i := range rules {
		if rules[i].ID == ref.ID {
			target = &rules[i]
			break
		}
	}
	if target == nil {
		return firewall.ErrRuleNotFound
	}
	base, err := buildMutationArgs(*target, zone, "remove")
	if err != nil {
		return err
	}
	return b.applyBoth(ctx, base)
}

// applyBoth issues args once for the immediate runtime effect and once more
// with --permanent prepended for persistence, avoiding a full --reload
// (which is unnecessary and, on some older firewalld builds, momentarily
// disruptive) just to make a single rule change take effect right away.
func (b *Backend) applyBoth(ctx context.Context, args []string) error {
	if _, err := b.runner.Run(ctx, gexec.Write, binary, args...); err != nil {
		return err
	}
	permanent := append([]string{"--permanent"}, args...)
	_, err := b.runner.Run(ctx, gexec.Write, binary, permanent...)
	return err
}

func (b *Backend) EditRule(ctx context.Context, ref firewall.RuleRef, updated firewall.Rule) error {
	if err := b.DeleteRule(ctx, ref); err != nil {
		return err
	}
	if updated.Zone == "" {
		updated.Zone = ref.Zone
	}
	return b.AddRule(ctx, updated)
}

func (b *Backend) Reload(ctx context.Context) error {
	_, err := b.runner.Run(ctx, gexec.Write, binary, "--reload")
	return err
}

func (b *Backend) activeZones(ctx context.Context) ([]string, error) {
	res, err := b.runner.Run(ctx, gexec.Read, binary, "--get-active-zones")
	if err != nil {
		return nil, err
	}
	return parseActiveZones(res.Stdout), nil
}

func (b *Backend) Snapshot(ctx context.Context) (*firewall.Snapshot, error) {
	status, err := b.Status(ctx)
	if err != nil {
		return nil, err
	}
	zones, err := b.zonesToCapture(ctx, status.ActiveZone)
	if err != nil {
		return nil, err
	}

	var allRules []firewall.Rule
	for _, z := range zones {
		rules, err := b.listZone(ctx, z)
		if err != nil {
			return nil, fmt.Errorf("listing zone %q: %w", z, err)
		}
		allRules = append(allRules, rules...)
	}

	return &firewall.Snapshot{
		Metadata: firewall.SnapshotMetadata{
			Backend:   firewall.Firewalld,
			CreatedAt: time.Now().UTC(),
		},
		Status: *status,
		Rules:  allRules,
	}, nil
}

// zonesToCapture is the active zones plus the default zone (covering a host
// where the default zone isn't bound to any interface yet but still holds
// configured rules worth backing up).
func (b *Backend) zonesToCapture(ctx context.Context, defaultZone string) ([]string, error) {
	active, err := b.activeZones(ctx)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{defaultZone: true}
	zones := []string{defaultZone}
	for _, z := range active {
		if !set[z] {
			set[z] = true
			zones = append(zones, z)
		}
	}
	return zones, nil
}

func (b *Backend) Restore(ctx context.Context, snap *firewall.Snapshot, opts firewall.RestoreOptions) (*firewall.RestorePlan, error) {
	if snap.Metadata.Backend != firewall.Firewalld {
		return nil, firewall.ErrCrossBackendRestore
	}

	zoneSet := map[string]bool{}
	for _, r := range snap.Rules {
		zoneSet[r.Zone] = true
	}
	status, err := b.Status(ctx)
	if err != nil {
		return nil, err
	}
	active, err := b.zonesToCapture(ctx, status.ActiveZone)
	if err != nil {
		return nil, err
	}
	for _, z := range active {
		zoneSet[z] = true
	}

	var live []firewall.Rule
	for z := range zoneSet {
		rules, err := b.listZone(ctx, z)
		if err != nil {
			return nil, fmt.Errorf("listing zone %q: %w", z, err)
		}
		live = append(live, rules...)
	}

	plan := firewall.Diff(live, snap.Rules)
	if opts.DryRun {
		return plan, nil
	}

	for _, r := range plan.ToRemove {
		if err := b.DeleteRule(ctx, firewall.RuleRef{ID: r.ID, Zone: r.Zone}); err != nil {
			return plan, fmt.Errorf("removing rule %s (zone %s): %w", r.ID, r.Zone, err)
		}
	}
	for _, r := range plan.ToAdd {
		if err := b.AddRule(ctx, r); err != nil {
			return plan, fmt.Errorf("adding rule %s (zone %s): %w", r.ID, r.Zone, err)
		}
	}
	return plan, nil
}
