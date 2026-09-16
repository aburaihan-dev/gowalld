// Package firewall defines the backend-agnostic model and interface that the
// firewalld and ufw implementations satisfy, plus the types shared by both
// one-shot CLI commands and the TUI.
package firewall

import (
	"context"
	"time"
)

// BackendType identifies which firewall management stack a Firewall talks to.
type BackendType string

const (
	Firewalld BackendType = "firewalld"
	UFW       BackendType = "ufw"
)

// Action is the disposition applied to matching traffic.
type Action string

const (
	Allow  Action = "allow"
	Deny   Action = "deny"
	Reject Action = "reject"
)

// Direction is the traffic direction a rule applies to.
type Direction string

const (
	In  Direction = "in"
	Out Direction = "out"
)

// Protocol is the IP protocol a rule matches. Empty means "any".
type Protocol string

const (
	TCP Protocol = "tcp"
	UDP Protocol = "udp"
)

// Rule is the union of what firewalld and ufw rules can express. Fields that
// only make sense for one backend are documented below; the other backend
// ignores them on write and reports a documented default on read.
type Rule struct {
	// ID is a deterministic content-hash computed by ListRules, used to
	// reference a rule for Delete/Edit without relying on either backend's
	// unstable rule numbering.
	ID string `yaml:"id" json:"id"`

	Action    Action    `yaml:"action" json:"action"`
	Direction Direction `yaml:"direction" json:"direction"`
	Protocol  Protocol  `yaml:"protocol,omitempty" json:"protocol,omitempty"`

	// Port is a single port ("22") or range ("8000-9000"). Mutually
	// exclusive with ServiceName.
	Port string `yaml:"port,omitempty" json:"port,omitempty"`

	// ServiceName is an opaque pass-through to the backend's own service/app
	// registry (firewalld services vs ufw app profiles). These registries do
	// not overlap in general — only Port-based rules are guaranteed portable
	// across backends.
	ServiceName string `yaml:"service_name,omitempty" json:"service_name,omitempty"`

	// Source is a CIDR or "any" (default).
	Source string `yaml:"source,omitempty" json:"source,omitempty"`
	// Destination is a CIDR, usually empty (any).
	Destination string `yaml:"destination,omitempty" json:"destination,omitempty"`
	// Interface restricts the rule to a network interface, usually empty (any).
	Interface string `yaml:"interface,omitempty" json:"interface,omitempty"`

	// Zone is firewalld-only. UfwBackend ignores it on write and reports
	// "default" on read.
	Zone string `yaml:"zone,omitempty" json:"zone,omitempty"`

	Comment string `yaml:"comment,omitempty" json:"comment,omitempty"`

	// Permanent distinguishes firewalld's runtime-vs-permanent rule sets.
	// ufw has no such split: every rule is persisted immediately, so
	// UfwBackend always reports true.
	Permanent bool `yaml:"permanent" json:"permanent"`
}

// RuleRef identifies a rule to Delete or Edit. At least one of ID or Index
// must be set; ID (content-hash) is preferred and is resolved against the
// live rule set immediately before acting, since neither backend guarantees
// stable numbering across mutations.
type RuleRef struct {
	ID    string
	Index int // 1-based, ufw-style; 0 means unset
}

// Status is the backend's enabled/disabled state and default policy.
type Status struct {
	Backend    BackendType `yaml:"backend" json:"backend"`
	Enabled    bool        `yaml:"enabled" json:"enabled"`
	DefaultIn  Action      `yaml:"default_in" json:"default_in"`
	DefaultOut Action      `yaml:"default_out" json:"default_out"`
	// ActiveZone is firewalld-only; empty for ufw.
	ActiveZone string `yaml:"active_zone,omitempty" json:"active_zone,omitempty"`
	// Raw is the backend's own verbose status text, for debugging/-v output.
	Raw string `yaml:"-" json:"-"`
}

// ListOptions filters ListRules output.
type ListOptions struct {
	Zone     string // firewalld only
	Protocol Protocol
	Action   Action
}

// SnapshotMetadata records provenance for a backup file.
type SnapshotMetadata struct {
	GowalldVersion string      `yaml:"gowalld_version" json:"gowalld_version"`
	Backend        BackendType `yaml:"backend" json:"backend"`
	BackendVersion string      `yaml:"backend_version" json:"backend_version"`
	Hostname       string      `yaml:"hostname" json:"hostname"`
	CreatedAt      time.Time   `yaml:"created_at" json:"created_at"`
	CreatedBy      string      `yaml:"created_by" json:"created_by"`
	Comment        string      `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// Snapshot is the full captured state written to and read from backup files.
type Snapshot struct {
	Metadata SnapshotMetadata `yaml:"metadata" json:"metadata"`
	Status   Status           `yaml:"status" json:"status"`
	Rules    []Rule           `yaml:"rules" json:"rules"`
}

// RestoreOptions controls how Restore reconciles a Snapshot against live state.
type RestoreOptions struct {
	DryRun bool
	Force  bool
}

// RestorePlan is the diff Restore computes before applying anything; it is
// also what `gowalld diff` prints standalone.
type RestorePlan struct {
	ToAdd     []Rule
	ToRemove  []Rule
	Unchanged []Rule
}

// Firewall is implemented by each backend (firewalld, ufw) and is the only
// thing internal/service — and therefore both the CLI and the TUI — depends
// on. Every mutating method must route its subprocess calls through an
// exec.Runner supplied at construction time, so that --dry-run works
// identically across backends with no per-method branching.
type Firewall interface {
	Backend() BackendType

	Status(ctx context.Context) (*Status, error)
	ListRules(ctx context.Context, opts ListOptions) ([]Rule, error)

	AddRule(ctx context.Context, rule Rule) error
	DeleteRule(ctx context.Context, ref RuleRef) error
	// EditRule is delete+add under the hood — neither backend supports
	// true in-place rule editing — but is presented to users as one step.
	EditRule(ctx context.Context, ref RuleRef, updated Rule) error

	Reload(ctx context.Context) error

	Snapshot(ctx context.Context) (*Snapshot, error)
	// Restore computes a RestorePlan by diffing snap against live state and,
	// unless opts.DryRun, applies it (removals before additions).
	Restore(ctx context.Context, snap *Snapshot, opts RestoreOptions) (*RestorePlan, error)
}
