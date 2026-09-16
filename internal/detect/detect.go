// Package detect figures out which firewall backend a host is running, so
// gowalld can pick the right firewall.Firewall implementation without the
// user having to say so on every invocation.
package detect

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

// Reason explains what detection found, for `gowalld backend` troubleshooting
// output across the four target distros.
type Reason struct {
	Backend firewall.BackendType
	Checks  []string
}

// Detect resolves the active backend. override, if non-empty, short-circuits
// probing entirely (used for --backend / GOWALLD_BACKEND / config.backend).
func Detect(ctx context.Context, override string) (*Reason, error) {
	if override != "" {
		bt, err := parseBackendType(override)
		if err != nil {
			return nil, err
		}
		return &Reason{Backend: bt, Checks: []string{"explicit override: " + override}}, nil
	}

	var checks []string

	firewalldBinOK := binExists("firewall-cmd")
	firewalldActive := serviceActive(ctx, "firewalld")
	checks = append(checks, fmt.Sprintf("firewall-cmd present: %v", firewalldBinOK), fmt.Sprintf("firewalld active: %v", firewalldActive))

	ufwBinOK := binExists("ufw")
	ufwUsable := ufwBinOK && ufwStatusRuns(ctx)
	checks = append(checks, fmt.Sprintf("ufw present: %v", ufwBinOK), fmt.Sprintf("ufw status runs: %v", ufwUsable))

	switch {
	case firewalldBinOK && firewalldActive:
		return &Reason{Backend: firewall.Firewalld, Checks: checks}, nil
	case ufwUsable:
		return &Reason{Backend: firewall.UFW, Checks: checks}, nil
	default:
		return &Reason{Checks: checks}, firewall.ErrNoBackendDetected
	}
}

func parseBackendType(s string) (firewall.BackendType, error) {
	switch s {
	case string(firewall.Firewalld):
		return firewall.Firewalld, nil
	case string(firewall.UFW):
		return firewall.UFW, nil
	default:
		return "", fmt.Errorf("unknown backend %q (want %q or %q)", s, firewall.Firewalld, firewall.UFW)
	}
}

func binExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func serviceActive(ctx context.Context, unit string) bool {
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", unit)
	out, _ := cmd.Output()
	return string(out) == "active\n"
}

func ufwStatusRuns(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "ufw", "status")
	return cmd.Run() == nil
}
