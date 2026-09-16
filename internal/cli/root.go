// Package cli wires up the cobra command tree. Every command builds a
// service.Service from the shared global flags and delegates to it — no
// command talks to internal/firewall or internal/exec directly, so the
// safety/dry-run/confirmation behavior lives in exactly one place.
package cli

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aburaihan-dev/gowalld/internal/detect"
	gexec "github.com/aburaihan-dev/gowalld/internal/exec"
	"github.com/aburaihan-dev/gowalld/internal/firewall"
	"github.com/aburaihan-dev/gowalld/internal/firewall/ufw"
	"github.com/aburaihan-dev/gowalld/internal/safety"
	"github.com/aburaihan-dev/gowalld/internal/service"
	"github.com/aburaihan-dev/gowalld/internal/version"
)

var (
	flagBackend          string
	flagDryRun           bool
	flagYes              bool
	flagOutput           string
	flagZone             string
	flagVerbose          bool
	flagForceLockoutRisk bool
)

var rootCmd = &cobra.Command{
	Use:           "gowalld",
	Short:         "One command for firewalld and ufw",
	Long:          "gowalld is a devops helper that manages firewalld and ufw through one consistent, ufw-simple command set, with safe backup/restore and an SSH self-lockout guard.",
	Version:       version.String(),
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return requireRoot()
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagBackend, "backend", "", "override backend detection: firewalld or ufw")
	rootCmd.PersistentFlags().BoolVar(&flagDryRun, "dry-run", false, "print the commands that would run without executing them")
	rootCmd.PersistentFlags().BoolVarP(&flagYes, "yes", "y", false, "skip confirmation prompts")
	rootCmd.PersistentFlags().StringVarP(&flagOutput, "output", "o", "table", "output format: table, json, or yaml")
	rootCmd.PersistentFlags().StringVar(&flagZone, "zone", "", "firewalld zone (ignored on ufw)")
	rootCmd.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "show underlying backend command output")
	rootCmd.PersistentFlags().BoolVar(&flagForceLockoutRisk, "force-lockout-risk", false, "proceed even if the change would remove firewall access for the current SSH session")

	rootCmd.AddCommand(statusCmd, listCmd, allowCmd, denyCmd, rejectCmd, deleteCmd, reloadCmd, backendCmd)
}

// Execute runs the CLI; cmd/gowalld/main.go's only job is to call this.
func Execute() error {
	return rootCmd.Execute()
}

// requireRoot enforces that mutating firewall operations run as root, which
// both firewall-cmd and ufw need for virtually everything. The check is
// skipped off-Linux so `--help` and unit-adjacent manual testing work on a
// non-Linux dev machine; gowalld itself is only ever meant to run on Linux.
func requireRoot() error {
	if runtime.GOOS != "linux" {
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("gowalld must run as root (both firewalld and ufw require it for nearly every operation)")
	}
	return nil
}

// newService builds the Service a command should use, resolving the active
// backend and wiring dry-run/confirmation/lockout-guard from global flags.
func newService(ctx context.Context) (*service.Service, error) {
	runner := newRunner()

	override := flagBackend
	if override == "" {
		override = os.Getenv("GOWALLD_BACKEND")
	}
	reason, err := detect.Detect(ctx, override)
	if err != nil {
		return nil, annotateDetectError(err, reason)
	}

	var fw firewall.Firewall
	switch reason.Backend {
	case firewall.UFW:
		fw = ufw.New(runner)
	case firewall.Firewalld:
		return nil, fmt.Errorf("firewalld backend is not implemented yet (detected firewalld as the active backend on this host)")
	default:
		return nil, firewall.ErrNoBackendDetected
	}

	confirmer := stdinConfirmer{in: os.Stdin, out: os.Stderr}
	opts := service.Options{Yes: flagYes, ForceLockoutRisk: flagForceLockoutRisk}
	return service.New(fw, confirmer, safety.EnvInspector{}, opts), nil
}

func newRunner() gexec.Runner {
	real := gexec.RealRunner{}
	if !flagDryRun {
		return real
	}
	return gexec.DryRunRunner{
		Underlying: real,
		Print: func(name string, args []string) {
			fmt.Fprintf(os.Stderr, "[dry-run] would run: %s %s\n", name, strings.Join(args, " "))
		},
	}
}

func annotateDetectError(err error, reason *detect.Reason) error {
	if reason == nil || len(reason.Checks) == 0 {
		return err
	}
	return fmt.Errorf("%w\n  %s", err, strings.Join(reason.Checks, "\n  "))
}
