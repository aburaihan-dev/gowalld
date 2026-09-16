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

	"github.com/aburaihan-dev/gowalld/internal/config"
	"github.com/aburaihan-dev/gowalld/internal/detect"
	gexec "github.com/aburaihan-dev/gowalld/internal/exec"
	"github.com/aburaihan-dev/gowalld/internal/firewall"
	"github.com/aburaihan-dev/gowalld/internal/firewall/firewalld"
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
	flagConfigPath       string
)

// loadedConfig is resolved once per invocation in PersistentPreRunE and read
// by commands that need a config value with no flag equivalent (e.g.
// backup's default output directory).
var loadedConfig *config.Config

var rootCmd = &cobra.Command{
	Use:           "gowalld",
	Short:         "One command for firewalld and ufw",
	Long:          "gowalld is a devops helper that manages firewalld and ufw through one consistent, ufw-simple command set, with safe backup/restore and an SSH self-lockout guard.",
	Version:       version.String(),
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRoot(); err != nil {
			return err
		}
		cfg, err := config.Load(flagConfigPath)
		if err != nil {
			return err
		}
		loadedConfig = cfg
		applyConfigDefaults(cmd, cfg)
		return nil
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
	rootCmd.PersistentFlags().StringVar(&flagConfigPath, "config", "", "path to a config file (overrides /etc/gowalld/config.yaml and ~/.config/gowalld/config.yaml)")

	rootCmd.AddCommand(statusCmd, listCmd, allowCmd, denyCmd, rejectCmd, deleteCmd, editCmd, reloadCmd, backendCmd, backupCmd, restoreCmd, diffCmd, tuiCmd)
}

// applyConfigDefaults fills in any global flag the user didn't explicitly
// pass with the loaded config's value, so a fleet-wide config.yaml can set
// defaults without every invocation needing the equivalent flag.
func applyConfigDefaults(cmd *cobra.Command, cfg *config.Config) {
	if !cmd.Flags().Changed("backend") && cfg.Backend != "" {
		flagBackend = cfg.Backend
	}
	if !cmd.Flags().Changed("zone") && cfg.DefaultZone != "" {
		flagZone = cfg.DefaultZone
	}
	if !cmd.Flags().Changed("output") && cfg.OutputFormat != "" {
		flagOutput = cfg.OutputFormat
	}
	if !cmd.Flags().Changed("yes") && !cfg.Confirm {
		flagYes = true
	}
	if !cmd.Flags().Changed("force-lockout-risk") && !cfg.SSHLockoutGuard {
		flagForceLockoutRisk = true
	}
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

// newService builds the Service a one-shot command should use: it reads
// confirmation prompts from stdin, which only works because nothing else is
// driving the terminal.
func newService(ctx context.Context) (*service.Service, error) {
	return newServiceWithConfirmer(ctx, stdinConfirmer{in: os.Stdin, out: os.Stderr})
}

// newServiceWithConfirmer resolves the active backend and wires
// dry-run/confirmation/lockout-guard from global flags, using confirmer for
// approvals. The TUI needs its own variant (see internal/cli/tui.go):
// bubbletea owns the terminal in raw mode, so a confirmer that blocks on
// reading os.Stdin directly would race it instead of ever seeing input —
// the TUI supplies its own on-screen confirm view and an auto-approving
// confirmer here instead.
func newServiceWithConfirmer(ctx context.Context, confirmer service.Confirmer) (*service.Service, error) {
	runner := newRunner()

	reason, err := detect.Detect(ctx, flagBackend)
	if err != nil {
		return nil, annotateDetectError(err, reason)
	}

	var fw firewall.Firewall
	switch reason.Backend {
	case firewall.UFW:
		fw = ufw.New(runner)
	case firewall.Firewalld:
		fw = firewalld.New(runner)
	default:
		return nil, firewall.ErrNoBackendDetected
	}

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
