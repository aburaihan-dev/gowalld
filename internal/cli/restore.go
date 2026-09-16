package cli

import (
	"github.com/spf13/cobra"

	"github.com/aburaihan-dev/gowalld/internal/backup"
	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

var restoreCmd = &cobra.Command{
	Use:   "restore <file>",
	Short: "Restore firewall rules from a backup, after previewing the diff",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		snap, err := backup.Read(args[0])
		if err != nil {
			return err
		}
		svc, err := newService(cmd.Context())
		if err != nil {
			return err
		}

		// Always show the full diff before anything is applied, even when
		// --yes was passed — --yes skips the prompt, not visibility into
		// what's about to change.
		preview, err := svc.Restore(cmd.Context(), snap, firewall.RestoreOptions{DryRun: true})
		if err != nil {
			return err
		}
		if err := printPlan(preview); err != nil {
			return err
		}
		if flagDryRun {
			return nil
		}

		_, err = svc.Restore(cmd.Context(), snap, firewall.RestoreOptions{})
		return err
	},
}
