package cli

import (
	"github.com/spf13/cobra"

	"github.com/aburaihan-dev/gowalld/internal/backup"
	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

var diffCmd = &cobra.Command{
	Use:   "diff <file>",
	Short: "Compare a backup file against the live firewall configuration",
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
		plan, err := svc.Restore(cmd.Context(), snap, firewall.RestoreOptions{DryRun: true})
		if err != nil {
			return err
		}
		return printPlan(plan)
	},
}
