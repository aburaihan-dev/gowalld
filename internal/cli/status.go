package cli

import "github.com/spf13/cobra"

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show whether the firewall is enabled and its default policy",
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := newService(cmd.Context())
		if err != nil {
			return err
		}
		status, err := svc.Status(cmd.Context())
		if err != nil {
			return err
		}
		return printStatus(status)
	},
}
