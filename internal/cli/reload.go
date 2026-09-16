package cli

import "github.com/spf13/cobra"

var reloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload the firewall backend",
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := newService(cmd.Context())
		if err != nil {
			return err
		}
		return svc.Reload(cmd.Context())
	},
}
