package cli

import (
	"github.com/spf13/cobra"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

var allowCmd = &cobra.Command{
	Use:   "allow <port[/proto]>|<service>",
	Short: "Allow traffic, e.g. gowalld allow 22/tcp --from 10.0.0.0/8",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAddRule(cmd, firewall.Allow, args)
	},
}

func init() {
	addRuleFlags(allowCmd)
}
