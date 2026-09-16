package cli

import (
	"github.com/spf13/cobra"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

var denyCmd = &cobra.Command{
	Use:   "deny <port[/proto]>|<service>",
	Short: "Silently drop traffic, e.g. gowalld deny 23",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAddRule(cmd, firewall.Deny, args)
	},
}

func init() {
	addRuleFlags(denyCmd)
}
