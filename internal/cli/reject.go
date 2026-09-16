package cli

import (
	"github.com/spf13/cobra"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

var rejectCmd = &cobra.Command{
	Use:   "reject <port[/proto]>|<service>",
	Short: "Reject traffic with an explicit response, e.g. gowalld reject 23",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAddRule(cmd, firewall.Reject, args)
	},
}

func init() {
	addRuleFlags(rejectCmd)
}
