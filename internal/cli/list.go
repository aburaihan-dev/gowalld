package cli

import (
	"github.com/spf13/cobra"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

var (
	listProto  string
	listAction string
)

var listCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List firewall rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := newService(cmd.Context())
		if err != nil {
			return err
		}
		opts := firewall.ListOptions{
			Zone:     flagZone,
			Protocol: firewall.Protocol(listProto),
			Action:   firewall.Action(listAction),
		}
		rules, err := svc.List(cmd.Context(), opts)
		if err != nil {
			return err
		}
		return printRules(rules)
	},
}

func init() {
	listCmd.Flags().StringVar(&listProto, "proto", "", "filter by protocol: tcp or udp")
	listCmd.Flags().StringVar(&listAction, "action", "", "filter by action: allow, deny, or reject")
}
