package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

var (
	ruleFrom    string
	ruleTo      string
	ruleIface   string
	ruleComment string
	ruleOut     bool
)

func addRuleFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&ruleFrom, "from", "", "restrict to a source CIDR (default: any)")
	cmd.Flags().StringVar(&ruleTo, "to", "", "restrict to a destination CIDR (default: any)")
	cmd.Flags().StringVar(&ruleIface, "iface", "", "restrict to a network interface")
	cmd.Flags().StringVar(&ruleComment, "comment", "", "attach a comment to the rule")
	cmd.Flags().BoolVar(&ruleOut, "out", false, "apply to outbound traffic instead of inbound")
}

func runAddRule(cmd *cobra.Command, action firewall.Action, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected exactly one argument: <port[/proto]>|<service>")
	}
	port, proto, serviceName, err := firewall.ParseTarget(args[0])
	if err != nil {
		return err
	}
	direction := firewall.In
	if ruleOut {
		direction = firewall.Out
	}
	rule := firewall.Rule{
		Action:      action,
		Direction:   direction,
		Protocol:    proto,
		Port:        port,
		ServiceName: serviceName,
		Source:      ruleFrom,
		Destination: ruleTo,
		Interface:   ruleIface,
		Zone:        flagZone,
		Comment:     ruleComment,
	}

	svc, err := newService(cmd.Context())
	if err != nil {
		return err
	}
	return svc.AddRule(cmd.Context(), rule)
}
