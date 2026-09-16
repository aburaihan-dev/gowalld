package cli

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

var editAction string

var editCmd = &cobra.Command{
	Use:   "edit <id|index>",
	Short: "Replace a rule's action/port/source/etc. (delete + re-add under the hood)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ref := firewall.RuleRef{ID: args[0], Zone: flagZone}
		if n, err := strconv.Atoi(args[0]); err == nil {
			ref = firewall.RuleRef{Index: n, Zone: flagZone}
		}

		var action firewall.Action
		switch editAction {
		case "", "allow":
			action = firewall.Allow
		case "deny":
			action = firewall.Deny
		case "reject":
			action = firewall.Reject
		default:
			return fmt.Errorf("invalid --action %q (want allow, deny, or reject)", editAction)
		}

		port, proto, serviceName := "", firewall.Protocol(""), ""
		if editPort != "" {
			p, pr, svc, err := firewall.ParseTarget(editPort)
			if err != nil {
				return err
			}
			port, proto, serviceName = p, pr, svc
		}

		direction := firewall.In
		if ruleOut {
			direction = firewall.Out
		}
		updated := firewall.Rule{
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
		return svc.EditRule(cmd.Context(), ref, updated)
	},
}

var editPort string

func init() {
	addRuleFlags(editCmd)
	editCmd.Flags().StringVar(&editPort, "port", "", "new port[/proto] or service name")
	editCmd.Flags().StringVar(&editAction, "action", "allow", "new action: allow, deny, or reject")
}
