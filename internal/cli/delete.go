package cli

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

var deleteCmd = &cobra.Command{
	Use:     "delete <id|index>",
	Aliases: []string{"rm"},
	Short:   "Delete a rule by ID (from `gowalld list`) or numbered index",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ref := firewall.RuleRef{ID: args[0]}
		if n, err := strconv.Atoi(args[0]); err == nil {
			ref = firewall.RuleRef{Index: n}
		}
		svc, err := newService(cmd.Context())
		if err != nil {
			return err
		}
		return svc.DeleteRule(cmd.Context(), ref)
	},
}
