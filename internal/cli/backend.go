package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aburaihan-dev/gowalld/internal/detect"
)

var backendCmd = &cobra.Command{
	Use:   "backend",
	Short: "Show which firewall backend gowalld detected, and why",
	RunE: func(cmd *cobra.Command, args []string) error {
		reason, err := detect.Detect(cmd.Context(), flagBackend)
		if reason != nil {
			fmt.Println("Detection checks:")
			for _, c := range reason.Checks {
				fmt.Println("  " + c)
			}
		}
		if err != nil {
			return err
		}
		fmt.Printf("Active backend: %s\n", reason.Backend)
		return nil
	},
}
