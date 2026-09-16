package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/aburaihan-dev/gowalld/internal/detect"
)

var backendCmd = &cobra.Command{
	Use:   "backend",
	Short: "Show which firewall backend gowalld detected, and why",
	RunE: func(cmd *cobra.Command, args []string) error {
		override := flagBackend
		if override == "" {
			override = os.Getenv("GOWALLD_BACKEND")
		}
		reason, err := detect.Detect(cmd.Context(), override)
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
