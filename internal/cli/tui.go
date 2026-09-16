package cli

import (
	"github.com/spf13/cobra"

	"github.com/aburaihan-dev/gowalld/internal/service"
	"github.com/aburaihan-dev/gowalld/internal/tui"
)

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Launch the interactive rule browser/editor",
	RunE: func(cmd *cobra.Command, args []string) error {
		// service.AutoConfirmer{}: the TUI has its own on-screen confirm
		// view, and a confirmer that blocks reading os.Stdin here would
		// race bubbletea for the terminal instead of ever seeing input.
		svc, err := newServiceWithConfirmer(cmd.Context(), service.AutoConfirmer{})
		if err != nil {
			return err
		}
		return tui.Run(cmd.Context(), svc, flagDryRun)
	},
}
