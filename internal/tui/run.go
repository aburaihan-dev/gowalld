package tui

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aburaihan-dev/gowalld/internal/service"
)

// Run drives the TUI until the user quits. svc must have been built with an
// auto-approving Confirmer — see internal/cli/tui.go for why.
func Run(ctx context.Context, svc *service.Service, dryRun bool) error {
	p := tea.NewProgram(New(ctx, svc, dryRun), tea.WithContext(ctx))
	_, err := p.Run()
	return err
}
