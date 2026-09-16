package tui

import "github.com/charmbracelet/lipgloss"

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	dimStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	errorStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9"))
	warnStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214"))
	okStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))

	statusBarStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("230")).
			Background(lipgloss.Color("62")).
			Padding(0, 1)

	helpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))

	formLabelStyle = lipgloss.NewStyle().Width(10).Foreground(lipgloss.Color("212"))
)
