package tui

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
	"github.com/aburaihan-dev/gowalld/internal/service"
)

// Every service.Service call is blocking (it shells out to firewall-cmd/ufw),
// so each one is wrapped in a tea.Cmd that runs on bubbletea's own goroutine
// and reports back via a message, keeping the Update loop responsive.

type rulesLoadedMsg struct {
	rules []firewall.Rule
	err   error
}

type statusLoadedMsg struct {
	status *firewall.Status
	err    error
}

type actionDoneMsg struct {
	verb string
	err  error
}

func loadRulesCmd(ctx context.Context, svc *service.Service) tea.Cmd {
	return func() tea.Msg {
		rules, err := svc.List(ctx, firewall.ListOptions{})
		return rulesLoadedMsg{rules: rules, err: err}
	}
}

func loadStatusCmd(ctx context.Context, svc *service.Service) tea.Cmd {
	return func() tea.Msg {
		status, err := svc.Status(ctx)
		return statusLoadedMsg{status: status, err: err}
	}
}

func addRuleCmd(ctx context.Context, svc *service.Service, rule firewall.Rule) tea.Cmd {
	return func() tea.Msg {
		return actionDoneMsg{verb: "add", err: svc.AddRule(ctx, rule)}
	}
}

func editRuleCmd(ctx context.Context, svc *service.Service, ref firewall.RuleRef, rule firewall.Rule) tea.Cmd {
	return func() tea.Msg {
		return actionDoneMsg{verb: "edit", err: svc.EditRule(ctx, ref, rule)}
	}
}

func deleteRuleCmd(ctx context.Context, svc *service.Service, ref firewall.RuleRef) tea.Cmd {
	return func() tea.Msg {
		return actionDoneMsg{verb: "delete", err: svc.DeleteRule(ctx, ref)}
	}
}
