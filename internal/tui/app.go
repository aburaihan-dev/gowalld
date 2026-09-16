// Package tui is gowalld's interactive mode: a bubbletea app that browses,
// adds, edits, and deletes rules. Every mutation goes through the exact same
// internal/service.Service the CLI commands use — this package is a
// presentation layer only, and never imports internal/firewall backends
// directly, so dry-run/confirmation/lockout-guard behavior can't drift
// between the two front ends.
package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
	"github.com/aburaihan-dev/gowalld/internal/service"
)

type viewState int

const (
	viewList viewState = iota
	viewForm
	viewConfirmDelete
)

type Model struct {
	ctx context.Context
	svc *service.Service

	dryRun bool

	state  viewState
	table  table.Model
	rules  []firewall.Rule
	status *firewall.Status

	form         formModel
	deleteTarget firewall.Rule

	message string
	err     error
}

func New(ctx context.Context, svc *service.Service, dryRun bool) Model {
	columns := []table.Column{
		{Title: "ACTION", Width: 8},
		{Title: "TARGET", Width: 22},
		{Title: "SOURCE", Width: 18},
		{Title: "ZONE", Width: 10},
		{Title: "COMMENT", Width: 24},
	}
	t := table.New(table.WithColumns(columns), table.WithFocused(true), table.WithHeight(15))
	return Model{ctx: ctx, svc: svc, dryRun: dryRun, table: t, state: viewList}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(loadRulesCmd(m.ctx, m.svc), loadStatusCmd(m.ctx, m.svc))
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		h := msg.Height - 8
		if h < 3 {
			h = 3
		}
		m.table.SetHeight(h)
		return m, nil

	case rulesLoadedMsg:
		if msg.err != nil {
			m.err = msg.err
			return m, nil
		}
		m.rules = msg.rules
		m.table.SetRows(rulesToRows(msg.rules))
		return m, nil

	case statusLoadedMsg:
		if msg.err == nil {
			m.status = msg.status
		}
		return m, nil

	case actionDoneMsg:
		m.state = viewList
		if msg.err != nil {
			m.err = msg.err
			m.message = ""
			return m, nil
		}
		m.err = nil
		m.message = msg.verb + " succeeded"
		return m, loadRulesCmd(m.ctx, m.svc)

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.state {
	case viewForm:
		return m.handleFormKey(msg)
	case viewConfirmDelete:
		return m.handleConfirmKey(msg)
	default:
		return m.handleListKey(msg)
	}
}

func (m Model) handleListKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "a":
		m.form = newForm(m.defaultZone())
		m.state = viewForm
		m.err = nil
		return m, nil
	case "e":
		if r, ok := m.selectedRule(); ok {
			m.form = newEditForm(r)
			m.state = viewForm
			m.err = nil
		}
		return m, nil
	case "d":
		if r, ok := m.selectedRule(); ok {
			m.deleteTarget = r
			m.state = viewConfirmDelete
			m.err = nil
		}
		return m, nil
	case "r":
		m.message = ""
		return m, tea.Batch(loadRulesCmd(m.ctx, m.svc), loadStatusCmd(m.ctx, m.svc))
	}
	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m Model) handleFormKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.state = viewList
		return m, nil
	case "enter":
		if m.form.focus != fieldCount-1 {
			m.form.focusField(m.form.focus + 1)
			return m, nil
		}
		rule, err := m.form.buildRule()
		if err != nil {
			m.err = err
			return m, nil
		}
		m.err = nil
		if m.form.editing {
			return m, editRuleCmd(m.ctx, m.svc, m.form.ref, rule)
		}
		return m, addRuleCmd(m.ctx, m.svc, rule)
	}
	var cmd tea.Cmd
	m.form, cmd = m.form.Update(msg)
	return m, cmd
}

func (m Model) handleConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		ref := firewall.RuleRef{ID: m.deleteTarget.ID, Zone: m.deleteTarget.Zone}
		return m, deleteRuleCmd(m.ctx, m.svc, ref)
	default:
		m.state = viewList
		return m, nil
	}
}

func (m Model) selectedRule() (firewall.Rule, bool) {
	idx := m.table.Cursor()
	if idx < 0 || idx >= len(m.rules) {
		return firewall.Rule{}, false
	}
	return m.rules[idx], true
}

func (m Model) defaultZone() string {
	if m.status != nil {
		return m.status.ActiveZone
	}
	return ""
}

func (m Model) View() string {
	switch m.state {
	case viewForm:
		return m.form.View()
	case viewConfirmDelete:
		return warnStyle.Render(fmt.Sprintf(
			"Delete rule: %s %s from %s?", m.deleteTarget.Action, targetLabel(m.deleteTarget), sourceLabel(m.deleteTarget),
		)) + "\n\n" + helpStyle.Render("y: confirm  •  any other key: cancel")
	default:
		return m.renderList()
	}
}

func (m Model) renderList() string {
	var b strings.Builder
	b.WriteString(m.renderStatusBar() + "\n\n")
	b.WriteString(m.table.View() + "\n\n")
	switch {
	case m.err != nil:
		b.WriteString(errorStyle.Render("Error: "+m.err.Error()) + "\n")
	case m.message != "":
		b.WriteString(okStyle.Render(m.message) + "\n")
	}
	b.WriteString(helpStyle.Render("a: add  •  e: edit  •  d: delete  •  r: refresh  •  q: quit"))
	return b.String()
}

func (m Model) renderStatusBar() string {
	if m.status == nil {
		return statusBarStyle.Render("gowalld — loading...")
	}
	state := "inactive"
	if m.status.Enabled {
		state = "active"
	}
	text := fmt.Sprintf("gowalld — backend: %s  status: %s", m.status.Backend, state)
	if m.status.ActiveZone != "" {
		text += fmt.Sprintf("  zone: %s", m.status.ActiveZone)
	}
	if m.dryRun {
		text += "  [DRY RUN]"
	}
	return statusBarStyle.Render(text)
}

func rulesToRows(rules []firewall.Rule) []table.Row {
	rows := make([]table.Row, len(rules))
	for i, r := range rules {
		rows[i] = table.Row{string(r.Action), targetLabel(r), sourceLabel(r), r.Zone, r.Comment}
	}
	return rows
}
