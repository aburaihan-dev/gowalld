package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

const (
	fieldAction = iota
	fieldTarget
	fieldSource
	fieldComment
	fieldCount
)

var fieldLabels = [fieldCount]string{"Action", "Target", "Source", "Comment"}
var fieldPlaceholders = [fieldCount]string{"allow", "22/tcp or service name", "any or CIDR", "optional"}

// formModel is the add/edit rule form. It intentionally exposes fewer knobs
// than the CLI (no --to/--iface/--out): those stay CLI-only for v1, keeping
// the on-screen form to the fields devops actually fill in most often.
type formModel struct {
	inputs [fieldCount]textinput.Model
	focus  int

	editing bool
	ref     firewall.RuleRef
	zone    string
}

func newForm(zone string) formModel {
	var f formModel
	f.zone = zone
	for i := 0; i < fieldCount; i++ {
		ti := textinput.New()
		ti.Placeholder = fieldPlaceholders[i]
		ti.CharLimit = 128
		ti.Width = 40
		f.inputs[i] = ti
	}
	f.inputs[fieldAction].SetValue("allow")
	f.inputs[fieldSource].SetValue("any")
	f.inputs[fieldAction].Focus()
	return f
}

func newEditForm(rule firewall.Rule) formModel {
	f := newForm(rule.Zone)
	f.editing = true
	f.ref = firewall.RuleRef{ID: rule.ID, Zone: rule.Zone}
	f.inputs[fieldAction].SetValue(string(rule.Action))
	f.inputs[fieldTarget].SetValue(targetLabel(rule))
	f.inputs[fieldSource].SetValue(sourceLabel(rule))
	f.inputs[fieldComment].SetValue(rule.Comment)
	return f
}

func (f *formModel) focusField(i int) {
	for j := range f.inputs {
		f.inputs[j].Blur()
	}
	f.focus = (i + fieldCount) % fieldCount
	f.inputs[f.focus].Focus()
}

// buildRule validates the form and produces the Rule to submit. Direction
// is always inbound from the TUI — outbound rules (ufw-only, and uncommon)
// stay a CLI-only capability (`gowalld allow --out`).
func (f formModel) buildRule() (firewall.Rule, error) {
	action := firewall.Action(strings.ToLower(strings.TrimSpace(f.inputs[fieldAction].Value())))
	switch action {
	case firewall.Allow, firewall.Deny, firewall.Reject:
	default:
		return firewall.Rule{}, fmt.Errorf("action must be allow, deny, or reject")
	}

	targetRaw := strings.TrimSpace(f.inputs[fieldTarget].Value())
	if targetRaw == "" {
		return firewall.Rule{}, fmt.Errorf("target (port or service) is required")
	}
	port, proto, svc, err := firewall.ParseTarget(targetRaw)
	if err != nil {
		return firewall.Rule{}, err
	}

	source := strings.TrimSpace(f.inputs[fieldSource].Value())
	if strings.EqualFold(source, "any") {
		source = ""
	}

	return firewall.Rule{
		Action:      action,
		Direction:   firewall.In,
		Protocol:    proto,
		Port:        port,
		ServiceName: svc,
		Source:      source,
		Zone:        f.zone,
		Comment:     strings.TrimSpace(f.inputs[fieldComment].Value()),
	}, nil
}

func (f formModel) Update(msg tea.Msg) (formModel, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "tab", "down":
			f.focusField(f.focus + 1)
			return f, nil
		case "shift+tab", "up":
			f.focusField(f.focus - 1)
			return f, nil
		}
	}
	var cmd tea.Cmd
	f.inputs[f.focus], cmd = f.inputs[f.focus].Update(msg)
	return f, cmd
}

func (f formModel) View() string {
	var b strings.Builder
	title := "Add rule"
	if f.editing {
		title = "Edit rule"
	}
	b.WriteString(titleStyle.Render(title) + "\n\n")
	for i := 0; i < fieldCount; i++ {
		b.WriteString(formLabelStyle.Render(fieldLabels[i]+":") + " " + f.inputs[i].View() + "\n")
	}
	b.WriteString("\n" + helpStyle.Render("tab/shift+tab: move field  •  enter (on last field): submit  •  esc: cancel"))
	return b.String()
}
