package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

// toggleStep is where the user is in the "enable/disable a port" wizard: a
// question-at-a-time flow, distinct from the full add/edit form, for the
// common "is this port open? flip it" task.
type toggleStep int

const (
	toggleStepPort toggleStep = iota
	toggleStepSource
	toggleStepConfirm
)

// portToggleModel walks: ask for a port → look it up against the currently
// loaded rules → if an ALLOW rule already covers it, offer to disable
// (delete) it; otherwise ask for an optional source restriction and offer to
// enable (add) it. It only ever considers ALLOW rules when deciding whether
// a port is "open" — a pre-existing deny/reject rule for the same port is
// left alone and stays editable through the regular e/d keys.
type portToggleModel struct {
	step   toggleStep
	port   textinput.Model
	source textinput.Model

	zone string
	err  error

	parsedPort    string
	parsedProto   firewall.Protocol
	parsedService string
	match         *firewall.Rule // existing ALLOW rule for this port, if any
}

func newPortToggle(zone string) portToggleModel {
	pi := textinput.New()
	pi.Placeholder = "22 or 22/tcp or service name"
	pi.CharLimit = 64
	pi.Width = 30
	pi.Focus()

	si := textinput.New()
	si.Placeholder = "any or CIDR"
	si.CharLimit = 64
	si.Width = 30
	si.SetValue("any")

	return portToggleModel{step: toggleStepPort, port: pi, source: si, zone: zone}
}

// resolvePort parses the entered port/service and searches rules (the TUI's
// currently loaded rule list) for a matching ALLOW entry, ignoring source so
// "is this port open at all" reads naturally. If more than one ALLOW rule
// matches, the first one found is what a "disable" would remove — a
// documented v1 simplification for hosts with duplicate port rules.
func (t *portToggleModel) resolvePort(rules []firewall.Rule) {
	raw := strings.TrimSpace(t.port.Value())
	port, proto, svc, err := firewall.ParseTarget(raw)
	if err != nil {
		t.err = err
		return
	}
	t.err = nil
	t.parsedPort, t.parsedProto, t.parsedService = port, proto, svc
	t.match = nil

	for i := range rules {
		r := rules[i]
		if r.Action != firewall.Allow {
			continue
		}
		if svc != "" {
			if r.ServiceName == svc {
				t.match = &rules[i]
				return
			}
			continue
		}
		if r.ServiceName == "" && r.Port == port && (proto == "" || r.Protocol == proto) {
			t.match = &rules[i]
			return
		}
	}
}

func (t portToggleModel) summary() string {
	if t.parsedService != "" {
		return t.parsedService
	}
	if t.parsedProto != "" {
		return t.parsedPort + "/" + string(t.parsedProto)
	}
	return t.parsedPort
}

func (t *portToggleModel) focusStep() {
	t.port.Blur()
	t.source.Blur()
	switch t.step {
	case toggleStepPort:
		t.port.Focus()
	case toggleStepSource:
		t.source.Focus()
	}
}

func (t portToggleModel) Update(msg tea.Msg) (portToggleModel, tea.Cmd) {
	var cmd tea.Cmd
	switch t.step {
	case toggleStepPort:
		t.port, cmd = t.port.Update(msg)
	case toggleStepSource:
		t.source, cmd = t.source.Update(msg)
	}
	return t, cmd
}

func (t portToggleModel) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Toggle port") + "\n\n")

	switch t.step {
	case toggleStepPort:
		b.WriteString(formLabelStyle.Render("Port:") + " " + t.port.View() + "\n")
		if t.err != nil {
			b.WriteString("\n" + errorStyle.Render(t.err.Error()) + "\n")
		}
		b.WriteString("\n" + helpStyle.Render("enter: check status  •  esc: cancel"))

	case toggleStepSource:
		b.WriteString(dimStyle.Render(fmt.Sprintf("Port %s is currently CLOSED.", t.summary())) + "\n\n")
		b.WriteString(formLabelStyle.Render("Source:") + " " + t.source.View() + "\n")
		b.WriteString("\n" + helpStyle.Render("enter: continue  •  esc: cancel"))

	case toggleStepConfirm:
		if t.match != nil {
			b.WriteString(warnStyle.Render(fmt.Sprintf(
				"Port %s is currently OPEN (allowed from %s). Disable it?", t.summary(), sourceLabel(*t.match),
			)) + "\n\n")
		} else {
			source := strings.TrimSpace(t.source.Value())
			if source == "" {
				source = "any"
			}
			b.WriteString(warnStyle.Render(fmt.Sprintf(
				"Port %s is currently CLOSED. Enable it, allowed from %s?", t.summary(), source,
			)) + "\n\n")
		}
		b.WriteString(helpStyle.Render("y: confirm  •  any other key: cancel"))
	}
	return b.String()
}
