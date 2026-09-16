package tui

import "github.com/aburaihan-dev/gowalld/internal/firewall"

func targetLabel(r firewall.Rule) string {
	t := r.Port
	if r.ServiceName != "" {
		t = r.ServiceName
	}
	if r.Protocol != "" && r.Port != "" {
		t += "/" + string(r.Protocol)
	}
	return t
}

func sourceLabel(r firewall.Rule) string {
	if r.Source == "" {
		return "any"
	}
	return r.Source
}
