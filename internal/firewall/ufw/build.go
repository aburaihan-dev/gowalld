package ufw

import (
	"strings"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

// buildAddArgs translates a Rule into `ufw` argv. ufw's grammar has two
// forms: a compact "PORT[/PROTOCOL]" shorthand when the rule has no
// source/destination restriction, and an extended "proto P from A to B port
// N" form once either address is specific. We emit the compact form
// whenever possible since that's what ufw users' muscle memory expects and
// it round-trips more predictably through `ufw status`.
func buildAddArgs(rule firewall.Rule) []string {
	args := []string{ufwAction(rule.Action)}
	if rule.Direction == firewall.Out {
		args = append(args, "out")
	}

	if isAny(rule.Source) && isAny(rule.Destination) {
		args = append(args, portSpec(rule))
	} else {
		if rule.Protocol != "" {
			args = append(args, "proto", string(rule.Protocol))
		}
		from := "any"
		if !isAny(rule.Source) {
			from = rule.Source
		}
		args = append(args, "from", from)

		to := "any"
		if !isAny(rule.Destination) {
			to = rule.Destination
		}
		args = append(args, "to", to)

		if port := formatPortOnly(rule); port != "" {
			args = append(args, "port", port)
		}
	}

	if rule.Comment != "" {
		args = append(args, "comment", rule.Comment)
	}
	return args
}

func ufwAction(a firewall.Action) string {
	switch a {
	case firewall.Deny:
		return "deny"
	case firewall.Reject:
		return "reject"
	default:
		return "allow"
	}
}

// portSpec renders the compact "PORT[/PROTOCOL]" form, or a bare service
// name for app-profile rules.
func portSpec(rule firewall.Rule) string {
	if rule.ServiceName != "" {
		return rule.ServiceName
	}
	if rule.Protocol != "" {
		return portToUfw(rule.Port) + "/" + string(rule.Protocol)
	}
	return portToUfw(rule.Port)
}

// formatPortOnly renders just the port/range for the extended "port N" form,
// where protocol is already carried by a separate "proto" argument.
func formatPortOnly(rule firewall.Rule) string {
	if rule.ServiceName != "" {
		return rule.ServiceName
	}
	return portToUfw(rule.Port)
}

func isAny(s string) bool {
	s = strings.TrimSpace(s)
	return s == "" || strings.EqualFold(s, "any")
}
