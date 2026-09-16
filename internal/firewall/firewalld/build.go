package firewalld

import (
	"fmt"
	"strings"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

// buildMutationArgs translates a Rule into the argv for `firewall-cmd
// --zone=Z --ADD_OR_REMOVE-...=value` (without --permanent; callers issue it
// once as-is for the runtime effect and once more with --permanent
// prepended for persistence). verb is "add" or "remove".
//
// firewalld's simple --add-port/--add-service forms can't carry a source
// restriction, a non-accept action, or a comment, so a rule needs any of
// those falls back to a rich rule, which can express all of them.
func buildMutationArgs(rule firewall.Rule, zone, verb string) ([]string, error) {
	if rule.Direction == firewall.Out {
		return nil, fmt.Errorf("%w: firewalld zones filter inbound traffic; there is no simple per-rule outbound equivalent to ufw's \"out\"", firewall.ErrUnsupported)
	}
	if rule.Interface != "" {
		return nil, fmt.Errorf("%w: interface scoping in firewalld is a zone-to-interface binding (firewall-cmd --zone=Z --add-interface=IFACE), not a per-rule attribute", firewall.ErrUnsupported)
	}

	if useSimpleForm(rule) {
		if rule.ServiceName != "" {
			return []string{"--zone=" + zone, fmt.Sprintf("--%s-service=%s", verb, rule.ServiceName)}, nil
		}
		return []string{"--zone=" + zone, fmt.Sprintf("--%s-port=%s", verb, formatPort(rule))}, nil
	}

	rich, err := buildRichRule(rule)
	if err != nil {
		return nil, err
	}
	return []string{"--zone=" + zone, fmt.Sprintf("--%s-rich-rule=%s", verb, rich)}, nil
}

// useSimpleForm reports whether rule can be expressed with --add-port or
// --add-service, which only ever mean "accept from anywhere, no comment".
func useSimpleForm(rule firewall.Rule) bool {
	return rule.Action == firewall.Allow && isAny(rule.Source) && isAny(rule.Destination) && rule.Comment == ""
}

func formatPort(rule firewall.Rule) string {
	if rule.Protocol == "" {
		return rule.Port + "/tcp"
	}
	return rule.Port + "/" + string(rule.Protocol)
}

// buildRichRule renders firewalld's rich-rule language. Attribute order
// matches firewall-cmd's own canonical normalization, which matters because
// firewalld deduplicates/matches rich rules on exact string form.
func buildRichRule(rule firewall.Rule) (string, error) {
	var b strings.Builder
	family := "ipv4"
	if looksIPv6(rule.Source) || looksIPv6(rule.Destination) {
		family = "ipv6"
	}
	fmt.Fprintf(&b, `rule family="%s"`, family)

	if !isAny(rule.Source) {
		fmt.Fprintf(&b, ` source address="%s"`, rule.Source)
	}
	if !isAny(rule.Destination) {
		fmt.Fprintf(&b, ` destination address="%s"`, rule.Destination)
	}

	switch {
	case rule.ServiceName != "":
		fmt.Fprintf(&b, ` service name="%s"`, rule.ServiceName)
	case rule.Port != "":
		// Rich rules require an explicit protocol, unlike --add-port (see
		// formatPort below) which defaults a bare port to tcp. Default here
		// too so a comment or a source restriction — which both force the
		// rich-rule path — doesn't turn a previously-fine bare port number
		// into an error.
		proto := rule.Protocol
		if proto == "" {
			proto = firewall.TCP
		}
		fmt.Fprintf(&b, ` port port="%s" protocol="%s"`, rule.Port, proto)
	}

	action, err := richAction(rule.Action)
	if err != nil {
		return "", err
	}
	b.WriteString(" " + action)

	if rule.Comment != "" {
		fmt.Fprintf(&b, ` comment="%s"`, sanitizeComment(rule.Comment))
	}
	return b.String(), nil
}

func richAction(a firewall.Action) (string, error) {
	switch a {
	case firewall.Allow:
		return "accept", nil
	case firewall.Deny:
		return "drop", nil
	case firewall.Reject:
		return "reject", nil
	default:
		return "", fmt.Errorf("unknown action %q", a)
	}
}

// sanitizeComment strips double quotes so the value can't break out of the
// rich rule's comment="..." attribute; firewalld has no escaping mechanism
// for them.
func sanitizeComment(s string) string {
	return strings.ReplaceAll(s, `"`, "'")
}

func isAny(s string) bool {
	s = strings.TrimSpace(s)
	return s == "" || strings.EqualFold(s, "any")
}

func looksIPv6(s string) bool {
	return strings.Contains(s, ":")
}
