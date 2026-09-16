package ufw

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

// numberedRule pairs a parsed Rule with the numbered index ufw reports it
// at, since ufw's own "delete" command addresses rules by that transient
// position rather than any stable ID.
type numberedRule struct {
	Index int
	Rule  firewall.Rule
}

var (
	statusLineRE  = regexp.MustCompile(`^Status:\s*(\w+)`)
	defaultLineRE = regexp.MustCompile(`^Default:\s*(\w+)\s*\(incoming\),\s*(\w+)\s*\(outgoing\)`)
	// e.g. "[ 1] 22/tcp                     ALLOW IN    10.0.0.0/8                 # SSH admin"
	numberedLineRE = regexp.MustCompile(`^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT)\s+(.+?)(?:\s{2,}#\s*(.*))?$`)
)

// parseStatus reads `ufw status verbose` output.
func parseStatus(out string) (*firewall.Status, error) {
	status := &firewall.Status{Backend: firewall.UFW, Raw: out}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if m := statusLineRE.FindStringSubmatch(line); m != nil {
			status.Enabled = strings.EqualFold(m[1], "active")
			continue
		}
		if m := defaultLineRE.FindStringSubmatch(line); m != nil {
			status.DefaultIn = parseAction(m[1])
			status.DefaultOut = parseAction(m[2])
		}
	}
	return status, nil
}

func parseAction(s string) firewall.Action {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "allow":
		return firewall.Allow
	case "deny":
		return firewall.Deny
	case "reject":
		return firewall.Reject
	default:
		return firewall.Deny
	}
}

// listNumbered reads `ufw status numbered` output. IPv6 duplicate entries
// (ufw auto-mirrors every rule as a "(v6)" counterpart) are skipped: they
// carry the same rule intent as their v4 line and including both would
// double every rule in list/backup/restore output.
func listNumbered(out string) ([]numberedRule, error) {
	var rules []numberedRule
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		m := numberedLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if strings.Contains(m[2], "(v6)") || strings.Contains(m[5], "(v6)") {
			continue
		}
		var idx int
		if _, err := fmt.Sscanf(m[1], "%d", &idx); err != nil {
			continue
		}

		rule := firewall.Rule{
			Action:    parseAction(m[3]),
			Direction: firewall.In,
			Source:    parseFromField(m[5]),
			Comment:   strings.TrimSpace(m[6]),
			Permanent: true,
		}
		if strings.EqualFold(m[4], "OUT") {
			rule.Direction = firewall.Out
		}
		port, proto, svc := parseToField(m[2])
		rule.Port = port
		rule.Protocol = proto
		rule.ServiceName = svc
		rule.ID = firewall.ComputeID(rule)

		rules = append(rules, numberedRule{Index: idx, Rule: rule})
	}
	return rules, nil
}

// parseToField splits ufw's "To" column into a port/proto or, when it isn't
// shaped like a port spec, an opaque service/app profile name.
func parseToField(s string) (port string, proto firewall.Protocol, serviceName string) {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "Anywhere") {
		return "", "", ""
	}
	if idx := strings.LastIndex(s, "/"); idx != -1 {
		port = portFromUfw(s[:idx])
		switch strings.ToLower(s[idx+1:]) {
		case "tcp":
			proto = firewall.TCP
		case "udp":
			proto = firewall.UDP
		}
		return port, proto, ""
	}
	if isPortLike(s) {
		return portFromUfw(s), "", ""
	}
	// Not a recognizable port spec (e.g. "OpenSSH" app profile name) —
	// pass it through as an opaque service name.
	return "", "", s
}

func isPortLike(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && r != ':' && r != ',' && r != '-' {
			return false
		}
	}
	return s != ""
}

func parseFromField(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "Anywhere") {
		return ""
	}
	return s
}

// portFromUfw converts ufw's colon-delimited range ("8000:9000") to
// gowalld's canonical dash form ("8000-9000"); single ports pass through.
func portFromUfw(s string) string {
	return strings.ReplaceAll(s, ":", "-")
}

// portToUfw is the inverse of portFromUfw, used when building argv.
func portToUfw(s string) string {
	return strings.ReplaceAll(s, "-", ":")
}
