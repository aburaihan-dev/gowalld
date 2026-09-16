package firewalld

import (
	"regexp"
	"strings"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

var (
	keyLineRE  = regexp.MustCompile(`^([\w-]+):\s*(.*)$`)
	sourceRE   = regexp.MustCompile(`\bsource address="([^"]+)"`)
	destRE     = regexp.MustCompile(`\bdestination address="([^"]+)"`)
	serviceRE  = regexp.MustCompile(`\bservice name="([^"]+)"`)
	portRE     = regexp.MustCompile(`\bport port="([^"]+)" protocol="(\w+)"`)
	commentRE  = regexp.MustCompile(`\bcomment="([^"]*)"`)
	richVerbRE = regexp.MustCompile(`\b(accept|reject|drop)\b`)
)

// zoneListing is what a single `--list-all` invocation yields: the zone's
// default-policy target (used for Status) plus every rule it configures.
type zoneListing struct {
	Target string
	Rules  []firewall.Rule
}

// parseListAll reads `firewall-cmd [--permanent] --zone=Z --list-all`
// output. Every returned Rule has Zone/Permanent/ID already populated.
func parseListAll(out, zone string, permanent bool) zoneListing {
	var listing zoneListing

	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if strings.HasPrefix(trimmed, "rule ") {
			if r, ok := parseRichRule(trimmed); ok {
				listing.Rules = append(listing.Rules, finalizeRule(r, zone, permanent))
			}
			continue
		}

		if m := keyLineRE.FindStringSubmatch(trimmed); m != nil {
			key, value := m[1], strings.TrimSpace(m[2])
			switch key {
			case "target":
				listing.Target = value
			case "services":
				for _, name := range fields(value) {
					r := firewall.Rule{Action: firewall.Allow, Direction: firewall.In, ServiceName: name}
					listing.Rules = append(listing.Rules, finalizeRule(r, zone, permanent))
				}
			case "ports":
				for _, spec := range fields(value) {
					port, proto := splitPortProto(spec)
					r := firewall.Rule{Action: firewall.Allow, Direction: firewall.In, Port: port, Protocol: proto}
					listing.Rules = append(listing.Rules, finalizeRule(r, zone, permanent))
				}
			}
			continue
		}
		// Anything else (the zone header line "public (active)", blank
		// "sources:"/"interfaces:" values, etc.) carries no rule data.
	}
	return listing
}

func finalizeRule(r firewall.Rule, zone string, permanent bool) firewall.Rule {
	r.Zone = zone
	r.Permanent = permanent
	r.ID = firewall.ComputeID(r)
	return r
}

func fields(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.Fields(s)
}

func splitPortProto(spec string) (port string, proto firewall.Protocol) {
	idx := strings.LastIndex(spec, "/")
	if idx == -1 {
		return spec, ""
	}
	switch strings.ToLower(spec[idx+1:]) {
	case "tcp":
		return spec[:idx], firewall.TCP
	case "udp":
		return spec[:idx], firewall.UDP
	default:
		return spec, ""
	}
}

// parseRichRule extracts the fields gowalld itself writes via buildRichRule.
// firewalld's rich-rule grammar is much larger than this (icmp-blocks, log,
// audit, limit, masquerade, forward-port rules, …); anything gowalld didn't
// write itself that doesn't match this shape is skipped rather than
// mis-represented, since a wrong parse is worse than a missing list entry.
func parseRichRule(line string) (firewall.Rule, bool) {
	m := richVerbRE.FindStringSubmatch(line)
	if m == nil {
		return firewall.Rule{}, false
	}
	r := firewall.Rule{Direction: firewall.In}
	switch m[1] {
	case "accept":
		r.Action = firewall.Allow
	case "drop":
		r.Action = firewall.Deny
	case "reject":
		r.Action = firewall.Reject
	}
	if sm := sourceRE.FindStringSubmatch(line); sm != nil {
		r.Source = sm[1]
	}
	if dm := destRE.FindStringSubmatch(line); dm != nil {
		r.Destination = dm[1]
	}
	if svcm := serviceRE.FindStringSubmatch(line); svcm != nil {
		r.ServiceName = svcm[1]
	} else if pm := portRE.FindStringSubmatch(line); pm != nil {
		r.Port = pm[1]
		switch strings.ToLower(pm[2]) {
		case "tcp":
			r.Protocol = firewall.TCP
		case "udp":
			r.Protocol = firewall.UDP
		}
	}
	if cm := commentRE.FindStringSubmatch(line); cm != nil {
		r.Comment = cm[1]
	}
	return r, true
}

// mapTarget converts a zone's firewalld "target" into gowalld's DefaultIn.
// Built-in zones normally report target "default", which behaves as an
// implicit deny/reject for unmatched traffic.
func mapTarget(target string) firewall.Action {
	switch strings.ToUpper(strings.TrimSpace(target)) {
	case "ACCEPT":
		return firewall.Allow
	case "DROP":
		return firewall.Deny
	case "REJECT", "%%REJECT%%":
		return firewall.Reject
	default:
		return firewall.Deny
	}
}

// parseActiveZones reads `firewall-cmd --get-active-zones`: zone names are
// the lines with no leading whitespace; everything indented under one
// (interfaces:/sources:) is that zone's detail and is ignored here.
func parseActiveZones(out string) []string {
	var zones []string
	for _, raw := range strings.Split(out, "\n") {
		if raw == "" || strings.TrimSpace(raw) == "" {
			continue
		}
		if raw[0] == ' ' || raw[0] == '\t' {
			continue
		}
		zones = append(zones, strings.TrimSpace(raw))
	}
	return zones
}

// isRunning interprets `firewall-cmd --state` output.
func isRunning(out string) bool {
	return strings.TrimSpace(out) == "running"
}
