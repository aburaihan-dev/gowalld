package firewall

import (
	"fmt"
	"strings"
)

// ParseTarget interprets the "<port[/proto]>|<service>" shorthand used by
// both the CLI (`gowalld allow 22/tcp`) and the TUI's add/edit form, e.g.
// "22/tcp", "8000-9000/udp", or "OpenSSH".
func ParseTarget(s string) (port string, proto Protocol, serviceName string, err error) {
	if idx := strings.LastIndex(s, "/"); idx != -1 {
		portPart, protoPart := s[:idx], s[idx+1:]
		if !isPortSpec(portPart) {
			return "", "", "", fmt.Errorf("invalid port %q in %q", portPart, s)
		}
		switch strings.ToLower(protoPart) {
		case "tcp":
			return portPart, TCP, "", nil
		case "udp":
			return portPart, UDP, "", nil
		default:
			return "", "", "", fmt.Errorf("invalid protocol %q (want tcp or udp)", protoPart)
		}
	}
	if isPortSpec(s) {
		return s, "", "", nil
	}
	// Not a port spec — treat as an opaque service/app profile name
	// (firewalld service or ufw app profile), resolved by the backend.
	return "", "", s, nil
}

func isPortSpec(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}
