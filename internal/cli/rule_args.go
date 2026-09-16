package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

var (
	ruleFrom    string
	ruleTo      string
	ruleIface   string
	ruleComment string
	ruleOut     bool
)

func addRuleFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&ruleFrom, "from", "", "restrict to a source CIDR (default: any)")
	cmd.Flags().StringVar(&ruleTo, "to", "", "restrict to a destination CIDR (default: any)")
	cmd.Flags().StringVar(&ruleIface, "iface", "", "restrict to a network interface")
	cmd.Flags().StringVar(&ruleComment, "comment", "", "attach a comment to the rule")
	cmd.Flags().BoolVar(&ruleOut, "out", false, "apply to outbound traffic instead of inbound")
}

// parseTarget interprets the positional "<port[/proto]>|<service>" argument
// shared by allow/deny/reject, e.g. "22/tcp", "8000-9000/udp", or "OpenSSH".
func parseTarget(s string) (port string, proto firewall.Protocol, serviceName string, err error) {
	if idx := strings.LastIndex(s, "/"); idx != -1 {
		portPart, protoPart := s[:idx], s[idx+1:]
		if !isPortSpec(portPart) {
			return "", "", "", fmt.Errorf("invalid port %q in %q", portPart, s)
		}
		switch strings.ToLower(protoPart) {
		case "tcp":
			return portPart, firewall.TCP, "", nil
		case "udp":
			return portPart, firewall.UDP, "", nil
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

func runAddRule(cmd *cobra.Command, action firewall.Action, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected exactly one argument: <port[/proto]>|<service>")
	}
	port, proto, serviceName, err := parseTarget(args[0])
	if err != nil {
		return err
	}
	direction := firewall.In
	if ruleOut {
		direction = firewall.Out
	}
	rule := firewall.Rule{
		Action:      action,
		Direction:   direction,
		Protocol:    proto,
		Port:        port,
		ServiceName: serviceName,
		Source:      ruleFrom,
		Destination: ruleTo,
		Interface:   ruleIface,
		Zone:        flagZone,
		Comment:     ruleComment,
	}

	svc, err := newService(cmd.Context())
	if err != nil {
		return err
	}
	return svc.AddRule(cmd.Context(), rule)
}
