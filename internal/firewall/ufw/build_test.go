package ufw

import (
	"strings"
	"testing"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

func TestBuildAddArgs(t *testing.T) {
	cases := []struct {
		name string
		rule firewall.Rule
		want string
	}{
		{
			name: "simple port allow",
			rule: firewall.Rule{Action: firewall.Allow, Protocol: firewall.TCP, Port: "22"},
			want: "allow 22/tcp",
		},
		{
			name: "port range",
			rule: firewall.Rule{Action: firewall.Deny, Protocol: firewall.UDP, Port: "8000-9000"},
			want: "deny 8000:9000/udp",
		},
		{
			name: "with source, extended form",
			rule: firewall.Rule{Action: firewall.Allow, Protocol: firewall.TCP, Port: "22", Source: "10.0.0.0/8", Comment: "SSH admin"},
			want: "allow proto tcp from 10.0.0.0/8 to any port 22 comment SSH admin",
		},
		{
			name: "outbound reject",
			rule: firewall.Rule{Action: firewall.Reject, Direction: firewall.Out, Protocol: firewall.TCP, Port: "443"},
			want: "reject out 443/tcp",
		},
		{
			name: "service name, no proto",
			rule: firewall.Rule{Action: firewall.Allow, ServiceName: "OpenSSH"},
			want: "allow OpenSSH",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.Join(buildAddArgs(tc.rule), " ")
			if got != tc.want {
				t.Errorf("buildAddArgs() = %q, want %q", got, tc.want)
			}
		})
	}
}
