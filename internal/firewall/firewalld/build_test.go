package firewalld

import (
	"errors"
	"strings"
	"testing"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

func TestBuildMutationArgs(t *testing.T) {
	cases := []struct {
		name string
		rule firewall.Rule
		verb string
		want string
	}{
		{
			name: "simple allow port -> --add-port",
			rule: firewall.Rule{Action: firewall.Allow, Protocol: firewall.TCP, Port: "22"},
			verb: "add",
			want: `--zone=public --add-port=22/tcp`,
		},
		{
			name: "simple allow service -> --add-service",
			rule: firewall.Rule{Action: firewall.Allow, ServiceName: "http"},
			verb: "add",
			want: `--zone=public --add-service=http`,
		},
		{
			name: "port range keeps dash (native firewalld syntax)",
			rule: firewall.Rule{Action: firewall.Allow, Protocol: firewall.UDP, Port: "9000-9100"},
			verb: "add",
			want: `--zone=public --add-port=9000-9100/udp`,
		},
		{
			name: "source-scoped -> rich rule",
			rule: firewall.Rule{Action: firewall.Allow, Protocol: firewall.TCP, Port: "22", Source: "10.0.0.0/8", Comment: "SSH admin"},
			verb: "add",
			want: `--zone=public --add-rich-rule=rule family="ipv4" source address="10.0.0.0/8" port port="22" protocol="tcp" accept comment="SSH admin"`,
		},
		{
			name: "deny -> rich rule with drop",
			rule: firewall.Rule{Action: firewall.Deny, Protocol: firewall.TCP, Port: "23"},
			verb: "remove",
			want: `--zone=public --remove-rich-rule=rule family="ipv4" port port="23" protocol="tcp" drop`,
		},
		{
			name: "reject service from CIDR -> rich rule",
			rule: firewall.Rule{Action: firewall.Reject, ServiceName: "http", Source: "192.168.1.0/24"},
			verb: "add",
			want: `--zone=public --add-rich-rule=rule family="ipv4" source address="192.168.1.0/24" service name="http" reject`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildMutationArgs(tc.rule, "public", tc.verb)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			joined := strings.Join(got, " ")
			if joined != tc.want {
				t.Errorf("buildMutationArgs() = %q, want %q", joined, tc.want)
			}
		})
	}
}

func TestBuildMutationArgsRejectsOutbound(t *testing.T) {
	_, err := buildMutationArgs(firewall.Rule{Action: firewall.Allow, Direction: firewall.Out, Port: "22"}, "public", "add")
	if !errors.Is(err, firewall.ErrUnsupported) {
		t.Errorf("err = %v, want ErrUnsupported", err)
	}
}

func TestBuildMutationArgsRejectsInterface(t *testing.T) {
	_, err := buildMutationArgs(firewall.Rule{Action: firewall.Allow, Port: "22", Interface: "eth0"}, "public", "add")
	if !errors.Is(err, firewall.ErrUnsupported) {
		t.Errorf("err = %v, want ErrUnsupported", err)
	}
}

func TestBuildRichRulePortWithoutProtocolErrors(t *testing.T) {
	_, err := buildMutationArgs(firewall.Rule{Action: firewall.Allow, Port: "22", Source: "10.0.0.0/8"}, "public", "add")
	if err == nil {
		t.Fatal("expected an error for a port without a protocol in rich-rule form")
	}
}
