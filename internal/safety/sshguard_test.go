package safety

import (
	"testing"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

func TestWouldLockout(t *testing.T) {
	sess := &Session{ClientIP: "203.0.113.5", ServerPort: "22"}

	cases := []struct {
		name      string
		rules     []firewall.Rule
		defaultIn firewall.Action
		want      bool
	}{
		{
			name:      "no rules, default deny -> locked out",
			rules:     nil,
			defaultIn: firewall.Deny,
			want:      true,
		},
		{
			name:      "no rules, default allow -> safe",
			rules:     nil,
			defaultIn: firewall.Allow,
			want:      false,
		},
		{
			name: "allow 22 from any -> safe",
			rules: []firewall.Rule{
				{Action: firewall.Allow, Direction: firewall.In, Port: "22"},
			},
			defaultIn: firewall.Deny,
			want:      false,
		},
		{
			name: "allow 22 from unrelated CIDR -> locked out",
			rules: []firewall.Rule{
				{Action: firewall.Allow, Direction: firewall.In, Port: "22", Source: "10.0.0.0/8"},
			},
			defaultIn: firewall.Deny,
			want:      true,
		},
		{
			name: "allow 22 from matching CIDR -> safe",
			rules: []firewall.Rule{
				{Action: firewall.Allow, Direction: firewall.In, Port: "22", Source: "203.0.113.0/24"},
			},
			defaultIn: firewall.Deny,
			want:      false,
		},
		{
			name: "allow 80 only -> locked out",
			rules: []firewall.Rule{
				{Action: firewall.Allow, Direction: firewall.In, Port: "80"},
			},
			defaultIn: firewall.Deny,
			want:      true,
		},
		{
			name: "allow range covering 22 -> safe",
			rules: []firewall.Rule{
				{Action: firewall.Allow, Direction: firewall.In, Port: "20-25"},
			},
			defaultIn: firewall.Deny,
			want:      false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := WouldLockout(sess, tc.defaultIn, tc.rules)
			if got != tc.want {
				t.Errorf("WouldLockout() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWouldLockoutNilSession(t *testing.T) {
	if WouldLockout(nil, firewall.Deny, nil) {
		t.Error("nil session should never report lockout risk")
	}
}
