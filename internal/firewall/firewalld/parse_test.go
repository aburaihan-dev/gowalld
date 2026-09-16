package firewalld

import (
	"testing"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

const listAllFixture = `public (active)
  target: default
  icmp-block-inversion: no
  interfaces: eth0
  sources:
  services: ssh dhcpv6-client
  ports: 8080/tcp 9000-9100/udp
  protocols:
  forward: no
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:
	rule family="ipv4" source address="10.0.0.0/8" port port="22" protocol="tcp" accept comment="SSH admin"
	rule family="ipv4" source address="192.168.1.0/24" service name="http" reject
	rule family="ipv4" port port="23" protocol="tcp" drop
`

func TestParseListAll(t *testing.T) {
	listing := parseListAll(listAllFixture, "public", true)

	if listing.Target != "default" {
		t.Errorf("Target = %q, want %q", listing.Target, "default")
	}

	// 2 services + 2 ports + 3 rich rules = 7.
	if len(listing.Rules) != 7 {
		t.Fatalf("got %d rules, want 7: %+v", len(listing.Rules), listing.Rules)
	}

	byServiceOrPort := func(name string) *firewall.Rule {
		for i, r := range listing.Rules {
			if r.ServiceName == name {
				return &listing.Rules[i]
			}
		}
		return nil
	}

	ssh := byServiceOrPort("ssh")
	if ssh == nil || ssh.Action != firewall.Allow || ssh.Zone != "public" || !ssh.Permanent {
		t.Errorf("ssh service rule wrong: %+v", ssh)
	}

	var port8080 *firewall.Rule
	for i, r := range listing.Rules {
		if r.Port == "8080" {
			port8080 = &listing.Rules[i]
		}
	}
	if port8080 == nil || port8080.Protocol != firewall.TCP || port8080.Action != firewall.Allow {
		t.Errorf("port 8080 rule wrong: %+v", port8080)
	}

	var richSSH *firewall.Rule
	for i, r := range listing.Rules {
		if r.Comment == "SSH admin" {
			richSSH = &listing.Rules[i]
		}
	}
	if richSSH == nil || richSSH.Source != "10.0.0.0/8" || richSSH.Port != "22" || richSSH.Protocol != firewall.TCP || richSSH.Action != firewall.Allow {
		t.Errorf("rich rule SSH admin wrong: %+v", richSSH)
	}

	httpReject := byServiceOrPort("http")
	if httpReject == nil || httpReject.Action != firewall.Reject || httpReject.Source != "192.168.1.0/24" {
		t.Errorf("http reject rich rule wrong: %+v", httpReject)
	}

	var drop23 *firewall.Rule
	for i, r := range listing.Rules {
		if r.Port == "23" {
			drop23 = &listing.Rules[i]
		}
	}
	if drop23 == nil || drop23.Action != firewall.Deny || drop23.Source != "" {
		t.Errorf("drop 23 rich rule wrong: %+v", drop23)
	}
}

func TestMapTarget(t *testing.T) {
	cases := map[string]firewall.Action{
		"default":    firewall.Deny,
		"ACCEPT":     firewall.Allow,
		"DROP":       firewall.Deny,
		"%%REJECT%%": firewall.Reject,
		"REJECT":     firewall.Reject,
	}
	for target, want := range cases {
		if got := mapTarget(target); got != want {
			t.Errorf("mapTarget(%q) = %v, want %v", target, got, want)
		}
	}
}

func TestParseActiveZones(t *testing.T) {
	out := "public\n  interfaces: eth0\ndocker\n  interfaces: docker0\n"
	zones := parseActiveZones(out)
	if len(zones) != 2 || zones[0] != "public" || zones[1] != "docker" {
		t.Errorf("parseActiveZones() = %v", zones)
	}
}
