package ufw

import (
	"testing"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

const statusVerboseFixture = `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
`

const statusNumberedFixture = `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 3] 80,443/tcp                 ALLOW IN    Anywhere
[ 4] 22/tcp                     ALLOW IN    10.0.0.0/8                 # SSH admin
[ 5] Anywhere                   DENY IN     192.168.1.0/24
[ 6] 8000:9000/udp              REJECT OUT  Anywhere
`

func TestParseStatus(t *testing.T) {
	status, err := parseStatus(statusVerboseFixture)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Enabled {
		t.Error("expected Enabled=true")
	}
	if status.DefaultIn != firewall.Deny {
		t.Errorf("DefaultIn = %v, want deny", status.DefaultIn)
	}
	if status.DefaultOut != firewall.Allow {
		t.Errorf("DefaultOut = %v, want allow", status.DefaultOut)
	}
}

func TestListNumbered(t *testing.T) {
	rules, err := listNumbered(statusNumberedFixture)
	if err != nil {
		t.Fatal(err)
	}
	// 6 lines in fixture minus 1 skipped (v6) = 5.
	if len(rules) != 5 {
		t.Fatalf("got %d rules, want 5: %+v", len(rules), rules)
	}

	r1 := rules[0].Rule
	if rules[0].Index != 1 || r1.Port != "22" || r1.Protocol != firewall.TCP || r1.Action != firewall.Allow || r1.Source != "" {
		t.Errorf("rule 1 mismatch: %+v", r1)
	}

	// index 3 in output is the 3rd surviving entry (80,443/tcp), since [2] was skipped.
	r3 := rules[1].Rule
	if rules[1].Index != 3 || r3.Port != "80,443" {
		t.Errorf("rule [3] mismatch: %+v (index %d)", r3, rules[1].Index)
	}

	r4 := rules[2].Rule
	if rules[2].Index != 4 || r4.Port != "22" || r4.Source != "10.0.0.0/8" || r4.Comment != "SSH admin" {
		t.Errorf("rule [4] mismatch: %+v", r4)
	}

	r5 := rules[3].Rule
	if rules[3].Index != 5 || r5.Action != firewall.Deny || r5.Port != "" || r5.Source != "192.168.1.0/24" {
		t.Errorf("rule [5] mismatch: %+v", r5)
	}

	r6 := rules[4].Rule
	if rules[4].Index != 6 || r6.Action != firewall.Reject || r6.Direction != firewall.Out || r6.Port != "8000-9000" || r6.Protocol != firewall.UDP {
		t.Errorf("rule [6] mismatch: %+v", r6)
	}
}
