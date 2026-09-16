package firewall

import "testing"

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in          string
		port        string
		proto       Protocol
		serviceName string
		wantErr     bool
	}{
		{in: "22/tcp", port: "22", proto: TCP},
		{in: "8000-9000/udp", port: "8000-9000", proto: UDP},
		{in: "22", port: "22"},
		{in: "OpenSSH", serviceName: "OpenSSH"},
		{in: "22/sctp", wantErr: true},
		{in: "abc/tcp", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			port, proto, svc, err := ParseTarget(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if port != tc.port || proto != tc.proto || svc != tc.serviceName {
				t.Errorf("ParseTarget(%q) = (%q, %q, %q), want (%q, %q, %q)", tc.in, port, proto, svc, tc.port, tc.proto, tc.serviceName)
			}
		})
	}
}
