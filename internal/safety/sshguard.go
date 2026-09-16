// Package safety guards against a gowalld command cutting off the very SSH
// session used to run it — the classic "locked myself out of the box"
// firewall mistake.
package safety

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

// Session is the SSH connection gowalld itself is running under.
type Session struct {
	ClientIP   string
	ServerPort string
}

// SessionInspector finds the current SSH session, if any. It's an interface
// so tests can supply a fixed session instead of depending on real
// environment/process state.
type SessionInspector interface {
	CurrentSession(ctx context.Context) (*Session, bool)
}

// EnvInspector reads the SSH_CONNECTION environment variable that sshd sets
// for every session ("client_ip client_port server_ip server_port"). This is
// best-effort: it only sees the invoking shell's own connection, and misses
// cases like a screen/tmux session detached from the original SSH login.
type EnvInspector struct{}

func (EnvInspector) CurrentSession(_ context.Context) (*Session, bool) {
	raw := os.Getenv("SSH_CONNECTION")
	fields := strings.Fields(raw)
	if len(fields) != 4 {
		return nil, false
	}
	return &Session{ClientIP: fields[0], ServerPort: fields[3]}, true
}

// WouldLockout reports whether, given the resulting rule set and default
// incoming policy, sess's connection would no longer be permitted. It is a
// heuristic: rules referencing an opaque ServiceName can't be resolved to a
// port without the backend's own service registry, so they're treated as
// NOT covering the session — biasing toward false-positive warnings rather
// than a missed lockout.
func WouldLockout(sess *Session, defaultIn firewall.Action, rules []firewall.Rule) bool {
	if sess == nil {
		return false
	}
	for _, r := range rules {
		if r.Direction == firewall.Out || r.Action != firewall.Allow {
			continue
		}
		if !portCoversSession(r, sess.ServerPort) {
			continue
		}
		if !sourceMatches(r.Source, sess.ClientIP) {
			continue
		}
		return false // an allow rule still covers this session
	}
	return defaultIn != firewall.Allow
}

func portCoversSession(r firewall.Rule, serverPort string) bool {
	if r.Port == "" {
		// No port restriction: a plain source-scoped allow, or a
		// service-name rule we can't resolve — conservatively assume it
		// does NOT cover the session unless it truly has no port field
		// at all (i.e. genuinely unrestricted by port).
		return r.ServiceName == ""
	}
	return portSpecContains(r.Port, serverPort)
}

func portSpecContains(spec, port string) bool {
	target, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if lo, hi, ok := parseRange(part); ok {
			if target >= lo && target <= hi {
				return true
			}
			continue
		}
		if n, err := strconv.Atoi(part); err == nil && n == target {
			return true
		}
	}
	return false
}

func parseRange(s string) (lo, hi int, ok bool) {
	i := strings.Index(s, "-")
	if i < 0 {
		return 0, 0, false
	}
	lo, err1 := strconv.Atoi(s[:i])
	hi, err2 := strconv.Atoi(s[i+1:])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return lo, hi, true
}

func sourceMatches(ruleSource, clientIP string) bool {
	ruleSource = strings.TrimSpace(ruleSource)
	if ruleSource == "" || strings.EqualFold(ruleSource, "any") {
		return true
	}
	client := net.ParseIP(clientIP)
	if client == nil {
		return false
	}
	if _, cidr, err := net.ParseCIDR(ruleSource); err == nil {
		return cidr.Contains(client)
	}
	return net.ParseIP(ruleSource).Equal(client)
}
