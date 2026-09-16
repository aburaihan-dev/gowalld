package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// ComputeID derives a deterministic content-hash for r, used as Rule.ID.
// Both backends call this from ListRules so that the same logical rule
// produces the same ID across repeated listings, even though neither
// firewall-cmd nor ufw exposes a stable rule identifier of its own.
func ComputeID(r Rule) string {
	fields := []string{
		string(r.Action),
		string(r.Direction),
		string(r.Protocol),
		normalizeEmpty(r.Port),
		normalizeEmpty(r.ServiceName),
		normalizeSource(r.Source),
		normalizeEmpty(r.Destination),
		normalizeEmpty(r.Interface),
		normalizeEmpty(r.Zone),
	}
	sum := sha256.Sum256([]byte(strings.Join(fields, "|")))
	return hex.EncodeToString(sum[:])[:12]
}

func normalizeEmpty(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func normalizeSource(s string) string {
	s = normalizeEmpty(s)
	if s == "" {
		return "any"
	}
	return s
}
