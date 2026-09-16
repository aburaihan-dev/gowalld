package firewall

import "errors"

var (
	// ErrNoBackendDetected is returned by detection when neither firewalld
	// nor ufw could be confirmed active, and no override was given.
	ErrNoBackendDetected = errors.New("no active firewall backend detected (pass --backend to override)")

	// ErrUnsupported is returned when a Rule field or operation has no
	// equivalent on the target backend (e.g. ufw rate-limit on firewalld).
	ErrUnsupported = errors.New("unsupported on this backend")

	// ErrCrossBackendRestore is returned when a snapshot captured from one
	// backend is restored against a host running the other.
	ErrCrossBackendRestore = errors.New("snapshot backend does not match the host's active backend")

	// ErrRuleNotFound is returned when a RuleRef cannot be resolved against
	// the live rule set.
	ErrRuleNotFound = errors.New("rule not found")
)
