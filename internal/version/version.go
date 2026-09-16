// Package version holds build-time metadata injected via -ldflags.
package version

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns a human-readable version line for --version output.
func String() string {
	return Version + " (commit " + Commit + ", built " + Date + ")"
}
