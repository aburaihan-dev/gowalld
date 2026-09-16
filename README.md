# gowalld

**One command for firewalld and ufw.** A devops CLI that manages both firewall backends through the same simple, `ufw`-style syntax — with built-in backup/restore, dry-run previews, and a guard against locking yourself out over SSH.

[![CI](https://github.com/aburaihan-dev/gowalld/actions/workflows/ci.yml/badge.svg)](https://github.com/aburaihan-dev/gowalld/actions/workflows/ci.yml)

Works identically on Ubuntu/Debian (`ufw`) and RHEL/AlmaLinux/Fedora (`firewalld`) — gowalld detects which one a host runs and speaks its native tongue underneath, so you don't have to remember two different firewall CLIs across a mixed fleet.

## Why

- **One syntax, two backends** — `gowalld allow 22/tcp` works the same on an Ubuntu box and a RHEL box, whichever firewall it actually runs.
- **Built-in backup/restore** — neither `firewall-cmd` nor `ufw` has one. `gowalld backup` snapshots the current rule set to a git-diffable YAML file; `gowalld restore` always previews the diff before touching anything.
- **Won't lock you out** — every rule change is checked against the SSH session you're using right now. If it would cut you off, gowalld refuses unless you explicitly force it.
- **Dry-run everything** — `--dry-run` prints the exact `firewall-cmd`/`ufw` commands gowalld would run, without running them.
- **Scriptable or interactive** — one-shot commands for automation and CI, or `gowalld tui` for an interactive rule browser.

## Quick start

```bash
# Build from source (requires Go 1.23+)
git clone https://github.com/aburaihan-dev/gowalld.git
cd gowalld
go build -o gowalld ./cmd/gowalld
sudo mv gowalld /usr/local/bin/

# See what firewall gowalld found, and its current state
sudo gowalld backend
sudo gowalld status

# Allow SSH from your admin network only
sudo gowalld allow 22/tcp --from 10.0.0.0/8 --comment "SSH admin"

# List the rules you just created
sudo gowalld list

# Take a backup before making a riskier change
sudo gowalld backup pre-change

# Preview a destructive change before it happens
sudo gowalld delete <rule-id> --dry-run
```

gowalld always needs root — both `firewall-cmd` and `ufw` require it for nearly every operation.

## Usage examples

```bash
# Allow a port, restricted to a source CIDR
sudo gowalld allow 22/tcp --from 10.0.0.0/8 --comment "SSH admin"

# Allow a named service instead of a raw port (firewalld service / ufw app profile)
sudo gowalld allow OpenSSH

# Silently drop traffic (no response sent)
sudo gowalld deny 23

# Reject traffic with an explicit response
sudo gowalld reject 8080/tcp --from 192.168.1.0/24

# Allow a port range
sudo gowalld allow 6000-6007/udp

# List rules, filtered
sudo gowalld list --proto tcp --action allow

# Delete by ID (from `gowalld list`) or by numbered index
sudo gowalld delete a1b2c3d4e5f6
sudo gowalld delete 3

# Edit a rule in place (delete + re-add under the hood)
sudo gowalld edit a1b2c3d4e5f6 --port 2222/tcp --from 10.0.0.0/8

# Preview any mutating command without applying it
sudo gowalld delete a1b2c3d4e5f6 --dry-run
sudo gowalld allow 443/tcp --dry-run

# Skip confirmation prompts (for scripts/CI)
sudo gowalld allow 80/tcp --yes

# Back up the current configuration
sudo gowalld backup                     # auto-named, written to /var/lib/gowalld/backups
sudo gowalld backup pre-migration       # explicit name
sudo gowalld backup --comment "before firewall audit"

# See what a backup would change, without applying it
sudo gowalld diff /var/lib/gowalld/backups/web01_ufw_20260916T102231Z.yaml

# Restore from a backup (always shows the diff first)
sudo gowalld restore /var/lib/gowalld/backups/web01_ufw_20260916T102231Z.yaml

# Machine-readable output for scripting
sudo gowalld list -o json | jq '.[] | select(.protocol=="tcp")'

# Force a firewalld zone explicitly
sudo gowalld allow 8443/tcp --zone dmz

# Reload the backend
sudo gowalld reload

# Launch the interactive rule browser
sudo gowalld tui
```

## Supported platforms

| Distro | Backend |
|---|---|
| Ubuntu / Debian | `ufw` |
| RHEL / AlmaLinux | `firewalld` |
| Fedora | `firewalld` |

gowalld auto-detects which backend is active; override with `--backend firewalld\|ufw` or `GOWALLD_BACKEND` when a host runs both or neither is currently active.

## Commands

| Command | Description |
|---|---|
| `status` | Show whether the firewall is enabled and its default policy |
| `list` (`ls`) | List firewall rules |
| `allow` | Allow traffic |
| `deny` | Silently drop traffic |
| `reject` | Reject traffic with an explicit response |
| `delete` (`rm`) | Delete a rule by ID or numbered index |
| `edit` | Replace a rule's action/port/source/etc. |
| `backup` | Snapshot the current firewall configuration to a file |
| `restore` | Restore firewall rules from a backup, after previewing the diff |
| `diff` | Compare a backup file against the live configuration |
| `reload` | Reload the firewall backend |
| `backend` | Show which firewall backend gowalld detected, and why |
| `tui` | Launch the interactive rule browser/editor |

Run `gowalld <command> --help` for a command's full flags. Global flags (apply to every command):

| Flag | Description |
|---|---|
| `--backend firewalld\|ufw` | Override backend detection |
| `--dry-run` | Print the commands that would run, without executing them |
| `-y`, `--yes` | Skip confirmation prompts |
| `-o`, `--output table\|json\|yaml` | Output format (default `table`) |
| `--zone` | firewalld zone (ignored on ufw) |
| `--force-lockout-risk` | Proceed even if the change would remove firewall access for the current SSH session |
| `-v`, `--verbose` | Show underlying backend command output |
| `--config <path>` | Path to a config file |

## Configuration

gowalld reads settings from, in ascending precedence: built-in defaults → `/etc/gowalld/config.yaml` → `~/.config/gowalld/config.yaml` (merged on top, for personal overrides) → `GOWALLD_*` environment variables → command-line flags.

```yaml
# /etc/gowalld/config.yaml
backend: ""                          # "" = auto-detect
default_zone: public                 # firewalld only
backup_dir: /var/lib/gowalld/backups
output_format: table
confirm: true                        # false behaves like always passing --yes
ssh_lockout_guard: true              # false behaves like always passing --force-lockout-risk
```

Use `--config <path>` to point at an entirely different file instead.

## Safety

- **Root required.** Both backends need it for nearly everything.
- **SSH self-lockout guard.** Before any rule change that could cut off your current SSH session, gowalld checks the session's source IP and port against the resulting rule set and refuses unless you pass `--force-lockout-risk`.
- **Dry-run.** `--dry-run` shows the exact backend commands without running them.
- **Confirmation prompts.** Destructive actions (`delete`, `edit`, `restore`, `reload`) ask before proceeding, unless `--yes` or `confirm: false` in config.
- **Restore always previews.** `gowalld restore` computes and prints the diff before applying anything, and never restores a snapshot from the other backend onto a mismatched host.

## Building from source

```bash
git clone https://github.com/aburaihan-dev/gowalld.git
cd gowalld
go build -o gowalld ./cmd/gowalld

# Run the test suite
go test ./...

# Cross-compile for a target host (gowalld itself only ever runs on Linux)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o gowalld-linux-amd64 ./cmd/gowalld
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o gowalld-linux-arm64 ./cmd/gowalld
```

Tagged releases are built for linux/amd64, linux/arm64, linux/arm, and linux/386 via [goreleaser](.goreleaser.yaml); see the [Releases](https://github.com/aburaihan-dev/gowalld/releases) page for prebuilt binaries once a version has been tagged.

## Project status

v1 is feature-complete: both backends, backup/restore, config, safety guards, and the TUI all work end-to-end. Deferred to v2: declarative `apply`/reconcile against a desired-state file (Terraform-style plan/apply). Out of scope by design: remote/multi-host management — wrap gowalld with Ansible or SSH for fleet-wide rollout instead of expecting it built in.
