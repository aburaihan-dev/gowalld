// Package exec is the single seam through which every backend shells out to
// firewall-cmd or ufw. Routing every subprocess call through the Runner
// interface — tagged as a Read or Write operation — is what lets --dry-run
// intercept mutating calls without any per-command branching in the
// firewalld/ufw backend code, and lets unit tests exercise argv-building and
// output-parsing without a real Linux firewall.
package exec

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// OpKind marks whether a Runner call reads state or mutates it. DryRunRunner
// uses this to decide whether to actually execute.
type OpKind int

const (
	Read OpKind = iota
	Write
)

// Result is the captured output of a subprocess invocation.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Runner executes a named command with arguments and returns its output.
// Every Firewall backend method takes a Runner at construction time instead
// of calling os/exec directly.
type Runner interface {
	Run(ctx context.Context, kind OpKind, name string, args ...string) (Result, error)
}

// RealRunner executes commands via os/exec.
type RealRunner struct{}

func (RealRunner) Run(ctx context.Context, _ OpKind, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	res := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	if exitErr, ok := runErr.(*exec.ExitError); ok {
		res.ExitCode = exitErr.ExitCode()
	}
	if runErr != nil {
		return res, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), runErr, strings.TrimSpace(res.Stderr))
	}
	return res, nil
}

// DryRunRunner passes Read calls through to Underlying so status/list output
// stays accurate under --dry-run, and intercepts Write calls, printing the
// argv that would have run instead of executing it.
type DryRunRunner struct {
	Underlying Runner
	Print      func(name string, args []string)
}

func (d DryRunRunner) Run(ctx context.Context, kind OpKind, name string, args ...string) (Result, error) {
	if kind == Read {
		return d.Underlying.Run(ctx, kind, name, args...)
	}
	if d.Print != nil {
		d.Print(name, args)
	}
	return Result{}, nil
}
