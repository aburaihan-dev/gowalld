package exec

import (
	"context"
	"fmt"
	"strings"
)

// Call records one invocation made against a MockRunner, for assertions
// about exactly what argv a backend built.
type Call struct {
	Kind OpKind
	Name string
	Args []string
}

type mockResponse struct {
	result Result
	err    error
}

// MockRunner is a Runner used by backend unit tests: register expected
// name+args combinations with Expect, then assert against Calls after
// exercising the code under test. An unregistered call returns an error
// rather than panicking, so a mismatched-argv bug surfaces as a test failure
// with a clear message instead of a nil dereference downstream.
type MockRunner struct {
	responses map[string]mockResponse
	Calls     []Call
}

func NewMock() *MockRunner {
	return &MockRunner{responses: make(map[string]mockResponse)}
}

// Expect registers the Result/error to return for an exact name+args match.
func (m *MockRunner) Expect(name string, args []string, stdout string, err error) *MockRunner {
	m.responses[key(name, args)] = mockResponse{Result{Stdout: stdout}, err}
	return m
}

func (m *MockRunner) Run(_ context.Context, kind OpKind, name string, args ...string) (Result, error) {
	m.Calls = append(m.Calls, Call{Kind: kind, Name: name, Args: args})
	if resp, ok := m.responses[key(name, args)]; ok {
		return resp.result, resp.err
	}
	return Result{}, fmt.Errorf("mock: unexpected call: %s %s", name, strings.Join(args, " "))
}

func key(name string, args []string) string {
	return name + "\x00" + strings.Join(args, "\x00")
}
