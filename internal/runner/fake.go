package runner

import (
	"context"
	"io"
	"strings"
	"sync"
)

// FakeHandler decides what a fake command invocation returns.
type FakeHandler func(name string, args []string) ([]byte, error)

// Fake records every invocation and delegates results to a FakeHandler.
// It is intended for unit tests only.
type Fake struct {
	mu      sync.Mutex
	handler FakeHandler
	calls   []string
	argv    [][]string
	inputs  map[string]string
	// stdins keeps every stdin capture in call order.
	stdins []string
}

// NewFake returns a Fake runner backed by handle.
func NewFake(handle FakeHandler) *Fake {
	return &Fake{handler: handle, inputs: map[string]string{}}
}

// Reset forgets the recorded calls, so a test can assert on one step alone.
func (f *Fake) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls, f.argv, f.inputs, f.stdins = nil, nil, map[string]string{}, nil
}

func (f *Fake) record(name string, args []string, input string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := commandLine(name, args)
	f.calls = append(f.calls, line)
	f.argv = append(f.argv, append([]string{name}, args...))
	if input != "" {
		f.inputs[line] = input
	}
	f.stdins = append(f.stdins, input)
	return line
}

// Output implements Runner.
func (f *Fake) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	f.record(name, args, "")
	return f.handler(name, args)
}

// Run implements Runner.
func (f *Fake) Run(_ context.Context, name string, args ...string) error {
	f.record(name, args, "")
	_, err := f.handler(name, args)
	return err
}

// RunWithInput implements Runner and captures what was streamed to stdin.
func (f *Fake) RunWithInput(_ context.Context, input io.Reader, name string, args ...string) error {
	data, _ := io.ReadAll(input)
	f.record(name, args, string(data))
	_, err := f.handler(name, args)
	return err
}

// OutputWithInput implements Runner and captures what was streamed to stdin.
func (f *Fake) OutputWithInput(_ context.Context, input io.Reader, name string, args ...string) ([]byte, error) {
	data, _ := io.ReadAll(input)
	f.record(name, args, string(data))
	return f.handler(name, args)
}

// Calls returns every recorded invocation as a space-joined command line.
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// Argv returns every recorded invocation with argument boundaries intact.
func (f *Fake) Argv() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, len(f.argv))
	for i, a := range f.argv {
		out[i] = append([]string(nil), a...)
	}
	return out
}

// Input returns the stdin content streamed to the first invocation whose
// command line ends with suffix.
func (f *Fake) Input(suffix string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for line, in := range f.inputs {
		if strings.HasSuffix(line, suffix) {
			return in, true
		}
	}
	return "", false
}

// Inputs returns the stdin content of every invocation whose command line
// ends with suffix, in call order.
func (f *Fake) Inputs(suffix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for i, line := range f.calls {
		if strings.HasSuffix(line, suffix) {
			out = append(out, f.stdins[i])
		}
	}
	return out
}

// Called reports whether an invocation matching the full command line was recorded.
func (f *Fake) Called(line string) bool {
	for _, c := range f.Calls() {
		if c == line {
			return true
		}
	}
	return false
}

// CalledWithSuffix reports whether any invocation's command line ends with suffix.
func (f *Fake) CalledWithSuffix(suffix string) bool {
	for _, c := range f.Calls() {
		if strings.HasSuffix(c, suffix) {
			return true
		}
	}
	return false
}

// Dump returns all recorded invocations, one per line.
func (f *Fake) Dump() string {
	return strings.Join(f.Calls(), "\n")
}

func commandLine(name string, args []string) string {
	if len(args) == 0 {
		return name
	}
	return name + " " + strings.Join(args, " ")
}
