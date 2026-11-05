// Package runner abstracts process execution so the CLI can be tested without
// spawning real commands.
package runner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// waitDelay is how long a cancelled command gets after SIGINT before SIGKILL.
const waitDelay = 5 * time.Second

// Runner executes external commands.
type Runner interface {
	// Output runs a command, returns its stdout and streams stderr to the user.
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
	// Run runs a command with stdin, stdout and stderr attached to the terminal.
	Run(ctx context.Context, name string, args ...string) error
	// RunWithInput runs a command with the given stdin; stdout/stderr go to the terminal.
	RunWithInput(ctx context.Context, input io.Reader, name string, args ...string) error
	// OutputWithInput runs a command with the given stdin and returns its stdout.
	OutputWithInput(ctx context.Context, input io.Reader, name string, args ...string) ([]byte, error)
}

// Exec is the production Runner backed by os/exec.
type Exec struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// NewExec returns an Exec on the process' stdin and stderr whose commands
// write their stdout to stdout: the terminal, or stderr while skiff's own
// stdout carries a result (--json) or a byte stream, which output from a
// setup script or an image build would otherwise corrupt.
func NewExec(stdout io.Writer) *Exec {
	return &Exec{Stdin: os.Stdin, Stdout: stdout, Stderr: os.Stderr}
}

// Silenced returns a Runner whose commands neither read nor write the
// terminal, for work in the background of an interactive session. Output
// still folds stderr into its errors. Runners other than Exec (test fakes)
// are returned unchanged.
func Silenced(r Runner) Runner {
	if _, ok := r.(*Exec); !ok {
		return r
	}
	return &Exec{Stdout: io.Discard, Stderr: io.Discard}
}

// Output implements Runner. Stderr is both streamed and captured so that error
// messages carry the command's own diagnostics.
func (e *Exec) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return e.OutputWithInput(ctx, nil, name, args...)
}

// OutputWithInput implements Runner.
func (e *Exec) OutputWithInput(ctx context.Context, input io.Reader, name string, args ...string) ([]byte, error) {
	var captured bytes.Buffer
	cmd := newCommand(ctx, name, args...)
	cmd.Stdin = input
	cmd.Stderr = io.MultiWriter(e.Stderr, &captured)
	out, err := cmd.Output()
	if err != nil {
		return out, commandError(name, args, err, captured.String())
	}
	return out, nil
}

// Run implements Runner.
func (e *Exec) Run(ctx context.Context, name string, args ...string) error {
	return e.RunWithInput(ctx, e.Stdin, name, args...)
}

// RunWithInput implements Runner.
func (e *Exec) RunWithInput(ctx context.Context, input io.Reader, name string, args ...string) error {
	cmd := newCommand(ctx, name, args...)
	cmd.Stdin = input
	cmd.Stdout = e.Stdout
	cmd.Stderr = e.Stderr
	if err := cmd.Run(); err != nil {
		return commandError(name, args, err, "")
	}
	return nil
}

// newCommand wires context cancellation to a polite SIGINT followed by SIGKILL
// after waitDelay, so Ctrl-C in skiff also stops container and ssh.
func newCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = waitDelay
	return cmd
}

// commandError wraps err (keeping *exec.ExitError reachable via errors.As) and
// appends the last stderr line, which usually carries the actual diagnosis.
func commandError(name string, args []string, err error, stderr string) error {
	suffix := ""
	if s := strings.TrimSpace(stderr); s != "" {
		suffix = ": " + lastLine(s)
	}
	return fmt.Errorf("%s %s: %w%s", name, strings.Join(args, " "), err, suffix)
}

func lastLine(s string) string {
	lines := strings.Split(s, "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
