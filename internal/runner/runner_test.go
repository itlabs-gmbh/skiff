package runner

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestExecOutputCapturesStdout(t *testing.T) {
	e := &Exec{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	out, err := e.Output(context.Background(), "sh", "-c", "echo hello; echo warn >&2")
	if err != nil {
		t.Fatalf("Output: %v", err)
	}
	if strings.TrimSpace(string(out)) != "hello" {
		t.Errorf("stdout = %q", out)
	}
	if !strings.Contains(e.Stderr.(*bytes.Buffer).String(), "warn") {
		t.Error("stderr should be streamed through")
	}
}

func TestExecOutputErrorIncludesStderr(t *testing.T) {
	e := &Exec{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	_, err := e.Output(context.Background(), "sh", "-c", "echo first >&2; echo it broke >&2; exit 3")
	if err == nil || !strings.Contains(err.Error(), "it broke") || !strings.Contains(err.Error(), "exit status 3") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecRunWithInput(t *testing.T) {
	stdout := &bytes.Buffer{}
	e := &Exec{Stdout: stdout, Stderr: &bytes.Buffer{}}
	if err := e.RunWithInput(context.Background(), strings.NewReader("ping"), "cat"); err != nil {
		t.Fatalf("RunWithInput: %v", err)
	}
	if stdout.String() != "ping" {
		t.Errorf("stdout = %q", stdout.String())
	}
}

func TestExecRunFailure(t *testing.T) {
	e := &Exec{Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	if err := e.Run(context.Background(), "false"); err == nil {
		t.Fatal("expected error from false")
	}
}

func TestNewExecSendsChildStdoutToTheGivenWriter(t *testing.T) {
	stdout := &bytes.Buffer{}
	e := NewExec(stdout)
	if e.Stdin == nil || e.Stderr == nil {
		t.Fatal("NewExec must wire stdin and stderr")
	}
	if err := e.RunWithInput(context.Background(), strings.NewReader("ping"), "cat"); err != nil {
		t.Fatalf("RunWithInput: %v", err)
	}
	if stdout.String() != "ping" {
		t.Errorf("child stdout must reach the given writer, got %q", stdout.String())
	}
}

func TestFakeRecordsCalls(t *testing.T) {
	f := NewFake(func(name string, args []string) ([]byte, error) { return []byte("ok"), nil })
	ctx := context.Background()
	_, _ = f.Output(ctx, "a", "b")
	_ = f.Run(ctx, "c")
	_ = f.RunWithInput(ctx, strings.NewReader(""), "d", "e", "f")
	if !f.Called("a b") || !f.Called("c") || !f.Called("d e f") || f.Called("nope") {
		t.Errorf("unexpected recording:\n%s", f.Dump())
	}
	if argv := f.Argv(); len(argv) != 3 || argv[2][2] != "f" {
		t.Errorf("argv boundaries lost: %q", argv)
	}
}

func TestFakeCapturesInput(t *testing.T) {
	f := NewFake(func(string, []string) ([]byte, error) { return nil, nil })
	_ = f.RunWithInput(context.Background(), strings.NewReader("secret"), "sh", "-c", "cat", "sh", "/etc/key", "0600")
	if in, ok := f.Input("sh /etc/key 0600"); !ok || in != "secret" {
		t.Errorf("Input = %q, %v", in, ok)
	}
	if !f.CalledWithSuffix("/etc/key 0600") || f.CalledWithSuffix("nope") {
		t.Error("CalledWithSuffix mismatch")
	}
}

func TestExecErrorsKeepExitError(t *testing.T) {
	e := &Exec{Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	err := e.Run(context.Background(), "sh", "-c", "exit 255")
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 255 {
		t.Fatalf("expected wrapped ExitError 255, got %v", err)
	}
}

func TestSilencedDetachesTerminal(t *testing.T) {
	loud := &Exec{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	quiet, ok := Silenced(loud).(*Exec)
	if !ok {
		t.Fatal("Silenced(*Exec) must stay an *Exec")
	}
	_, err := quiet.Output(context.Background(), "sh", "-c", "echo noisy >&2; exit 4")
	if err == nil || !strings.Contains(err.Error(), "noisy") {
		t.Errorf("errors must still carry stderr, got %v", err)
	}
	if err := quiet.Run(context.Background(), "sh", "-c", "echo out; echo err >&2"); err != nil {
		t.Fatal(err)
	}
	if loud.Stdout.(*bytes.Buffer).Len()+loud.Stderr.(*bytes.Buffer).Len() != 0 {
		t.Error("a silenced runner must not write to the original streams")
	}
	fake := NewFake(func(string, []string) ([]byte, error) { return nil, nil })
	if Silenced(fake) != Runner(fake) {
		t.Error("runners other than Exec are returned unchanged")
	}
}
