package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/sovyn-eu/skiff/internal/app"
	"github.com/sovyn-eu/skiff/internal/backend/backendtest"
	"github.com/sovyn-eu/skiff/internal/config"
	"github.com/sovyn-eu/skiff/internal/runner"
	"github.com/sovyn-eu/skiff/internal/vm"
)

// fakeHandler answers the commands app runs itself; the VMs live in the
// fake backend.
func fakeHandler(t *testing.T) runner.FakeHandler {
	t.Helper()
	return func(name string, args []string) ([]byte, error) {
		if name == "ssh" || name == "security" {
			return nil, nil
		}
		return nil, errors.New("unexpected: " + name + " " + strings.Join(args, " "))
	}
}

// seededBackend has the one VM most tests expect.
func seededBackend() *backendtest.Fake {
	fb := backendtest.New()
	fb.Add(vm.Info{Name: "vm1", VCPUs: 2, MemMiB: 1024})
	return fb
}

// builder returns an appBuilder on the given fakes with extra options.
func builder(fake *runner.Fake, fb *backendtest.Fake, home string, opts ...app.Option) appBuilder {
	return func(out io.Writer) (*app.App, error) {
		opts = append([]app.Option{app.WithBackend(fb)}, opts...)
		return app.New(fake, config.Paths{Home: home}, out, opts...), nil
	}
}

func run(t *testing.T, args ...string) (string, *backendtest.Fake, error) {
	t.Helper()
	out, fb, _, err := runWith(t, seededBackend(), args...)
	return out, fb, err
}

// runWith runs the CLI against the given backend and returns stdout+stderr,
// the backend and the runner fake.
func runWith(t *testing.T, fb *backendtest.Fake, args ...string) (string, *backendtest.Fake, *runner.Fake, error) {
	t.Helper()
	fake := runner.NewFake(fakeHandler(t))
	buf := &bytes.Buffer{}
	root := newRoot(builder(fake, fb, t.TempDir()))
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), fb, fake, err
}

func TestLsPrintsTable(t *testing.T) {
	out, _, err := run(t, "ls")
	if err != nil {
		t.Fatalf("ls: %v", err)
	}
	if !strings.Contains(out, "NAME") || !strings.Contains(out, "vm1") || !strings.Contains(out, "192.168.64.2") {
		t.Errorf("unexpected output:\n%s", out)
	}
}

func TestNewPassesFlags(t *testing.T) {
	_, fb, err := run(t, "new", "box", "--vcpus", "3", "--mem", "2048")
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if !fb.Called("create box 3 2048") {
		t.Errorf("flags not forwarded:\n%s", fb.Dump())
	}
}

func TestNewDefaultsAndAutoName(t *testing.T) {
	_, fb, err := run(t, "new")
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if !fb.Called("create  2 1024") {
		t.Errorf("defaults not applied:\n%s", fb.Dump())
	}
	if _, ok := fb.VM("vm2"); !ok {
		t.Errorf("the backend picks the next free name, got %v", fb.Names())
	}
}

func TestNewRejectsRemovedFlags(t *testing.T) {
	// --profile exists again since 0.4.0, with a different meaning (profile files).
	for _, flag := range []string{"--disk", "--fresh"} {
		if _, _, err := run(t, "new", "box", flag, "x"); err == nil || !strings.Contains(err.Error(), "unknown flag") {
			t.Errorf("%s belonged to the Lima backend and must be gone, got %v", flag, err)
		}
	}
}

func TestRmRequiresName(t *testing.T) {
	if _, _, err := run(t, "rm"); err == nil {
		t.Fatal("expected usage error")
	}
}

func TestRmCallsTheBackend(t *testing.T) {
	_, fb, err := run(t, "rm", "vm1")
	if err != nil {
		t.Fatalf("rm: %v", err)
	}
	if !fb.Called("rm vm1") {
		t.Errorf("rm not forwarded:\n%s", fb.Dump())
	}
}

func TestSSHForwardsCommandWithFlags(t *testing.T) {
	_, _, fake, err := runWith(t, seededBackend(), "ssh", "vm1", "ls", "-la")
	if err != nil {
		t.Fatalf("ssh: %v", err)
	}
	found := false
	for _, c := range fake.Calls() {
		if strings.HasPrefix(c, "ssh -F ") && strings.HasSuffix(c, " vm1.skiff -- ls -la") {
			found = true
		}
	}
	if !found {
		t.Errorf("ssh command not forwarded verbatim after --:\n%s", fake.Dump())
	}
}

func TestSSHStripsLeadingSeparator(t *testing.T) {
	_, _, fake, err := runWith(t, seededBackend(), "ssh", "vm1", "--", "echo", "hi")
	if err != nil {
		t.Fatalf("ssh: %v", err)
	}
	if !fake.CalledWithSuffix(" vm1.skiff -- echo hi") || fake.CalledWithSuffix(" vm1.skiff -- -- echo hi") {
		t.Errorf("a user-supplied -- must not be doubled:\n%s", fake.Dump())
	}
}

func TestBuilderErrorsSurface(t *testing.T) {
	root := newRoot(func(io.Writer) (*app.App, error) { return nil, errors.New("no home") })
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"ls"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "no home") {
		t.Fatalf("expected builder error, got %v", err)
	}
}

func TestExitCodeMapping(t *testing.T) {
	stderr := &bytes.Buffer{}
	if code := exitCode(nil, stderr); code != 0 {
		t.Errorf("nil error should exit 0, got %d", code)
	}
	if code := exitCode(&app.RemoteExitError{Code: 7}, stderr); code != 7 || stderr.Len() != 0 {
		t.Errorf("remote exit should be silent and mirror the code, got %d / %q", code, stderr.String())
	}
	if code := exitCode(&app.RemoteExitError{Code: 143, Reason: "ssh terminated by signal terminated"}, stderr); code != 143 || !strings.Contains(stderr.String(), "signal") {
		t.Errorf("signal deaths should be explained, got %d / %q", code, stderr.String())
	}
	stderr.Reset()
	if code := exitCode(errors.New("boom"), stderr); code != 1 || !strings.Contains(stderr.String(), "boom") {
		t.Errorf("generic errors should print and exit 1, got %d / %q", code, stderr.String())
	}
}

func TestStartStopForwardToTheBackend(t *testing.T) {
	for _, verb := range []string{"stop", "start"} {
		_, fb, err := run(t, verb, "vm1")
		if err != nil {
			t.Fatalf("%s: %v", verb, err)
		}
		if !fb.Called(verb + " vm1") {
			t.Errorf("%s not forwarded:\n%s", verb, fb.Dump())
		}
	}
}

func TestPrepareAndDoctorWiring(t *testing.T) {
	out, fb, err := run(t, "doctor")
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if !strings.Contains(out, "backend: fake") || !fb.Called("doctor") {
		t.Errorf("doctor output should name the backend and ask it:\n%s", out)
	}
	out, fb, err = run(t, "prepare")
	if err != nil {
		t.Fatalf("prepare: %v\n%s", err, out)
	}
	if !fb.Called("prepare") || !strings.Contains(out, "Ready") {
		t.Errorf("prepare must run the backend's prepare:\n%s\n%s", out, fb.Dump())
	}
	for _, flag := range []string{"--backend", "--cpus", "--profile"} {
		if _, _, err := run(t, "prepare", flag, "x"); err == nil || !strings.Contains(err.Error(), "unknown flag") {
			t.Errorf("prepare %s belonged to the Lima backend and must be gone, got %v", flag, err)
		}
	}
}

func TestDefaultBuilder(t *testing.T) {
	t.Setenv("SKIFF_HOME", t.TempDir())
	if a, err := defaultBuilder(io.Discard); err != nil || a == nil {
		t.Fatalf("defaultBuilder: %v", err)
	}
}

func TestForwardCommands(t *testing.T) {
	fb := backendtest.New()
	fb.Add(vm.Info{Name: "web", VCPUs: 2, MemMiB: 1024})
	fake := runner.NewFake(fakeHandler(t))
	home := t.TempDir()
	exec := func(args ...string) (string, error) {
		buf := &bytes.Buffer{}
		root := newRoot(builder(fake, fb, home,
			app.WithPortProbe(func(context.Context, int) bool { return true }),
			app.WithPortCheck(func(int) bool { return false })))
		root.SetOut(buf)
		root.SetErr(buf)
		root.SetArgs(args)
		err := root.Execute()
		return buf.String(), err
	}

	if out, err := exec("forward", "web", "8080:80", "3000"); err != nil || !strings.Contains(out, "ready") {
		t.Errorf("forward: %v %q", err, out)
	}
	if !fb.Called("forward web 8080:80 3000:3000") {
		t.Errorf("forward not forwarded:\n%s", fb.Dump())
	}
	if out, err := exec("forward", "web"); err != nil || !strings.Contains(out, "localhost:8080") || !strings.Contains(out, "web:80") {
		t.Errorf("forward listing: %v %q", err, out)
	}
	if out, err := exec("ls"); err != nil || !strings.Contains(out, "PORTS") || !strings.Contains(out, "8080→80,3000→3000") {
		t.Errorf("ls should show forwards: %v %q", err, out)
	}
	if _, err := exec("unforward", "web", "8080"); err != nil {
		t.Errorf("unforward: %v", err)
	}
	if !fb.Called("unforward web 8080") {
		t.Errorf("unforward not forwarded:\n%s", fb.Dump())
	}
	if _, err := exec("unforward", "web", "abc"); err == nil {
		t.Error("non-numeric port must be rejected")
	}
}

func TestNewWithPortFlags(t *testing.T) {
	fb := backendtest.New()
	fake := runner.NewFake(fakeHandler(t))
	root := newRoot(builder(fake, fb, t.TempDir(),
		app.WithPortProbe(func(context.Context, int) bool { return true }),
		app.WithPortCheck(func(int) bool { return false })))
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"new", "web", "-p", "8080:80", "-p", "3000"})
	if err := root.Execute(); err != nil {
		t.Fatalf("new: %v", err)
	}
	if !fb.Called("forward web 8080:80 3000:3000") {
		t.Errorf("-p flags not applied:\n%s", fb.Dump())
	}
}

func TestTunnelWiring(t *testing.T) {
	if _, _, err := run(t, "tunnel"); err == nil {
		t.Error("tunnel without a name must fail")
	}
	_, _, fake, err := runWith(t, seededBackend(), "tunnel", "vm1")
	if err == nil || !strings.Contains(err.Error(), "skiff grant vm1") {
		t.Errorf("tunnel without broker grants should hint at grant, got %v", err)
	}
	for _, c := range fake.Calls() {
		if strings.HasPrefix(c, "ssh ") {
			t.Errorf("no ssh without grants: %s", c)
		}
	}
}
