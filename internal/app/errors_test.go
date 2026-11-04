package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sovyn-eu/skiff/internal/vm"
)

func TestLifecycleSurfacesBackendErrors(t *testing.T) {
	app, _, _ := newTestApp(t, sshOnly) // no VMs
	if _, err := app.StartVM(context.Background(), "vm1"); err == nil {
		t.Error("start should surface the backend error")
	}
	if _, err := app.StopVM(context.Background(), "vm1"); err == nil {
		t.Error("stop should surface the backend error")
	}
	if err := app.RemoveVM(context.Background(), "vm1"); err == nil {
		t.Error("rm should surface the backend error")
	}
	backendOf(app).ListErr = errors.New("container machine ls: exploded")
	if _, err := app.ListVMs(context.Background()); err == nil || !strings.Contains(err.Error(), "exploded") {
		t.Errorf("ls should surface the backend error, got %v", err)
	}
}

func TestCommandsFailWhenTheRuntimeIsNotReady(t *testing.T) {
	app, _, _ := newTestApp(t, sshOnly)
	backendOf(app).ReadyErr = errors.New("run 'skiff prepare'")
	for label, err := range map[string]error{
		"rm":  app.RemoveVM(context.Background(), "vm1"),
		"ssh": app.SSH(context.Background(), "vm1", nil),
	} {
		if err == nil || !strings.Contains(err.Error(), "skiff prepare") {
			t.Errorf("%s: expected hint to run skiff prepare, got %v", label, err)
		}
	}
	if _, err := app.ListVMs(context.Background()); err == nil {
		t.Error("ls: expected error when the runtime is not ready")
	}
}

func TestRemoteExitErrorMessage(t *testing.T) {
	if got := (&RemoteExitError{Code: 4}).Error(); !strings.Contains(got, "4") {
		t.Errorf("unexpected message %q", got)
	}
	if got := (&RemoteExitError{Code: 143, Reason: "killed"}).Error(); got != "killed" {
		t.Errorf("reason should win, got %q", got)
	}
}

func TestNewCleansUpWhenInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	app, _, out := newTestApp(t, sshOnly)
	fb := backendOf(app)
	fb.OnCreate = func(context.Context, vm.Spec) error {
		cancel() // Ctrl-C while the backend creates the VM
		return errors.New("signal: interrupt")
	}
	if _, err := app.NewVM(ctx, vm.Spec{Name: "doomed", VCPUs: 1, MemMiB: 1024}, nil); err == nil {
		t.Fatal("expected the interrupted creation to fail")
	}
	if !fb.Called("rm doomed") {
		t.Errorf("expected a best-effort rm after cancellation:\n%s", fb.Dump())
	}
	if !strings.Contains(out.String(), "interrupted") {
		t.Errorf("user should be told about the cleanup:\n%s", out.String())
	}
}

func TestNewDoesNotCleanUpOnOrdinaryFailure(t *testing.T) {
	app, _, _ := newTestApp(t, sshOnly)
	fb := backendOf(app)
	fb.OnCreate = func(context.Context, vm.Spec) error { return errors.New("exit status 1") }
	if _, err := app.NewVM(context.Background(), vm.Spec{Name: "x", VCPUs: 1, MemMiB: 1024}, nil); err == nil {
		t.Fatal("expected failure")
	}
	if fb.CalledWithPrefix("rm") {
		t.Error("an ordinary failure is rolled back by the backend itself; no rm expected")
	}
}

func TestNewInterruptedWithoutNameOnlyHints(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	app, _, out := newTestApp(t, sshOnly)
	fb := backendOf(app)
	fb.OnCreate = func(context.Context, vm.Spec) error {
		cancel()
		return errors.New("signal: interrupt")
	}
	_, _ = app.NewVM(ctx, vm.Spec{VCPUs: 1, MemMiB: 1024}, nil)
	if fb.CalledWithPrefix("rm") || !strings.Contains(out.String(), "skiff ls") {
		t.Errorf("unnamed VMs cannot be cleaned up blindly:\n%s\n%s", fb.Dump(), out.String())
	}
}
