package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sovyn-eu/skiff/internal/backend/backendtest"
	"github.com/sovyn-eu/skiff/internal/config"
	"github.com/sovyn-eu/skiff/internal/runner"
	"github.com/sovyn-eu/skiff/internal/vm"
)

// newTestApp wires an App on an in-memory backend and a fake runner for the
// commands app runs itself (ssh, security); handle answers those.
func newTestApp(t *testing.T, handle runner.FakeHandler) (*App, *runner.Fake, *bytes.Buffer) {
	t.Helper()
	fake := runner.NewFake(handle)
	out := &bytes.Buffer{}
	return New(fake, testPaths(t), out, WithBackend(backendtest.New()), WithStatus(out)), fake, out
}

// backendOf reaches the fake backend behind an App.
func backendOf(a *App) *backendtest.Fake {
	return a.backend.(*backendtest.Fake)
}

// sshOnly answers ssh and the Keychain and refuses everything else: with the
// backend faked in memory, no other command should run.
func sshOnly(name string, args []string) ([]byte, error) {
	if name == "ssh" || name == "security" {
		return nil, nil
	}
	return nil, errors.New("unexpected command: " + name + " " + strings.Join(args, " "))
}

// seed adds VMs to the App's fake backend.
func seed(a *App, vms ...vm.Info) {
	for _, v := range vms {
		backendOf(a).Add(v)
	}
}

func TestNewCreatesThroughTheBackend(t *testing.T) {
	app, _, out := newTestApp(t, sshOnly)
	info, err := app.NewVM(context.Background(), vm.Spec{Name: "vm1", VCPUs: 2, MemMiB: 1024}, nil)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	if info.Name != "vm1" || info.IP == "" || info.State != vm.StateRunning {
		t.Errorf("unexpected info: %+v", info)
	}
	if !backendOf(app).Called("create vm1 2 1024") {
		t.Errorf("expected a create call, got:\n%s", backendOf(app).Dump())
	}
	if !strings.Contains(out.String(), "skiff ssh vm1") {
		t.Errorf("output should hint at ssh usage, got:\n%s", out.String())
	}
}

func TestNewRejectsInvalidSpec(t *testing.T) {
	app, _, _ := newTestApp(t, sshOnly)
	if _, err := app.NewVM(context.Background(), vm.Spec{Name: "Bad Name", VCPUs: 2, MemMiB: 1024}, nil); err == nil {
		t.Fatal("expected validation error")
	}
	if len(backendOf(app).Calls) != 0 {
		t.Errorf("nothing should reach the backend for an invalid spec, got:\n%s", backendOf(app).Dump())
	}
}

func TestNewRequiresReadyBackend(t *testing.T) {
	app, _, _ := newTestApp(t, sshOnly)
	backendOf(app).ReadyErr = errors.New("the container system service is not running, run 'skiff prepare'")
	_, err := app.NewVM(context.Background(), vm.Spec{Name: "vm1", VCPUs: 2, MemMiB: 1024}, nil)
	if err == nil || !strings.Contains(err.Error(), "skiff prepare") {
		t.Fatalf("expected error pointing at 'skiff prepare', got %v", err)
	}
	if backendOf(app).CalledWithPrefix("create") {
		t.Error("nothing is created while the backend is not ready")
	}
}

func TestListReportsTheBackendsVMs(t *testing.T) {
	app, _, _ := newTestApp(t, sshOnly)
	seed(app, vm.Info{Name: "vm1", VCPUs: 2, MemMiB: 1024})
	vms, err := app.ListVMs(context.Background())
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	if len(vms) != 1 || vms[0].Name != "vm1" || vms[0].State != "running" || vms[0].VCPUs != 2 {
		t.Errorf("unexpected vms: %+v", vms)
	}
}

func TestInspectVM(t *testing.T) {
	app, _, _ := newTestApp(t, sshOnly)
	seed(app, vm.Info{Name: "vm1"}, vm.Info{Name: "vm2", State: vm.StateStopped})
	ctx := context.Background()
	info, err := app.InspectVM(ctx, "vm2")
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}
	if info.Name != "vm2" || info.State != "stopped" {
		t.Errorf("unexpected VM: %+v", info)
	}
	if _, err := app.InspectVM(ctx, "vm9"); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("unknown VM: want 'does not exist', got %v", err)
	}
	calls := len(backendOf(app).Calls)
	if _, err := app.InspectVM(ctx, "../etc"); err == nil {
		t.Error("invalid name must be rejected")
	}
	if len(backendOf(app).Calls) != calls {
		t.Errorf("an invalid name must not reach the backend:\n%s", backendOf(app).Dump())
	}
}

func TestRemoveCallsTheBackend(t *testing.T) {
	app, _, _ := newTestApp(t, sshOnly)
	seed(app, vm.Info{Name: "vm1"})
	if err := app.RemoveVM(context.Background(), "vm1"); err != nil {
		t.Fatalf("RemoveVM: %v", err)
	}
	if !backendOf(app).Called("rm vm1") {
		t.Errorf("expected rm call, got:\n%s", backendOf(app).Dump())
	}
}

func TestRemoveRejectsInvalidName(t *testing.T) {
	app, _, _ := newTestApp(t, sshOnly)
	if err := app.RemoveVM(context.Background(), "../etc"); err == nil {
		t.Fatal("expected validation error")
	}
	if len(backendOf(app).Calls) != 0 {
		t.Errorf("nothing should run, got:\n%s", backendOf(app).Dump())
	}
}

func TestSSHArgsSeparateRemoteCommand(t *testing.T) {
	app, _, _ := newTestApp(t, sshOnly)
	args := app.sshArgs("vm1", []string{"uname", "-a"})
	joined := strings.Join(args, " ")
	if !strings.HasPrefix(joined, "-F ") || !strings.HasSuffix(joined, " vm1.skiff -- uname -a") {
		t.Errorf("unexpected ssh args: %q", joined)
	}
	if got := app.sshArgs("vm1", nil); got[len(got)-1] != "vm1.skiff" {
		t.Errorf("interactive sessions must not end with a separator: %q", got)
	}
}

func TestSSHArgsNeutraliseOptionLookalikes(t *testing.T) {
	app, _, _ := newTestApp(t, sshOnly)
	payload := "-oProxyCommand=touch /tmp/pwned"
	args := app.sshArgs("vm1", []string{payload})
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
		}
	}
	if sep < 0 || args[len(args)-1] != payload || sep > len(args)-2 {
		t.Fatalf("payload must follow the -- separator, got %q", args)
	}
	for _, a := range args[:sep] {
		if a == payload {
			t.Fatalf("payload leaked before the separator: %q", args)
		}
	}
}

func TestSSHWritesAStrictConfig(t *testing.T) {
	app, fake, _ := newTestApp(t, sshOnly)
	if err := app.SSH(context.Background(), "vm1", []string{"true"}); err != nil {
		t.Fatalf("SSH: %v", err)
	}
	if !fake.Called("ssh -F " + app.paths.SSHConfigPath() + " vm1.skiff -- true") {
		t.Errorf("ssh not run:\n%s", fake.Dump())
	}
	text, err := readFile(app.paths.SSHConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"StrictHostKeyChecking yes", "UserKnownHostsFile /tmp/known_hosts", "ProxyCommand /usr/local/bin/skiff _dial %h %p"} {
		if !strings.Contains(text, want) {
			t.Errorf("ssh_config lacks %q:\n%s", want, text)
		}
	}
}

// testPaths returns a short home so Unix sockets fit on macOS.
func testPaths(t *testing.T) config.Paths {
	t.Helper()
	return config.Paths{Home: t.TempDir()}
}
