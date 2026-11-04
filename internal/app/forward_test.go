package app

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/sovyn-eu/skiff/internal/backend/backendtest"
	"github.com/sovyn-eu/skiff/internal/runner"
	"github.com/sovyn-eu/skiff/internal/vm"
)

// forwardApp has a running VM "web" without forwards.
func forwardApp(t *testing.T, probeResult bool, busy func(int) bool) (*App, *backendtest.Fake, *bytes.Buffer, *[]int) {
	t.Helper()
	out := &bytes.Buffer{}
	probed := &[]int{}
	fb := backendtest.New()
	fb.Add(vm.Info{Name: "web", VCPUs: 2, MemMiB: 1024})
	app := New(runner.NewFake(sshOnly), testPaths(t), out, WithBackend(fb),
		WithPortProbe(func(_ context.Context, port int) bool {
			*probed = append(*probed, port)
			return probeResult
		}),
		WithPortCheck(busy))
	return app, fb, out, probed
}

func free(int) bool { return false }

func TestForwardRefusesBusyHostPorts(t *testing.T) {
	app, fb, _, _ := forwardApp(t, true, func(port int) bool { return port == 8080 })
	_, err := app.Forward(context.Background(), "web", []string{"8080:80"})
	if err == nil || !strings.Contains(err.Error(), "already in use on this Mac") {
		t.Fatalf("expected busy-port error, got %v", err)
	}
	if fb.CalledWithPrefix("forward") {
		t.Error("the backend must not be asked to forward a busy port")
	}
	_, err = app.NewVM(context.Background(), vm.Spec{Name: "web2", VCPUs: 1, MemMiB: 1024, Forwards: []string{"8080"}}, nil)
	if err == nil || fb.CalledWithPrefix("create") {
		t.Errorf("new must refuse busy ports before creating the VM: err=%v\n%s", err, fb.Dump())
	}
}

func TestHostPortBusyAgainstRealListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen on loopback")
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	if !hostPortBusy(port) {
		t.Errorf("port %d has a listener and must be reported busy", port)
	}
	ln.Close()
	if hostPortBusy(port) {
		t.Errorf("port %d is free again and must not be reported busy", port)
	}
}

func TestForwardAddsAndProbes(t *testing.T) {
	app, fb, out, probed := forwardApp(t, true, free)
	info, err := app.Forward(context.Background(), "web", []string{"8080:80"})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if !fb.Called("forward web 8080:80") {
		t.Errorf("backend call missing:\n%s", fb.Dump())
	}
	if len(info.Forwards) != 1 || info.Forwards[0].Host != 8080 {
		t.Errorf("unexpected info: %+v", info)
	}
	if len(*probed) != 1 || (*probed)[0] != 8080 || !strings.Contains(out.String(), "localhost:8080 -> web:80 ready") {
		t.Errorf("probe/report mismatch: probed=%v out=%q", *probed, out.String())
	}
}

func TestForwardCanonicalisesSpecs(t *testing.T) {
	app, fb, _, _ := forwardApp(t, true, free)
	if _, err := app.Forward(context.Background(), "web", []string{"3000", " 9000:90 "}); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if !fb.Called("forward web 3000:3000 9000:90") {
		t.Errorf("specs must be canonical HOST:GUEST:\n%s", fb.Dump())
	}
}

func TestForwardReportsStoredForStoppedVM(t *testing.T) {
	app, fb, out, probed := forwardApp(t, true, free)
	fb.SetState("web", vm.StateStopped)
	if _, err := app.Forward(context.Background(), "web", []string{"8080:80"}); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if len(*probed) != 0 || !strings.Contains(out.String(), "applied when web starts") {
		t.Errorf("stopped VMs must not be probed: probed=%v out=%q", *probed, out.String())
	}
}

func TestForwardWarnsWhenHostPortNotReachable(t *testing.T) {
	app, _, out, _ := forwardApp(t, false, free)
	if _, err := app.Forward(context.Background(), "web", []string{"8080:80"}); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if !strings.Contains(out.String(), "not reachable yet") {
		t.Errorf("expected a warning, got %q", out.String())
	}
}

func TestForwardRejectsBadSpecsBeforeRunning(t *testing.T) {
	app, fb, _, _ := forwardApp(t, true, free)
	if _, err := app.Forward(context.Background(), "web", []string{"80"}); err == nil {
		t.Fatal("privileged host port must be rejected")
	}
	if _, err := app.Forward(context.Background(), "Bad", []string{"8080"}); err == nil {
		t.Fatal("invalid name must be rejected")
	}
	if len(fb.Calls) != 0 {
		t.Errorf("nothing should run:\n%s", fb.Dump())
	}
}

func TestForwardWithoutSpecsDescribes(t *testing.T) {
	app, fb, _, _ := forwardApp(t, true, free)
	if _, err := fb.Forward(context.Background(), "web", []vm.Forward{{Host: 8080, Guest: 80}}); err != nil {
		t.Fatal(err)
	}
	fb.Calls = nil
	info, err := app.Forward(context.Background(), "web", nil)
	if err != nil || len(info.Forwards) != 1 {
		t.Fatalf("expected the existing forward, got %+v, %v", info, err)
	}
	if fb.CalledWithPrefix("forward") {
		t.Error("listing must not call the backend's forward")
	}
	if _, err := app.Forward(context.Background(), "nope", nil); err == nil {
		t.Error("unknown VM must be reported")
	}
}

func TestUnforward(t *testing.T) {
	app, fb, out, _ := forwardApp(t, true, free)
	if _, err := fb.Forward(context.Background(), "web", []vm.Forward{{Host: 8080, Guest: 80}}); err != nil {
		t.Fatal(err)
	}
	info, err := app.Unforward(context.Background(), "web", []int{8080, 3000})
	if err != nil {
		t.Fatalf("Unforward: %v", err)
	}
	if !fb.Called("unforward web 8080 3000") || len(info.Forwards) != 0 {
		t.Errorf("unexpected call/info: %+v\n%s", info, fb.Dump())
	}
	if !strings.Contains(out.String(), "removed forward localhost:8080") {
		t.Errorf("unexpected output %q", out.String())
	}
	if _, err := app.Unforward(context.Background(), "web", nil); err == nil {
		t.Error("empty port list must be rejected")
	}
	if _, err := app.Unforward(context.Background(), "web", []int{0}); err == nil {
		t.Error("invalid port must be rejected")
	}
}

func TestNewAppliesForwards(t *testing.T) {
	app, fb, _, _ := forwardApp(t, true, free)
	info, err := app.NewVM(context.Background(), vm.Spec{Name: "api", VCPUs: 1, MemMiB: 1024, Forwards: []string{"8080:80"}}, nil)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	if !fb.Called("forward api 8080:80") || len(info.Forwards) != 1 {
		t.Errorf("forwards not applied after creation: %+v\n%s", info, fb.Dump())
	}
}

func TestForwardSurfacesBackendErrors(t *testing.T) {
	app, fb, _, _ := forwardApp(t, true, free)
	fb.Add(vm.Info{Name: "other", Forwards: []vm.Forward{{Host: 8080, Guest: 80}}})
	if _, err := app.Forward(context.Background(), "web", []string{"8080"}); err == nil || !strings.Contains(err.Error(), "already forwarded") {
		t.Fatalf("expected the backend's error, got %v", err)
	}
}

// TestForwardMayReplaceItsOwnBusyPort: a host port the VM already owns is
// busy on the Mac (the relay serves it), yet re-forwarding it to another
// guest port must work; only ports of other listeners are refused.
func TestForwardMayReplaceItsOwnBusyPort(t *testing.T) {
	app, fb, _, _ := forwardApp(t, true, func(port int) bool { return port == 8080 || port == 9090 })
	if _, err := fb.Forward(context.Background(), "web", []vm.Forward{{Host: 8080, Guest: 80}}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Forward(context.Background(), "web", []string{"8080:8080"}); err != nil {
		t.Fatalf("re-forwarding the VM's own port must pass: %v", err)
	}
	if !fb.Called("forward web 8080:8080") {
		t.Errorf("backend call missing:\n%s", fb.Dump())
	}
	if _, err := app.Forward(context.Background(), "web", []string{"9090:90"}); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Errorf("a port of another listener must still be refused, got %v", err)
	}
}
