package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sovyn-eu/skiff/internal/backend/backendtest"
	"github.com/sovyn-eu/skiff/internal/grant"
	"github.com/sovyn-eu/skiff/internal/vm"
)

var gcNow = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func at(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return &t
}

// seedGC adds one VM of every kind gc has to tell apart. paseo-4 is removed
// by someone else after the listing, so the backend reports it gone.
func seedGC(fb *backendtest.Fake, failRm, reborn string) {
	for _, v := range []vm.Info{
		{Name: "manual", CreatedAt: at("2026-10-01T12:00:00Z")},
		{Name: "paseo-1", Owner: "paseo", Slot: "1", CreatedAt: at("2026-10-07T09:00:00Z")},
		{Name: "paseo-2", Owner: "paseo", Slot: "2", CreatedAt: at("2026-10-07T11:50:00Z")},
		{Name: "ci-7", State: vm.StateStopped, Owner: "ci", CreatedAt: at("2026-10-07T07:00:00Z")},
		{Name: "undated", State: vm.StateBroken, Owner: "paseo"},
		{Name: "paseo-9", State: vm.StateCreating, Owner: "paseo", Slot: "9", CreatedAt: at("2026-10-07T08:00:00Z")},
		{Name: "paseo-4", State: vm.StateStopped, Owner: "paseo", Slot: "4", CreatedAt: at("2026-10-07T08:00:00Z")},
	} {
		fb.Add(v)
	}
	fb.OnRemove = func(name string) error {
		switch name {
		case failRm:
			return errors.New("rm: VM is wedged")
		case "paseo-4":
			fb.Drop(name) // vanished between the listing and the removal
		}
		return nil
	}
	fb.OnRemoved = func(name string) {
		if name == reborn { // a concurrent `new --grant` creates it again
			fb.Add(vm.Info{Name: name, Owner: "paseo", CreatedAt: at("2026-10-07T12:00:00Z")})
		}
	}
}

// removed lists the guarded removals the backend was asked for, as
// "name owner created".
func removed(fb *backendtest.Fake) []string {
	var out []string
	for _, c := range fb.Calls {
		if rest, ok := strings.CutPrefix(c, "rm "); ok {
			out = append(out, rest)
		}
	}
	return out
}

func newGCApp(t *testing.T, failRm, reborn string) (*App, *backendtest.Fake) {
	t.Helper()
	a, _, _ := newTestApp(t, sshOnly)
	a.now = func() time.Time { return gcNow }
	seedGC(backendOf(a), failRm, reborn)
	return a, backendOf(a)
}

func TestGCRemovesOnlyTheListedVM(t *testing.T) {
	a, fb := newGCApp(t, "", "")
	if _, err := a.GC(context.Background(), GCOptions{Owner: "paseo"}); err != nil {
		t.Fatalf("GC: %v", err)
	}
	// owner and creation time let the backend refuse a VM recreated under the same name
	want := "paseo-1 paseo 2026-10-07T09:00:00Z,paseo-2 paseo 2026-10-07T11:50:00Z,undated paseo -,paseo-4 paseo 2026-10-07T08:00:00Z"
	if got := strings.Join(removed(fb), ","); got != want {
		t.Errorf("rm calls %q, want %q", got, want)
	}
}

// firstWords reduces "name owner created" lines to the names.
func firstWords(calls []string) string {
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		out = append(out, strings.Fields(c)[0])
	}
	return strings.Join(out, ",")
}

// collected lists the VMs whose removal the backend carried out: paseo-4
// vanished before its guarded rm, so it never counts.
func collected(fb *backendtest.Fake) string {
	var out []string
	for _, r := range removed(fb) {
		if name := strings.Fields(r)[0]; name != "paseo-4" {
			out = append(out, name)
		}
	}
	return strings.Join(out, ",")
}

func names(vms []VMInfo) string {
	out := make([]string, 0, len(vms))
	for _, v := range vms {
		out = append(out, v.Name)
	}
	return strings.Join(out, ",")
}

func TestGCSelectsOwnedVMs(t *testing.T) {
	cases := []struct {
		opts GCOptions
		want string
	}{
		// paseo-9 is still being created, paseo-4 vanished meanwhile
		{GCOptions{Owner: "paseo"}, "paseo-1,paseo-2,undated"},
		{GCOptions{Owner: "paseo", Keep: []string{"paseo-2", "undated"}}, "paseo-1"},
		// unknown age is never old, and VMs made by hand are never collected
		{GCOptions{OlderThan: time.Hour}, "paseo-1,ci-7"},
		{GCOptions{Owner: "ci", OlderThan: 6 * time.Hour}, ""},
		{GCOptions{Owner: "nobody"}, ""},
	}
	for _, c := range cases {
		a, fb := newGCApp(t, "", "")
		res, err := a.GC(context.Background(), c.opts)
		if err != nil {
			t.Fatalf("GC(%+v): %v", c.opts, err)
		}
		if got := names(res.VMs); got != c.want {
			t.Errorf("GC(%+v) reported %q, want %q", c.opts, got, c.want)
		}
		if got := collected(fb); got != c.want {
			t.Errorf("GC(%+v) removed %q, want %q", c.opts, got, c.want)
		}
	}
}

func TestGCDryRunRemovesNothing(t *testing.T) {
	a, fb := newGCApp(t, "", "")
	store := grant.Store{Dir: a.paths.VMsDir()}
	if err := store.Save("ghost", grant.Set{{Cap: "claude"}}); err != nil {
		t.Fatal(err)
	}
	res, err := a.GC(context.Background(), GCOptions{Owner: "paseo", DryRun: true})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if !res.DryRun || names(res.VMs) != "paseo-1,paseo-2,undated,paseo-4" || strings.Join(res.HostState, ",") != "ghost" {
		t.Errorf("unexpected result: %+v", res)
	}
	if r := removed(fb); len(r) != 0 {
		t.Errorf("a dry run must not remove VMs, removed %v", r)
	}
	if set, _ := store.Load("ghost"); len(set) != 1 {
		t.Error("a dry run must not remove host state")
	}
}

func TestGCPrunesHostStateOfVanishedVMs(t *testing.T) {
	a, fb := newGCApp(t, "", "")
	store := grant.Store{Dir: a.paths.VMsDir()}
	for _, name := range []string{"ghost", "manual", "paseo-1"} {
		if err := store.Save(name, grant.Set{{Cap: "claude"}}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := a.GC(context.Background(), GCOptions{})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if len(res.VMs) != 0 || len(removed(fb)) != 0 {
		t.Errorf("without --owner or --older-than gc removes no VM, got %+v / %v", res.VMs, removed(fb))
	}
	if strings.Join(res.HostState, ",") != "ghost" {
		t.Errorf("pruned %v, want [ghost]", res.HostState)
	}
	for name, want := range map[string]int{"ghost": 0, "manual": 1, "paseo-1": 1} {
		if set, _ := store.Load(name); len(set) != want {
			t.Errorf("%s has %d grants, want %d", name, len(set), want)
		}
	}
	// the second listing is the liveness check under the VMs' locks
	lists := 0
	for _, c := range fb.Calls {
		if c == "list" {
			lists++
		}
	}
	if lists != 2 {
		t.Errorf("expected a re-check before pruning, got %d listings:\n%s", lists, fb.Dump())
	}
}

func TestGCRemovesStateOfCollectedVMs(t *testing.T) {
	a, _ := newGCApp(t, "", "")
	store := grant.Store{Dir: a.paths.VMsDir()}
	if err := store.Save("paseo-1", grant.Set{{Cap: "claude"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GC(context.Background(), GCOptions{Owner: "paseo", Keep: []string{"paseo-2", "undated"}}); err != nil {
		t.Fatalf("GC: %v", err)
	}
	if set, _ := store.Load("paseo-1"); len(set) != 0 {
		t.Errorf("grants of a collected VM must go with it, got %v", set)
	}
}

func TestGCKeepsStateOfAVMRecreatedMeanwhile(t *testing.T) {
	a, _ := newGCApp(t, "", "paseo-1")
	store := grant.Store{Dir: a.paths.VMsDir()}
	if err := store.Save("paseo-1", grant.Set{{Cap: "claude"}}); err != nil {
		t.Fatal(err)
	}
	res, err := a.GC(context.Background(), GCOptions{Owner: "paseo", Keep: []string{"paseo-2", "undated"}})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if names(res.VMs) != "paseo-1" {
		t.Fatalf("paseo-1 should have been collected, got %q", names(res.VMs))
	}
	// the grants now belong to the new paseo-1 and must survive
	if set, _ := store.Load("paseo-1"); len(set) != 1 {
		t.Errorf("grants of the recreated VM were deleted")
	}
	if len(res.HostState) != 0 {
		t.Errorf("no leftovers expected, got %v", res.HostState)
	}
}

func TestGCPrunesStateOfAVMGoneMeanwhile(t *testing.T) {
	a, _ := newGCApp(t, "", "")
	store := grant.Store{Dir: a.paths.VMsDir()}
	if err := store.Save("paseo-4", grant.Set{{Cap: "claude"}}); err != nil {
		t.Fatal(err)
	}
	res, err := a.GC(context.Background(), GCOptions{Owner: "paseo"})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if set, _ := store.Load("paseo-4"); len(set) != 0 {
		t.Errorf("leftover grants of a VM removed by someone else must go in the same run")
	}
	if strings.Join(res.HostState, ",") != "paseo-4" || strings.Contains(names(res.VMs), "paseo-4") {
		t.Errorf("paseo-4 is a host-state leftover, not a collected VM: %+v", res)
	}
}

func TestGCContinuesAfterAFailedRemoval(t *testing.T) {
	a, fb := newGCApp(t, "paseo-1", "")
	res, err := a.GC(context.Background(), GCOptions{Owner: "paseo"})
	if err == nil || !strings.Contains(err.Error(), "paseo-1") {
		t.Fatalf("expected an error naming paseo-1, got %v", err)
	}
	if got := strings.Replace(collected(fb), "paseo-1,", "", 1); got != "paseo-2,undated" || names(res.VMs) != "paseo-2,undated" {
		t.Errorf("the other VMs must still be collected: removed %v, reported %q", removed(fb), names(res.VMs))
	}
}

func TestGCRejectsInvalidOptions(t *testing.T) {
	for _, opts := range []GCOptions{
		{Owner: "a b"},
		{Owner: "-"},
		{OlderThan: -time.Hour},
		{Owner: "paseo", Keep: []string{"../etc"}},
	} {
		a, fb := newGCApp(t, "", "")
		if _, err := a.GC(context.Background(), opts); err == nil {
			t.Errorf("GC(%+v) expected an error", opts)
		}
		if len(fb.Calls) != 0 {
			t.Errorf("GC(%+v) must not touch the backend, got:\n%s", opts, fb.Dump())
		}
	}
}

func TestNewPassesOwnerAndSlot(t *testing.T) {
	cases := map[string]vm.Spec{
		"create vm1 2 1024 paseo 3": {Name: "vm1", VCPUs: 2, MemMiB: 1024, Owner: "paseo", Slot: "3"},
		"create vm1 2 1024 paseo ":  {Name: "vm1", VCPUs: 2, MemMiB: 1024, Owner: "paseo"},
	}
	for want, spec := range cases {
		a, _, _ := newTestApp(t, sshOnly)
		// the Mac stamps owned VMs, in UTC, because gc measures ages with its clock
		a.now = func() time.Time { return gcNow.In(time.FixedZone("CEST", 2*3600)) }
		info, err := a.NewVM(context.Background(), spec, nil)
		if err != nil {
			t.Fatalf("NewVM: %v", err)
		}
		if !backendOf(a).Called(want) {
			t.Errorf("expected call %q, got:\n%s", want, backendOf(a).Dump())
		}
		if info.Owner != "paseo" || info.Slot != spec.Slot || info.CreatedAt == nil || !info.CreatedAt.Equal(gcNow) {
			t.Errorf("metadata not kept: %+v", info)
		}
	}
}

func TestHumanAge(t *testing.T) {
	for d, want := range map[time.Duration]string{
		-time.Second:        "0s",
		45 * time.Second:    "45s",
		12 * time.Minute:    "12m",
		47 * time.Hour:      "47h",
		49 * time.Hour:      "2d",
		10 * 24 * time.Hour: "10d",
	} {
		if got := HumanAge(d); got != want {
			t.Errorf("HumanAge(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestVMInfoJSONKeepsMetadataKeys(t *testing.T) {
	data, err := json.Marshal(VMInfo{Name: "vm1"})
	if err != nil {
		t.Fatal(err)
	}
	// consumers see the same keys for every VM
	if !strings.Contains(string(data), `"owner":"","slot":"","created_at":null`) {
		t.Errorf("metadata keys missing: %s", data)
	}
}

func TestNewVMPrunesLeftoversBeforeTheVMRuns(t *testing.T) {
	store := grant.Store{}
	var leftoverAtCreate []string
	a, _, _ := newTestApp(t, sshOnly)
	seed(a, vm.Info{Name: "agent1"})
	backendOf(a).OnCreate = func(context.Context, vm.Spec) error {
		// the broker reads grants by name as soon as the VM runs
		leftoverAtCreate, _ = store.Names()
		return nil
	}
	store.Dir = a.paths.VMsDir()
	for _, vmName := range []string{"agent1", "vm1"} { // vm1: an earlier VM the backend will auto-name again
		if err := store.Save(vmName, grant.Set{{Cap: "claude"}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.NewVM(context.Background(), vm.Spec{VCPUs: 2, MemMiB: 1024}, nil); err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	if strings.Join(leftoverAtCreate, ",") != "agent1" {
		t.Errorf("state left when the VM started: %v, want only the live agent1", leftoverAtCreate)
	}
	if set, _ := store.Load("agent1"); len(set) != 1 {
		t.Error("grants of a live VM must survive")
	}
}

func TestNewVMStartsWithoutLeftoverGrants(t *testing.T) {
	// paseo-1 still existed when NewVM pruned and was replaced right after
	// (gc removing it); the clear after creation catches that ordering
	a, _, _ := newTestApp(t, sshOnly)
	seed(a, vm.Info{Name: "paseo-1", Owner: "paseo"})
	backendOf(a).OnCreate = func(_ context.Context, spec vm.Spec) error {
		backendOf(a).Drop(spec.Name) // gc removed the old one just now
		return nil
	}
	store := grant.Store{Dir: a.paths.VMsDir()}
	// state of an earlier paseo-1 that gc kept because the new one already existed
	if err := store.Save("paseo-1", grant.Set{{Cap: "github"}}); err != nil {
		t.Fatal(err)
	}
	oldToken, err := store.Token("paseo-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.NewVM(context.Background(), vm.Spec{Name: "paseo-1", VCPUs: 2, MemMiB: 1024, Owner: "paseo", Slot: "1"}, nil); err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	if set, _ := store.Load("paseo-1"); len(set) != 0 {
		t.Errorf("a new VM must not inherit the grants of an earlier VM with its name, got %v", set)
	}
	if tok, _ := store.Token("paseo-1"); tok == oldToken {
		t.Error("a new VM must not inherit the placeholder token either")
	}
}

func TestNewVMKeepsAGrantGivenWhileItStarts(t *testing.T) {
	store := grant.Store{}
	granted := make(chan struct{})
	a, _, _ := newTestApp(t, sshOnly)
	backendOf(a).OnCreate = func(context.Context, vm.Spec) error {
		// `skiff grant box claude` in another terminal, as soon as box runs
		go func() {
			defer close(granted)
			unlock, err := store.Lock("box")
			if err != nil {
				t.Error(err)
				return
			}
			defer unlock()
			if err := store.Save("box", grant.Set{{Cap: "claude"}}); err != nil {
				t.Error(err)
			}
		}()
		select { // give it the chance to land before NewVM clears
		case <-granted:
		case <-time.After(100 * time.Millisecond):
		}
		return nil
	}
	store.Dir = a.paths.VMsDir()
	if _, err := a.NewVM(context.Background(), vm.Spec{Name: "box", VCPUs: 2, MemMiB: 1024}, nil); err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	<-granted
	if set, _ := store.Load("box"); len(set) != 1 {
		t.Errorf("a grant given while the VM started must survive, got %v", set)
	}
}

func TestNewVMCancelledWhileWaitingLeavesTheOtherVMAlone(t *testing.T) {
	a, _, _ := newTestApp(t, sshOnly)
	fb := backendOf(a)
	fb.OnCreate = func(context.Context, vm.Spec) error { return errors.New("signal: killed") }
	store := grant.Store{Dir: a.paths.VMsDir()}
	// another `skiff new box` is creating box and holds its grant lock
	unlock, err := store.Lock("box")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := a.NewVM(ctx, vm.Spec{Name: "box", VCPUs: 2, MemMiB: 1024}, nil)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond) // let NewVM block on the lock
	cancel()                          // Ctrl-C while waiting
	unlock()                          // the other call finished box
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("want the cancellation, got %v", err)
	}
	for _, c := range fb.Calls {
		if strings.HasPrefix(c, "rm ") || strings.HasPrefix(c, "create ") {
			t.Errorf("a call cancelled before it created anything must not touch box: %s", c)
		}
	}
}

func TestNewVMKeepsGrantsWhenTheNameIsTaken(t *testing.T) {
	a, _, _ := newTestApp(t, sshOnly)
	seed(a, vm.Info{Name: "paseo-1"})
	store := grant.Store{Dir: a.paths.VMsDir()}
	if err := store.Save("paseo-1", grant.Set{{Cap: "claude"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.NewVM(context.Background(), vm.Spec{Name: "paseo-1", VCPUs: 2, MemMiB: 1024}, nil); err == nil {
		t.Fatal("expected the backend's error")
	}
	if set, _ := store.Load("paseo-1"); len(set) != 1 {
		t.Error("a failed new must not touch the grants of the existing VM")
	}
}
