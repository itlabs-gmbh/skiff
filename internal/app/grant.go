package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sovyn-eu/skiff/internal/cap"
	"github.com/sovyn-eu/skiff/internal/config"
	"github.com/sovyn-eu/skiff/internal/grant"
	"github.com/sovyn-eu/skiff/internal/guest"
	"github.com/sovyn-eu/skiff/internal/intercept"
	"github.com/sovyn-eu/skiff/internal/profile"
	"github.com/sovyn-eu/skiff/internal/vm"
)

func (a *App) grantStore() grant.Store {
	return grant.Store{Dir: a.paths.VMsDir()}
}

// loadCaps resolves embedded and user capabilities.
func (a *App) loadCaps() (cap.Set, error) {
	return cap.Load(a.paths.CapsDir())
}

// Grant allows capabilities for a VM and provisions the guest accordingly.
func (a *App) Grant(ctx context.Context, name string, specs []string) (grant.Set, error) {
	if err := vm.ValidateName(name); err != nil {
		return nil, err
	}
	caps, err := a.loadCaps()
	if err != nil {
		return nil, err
	}
	requested, err := grant.ParseSet(specs)
	if err != nil {
		return nil, err
	}
	for _, g := range requested {
		if err := checkGrant(caps, g); err != nil {
			return nil, err
		}
	}
	store := a.grantStore()
	unlock, err := store.Lock(name)
	if err != nil {
		return nil, err
	}
	defer unlock()
	set, err := store.Load(name)
	if err != nil {
		return nil, err
	}
	for _, g := range requested {
		set = set.Add(g)
	}
	// Configure the guest first: a grant is only persisted once the guest can
	// actually use it, so a failed provision never leaves a silent allow.
	if err := a.provision(ctx, name, caps, set, nil); err != nil {
		return nil, err
	}
	if err := store.Save(name, set); err != nil {
		return nil, err
	}
	a.printf("%s may now use: %s\n", name, strings.Join(set.Caps(), ", "))
	return set, nil
}

// Revoke withdraws capabilities and removes their guest configuration.
func (a *App) Revoke(ctx context.Context, name string, specs []string) (grant.Set, error) {
	if err := vm.ValidateName(name); err != nil {
		return nil, err
	}
	requested, err := grant.ParseSet(specs)
	if err != nil {
		return nil, err
	}
	store := a.grantStore()
	unlock, err := store.Lock(name)
	if err != nil {
		return nil, err
	}
	defer unlock()
	stored, err := store.Load(name)
	if err != nil {
		return nil, err
	}
	// Check every grant before withdrawing any, so a typo in one leaves the
	// others in place.
	set := stored
	for _, g := range requested {
		if !stored.Contains(g) {
			return nil, fmt.Errorf("%s is not granted to %s", g, name)
		}
		set = set.Remove(g)
	}
	if err := store.Save(name, set); err != nil {
		return nil, err
	}
	caps, err := a.loadCaps()
	if err != nil {
		return nil, err
	}
	if err := a.provision(ctx, name, caps, set, nil); err != nil {
		return nil, err
	}
	if len(set) == 0 {
		a.printf("%s has no grants left\n", name)
	} else {
		a.printf("%s may still use: %s\n", name, strings.Join(set.Caps(), ", "))
	}
	return set, nil
}

// Grants returns the current grants of a VM.
func (a *App) Grants(name string) (grant.Set, error) {
	if err := vm.ValidateName(name); err != nil {
		return nil, err
	}
	return a.grantStore().Load(name)
}

// checkGrant verifies that a grant names a known capability.
func checkGrant(caps cap.Set, g grant.Grant) error {
	if g.Cap == grant.SSHAgent {
		return nil
	}
	if _, ok := caps[g.Cap]; !ok {
		return fmt.Errorf("unknown capability %q (see 'skiff cap ls')", g.Cap)
	}
	return nil
}

// templateData is what guest templates of a VM see.
func (a *App) templateData(name string) (cap.TemplateData, error) {
	token, err := a.grantStore().Token(name)
	if err != nil {
		return cap.TemplateData{}, err
	}
	return cap.TemplateData{
		VM:           name,
		BrokerURL:    fmt.Sprintf("http://127.0.0.1:%d", config.BrokerGuestPort),
		PseudoToken:  token,
		BrokerSocket: config.BrokerGuestSocket,
	}, nil
}

// provision renders the guest configuration for the granted caps and the
// VM's profile and applies it over SSH: one call reads the current state,
// one call applies the plan. A nil prof means the profile stored for the VM.
func (a *App) provision(ctx context.Context, name string, caps cap.Set, set grant.Set, prof *profile.Profile) error {
	data, err := a.templateData(name)
	if err != nil {
		return err
	}
	if prof == nil {
		if prof, err = a.storedProfile(name); err != nil {
			return err
		}
	}
	var granted []cap.Cap
	for _, n := range set.Caps() {
		if c, ok := caps[n]; ok {
			granted = append(granted, c)
		}
	}
	all := granted
	if prof != nil && !prof.IsZero() {
		pc, err := prof.GuestConfig()
		if err != nil {
			return err
		}
		all = append(append([]cap.Cap(nil), granted...), pc)
	}
	plan, err := guest.Render(all, data)
	if err != nil {
		return err
	}
	// The relay only serves capabilities; a profile alone does not need it.
	plan.Relay = len(granted) > 0
	plan, rotation, err := a.withIntercept(plan, name, caps, set)
	if err != nil {
		return err
	}
	if err := a.backend.Ready(ctx); err != nil {
		return err
	}
	if err := a.ensureSSHConfig(); err != nil {
		return err
	}
	out, err := a.sshScript(ctx, name, plan.ReadScript())
	if err != nil {
		return fmt.Errorf("read guest state of %s: %w", name, err)
	}
	state, err := guest.ParseState(out)
	if err != nil {
		return err
	}
	script, err := plan.ApplyScript(state)
	if err != nil {
		return err
	}
	if _, err := a.sshScript(ctx, name, script); err != nil {
		return fmt.Errorf("apply guest configuration to %s: %w", name, err)
	}
	return a.commitIntercept(name, rotation)
}

// withIntercept adds interception to the plan when a granted capability
// declares intercept routes. A CA that must be created or grown is only
// prepared: the guest trusts the current and the next certificate, and
// commitIntercept writes the next one once the guest has been updated, so a
// failed update leaves the broker on the CA the guest still trusts. Only
// certificates go into the plan; the key stays in the VM's state.
func (a *App) withIntercept(plan guest.Plan, name string, caps cap.Set, set grant.Set) (guest.Plan, *intercept.Rotation, error) {
	hosts := caps.InterceptHosts(set.Caps())
	if len(hosts) == 0 {
		return plan, nil, nil
	}
	dir, err := a.grantStore().InterceptDir(name)
	if err != nil {
		return guest.Plan{}, nil, err
	}
	rotation, err := intercept.Prepare(dir, hosts, time.Now)
	if err != nil {
		return guest.Plan{}, nil, err
	}
	plan, err = plan.WithIntercept(hosts, rotation.TrustPEM())
	if err != nil {
		return guest.Plan{}, nil, err
	}
	return plan, rotation, nil
}

// commitIntercept makes a prepared CA the broker's, after the guest trusts it.
func (a *App) commitIntercept(name string, rotation *intercept.Rotation) error {
	if rotation == nil {
		return nil
	}
	issued, err := rotation.Commit()
	if err != nil {
		return fmt.Errorf("save the intercept CA of %s: %w", name, err)
	}
	if issued {
		a.printf("issued an intercept CA for %s\n", name)
	}
	return nil
}

// sshScript runs a shell script in the guest. The script is streamed to
// `bash -s` over stdin, so neither the remote shell's quoting rules nor the
// argument length limit apply, however large a merged JSON file gets.
func (a *App) sshScript(ctx context.Context, name, script string) ([]byte, error) {
	return a.r.OutputWithInput(ctx, strings.NewReader(script), "ssh", a.sshArgs(name, []string{"bash", "-s"})...)
}
