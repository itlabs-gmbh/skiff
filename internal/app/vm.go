package app

import (
	"context"
	"fmt"
	"time"

	"github.com/sovyn-eu/skiff/internal/config"
	"github.com/sovyn-eu/skiff/internal/profile"
	"github.com/sovyn-eu/skiff/internal/vm"
)

// cleanupTimeout bounds the best-effort removal of a VM whose creation was
// interrupted; it may have to wait for the agent's lock first.
const cleanupTimeout = 2 * time.Minute

// VMInfo is what the backend reports about a VM, plus its grants.
type VMInfo = vm.Info

// NewVM creates and boots a microVM. With a profile, its setup runs in the
// fresh guest and its grants and agent configuration are applied together
// with the grants of the spec.
func (a *App) NewVM(ctx context.Context, spec vm.Spec, prof *profile.Profile) (VMInfo, error) {
	if err := spec.Validate(); err != nil {
		return VMInfo{}, err
	}
	forwards := make([]vm.Forward, 0, len(spec.Forwards))
	for _, s := range spec.Forwards {
		f, _ := vm.ParseForward(s) // validated above
		forwards = append(forwards, f)
	}
	if err := a.checkHostPortsFree(forwards); err != nil {
		return VMInfo{}, err
	}
	if err := a.backend.Ready(ctx); err != nil {
		return VMInfo{}, err
	}
	if err := a.pruneVanished(ctx); err != nil {
		return VMInfo{}, fmt.Errorf("clear grants left by removed VMs: %w", err)
	}
	var info VMInfo
	var err error
	started := false
	create := func() (err error) {
		// Ctrl-C while waiting for the lock: another `new` of this name
		// may hold it, and its VM must not be cleaned up as ours.
		if err := ctx.Err(); err != nil {
			return err
		}
		started = true
		info, err = a.backend.Create(ctx, spec, a.now())
		return err
	}
	// pruneVanished cleared leftovers before, but an earlier VM of this name
	// may have been removed only after that (by gc, whose own prune then sees
	// the new VM and keeps the state). A named VM is therefore created under
	// its grant lock and starts clean before a concurrent grant can save.
	if spec.Name != "" {
		err = a.grantStore().WithFreshState(spec.Name, create)
	} else {
		err = create()
	}
	if err != nil {
		if started && ctx.Err() != nil {
			a.cleanupInterrupted(spec.Name)
		}
		return VMInfo{}, err
	}
	if spec.Name == "" {
		// The backend picked the name, so it could not be locked in advance;
		// nobody can have granted the VM before learning its name.
		if err := a.grantStore().Remove(info.Name); err != nil {
			return info, fmt.Errorf("%s was created, but clearing grants left by an earlier VM of that name failed: %w", info.Name, err)
		}
	}
	a.printf("%s is running at %s\n  skiff ssh %s\n  ssh %s.%s\n", info.Name, info.IP, info.Name, info.Name, config.Instance)
	if len(forwards) > 0 {
		if info, err = a.forward(ctx, info, forwards); err != nil {
			return info, err
		}
	}
	switch {
	case prof != nil && !prof.IsZero():
		set, err := a.Apply(ctx, info.Name, *prof, spec.Grants, true)
		if err != nil {
			return info, &ProfileError{Name: info.Name, Err: err}
		}
		info.Grants = set.Caps()
	case len(spec.Grants) > 0:
		set, err := a.Grant(ctx, info.Name, spec.Grants)
		if err != nil {
			return info, err
		}
		info.Grants = set.Caps()
	}
	return info, nil
}

// ProfileError reports that NewVM created and booted the VM but could not
// apply its profile. Apply stores grants only after the setup, so the VM has
// neither the profile nor any grant; the caller knows which profile was
// selected and can name the `skiff apply` that finishes the VM.
type ProfileError struct {
	Name string
	Err  error
}

func (e *ProfileError) Error() string { return e.Err.Error() }

func (e *ProfileError) Unwrap() error { return e.Err }

// StartVM boots a stopped microVM.
func (a *App) StartVM(ctx context.Context, name string) (VMInfo, error) {
	if err := vm.ValidateName(name); err != nil {
		return VMInfo{}, err
	}
	if err := a.backend.Ready(ctx); err != nil {
		return VMInfo{}, err
	}
	return a.report(a.backend.Start(ctx, name))
}

// StopVM shuts a VM down but keeps its disk.
func (a *App) StopVM(ctx context.Context, name string) (VMInfo, error) {
	if err := vm.ValidateName(name); err != nil {
		return VMInfo{}, err
	}
	if err := a.backend.Ready(ctx); err != nil {
		return VMInfo{}, err
	}
	return a.report(a.backend.Stop(ctx, name))
}

func (a *App) report(info VMInfo, err error) (VMInfo, error) {
	if err != nil {
		return VMInfo{}, err
	}
	a.printf("%s is %s\n", info.Name, info.State)
	return info, nil
}

// RemoveVM stops and deletes a microVM.
func (a *App) RemoveVM(ctx context.Context, name string) error {
	if err := vm.ValidateName(name); err != nil {
		return err
	}
	if err := a.backend.Ready(ctx); err != nil {
		return err
	}
	if err := a.removeVM(ctx, name); err != nil {
		return err
	}
	a.printf("%s removed\n", name)
	return nil
}

// removeVM removes the VM and its host state (grants, token).
func (a *App) removeVM(ctx context.Context, name string) error {
	if _, err := a.backend.Remove(ctx, name, nil); err != nil {
		return err
	}
	return a.grantStore().Remove(name)
}

// ListVMs returns all microVMs known to the backend, with their grants.
func (a *App) ListVMs(ctx context.Context) ([]VMInfo, error) {
	if err := a.backend.Ready(ctx); err != nil {
		return nil, err
	}
	vms, err := a.backend.List(ctx)
	if err != nil {
		return nil, err
	}
	store := a.grantStore()
	for i := range vms {
		set, err := store.Load(vms[i].Name)
		if err != nil {
			return nil, err
		}
		vms[i].Grants = set.Caps()
	}
	return vms, nil
}

// InspectVM returns a single microVM, including its host-side grants.
func (a *App) InspectVM(ctx context.Context, name string) (VMInfo, error) {
	if err := vm.ValidateName(name); err != nil {
		return VMInfo{}, err
	}
	return a.describe(ctx, name)
}

// cleanupInterrupted removes a VM whose creation was cancelled (Ctrl-C). The
// backend keeps working after the connection drops and either finishes or
// rolls back on its own, so the removal is best-effort and waits for its lock.
func (a *App) cleanupInterrupted(name string) {
	if name == "" {
		a.printf("creation interrupted; check 'skiff ls' and remove leftovers with 'skiff rm'\n")
		return
	}
	a.printf("creation of %s interrupted, cleaning up\n", name)
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if _, err := a.backend.Remove(ctx, name, nil); err != nil {
		a.printf("  cleanup did not complete (%v); check 'skiff ls'\n", err)
	}
}
