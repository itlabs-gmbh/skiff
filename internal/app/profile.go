package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/sovyn-eu/skiff/internal/broker"
	"github.com/sovyn-eu/skiff/internal/cap"
	"github.com/sovyn-eu/skiff/internal/grant"
	"github.com/sovyn-eu/skiff/internal/guest"
	"github.com/sovyn-eu/skiff/internal/profile"
	"github.com/sovyn-eu/skiff/internal/vm"
)

// ResolveProfile merges the machine default (~/.skiff/profile.toml) with the
// repository file. An explicitly named repository file must exist; the
// default name (.skiff) is simply skipped when it is missing. Both files
// are optional, so the result may be zero.
func (a *App) ResolveProfile(repoFile string, explicit bool) (profile.Profile, error) {
	p, _, err := a.resolveProfile(repoFile, explicit)
	return p, err
}

// resolveProfile also returns the bytes the repository file was parsed
// from, so a trust check hashes exactly what will be applied.
func (a *App) resolveProfile(repoFile string, explicit bool) (profile.Profile, []byte, error) {
	var merged profile.Profile
	data, found, err := readOptional(a.paths.ProfilePath())
	if err != nil {
		return profile.Profile{}, nil, err
	}
	if found {
		if merged, err = profile.Parse(string(data), a.paths.ProfilePath()); err != nil {
			return profile.Profile{}, nil, err
		}
	}
	var repoData []byte
	if repoFile != "" {
		data, found, err := readOptional(repoFile)
		if err != nil {
			return profile.Profile{}, nil, err
		}
		if !found && explicit {
			return profile.Profile{}, nil, fmt.Errorf("profile %s does not exist", repoFile)
		}
		if found {
			repo, err := profile.Parse(string(data), repoFile)
			if err != nil {
				return profile.Profile{}, nil, err
			}
			merged = profile.Merge(merged, repo)
			repoData = data
		}
	}
	// Each file was checked on its own; references between them (a plugin's
	// marketplace) and the default alone are checked here, on every path.
	if err := merged.Validate(); err != nil {
		return profile.Profile{}, nil, fmt.Errorf("%s: %w", strings.Join(merged.Sources, " + "), err)
	}
	return merged, repoData, nil
}

func readOptional(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read profile: %w", err)
	}
	return data, true, nil
}

// ResolveTrustedProfile is ResolveProfile for commands that act on the
// profile: a repository file must have been trusted (skiff profile trust)
// in its current content, or trust records it now. The trust check and the
// parse share one read of the file.
func (a *App) ResolveTrustedProfile(repoFile string, explicit, trust bool) (profile.Profile, error) {
	p, repoData, err := a.resolveProfile(repoFile, explicit)
	if err != nil {
		return profile.Profile{}, err
	}
	if repoData == nil {
		return p, nil
	}
	key, err := trustKey(repoFile, repoData)
	if err != nil {
		return profile.Profile{}, err
	}
	ok, err := a.isTrusted(key)
	if err != nil {
		return profile.Profile{}, err
	}
	switch {
	case ok:
		return p, nil
	case trust:
		if err := a.recordTrust(key); err != nil {
			return profile.Profile{}, err
		}
		a.printf("trusted %s (until it changes)\n", repoFile)
		return p, nil
	}
	return profile.Profile{}, untrustedError(repoFile, p)
}

// Apply makes a profile the VM's: its grants are added to extra and granted,
// its agent configuration is provisioned, and with setup its packages,
// tools, skills and setup script are installed first. The profile is stored
// with the VM so later grants and revokes keep its configuration. Grants
// are only ever added; revoke what the profile no longer lists by hand.
func (a *App) Apply(ctx context.Context, name string, p profile.Profile, extra []string, setup bool) (grant.Set, error) {
	if err := vm.ValidateName(name); err != nil {
		return nil, err
	}
	if p.IsZero() {
		return nil, fmt.Errorf("nothing to apply: no profile declares anything (see 'skiff profile show')")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	caps, err := a.loadCaps()
	if err != nil {
		return nil, err
	}
	requested, err := grant.ParseSet(append(append([]string(nil), p.Grants...), extra...))
	if err != nil {
		return nil, err
	}
	for _, g := range requested {
		if err := checkGrant(caps, g); err != nil {
			return nil, err
		}
	}
	text, err := p.Encode()
	if err != nil {
		return nil, err
	}
	if len(p.Sources) > 0 {
		a.printf("applying profile %s to %s\n", strings.Join(p.Sources, " + "), name)
	}
	store := a.grantStore()
	// The setup can take minutes and touches neither grants nor the stored
	// profile, so it runs before the VM's lock is taken: `skiff new` and
	// `gc` wait on that lock for every VM. A clash between the profile and
	// the grants is checked first, so it cannot surface after the installs.
	if setup {
		current, err := store.Load(name)
		if err != nil {
			return nil, err
		}
		for _, g := range requested {
			current = current.Add(g)
		}
		if _, err := a.renderPlan(name, caps, current, &p); err != nil {
			return nil, err
		}
		if err := a.runSetup(ctx, name, p); err != nil {
			return nil, err
		}
	}
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
	if err := a.provision(ctx, name, caps, set, &p); err != nil {
		return nil, err
	}
	if err := store.SaveProfile(name, text); err != nil {
		return nil, err
	}
	if err := store.Save(name, set); err != nil {
		return nil, err
	}
	if len(set) > 0 {
		a.printf("%s may now use: %s\n", name, strings.Join(set.Caps(), ", "))
	}
	return set, nil
}

// runSetup streams the profile's setup script into the guest, with its
// output on the terminal. It owns the VM's broker claim while it runs, so no
// broker serves the VM: an open session or tunnel is refused, a session
// started meanwhile waits in standby, and a second setup cannot interleave.
// That is what keeps a repository's .skiff from reaching credentials.
func (a *App) runSetup(ctx context.Context, name string, p profile.Profile) error {
	data, err := a.templateData(name)
	if err != nil {
		return err
	}
	script, err := p.SetupScript(data)
	if err != nil {
		return err
	}
	if err := a.backend.Ready(ctx); err != nil {
		return err
	}
	if err := a.ensureSSHConfig(); err != nil {
		return err
	}
	socket := a.paths.SocketPath(name)
	release, err := broker.Claim(socket)
	if err == nil && broker.Alive(socket) {
		release()
		err = broker.ErrBusy
	}
	if errors.Is(err, broker.ErrBusy) {
		return fmt.Errorf("%s has an open session, tunnel or setup; close it before running the setup, which must not see the broker", name)
	}
	if err != nil {
		return err
	}
	defer release()
	a.printf("setting up %s\n", name)
	if err := a.r.RunWithInput(ctx, strings.NewReader(script), "ssh", a.sshArgs(name, []string{"bash", "-s"})...); err != nil {
		return fmt.Errorf("setup of %s failed: %w", name, err)
	}
	return nil
}

// storedProfile returns the profile applied to a VM, nil when none.
func (a *App) storedProfile(name string) (*profile.Profile, error) {
	text, err := a.grantStore().LoadProfile(name)
	if err != nil || text == "" {
		return nil, err
	}
	p, err := profile.Parse(text, "profile of "+name)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// ProfileShow prints the resolved profile, or the one applied to vmName,
// and with render what the guest receives from it.
func (a *App) ProfileShow(repoFile string, explicit bool, vmName string, render bool) error {
	var p profile.Profile
	if vmName != "" {
		if err := vm.ValidateName(vmName); err != nil {
			return err
		}
		stored, err := a.storedProfile(vmName)
		if err != nil {
			return err
		}
		if stored == nil {
			return fmt.Errorf("no profile has been applied to %s", vmName)
		}
		p = *stored
	} else {
		var err error
		if p, err = a.ResolveProfile(repoFile, explicit); err != nil {
			return err
		}
	}
	if p.IsZero() {
		a.printf("# no profile: neither %s nor %s exists\n", a.paths.ProfilePath(), repoFile)
		return nil
	}
	text, err := p.Encode()
	if err != nil {
		return err
	}
	a.printf("# sources: %s\n%s", strings.Join(p.Sources, " + "), text)
	if !render {
		return nil
	}
	return a.printProfilePlan(p, vmName)
}

func (a *App) printProfilePlan(p profile.Profile, vmName string) error {
	data, err := a.previewData(vmName)
	if err != nil {
		return err
	}
	if vmName == "" {
		vmName = data.VM
	}
	c, err := p.GuestConfig(data)
	if err != nil {
		return err
	}
	plan, err := guest.Render([]cap.Cap{c}, data)
	if err != nil {
		return err
	}
	a.printf("# guest configuration for %s\n", vmName)
	if len(p.Grants) > 0 {
		a.printf("grants %s\n", strings.Join(p.Grants, " "))
	}
	a.printPlan(plan)
	script, err := p.SetupScript(data)
	if err != nil {
		return err
	}
	if script != "" {
		a.printf("setup script:\n%s", indent(script))
	}
	return nil
}

// ProfileInit writes the commented skeleton as the repository file, or as
// the machine default with global set.
func (a *App) ProfileInit(repoFile string, global bool) error {
	path, mode := repoFile, os.FileMode(0o644)
	if global {
		path, mode = a.paths.ProfilePath(), 0o600
		if err := os.MkdirAll(a.paths.Home, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", a.paths.Home, err)
		}
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	if err := os.WriteFile(path, []byte(profile.Skeleton), mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	a.printf("wrote %s\n  edit it, then: skiff profile show\n", path)
	return nil
}

// ProfileLint validates one file, or the machine default and the repository
// file and their merge.
func (a *App) ProfileLint(path string, repoFile string) error {
	if path != "" {
		if _, err := profile.ParseFile(path); err != nil {
			return err
		}
		a.printf("%s: ok\n", path)
		return nil
	}
	p, err := a.ResolveProfile(repoFile, false)
	if err != nil {
		return err
	}
	if len(p.Sources) == 0 {
		a.printf("no profile found (%s, %s)\n", a.paths.ProfilePath(), repoFile)
		return nil
	}
	a.printf("%s: ok\n", strings.Join(p.Sources, " + "))
	return nil
}
