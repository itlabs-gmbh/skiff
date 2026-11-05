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
// repository files, in the order given: a later file's values win. Files
// named explicitly must exist; the default name (.skiff) is simply skipped
// when it is missing. All files are optional, so the result may be zero.
func (a *App) ResolveProfile(repoFiles []string, explicit bool) (profile.Profile, error) {
	p, _, err := a.resolveProfile(repoFiles, explicit)
	return p, err
}

// readProfile is a repository file with the bytes it was parsed from, so a
// trust check hashes exactly what will be applied.
type readProfile struct {
	path string
	data []byte
	prof profile.Profile
}

// resolveProfile also returns the repository files that were read.
func (a *App) resolveProfile(repoFiles []string, explicit bool) (profile.Profile, []readProfile, error) {
	var merged profile.Profile
	var seen fileSet
	data, found, err := readOptional(a.paths.ProfilePath())
	if err != nil {
		return profile.Profile{}, nil, err
	}
	if found {
		if merged, err = profile.Parse(string(data), a.paths.ProfilePath()); err != nil {
			return profile.Profile{}, nil, err
		}
		if seen, err = seen.add(a.paths.ProfilePath()); err != nil {
			return profile.Profile{}, nil, err
		}
	}
	var read []readProfile
	for _, path := range repoFiles {
		data, found, err := readOptional(path)
		if err != nil {
			return profile.Profile{}, nil, err
		}
		if !found {
			if explicit {
				return profile.Profile{}, nil, fmt.Errorf("profile %s does not exist", path)
			}
			continue
		}
		if seen, err = seen.add(path); err != nil {
			return profile.Profile{}, nil, err
		}
		repo, err := profile.Parse(string(data), path)
		if err != nil {
			return profile.Profile{}, nil, err
		}
		merged = profile.Merge(merged, repo)
		read = append(read, readProfile{path: path, data: data, prof: repo})
	}
	// Each file was checked on its own; references between them (a plugin's
	// marketplace) and the default alone are checked here, on every path.
	if err := merged.Validate(); err != nil {
		return profile.Profile{}, nil, fmt.Errorf("%s: %w", strings.Join(merged.Sources, " + "), err)
	}
	return merged, read, nil
}

// fileSet holds the profile files read so far, by identity rather than by
// name: a file reached twice, under another path, through a symlink or a
// hard link, would run its setup twice. The machine default is the first
// entry when it exists, as it always applies.
type fileSet []seenFile

type seenFile struct {
	path string
	info os.FileInfo
}

// add returns the set with path added, or an error when the file is in it.
func (s fileSet) add(path string) (fileSet, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}
	for _, f := range s {
		if os.SameFile(f.info, info) {
			return nil, fmt.Errorf("profile %s is named more than once (also as %s)", path, f.path)
		}
	}
	return append(s[:len(s):len(s)], seenFile{path: path, info: info}), nil
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
// profile: every repository file must have been trusted (skiff profile
// trust) in its current content, or trust records the missing ones now.
// Each file is checked on its own, against the bytes it was parsed from, so
// a file swapped after it was trusted is refused. The machine default needs
// no trust.
func (a *App) ResolveTrustedProfile(repoFiles []string, explicit, trust bool) (profile.Profile, error) {
	p, read, err := a.resolveProfile(repoFiles, explicit)
	if err != nil {
		return profile.Profile{}, err
	}
	untrusted, err := a.untrustedProfiles(read)
	if err != nil {
		return profile.Profile{}, err
	}
	if len(untrusted) == 0 {
		return p, nil
	}
	if !trust {
		return profile.Profile{}, untrustedError(untrusted)
	}
	for _, u := range untrusted {
		if err := a.recordTrust(u.key); err != nil {
			return profile.Profile{}, err
		}
		a.printf("trusted %s (until it changes)\n", u.path)
	}
	return p, nil
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

// ProfileClear removes the profile's configuration from a VM and forgets the
// stored profile; grants stay. It is the way back for a profile whose
// sections were all removed, which Apply refuses as "nothing to apply".
func (a *App) ProfileClear(ctx context.Context, name string) error {
	if err := vm.ValidateName(name); err != nil {
		return err
	}
	caps, err := a.loadCaps()
	if err != nil {
		return err
	}
	store := a.grantStore()
	unlock, err := store.Lock(name)
	if err != nil {
		return err
	}
	defer unlock()
	stored, err := a.storedProfile(name)
	if err != nil {
		return err
	}
	if stored == nil {
		return fmt.Errorf("no profile has been applied to %s", name)
	}
	set, err := store.Load(name)
	if err != nil {
		return err
	}
	if err := a.provision(ctx, name, caps, set, &profile.Profile{}); err != nil {
		return err
	}
	if err := store.RemoveProfile(name); err != nil {
		return err
	}
	a.printf("%s no longer has a profile; grants are unchanged\n", name)
	return nil
}

// runSetup streams the profile's setup script into the guest, with its
// output on the terminal. It owns the VM's broker claim and the agent lock
// while it runs, so neither a broker nor a forwarded SSH agent reaches the
// VM: an open session or tunnel is refused, a session started meanwhile gets
// its broker in standby and no agent until the setup ends, and a second
// setup cannot interleave. That is what keeps a repository's .skiff from
// reaching credentials.
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
	busy := fmt.Errorf("%s has an open session, tunnel or setup; close it before running the setup, which must not see the broker or a forwarded SSH agent", name)
	releaseAgent, err := a.lockAgent(name, true)
	if errors.Is(err, errAgentLockBusy) {
		return busy
	}
	if err != nil {
		return err
	}
	defer releaseAgent()
	socket := a.paths.SocketPath(name)
	release, err := broker.Claim(socket)
	if err == nil && broker.Alive(socket) {
		release()
		err = broker.ErrBusy
	}
	if errors.Is(err, broker.ErrBusy) {
		return busy
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
func (a *App) ProfileShow(repoFiles []string, explicit bool, vmName string, render bool) error {
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
		if p, err = a.ResolveProfile(repoFiles, explicit); err != nil {
			return err
		}
	}
	if p.IsZero() {
		a.printf("# no profile: none of %s exists\n", strings.Join(append([]string{a.paths.ProfilePath()}, repoFiles...), ", "))
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
	p, err := a.ResolveProfile([]string{repoFile}, false)
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
