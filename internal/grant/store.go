package grant

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/sovyn-eu/skiff/internal/cap"
)

// Store keeps per-VM grants and placeholder tokens on the Mac, where the
// broker runs, so policy and enforcement live in the same place.
type Store struct {
	// Dir is the root, usually ~/.skiff/vms.
	Dir string
}

const (
	grantsFile = "grants"
	tokenFile  = "token"
	tokenBytes = 16
)

// vmDir validates the name before building a path; VM names and cap names
// share the same label rules.
func (s Store) vmDir(vm string) (string, error) {
	if err := cap.ValidateName(vm); err != nil {
		return "", fmt.Errorf("vm %w", err)
	}
	return filepath.Join(s.Dir, vm), nil
}

// InterceptDir is where the VM's intercept CA lives. It sits inside the
// VM's state directory, so Remove, WithFreshState and Prune take it along.
func (s Store) InterceptDir(vm string) (string, error) {
	dir, err := s.vmDir(vm)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "intercept"), nil
}

// Load returns the grants of a VM; a VM without state has none.
func (s Store) Load(vm string) (Set, error) {
	dir, err := s.vmDir(vm)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, grantsFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read grants: %w", err)
	}
	var specs []string
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			specs = append(specs, line)
		}
	}
	set, err := ParseSet(specs)
	if err != nil {
		return nil, fmt.Errorf("grants of %s: %w", vm, err)
	}
	return set, nil
}

// Save replaces the grants of a VM.
func (s Store) Save(vm string, set Set) error {
	dir, err := s.vmDir(vm)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create vm state: %w", err)
	}
	text := strings.Join(set.Caps(), "\n")
	if text != "" {
		text += "\n"
	}
	return writeAtomic(filepath.Join(dir, grantsFile), []byte(text), 0o600)
}

// Token returns the VM's placeholder token, creating it on first use. The
// broker never verifies it; it exists for clients that insist on a token.
func (s Store) Token(vm string) (string, error) {
	dir, err := s.vmDir(vm)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, tokenFile)
	data, err := os.ReadFile(path)
	if err == nil && len(strings.TrimSpace(string(data))) > 0 {
		return strings.TrimSpace(string(data)), nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("read token: %w", err)
	}
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	token := hex.EncodeToString(raw)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create vm state: %w", err)
	}
	if err := writeAtomic(path, []byte(token+"\n"), 0o600); err != nil {
		return "", err
	}
	return token, nil
}

// Lock takes an exclusive, cross-process lock for a VM and returns the
// function that releases it. Grant and revoke hold it from reading the
// grants through provisioning the guest to saving, so two invocations
// cannot lose each other's change (atomic file replacement alone would let
// a slower grant re-save a grant that a concurrent revoke removed).
func (s Store) Lock(vm string) (func(), error) {
	dir, err := s.vmDir(vm)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("create vm state: %w", err)
	}
	f, err := os.OpenFile(dir+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock %s: %w", vm, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// Remove deletes all state of a VM. The lock file itself stays: deleting it
// would let a later Lock create a fresh file and succeed while a holder of
// the old inode still believes it is exclusive.
func (s Store) Remove(vm string) error {
	unlock, err := s.Lock(vm)
	if err != nil {
		return err
	}
	defer unlock()
	dir, err := s.vmDir(vm)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove vm state: %w", err)
	}
	return nil
}

// WithFreshState runs create, which creates the VM, under the VM's lock and,
// when it succeeds, removes whatever state is stored under the name before
// releasing the lock. Grants saved by a concurrent grant therefore land after
// the clear and belong to the new VM, while none of a predecessor's remain.
// A failed create (e.g. the name is taken) leaves the state alone.
func (s Store) WithFreshState(vm string, create func() error) error {
	unlock, err := s.Lock(vm)
	if err != nil {
		return err
	}
	defer unlock()
	if err := create(); err != nil {
		return err
	}
	dir, _ := s.vmDir(vm) // validated by Lock
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("clear state left by an earlier %s: %w", vm, err)
	}
	return nil
}

// Names lists the VMs that have host-side state, sorted. Lock files and
// entries that are not valid VM names are ignored.
func (s Store) Names() ([]string, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list vm state: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() && cap.ValidateName(e.Name()) == nil {
			names = append(names, e.Name()) // ReadDir sorts by name
		}
	}
	return names, nil
}

// Prune removes the state of every VM in names that alive does not report.
// The locks of all of them are held while alive runs, so a VM that is
// created and granted concurrently is either reported by alive or gets its
// state only after the removal. Nothing is removed when alive fails.
func (s Store) Prune(names []string, alive func() (map[string]bool, error)) ([]string, error) {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted) // one global order, so two pruners cannot deadlock
	for _, vm := range sorted {
		if _, err := s.vmDir(vm); err != nil {
			return nil, err
		}
	}
	for _, vm := range sorted {
		unlock, err := s.Lock(vm)
		if err != nil {
			return nil, err
		}
		defer unlock()
	}
	live, err := alive()
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, vm := range sorted {
		if live[vm] {
			continue
		}
		dir, _ := s.vmDir(vm) // validated above
		if err := os.RemoveAll(dir); err != nil {
			return removed, fmt.Errorf("remove vm state: %w", err)
		}
		removed = append(removed, vm)
	}
	return removed, nil
}

// writeAtomic writes through a uniquely named temp file so two concurrent
// writers cannot clobber each other's temp file; the last rename wins whole.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
