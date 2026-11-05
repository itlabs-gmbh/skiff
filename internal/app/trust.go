package app

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sovyn-eu/skiff/internal/profile"
)

// trustedFile lists trusted repository profiles, one "<sha256> <path>"
// per line, relative to the skiff home.
const trustedFile = "trusted"

// ErrUntrusted reports a repository profile that has not been trusted in
// its current content.
var ErrUntrusted = errors.New("profile is not trusted")

// untrustedProfile is a repository file that is not trusted as it was read.
type untrustedProfile struct {
	readProfile
	key string
}

// untrustedProfiles checks each file on its own, in the order given.
func (a *App) untrustedProfiles(read []readProfile) ([]untrustedProfile, error) {
	var out []untrustedProfile
	for _, r := range read {
		key, err := trustKey(r.path, r.data)
		if err != nil {
			return nil, err
		}
		ok, err := a.isTrusted(key)
		if err != nil {
			return nil, err
		}
		if !ok {
			out = append(out, untrustedProfile{readProfile: r, key: key})
		}
	}
	return out, nil
}

// untrustedError names every untrusted file and spells out what each would
// do, so the decision is about consequences rather than file names.
func untrustedError(files []untrustedProfile) error {
	named := make([]string, len(files))
	for i, f := range files {
		named[i] = f.path + describeProfile(f.prof)
	}
	it := "it"
	if len(files) > 1 {
		it = "them"
	}
	return fmt.Errorf("%w: %s; read %s with 'skiff profile show --render', then 'skiff profile trust' or --trust, or pass --no-profile", ErrUntrusted, strings.Join(named, "; "), it)
}

// describeProfile lists what a file would do, as " (it ...)", or "".
func describeProfile(p profile.Profile) string {
	var does []string
	if len(p.Grants) > 0 {
		does = append(does, "grants "+strings.Join(p.Grants, ", "))
	}
	if len(p.Machine.Ports) > 0 {
		does = append(does, "forwards ports "+strings.Join(p.Machine.Ports, ", "))
	}
	if len(p.Guest.Packages) > 0 || len(p.Guest.Tools) > 0 || len(p.Skills) > 0 || strings.TrimSpace(p.Guest.Setup) != "" {
		does = append(does, "runs a setup as root in the VM")
	}
	if p.Claude != nil || p.Codex != nil {
		does = append(does, "configures the agents")
	}
	if len(does) == 0 {
		return ""
	}
	return " (it " + strings.Join(does, ", ") + ")"
}

// trustKey identifies a file by its absolute path and the content it was
// read with, so what is checked is what gets applied. The path is quoted,
// so a directory name with a line break cannot forge a second record.
func trustKey(path string, data []byte) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) + " " + strconv.Quote(abs), nil
}

func (a *App) trustedPath() string { return filepath.Join(a.paths.Home, trustedFile) }

// isTrusted reports whether a trust key is on record.
func (a *App) isTrusted(key string) (bool, error) {
	f, err := os.Open(a.trustedPath())
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read trusted profiles: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == key {
			return true, nil
		}
	}
	if err := sc.Err(); err != nil {
		return false, fmt.Errorf("read trusted profiles: %w", err)
	}
	return false, nil
}

// ProfileTrust validates the file and records its content as trusted.
func (a *App) ProfileTrust(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read profile: %w", err)
	}
	if _, err := profile.Parse(string(data), path); err != nil {
		return err
	}
	key, err := trustKey(path, data)
	if err != nil {
		return err
	}
	ok, err := a.isTrusted(key)
	if err != nil {
		return err
	}
	if ok {
		a.printf("%s is already trusted\n", path)
		return nil
	}
	if err := a.recordTrust(key); err != nil {
		return err
	}
	a.printf("trusted %s (until it changes)\n", path)
	return nil
}

// recordTrust appends a trust key to the record.
func (a *App) recordTrust(key string) error {
	if err := os.MkdirAll(a.paths.Home, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", a.paths.Home, err)
	}
	f, err := os.OpenFile(a.trustedPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("record trust: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(key + "\n"); err != nil {
		return fmt.Errorf("record trust: %w", err)
	}
	return nil
}
