package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sovyn-eu/skiff/internal/app"
	"github.com/sovyn-eu/skiff/internal/backend/backendtest"
	"github.com/sovyn-eu/skiff/internal/runner"
)

const cliProfile = `
grants = ["claude"]
[machine]
vcpus = 4
mem = 4096
ports = ["3000"]
[claude]
plugins = ["frontend-design@claude-plugins-official"]
`

func writeProfile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".skiff")
	if err := os.WriteFile(path, []byte(cliProfile), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// runNew runs `skiff new` with port forwards stubbed so no real port is probed.
func runNew(t *testing.T, args ...string) (string, *backendtest.Fake, *runner.Fake, error) {
	t.Helper()
	fake := runner.NewFake(fakeHandler(t))
	fb := backendtest.New()
	buf := &bytes.Buffer{}
	root := newRoot(builder(fake, fb, t.TempDir(),
		app.WithPortProbe(func(context.Context, int) bool { return true }),
		app.WithPortCheck(func(int) bool { return false })))
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(append([]string{"new"}, args...))
	err := root.Execute()
	return buf.String(), fb, fake, err
}

func TestNewTakesSizeAndGrantsFromProfile(t *testing.T) {
	path := writeProfile(t)
	if _, _, _, err := runNew(t, "box", "--profile", path); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("an untrusted repository file must be refused, got %v", err)
	}
	out, fb, fake, err := runNew(t, "box", "--profile", path, "--trust", "--vcpus", "1", "--port", "8080")
	if err != nil {
		t.Fatalf("new: %v\n%s", err, out)
	}
	if !strings.Contains(out, "applying profile "+path) || !strings.Contains(out, "box may now use: claude") {
		t.Errorf("output:\n%s", out)
	}
	if !fake.CalledWithSuffix("box.skiff -- bash -s") {
		t.Errorf("guest should have been configured:\n%s", fake.Dump())
	}
	// --vcpus wins over the profile, mem and ports come from it.
	if !fb.Called("create box 1 4096") || !fb.Called("forward box 8080:8080 3000:3000") {
		t.Errorf("backend calls:\n%s", fb.Dump())
	}
}

func TestNewWithMissingExplicitProfileFails(t *testing.T) {
	if _, _, err := run(t, "new", "box", "--profile", filepath.Join(t.TempDir(), "none")); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("want missing-file error, got %v", err)
	}
	if out, _, err := run(t, "new", "box", "--no-profile"); err != nil {
		t.Errorf("--no-profile: %v\n%s", err, out)
	}
}

func TestApplyAndProfileCommands(t *testing.T) {
	home := t.TempDir()
	path := writeProfile(t)
	if out, _, err := runIn(t, home, "", "apply", "vm1", "--profile", path); err == nil {
		t.Fatalf("apply must refuse an untrusted file:\n%s", out)
	}
	out, _, err := runIn(t, home, "", "profile", "trust", path)
	if err != nil || !strings.Contains(out, "trusted "+path) {
		t.Fatalf("profile trust: %v\n%s", err, out)
	}
	out, fake, err := runIn(t, home, "", "apply", "vm1", "--profile", path, "--setup")
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	if !strings.Contains(out, "vm1 may now use: claude") || !fake.CalledWithSuffix("vm1.skiff -- bash -s") {
		t.Errorf("apply output:\n%s\n%s", out, fake.Dump())
	}
	out, _, err = runIn(t, home, "", "apply", "vm1", "--profile", path, "--grant", "github")
	if err != nil || !strings.Contains(out, "vm1 may now use: claude, github") {
		t.Errorf("apply --grant: %v\n%s", err, out)
	}
	out, _, err = runIn(t, home, "", "profile", "show", "--vm", "vm1", "--render")
	if err != nil || !strings.Contains(out, "vcpus = 4") || !strings.Contains(out, "enabledPlugins") {
		t.Errorf("profile show --vm: %v\n%s", err, out)
	}
	out, _, err = runIn(t, home, "", "profile", "show", "--profile", path)
	if err != nil || !strings.Contains(out, "# sources: "+path) {
		t.Errorf("profile show: %v\n%s", err, out)
	}
	out, _, err = runIn(t, home, "", "profile", "lint", path)
	if err != nil || !strings.Contains(out, "ok") {
		t.Errorf("profile lint: %v\n%s", err, out)
	}
	target := filepath.Join(t.TempDir(), ".skiff")
	out, _, err = runIn(t, home, "", "profile", "init", target)
	if err != nil || !strings.Contains(out, "wrote "+target) {
		t.Errorf("profile init: %v\n%s", err, out)
	}
	if _, err := os.Stat(target); err != nil {
		t.Errorf("skeleton not written: %v", err)
	}
	if _, _, err := runIn(t, home, "", "apply", "vm1", "--no-profile"); err == nil || !strings.Contains(err.Error(), "nothing to apply") {
		t.Errorf("apply without any profile must refuse, got %v", err)
	}
	if _, _, err := runIn(t, home, "", "apply", "vm1", "--clear", "--setup"); err == nil {
		t.Error("--clear and --setup are exclusive")
	}
	out, _, err = runIn(t, home, "", "apply", "vm1", "--clear")
	if err != nil || !strings.Contains(out, "no longer has a profile") {
		t.Errorf("apply --clear: %v\n%s", err, out)
	}
}

func TestNewNamesTheApplyRetryWithTheSameProfileWhenSetupFails(t *testing.T) {
	path := writeProfile(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"explicit file", []string{"--profile", path, "--trust", "--grant", "github"},
			"skiff apply box --setup --profile " + path + " --grant github"},
		{"default file", []string{"--grant", "github"}, "skiff apply box --setup --grant github"},
		{"machine default only", []string{"--no-profile"}, "skiff apply box --setup --no-profile"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			if err := os.WriteFile(filepath.Join(home, "profile.toml"), []byte("[guest]\npackages = [\"jq\"]\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			fake := runner.NewFake(func(name string, args []string) ([]byte, error) {
				if name == "ssh" {
					return nil, errors.New("apt failed")
				}
				return fakeHandler(t)(name, args)
			})
			root := newRoot(builder(fake, backendtest.New(), home,
				app.WithPortProbe(func(context.Context, int) bool { return true }),
				app.WithPortCheck(func(int) bool { return false })))
			buf := &bytes.Buffer{}
			root.SetOut(buf)
			root.SetErr(buf)
			root.SetArgs(append([]string{"new", "box"}, tc.args...))
			err := root.Execute()
			if err == nil || !strings.Contains(err.Error(), "setup of box failed") {
				t.Fatalf("want setup failure, got %v\n%s", err, buf.String())
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error must name %q, got %v", tc.want, err)
			}
		})
	}
}
