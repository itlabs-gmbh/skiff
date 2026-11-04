package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sovyn-eu/skiff/internal/backend/backendtest"
	"github.com/sovyn-eu/skiff/internal/broker"
	"github.com/sovyn-eu/skiff/internal/profile"
	"github.com/sovyn-eu/skiff/internal/runner"
	"github.com/sovyn-eu/skiff/internal/vm"
)

const repoProfile = `
grants = ["claude"]
skills = ["anthropics/skills/skills/pdf"]
[machine]
vcpus = 4
[guest]
packages = ["jq"]
[claude]
plugins = ["frontend-design@claude-plugins-official"]
[claude.mcp.context7]
type = "http"
url = "https://mcp.context7.com/mcp"
[codex.config]
approval_policy = "never"
`

func writeFile(t *testing.T, path, text string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolveProfileMergesDefaultAndRepo(t *testing.T) {
	app, _ := newGrantApp(t, &sshScripts{})
	p, err := app.ResolveProfile(filepath.Join(t.TempDir(), ".skiff"), false)
	if err != nil || !p.IsZero() {
		t.Fatalf("no files: want zero profile, got %+v, %v", p, err)
	}
	writeFile(t, app.paths.ProfilePath(), "grants = [\"github\"]\n[machine]\nmem = 2048\n[guest]\ntools = [\"claude\"]\n")
	repo := writeFile(t, filepath.Join(t.TempDir(), ".skiff"), repoProfile)
	p, err = app.ResolveProfile(repo, true)
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	if got := strings.Join(p.Grants, ","); got != "github,claude" {
		t.Errorf("grants: %s", got)
	}
	if p.Machine.VCPUs != 4 || p.Machine.MemMiB != 2048 || len(p.Guest.Tools) != 1 || len(p.Sources) != 2 {
		t.Errorf("merge: %+v", p)
	}
	if _, err := app.ResolveProfile(filepath.Join(t.TempDir(), "missing"), true); err == nil {
		t.Error("an explicitly named file must exist")
	}
	if p, err := app.ResolveProfile(filepath.Join(t.TempDir(), "missing"), false); err != nil || len(p.Sources) != 1 {
		t.Errorf("a missing .skiff is skipped: %+v, %v", p.Sources, err)
	}
	writeFile(t, repo, "[machine]\nvcpus = 99\n")
	if _, err := app.ResolveProfile(repo, true); err == nil {
		t.Error("a broken repository file is an error, not ignored")
	}
}

func TestResolveTrustedProfileRequiresTrust(t *testing.T) {
	app, out := newTestAppOut(t)
	writeFile(t, app.paths.ProfilePath(), "grants = [\"github\"]\n")
	repo := writeFile(t, filepath.Join(t.TempDir(), ".skiff"), repoProfile)
	// The machine default alone needs no trust.
	if _, err := app.ResolveTrustedProfile(filepath.Join(t.TempDir(), "none"), false, false); err != nil {
		t.Errorf("default only: %v", err)
	}
	_, err := app.ResolveTrustedProfile(repo, false, false)
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("want ErrUntrusted, got %v", err)
	}
	for _, want := range []string{"grants github, claude", "runs a setup as root", "configures the agents", "skiff profile trust"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should say what the file does (%q): %v", want, err)
		}
	}
	if err := app.ProfileTrust(repo); err != nil {
		t.Fatalf("ProfileTrust: %v", err)
	}
	if !strings.Contains(out.String(), "trusted "+repo) {
		t.Errorf("output: %s", out.String())
	}
	if p, err := app.ResolveTrustedProfile(repo, false, false); err != nil || len(p.Sources) != 2 {
		t.Errorf("after trust: %v, %v", p.Sources, err)
	}
	if err := app.ProfileTrust(repo); err != nil || !strings.Contains(out.String(), "already trusted") {
		t.Errorf("trusting twice: %v\n%s", err, out.String())
	}
	// An edit withdraws the trust; --trust records the new content.
	writeFile(t, repo, repoProfile+"\n[guest.env]\nX = \"1\"\n")
	if _, err := app.ResolveTrustedProfile(repo, false, false); !errors.Is(err, ErrUntrusted) {
		t.Errorf("edited file must be untrusted again, got %v", err)
	}
	if _, err := app.ResolveTrustedProfile(repo, false, true); err != nil {
		t.Errorf("--trust: %v", err)
	}
	if _, err := app.ResolveTrustedProfile(repo, false, false); err != nil {
		t.Errorf("--trust must record the file: %v", err)
	}
	if err := app.ProfileTrust(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("trusting a missing file must fail")
	}
}

func TestApplyRefusesZeroProfile(t *testing.T) {
	app, _ := newGrantApp(t, &sshScripts{}, vm.Info{Name: "agent1"})
	if _, err := app.Apply(context.Background(), "agent1", profile.Profile{}, nil, false); err == nil || !strings.Contains(err.Error(), "nothing to apply") {
		t.Errorf("want nothing-to-apply error, got %v", err)
	}
}

func TestProfileShowRenderLeavesNoState(t *testing.T) {
	app, _ := newTestAppOut(t)
	repo := writeFile(t, filepath.Join(t.TempDir(), ".skiff"), repoProfile)
	if err := app.ProfileShow(repo, true, "", true); err != nil {
		t.Fatalf("ProfileShow: %v", err)
	}
	if names, _ := app.grantStore().Names(); len(names) != 0 {
		t.Errorf("a preview must not create VM state, got %v", names)
	}
}

func TestNewAppliesProfile(t *testing.T) {
	scripts := &sshScripts{state: "/etc/skiff/manifest\n\n/root/.claude.json\n\n"}
	app, fake := newGrantApp(t, scripts)
	p, err := profile.Parse(repoProfile, ".skiff")
	if err != nil {
		t.Fatal(err)
	}
	info, err := app.NewVM(context.Background(), vm.Spec{Name: "agent1", VCPUs: 4, MemMiB: 1024, Grants: []string{"github"}}, &p)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	if got := strings.Join(info.Grants, ","); got != "claude,github" {
		t.Errorf("grants from profile and flags: %s", got)
	}
	inputs := fake.Inputs("bash -s")
	if len(inputs) != 3 {
		t.Fatalf("expected setup, read and apply scripts, got %d:\n%s", len(inputs), fake.Dump())
	}
	setup := inputs[0]
	for _, want := range []string{"apt-get install", "'jq'", "git clone", "/root/.claude/skills/pdf"} {
		if !strings.Contains(setup, want) {
			t.Errorf("setup script lacks %q:\n%s", want, setup)
		}
	}
	decoded := decodeAll(inputs[2])
	for _, want := range []string{
		profile.ClaudeSettingsFile, `"frontend-design@claude-plugins-official": true`,
		`ANTHROPIC_BASE_URL="http://127.0.0.1:7777/claude"`, `CLAUDE_CODE_SYNC_PLUGIN_INSTALL="1"`,
		"mcp.context7", "approval_policy = \"never\"", profile.CodexConfigFile, "skiff:github",
	} {
		if !strings.Contains(decoded+inputs[2], want) {
			t.Errorf("apply script lacks %q:\n%s", want, decoded)
		}
	}
	stored, err := app.storedProfile("agent1")
	if err != nil || stored == nil || len(stored.Claude.Plugins) != 1 {
		t.Errorf("profile must be stored with the VM: %+v, %v", stored, err)
	}
	// A later grant keeps the profile's configuration in the guest.
	fake.Reset()
	if _, err := app.Grant(context.Background(), "agent1", []string{"ssh-agent"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	inputs = fake.Inputs("bash -s")
	if len(inputs) != 2 || !strings.Contains(decodeAll(inputs[1]), `"frontend-design@claude-plugins-official": true`) {
		t.Errorf("grant must re-apply the stored profile:\n%s", fake.Dump())
	}
}

func TestNewWithZeroProfileBehavesAsBefore(t *testing.T) {
	scripts := &sshScripts{}
	app, fake := newGrantApp(t, scripts)
	empty := profile.Profile{}
	if _, err := app.NewVM(context.Background(), vm.Spec{Name: "plain", VCPUs: 2, MemMiB: 1024}, &empty); err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	if fake.CalledWithSuffix("bash -s") {
		t.Errorf("nothing to apply, nothing should reach the guest:\n%s", fake.Dump())
	}
	if stored, _ := app.storedProfile("plain"); stored != nil {
		t.Error("no profile should be stored")
	}
}

func TestApplyWithoutSetupSkipsInstalls(t *testing.T) {
	scripts := &sshScripts{state: "/etc/skiff/manifest\n\n"}
	app, fake := newGrantApp(t, scripts, vm.Info{Name: "agent1"})
	p, _ := profile.Parse("[guest]\npackages = [\"jq\"]\n[claude]\nplugins = [\"a@claude-plugins-official\"]\n", ".skiff")
	set, err := app.Apply(context.Background(), "agent1", p, nil, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(set) != 0 {
		t.Errorf("no grants expected, got %v", set.Caps())
	}
	inputs := fake.Inputs("bash -s")
	if len(inputs) != 2 || strings.Contains(inputs[0], "apt-get") || strings.Contains(inputs[0], "skiff_setup") {
		t.Errorf("expected read and apply only:\n%s", fake.Dump())
	}
	if strings.Contains(inputs[1], "skiff-broker") {
		t.Errorf("a profile without grants needs no relay:\n%s", inputs[1])
	}
}

func TestApplyRejectsUnknownGrantBeforeTouchingTheGuest(t *testing.T) {
	app, fake := newGrantApp(t, &sshScripts{}, vm.Info{Name: "agent1"})
	p, _ := profile.Parse("grants = [\"nope\"]\n", ".skiff")
	if _, err := app.Apply(context.Background(), "agent1", p, nil, true); err == nil || !strings.Contains(err.Error(), "unknown capability") {
		t.Fatalf("want unknown capability, got %v", err)
	}
	if fake.CalledWithSuffix("bash -s") {
		t.Errorf("nothing should reach the guest:\n%s", fake.Dump())
	}
}

func TestApplyStoresNothingWhenSetupFails(t *testing.T) {
	fake := runner.NewFake(func(name string, args []string) ([]byte, error) {
		if name == "ssh" {
			return nil, errors.New("apt failed")
		}
		return sshOnly(name, args)
	})
	app := New(fake, testPaths(t), &strings.Builder{}, WithBackend(backendtest.New()), WithTunnel(fakeTunnel))
	seed(app, vm.Info{Name: "agent1"})
	p, _ := profile.Parse("grants = [\"claude\"]\n[guest]\npackages = [\"jq\"]\n", ".skiff")
	if _, err := app.Apply(context.Background(), "agent1", p, nil, true); err == nil || !strings.Contains(err.Error(), "setup of agent1 failed") {
		t.Fatalf("want setup failure, got %v", err)
	}
	if set, _ := app.Grants("agent1"); len(set) != 0 {
		t.Errorf("grants must not be persisted: %v", set.Caps())
	}
	if stored, _ := app.storedProfile("agent1"); stored != nil {
		t.Error("profile must not be stored")
	}
}

func TestProfileShowInitLint(t *testing.T) {
	app, out := newTestAppOut(t)
	dir := t.TempDir()
	repo := filepath.Join(dir, ".skiff")
	if err := app.ProfileShow(repo, false, "", false); err != nil || !strings.Contains(out.String(), "no profile") {
		t.Errorf("show without files: %v\n%s", err, out.String())
	}
	if err := app.ProfileInit(repo, false); err != nil {
		t.Fatalf("ProfileInit: %v", err)
	}
	if err := app.ProfileInit(repo, false); err == nil {
		t.Error("init must not overwrite")
	}
	if err := app.ProfileInit("", true); err != nil {
		t.Fatalf("ProfileInit --global: %v", err)
	}
	if _, err := os.Stat(app.paths.ProfilePath()); err != nil {
		t.Errorf("global skeleton missing: %v", err)
	}
	out.Reset()
	if err := app.ProfileLint("", repo); err != nil || !strings.Contains(out.String(), "ok") {
		t.Errorf("lint of skeletons: %v\n%s", err, out.String())
	}
	writeFile(t, repo, repoProfile)
	out.Reset()
	if err := app.ProfileShow(repo, true, "", true); err != nil {
		t.Fatalf("ProfileShow --render: %v", err)
	}
	for _, want := range []string{"# sources:", "vcpus = 4", "grants claude", "file " + profile.ClaudeSettingsFile, "json /root/.claude.json mcpServers.context7", "file /root/.codex/config.toml", "setup script:", "apt-get install"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("rendered show lacks %q:\n%s", want, out.String())
		}
	}
	if err := app.ProfileLint(repo, ""); err != nil {
		t.Errorf("lint file: %v", err)
	}
	writeFile(t, repo, "[machine]\nmem = 1\n")
	if err := app.ProfileLint(repo, ""); err == nil {
		t.Error("lint must report the broken file")
	}
	if err := app.ProfileShow("", false, "nobody", false); err == nil || !strings.Contains(err.Error(), "no profile has been applied") {
		t.Errorf("show --vm without a stored profile: %v", err)
	}
}

func newTestAppOut(t *testing.T) (*App, *strings.Builder) {
	t.Helper()
	out := &strings.Builder{}
	return New(runner.NewFake(sshOnly), testPaths(t), out, WithBackend(backendtest.New()), WithTunnel(fakeTunnel)), out
}

func TestSetupRefusedWhileABrokerIsOwned(t *testing.T) {
	app, fake := newGrantApp(t, &sshScripts{}, vm.Info{Name: "agent1"})
	release, err := broker.Claim(app.paths.SocketPath("agent1"))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	p, _ := profile.Parse("[guest]\npackages = [\"jq\"]\n", ".skiff")
	_, err = app.Apply(context.Background(), "agent1", p, nil, true)
	if err == nil || !strings.Contains(err.Error(), "open session, tunnel or setup") {
		t.Fatalf("want refusal while the broker is owned, got %v", err)
	}
	if fake.CalledWithSuffix("bash -s") {
		t.Errorf("nothing should reach the guest:\n%s", fake.Dump())
	}
}

func TestApplyChecksConflictsBeforeSetup(t *testing.T) {
	app, fake := newGrantApp(t, &sshScripts{}, vm.Info{Name: "agent1"})
	p, _ := profile.Parse("grants = [\"claude\"]\n[guest]\npackages = [\"jq\"]\n[guest.env]\nANTHROPIC_BASE_URL = \"http://x\"\n", ".skiff")
	_, err := app.Apply(context.Background(), "agent1", p, nil, true)
	if err == nil || !strings.Contains(err.Error(), "ANTHROPIC_BASE_URL") {
		t.Fatalf("want the env clash, got %v", err)
	}
	if fake.CalledWithSuffix("bash -s") {
		t.Errorf("the clash must be found before the setup runs:\n%s", fake.Dump())
	}
}

func TestResolveProfileValidatesTheDefaultAlone(t *testing.T) {
	app, _ := newGrantApp(t, &sshScripts{})
	writeFile(t, app.paths.ProfilePath(), "[claude]\nplugins = [\"x@missing\"]\n")
	if _, err := app.ResolveProfile(filepath.Join(t.TempDir(), "none"), false); err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Errorf("the default alone must be validated as a whole, got %v", err)
	}
}
