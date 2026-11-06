package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sovyn-eu/skiff/internal/app"
	"github.com/sovyn-eu/skiff/internal/runner"
)

// runIn executes several commands against one state directory.
func runIn(t *testing.T, home string, stdin string, args ...string) (string, *runner.Fake, error) {
	t.Helper()
	fake := runner.NewFake(fakeHandler(t))
	buf := &bytes.Buffer{}
	tunnel := func(ctx contextT, name string) (app.Forwards, func(), error) {
		return app.Forwards{Broker: "/tmp/t.sock"}, func() {}, nil
	}
	root := newRoot(builder(fake, seededBackend(), home, app.WithTunnel(tunnel)))
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), fake, err
}

func TestGrantRevokeGrantsFlow(t *testing.T) {
	home := t.TempDir()
	out, fake, err := runIn(t, home, "", "grant", "vm1", "claude", "github")
	if err != nil {
		t.Fatalf("grant: %v\n%s", err, out)
	}
	if !strings.Contains(out, "vm1 may now use: claude, github") {
		t.Errorf("output:\n%s", out)
	}
	if !fake.CalledWithSuffix("vm1.skiff -- bash -s") {
		t.Errorf("guest should have been provisioned:\n%s", fake.Dump())
	}
	out, _, err = runIn(t, home, "", "grants", "vm1")
	if err != nil || out != "claude\ngithub\n" {
		t.Errorf("grants: %q, %v", out, err)
	}
	out, _, err = runIn(t, home, "", "revoke", "vm1", "claude")
	if err != nil || !strings.Contains(out, "may still use: github") {
		t.Errorf("revoke: %q, %v", out, err)
	}
	out, _, err = runIn(t, home, "", "grants", "vm2")
	if err != nil || out != "vm2 has no grants\n" {
		t.Errorf("grants of unknown vm: %q, %v", out, err)
	}
	if _, _, err := runIn(t, home, "", "grant", "vm1", "bogus"); err == nil {
		t.Errorf("unknown cap must fail")
	}
}

func TestSSHUsesTunnelAfterGrant(t *testing.T) {
	home := t.TempDir()
	if _, _, err := runIn(t, home, "", "grant", "vm1", "claude"); err != nil {
		t.Fatal(err)
	}
	_, fake, err := runIn(t, home, "", "ssh", "vm1")
	if err != nil {
		t.Fatal(err)
	}
	if !fake.CalledWithSuffix("-R 127.0.0.1:7777:/tmp/t.sock -F " + filepath.Join(home, "ssh_config") + " vm1.skiff") {
		t.Errorf("tunnel missing:\n%s", fake.Dump())
	}
}

func TestNewWithGrantAndLsShowsGrants(t *testing.T) {
	home := t.TempDir()
	out, _, err := runIn(t, home, "", "new", "box", "--grant", "claude")
	if err != nil {
		t.Fatalf("new: %v\n%s", err, out)
	}
	if !strings.Contains(out, "box may now use: claude") {
		t.Errorf("output:\n%s", out)
	}
	out, _, err = runIn(t, home, "", "grant", "vm1", "ssh-agent")
	if err != nil {
		t.Fatal(err)
	}
	out, _, err = runIn(t, home, "", "ls")
	if err != nil || !strings.Contains(out, "GRANTS") || !strings.Contains(out, "ssh-agent") {
		t.Errorf("ls: %v\n%s", err, out)
	}
}

func TestCapCommands(t *testing.T) {
	home := t.TempDir()
	out, _, err := runIn(t, home, "", "cap", "ls")
	if err != nil || !strings.Contains(out, "claude") || !strings.Contains(out, "github") {
		t.Errorf("cap ls: %v\n%s", err, out)
	}
	out, _, err = runIn(t, home, "", "cap", "show", "claude")
	if err != nil || !strings.Contains(out, "api.anthropic.com") {
		t.Errorf("cap show: %v\n%s", err, out)
	}
	out, _, err = runIn(t, home, "", "cap", "show", "claude", "--render", "--vm", "vm1")
	if err != nil || !strings.Contains(out, "env ANTHROPIC_BASE_URL=http://127.0.0.1:7777/claude") {
		t.Errorf("cap show --render: %v\n%s", err, out)
	}
	out, _, err = runIn(t, home, "", "cap", "init", "mine")
	if err != nil || !strings.Contains(out, "wrote") {
		t.Errorf("cap init: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(home, "caps", "mine.toml")); err != nil {
		t.Errorf("skeleton missing: %v", err)
	}
	out, _, err = runIn(t, home, "", "cap", "lint")
	if err != nil || !strings.Contains(out, "1 user capabilities") {
		t.Errorf("cap lint: %v\n%s", err, out)
	}
	if _, _, err := runIn(t, home, "", "cap", "add", "http://nope"); err == nil {
		t.Errorf("cap add must insist on https")
	}
}

func TestSecretCommandsReadStdin(t *testing.T) {
	home := t.TempDir()
	out, fake, err := runIn(t, home, "s3cret\n", "secret", "set", "claude-token")
	if err != nil {
		t.Fatalf("secret set: %v\n%s", err, out)
	}
	if in, ok := fake.Input("security -i"); !ok || !strings.Contains(in, `-a claude-token -w "s3cret"`) {
		t.Errorf("secret should be piped to security -i, got %q", in)
	}
	if _, _, err := runIn(t, home, "\n", "secret", "set", "claude-token"); err == nil {
		t.Errorf("empty secret must fail")
	}
	out, fake, err = runIn(t, home, "", "secret", "rm", "claude-token")
	if err != nil || !fake.Called("security delete-generic-password -s skiff -a claude-token") {
		t.Errorf("secret rm: %v\n%s", err, fake.Dump())
	}
}
