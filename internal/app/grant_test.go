package app

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sovyn-eu/skiff/internal/backend/backendtest"
	"github.com/sovyn-eu/skiff/internal/runner"
	"github.com/sovyn-eu/skiff/internal/vm"
)

// sshScripts answers the scripts skiff streams to a guest: the read
// script (every odd `bash -s` call) gets the given state output. The scripts
// themselves are recovered from the fake runner's captured stdin.
type sshScripts struct {
	state string
	calls int
	fake  *runner.Fake
	// failApply makes the apply script (every even call) fail, as a broken
	// SSH connection would.
	failApply bool
}

func (s *sshScripts) handle(fallback runner.FakeHandler) runner.FakeHandler {
	return func(name string, args []string) ([]byte, error) {
		if name != "ssh" {
			return fallback(name, args)
		}
		if args[len(args)-1] != "-s" {
			return nil, nil // an interactive session or a user command
		}
		s.calls++
		if s.calls%2 == 1 {
			return []byte(s.state), nil
		}
		if s.failApply {
			return nil, errors.New("connection reset")
		}
		return nil, nil
	}
}

// last returns the most recent script streamed to the guest (the fake runner
// keeps one stdin capture per command line, and read and apply share it).
func (s *sshScripts) last() string {
	in, _ := s.fake.Input("bash -s")
	return in
}

// decodeAll decodes every base64 heredoc in a script so tests can look at
// the provisioned content.
func decodeAll(script string) string {
	var out strings.Builder
	lines := strings.Split(script, "\n")
	for i, line := range lines {
		if strings.HasSuffix(line, "<<'SKIFF_B64'") && i+1 < len(lines) {
			if raw, err := base64.StdEncoding.DecodeString(lines[i+1]); err == nil {
				out.Write(raw)
				out.WriteString("\n")
			}
		}
	}
	return out.String()
}

func fakeTunnel(ctx context.Context, name string) (string, func(), error) {
	return "/tmp/fake-" + name + ".sock", func() {}, nil
}

func newGrantApp(t *testing.T, scripts *sshScripts, vms ...vm.Info) (*App, *runner.Fake) {
	t.Helper()
	fake := runner.NewFake(scripts.handle(sshOnly))
	scripts.fake = fake
	app := New(fake, testPaths(t), &strings.Builder{}, WithBackend(backendtest.New()), WithTunnel(fakeTunnel))
	seed(app, vms...)
	return app, fake
}

func TestGrantProvisionsGuestAndPersists(t *testing.T) {
	scripts := &sshScripts{state: "/etc/skiff/manifest\n\n/root/.claude.json\n\n"}
	app, fake := newGrantApp(t, scripts)
	set, err := app.Grant(context.Background(), "agent1", []string{"claude", "github"})
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if strings.Join(set.Caps(), ",") != "claude,github" {
		t.Errorf("grants = %v", set.Caps())
	}
	if scripts.calls != 2 {
		t.Fatalf("expected a read and an apply script, got %d:\n%s", scripts.calls, fake.Dump())
	}
	apply := scripts.last()
	for _, want := range []string{"/root/.claude.json", "/etc/environment", "skiff:github"} {
		if !strings.Contains(apply, want) {
			t.Errorf("apply script should contain %q:\n%s", want, apply)
		}
	}
	decoded := decodeAll(apply)
	for _, want := range []string{`ANTHROPIC_BASE_URL="http://127.0.0.1:7777/claude"`, "CLAUDE_CODE_OAUTH_TOKEN=\"sk-ant-oat01-", `[url "http://127.0.0.1:7777/github/"]`} {
		if !strings.Contains(decoded, want) {
			t.Errorf("apply script should provision %q:\n%s", want, decoded)
		}
	}
	if strings.Contains(apply+decoded, "claude-token") {
		t.Errorf("no secret reference may reach the guest:\n%s", apply)
	}
	again, err := app.Grants("agent1")
	if err != nil || strings.Join(again.Caps(), ",") != "claude,github" {
		t.Errorf("Grants = %v, %v", again, err)
	}
}

func TestGrantIsNotPersistedWhenProvisionFails(t *testing.T) {
	fake := runner.NewFake(func(name string, args []string) ([]byte, error) {
		if name == "ssh" {
			return nil, errors.New("connection refused")
		}
		return sshOnly(name, args)
	})
	app := New(fake, testPaths(t), &strings.Builder{}, WithBackend(backendtest.New()), WithTunnel(fakeTunnel))
	if _, err := app.Grant(context.Background(), "agent1", []string{"claude"}); err == nil {
		t.Fatal("expected provision failure")
	}
	if set, _ := app.Grants("agent1"); len(set) != 0 {
		t.Errorf("failed grant must not be persisted, got %v", set.Caps())
	}
}

func TestGrantValidation(t *testing.T) {
	app, _ := newGrantApp(t, &sshScripts{})
	cases := map[string]string{
		"nope":            "unknown capability",
		"github:org/repo": "have no scopes",
		"github:*":        "have no scopes",
		"ssh-agent:x":     "have no scopes",
		"Bad Grant":       "cap name",
	}
	for spec, want := range cases {
		_, err := app.Grant(context.Background(), "agent1", []string{spec})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Grant(%q): want %q, got %v", spec, want, err)
		}
	}
	if _, err := app.Grant(context.Background(), "Bad", []string{"claude"}); err == nil {
		t.Errorf("invalid VM name must fail")
	}
}

func TestRevokeRemovesAndReprovisions(t *testing.T) {
	scripts := &sshScripts{state: "/etc/skiff/manifest\n\n"}
	app, _ := newGrantApp(t, scripts)
	if _, err := app.Grant(context.Background(), "agent1", []string{"claude", "ssh-agent"}); err != nil {
		t.Fatal(err)
	}
	set, err := app.Revoke(context.Background(), "agent1", []string{"claude"})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if strings.Join(set.Caps(), ",") != "ssh-agent" {
		t.Errorf("grants after revoke = %v", set.Caps())
	}
	if decoded := decodeAll(scripts.last()); strings.Contains(decoded, "ANTHROPIC_BASE_URL") {
		t.Errorf("revoked env must not be written:\n%s", decoded)
	}
	if _, err := app.Revoke(context.Background(), "agent1", []string{"github"}); err == nil || !strings.Contains(err.Error(), "is not granted") {
		t.Errorf("revoking a missing grant should fail, got %v", err)
	}
}

func TestRevokeIsAllOrNothing(t *testing.T) {
	scripts := &sshScripts{state: "/etc/skiff/manifest\n\n"}
	app, _ := newGrantApp(t, scripts)
	if _, err := app.Grant(context.Background(), "agent1", []string{"claude", "github"}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Revoke(context.Background(), "agent1", []string{"github", "gitlab"}); err == nil || !strings.Contains(err.Error(), "gitlab is not granted") {
		t.Errorf("a cap that was never granted should fail, got %v", err)
	}
	if got, _ := app.Grants("agent1"); strings.Join(got.Caps(), ",") != "claude,github" {
		t.Errorf("a failed revoke must not change grants, got %v", got.Caps())
	}
	if _, err := app.Revoke(context.Background(), "agent1", []string{"github:*"}); err == nil || !strings.Contains(err.Error(), "have no scopes") {
		t.Errorf("a scoped revoke should be refused, got %v", err)
	}
	set, err := app.Revoke(context.Background(), "agent1", []string{"github", "github"})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if strings.Join(set.Caps(), ",") != "claude" {
		t.Errorf("grants after revoke = %v", set.Caps())
	}
}

func TestSSHAttachesTunnelOnlyWithGrants(t *testing.T) {
	scripts := &sshScripts{state: "/etc/skiff/manifest\n\n"}
	app, fake := newGrantApp(t, scripts)
	if err := app.SSH(context.Background(), "agent1", nil); err != nil {
		t.Fatalf("SSH: %v", err)
	}
	argv := fake.Argv()
	last := argv[len(argv)-1]
	if strings.Contains(strings.Join(last, " "), "-R") {
		t.Errorf("no tunnel without grants: %v", last)
	}

	if _, err := app.Grant(context.Background(), "agent1", []string{"claude", "ssh-agent"}); err != nil {
		t.Fatal(err)
	}
	if err := app.SSH(context.Background(), "agent1", []string{"uname"}); err != nil {
		t.Fatalf("SSH: %v", err)
	}
	argv = fake.Argv()
	last = argv[len(argv)-1]
	line := strings.Join(last, " ")
	if !strings.Contains(line, "-o ExitOnForwardFailure=yes -R 127.0.0.1:7777:/tmp/fake-agent1.sock") || !strings.Contains(line, " -A ") {
		t.Errorf("expected tunnel and agent forwarding: %v", last)
	}
	if !strings.HasSuffix(line, "agent1.skiff -- uname") {
		t.Errorf("remote command must stay last: %v", last)
	}
}

func TestSSHAgentOnlyNeedsNoBroker(t *testing.T) {
	calls := 0
	app, fake := newGrantApp(t, &sshScripts{state: "/etc/skiff/manifest\n\n"})
	app.tunnel = func(ctx context.Context, name string) (string, func(), error) {
		calls++
		return "", func() {}, nil
	}
	if _, err := app.Grant(context.Background(), "agent1", []string{"ssh-agent"}); err != nil {
		t.Fatal(err)
	}
	if err := app.SSH(context.Background(), "agent1", nil); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Errorf("ssh-agent alone must not start the broker")
	}
	if !strings.Contains(fake.Calls()[len(fake.Calls())-1], " -A ") {
		t.Errorf("agent forwarding missing:\n%s", fake.Dump())
	}
}

func TestNewWithGrantsAndRemoveCleansState(t *testing.T) {
	scripts := &sshScripts{state: "/etc/skiff/manifest\n\n"}
	app, _ := newGrantApp(t, scripts)
	info, err := app.NewVM(context.Background(), vm.Spec{Name: "agent1", VCPUs: 2, MemMiB: 1024, Grants: []string{"claude"}}, nil)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	if strings.Join(info.Grants, ",") != "claude" {
		t.Errorf("info.Grants = %v", info.Grants)
	}
	stateDir := filepath.Join(app.paths.VMsDir(), "agent1")
	if _, err := os.Stat(stateDir); err != nil {
		t.Fatalf("state dir should exist: %v", err)
	}
	if err := app.RemoveVM(context.Background(), "agent1"); err != nil {
		t.Fatalf("RemoveVM: %v", err)
	}
	if _, err := os.Stat(stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("rm must remove host-side state, got %v", err)
	}
}

func TestListIncludesGrants(t *testing.T) {
	app, _ := newGrantApp(t, &sshScripts{state: "/etc/skiff/manifest\n\n"}, vm.Info{Name: "agent1"})
	if _, err := app.Grant(context.Background(), "agent1", []string{"claude"}); err != nil {
		t.Fatal(err)
	}
	vms, err := app.ListVMs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(vms) != 1 || strings.Join(vms[0].Grants, ",") != "claude" {
		t.Errorf("ListVMs = %+v", vms)
	}
}

const interceptCapFile = `name = "cloud"
description = "test cap with an intercept route"
[proxy]
upstream = "https://api.cloud.example"
[proxy.headers]
Authorization = "Bearer {{ secret \"env:CLOUD_TOKEN\" }}"
[[proxy.routes]]
host = "management.cloud.example"
intercept = true
[proxy.routes.headers]
Authorization = "Bearer {{ secret \"env:CLOUD_TOKEN\" }}"
`

func TestGrantInterceptCapInstallsCA(t *testing.T) {
	scripts := &sshScripts{state: "/etc/skiff/manifest\n\n"}
	app, _ := newGrantApp(t, scripts)
	if err := os.MkdirAll(app.paths.CapsDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app.paths.CapsDir(), "cloud.toml"), []byte(interceptCapFile), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Grant(context.Background(), "agent1", []string{"cloud"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	dir, err := app.grantStore().InterceptDir("agent1")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatalf("no CA on the Mac after an intercept grant: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("CA mode = %v", info.Mode().Perm())
	}
	apply := scripts.last()
	decoded := decodeAll(apply)
	for _, want := range []string{"127.77.0.1 management.cloud.example", "BEGIN CERTIFICATE", "ListenStream=127.77.0.1:443"} {
		if !strings.Contains(decoded, want) {
			t.Errorf("apply script should provision %q:\n%s", want, decoded)
		}
	}
	if strings.Contains(apply+decoded, "PRIVATE KEY") {
		t.Fatal("the CA key must never reach the guest")
	}

	// Removing the VM's state takes the CA along.
	if err := app.grantStore().Remove("agent1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.pem")); !os.IsNotExist(err) {
		t.Errorf("CA survived the VM's state: %v", err)
	}
}

func TestGrantWithoutInterceptCreatesNoCA(t *testing.T) {
	scripts := &sshScripts{state: "/etc/skiff/manifest\n\n"}
	app, _ := newGrantApp(t, scripts)
	if _, err := app.Grant(context.Background(), "agent1", []string{"claude"}); err != nil {
		t.Fatal(err)
	}
	dir, err := app.grantStore().InterceptDir("agent1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("a grant without intercept routes created %s: %v", dir, err)
	}
	if strings.Contains(decodeAll(scripts.last()), "127.77.0.1") {
		t.Error("intercept provisioned without an intercept grant")
	}
}

// A grant that grows the CA must keep the old one when the guest cannot be
// updated: the running broker would otherwise present a CA the guest does
// not trust and break routes that worked.
func TestGrantKeepsCAWhenGuestUpdateFails(t *testing.T) {
	scripts := &sshScripts{state: "/etc/skiff/manifest\n\n"}
	app, _ := newGrantApp(t, scripts)
	writeCap := func(name, host string) {
		t.Helper()
		text := strings.ReplaceAll(strings.Replace(interceptCapFile, `name = "cloud"`, `name = "`+name+`"`, 1), "management.cloud.example", host)
		if err := os.MkdirAll(app.paths.CapsDir(), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(app.paths.CapsDir(), name+".toml"), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeCap("cloud", "management.cloud.example")
	writeCap("graph", "graph.cloud.example")
	if _, err := app.Grant(context.Background(), "agent1", []string{"cloud"}); err != nil {
		t.Fatal(err)
	}
	dir, err := app.grantStore().InterceptDir("agent1")
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}

	scripts.failApply = true
	if _, err := app.Grant(context.Background(), "agent1", []string{"graph"}); err == nil {
		t.Fatal("grant succeeded although the guest update failed")
	}
	if after, _ := os.ReadFile(filepath.Join(dir, "ca.pem")); string(after) != string(before) {
		t.Fatal("a failed grant replaced the CA")
	}

	scripts.failApply = false
	if _, err := app.Grant(context.Background(), "agent1", []string{"graph"}); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(decodeAll(scripts.last()), "BEGIN CERTIFICATE"); n != 2 {
		t.Errorf("during the change the guest must trust both CAs, got %d certificates", n)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, "ca.pem")); string(after) == string(before) {
		t.Error("a successful grant did not commit the grown CA")
	}
}
