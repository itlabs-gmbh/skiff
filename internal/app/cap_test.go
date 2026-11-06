package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sovyn-eu/skiff/internal/backend/backendtest"
	"github.com/sovyn-eu/skiff/internal/broker"
	"github.com/sovyn-eu/skiff/internal/config"
	"github.com/sovyn-eu/skiff/internal/runner"
)

func newCapApp(t *testing.T) (*App, *strings.Builder, *runner.Fake) {
	t.Helper()
	fake := runner.NewFake(func(name string, args []string) ([]byte, error) { return nil, nil })
	out := &strings.Builder{}
	return New(fake, testPaths(t), out, WithBackend(backendtest.New()), WithTunnel(fakeTunnel)), out, fake
}

func TestCapListShowsEmbeddedAndBuiltIn(t *testing.T) {
	app, out, _ := newCapApp(t)
	if err := app.CapList(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"claude", "github", "embedded", "ssh-agent", "built-in"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
}

func TestCapShowSourceAndRender(t *testing.T) {
	app, out, _ := newCapApp(t)
	if err := app.CapShow("claude", false, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "upstream = \"https://api.anthropic.com\"") {
		t.Errorf("source not shown:\n%s", out.String())
	}
	out.Reset()
	if err := app.CapShow("github", true, "agent1"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "block /etc/gitconfig") || !strings.Contains(out.String(), "http://127.0.0.1:7777/github/") {
		t.Errorf("render not shown:\n%s", out.String())
	}
	if err := app.CapShow("nope", false, ""); err == nil {
		t.Errorf("unknown cap must fail")
	}
}

func TestCapInitAndLint(t *testing.T) {
	app, out, _ := newCapApp(t)
	if err := app.CapInit("mything"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(app.paths.CapsDir(), "mything.toml")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("skeleton not written: %v", err)
	}
	if err := app.CapInit("mything"); err == nil {
		t.Errorf("init must not overwrite")
	}
	if err := app.CapLint("mything"); err != nil {
		t.Errorf("skeleton should lint clean: %v", err)
	}
	if err := app.CapLint(""); err != nil || !strings.Contains(out.String(), "1 user capabilities") {
		t.Errorf("lint all: %v\n%s", err, out.String())
	}
	_ = os.WriteFile(path, []byte("name = \"mything\"\n"), 0o600)
	if err := app.CapLint("mything"); err == nil {
		t.Errorf("broken file must fail lint")
	}
	if err := app.CapLint(""); err == nil {
		t.Errorf("broken user file must fail Load")
	}
}

func TestCapAddDownloadsAndInstalls(t *testing.T) {
	body := "name = \"remote\"\n[proxy]\nupstream = \"https://x.example\"\n[proxy.headers]\nAuthorization = \"Bearer {{ secret \\\"keychain:skiff/claude-token\\\" }}\"\n"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bad":
			_, _ = w.Write([]byte("name = ["))
		case "/claude.toml":
			_, _ = w.Write([]byte(strings.Replace(body, `"remote"`, `"claude"`, 1)))
		default:
			_, _ = w.Write([]byte(body))
		}
	}))
	defer srv.Close()
	http.DefaultClient = srv.Client()
	defer func() { http.DefaultClient = &http.Client{} }()

	app, out, _ := newCapApp(t)
	if err := app.CapAdd(context.Background(), "http://insecure", true, strings.NewReader("")); err == nil {
		t.Errorf("http URLs must be rejected")
	}
	if err := app.CapAdd(context.Background(), srv.URL+"/bad", true, strings.NewReader("")); err == nil {
		t.Errorf("invalid downloads must be rejected")
	}
	if err := app.CapAdd(context.Background(), srv.URL+"/claude.toml", true, strings.NewReader("")); err == nil || !strings.Contains(err.Error(), "embedded capability") {
		t.Errorf("downloads must not shadow embedded caps, got %v", err)
	}
	if err := app.CapAdd(context.Background(), srv.URL+"/remote.toml", false, strings.NewReader("n\n")); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Errorf("declining must not install, got %v", err)
	}
	if !strings.Contains(out.String(), "sends the secret keychain:skiff/claude-token in the Authorization header") ||
		!strings.Contains(out.String(), "proxies guest requests to https://x.example") {
		t.Errorf("confirmation should spell out the consequences:\n%s", out.String())
	}
	if err := app.CapAdd(context.Background(), srv.URL+"/remote.toml", false, strings.NewReader("y\n")); err != nil {
		t.Fatalf("CapAdd: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(app.paths.CapsDir(), "remote.toml"))
	if err != nil || string(data) != body {
		t.Errorf("installed file = %q, %v", data, err)
	}
	if !strings.Contains(out.String(), "skiff grant <vm> remote") {
		t.Errorf("hint missing:\n%s", out.String())
	}
}

func TestSecretRefsListLiteralReferences(t *testing.T) {
	cases := map[string][]string{
		`Bearer {{ secret "keychain:skiff/a" }}`:    {"keychain:skiff/a"},
		"Bearer {{ secret `keychain:skiff/b` }}":    {"keychain:skiff/b"},
		`{{ secret "env:D" }} {{ secret "env:E" }}`: {"env:D", "env:E"},
		`plain`: nil,
	}
	for tmpl, want := range cases {
		if got := secretRefs(tmpl); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("secretRefs(%q) = %v, want %v", tmpl, got, want)
		}
	}
}

func TestStripControlRemovesHiddenCharacters(t *testing.T) {
	in := "ok\x1b[2Khidden\u202ereversed\u200bzero\u0085c1\ttab\nline"
	got := stripControl(in)
	for _, bad := range []string{"\x1b", "\u202e", "\u200b", "\u0085"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q survived: %q", bad, got)
		}
	}
	if !strings.Contains(got, "\ttab\nline") {
		t.Errorf("tab and newline must survive: %q", got)
	}
}

func TestSecretSetAndRemove(t *testing.T) {
	app, out, fake := newCapApp(t)
	if err := app.SecretSet(context.Background(), "claude-token", "value"); err != nil {
		t.Fatal(err)
	}
	if in, ok := fake.Input("security -i"); !ok || !strings.Contains(in, "-a claude-token -w \"value\"") {
		t.Errorf("secret should go to security -i via stdin, got %q:\n%s", in, fake.Dump())
	}
	if !strings.Contains(out.String(), "keychain:skiff/claude-token") {
		t.Errorf("output:\n%s", out.String())
	}
	if err := app.SecretSet(context.Background(), "Bad Name", "v"); err == nil {
		t.Errorf("invalid names must fail")
	}
	if err := app.SecretRemove(context.Background(), "claude-token"); err != nil {
		t.Fatal(err)
	}
	if !fake.Called("security delete-generic-password -s skiff -a claude-token") {
		t.Errorf("unexpected calls:\n%s", fake.Dump())
	}
}

func TestStartBrokerServesSocket(t *testing.T) {
	fake := runner.NewFake(func(name string, args []string) ([]byte, error) { return nil, errors.New("no") })
	dir, err := os.MkdirTemp("/tmp", "skiff-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	app := New(fake, config.Paths{Home: dir}, &strings.Builder{}, WithBackend(backendtest.New()))
	if err := app.grantStore().Save("agent1", nil); err != nil {
		t.Fatal(err)
	}
	fwd, stop, err := app.startBroker(context.Background(), "agent1")
	if err != nil {
		t.Fatalf("startBroker: %v", err)
	}
	socket := fwd.Broker
	if socket != app.paths.SocketPath("agent1") || len(fwd.TCP) != 0 {
		t.Errorf("forwards = %+v", fwd)
	}
	if _, _, err := app.startBroker(context.Background(), "agent1"); !errors.Is(err, broker.ErrBusy) {
		t.Errorf("a second start must find the broker owned, got %v", err)
	}
	stop()
	if _, err := os.Stat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stop should remove the socket, got %v", err)
	}
	_, stopAgain, err := app.startBroker(context.Background(), "agent1")
	if err != nil {
		t.Fatalf("start after stop: %v", err)
	}
	stopAgain()
	if _, err := os.Stat(app.paths.AuditLog()); err != nil {
		t.Errorf("audit log should be created: %v", err)
	}
}
