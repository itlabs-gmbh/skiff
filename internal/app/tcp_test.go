package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sovyn-eu/skiff/internal/backend/backendtest"
	"github.com/sovyn-eu/skiff/internal/broker"
	"github.com/sovyn-eu/skiff/internal/cap"
	"github.com/sovyn-eu/skiff/internal/config"
	"github.com/sovyn-eu/skiff/internal/grant"
	"github.com/sovyn-eu/skiff/internal/runner"
)

// writeTCPCap installs a tcp capability file in the App's caps directory.
func writeTCPCap(t *testing.T, app *App, name, upstream string, port int) {
	t.Helper()
	if err := os.MkdirAll(app.paths.CapsDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	text := fmt.Sprintf("name = %q\n[tcp]\nupstream = %q\nport = %d\n[guest.env]\n%s_URL = \"db://127.0.0.1:%d\"\n",
		name, upstream, port, strings.ToUpper(strings.ReplaceAll(name, "-", "_")), port)
	if err := os.WriteFile(filepath.Join(app.paths.CapsDir(), name+".toml"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// newSocketApp returns an App whose state lives under /tmp, where socket
// paths stay within the limit, with agent1 granted the given capabilities.
func newSocketApp(t *testing.T, out io.Writer) *App {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "skiff-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fake := runner.NewFake(func(string, []string) ([]byte, error) { return nil, nil })
	return New(fake, config.Paths{Home: dir}, out, WithBackend(backendtest.New()))
}

func saveGrants(t *testing.T, app *App, caps ...string) {
	t.Helper()
	set, err := grant.ParseSet(caps)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.grantStore().Save("agent1", set); err != nil {
		t.Fatal(err)
	}
}

// echoServer answers every connection with what it sends.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestBrokerForwardCarriesTCPCaps(t *testing.T) {
	cases := map[string]struct {
		fwd  Forwards
		want []string
	}{
		"broker only": {
			Forwards{Broker: "/run/a.sock"},
			[]string{"-o", "ExitOnForwardFailure=yes", "-R", "127.0.0.1:7777:/run/a.sock"},
		},
		"with tcp capabilities": {
			Forwards{Broker: "/run/a.sock", TCP: []TCPSocket{
				{Cap: "mongo", Port: 27017, Socket: "/run/a.tcp-27017.sock"},
				{Cap: "postgres", Port: 5432, Socket: "/run/a.tcp-5432.sock"},
			}},
			[]string{"-o", "ExitOnForwardFailure=yes", "-R", "127.0.0.1:7777:/run/a.sock",
				"-R", "127.0.0.1:27017:/run/a.tcp-27017.sock", "-R", "127.0.0.1:5432:/run/a.tcp-5432.sock"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := brokerForward(tc.fwd); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestStartBrokerServesGrantedTCPCaps(t *testing.T) {
	app := newSocketApp(t, &strings.Builder{})
	writeTCPCap(t, app, "mongo", echoServer(t), 27017)
	writeTCPCap(t, app, "postgres", "127.0.0.1:5433", 5432) // installed, not granted
	saveGrants(t, app, "mongo", "claude")

	fwd, stop, err := app.startBroker(context.Background(), "agent1")
	if err != nil {
		t.Fatalf("startBroker: %v", err)
	}
	socket := app.paths.TCPSocketPath("agent1", 27017)
	want := []TCPSocket{{Cap: "mongo", Port: 27017, Socket: socket}}
	if !reflect.DeepEqual(fwd.TCP, want) {
		t.Fatalf("tcp forwards = %+v, want %+v", fwd.TCP, want)
	}
	if info, err := os.Stat(socket); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the tcp socket must exist with mode 0600, got %v, %v", info, err)
	}

	c, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatalf("dial the tcp socket: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = c.(*net.UnixConn).CloseWrite()
	got, _ := io.ReadAll(c)
	_ = c.Close()
	if string(got) != "ping" {
		t.Errorf("relayed %q, want %q", got, "ping")
	}

	if !app.servedTCP("agent1", "mongo", 27017) || app.servedTCP("agent1", "postgres", 5432) || app.servedTCP("agent1", "mongo", 5432) {
		t.Errorf("the record of served capabilities should name mongo on 27017 only")
	}

	stop()
	if _, err := os.Stat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stop should remove the tcp socket, got %v", err)
	}
	if app.servedTCP("agent1", "mongo", 27017) {
		t.Errorf("stop should remove the record of served capabilities")
	}
	log, _ := os.ReadFile(app.paths.AuditLog())
	if !strings.Contains(string(log), "vm=agent1 cap=mongo allow TCP") {
		t.Errorf("the connection should be in the audit log:\n%s", log)
	}
}

func TestStartBrokerRefusesTCPCapOnSkiffSockets(t *testing.T) {
	app := newSocketApp(t, &strings.Builder{})
	// Another VM's broker socket: reaching it would lend this VM that VM's grants.
	writeTCPCap(t, app, "sneaky", "unix:"+app.paths.SocketPath("other"), 9000)
	saveGrants(t, app, "sneaky")

	_, _, err := app.startBroker(context.Background(), "agent1")
	if err == nil || !strings.Contains(err.Error(), "skiff's own sockets") {
		t.Fatalf("want a refusal naming skiff's own sockets, got %v", err)
	}
	if _, err := os.Stat(app.paths.SocketPath("agent1")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused start must not leave the broker socket behind, got %v", err)
	}
	if _, _, err := app.startBroker(context.Background(), "agent1"); errors.Is(err, broker.ErrBusy) {
		t.Error("a refused start must give the broker up again")
	}
}

func TestOwnSocketComparesDirectoriesByIdentity(t *testing.T) {
	app := newSocketApp(t, &strings.Builder{})
	run := app.paths.RunDir()
	other := filepath.Join(app.paths.Home, "proxies")
	link := filepath.Join(app.paths.Home, "link")
	for _, dir := range []string{run, filepath.Join(run, "nested"), other} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(run, link); err != nil {
		t.Fatal(err)
	}
	// Aliases outside the run directory: one leads to a broker socket, the
	// other to a proxy's.
	for target, alias := range map[string]string{
		filepath.Join(run, "other.sock"):   filepath.Join(other, "alias.sock"),
		filepath.Join(other, "mongo.sock"): filepath.Join(other, "mongo-alias.sock"),
	} {
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, alias); err != nil {
			t.Fatal(err)
		}
	}
	cases := map[string]struct {
		upstream string
		want     bool
	}{
		"a broker socket":              {"unix:" + filepath.Join(run, "other.sock"), true},
		"below the run directory":      {"unix:" + filepath.Join(run, "nested", "x.sock"), true},
		"through a symlink":            {"unix:" + filepath.Join(link, "other.sock"), true},
		"an alias of a broker socket":  {"unix:" + filepath.Join(other, "alias.sock"), true},
		"a proxy's socket":             {"unix:" + filepath.Join(other, "mongo.sock"), false},
		"an alias of a proxy's socket": {"unix:" + filepath.Join(other, "mongo-alias.sock"), false},
		"a sibling with a longer name": {"unix:" + run + "-old/x.sock", false},
		"a TCP address":                {"127.0.0.1:27016", false},
	}
	// On the Mac's default file system RUN/ is run/; a spelling check alone
	// would let that through.
	upper := filepath.Join(app.paths.Home, strings.ToUpper(filepath.Base(run)))
	if _, err := os.Stat(upper); err == nil {
		cases["another spelling of the run directory"] = struct {
			upstream string
			want     bool
		}{"unix:" + filepath.Join(upper, "other.sock"), true}
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := app.ownSocket(tc.upstream); got != tc.want {
				t.Errorf("ownSocket(%q) = %v, want %v", tc.upstream, got, tc.want)
			}
		})
	}
}

func TestStartBrokerCleansUpWhenTCPSocketCannotListen(t *testing.T) {
	app := newSocketApp(t, &strings.Builder{})
	writeTCPCap(t, app, "mongo", "127.0.0.1:27016", 27017)
	saveGrants(t, app, "mongo")
	// A directory where the socket belongs cannot be replaced by Listen.
	if err := os.MkdirAll(filepath.Join(app.paths.TCPSocketPath("agent1", 27017), "x"), 0o700); err != nil {
		t.Fatal(err)
	}

	if _, _, err := app.startBroker(context.Background(), "agent1"); err == nil {
		t.Fatal("want an error when the tcp socket cannot be bound")
	}
	if _, err := os.Stat(app.paths.SocketPath("agent1")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a failed start must not leave the broker socket behind, got %v", err)
	}
}

func TestGrantRefusesTCPCapsThatCannotBeServed(t *testing.T) {
	cases := map[string]struct {
		install func(t *testing.T, app *App)
		grant   []string
		want    string
	}{
		"two capabilities on one guest port": {
			func(t *testing.T, app *App) {
				writeTCPCap(t, app, "mongo", "127.0.0.1:27016", 27017)
				writeTCPCap(t, app, "mongo-staging", "127.0.0.1:27018", 27017)
			},
			[]string{"mongo", "mongo-staging"}, "both forward guest port 27017",
		},
		"upstream is a skiff socket": {
			func(t *testing.T, app *App) {
				writeTCPCap(t, app, "sneaky", "unix:"+app.paths.SocketPath("other"), 9000)
			},
			[]string{"sneaky"}, "skiff's own sockets",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			scripts := &sshScripts{state: "/etc/skiff/manifest\n\n"}
			app, _ := newGrantApp(t, scripts)
			tc.install(t, app)
			_, err := app.Grant(context.Background(), "agent1", tc.grant)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error containing %q, got %v", tc.want, err)
			}
			if set, _ := app.Grants("agent1"); len(set) != 0 {
				t.Errorf("a refused grant must not be persisted, got %v", set.Caps())
			}
			if scripts.calls != 0 {
				t.Errorf("a refused grant must not touch the guest")
			}
		})
	}
}

func TestGrantOfTCPCapProvisionsGuestSection(t *testing.T) {
	scripts := &sshScripts{state: "/etc/skiff/manifest\n\n"}
	app, _ := newGrantApp(t, scripts)
	writeTCPCap(t, app, "mongo", "127.0.0.1:27016", 27017)
	if _, err := app.Grant(context.Background(), "agent1", []string{"mongo"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	decoded := decodeAll(scripts.last())
	if !strings.Contains(decoded, `MONGO_URL="db://127.0.0.1:27017"`) {
		t.Errorf("the guest section should be provisioned:\n%s", decoded)
	}
	if strings.Contains(scripts.last()+decoded, "27016") {
		t.Errorf("the upstream must not reach the guest:\n%s", decoded)
	}
}

func TestGrantOfTCPCapNotesOpenSession(t *testing.T) {
	out := &strings.Builder{}
	app := newSocketApp(t, out)
	writeTCPCap(t, app, "mongo", "127.0.0.1:27016", 27017)
	note := "mongo reaches guest port 27017 through sessions and tunnels opened from now on"

	if _, err := app.Grant(context.Background(), "agent1", []string{"mongo"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if strings.Contains(out.String(), note) {
		t.Errorf("no session is open, so there is nothing to reopen:\n%s", out.String())
	}

	// A session that started before the grant serves the broker.
	ln, err := broker.Listen(app.paths.SocketPath("agent1"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	out.Reset()
	if _, err := app.Revoke(context.Background(), "agent1", []string{"mongo"}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := app.Grant(context.Background(), "agent1", []string{"mongo", "claude"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if !strings.Contains(out.String(), note) {
		t.Errorf("want a note that open sessions do not forward the port:\n%s", out.String())
	}
	if strings.Contains(out.String(), "claude reaches") {
		t.Errorf("only tcp capabilities need the note:\n%s", out.String())
	}

	// A session that was opened while the capability was granted still
	// forwards the port: after a revoke, granting it again works at once.
	_ = ln.Close()
	_, stop, err := app.startBroker(context.Background(), "agent1")
	if err != nil {
		t.Fatalf("startBroker: %v", err)
	}
	defer stop()
	if _, err := app.Revoke(context.Background(), "agent1", []string{"mongo"}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	out.Reset()
	if _, err := app.Grant(context.Background(), "agent1", []string{"mongo"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if strings.Contains(out.String(), note) {
		t.Errorf("the open session already forwards the port, so nothing needs reopening:\n%s", out.String())
	}
	// Finding that out must not look like a connection from the guest.
	if log, _ := os.ReadFile(app.paths.AuditLog()); strings.Contains(string(log), " TCP ") {
		t.Errorf("a grant must not connect to the capability's socket:\n%s", log)
	}

	// Another capability on the same port is not what the session serves:
	// its relay still answers for mongo and would refuse every connection.
	writeTCPCap(t, app, "mongo-b", "127.0.0.1:27018", 27017)
	if _, err := app.Revoke(context.Background(), "agent1", []string{"mongo"}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	out.Reset()
	if _, err := app.Grant(context.Background(), "agent1", []string{"mongo-b"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if !strings.Contains(out.String(), "mongo-b reaches guest port 27017 through sessions and tunnels opened from now on") {
		t.Errorf("want the note for a capability the open session does not serve:\n%s", out.String())
	}
}

func TestSessionForwardsTCPCaps(t *testing.T) {
	fake := runner.NewFake(sshOnly)
	tunnel := func(_ context.Context, name string) (Forwards, func(), error) {
		return Forwards{Broker: "/tmp/fake-" + name + ".sock",
			TCP: []TCPSocket{{Cap: "mongo", Port: 27017, Socket: "/tmp/fake-" + name + ".tcp-27017.sock"}}}, func() {}, nil
	}
	app := New(fake, testPaths(t), &strings.Builder{}, WithBackend(backendtest.New()), WithTunnel(tunnel))
	saveGrants(t, app, "mongo")
	if err := app.SSH(context.Background(), "agent1", nil); err != nil {
		t.Fatalf("SSH: %v", err)
	}
	for _, want := range []string{
		"-R 127.0.0.1:7777:/tmp/fake-agent1.sock",
		"-R 127.0.0.1:27017:/tmp/fake-agent1.tcp-27017.sock",
	} {
		if !strings.Contains(fake.Dump(), want) {
			t.Errorf("ssh should be called with %q:\n%s", want, fake.Dump())
		}
	}
}

func TestTunnelForwardsAndAnnouncesTCPCaps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	script := &tunnelScript{states: []string{"running"}, onSSH: func(int) { cancel() }}
	app, fake := newTunnelApp(t, script, "mongo")
	out := &strings.Builder{}
	app.out = out
	app.tunnel = func(_ context.Context, name string) (Forwards, func(), error) {
		return Forwards{Broker: "/tmp/fake-" + name + ".sock",
			TCP: []TCPSocket{{Cap: "mongo", Port: 27017, Socket: "/tmp/fake-" + name + ".tcp-27017.sock"}}}, func() {}, nil
	}
	if err := app.Tunnel(ctx, "agent1"); err != nil {
		t.Fatalf("Tunnel: %v", err)
	}
	calls := tunnelCalls(fake)
	if len(calls) != 1 || !strings.Contains(calls[0], "-R 127.0.0.1:27017:/tmp/fake-agent1.tcp-27017.sock") {
		t.Errorf("the tunnel should forward the tcp capability:\n%s", fake.Dump())
	}
	if !strings.Contains(out.String(), "mongo on guest 127.0.0.1:27017") {
		t.Errorf("the tunnel should say where the capability appears:\n%s", out.String())
	}
}

func TestCapSummaryOfTCPCap(t *testing.T) {
	c := cap.Cap{Name: "mongo", TCP: &cap.TCP{Upstream: "127.0.0.1:27016", Port: 27017}}
	want := "=> mongo lets the guest connect to 127.0.0.1:27016 as seen from this Mac, on guest port 27017\n"
	if got := capSummary(c); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestCapShowRendersTCPPort(t *testing.T) {
	app, out, _ := newCapApp(t)
	writeTCPCap(t, app, "mongo", "127.0.0.1:27016", 27017)
	if err := app.CapShow("mongo", true, ""); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tcp 127.0.0.1:27017", `env MONGO_URL=db://127.0.0.1:27017`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "27016") {
		t.Errorf("the render shows the guest's side only:\n%s", out.String())
	}
}
