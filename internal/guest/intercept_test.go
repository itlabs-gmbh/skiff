package guest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sovyn-eu/skiff/internal/cap"
)

const testCAPEM = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIBATAKBggqhkjOPQQDAjAAMB4XDTI2MTEwMzAwMDAwMFoX\n-----END CERTIFICATE-----\n"

var interceptHosts = []string{"graph.microsoft.com", "management.azure.com"}

func interceptPlan(t *testing.T, caps ...cap.Cap) Plan {
	t.Helper()
	plan, err := Render(caps, data)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = plan.WithIntercept(interceptHosts, []byte(testCAPEM))
	if err != nil {
		t.Fatalf("WithIntercept: %v", err)
	}
	return plan
}

func TestInterceptInstalled(t *testing.T) {
	plan := interceptPlan(t, claudeLike())
	manifest := strings.Join(plan.Manifest(), "\n")
	for _, want := range []string{
		"file:" + InterceptCAFile, "file:" + InterceptSocketUnit, "file:" + InterceptServiceUnit,
		"block:" + HostsFile + "#" + interceptOwner,
	} {
		if !strings.Contains(manifest, want) {
			t.Errorf("manifest lacks %s:\n%s", want, manifest)
		}
	}
	for k, want := range map[string]string{
		"REQUESTS_CA_BUNDLE":  systemCABundle,
		"SSL_CERT_FILE":       systemCABundle,
		"NODE_EXTRA_CA_CERTS": InterceptCAFile,
	} {
		if plan.Env[k] != want {
			t.Errorf("env %s = %q, want %q", k, plan.Env[k], want)
		}
	}
	script, err := plan.ApplyScript(State{})
	if err != nil {
		t.Fatal(err)
	}
	socket := decodeHeredoc(t, script, InterceptSocketUnit)
	if !strings.Contains(socket, "ListenStream="+InterceptAddress+":443") {
		t.Errorf("socket unit:\n%s", socket)
	}
	service := decodeHeredoc(t, script, InterceptServiceUnit)
	if !strings.Contains(service, "systemd-socket-proxyd 127.0.0.1:7777") {
		t.Errorf("service unit:\n%s", service)
	}
	for _, want := range []string{
		"systemctl --quiet enable --now skiff-intercept.socket",
		"update-ca-certificates",
		"skiff:" + interceptOwner,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("apply script lacks %q:\n%s", want, script)
		}
	}
}

func TestWithInterceptDoesNotChangeReceiver(t *testing.T) {
	plan, err := Render([]cap.Cap{claudeLike()}, data)
	if err != nil {
		t.Fatal(err)
	}
	before := len(plan.Env)
	if _, err := plan.WithIntercept(interceptHosts, []byte(testCAPEM)); err != nil {
		t.Fatal(err)
	}
	if len(plan.Env) != before || plan.Intercept != nil {
		t.Fatal("WithIntercept modified the plan it was called on")
	}
}

func TestWithInterceptRejects(t *testing.T) {
	squatter := cap.Cap{Name: "squat", Guest: cap.Guest{Env: map[string]string{"SSL_CERT_FILE": "/mine.pem"}}}
	tests := []struct {
		name  string
		caps  []cap.Cap
		hosts []string
		pem   string
		want  string
	}{
		{"no hosts", nil, nil, testCAPEM, "no hosts"},
		{"host with space", nil, []string{"a.example.com evil.example.com"}, testCAPEM, "host"},
		{"host with newline", nil, []string{"a.example.com\n1.2.3.4 x"}, testCAPEM, "host"},
		{"not a certificate", nil, interceptHosts, "garbage", "certificate"},
		{"env set by a cap", []cap.Cap{squatter}, interceptHosts, testCAPEM, "SSL_CERT_FILE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, err := Render(tt.caps, data)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := plan.WithIntercept(tt.hosts, []byte(tt.pem)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestInterceptPathsAreReserved(t *testing.T) {
	for _, p := range []string{InterceptCAFile, InterceptSocketUnit, InterceptServiceUnit} {
		squatter := cap.Cap{Name: "squat", Guest: cap.Guest{Files: []cap.File{{Path: p, Content: "x"}}}}
		if _, err := Render([]cap.Cap{squatter}, data); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("%s: a cap must not overwrite it, got %v", p, err)
		}
	}
}

func TestInterceptRemovedWithLastInterceptGrant(t *testing.T) {
	plan, err := Render([]cap.Cap{claudeLike()}, data)
	if err != nil {
		t.Fatal(err)
	}
	st := State{Manifest: []string{
		"file:" + InterceptCAFile, "file:" + InterceptSocketUnit, "file:" + InterceptServiceUnit,
		"block:" + HostsFile + "#" + interceptOwner,
	}}
	script, err := plan.ApplyScript(st)
	if err != nil {
		t.Fatal(err)
	}
	stop := strings.Index(script, "systemctl disable --now skiff-intercept.socket skiff-intercept.service")
	rm := strings.Index(script, "rm -f '"+InterceptSocketUnit+"'")
	if stop < 0 || rm < 0 || stop > rm {
		t.Fatalf("intercept relay must be stopped before its units are removed:\n%s", script)
	}
	rmCA := strings.Index(script, "rm -f '"+InterceptCAFile+"'")
	update := strings.Index(script, "update-ca-certificates --fresh")
	if rmCA < 0 || update < rmCA {
		t.Errorf("CA must be removed and the trust store rebuilt afterwards:\n%s", script)
	}
	if !strings.Contains(script, "skiff:"+interceptOwner) {
		t.Errorf("hosts block is not removed:\n%s", script)
	}
	if strings.Contains(script, "enable --now skiff-intercept") {
		t.Errorf("intercept relay must not be started:\n%s", script)
	}
}

func TestInterceptScriptsRunUnderBash(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	root := t.TempDir()
	rooted := func(p string) string { return filepath.Join(root, p) }
	_ = os.MkdirAll(rooted("/etc"), 0o755)
	_ = os.WriteFile(rooted(HostsFile), []byte("127.0.0.1 localhost\n"), 0o644)

	plan := interceptPlan(t)
	apply, err := plan.ApplyScript(State{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // the second run must change nothing
		if out, err := exec.Command("bash", "-c", rewriteRoot(apply, root)).CombinedOutput(); err != nil {
			t.Fatalf("apply %d: %v\n%s", i, err, out)
		}
	}
	hosts, _ := os.ReadFile(rooted(HostsFile))
	want := InterceptAddress + " graph.microsoft.com management.azure.com\n"
	if !strings.HasPrefix(string(hosts), "127.0.0.1 localhost\n") || strings.Count(string(hosts), want) != 1 {
		t.Errorf("hosts:\n%s", hosts)
	}
	if ca, _ := os.ReadFile(rooted(InterceptCAFile)); string(ca) != testCAPEM {
		t.Errorf("CA file = %q", ca)
	}

	st, err := ParseState(mustOutput(t, rewriteRoot(Plan{}.ReadScript(), root)))
	if err != nil {
		t.Fatal(err)
	}
	revoke, err := Plan{Env: map[string]string{}}.ApplyScript(unrootState(st, root))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("bash", "-c", rewriteRoot(revoke, root)).CombinedOutput(); err != nil {
		t.Fatalf("revoke: %v\n%s", err, out)
	}
	if hosts, _ := os.ReadFile(rooted(HostsFile)); string(hosts) != "127.0.0.1 localhost\n" {
		t.Errorf("hosts after revoke = %q", hosts)
	}
	if _, err := os.Stat(rooted(InterceptCAFile)); !os.IsNotExist(err) {
		t.Errorf("CA file survived revoke: %v", err)
	}
}
