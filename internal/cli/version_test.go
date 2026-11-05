package cli

import (
	"bytes"
	"errors"
	"io"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/sovyn-eu/skiff/internal/app"
)

func TestResolveVersion(t *testing.T) {
	info := func(v string) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Version: v}}, true
		}
	}
	none := func() (*debug.BuildInfo, bool) { return nil, false }

	tests := []struct {
		name    string
		stamped string
		read    func() (*debug.BuildInfo, bool)
		want    string
	}{
		{"ldflags win", "v9.9.9", info("v0.5.0"), "v9.9.9"},
		{"go install @version", "", info("v0.5.0"), "v0.5.0"},
		{"vcs pseudo-version", "", info("v0.5.1-0.20261105-6bd3446+dirty"), "v0.5.1-0.20261105-6bd3446+dirty"},
		{"devel build", "", info("(devel)"), devVersion},
		{"empty module version", "", info(""), devVersion},
		{"no build info", "", none, devVersion},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveVersion(tt.stamped, tt.read); got != tt.want {
				t.Errorf("resolveVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVersionFlag(t *testing.T) {
	for _, flag := range []string{"--version", "-v"} {
		t.Run(flag, func(t *testing.T) {
			out, _, err := run(t, flag)
			if err != nil {
				t.Fatalf("%s: %v", flag, err)
			}
			if !strings.HasPrefix(out, "skiff version ") || strings.TrimSpace(out) == "skiff version" {
				t.Errorf("unexpected output: %q", out)
			}
		})
	}
}

// --version must not need a working App: it answers before PersistentPreRunE.
func TestVersionFlagSkipsAppBuild(t *testing.T) {
	built := false
	root := newRoot(func(_ io.Writer) (*app.App, error) {
		built = true
		return nil, errors.New("must not build")
	})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("--version: %v", err)
	}
	if built {
		t.Error("--version built the App")
	}
}
