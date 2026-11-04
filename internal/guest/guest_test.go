package guest

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sovyn-eu/skiff/internal/cap"
)

var data = cap.TemplateData{VM: "agent1", BrokerURL: "http://127.0.0.1:7777", PseudoToken: "tok"}

func claudeLike() cap.Cap {
	return cap.Cap{Name: "claude", Guest: cap.Guest{
		Env:       map[string]string{"ANTHROPIC_BASE_URL": "{{ .BrokerURL }}/claude", "CLAUDE_CODE_OAUTH_TOKEN": "sk-{{ .PseudoToken }}"},
		JSONMerge: []cap.JSONMerge{{Path: "/root/.claude.json", Key: "hasCompletedOnboarding", Value: true}},
	}}
}

func mcpLike() cap.Cap {
	return cap.Cap{Name: "devtools", Guest: cap.Guest{
		JSONMerge: []cap.JSONMerge{{Path: "/root/.claude.json", Key: "mcpServers.devtools",
			Value: map[string]any{"type": "http", "url": "{{ .BrokerURL }}/devtools"}}},
	}}
}

func blockLike() cap.Cap {
	return cap.Cap{Name: "github", Guest: cap.Guest{
		Blocks: []cap.Block{{Path: "/etc/gitconfig", Content: "[url \"{{ .BrokerURL }}/github/\"]\n\tinsteadOf = https://github.com/\n"}},
	}}
}

func fileLike() cap.Cap {
	return cap.Cap{Name: "github", Guest: cap.Guest{
		Files: []cap.File{{Path: "/etc/gitconfig", Content: "[url \"{{ .BrokerURL }}/github/\"]\n\tinsteadOf = https://github.com/\n"}},
	}}
}

func TestRenderMergesCapsAndRejectsConflicts(t *testing.T) {
	plan, err := Render([]cap.Cap{claudeLike(), mcpLike(), fileLike()}, data)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if plan.Env["ANTHROPIC_BASE_URL"] != "http://127.0.0.1:7777/claude" || plan.Env["CLAUDE_CODE_OAUTH_TOKEN"] != "sk-tok" {
		t.Errorf("env = %v", plan.Env)
	}
	if len(plan.Files) != 1 || plan.Files[0].Mode != "0644" || !strings.Contains(plan.Files[0].Content, "http://127.0.0.1:7777/github/") {
		t.Errorf("files = %+v", plan.Files)
	}
	if len(plan.Merges) != 2 || plan.Merges[1].Value.(map[string]any)["url"] != "http://127.0.0.1:7777/devtools" {
		t.Errorf("merges = %+v", plan.Merges)
	}
	want := []string{"file:/etc/gitconfig", "file:" + RelayServiceUnit, "file:" + RelaySocketUnit,
		"json:/root/.claude.json#hasCompletedOnboarding", "json:/root/.claude.json#mcpServers.devtools"}
	if strings.Join(plan.Manifest(), ",") != strings.Join(want, ",") {
		t.Errorf("manifest = %v", plan.Manifest())
	}

	dupEnv := claudeLike()
	dupEnv.Name = "other"
	if _, err := Render([]cap.Cap{claudeLike(), dupEnv}, data); err == nil || !strings.Contains(err.Error(), "both set ANTHROPIC_BASE_URL") {
		t.Errorf("duplicate env should fail, got %v", err)
	}
	dupFile := fileLike()
	dupFile.Name = "other"
	if _, err := Render([]cap.Cap{fileLike(), dupFile}, data); err == nil || !strings.Contains(err.Error(), "both write /etc/gitconfig") {
		t.Errorf("duplicate file should fail, got %v", err)
	}
	fileAndJSON := cap.Cap{Name: "other", Guest: cap.Guest{Files: []cap.File{{Path: "/root/.claude.json", Content: "{}"}}}}
	if _, err := Render([]cap.Cap{claudeLike(), fileAndJSON}, data); err == nil || !strings.Contains(err.Error(), "merges JSON into /root/.claude.json") {
		t.Errorf("file and JSON merge on the same path must fail, got %v", err)
	}
	if _, err := Render([]cap.Cap{fileAndJSON, claudeLike()}, data); err == nil || !strings.Contains(err.Error(), "as a file") {
		t.Errorf("JSON merge after file on the same path must fail, got %v", err)
	}
	parent := cap.Cap{Name: "p", Guest: cap.Guest{JSONMerge: []cap.JSONMerge{{Path: "/x.json", Key: "settings", Value: 1}}}}
	child := cap.Cap{Name: "c", Guest: cap.Guest{JSONMerge: []cap.JSONMerge{{Path: "/x.json", Key: "settings.mode", Value: 2}}}}
	for _, order := range [][]cap.Cap{{parent, child}, {child, parent}} {
		if _, err := Render(order, data); err == nil || !strings.Contains(err.Error(), "overlapping keys") {
			t.Errorf("nested keys must fail, got %v", err)
		}
	}
	sibling := cap.Cap{Name: "s", Guest: cap.Guest{JSONMerge: []cap.JSONMerge{{Path: "/x.json", Key: "settingsExtra", Value: 2}}}}
	if _, err := Render([]cap.Cap{parent, sibling}, data); err != nil {
		t.Errorf("sibling keys must be fine, got %v", err)
	}
	badEnv := cap.Cap{Name: "x", Guest: cap.Guest{Env: map[string]string{"A": `has "quote"`}}}
	if _, err := Render([]cap.Cap{badEnv}, data); err == nil {
		t.Errorf("env values with quotes must be rejected")
	}
	for _, bad := range []string{"/etc/with space", "/tmp/x;id", "/tmp/$(id)", "/tmp/a|b", "/etc/../root/x", "relative"} {
		badPath := cap.Cap{Name: "x", Guest: cap.Guest{Files: []cap.File{{Path: bad}}}}
		if _, err := Render([]cap.Cap{badPath}, data); err == nil {
			t.Errorf("path %q must be rejected", bad)
		}
	}
	stale := Plan{}.staleFiles(State{Manifest: []string{"file:/tmp/x;id", "file:/etc/ok"}})
	if len(stale) != 1 || stale[0] != "/etc/ok" {
		t.Errorf("unsafe manifest entries must be ignored, got %v", stale)
	}
}

func TestBlocksAreManagedPerOwner(t *testing.T) {
	plan, err := Render([]cap.Cap{blockLike()}, data)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Manifest()[0] != "block:/etc/gitconfig#github" {
		t.Errorf("manifest = %v", plan.Manifest())
	}
	script, err := plan.ApplyScript(State{Manifest: []string{"block:/etc/gitconfig#old-cap", "block:/etc/x;y#bad"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, ">>> skiff:old-cap ") || strings.Contains(script, "x;y") {
		t.Errorf("stale block should be stripped, unsafe manifest entries ignored:\n%s", script)
	}
	if !strings.Contains(script, "sed '/^.* >>> skiff:github .*$/,/^.* <<< skiff:github$/d' '/etc/gitconfig'") {
		t.Errorf("own block should be replaced:\n%s", script)
	}
	conflict := cap.Cap{Name: "other", Guest: cap.Guest{Files: []cap.File{{Path: "/etc/gitconfig", Content: "x"}}}}
	for _, order := range [][]cap.Cap{{blockLike(), conflict}, {conflict, blockLike()}} {
		if _, err := Render(order, data); err == nil {
			t.Errorf("file and block on the same path must conflict")
		}
	}
	twice := cap.Cap{Name: "t", Guest: cap.Guest{Blocks: []cap.Block{{Path: "/etc/t", Content: "a"}, {Path: "/etc/t", Content: "b"}}}}
	if _, err := Render([]cap.Cap{twice}, data); err == nil || !strings.Contains(err.Error(), "two blocks") {
		t.Errorf("two blocks of one cap for one path must fail, got %v", err)
	}
	jsonSame := cap.Cap{Name: "j", Guest: cap.Guest{JSONMerge: []cap.JSONMerge{{Path: "/etc/gitconfig", Key: "k", Value: 1}}}}
	for _, order := range [][]cap.Cap{{blockLike(), jsonSame}, {jsonSame, blockLike()}} {
		if _, err := Render(order, data); err == nil || !strings.Contains(err.Error(), "block") {
			t.Errorf("block and JSON merge on one path must fail, got %v", err)
		}
	}
	shared := cap.Cap{Name: "other", Guest: cap.Guest{Blocks: []cap.Block{{Path: "/etc/gitconfig", Content: "[x]\n"}}}}
	if _, err := Render([]cap.Cap{blockLike(), shared}, data); err != nil {
		t.Errorf("different owners may share a file, got %v", err)
	}
	selfMarker := cap.Cap{Name: "m", Guest: cap.Guest{Blocks: []cap.Block{{Path: "/etc/m", Content: "# <<< skiff:m\n"}}}}
	if _, err := Render([]cap.Cap{selfMarker}, data); err == nil {
		t.Errorf("content containing the own marker must be rejected")
	}
}

func TestParseState(t *testing.T) {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	out := ManifestPath + "\n" + enc("file:/etc/gitconfig\njson:/root/.claude.json#old\n") + "\n" +
		"/root/.claude.json\n" + enc(`{"old":1}`) + "\n" +
		"/missing.json\n\n"
	st, err := ParseState([]byte(out))
	if err != nil {
		t.Fatalf("ParseState: %v", err)
	}
	if len(st.Manifest) != 2 || st.Files["/root/.claude.json"] != `{"old":1}` {
		t.Errorf("state = %+v", st)
	}
	if _, ok := st.Files["/missing.json"]; ok {
		t.Errorf("missing files must be absent")
	}
	if _, err := ParseState([]byte("odd\n")); err == nil {
		t.Errorf("odd line count must fail")
	}
	if _, err := ParseState([]byte("/x\n!!!\n")); err == nil {
		t.Errorf("bad base64 must fail")
	}
}

func TestApplyScriptRemovesStaleAndMergesJSON(t *testing.T) {
	plan, err := Render([]cap.Cap{claudeLike()}, data)
	if err != nil {
		t.Fatal(err)
	}
	st := State{
		Manifest: []string{"file:/etc/gitconfig", "json:/root/.claude.json#mcpServers.devtools", "json:/root/.claude.json#hasCompletedOnboarding"},
		Files:    map[string]string{"/root/.claude.json": `{"mcpServers":{"devtools":{"type":"http"},"mine":{"type":"stdio"}},"projects":{"x":1}}`},
	}
	script, err := plan.ApplyScript(st)
	if err != nil {
		t.Fatalf("ApplyScript: %v", err)
	}
	if !strings.Contains(script, "rm -f '/etc/gitconfig'\n") {
		t.Errorf("stale file should be removed:\n%s", script)
	}
	merged := decodeHeredoc(t, script, "/root/.claude.json")
	for _, want := range []string{`"hasCompletedOnboarding": true`, `"mine"`, `"projects"`} {
		if !strings.Contains(merged, want) {
			t.Errorf("merged JSON should contain %s:\n%s", want, merged)
		}
	}
	if strings.Contains(merged, `"devtools"`) {
		t.Errorf("stale key should be deleted:\n%s", merged)
	}
	if !strings.Contains(decodeEnvBlock(t, script), `ANTHROPIC_BASE_URL="http://127.0.0.1:7777/claude"`) {
		t.Errorf("env block missing:\n%s", script)
	}
	manifest := decodeHeredoc(t, script, ManifestPath)
	if manifest != "file:"+RelayServiceUnit+"\nfile:"+RelaySocketUnit+"\njson:/root/.claude.json#hasCompletedOnboarding\n" {
		t.Errorf("manifest = %q", manifest)
	}

	bad := State{Files: map[string]string{"/root/.claude.json": "[1,2]"}}
	if _, err := plan.ApplyScript(bad); err == nil || !strings.Contains(err.Error(), "not a JSON object") {
		t.Errorf("non-object JSON must fail, got %v", err)
	}
}

func TestEmptyPlanClearsEnvBlock(t *testing.T) {
	script, err := Plan{Env: map[string]string{}}.ApplyScript(State{})
	if err != nil {
		t.Fatal(err)
	}
	if decodeEnvBlock(t, script) != "" {
		t.Errorf("empty plan should not write markers:\n%s", script)
	}
	if !strings.Contains(script, "sed '/^"+markerBegin) {
		t.Errorf("old block should still be stripped:\n%s", script)
	}
}

// TestScriptsRunUnderBash executes the generated scripts against a fake root
// so quoting and heredocs are verified by a real shell, not by eye.
func TestScriptsRunUnderBash(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	root := t.TempDir()
	rooted := func(p string) string { return filepath.Join(root, p) }
	_ = os.MkdirAll(rooted("/etc"), 0o755)
	_ = os.MkdirAll(rooted("/root"), 0o755)
	_ = os.WriteFile(rooted(EnvFile), []byte("PATH=/usr/bin\n"+markerBegin+"\nOLD=\"1\"\n"+markerEnd+"\n"), 0o644)
	_ = os.WriteFile(rooted("/root/.claude.json"), []byte(`{"projects":{"keep":true}}`), 0o600)
	// No trailing newline and a restrictive mode: both must survive.
	_ = os.WriteFile(rooted("/etc/gitconfig"), []byte("[user]\n\tname = Keep Me"), 0o600)

	plan, err := Render([]cap.Cap{claudeLike(), blockLike()}, data)
	if err != nil {
		t.Fatal(err)
	}
	read := rewriteRoot(plan.ReadScript(), root)
	out, err := exec.Command("bash", "-c", read).Output()
	if err != nil {
		t.Fatalf("read script: %v\n%s", err, out)
	}
	st, err := ParseState(out)
	if err != nil {
		t.Fatalf("ParseState: %v\n%s", err, out)
	}
	st = unrootState(st, root)
	if !strings.Contains(st.Files["/root/.claude.json"], "keep") {
		t.Fatalf("read script should return existing JSON, got %+v", st)
	}
	apply, err := plan.ApplyScript(st)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("bash", "-c", rewriteRoot(apply, root)).CombinedOutput(); err != nil {
		t.Fatalf("apply script: %v\n%s", err, out)
	}
	env, _ := os.ReadFile(rooted(EnvFile))
	if !strings.Contains(string(env), "PATH=/usr/bin\n") || strings.Contains(string(env), "OLD=") ||
		!strings.Contains(string(env), `CLAUDE_CODE_OAUTH_TOKEN="sk-tok"`) {
		t.Errorf("environment file:\n%s", env)
	}
	js, _ := os.ReadFile(rooted("/root/.claude.json"))
	if !strings.Contains(string(js), `"keep": true`) || !strings.Contains(string(js), `"hasCompletedOnboarding": true`) {
		t.Errorf("claude.json:\n%s", js)
	}
	git, _ := os.ReadFile(rooted("/etc/gitconfig"))
	if !strings.Contains(string(git), "name = Keep Me\n# >>> skiff:github managed") || !strings.Contains(string(git), "insteadOf = https://github.com/") {
		t.Errorf("gitconfig should keep existing settings and gain the block on its own line:\n%s", git)
	}
	if info, _ := os.Stat(rooted("/etc/gitconfig")); info.Mode().Perm() != 0o600 {
		t.Errorf("existing mode must be preserved, got %o", info.Mode().Perm())
	}
	// Re-applying the same plan must not duplicate or eat anything.
	if out, err := exec.Command("bash", "-c", rewriteRoot(apply, root)).CombinedOutput(); err != nil {
		t.Fatalf("second apply: %v\n%s", err, out)
	}
	git, _ = os.ReadFile(rooted("/etc/gitconfig"))
	if strings.Count(string(git), "skiff:github managed") != 1 || !strings.Contains(string(git), "name = Keep Me") {
		t.Errorf("second apply should replace the block in place:\n%s", git)
	}
	manifest, _ := os.ReadFile(rooted(ManifestPath))
	if !strings.Contains(string(manifest), "block:/etc/gitconfig#github") {
		t.Errorf("manifest:\n%s", manifest)
	}

	// Revoke everything: the block disappears, the user's settings stay.
	st2, _ := ParseState(mustOutput(t, rewriteRoot(Plan{}.ReadScript(), root)))
	st2 = unrootState(st2, root)
	revoke, err := Plan{Env: map[string]string{}}.ApplyScript(st2)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("bash", "-c", rewriteRoot(revoke, root)).CombinedOutput(); err != nil {
		t.Fatalf("revoke script: %v\n%s", err, out)
	}
	git, _ = os.ReadFile(rooted("/etc/gitconfig"))
	if string(git) != "[user]\n\tname = Keep Me\n" {
		t.Errorf("revoke should strip the block only:\n%q", git)
	}
	if info, _ := os.Stat(rooted("/etc/gitconfig")); info.Mode().Perm() != 0o600 {
		t.Errorf("mode must survive revoke, got %o", info.Mode().Perm())
	}
}

// TestFailedWriteKeepsOriginal runs the apply script with a tool on PATH
// that fails mid-write, standing in for a full disk, and checks the target
// is never left truncated. Two tools are faked: base64 -d, which is where
// the current implementation writes, and cat, which the former
// `cat "$tmp" > target` used and which truncated the target first.
func TestFailedWriteKeepsOriginal(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	for _, tool := range []string{"base64", "cat"} {
		t.Run(tool, func(t *testing.T) {
			root := t.TempDir()
			rooted := func(p string) string { return filepath.Join(root, p) }
			_ = os.MkdirAll(rooted("/etc/skiff"), 0o755)
			target := rooted("/etc/gitconfig")
			original := "[user]\n\tname = Keep Me\n"
			_ = os.WriteFile(target, []byte(original), 0o600)

			bin := t.TempDir()
			reached := filepath.Join(bin, "reached")
			fake := "#!/bin/sh\ntouch " + reached + "; printf 'partial'; exit 1\n"
			if tool == "base64" {
				// Only decoding fails; encoding stays real for the read script.
				fake = "#!/bin/sh\ncase \"$1\" in -d) touch " + reached + "; printf 'partial'; exit 1;; esac\nexec /usr/bin/base64 \"$@\"\n"
			}
			if err := os.WriteFile(filepath.Join(bin, tool), []byte(fake), 0o755); err != nil {
				t.Fatal(err)
			}

			plan, err := Render([]cap.Cap{blockLike()}, data)
			if err != nil {
				t.Fatal(err)
			}
			script, err := plan.ApplyScript(State{})
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", rewriteRoot(script, root))
			cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
			out, runErr := cmd.CombinedOutput()
			_, wasReached := os.Stat(reached)

			got, _ := os.ReadFile(target)
			withBlock := strings.HasPrefix(string(got), original) && strings.Contains(string(got), "<<< skiff:github")
			if string(got) != original && !withBlock {
				t.Errorf("target must be either untouched or complete, got %q\n%s", got, out)
			}
			if info, _ := os.Stat(target); info.Mode().Perm() != 0o600 {
				t.Errorf("mode changed to %o", info.Mode().Perm())
			}
			if wasReached == nil && runErr == nil {
				t.Errorf("a failing write must fail the script:\n%s", out)
			}
			if tool == "base64" && wasReached != nil {
				t.Errorf("script never reached the write step:\n%s", out)
			}
		})
	}
}

func mustOutput(t *testing.T, script string) []byte {
	t.Helper()
	out, err := exec.Command("bash", "-c", script).Output()
	if err != nil {
		t.Fatalf("script: %v", err)
	}
	return out
}

// rewriteRoot points every absolute guest path in a script at a temp root.
func rewriteRoot(script, root string) string {
	re := regexp.MustCompile(`([\s='])/(etc|root|usr)(/|\s|'|$)`)
	return re.ReplaceAllString(script, "${1}"+root+"/${2}${3}")
}

// unrootState maps the rooted paths back. Under the temp root ParseState
// does not recognise the manifest by its constant path, so it arrives as a
// plain file and is parsed here.
func unrootState(st State, root string) State {
	out := State{Manifest: st.Manifest, Files: map[string]string{}}
	for p, c := range st.Files {
		unrooted := strings.TrimPrefix(p, root)
		if unrooted == ManifestPath {
			for _, l := range strings.Split(c, "\n") {
				if l = strings.TrimSpace(l); l != "" {
					out.Manifest = append(out.Manifest, l)
				}
			}
			continue
		}
		out.Files[unrooted] = c
	}
	return out
}

func decodeEnvBlock(t *testing.T, script string) string {
	t.Helper()
	// The env section is the heredoc that follows the /etc/environment sed.
	anchor := strings.Index(script, "sed '/^"+markerBegin)
	if anchor < 0 {
		t.Fatalf("no env rewrite in:\n%s", script)
	}
	marker := "base64 -d >> \"$tmp\" <<'SKIFF_B64'\n"
	i := strings.Index(script[anchor:], marker)
	if i < 0 {
		t.Fatalf("no env heredoc in:\n%s", script)
	}
	i += anchor
	rest := script[i+len(marker):]
	data, err := base64.StdEncoding.DecodeString(rest[:strings.Index(rest, "\n")])
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func decodeHeredoc(t *testing.T, script, path string) string {
	t.Helper()
	marker := "base64 -d > '" + path + "' <<'SKIFF_B64'\n"
	i := strings.Index(script, marker)
	if i < 0 {
		t.Fatalf("no heredoc for %s in:\n%s", path, script)
	}
	rest := script[i+len(marker):]
	enc := rest[:strings.Index(rest, "\n")]
	data, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
