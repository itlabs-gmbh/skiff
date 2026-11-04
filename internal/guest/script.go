package guest

import (
	"encoding/base64"
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/sovyn-eu/skiff/internal/cap"
)

// State is what the guest reported before an apply: the previous manifest and
// the current content of every JSON file involved (absent when missing).
type State struct {
	Manifest []string
	Files    map[string]string
}

// ReadScript returns a POSIX shell script that prints, for the manifest and
// every JSON file the plan or the old manifest touches, the path on one line
// and its base64 content on the next (empty when the file does not exist).
// Paths read back from the guest's manifest are filtered with the same
// character class the plan enforces before the shell sees them.
func (p Plan) ReadScript() string {
	paths := map[string]bool{}
	for _, m := range p.Merges {
		paths[m.Path] = true
	}
	list := make([]string, 0, len(paths))
	for k := range paths {
		list = append(list, k)
	}
	sort.Strings(list)
	var b strings.Builder
	b.WriteString("m=" + ManifestPath + "\n")
	b.WriteString("paths='" + strings.Join(list, " ") + "'\n")
	b.WriteString(`if [ -f "$m" ]; then paths="$paths $(sed -n 's/^json:\(\/[A-Za-z0-9._\/-]*\)#.*$/\1/p' "$m" | tr '\n' ' ')"; fi` + "\n")
	// `base64 | tr` instead of `base64 -w0`: the latter is GNU-only and the
	// scripts are also exercised on macOS in tests.
	b.WriteString(`for p in "$m" $paths; do echo "$p"; if [ -f "$p" ]; then base64 < "$p" | tr -d '\n'; fi; echo; done` + "\n")
	return b.String()
}

// ParseState decodes ReadScript's output.
func ParseState(out []byte) (State, error) {
	st := State{Files: map[string]string{}}
	if strings.TrimSpace(string(out)) == "" {
		return st, nil
	}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(lines)%2 != 0 {
		return State{}, fmt.Errorf("unexpected guest state output (%d lines)", len(lines))
	}
	for i := 0; i+1 < len(lines); i += 2 {
		p, enc := strings.TrimSpace(lines[i]), strings.TrimSpace(lines[i+1])
		if p == "" {
			continue
		}
		if enc == "" {
			continue // file does not exist
		}
		data, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			return State{}, fmt.Errorf("decode %s: %w", p, err)
		}
		if p == ManifestPath {
			for _, l := range strings.Split(string(data), "\n") {
				if l = strings.TrimSpace(l); l != "" {
					st.Manifest = append(st.Manifest, l)
				}
			}
			continue
		}
		st.Files[p] = string(data)
	}
	return st, nil
}

// ApplyScript returns a bash script that brings the guest to the plan:
// stale managed files are removed, stale JSON keys deleted, files and merges
// written, the environment block replaced and the manifest updated.
func (p Plan) ApplyScript(st State) (string, error) {
	var b strings.Builder
	b.WriteString("set -eu\n")
	b.WriteString("install -d -m 0755 " + path.Dir(ManifestPath) + "\n")
	stale := p.staleFiles(st)
	relayGone := !p.Relay && slices.ContainsFunc(stale, isRelayUnit)
	interceptGone := p.Intercept == nil && slices.ContainsFunc(stale, isInterceptUnit)
	if relayGone {
		stopRelay(&b)
	}
	if interceptGone {
		stopIntercept(&b)
	}
	for _, f := range stale {
		b.WriteString("rm -f " + shQuote(f) + "\n")
	}
	if relayGone || interceptGone {
		b.WriteString("if " + asRootOnSystemd + "; then systemctl daemon-reload; fi\n")
	}
	if slices.Contains(stale, InterceptCAFile) {
		b.WriteString(updateTrust("--fresh", "") + "\n")
	}
	for _, f := range p.Files {
		writeFile(&b, f.Path, f.Mode, []byte(f.Content))
	}
	if p.Relay {
		writeRelay(&b)
	}
	if p.Intercept != nil {
		p.Intercept.write(&b)
	}
	for _, stale := range p.staleBlocks(st) {
		writeBlock(&b, stale.Path, stale.Owner, "", "")
	}
	for _, blk := range p.Blocks {
		writeBlock(&b, blk.Path, blk.Owner, blk.Comment, blk.Content)
	}
	merged, err := p.mergedJSON(st)
	if err != nil {
		return "", err
	}
	for _, jp := range sortedMapKeys(merged) {
		writeFile(&b, jp, "0600", []byte(merged[jp]))
	}
	p.writeEnv(&b)
	writeFile(&b, ManifestPath, "0644", []byte(strings.Join(p.Manifest(), "\n")+"\n"))
	return b.String(), nil
}

// staleFiles are files a previous plan wrote that this plan no longer owns.
func (p Plan) staleFiles(st State) []string {
	current := map[string]bool{}
	for _, l := range p.Manifest() {
		current[l] = true
	}
	var stale []string
	for _, l := range st.Manifest {
		if !strings.HasPrefix(l, "file:") || current[l] {
			continue
		}
		// The manifest is read back from the guest; never trust it blindly.
		if path := strings.TrimPrefix(l, "file:"); validateManifestPath(path) == nil {
			stale = append(stale, path)
		}
	}
	return stale
}

// staleBlocks are managed sections a previous plan owned that this plan no
// longer declares. The comment syntax is unknown by then, so the markers
// are matched on their skiff:<owner> tag alone.
func (p Plan) staleBlocks(st State) []Block {
	current := map[string]bool{}
	for _, l := range p.Manifest() {
		current[l] = true
	}
	var stale []Block
	for _, l := range st.Manifest {
		if !strings.HasPrefix(l, "block:") || current[l] {
			continue
		}
		path, owner, ok := strings.Cut(strings.TrimPrefix(l, "block:"), "#")
		if !ok || validateManifestPath(path) != nil || (cap.ValidateName(owner) != nil && owner != interceptOwner) {
			continue
		}
		stale = append(stale, Block{Path: path, Owner: owner})
	}
	return stale
}

// mergedJSON computes the new content of every JSON file: stale keys from
// the old manifest are removed, then the plan's keys are set.
func (p Plan) mergedJSON(st State) (map[string]string, error) {
	current := map[string]bool{}
	for _, l := range p.Manifest() {
		current[l] = true
	}
	docs := map[string]map[string]any{}
	load := func(jp string) (map[string]any, error) {
		if d, ok := docs[jp]; ok {
			return d, nil
		}
		d, err := parseJSONObject(st.Files[jp])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", jp, err)
		}
		docs[jp] = d
		return d, nil
	}
	for _, l := range st.Manifest {
		if !strings.HasPrefix(l, "json:") || current[l] {
			continue
		}
		jp, key, _ := strings.Cut(strings.TrimPrefix(l, "json:"), "#")
		d, err := load(jp)
		if err != nil {
			return nil, err
		}
		docs[jp] = deleteKey(d, key)
	}
	for _, m := range p.Merges {
		d, err := load(m.Path)
		if err != nil {
			return nil, err
		}
		docs[m.Path] = setKey(d, m.Key, m.Value)
	}
	out := map[string]string{}
	for jp, d := range docs {
		text, err := marshalJSON(d)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", jp, err)
		}
		out[jp] = text
	}
	return out, nil
}

// writeEnv replaces the managed block in /etc/environment.
func (p Plan) writeEnv(b *strings.Builder) {
	var block strings.Builder
	if len(p.Env) > 0 {
		block.WriteString(markerBegin + "\n")
		for _, k := range sortedKeys(p.Env) {
			block.WriteString(k + "=\"" + p.Env[k] + "\"\n")
		}
		block.WriteString(markerEnd + "\n")
	}
	rewriteSection(b, EnvFile, "^"+markerBegin+"$", "^"+markerEnd+"$", block.String())
}

// writeBlock replaces the section tagged skiff:<owner> in a file with
// content (an empty content just removes it). Markers are matched by their
// tag so the comment syntax may change between versions.
func writeBlock(b *strings.Builder, p, owner, comment, content string) {
	begin, end := blockMarkers(owner, comment)
	var block strings.Builder
	if content != "" {
		block.WriteString(begin + "\n" + content + end + "\n")
	}
	tag := blockTag(owner)
	rewriteSection(b, p, "^.* >>> "+tag+" .*$", "^.* <<< "+tag+"$", block.String())
}

// rewriteSection emits shell that removes the lines between the begin and
// end patterns from a file and appends section instead. The new content is
// built in a temp file next to the target that was cloned from it with
// `cp -p`, so mode and owner carry over, and is moved into place only after
// every write succeeded: a failure (disk full, read-only directory) leaves
// the original untouched and, under set -e, fails the script and with it
// the grant. A missing file is created with 0644. A retained content that
// does not end in a newline gets one first, otherwise the begin marker
// would attach to the last foreign line and take it along next time.
func rewriteSection(b *strings.Builder, p, beginPat, endPat, section string) {
	q := shQuote(p)
	dir := shQuote(path.Dir(p))
	b.WriteString("install -d -m 0755 " + dir + "\n")
	b.WriteString("tmp=$(mktemp " + dir + "/.skiff.XXXXXX)\n")
	b.WriteString("if [ -f " + q + " ]; then cp -p " + q + " \"$tmp\"; sed '/" + beginPat + "/,/" + endPat + "/d' " + q + " > \"$tmp\"; else chmod 0644 \"$tmp\"; fi\n")
	// $(...) strips trailing newlines, so the output is empty exactly when
	// the file is empty or already ends in a newline.
	b.WriteString("if [ -n \"$(tail -c1 \"$tmp\")\" ]; then echo >> \"$tmp\"; fi\n")
	b.WriteString("base64 -d >> \"$tmp\" <<'SKIFF_B64'\n")
	b.WriteString(base64.StdEncoding.EncodeToString([]byte(section)) + "\n")
	b.WriteString("SKIFF_B64\n")
	b.WriteString("mv -f \"$tmp\" " + q + "\n")
}

func blockTag(owner string) string { return "skiff:" + owner }

func blockMarkers(owner, comment string) (string, string) {
	return comment + " >>> " + blockTag(owner) + " managed, do not edit", comment + " <<< " + blockTag(owner)
}

// writeFile emits a heredoc with base64 content, so no byte of the content
// can terminate the heredoc early or be interpreted by the shell.
func writeFile(b *strings.Builder, p, mode string, content []byte) {
	b.WriteString("install -d -m 0755 " + shQuote(path.Dir(p)) + "\n")
	b.WriteString("base64 -d > " + shQuote(p) + " <<'SKIFF_B64'\n")
	b.WriteString(base64.StdEncoding.EncodeToString(content) + "\n")
	b.WriteString("SKIFF_B64\n")
	b.WriteString("chmod " + shQuote(mode) + " " + shQuote(p) + "\n")
}

// shQuote single-quotes a word for POSIX shells. Paths and modes are already
// validated to a safe character class; quoting is defence in depth.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func sortedMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
