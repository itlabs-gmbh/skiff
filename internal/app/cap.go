package app

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"unicode"

	"github.com/sovyn-eu/skiff/internal/cap"
	"github.com/sovyn-eu/skiff/internal/config"
	"github.com/sovyn-eu/skiff/internal/grant"
	"github.com/sovyn-eu/skiff/internal/guest"
	"github.com/sovyn-eu/skiff/internal/vm"
)

// maxCapDownload bounds `skiff cap add` downloads.
const maxCapDownload = 256 << 10

// CapList prints every known capability with its kind and origin.
func (a *App) CapList() error {
	caps, err := a.loadCaps()
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tKIND\tSOURCE\tDESCRIPTION")
	for _, name := range caps.Names() {
		c := caps[name]
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", c.Name, c.Kind(), c.Source, c.Description)
	}
	fmt.Fprintf(w, "%s\tbuilt-in\t-\tforward the Mac's SSH agent (ssh -A)\n", grant.SSHAgent)
	return w.Flush()
}

// CapShow prints a capability's source file. With render set, it prints what
// the guest of vmName would receive instead.
func (a *App) CapShow(name string, render bool, vmName string) error {
	if err := cap.ValidateName(name); err != nil {
		return err
	}
	caps, err := a.loadCaps()
	if err != nil {
		return err
	}
	c, ok := caps[name]
	if !ok {
		return fmt.Errorf("unknown capability %q (see 'skiff cap ls')", name)
	}
	if !render {
		return a.printCapSource(c)
	}
	data, err := a.previewData(vmName)
	if err != nil {
		return err
	}
	if vmName == "" {
		vmName = data.VM
	}
	plan, err := guest.Render([]cap.Cap{c}, data)
	if err != nil {
		return err
	}
	a.printf("# guest configuration of %s for %s\n", name, vmName)
	if c.TCP != nil {
		a.printf("tcp 127.0.0.1:%d\n", c.TCP.Port)
	}
	a.printPlan(plan)
	return nil
}

// previewData is the template data for a VM, or, with no name, for an
// example VM that leaves no state behind on the Mac.
func (a *App) previewData(vmName string) (cap.TemplateData, error) {
	if vmName == "" {
		return cap.TemplateData{VM: "example", BrokerURL: fmt.Sprintf("http://127.0.0.1:%d", config.BrokerGuestPort),
			PseudoToken: "example-token", BrokerSocket: config.BrokerGuestSocket}, nil
	}
	if err := vm.ValidateName(vmName); err != nil {
		return cap.TemplateData{}, err
	}
	return a.templateData(vmName)
}

// printPlan prints what a guest receives, one line per item.
func (a *App) printPlan(plan guest.Plan) {
	for _, k := range sortedKeys(plan.Env) {
		a.printf("env %s=%s\n", k, plan.Env[k])
	}
	for _, f := range plan.Files {
		a.printf("file %s (%s):\n%s", f.Path, f.Mode, indent(f.Content))
	}
	for _, blk := range plan.Blocks {
		a.printf("block %s (section skiff:%s):\n%s", blk.Path, blk.Owner, indent(blk.Content))
	}
	for _, m := range plan.Merges {
		a.printf("json %s %s = %v\n", m.Path, m.Key, m.Value)
	}
}

func (a *App) printCapSource(c cap.Cap) error {
	var text []byte
	var err error
	if c.Source == cap.SourceEmbedded {
		text, err = cap.EmbeddedSource(c.Name)
	} else {
		text, err = os.ReadFile(c.Source)
	}
	if err != nil {
		return err
	}
	a.printf("# source: %s\n%s", c.Source, text)
	return nil
}

// CapLint validates one capability file or every user file.
func (a *App) CapLint(name string) error {
	if name != "" {
		if err := cap.ValidateName(name); err != nil {
			return err
		}
		if _, err := cap.ParseFile(filepath.Join(a.paths.CapsDir(), name+".toml")); err != nil {
			return err
		}
		a.printf("%s: ok\n", name)
		return nil
	}
	caps, err := a.loadCaps()
	if err != nil {
		return err
	}
	n := 0
	for _, c := range caps {
		if c.Source != cap.SourceEmbedded {
			n++
		}
	}
	a.printf("%d user capabilities in %s: ok\n", n, a.paths.CapsDir())
	return nil
}

// CapInit writes a commented skeleton for a new capability.
func (a *App) CapInit(name string) error {
	text, err := cap.Skeleton(name)
	if err != nil {
		return err
	}
	path := filepath.Join(a.paths.CapsDir(), name+".toml")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	if err := os.MkdirAll(a.paths.CapsDir(), 0o700); err != nil {
		return fmt.Errorf("create caps directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	a.printf("wrote %s\n  edit it, then: skiff cap lint %s\n", path, name)
	return nil
}

// CapAdd downloads a capability file, shows it, and installs it after
// confirmation (or straight away with yes).
func (a *App) CapAdd(ctx context.Context, url string, yes bool, confirm io.Reader) error {
	if !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("capability URLs must use https")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := *http.DefaultClient
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("redirect to non-https URL %s refused", req.URL)
		}
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCapDownload+1))
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	if len(body) > maxCapDownload {
		return fmt.Errorf("%s is larger than %d bytes", url, maxCapDownload)
	}
	c, err := cap.Parse(string(body), url)
	if err != nil {
		return err
	}
	// A downloaded file must not silently take over an embedded capability:
	// a remote "claude.toml" could point the broker, and with it the stored
	// token, at any upstream. Overriding embedded caps stays a manual step.
	embedded, err := cap.Embedded()
	if err != nil {
		return err
	}
	if _, shadows := embedded[c.Name]; shadows {
		return fmt.Errorf("%q is an embedded capability; downloaded files may not replace it (copy it into %s by hand if you really want that)", c.Name, a.paths.CapsDir())
	}
	// Nor may it claim a host another capability routes: the broker would
	// refuse to load the set afterwards.
	if err := a.checkFitsInstalled(c); err != nil {
		return err
	}
	// Control characters could hide lines from the review below.
	a.printf("%s\n", strings.ToValidUTF8(stripControl(string(body)), "?"))
	a.printf("%s", stripControl(capSummary(c)))
	path := filepath.Join(a.paths.CapsDir(), c.Name+".toml")
	if _, err := os.Stat(path); err == nil {
		a.printf("note: this replaces the existing %s\n", path)
	}
	if !yes {
		a.printf("install as %s? [y/N] ", path)
		line, _ := bufio.NewReader(confirm).ReadString('\n')
		if answer := strings.ToLower(strings.TrimSpace(line)); answer != "y" && answer != "yes" {
			return fmt.Errorf("not installed")
		}
	}
	if err := os.MkdirAll(a.paths.CapsDir(), 0o700); err != nil {
		return fmt.Errorf("create caps directory: %w", err)
	}
	unlock, err := lockFile(a.paths.CapsLock())
	if err != nil {
		return err
	}
	defer unlock()
	// Check again under the lock: another `cap add` may have installed a
	// route for the same host while this one waited for confirmation.
	if err := a.checkFitsInstalled(c); err != nil {
		return err
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	a.printf("installed %s\n  grant it with: skiff grant <vm> %s\n", path, c.Name)
	return nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	return keys
}

// lockFile takes an exclusive flock on p and returns its release.
func lockFile(p string) (func(), error) {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock %s: %w", p, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// checkFitsInstalled validates the installed caps with c added or replaced.
func (a *App) checkFitsInstalled(c cap.Cap) error {
	installed, err := a.loadCaps()
	if err != nil {
		return err
	}
	merged := make(cap.Set, len(installed)+1)
	for k, v := range installed {
		merged[k] = v
	}
	merged[c.Name] = c
	if err := merged.Validate(); err != nil {
		return fmt.Errorf("%s does not fit the installed capabilities: %w", c.Name, err)
	}
	return nil
}

// capSummary spells out what a capability would do with your secrets, so the
// confirmation is about consequences rather than TOML.
func capSummary(c cap.Cap) string {
	var b strings.Builder
	switch c.Kind() {
	case cap.KindProxy:
		fmt.Fprintf(&b, "=> %s proxies guest requests to %s\n", c.Name, c.Proxy.Upstream)
		writeHeaderSecrets(&b, c.Proxy.Headers)
		for _, r := range c.Proxy.Routes {
			fmt.Fprintf(&b, "=> %s answers requests for %s with %s\n", c.Name, r.Host, r.Upstream)
			writeHeaderSecrets(&b, r.Headers)
		}
	case cap.KindMCP:
		fmt.Fprintf(&b, "=> %s runs %q on this Mac\n", c.Name, strings.Join(append([]string{c.MCP.Command}, c.MCP.Args...), " "))
	case cap.KindExec:
		fmt.Fprintf(&b, "=> %s runs %q on this Mac for every request\n", c.Name, strings.Join(append([]string{c.Exec.Command}, c.Exec.Args...), " "))
	case cap.KindTCP:
		fmt.Fprintf(&b, "=> %s lets the guest connect to %s as seen from this Mac, on guest port %d\n", c.Name, c.TCP.Upstream, c.TCP.Port)
	}
	return b.String()
}

func writeHeaderSecrets(b *strings.Builder, headers map[string]string) {
	for _, k := range sortedKeys(headers) {
		for _, ref := range secretRefs(headers[k]) {
			fmt.Fprintf(b, "   and sends the secret %s in the %s header\n", ref, k)
		}
	}
}

// secretRefs lists the secrets a header template sends. The template was
// validated by cap.Parse, which only admits literal references, so the list
// is exact: nothing a VM name or any other data could change at runtime.
func secretRefs(tmpl string) []string {
	refs, _ := cap.SecretRefs(tmpl)
	return refs
}

// stripControl replaces everything that could hide or reorder text in a
// terminal: C0 and C1 control characters (except newline and tab) and
// Unicode format characters such as bidi overrides and zero-width joiners.
func stripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return '?'
		}
		return r
	}, s)
}

func indent(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = "  " + l
	}
	return strings.Join(lines, "\n") + "\n"
}
