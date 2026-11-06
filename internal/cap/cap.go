// Package cap defines capabilities: declarative descriptions of how the
// broker on the Mac hands a connection into a microVM and what the guest needs
// to use it. skiff's core knows four primitives (proxy, mcp, exec, tcp);
// every harness-specific detail lives in a TOML file, never in Go code.
package cap

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Kind is the broker primitive a capability uses.
type Kind string

const (
	// KindProxy is a header-injecting reverse proxy to an upstream URL.
	KindProxy Kind = "proxy"
	// KindMCP runs a stdio MCP server on the Mac and exposes it as an HTTP MCP endpoint.
	KindMCP Kind = "mcp"
	// KindExec delegates each request to an external program.
	KindExec Kind = "exec"
	// KindTCP hands a port in the guest to an address on the Mac.
	KindTCP Kind = "tcp"
)

const maxNameLength = 32

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// Cap is one capability as declared in a TOML file.
type Cap struct {
	Name        string `toml:"name"`
	Description string `toml:"description"`
	Proxy       *Proxy `toml:"proxy"`
	MCP         *MCP   `toml:"mcp"`
	Exec        *Exec  `toml:"exec"`
	TCP         *TCP   `toml:"tcp"`
	Guest       Guest  `toml:"guest"`

	// Source records where the definition came from ("embedded" or a file path).
	Source string `toml:"-"`
}

// Proxy configures the reverse-proxy primitive.
type Proxy struct {
	// Upstream is the base URL requests are forwarded to.
	Upstream string `toml:"upstream"`
	// Headers are set on every upstream request; values are templates that
	// may call {{ secret "ref" }}.
	Headers map[string]string `toml:"headers"`
	// StripHeaders are removed from the guest's request in addition to the
	// built-in credential headers.
	StripHeaders []string `toml:"strip_headers"`
	// AllowHeaders, when set, is the only set of guest headers passed through.
	AllowHeaders []string `toml:"allow_headers"`
	// Routes reach further upstreams of the same capability by Host header.
	Routes []Route `toml:"routes"`
}

// MCP configures the stdio-to-HTTP MCP bridge primitive.
type MCP struct {
	Command string            `toml:"command"`
	Args    []string          `toml:"args"`
	Env     map[string]string `toml:"env"`
}

// Exec configures the external-program primitive. The program receives the
// request body on stdin and answers on stdout.
type Exec struct {
	Command string   `toml:"command"`
	Args    []string `toml:"args"`
}

// Guest describes what the microVM needs so its tools use the capability.
// Every string is a template with access to .VM, .BrokerURL and .PseudoToken.
type Guest struct {
	// Env is added to /etc/environment in the guest.
	Env map[string]string `toml:"env"`
	// Files are written verbatim (after templating).
	Files []File `toml:"files"`
	// Blocks are managed sections appended to existing files, delimited by
	// marker comments and removed again on revoke. Use them for shared
	// configuration files such as /etc/gitconfig.
	Blocks []Block `toml:"blocks"`
	// JSONMerge sets a dotted key inside a JSON file, creating it if needed.
	JSONMerge []JSONMerge `toml:"json_merge"`
}

// File is a guest file to write.
type File struct {
	Path    string `toml:"path"`
	Mode    string `toml:"mode"`
	Content string `toml:"content"`
}

// Block is a managed section inside an existing file. Comment is the line
// comment prefix of the file's syntax ("#" by default) used for the markers.
type Block struct {
	Path    string `toml:"path"`
	Comment string `toml:"comment"`
	Content string `toml:"content"`
}

// JSONMerge sets Key (dotted, e.g. mcpServers.chrome-devtools) in Path to Value.
type JSONMerge struct {
	Path  string `toml:"path"`
	Key   string `toml:"key"`
	Value any    `toml:"value"`
}

// Kind reports which primitive the capability uses.
func (c Cap) Kind() Kind {
	switch {
	case c.Proxy != nil:
		return KindProxy
	case c.MCP != nil:
		return KindMCP
	case c.Exec != nil:
		return KindExec
	case c.TCP != nil:
		return KindTCP
	}
	return ""
}

// ValidateName enforces the same label rules as VM names so cap names are
// safe in URL paths, grant files and file names.
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("cap name must not be empty")
	}
	if len(name) > maxNameLength {
		return fmt.Errorf("cap name %q is longer than %d characters", name, maxNameLength)
	}
	if !nameRe.MatchString(name) {
		return fmt.Errorf("cap name %q must be lowercase letters, digits and dashes, starting with a letter", name)
	}
	return nil
}

// Validate checks the declaration for structural problems; the returned
// error lists every finding so a user can fix them in one go.
func (c Cap) Validate() error {
	var problems []string
	if err := ValidateName(c.Name); err != nil {
		problems = append(problems, err.Error())
	}
	problems = append(problems, c.validateKind()...)
	problems = append(problems, c.validateGuest()...)
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("cap %q: %s", c.Name, strings.Join(problems, "; "))
}

func (c Cap) validateKind() []string {
	kinds := 0
	for _, present := range []bool{c.Proxy != nil, c.MCP != nil, c.Exec != nil, c.TCP != nil} {
		if present {
			kinds++
		}
	}
	if kinds != 1 {
		return []string{"exactly one of [proxy], [mcp], [exec] or [tcp] is required"}
	}
	switch c.Kind() {
	case KindProxy:
		return c.Proxy.validate()
	case KindMCP:
		if c.MCP.Command == "" {
			return []string{"mcp.command is required"}
		}
	case KindExec:
		if c.Exec.Command == "" {
			return []string{"exec.command is required"}
		}
	case KindTCP:
		return c.TCP.validate()
	}
	return nil
}

func (p Proxy) validate() []string {
	var problems []string
	if err := validateUpstream(p.Upstream); err != nil {
		problems = append(problems, err.Error())
	}
	problems = append(problems, validateHeaders("proxy.headers", p.Headers)...)
	return append(problems, p.validateRoutes()...)
}

// validateUpstream insists on TLS: the broker injects credentials, which
// must not travel in cleartext. Loopback is exempt for local gateways.
func validateUpstream(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("proxy.upstream must be an http(s) URL")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return fmt.Errorf("proxy.upstream %s would send credentials in cleartext; use https (http is only allowed for localhost)", raw)
	}
	return fmt.Errorf("proxy.upstream must be an http(s) URL")
}

func (c Cap) validateGuest() []string {
	var problems []string
	for _, k := range sortedKeys(c.Guest.Env) {
		if !envNameRe.MatchString(k) {
			problems = append(problems, fmt.Sprintf("guest.env: invalid variable name %q", k))
		}
		if err := checkTemplate(c.Guest.Env[k], false); err != nil {
			problems = append(problems, fmt.Sprintf("guest.env.%s: %v", k, err))
		}
	}
	for i, f := range c.Guest.Files {
		if !strings.HasPrefix(f.Path, "/") {
			problems = append(problems, fmt.Sprintf("guest.files[%d]: path must be absolute", i))
		}
		if f.Mode != "" && !modeRe.MatchString(f.Mode) {
			problems = append(problems, fmt.Sprintf("guest.files[%d]: mode must be octal like 0644", i))
		}
		if err := checkTemplate(f.Content, false); err != nil {
			problems = append(problems, fmt.Sprintf("guest.files[%d].content: %v", i, err))
		}
	}
	for i, b := range c.Guest.Blocks {
		if !strings.HasPrefix(b.Path, "/") {
			problems = append(problems, fmt.Sprintf("guest.blocks[%d]: path must be absolute", i))
		}
		if b.Comment != "" && b.Comment != "#" && b.Comment != ";" && b.Comment != "//" {
			problems = append(problems, fmt.Sprintf("guest.blocks[%d]: comment must be #, ; or //", i))
		}
		if err := checkTemplate(b.Content, false); err != nil {
			problems = append(problems, fmt.Sprintf("guest.blocks[%d].content: %v", i, err))
		}
	}
	for i, m := range c.Guest.JSONMerge {
		if !strings.HasPrefix(m.Path, "/") {
			problems = append(problems, fmt.Sprintf("guest.json_merge[%d]: path must be absolute", i))
		}
		if m.Key == "" {
			problems = append(problems, fmt.Sprintf("guest.json_merge[%d]: key is required", i))
		}
		if err := checkValueTemplates(m.Value, false); err != nil {
			problems = append(problems, fmt.Sprintf("guest.json_merge[%d].value: %v", i, err))
		}
	}
	return problems
}

var (
	envNameRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	modeRe    = regexp.MustCompile(`^0[0-7]{3}$`)
)

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
