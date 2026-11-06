package cap

import (
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/sovyn-eu/skiff/internal/config"
)

// TCP configures the tcp primitive: a port on the guest's loopback that
// reaches an address on the Mac. The broker checks the grant for every
// connection and then only carries bytes; it injects nothing. Whatever
// authenticates upstream, such as a database proxy that holds the password,
// runs on the Mac, so the guest connects without a credential.
type TCP struct {
	// Upstream is where connections go: host:port, or unix:/absolute/path
	// for a Unix socket on the Mac.
	Upstream string `toml:"upstream"`
	// Port is the port on the guest's 127.0.0.1.
	Port int `toml:"port"`
}

const (
	unixPrefix = "unix:"
	// guestSSHPort is where the guest's sshd listens.
	guestSSHPort = 22
	maxPort      = 65535
)

// Dial returns the network and address of the upstream, as net.Dial takes
// them. The upstream was validated when the capability was parsed.
func (t TCP) Dial() (network, address string) {
	if p, ok := strings.CutPrefix(t.Upstream, unixPrefix); ok {
		return "unix", p
	}
	return "tcp", t.Upstream
}

func (t TCP) validate() []string {
	var problems []string
	switch {
	case t.Upstream == "":
		problems = append(problems, "tcp.upstream is required")
	case !validTCPUpstream(t.Upstream):
		problems = append(problems, fmt.Sprintf("tcp.upstream must be host:port or unix:/absolute/path, not %q", t.Upstream))
	}
	switch {
	case t.Port < 1 || t.Port > maxPort:
		problems = append(problems, "tcp.port must be between 1 and 65535")
	case t.Port == config.BrokerGuestPort:
		problems = append(problems, fmt.Sprintf("tcp.port %d is the broker's own port in the guest", t.Port))
	case t.Port == guestSSHPort:
		problems = append(problems, fmt.Sprintf("tcp.port %d is the guest's SSH port", t.Port))
	}
	return problems
}

// validTCPUpstream accepts host:port and unix:/absolute/path in one spelling
// each. The value is shown in `skiff cap add` and written to the audit log,
// so it must not carry whitespace or control characters.
func validTCPUpstream(upstream string) bool {
	if strings.ContainsFunc(upstream, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return false
	}
	if p, ok := strings.CutPrefix(upstream, unixPrefix); ok {
		return filepath.IsAbs(p) && filepath.Clean(p) == p
	}
	host, port, err := net.SplitHostPort(upstream)
	if err != nil || host == "" || strings.ContainsAny(host, "/{}") {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= maxPort
}

// TCPForward is one guest port a session has to forward for a granted tcp
// capability.
type TCPForward struct {
	Cap      string
	Port     int
	Upstream string
}

// TCPForwards lists what the granted tcp capabilities forward, in name
// order. Unknown names are ignored: a grant may outlive the capability file
// it names. Two granted capabilities on one guest port are an error, because
// only one of them could be reached there.
func (s Set) TCPForwards(granted []string) ([]TCPForward, error) {
	names := slices.Clone(granted)
	slices.Sort(names)
	var forwards []TCPForward
	owner := map[int]string{}
	for _, name := range names {
		c, ok := s[name]
		if !ok || c.TCP == nil {
			continue
		}
		if other, dup := owner[c.TCP.Port]; dup {
			if other == name {
				continue
			}
			return nil, fmt.Errorf("caps %s and %s both forward guest port %d; revoke one of them or change its tcp.port", other, name, c.TCP.Port)
		}
		owner[c.TCP.Port] = name
		forwards = append(forwards, TCPForward{Cap: name, Port: c.TCP.Port, Upstream: c.TCP.Upstream})
	}
	return forwards, nil
}
