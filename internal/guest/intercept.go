package guest

import (
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/sovyn-eu/skiff/internal/config"
)

// The guest side of the broker's intercept routes (see
// docs/design/credential-intercept.md): /etc/hosts sends each intercepted
// host to InterceptAddress, where systemd relays port 443 into the broker
// tunnel, and the VM's intercept CA joins the system trust store.
const (
	InterceptAddress     = "127.77.0.1"
	InterceptCAFile      = "/usr/local/share/ca-certificates/skiff-intercept.crt"
	InterceptSocketUnit  = "/etc/systemd/system/skiff-intercept.socket"
	InterceptServiceUnit = "/etc/systemd/system/skiff-intercept.service"
	HostsFile            = "/etc/hosts"

	// interceptOwner tags the hosts block. It is not a valid cap name, so no
	// capability can own or remove that block.
	interceptOwner = "_intercept"

	systemCABundle = "/etc/ssl/certs/ca-certificates.crt"
)

// interceptEnv points the common TLS stacks at a bundle that contains the
// intercept CA: Python requests and ssl, OpenSSL-based tools and Go read the
// system bundle, Node only adds extra certificates.
var interceptEnv = map[string]string{
	"REQUESTS_CA_BUNDLE":  systemCABundle,
	"SSL_CERT_FILE":       systemCABundle,
	"NODE_EXTRA_CA_CERTS": InterceptCAFile,
}

// interceptHostRe is stricter than DNS: the hosts end up in /etc/hosts and
// a root shell, so only characters that need no quoting pass.
var interceptHostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// Intercept is what the guest needs for the VM's intercept routes.
type Intercept struct {
	Hosts  []string
	CACert []byte
}

// WithIntercept returns a copy of the plan that also installs interception
// for hosts, trusting caPEM. The receiver is left unchanged.
func (p Plan) WithIntercept(hosts []string, caPEM []byte) (Plan, error) {
	if len(hosts) == 0 {
		return Plan{}, errors.New("intercept: no hosts")
	}
	for _, h := range hosts {
		if !interceptHostRe.MatchString(h) {
			return Plan{}, fmt.Errorf("intercept: invalid host %q", h)
		}
	}
	if err := checkCertificates(caPEM); err != nil {
		return Plan{}, err
	}
	env := maps.Clone(p.Env)
	if env == nil {
		env = map[string]string{}
	}
	for _, k := range sortedKeys(interceptEnv) {
		if _, taken := env[k]; taken {
			return Plan{}, fmt.Errorf("intercept: a granted cap already sets %s, which interception needs", k)
		}
		env[k] = interceptEnv[k]
	}
	sorted := slices.Clone(hosts)
	slices.Sort(sorted)
	out := p
	out.Env = env
	out.Intercept = &Intercept{Hosts: slices.Compact(sorted), CACert: slices.Clone(caPEM)}
	return out, nil
}

// checkCertificates accepts one or more PEM certificates and nothing else:
// while a CA changes the guest trusts the current and the next one, and no
// key may ever reach the guest.
func checkCertificates(caPEM []byte) error {
	rest := caPEM
	count := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("intercept: CA may only contain certificates, found %s", block.Type)
		}
		count++
	}
	if count == 0 || len(strings.TrimSpace(string(rest))) > 0 {
		return errors.New("intercept: CA must be PEM certificates only")
	}
	return nil
}

func (i *Intercept) manifest() []string {
	return []string{
		"file:" + InterceptCAFile, "file:" + InterceptSocketUnit, "file:" + InterceptServiceUnit,
		"block:" + HostsFile + "#" + interceptOwner,
	}
}

func isInterceptFile(p string) bool {
	return p == InterceptCAFile || p == InterceptSocketUnit || p == InterceptServiceUnit
}

// writeIntercept installs the CA (rebuilding the trust store only when it
// changed), the relay on port 443 and the hosts block.
func (i *Intercept) write(b *strings.Builder) {
	writeFile(b, InterceptCAFile+".new", "0644", i.CACert)
	newCA, ca := shQuote(InterceptCAFile+".new"), shQuote(InterceptCAFile)
	// A failed rebuild removes the CA again, so the next grant sees a change
	// and retries instead of skipping identical bytes.
	b.WriteString("if cmp -s " + newCA + " " + ca + "; then rm -f " + newCA + "; else mv -f " + newCA + " " + ca + "; " + updateTrust("", "rm -f "+ca) + "; fi\n")
	writeFile(b, InterceptSocketUnit, "0644", []byte(interceptSocket()))
	writeFile(b, InterceptServiceUnit, "0644", []byte(interceptService()))
	b.WriteString("if " + asRootOnSystemd + "; then systemctl daemon-reload && systemctl --quiet enable --now " + path.Base(InterceptSocketUnit) + "; fi\n")
	writeBlock(b, HostsFile, interceptOwner, "#", InterceptAddress+" "+strings.Join(i.Hosts, " ")+"\n")
}

// stopIntercept stops the relay before its units are removed; best effort,
// like stopRelay.
func stopIntercept(b *strings.Builder) {
	b.WriteString("if " + asRootOnSystemd + "; then systemctl disable --now " +
		path.Base(InterceptSocketUnit) + " " + path.Base(InterceptServiceUnit) + " >/dev/null 2>&1 || true; fi\n")
}

// updateTrust rebuilds the system trust store. It only runs as root: tests
// execute the scripts under a temporary root as an ordinary user, where the
// real tool would try to rewrite the host's store.
// onFail runs before the script fails, to undo what made the rebuild
// necessary.
func updateTrust(flags, onFail string) string {
	cmd := "update-ca-certificates"
	if flags != "" {
		cmd += " " + flags
	}
	undo := ""
	if onFail != "" {
		undo = onFail + "; "
	}
	// Its routine warnings about the bundle would show on every grant; the
	// output is printed only when it fails.
	return `if [ "$(id -u)" = 0 ] && command -v update-ca-certificates >/dev/null; then ` +
		`out=$(` + cmd + ` 2>&1) || { echo "$out" >&2; ` + undo + `exit 1; }; fi`
}

func interceptSocket() string {
	return fmt.Sprintf(`[Unit]
Description=skiff broker for intercepted HTTPS hosts

[Socket]
ListenStream=%s:443

[Install]
WantedBy=sockets.target
`, InterceptAddress)
}

func interceptService() string {
	return fmt.Sprintf(`[Unit]
Description=skiff relay of intercepted HTTPS to the SSH tunnel
Requires=skiff-intercept.socket
After=skiff-intercept.socket

[Service]
ExecStart=/usr/lib/systemd/systemd-socket-proxyd 127.0.0.1:%d
`, config.BrokerGuestPort)
}

func isInterceptUnit(p string) bool {
	return p == InterceptSocketUnit || p == InterceptServiceUnit
}
