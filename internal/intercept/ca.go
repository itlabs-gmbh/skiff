// Package intercept holds the TLS side of the broker's intercept routes: a
// per-VM certificate authority whose key never leaves the Mac. The guest
// trusts only its certificate, which is name-constrained to the hosts the
// VM's capabilities intercept, so even a leaked key could not vouch for any
// other site. See docs/design/credential-intercept.md.
package intercept

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	certFile = "ca.pem"
	keyFile  = "ca.key"

	// caValidity is how long a CA lives; it is renewed caRenewBefore its end
	// the next time the VM is provisioned.
	caValidity    = 365 * 24 * time.Hour
	caRenewBefore = 30 * 24 * time.Hour

	// leafValidity bounds the certificates the broker presents to the guest.
	leafValidity    = 24 * time.Hour
	leafRenewBefore = time.Hour

	// clockSkew backdates certificates so a guest clock slightly behind the
	// Mac's still accepts them.
	clockSkew = 5 * time.Minute
)

// reservedDomain can never be registered (RFC 2606); permitting only it
// forbids a name type.
const reservedDomain = "invalid"

var allIPs = []*net.IPNet{
	{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
	{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
}

// Authority is a VM's intercept CA.
type Authority struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	now     func() time.Time

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// LoadOrCreate returns the CA stored in dir. It issues a new one when there
// is none, when the stored one does not cover every host or when it is about
// to expire; created reports that, since the guest must then trust the new
// certificate. A CA only grows: hosts it covers but that are no longer
// requested stay permitted, because grants are checked per request anyway.
func LoadOrCreate(dir string, hosts []string, now func() time.Time) (a *Authority, created bool, err error) {
	hosts = normalize(hosts)
	if len(hosts) == 0 {
		return nil, false, errors.New("intercept CA: no hosts to cover")
	}
	existing, err := load(dir, now)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, false, err
	}
	if existing != nil && existing.coversAll(hosts) && existing.cert.NotAfter.Sub(now()) > caRenewBefore {
		return existing, false, nil
	}
	if existing != nil {
		hosts = normalize(append(hosts, existing.cert.PermittedDNSDomains...))
	}
	a, err = create(hosts, now)
	if err != nil {
		return nil, false, err
	}
	if err := a.save(dir); err != nil {
		return nil, false, err
	}
	return a, true, nil
}

// CertPEM is the certificate the guest must trust.
func (a *Authority) CertPEM() []byte { return a.certPEM }

// Leaf returns a server certificate for host, issuing it on first use and
// again shortly before it expires.
func (a *Authority) Leaf(host string) (*tls.Certificate, error) {
	if !covered(a.cert.PermittedDNSDomains, host) {
		return nil, fmt.Errorf("intercept CA does not cover %q", host)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.leaves[host]; ok && c.Leaf.NotAfter.Sub(a.now()) > leafRenewBefore {
		return c, nil
	}
	c, err := a.issueLeaf(host)
	if err != nil {
		return nil, err
	}
	a.leaves[host] = c
	return c, nil
}

func (a *Authority) issueLeaf(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("leaf key for %s: %w", host, err)
	}
	now := a.now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, fmt.Errorf("leaf certificate for %s: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("leaf certificate for %s: %w", host, err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func create(hosts []string, now func() time.Time) (*Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("intercept CA key: %w", err)
	}
	start := now()
	tmpl := &x509.Certificate{
		SerialNumber:                serial(),
		Subject:                     pkix.Name{CommonName: "skiff intercept CA", Organization: []string{"skiff"}},
		NotBefore:                   start.Add(-clockSkew),
		NotAfter:                    start.Add(caValidity),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLenZero:              true,
		KeyUsage:                    x509.KeyUsageCertSign,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         hosts,
		// A missing constraint leaves a name type unconstrained, so close the
		// others explicitly: no IPs at all, and email and URI names only under
		// the reserved TLD "invalid", which nothing can use.
		ExcludedIPRanges:        allIPs,
		PermittedEmailAddresses: []string{reservedDomain},
		PermittedURIDomains:     []string{reservedDomain},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("intercept CA certificate: %w", err)
	}
	return newAuthority(der, key, now)
}

func newAuthority(der []byte, key *ecdsa.PrivateKey, now func() time.Time) (*Authority, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("intercept CA certificate: %w", err)
	}
	if !cert.IsCA || !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("intercept CA: certificate and key do not belong together")
	}
	return &Authority{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		now:     now,
		leaves:  map[string]*tls.Certificate{},
	}, nil
}

// load reads the CA from dir; a missing CA is fs.ErrNotExist, a damaged one
// is an error rather than a reason to replace it silently.
func load(dir string, now func() time.Time) (*Authority, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, certFile))
	if err != nil {
		return nil, fmt.Errorf("read intercept CA: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, keyFile))
	if err != nil {
		return nil, fmt.Errorf("read intercept CA key: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		return nil, fmt.Errorf("intercept CA in %s is damaged; remove %s and %s to issue a new one", dir, certFile, keyFile)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("intercept CA key in %s: %w", dir, err)
	}
	return newAuthority(certBlock.Bytes, key, now)
}

// save writes key and certificate, each through a temporary file so a crash
// never leaves half a file behind.
func (a *Authority) save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	keyDER, err := x509.MarshalECPrivateKey(a.key)
	if err != nil {
		return fmt.Errorf("encode intercept CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := writeAtomic(filepath.Join(dir, keyFile), keyPEM, 0o600); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, certFile), a.certPEM, 0o644)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func (a *Authority) coversAll(hosts []string) bool {
	for _, h := range hosts {
		if !covered(a.cert.PermittedDNSDomains, h) {
			return false
		}
	}
	return true
}

// covered applies the x509 name-constraint rule: a permitted domain covers
// itself and every name below it.
func covered(domains []string, host string) bool {
	if host == "" {
		return false
	}
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// normalize lowercases, sorts and de-duplicates hosts.
func normalize(hosts []string) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			out = append(out, h)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err)) // never on supported platforms
	}
	return n
}
