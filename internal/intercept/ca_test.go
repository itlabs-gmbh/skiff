package intercept

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func clockAt(t *time.Time) func() time.Time { return func() time.Time { return *t } }

func mustLoad(t *testing.T, dir string, hosts []string, now func() time.Time) (*Authority, bool) {
	t.Helper()
	a, created, err := LoadOrCreate(dir, hosts, now)
	if err != nil {
		t.Fatalf("LoadOrCreate(%v): %v", hosts, err)
	}
	return a, created
}

func pool(a *Authority) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(a.cert)
	return p
}

func TestLoadOrCreateWritesConstrainedCA(t *testing.T) {
	dir := t.TempDir()
	now := t0
	a, created := mustLoad(t, dir, []string{"graph.microsoft.com", "management.azure.com"}, clockAt(&now))
	if !created {
		t.Fatal("created = false for an empty directory")
	}
	c := a.cert
	if !c.IsCA || !c.MaxPathLenZero || c.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Errorf("not a leaf-only CA: IsCA=%v MaxPathLenZero=%v KeyUsage=%v", c.IsCA, c.MaxPathLenZero, c.KeyUsage)
	}
	if !c.PermittedDNSDomainsCritical {
		t.Error("name constraints are not critical")
	}
	if want := []string{"graph.microsoft.com", "management.azure.com"}; !slices.Equal(c.PermittedDNSDomains, want) {
		t.Errorf("PermittedDNSDomains = %v, want %v", c.PermittedDNSDomains, want)
	}
	info, err := os.Stat(filepath.Join(dir, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key mode = %v, want 0600", perm)
	}
	block, _ := pem.Decode(a.CertPEM())
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("CertPEM is not a PEM certificate: %q", a.CertPEM())
	}
}

func TestLoadOrCreateRejectsNoHosts(t *testing.T) {
	if _, _, err := LoadOrCreate(t.TempDir(), nil, time.Now); err == nil {
		t.Fatal("expected an error for a CA without hosts")
	}
}

func TestLoadOrCreateReuse(t *testing.T) {
	tests := []struct {
		name        string
		first, next []string
		after       time.Duration
		wantCreated bool
		wantDomains []string
	}{
		{"same hosts", []string{"a.example.com"}, []string{"a.example.com"}, 0, false, []string{"a.example.com"}},
		{"fewer hosts keep the CA", []string{"a.example.com", "b.example.com"}, []string{"a.example.com"}, 0, false, []string{"a.example.com", "b.example.com"}},
		{"subdomain is covered", []string{"example.com"}, []string{"api.example.com"}, 0, false, []string{"example.com"}},
		{"new host grows the CA", []string{"a.example.com"}, []string{"b.example.com"}, 0, true, []string{"a.example.com", "b.example.com"}},
		{"expiring CA is renewed", []string{"a.example.com"}, []string{"a.example.com"}, caValidity - caRenewBefore + time.Hour, true, []string{"a.example.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			now := t0
			first, _ := mustLoad(t, dir, tt.first, clockAt(&now))
			now = now.Add(tt.after)
			next, created := mustLoad(t, dir, tt.next, clockAt(&now))
			if created != tt.wantCreated {
				t.Errorf("created = %v, want %v", created, tt.wantCreated)
			}
			if !slices.Equal(next.cert.PermittedDNSDomains, tt.wantDomains) {
				t.Errorf("PermittedDNSDomains = %v, want %v", next.cert.PermittedDNSDomains, tt.wantDomains)
			}
			if same := first.cert.Equal(next.cert); same == tt.wantCreated {
				t.Errorf("same certificate = %v after created = %v", same, tt.wantCreated)
			}
		})
	}
}

func TestLoadOrCreateRejectsDamagedFiles(t *testing.T) {
	dir := t.TempDir()
	mustLoad(t, dir, []string{"a.example.com"}, time.Now)
	if err := os.WriteFile(filepath.Join(dir, keyFile), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreate(dir, []string{"a.example.com"}, time.Now); err == nil {
		t.Fatal("expected an error for a damaged key, not a silent new CA")
	}
}

func TestLoadOrCreateRejectsMismatchedKey(t *testing.T) {
	dir, other := t.TempDir(), t.TempDir()
	mustLoad(t, dir, []string{"a.example.com"}, time.Now)
	mustLoad(t, other, []string{"a.example.com"}, time.Now)
	foreign, err := os.ReadFile(filepath.Join(other, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, keyFile), foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreate(dir, []string{"a.example.com"}, time.Now); err == nil {
		t.Fatal("expected an error for a key of another CA")
	}
}

func TestLoadOrCreateRejectsMissingKey(t *testing.T) {
	dir := t.TempDir()
	mustLoad(t, dir, []string{"a.example.com"}, time.Now)
	if err := os.Remove(filepath.Join(dir, keyFile)); err != nil {
		t.Fatal(err)
	}
	if _, created, err := LoadOrCreate(dir, []string{"a.example.com"}, time.Now); err != nil || !created {
		t.Fatalf("missing key: created=%v err=%v, want a new CA", created, err)
	}
}

func TestLeafVerifiesForCoveredHost(t *testing.T) {
	now := t0
	a, _ := mustLoad(t, t.TempDir(), []string{"management.azure.com"}, clockAt(&now))
	leaf, err := a.Leaf("management.azure.com")
	if err != nil {
		t.Fatal(err)
	}
	_, err = leaf.Leaf.Verify(x509.VerifyOptions{
		DNSName: "management.azure.com", Roots: pool(a), CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Errorf("leaf does not verify: %v", err)
	}
}

func TestLeafRefusesUncoveredHost(t *testing.T) {
	a, _ := mustLoad(t, t.TempDir(), []string{"management.azure.com"}, time.Now)
	for _, host := range []string{"evil.example.com", "azure.com", "", "management.azure.com.evil.example.com"} {
		if _, err := a.Leaf(host); err == nil {
			t.Errorf("Leaf(%q) issued a certificate", host)
		}
	}
}

// The name constraints must hold even for a certificate the CA key signs
// outside Leaf, so a leaked key cannot vouch for other sites.
func TestNameConstraintsEnforcedByVerify(t *testing.T) {
	now := t0
	a, _ := mustLoad(t, t.TempDir(), []string{"management.azure.com"}, clockAt(&now))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "www.example.com"},
		DNSNames:     []string{"www.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	_, err = forged.Verify(x509.VerifyOptions{DNSName: "www.example.com", Roots: pool(a), CurrentTime: now})
	if err == nil {
		t.Fatal("a certificate outside the name constraints verified")
	}
}

func TestLeafIsCachedAndRenewed(t *testing.T) {
	now := t0
	a, _ := mustLoad(t, t.TempDir(), []string{"management.azure.com"}, clockAt(&now))
	first, err := a.Leaf("management.azure.com")
	if err != nil {
		t.Fatal(err)
	}
	again, err := a.Leaf("management.azure.com")
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Error("second Leaf call issued a new certificate")
	}
	now = now.Add(leafValidity - leafRenewBefore + time.Minute)
	renewed, err := a.Leaf("management.azure.com")
	if err != nil {
		t.Fatal(err)
	}
	if renewed == first {
		t.Error("leaf close to expiry was not renewed")
	}
}
