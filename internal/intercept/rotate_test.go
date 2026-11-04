package intercept

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func caFileBytes(t *testing.T, dir string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, caFile))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return data
}

// A grant that grows the CA must not touch the disk before the guest trusts
// the new certificate: the running broker would switch while the guest
// still trusts only the old one.
func TestPrepareWritesNothingUntilCommit(t *testing.T) {
	dir := t.TempDir()
	mustLoad(t, dir, []string{"a.example.com"}, time.Now)
	before := caFileBytes(t, dir)

	r, err := Prepare(dir, []string{"a.example.com", "b.example.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Current == nil || r.Next == nil {
		t.Fatalf("Current=%v Next=%v, want both", r.Current, r.Next)
	}
	if !bytes.Equal(caFileBytes(t, dir), before) {
		t.Fatal("Prepare changed the CA on disk")
	}
	trust := r.TrustPEM()
	if !bytes.Contains(trust, r.Current.CertPEM()) || !bytes.Contains(trust, r.Next.CertPEM()) {
		t.Fatal("during the change the guest must trust the current and the next certificate")
	}

	issued, err := r.Commit()
	if err != nil || !issued {
		t.Fatalf("Commit() = %v, %v", issued, err)
	}
	w := &Watcher{Dir: dir}
	got, err := w.Current()
	if err != nil {
		t.Fatal(err)
	}
	if !got.cert.Equal(r.Next.cert) {
		t.Fatal("after Commit the broker must see the next CA")
	}
}

func TestPrepareWithoutChange(t *testing.T) {
	dir := t.TempDir()
	current, _ := mustLoad(t, dir, []string{"a.example.com"}, time.Now)
	r, err := Prepare(dir, []string{"a.example.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Next != nil {
		t.Fatal("a covering CA must not be replaced")
	}
	if !bytes.Equal(r.TrustPEM(), current.CertPEM()) {
		t.Fatal("without a change the guest trusts exactly the current CA")
	}
	if issued, err := r.Commit(); err != nil || issued {
		t.Fatalf("Commit() = %v, %v; want a no-op", issued, err)
	}
}

func TestPrepareFirstCA(t *testing.T) {
	dir := t.TempDir()
	r, err := Prepare(dir, []string{"a.example.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Current != nil || r.Next == nil {
		t.Fatalf("Current=%v Next=%v", r.Current, r.Next)
	}
	if !bytes.Equal(r.TrustPEM(), r.Next.CertPEM()) {
		t.Fatal("a first CA is trusted alone")
	}
	if len(caFileBytes(t, dir)) != 0 {
		t.Fatal("Prepare wrote the first CA before Commit")
	}
}
