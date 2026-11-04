package intercept

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatcherWithoutCAReturnsNil(t *testing.T) {
	w := &Watcher{Dir: filepath.Join(t.TempDir(), "missing"), Now: time.Now}
	a, err := w.Current()
	if err != nil || a != nil {
		t.Fatalf("Current() = %v, %v; want nil, nil", a, err)
	}
}

func TestWatcherKeepsAuthorityUntilFileChanges(t *testing.T) {
	dir := t.TempDir()
	mustLoad(t, dir, []string{"a.example.com"}, time.Now)
	w := &Watcher{Dir: dir, Now: time.Now}
	first, err := w.Current()
	if err != nil || first == nil {
		t.Fatalf("Current() = %v, %v", first, err)
	}
	again, err := w.Current()
	if err != nil || again != first {
		t.Fatal("unchanged CA was reloaded; leaf certificates would not be cached")
	}

	// A grant that needs another host re-issues the CA on disk.
	mustLoad(t, dir, []string{"b.example.com"}, time.Now)
	// Make the change visible even on file systems with coarse timestamps.
	later := time.Now().Add(time.Second)
	if err := os.Chtimes(filepath.Join(dir, caFile), later, later); err != nil {
		t.Fatal(err)
	}
	renewed, err := w.Current()
	if err != nil {
		t.Fatal(err)
	}
	if renewed == first || !renewed.coversAll([]string{"b.example.com"}) {
		t.Fatal("re-issued CA was not picked up")
	}
}

func TestWatcherReportsDamagedCA(t *testing.T) {
	dir := t.TempDir()
	mustLoad(t, dir, []string{"a.example.com"}, time.Now)
	if err := os.WriteFile(filepath.Join(dir, caFile), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := &Watcher{Dir: dir, Now: time.Now}
	if _, err := w.Current(); err == nil {
		t.Fatal("expected an error for a damaged CA")
	}
}
