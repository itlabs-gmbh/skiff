package intercept

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Watcher hands a long-running broker the VM's current CA. A grant that
// needs a new host re-issues the CA on disk and the guest trusts only the new
// one, so the broker must pick it up without a restart; reading the file
// again only when it changed keeps the leaf certificates cached.
type Watcher struct {
	Dir string
	Now func() time.Time

	mu      sync.Mutex
	current *Authority
	modTime time.Time
	size    int64
}

// Current returns the CA as it is on disk, or nil when the VM has none.
func (w *Watcher) Current() (*Authority, error) {
	info, err := os.Stat(filepath.Join(w.Dir, caFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("intercept CA: %w", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current != nil && info.ModTime().Equal(w.modTime) && info.Size() == w.size {
		return w.current, nil
	}
	now := w.Now
	if now == nil {
		now = time.Now
	}
	a, err := load(w.Dir, now)
	if err != nil {
		return nil, err
	}
	w.current, w.modTime, w.size = a, info.ModTime(), info.Size()
	return a, nil
}
