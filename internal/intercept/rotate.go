package intercept

import (
	"errors"
	"io/fs"
	"time"
)

// Rotation is a pending change of a VM's CA. The guest must trust both
// certificates while it changes; only Commit writes the next CA, so the
// broker keeps presenting the current one until the guest is updated.
type Rotation struct {
	dir string
	// Current is the CA on disk, nil when the VM has none.
	Current *Authority
	// Next is a new CA issued in memory, nil when Current covers every host
	// and is not about to expire.
	Next *Authority
}

// Prepare loads the CA in dir and, when there is none, when it does not
// cover every host or when it is about to expire, issues the next one in
// memory. A CA only grows: hosts it covers but that are no longer requested
// stay permitted, because grants are checked per request anyway.
func Prepare(dir string, hosts []string, now func() time.Time) (*Rotation, error) {
	hosts = normalize(hosts)
	if len(hosts) == 0 {
		return nil, errors.New("intercept CA: no hosts to cover")
	}
	current, err := load(dir, now)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	r := &Rotation{dir: dir, Current: current}
	if current != nil && current.coversAll(hosts) && current.cert.NotAfter.Sub(now()) > caRenewBefore {
		return r, nil
	}
	if current != nil {
		hosts = normalize(append(hosts, current.cert.PermittedDNSDomains...))
	}
	if r.Next, err = create(hosts, now); err != nil {
		return nil, err
	}
	return r, nil
}

// TrustPEM is what the guest must trust while the change is in flight.
func (r *Rotation) TrustPEM() []byte {
	var out []byte
	for _, a := range []*Authority{r.Current, r.Next} {
		if a != nil {
			out = append(out, a.CertPEM()...)
		}
	}
	return out
}

// Active is the CA the broker uses after Commit.
func (r *Rotation) Active() *Authority {
	if r.Next != nil {
		return r.Next
	}
	return r.Current
}

// Commit writes the next CA, replacing the current one; it reports whether
// there was one to write.
func (r *Rotation) Commit() (bool, error) {
	if r.Next == nil {
		return false, nil
	}
	if err := r.Next.save(r.dir); err != nil {
		return false, err
	}
	return true, nil
}
