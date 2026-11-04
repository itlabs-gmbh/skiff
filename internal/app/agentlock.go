package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// agentLockPath is a per-VM lock that ties SSH agent forwarding and the
// profile setup together: sessions that forward the agent hold it shared,
// a setup holds it exclusive. Agent forwarding is not served by the broker,
// so the broker claim alone would not keep a root setup script away from a
// forwarded agent socket.
func (a *App) agentLockPath(name string) string {
	return filepath.Join(a.paths.VMsDir(), name+".agent.lock")
}

// errAgentLockBusy reports that the other side holds the lock.
var errAgentLockBusy = errors.New("agent lock busy")

// lockAgent takes the VM's agent lock, shared or exclusive, without
// waiting; errAgentLockBusy when the other side holds it.
func (a *App) lockAgent(name string, exclusive bool) (func(), error) {
	if err := os.MkdirAll(a.paths.VMsDir(), 0o700); err != nil {
		return nil, fmt.Errorf("create vm state: %w", err)
	}
	f, err := os.OpenFile(a.agentLockPath(name), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open agent lock: %w", err)
	}
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errAgentLockBusy
		}
		return nil, fmt.Errorf("lock agent forwarding of %s: %w", name, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
