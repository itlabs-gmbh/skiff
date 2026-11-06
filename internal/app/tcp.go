package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sovyn-eu/skiff/internal/broker"
	"github.com/sovyn-eu/skiff/internal/cap"
	"github.com/sovyn-eu/skiff/internal/grant"
)

// tcpForwards lists the guest ports the granted tcp capabilities need and
// refuses what skiff cannot or must not serve: two capabilities on one port,
// and an upstream among skiff's own sockets.
func (a *App) tcpForwards(caps cap.Set, set grant.Set) ([]cap.TCPForward, error) {
	forwards, err := caps.TCPForwards(set.Caps())
	if err != nil {
		return nil, err
	}
	for _, f := range forwards {
		if a.ownSocket(f.Upstream) {
			return nil, fmt.Errorf("cap %s: tcp.upstream %s is one of skiff's own sockets; a VM that reached another VM's broker there would use that VM's grants", f.Cap, f.Upstream)
		}
	}
	return forwards, nil
}

// ownSocket reports whether upstream is a Unix socket in skiff's run
// directory, where the brokers of all VMs listen. Directories are compared
// by identity, not by spelling: on the Mac's case-insensitive file system
// run/ and RUN/ are the same directory, and a symlink may lead there too,
// as a directory on the way or as the socket's own name. A link made after
// the check is not seen; making one takes write access on the Mac, which
// the guest and a capability file do not have.
func (a *App) ownSocket(upstream string) bool {
	network, address := cap.TCP{Upstream: upstream}.Dial()
	if network != "unix" {
		return false
	}
	run, err := os.Stat(a.paths.RunDir())
	if err != nil {
		// Before the run directory exists only its spelling can be compared.
		// The check runs again when a session starts, and the directory
		// exists by then.
		rel, err := filepath.Rel(a.paths.RunDir(), address)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	// A socket path that is itself a symlink is judged by where it leads.
	if target, err := filepath.EvalSymlinks(address); err == nil {
		address = target
	}
	// The socket itself need not exist yet; its directory decides.
	for dir := filepath.Dir(address); ; dir = filepath.Dir(dir) {
		if info, err := os.Stat(dir); err == nil && os.SameFile(info, run) {
			return true
		}
		if dir == filepath.Dir(dir) {
			return false
		}
	}
}

// serveTCP binds the socket of every tcp forward and hands it to the broker,
// which closes the listeners when it is closed. When one cannot be served,
// the sockets bound so far are removed and the caller closes the broker.
func (a *App) serveTCP(b *broker.Broker, name string, caps cap.Set, forwards []cap.TCPForward) ([]TCPSocket, error) {
	var served []TCPSocket
	for _, f := range forwards {
		s := TCPSocket{Cap: f.Cap, Port: f.Port, Socket: a.paths.TCPSocketPath(name, f.Port)}
		ln, err := broker.Listen(s.Socket)
		if err == nil {
			err = b.ServeTCP(caps[f.Cap], ln)
		}
		if err != nil {
			removeSockets(served)
			return nil, fmt.Errorf("cap %s: %w", f.Cap, err)
		}
		served = append(served, s)
	}
	return served, nil
}

// removeSockets deletes the socket files of tcp capabilities; closing their
// listeners usually has already, this covers the ones it left.
func removeSockets(sockets []TCPSocket) {
	for _, s := range sockets {
		_ = os.Remove(s.Socket)
	}
}

// recordTCPForwards notes which tcp capabilities the VM's broker serves from
// now on. The file is replaced at every start, an empty list included, so
// what a crashed broker left behind never describes a later one.
func (a *App) recordTCPForwards(name string, served []TCPSocket) error {
	data, err := json.Marshal(served)
	if err != nil {
		return fmt.Errorf("encode tcp forwards: %w", err)
	}
	if err := os.WriteFile(a.paths.TCPForwardsPath(name), data, 0o600); err != nil {
		return fmt.Errorf("record tcp forwards: %w", err)
	}
	return nil
}

// servedTCP reports whether the VM's running broker forwards the guest port
// of the tcp capability capName. It reads the record instead of probing the
// socket: a connection there would be relayed to the upstream like one from
// the guest, and the socket's name tells the port, not the capability.
func (a *App) servedTCP(name, capName string, port int) bool {
	data, err := os.ReadFile(a.paths.TCPForwardsPath(name))
	if err != nil {
		return false
	}
	var served []TCPSocket
	if err := json.Unmarshal(data, &served); err != nil {
		return false
	}
	return slices.ContainsFunc(served, func(s TCPSocket) bool { return s.Cap == capName && s.Port == port })
}

// noteTCPForwards says that the tcp capabilities among requested only reach
// the guest through sessions started from now on: ssh fixes its forwards
// when it connects, so a session that is already open cannot add one. It
// stays quiet about a capability the open session forwards already, which
// is the case when it is granted again after a revoke.
func (a *App) noteTCPForwards(name string, caps cap.Set, requested grant.Set) {
	if !broker.Alive(a.paths.SocketPath(name)) {
		return
	}
	for _, g := range requested {
		c, ok := caps[g.Cap]
		if !ok || c.TCP == nil || a.servedTCP(name, g.Cap, c.TCP.Port) {
			continue
		}
		a.printf("note: %s reaches guest port %d through sessions and tunnels opened from now on; close the open ones first\n", g.Cap, c.TCP.Port)
	}
}
