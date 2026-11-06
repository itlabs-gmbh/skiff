// Package config holds the constants and filesystem layout used by skiff.
package config

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	// Instance is the ssh host alias suffix: VMs are reached as <vm>.skiff.
	Instance = "skiff"

	DefaultVCPUs  = 2
	DefaultMemMiB = 1024

	// BrokerGuestPort is where the broker tunnel appears inside a VM
	// (127.0.0.1:PORT) while `skiff ssh` is open.
	BrokerGuestPort = 7777
	// BrokerGuestSocket is a Unix socket in the VM that relays to the
	// tunnel port, for clients such as gh that cannot take a base URL.
	BrokerGuestSocket = "/run/skiff/broker.sock"
)

// Paths describes the host-side directories skiff works with.
type Paths struct {
	// Home is the skiff state directory (default ~/.skiff).
	Home string
}

// DefaultPaths resolves Paths from the environment (SKIFF_HOME) or the user's home.
func DefaultPaths() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, fmt.Errorf("resolve home directory: %w", err)
	}
	p := Paths{Home: filepath.Join(home, ".skiff")}
	if v := os.Getenv("SKIFF_HOME"); v != "" {
		p.Home = v
	}
	return p, nil
}

// KeyPath is the SSH private key used to reach VMs.
func (p Paths) KeyPath() string { return filepath.Join(p.Home, "id_ed25519") }

// PubKeyPath is the matching public key.
func (p Paths) PubKeyPath() string { return p.KeyPath() + ".pub" }

// SSHConfigPath is the generated ssh_config with the *.skiff host alias.
func (p Paths) SSHConfigPath() string { return filepath.Join(p.Home, "ssh_config") }

// KnownHostsPath holds the host keys pinned when each VM was created.
func (p Paths) KnownHostsPath() string { return filepath.Join(p.Home, "known_hosts") }

// CapsDir holds the user's capability files (one <name>.toml each).
func (p Paths) CapsDir() string { return filepath.Join(p.Home, "caps") }

// ProfilePath is the machine default profile, applied to every VM.
func (p Paths) ProfilePath() string { return filepath.Join(p.Home, "profile.toml") }

// CapsLock serialises installations into CapsDir.
func (p Paths) CapsLock() string { return filepath.Join(p.Home, "caps.lock") }

// VMsDir holds per-VM host-side state (grants, placeholder token).
func (p Paths) VMsDir() string { return filepath.Join(p.Home, "vms") }

// RunDir holds the broker sockets.
func (p Paths) RunDir() string { return filepath.Join(p.Home, "run") }

// SocketPath is the broker socket for a VM.
func (p Paths) SocketPath(vm string) string { return filepath.Join(p.RunDir(), vm+".sock") }

// TCPSocketPath is the socket a VM's guest port is forwarded to for a tcp
// capability. VM names contain no dots, so it never collides with a broker
// socket; the port keeps it short and is unique among a VM's granted caps.
func (p Paths) TCPSocketPath(vm string, port int) string {
	return filepath.Join(p.RunDir(), fmt.Sprintf("%s.tcp-%d.sock", vm, port))
}

// AuditLog records every broker decision.
func (p Paths) AuditLog() string { return filepath.Join(p.Home, "audit.log") }

// MachinesDir holds the container backend's per-VM records (owner, slot,
// creation time, host key, forwards), kept apart from VMsDir so gc's
// host-state pruning never touches them.
func (p Paths) MachinesDir() string { return filepath.Join(p.Home, "machines") }

// ContainerLockPath serializes the container backend's API calls.
func (p Paths) ContainerLockPath() string { return filepath.Join(p.Home, "container.lock") }

// ContainerBootLockPath is held while the container system service is started
// and its machines restored, so parallel commands wait for the VMs to be back.
func (p Paths) ContainerBootLockPath() string { return filepath.Join(p.Home, "container-boot.lock") }

// RelayLockPath is held by the running forward relay (`skiff _relay`), so
// a command can tell whether one serves this state directory.
func (p Paths) RelayLockPath() string { return filepath.Join(p.Home, "relay.lock") }

// RelayLogPath collects what the detached relay prints.
func (p Paths) RelayLogPath() string { return filepath.Join(p.Home, "relay.log") }
