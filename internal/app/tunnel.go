package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sovyn-eu/skiff/internal/broker"
	"github.com/sovyn-eu/skiff/internal/cap"
	"github.com/sovyn-eu/skiff/internal/config"
	"github.com/sovyn-eu/skiff/internal/grant"
	"github.com/sovyn-eu/skiff/internal/intercept"
	"github.com/sovyn-eu/skiff/internal/runner"
	"github.com/sovyn-eu/skiff/internal/secret"
)

// Tunnel makes this process the owner of a VM's broker and returns the
// sockets to forward plus a stop function that gives ownership up again. It
// fails with broker.ErrBusy while another process owns it. Tests replace it to
// avoid real sockets.
type Tunnel func(ctx context.Context, name string) (fwd Forwards, stop func(), err error)

// Forwards is what the owner of a VM's broker forwards into the guest: the
// broker's socket and one socket for every tcp capability granted when the
// broker started.
type Forwards struct {
	Broker string
	TCP    []TCPSocket
}

// TCPSocket is the socket on the Mac behind a tcp capability's guest port.
type TCPSocket struct {
	Cap    string
	Port   int
	Socket string
}

// WithTunnel overrides how the broker is started (used by tests).
func WithTunnel(t Tunnel) Option {
	return func(a *App) { a.tunnel = t }
}

// claimTunnel runs the configured Tunnel; the production one is bound late so
// that a copy of the App (see standby) starts brokers with its own runner and
// output.
func (a *App) claimTunnel(ctx context.Context, name string) (Forwards, func(), error) {
	if a.tunnel != nil {
		return a.tunnel(ctx, name)
	}
	return a.startBroker(ctx, name)
}

// sshExtraArgs returns the ssh options that attach the broker tunnel and, if
// granted, the SSH agent. It returns a stop function for the broker.
func (a *App) sshExtraArgs(ctx context.Context, name string) ([]string, func(), error) {
	set, err := a.grantStore().Load(name)
	if err != nil {
		return nil, nil, err
	}
	if len(set) == 0 {
		return nil, func() {}, nil
	}
	var args []string
	releaseAgent := func() {}
	if set.Contains(grant.Grant{Cap: grant.SSHAgent}) {
		// Held for the session, so a profile setup cannot start while the
		// agent is forwarded, and refused while a setup holds it.
		release, err := a.lockAgent(name, false)
		if errors.Is(err, errAgentLockBusy) {
			return nil, nil, fmt.Errorf("%s is being set up; the SSH agent is forwarded again when the setup is done", name)
		}
		if err != nil {
			return nil, nil, err
		}
		releaseAgent = release
		args = append(args, "-A")
	}
	if !needsBroker(set) {
		return args, releaseAgent, nil
	}
	fwd, stop, err := a.claimTunnel(ctx, name)
	switch {
	case errors.Is(err, broker.ErrBusy):
		// A `skiff tunnel` or another session owns the broker and its
		// forward; this session takes over if that owner ends first.
		standby := a.standby(ctx, name)
		return args, func() { standby(); releaseAgent() }, nil
	case err != nil:
		releaseAgent()
		return nil, nil, err
	}
	return append(args, brokerForward(fwd)...), func() { stop(); releaseAgent() }, nil
}

// defaultBrokerWatch is how often a session waiting for a broker's owner to
// leave tries to take it over.
const defaultBrokerWatch = 2 * time.Second

// standby keeps a session served whose broker is owned elsewhere: holdTunnel
// waits for the owner to leave, then claims broker and forward together and
// holds them until the returned stop is called. The terminal belongs to the
// interactive session, so standby neither prints nor lets its commands write
// there; takeovers and failures go to the audit log.
func (a *App) standby(ctx context.Context, name string) func() {
	ctx, cancel := context.WithCancel(ctx)
	quiet := *a
	quiet.out = io.Discard
	quiet.r = runner.Silenced(a.r)
	quiet.backend = quiet.newBackend(&quiet)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			err := quiet.holdTunnel(ctx, name)
			if err == nil || ctx.Err() != nil {
				return // the VM stopped, or the session ended
			}
			quiet.auditTunnel(name, "failed", err.Error())
			if !sleepCtx(ctx, maxTunnelRetry) {
				return
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// needsBroker reports whether any grant is served by the broker; ssh-agent
// alone is plain agent forwarding.
func needsBroker(set grant.Set) bool {
	for _, c := range set.Caps() {
		if c != grant.SSHAgent {
			return true
		}
	}
	return false
}

// brokerForward maps the guest's broker port, and the port of every tcp
// capability, onto the host sockets. Without ExitOnForwardFailure a squatter
// on a guest port would leave ssh running with no tunnel and only a warning.
func brokerForward(fwd Forwards) []string {
	args := []string{"-o", "ExitOnForwardFailure=yes", "-R", fmt.Sprintf("127.0.0.1:%d:%s", config.BrokerGuestPort, fwd.Broker)}
	for _, t := range fwd.TCP {
		args = append(args, "-R", fmt.Sprintf("127.0.0.1:%d:%s", t.Port, t.Socket))
	}
	return args
}

// startBroker is the production Tunnel: it claims the VM's broker and serves
// it on Unix sockets until stop, which removes the sockets before giving
// ownership up, so the next owner never finds a stale one in use.
func (a *App) startBroker(ctx context.Context, name string) (Forwards, func(), error) {
	socket := a.paths.SocketPath(name)
	release, err := broker.Claim(socket)
	if err != nil {
		return Forwards{}, nil, err
	}
	// A skiff from before ownership locks may still serve this socket.
	if broker.Alive(socket) {
		release()
		return Forwards{}, nil, broker.ErrBusy
	}
	tcp, stop, err := a.serveBroker(ctx, name, socket)
	if err != nil {
		release()
		return Forwards{}, nil, err
	}
	return Forwards{Broker: socket, TCP: tcp}, func() {
		stop()
		release()
	}, nil
}

// serveBroker listens on socket and serves the VM's broker until stop. It
// also listens for every tcp capability granted right now and returns those
// sockets, which the caller forwards together with the broker's.
func (a *App) serveBroker(ctx context.Context, name, socket string) ([]TCPSocket, func(), error) {
	caps, err := a.loadCaps()
	if err != nil {
		return nil, nil, err
	}
	set, err := a.grantStore().Load(name)
	if err != nil {
		return nil, nil, err
	}
	forwards, err := a.tcpForwards(caps, set)
	if err != nil {
		return nil, nil, err
	}
	b, closeBroker, err := a.openBroker(name, caps)
	if err != nil {
		return nil, nil, err
	}
	ln, err := broker.Listen(socket)
	if err != nil {
		closeBroker()
		return nil, nil, err
	}
	tcp, err := a.serveTCP(b, name, caps, forwards)
	if err == nil {
		err = a.recordTCPForwards(name, tcp)
	}
	if err != nil {
		_ = ln.Close()
		closeBroker()
		_ = os.Remove(socket)
		removeSockets(tcp)
		return nil, nil, err
	}
	serveCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := broker.Serve(serveCtx, b.Listener(ln), b.Handler()); err != nil {
			a.printf("broker for %s stopped: %v\n", name, err)
		}
	}()
	return tcp, func() {
		cancel()
		<-done
		closeBroker()
		_ = os.Remove(socket)
		removeSockets(tcp)
		_ = os.Remove(a.paths.TCPForwardsPath(name))
	}, nil
}

// openBroker builds the VM's broker and opens its audit log. The returned
// function closes the broker first, so its last lines still reach the log.
func (a *App) openBroker(name string, caps cap.Set) (*broker.Broker, func(), error) {
	data, err := a.templateData(name)
	if err != nil {
		return nil, nil, err
	}
	store := a.grantStore()
	caDir, err := store.InterceptDir(name)
	if err != nil {
		return nil, nil, err
	}
	audit, err := os.OpenFile(a.paths.AuditLog(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open audit log: %w", err)
	}
	b := &broker.Broker{
		VM:      name,
		Caps:    caps,
		Grants:  func() (grant.Set, error) { return store.Load(name) },
		Secrets: secret.NewResolver(a.r),
		Audit:   audit,
		Data:    data,
		Warn:    func(msg string) { a.printf("skiff: warning: %s\n", msg) },
		CA:      &intercept.Watcher{Dir: caDir, Now: time.Now},
	}
	return b, func() {
		b.Close()
		_ = audit.Close()
	}, nil
}
