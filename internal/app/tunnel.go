package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sovyn-eu/skiff/internal/broker"
	"github.com/sovyn-eu/skiff/internal/config"
	"github.com/sovyn-eu/skiff/internal/grant"
	"github.com/sovyn-eu/skiff/internal/intercept"
	"github.com/sovyn-eu/skiff/internal/runner"
	"github.com/sovyn-eu/skiff/internal/secret"
)

// Tunnel makes this process the owner of a VM's broker and returns the
// socket to forward plus a stop function that gives ownership up again. It
// fails with broker.ErrBusy while another process owns it. Tests replace it to
// avoid real sockets.
type Tunnel func(ctx context.Context, name string) (socket string, stop func(), err error)

// WithTunnel overrides how the broker is started (used by tests).
func WithTunnel(t Tunnel) Option {
	return func(a *App) { a.tunnel = t }
}

// claimTunnel runs the configured Tunnel; the production one is bound late so
// that a copy of the App (see standby) starts brokers with its own runner and
// output.
func (a *App) claimTunnel(ctx context.Context, name string) (string, func(), error) {
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
	if set.Contains(grant.Grant{Cap: grant.SSHAgent}) {
		args = append(args, "-A")
	}
	if !needsBroker(set) {
		return args, func() {}, nil
	}
	socket, stop, err := a.claimTunnel(ctx, name)
	switch {
	case errors.Is(err, broker.ErrBusy):
		// A `skiff tunnel` or another session owns the broker and its
		// forward; this session takes over if that owner ends first.
		return args, a.standby(ctx, name), nil
	case err != nil:
		return nil, nil, err
	}
	return append(args, brokerForward(socket)...), stop, nil
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

// brokerForward maps the guest's broker port onto the host socket. Without
// ExitOnForwardFailure a squatter on the guest port would leave ssh running
// with no tunnel and only a warning.
func brokerForward(socket string) []string {
	return []string{"-o", "ExitOnForwardFailure=yes", "-R", fmt.Sprintf("127.0.0.1:%d:%s", config.BrokerGuestPort, socket)}
}

// startBroker is the production Tunnel: it claims the VM's broker and serves
// it on a Unix socket until stop, which removes the socket before giving
// ownership up, so the next owner never finds a stale one in use.
func (a *App) startBroker(ctx context.Context, name string) (string, func(), error) {
	socket := a.paths.SocketPath(name)
	release, err := broker.Claim(socket)
	if err != nil {
		return "", nil, err
	}
	// A skiff from before ownership locks may still serve this socket.
	if broker.Alive(socket) {
		release()
		return "", nil, broker.ErrBusy
	}
	stop, err := a.serveBroker(ctx, name, socket)
	if err != nil {
		release()
		return "", nil, err
	}
	return socket, func() {
		stop()
		release()
	}, nil
}

// serveBroker listens on socket and serves the VM's broker until stop.
func (a *App) serveBroker(ctx context.Context, name, socket string) (func(), error) {
	caps, err := a.loadCaps()
	if err != nil {
		return nil, err
	}
	data, err := a.templateData(name)
	if err != nil {
		return nil, err
	}
	audit, err := os.OpenFile(a.paths.AuditLog(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	store := a.grantStore()
	b := &broker.Broker{
		VM:      name,
		Caps:    caps,
		Grants:  func() (grant.Set, error) { return store.Load(name) },
		Secrets: secret.NewResolver(a.r),
		Audit:   audit,
		Data:    data,
		Warn:    func(msg string) { a.printf("skiff: warning: %s\n", msg) },
	}
	caDir, err := store.InterceptDir(name)
	if err != nil {
		_ = audit.Close()
		return nil, err
	}
	b.CA = &intercept.Watcher{Dir: caDir, Now: time.Now}
	ln, err := broker.Listen(socket)
	if err != nil {
		_ = audit.Close()
		return nil, err
	}
	serveCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := broker.Serve(serveCtx, b.Listener(ln), b.Handler()); err != nil {
			a.printf("broker for %s stopped: %v\n", name, err)
		}
	}()
	return func() {
		cancel()
		<-done
		b.Close()
		_ = audit.Close()
		_ = os.Remove(socket)
	}, nil
}
