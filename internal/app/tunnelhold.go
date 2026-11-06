package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/sovyn-eu/skiff/internal/broker"
	"github.com/sovyn-eu/skiff/internal/config"
	"github.com/sovyn-eu/skiff/internal/vm"
)

const (
	// defaultTunnelRetry is the first pause before `skiff tunnel`
	// reconnects after the ssh connection dropped.
	defaultTunnelRetry = 5 * time.Second
	// maxTunnelRetry caps the backoff: a guest port held by another session
	// is retried about once a minute rather than flooding the audit log.
	maxTunnelRetry = time.Minute
	// tunnelStable is how long a connection must have lasted for the backoff
	// to start over.
	tunnelStable = time.Minute
	// maxTunnelFailures consecutive failed status checks end the tunnel; a
	// single one is usually the runtime restarting.
	maxTunnelFailures = 5
)

// tunnelKeepAlive lets ssh notice a dead connection (Mac asleep, VM
// killed) within about 45 seconds instead of waiting for TCP to give up.
var tunnelKeepAlive = []string{"-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3"}

// Tunnel serves the VM's broker without an interactive session: it holds an
// ssh connection that carries only the broker forward, reconnects when it
// drops, and returns when ctx is cancelled or the VM stops running.
func (a *App) Tunnel(ctx context.Context, name string) error {
	if err := vm.ValidateName(name); err != nil {
		return err
	}
	if err := a.backend.Ready(ctx); err != nil {
		return err
	}
	if err := a.ensureSSHConfig(); err != nil {
		return err
	}
	set, err := a.grantStore().Load(name)
	if err != nil {
		return err
	}
	if !needsBroker(set) {
		return fmt.Errorf("%s has no grants served by the broker; add one with 'skiff grant %s CAP'", name, name)
	}
	running, err := a.vmRunning(ctx, name)
	if err != nil {
		return err
	}
	if !running {
		return fmt.Errorf("%s is not running; start it with 'skiff start %s'", name, name)
	}
	a.printf("broker tunnel for %s on guest 127.0.0.1:%d; stop it with Ctrl-C\n", name, config.BrokerGuestPort)
	return a.holdTunnel(ctx, name)
}

// holdTunnel owns the VM's broker and keeps it forwarded until ctx ends or
// the VM is no longer running. While another process owns the broker it
// waits rather than forward: a forward is only ever made by the broker's
// owner, so none can outlive the broker it points to. Ownership is kept
// across reconnects.
func (a *App) holdTunnel(ctx context.Context, name string) error {
	fwd, stop, err := a.awaitBroker(ctx, name)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	// Registered before any other return: a claim that raced with
	// cancellation must still be given up.
	defer stop()
	if ctx.Err() != nil {
		return nil
	}
	for _, t := range fwd.TCP {
		a.printf("%s on guest 127.0.0.1:%d\n", t.Cap, t.Port)
	}
	return a.keepForwarded(ctx, name, fwd)
}

// awaitBroker claims the VM's broker, waiting while another process owns it.
func (a *App) awaitBroker(ctx context.Context, name string) (Forwards, func(), error) {
	announced := false
	for {
		fwd, stop, err := a.claimTunnel(ctx, name)
		if !errors.Is(err, broker.ErrBusy) {
			return fwd, stop, err
		}
		if !announced {
			a.printf("another session serves %s's broker; taking over when it ends\n", name)
			announced = true
		}
		if !sleepCtx(ctx, a.brokerWatch) {
			return Forwards{}, nil, ctx.Err()
		}
	}
}

// keepForwarded reconnects the forward with backoff until ctx ends or the VM
// is no longer running.
func (a *App) keepForwarded(ctx context.Context, name string, fwd Forwards) error {
	var wait time.Duration
	failures := 0
	for {
		started := time.Now()
		sshErr := a.forwardOnce(ctx, name, fwd)
		if ctx.Err() != nil {
			a.printf("broker tunnel for %s closed\n", name)
			return nil
		}
		running, err := a.vmRunning(ctx, name)
		switch {
		case err != nil:
			if failures++; failures >= maxTunnelFailures {
				return fmt.Errorf("check whether %s still runs: %w", name, err)
			}
			a.printf("could not check whether %s still runs: %v\n", name, err)
		case !running:
			a.printf("%s is no longer running, broker tunnel closed\n", name)
			return nil
		default:
			failures = 0
		}
		wait = a.nextTunnelRetry(wait, time.Since(started))
		a.printf("broker tunnel for %s dropped (%s), reconnecting in %s\n", name, sshEnd(sshErr), wait)
		if !sleepCtx(ctx, wait) {
			return nil
		}
	}
}

// nextTunnelRetry doubles the previous pause up to maxTunnelRetry and starts
// over after a connection that held for tunnelStable.
func (a *App) nextTunnelRetry(prev, lasted time.Duration) time.Duration {
	if prev == 0 || lasted >= tunnelStable {
		return a.tunnelRetry
	}
	return min(2*prev, maxTunnelRetry)
}

// forwardOnce runs one ssh connection that executes nothing (-N), never reads
// the terminal (-n) and only carries the broker's forwards.
func (a *App) forwardOnce(ctx context.Context, name string, fwd Forwards) error {
	args := append([]string{"-N", "-n"}, tunnelKeepAlive...)
	args = append(args, brokerForward(fwd)...)
	a.auditTunnel(name, "open", "")
	err := a.r.Run(ctx, "ssh", append(args, a.sshArgs(name, nil)...)...)
	a.auditTunnel(name, "closed", sshEnd(err))
	return err
}

// sshEnd says briefly why an ssh connection ended; the runner's error repeats
// the whole command line, which the audit log already has.
func sshEnd(err error) string {
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return "ssh exited"
	case errors.As(err, &exitErr):
		return fmt.Sprintf("ssh exit %d", exitErr.ExitCode())
	default:
		return err.Error()
	}
}

// vmRunning asks the backend whether the VM exists and runs. It polls in the
// background, so it never starts a stopped runtime.
func (a *App) vmRunning(ctx context.Context, name string) (bool, error) {
	if err := a.backend.Alive(ctx); err != nil {
		return false, err
	}
	vms, err := a.backend.List(ctx)
	if err != nil {
		return false, err
	}
	for _, v := range vms {
		if v.Name == name {
			return v.State == "running", nil
		}
	}
	return false, nil
}

// auditTunnel records tunnel lifecycle events next to the broker's request
// lines, so a gap in decisions can be told apart from an idle guest.
func (a *App) auditTunnel(name, event, reason string) {
	f, err := os.OpenFile(a.paths.AuditLog(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		a.printf("skiff: warning: audit log: %v\n", err)
		return
	}
	defer f.Close()
	line := fmt.Sprintf("%s vm=%s tunnel=%s", time.Now().UTC().Format(time.RFC3339), name, event)
	if reason != "" {
		line += fmt.Sprintf(" reason=%q", reason)
	}
	if _, err := fmt.Fprintln(f, line); err != nil {
		a.printf("skiff: warning: audit log: %v\n", err)
	}
}

// sleepCtx waits d and reports false if ctx ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
