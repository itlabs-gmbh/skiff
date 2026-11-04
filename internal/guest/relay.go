package guest

import (
	"fmt"
	"path"
	"strings"

	"github.com/sovyn-eu/skiff/internal/config"
)

// The broker relay gives clients that only speak HTTP over a Unix socket
// (gh with http_unix_socket) a path to the broker: systemd listens on
// config.BrokerGuestSocket and systemd-socket-proxyd forwards each
// connection to the tunnel port. The socket exists for as long as any cap is
// granted; without an open `skiff ssh` its connections are simply refused.
const (
	RelaySocketUnit  = "/etc/systemd/system/skiff-broker.socket"
	RelayServiceUnit = "/etc/systemd/system/skiff-broker.service"
)

// asRootOnSystemd guards every systemctl call: the guest runs the scripts as
// root under systemd, tests and CI runners do neither.
const asRootOnSystemd = `[ "$(id -u)" = 0 ] && [ -d /run/systemd/system ]`

func relaySocket() string {
	return fmt.Sprintf(`[Unit]
Description=skiff broker on a Unix socket

[Socket]
ListenStream=%s
SocketMode=0600
DirectoryMode=0755
RemoveOnStop=yes

[Install]
WantedBy=sockets.target
`, config.BrokerGuestSocket)
}

func relayService() string {
	return fmt.Sprintf(`[Unit]
Description=skiff broker relay to the SSH tunnel
Requires=skiff-broker.socket
After=skiff-broker.socket

[Service]
ExecStart=/usr/lib/systemd/systemd-socket-proxyd 127.0.0.1:%d
`, config.BrokerGuestPort)
}

func isRelayUnit(p string) bool {
	return p == RelaySocketUnit || p == RelayServiceUnit
}

// isReserved reports paths skiff writes itself, which no cap may touch.
func isReserved(p string) bool {
	return isRelayUnit(p) || isInterceptFile(p) || p == InterceptCAFile+".new"
}

// writeRelay installs and starts the relay.
func writeRelay(b *strings.Builder) {
	writeFile(b, RelaySocketUnit, "0644", []byte(relaySocket()))
	writeFile(b, RelayServiceUnit, "0644", []byte(relayService()))
	b.WriteString("if " + asRootOnSystemd + "; then systemctl daemon-reload && systemctl --quiet enable --now " + path.Base(RelaySocketUnit) + "; fi\n")
}

// stopRelay stops the relay before its units are removed. It is best effort:
// a unit someone already disabled or deleted must not fail the revoke, and
// the files go away regardless.
func stopRelay(b *strings.Builder) {
	b.WriteString("if " + asRootOnSystemd + "; then systemctl disable --now " +
		path.Base(RelaySocketUnit) + " " + path.Base(RelayServiceUnit) + " >/dev/null 2>&1 || true; fi\n")
}
