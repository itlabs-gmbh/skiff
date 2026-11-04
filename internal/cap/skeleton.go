package cap

import "fmt"

// Skeleton returns a commented starting point for a new capability file.
func Skeleton(name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	return fmt.Sprintf(`# skiff capability %q
# Exactly one of [proxy], [mcp] or [exec] decides what the broker does.
# Grant it to a VM with: skiff grant <vm> %s

name = %q
description = "describe what this hands into the guest"

# --- proxy: forward requests to an upstream and inject credentials on the Mac
[proxy]
upstream = "https://api.example.com"
# allow_headers = ["Content-Type", "Accept"]
[proxy.headers]
Authorization = "Bearer {{ secret \"keychain:skiff/%s-token\" }}"

# Clients that insist on https:// to a fixed host (the Azure CLI, most SDKs)
# use an intercept route: the guest resolves the host to the broker, which
# terminates TLS with the VM's own CA and injects the headers. The upstream
# defaults to https://<host>; list every host by name, wildcards do not exist.
# [[proxy.routes]]
# host = "api.example.com"
# intercept = true
# [proxy.routes.headers]
# Authorization = "Bearer {{ secret \"keychain:skiff/%s-token\" }}"

# --- mcp: run a stdio MCP server on the Mac, exposed as HTTP MCP in the guest
# [mcp]
# command = "npx"
# args = ["-y", "some-mcp-server@latest"]

# --- exec: delegate each request to a program on the Mac (stdin -> stdout)
# [exec]
# command = "skiff-cap-%s"

# --- guest: what the microVM needs; templates see .VM, .BrokerURL, .PseudoToken
[guest.env]
EXAMPLE_BASE_URL = "{{ .BrokerURL }}/%s"

# [[guest.files]]
# path = "/etc/example.conf"
# mode = "0644"
# content = "token = {{ .PseudoToken }}\n"

# [[guest.json_merge]]
# path = "/root/.claude.json"
# key = "mcpServers.%s"
# value = { type = "http", url = "{{ .BrokerURL }}/%s" }
`, name, name, name, name, name, name, name, name, name), nil
}
