package cli

import "runtime/debug"

// version can be stamped at build time:
//
//	go build -ldflags "-X github.com/sovyn-eu/skiff/internal/cli.version=v1.2.3" ./cmd/skiff
//
// Without it the version comes from the Go build info, which `go install
// .../cmd/skiff@vX.Y.Z` and builds inside a git checkout fill in already.
var version = ""

// devVersion is reported when neither source knows the version.
const devVersion = "dev"

// Version returns the version of this skiff binary.
func Version() string {
	return resolveVersion(version, debug.ReadBuildInfo)
}

func resolveVersion(stamped string, read func() (*debug.BuildInfo, bool)) string {
	if stamped != "" {
		return stamped
	}
	info, ok := read()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return devVersion
	}
	return info.Main.Version
}
