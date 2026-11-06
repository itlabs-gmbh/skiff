#!/usr/bin/env bash
# Builds the Apple Silicon release archive for a tag:
#
#   scripts/dist.sh vX.Y.Z [source dir] [output dir]
#
# Writes <output>/skiff_vX.Y.Z_darwin_arm64.tar.gz and its .sha256. The source
# defaults to the checkout this script lives in and the output to its dist/.
# The release workflow passes a checkout of the tag as the source, so the
# packaging from main also builds tags that predate it.
#
# skiff is pure Go, so this cross-builds from any host; the Go linker ad-hoc
# signs darwin/arm64 binaries itself.
set -euo pipefail

usage() {
	echo "usage: $0 <tag vX.Y.Z> [source dir] [output dir]" >&2
	exit 2
}

[[ $# -ge 1 && $# -le 3 ]] || usage
tag=$1
src=${2:-"$(cd "$(dirname "$0")/.." && pwd)"}
out=${3:-"$src/dist"}

if [[ ! $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
	echo "$0: '$tag' is not a release tag like v1.2.3" >&2
	exit 2
fi
if [[ ! -f $src/go.mod ]]; then
	echo "$0: '$src' is not a skiff checkout (no go.mod)" >&2
	exit 2
fi

archive="skiff_${tag}_darwin_arm64.tar.gz"
files=(skiff LICENSE NOTICE README.md)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

(
	cd "$src"
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath \
		-ldflags "-s -w -X github.com/sovyn-eu/skiff/internal/cli.version=$tag" \
		-o "$stage/skiff" ./cmd/skiff
)
cp "$src/LICENSE" "$src/NOTICE" "$src/README.md" "$stage/"

mkdir -p "$out"
out=$(cd "$out" && pwd)
rm -f "$out/$archive" "$out/$archive.sha256"
# COPYFILE_DISABLE keeps macOS tar from adding ._ resource files.
COPYFILE_DISABLE=1 tar -C "$stage" -czf "$out/$archive" "${files[@]}"
(cd "$out" && shasum -a 256 "$archive" > "$archive.sha256")
echo "$out/$archive"
