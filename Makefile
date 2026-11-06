BINARY := skiff
GOFLAGS ?=
# Stamped into `skiff --version`; empty outside a git checkout, where the
# binary falls back to the Go build info.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null)
LDFLAGS := -X github.com/sovyn-eu/skiff/internal/cli.version=$(VERSION)

# Release archive for Apple Silicon, what the Homebrew formula installs.
DIST_ARCHIVE := $(BINARY)_$(VERSION)_darwin_arm64.tar.gz
DIST_FILES := $(BINARY) LICENSE NOTICE README.md

.PHONY: build install test cover lint e2e e2e-intercept dist clean

build:
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/$(BINARY)

install:
	go install $(GOFLAGS) -ldflags '$(LDFLAGS)' ./cmd/$(BINARY)

test:
	go test -race ./...

cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

lint:
	gofmt -l . | tee /dev/stderr | test -z "$$(cat)"
	go vet ./...

# Boots a real VM; needs a prepared host (skiff prepare). Always cleans up.
e2e: build
	./bin/$(BINARY) new e2e-smoke --mem 512 \
	  && ./bin/$(BINARY) ssh e2e-smoke uname -a \
	  && ./bin/$(BINARY) ls; status=$$?; \
	./bin/$(BINARY) rm e2e-smoke; exit $$status

e2e-intercept: build
	scripts/e2e-intercept.sh ./bin/$(BINARY)

# Pure Go, so it cross-builds from any host; the Go linker ad-hoc signs
# darwin/arm64 binaries itself. COPYFILE_DISABLE keeps macOS tar from adding
# ._ resource files.
dist:
	@case "$(VERSION)" in v[0-9]*) ;; *) echo "dist: VERSION must be a release tag like v1.2.3, got '$(VERSION)'" >&2; exit 1;; esac
	rm -rf dist && mkdir -p dist/stage
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath \
	  -ldflags '-s -w $(LDFLAGS)' -o dist/stage/$(BINARY) ./cmd/$(BINARY)
	cp LICENSE NOTICE README.md dist/stage/
	COPYFILE_DISABLE=1 tar -C dist/stage -czf dist/$(DIST_ARCHIVE) $(DIST_FILES)
	cd dist && shasum -a 256 $(DIST_ARCHIVE) > $(DIST_ARCHIVE).sha256
	rm -rf dist/stage

clean:
	rm -rf bin dist coverage.out
