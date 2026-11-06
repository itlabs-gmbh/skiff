BINARY := skiff
GOFLAGS ?=
# Stamped into `skiff --version`; empty outside a git checkout, where the
# binary falls back to the Go build info.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null)
LDFLAGS := -X github.com/sovyn-eu/skiff/internal/cli.version=$(VERSION)

.PHONY: build install test cover lint e2e e2e-intercept e2e-tcp dist clean

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

e2e-tcp: build
	scripts/e2e-tcp.sh ./bin/$(BINARY)

# Release archive for Apple Silicon, what the Homebrew formula installs:
# dist/skiff_$(VERSION)_darwin_arm64.tar.gz and its sha256.
dist:
	scripts/dist.sh '$(VERSION)'

clean:
	rm -rf bin dist coverage.out
