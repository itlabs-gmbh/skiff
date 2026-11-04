BINARY := skiff
GOFLAGS ?=


.PHONY: build install test cover lint e2e e2e-intercept clean

build:
	go build $(GOFLAGS) -o bin/$(BINARY) ./cmd/$(BINARY)

install:
	go install $(GOFLAGS) ./cmd/$(BINARY)

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

clean:
	rm -rf bin coverage.out
