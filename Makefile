SHELL := /bin/sh

BINARY := bin/cinderpath
PACKAGE := ./cmd/cinderpath
MODULE := github.com/Lmarkussen/CinderPath
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || printf '%s' dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf '%s' unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf '%s' unknown)
LDFLAGS := -X $(MODULE)/internal/version.Version=$(VERSION) -X $(MODULE)/internal/version.Commit=$(COMMIT) -X $(MODULE)/internal/version.BuildDate=$(BUILD_DATE)

.PHONY: build test vet fmt fmt-check check run clean race integration install-local

build:
	mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(PACKAGE)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	go fmt ./...

fmt-check:
	@test -z "$$(gofmt -l $$(find . -type f -name '*.go' -not -path './vendor/*'))" || { \
		printf '%s\n' 'Go files require formatting; run make fmt'; \
		gofmt -l $$(find . -type f -name '*.go' -not -path './vendor/*'); \
		exit 1; \
	}

check: fmt-check vet test build

run:
	go run $(PACKAGE) discover --provider mock

clean:
	rm -f $(BINARY) coverage.out
	rmdir bin 2>/dev/null || true

race:
	go test -race ./...

integration:
	go test -tags=integration ./...

install-local: build
	mkdir -p $(HOME)/.local/bin
	cp $(BINARY) $(HOME)/.local/bin/cinderpath
	@case ":$$PATH:" in *":$(HOME)/.local/bin:"*) ;; *) printf '%s\n' 'Add $(HOME)/.local/bin to PATH to run cinderpath.' ;; esac
