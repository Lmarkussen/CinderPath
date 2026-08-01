SHELL := /bin/sh

BINARY := bin/cinderpath
PACKAGE := ./cmd/cinderpath
MODULE := github.com/Lmarkussen/CinderPath
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || printf '%s' dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf '%s' unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf '%s' unknown)
LDFLAGS := -X $(MODULE)/internal/version.Version=$(VERSION) -X $(MODULE)/internal/version.Commit=$(COMMIT) -X $(MODULE)/internal/version.BuildDate=$(BUILD_DATE)

.PHONY: help build test vet fmt fmt-check check run clean race integration install-local auth-dry-run config-example run-mock run-dry protocol-fixtures protocol-test protocol-report-test protocol-bundle-test policy-offline-test fuzz-policy fuzz-protocol docs-check

help:
	@printf '%s\n' \
	  'CinderPath targets (tests are offline; servers use loopback only):' \
	  '  build                 build bin/cinderpath' \
	  '  check                 formatting, vet, unit tests, and build' \
	  '  race                  race-enabled unit tests' \
	  '  integration           integration-tag tests (fixtures skip when absent)' \
	  '  protocol-test         all offline protocol package tests' \
	  '  protocol-report-test  policy persistence and redacted report tests' \
	  '  protocol-bundle-test  real bundle export/inspect/import tests' \
	  '  policy-offline-test   offline assignment/policy/classifier tests' \
	  '  fuzz-policy           bounded offline policy fuzz smoke tests' \
	  '  fuzz-protocol         bounded offline protocol fuzz smoke tests' \
	  '  docs-check            high-value CLI/docs/Makefile consistency tests' \
	  '  run-mock              isolated network-free mock workflow' \
	  '  run-dry               persist a network-free dry-run plan' \
	  'No target performs live SCCM policy requests or live authentication.'

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

auth-dry-run: build
	$(BINARY) auth validate --dry-run $(ARGS)

config-example: build
	@tmp=$$(mktemp -d); $(BINARY) config init --non-interactive --domain lab.local --profile safe --output $$tmp/lab_local.yaml; $(BINARY) config validate $$tmp/lab_local.yaml

run-mock: build
	@tmp=$$(mktemp -d); $(BINARY) --db $$tmp/cinderpath.db --output-dir $$tmp/reports run --domain lab.local --profile safe --provider mock

run-dry: build
	$(BINARY) run --domain lab.local --profile safe --provider mock --dry-run

protocol-fixtures:
	go test ./internal/policy -run 'TestImport|TestSanitize'

protocol-test:
	go test ./internal/policy

policy-offline-test:
	go test ./internal/policy -run 'TestImportParse|TestParser|TestContract|TestSanitization|TestBinary|TestCapture'

protocol-report-test:
	go test ./internal/report ./internal/database ./internal/app -run 'Test.*Policy|TestDryRun|TestReport'

protocol-bundle-test:
	go test ./internal/policy -run '^TestBundle'

fuzz-policy:
	go test ./internal/policy -run '^$$' -fuzz '^FuzzPolicyParser$$' -fuzztime=1s
	go test ./internal/policy -run '^$$' -fuzz '^FuzzAssignmentParser$$' -fuzztime=1s
	go test ./internal/policy -run '^$$' -fuzz '^FuzzCandidateClassifier$$' -fuzztime=1s
	go test ./internal/policy -run '^$$' -fuzz '^FuzzFixtureMetadataParser$$' -fuzztime=1s

fuzz-protocol:
	go test ./internal/policy -run '^$$' -fuzz '^FuzzBinaryInspection$$' -fuzztime=1s
	go test ./internal/policy -run '^$$' -fuzz '^FuzzBinaryTextRegionDetector$$' -fuzztime=1s
	go test ./internal/policy -run '^$$' -fuzz '^FuzzReplacementPlanner$$' -fuzztime=1s
	go test ./internal/policy -run '^$$' -fuzz '^FuzzBundleManifestParser$$' -fuzztime=1s
	go test ./internal/policy -run '^$$' -fuzz '^FuzzBundleArchiveValidator$$' -fuzztime=1s

docs-check:
	go test ./internal/buildtool -run '^TestDocumentationConsistency$$'
