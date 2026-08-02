SHELL := /bin/sh

BINARY := bin/cinderpath
PACKAGE := ./cmd/cinderpath
MODULE := github.com/Lmarkussen/CinderPath
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || printf '%s' dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf '%s' unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf '%s' unknown)
LDFLAGS := -X $(MODULE)/internal/version.Version=$(VERSION) -X $(MODULE)/internal/version.Commit=$(COMMIT) -X $(MODULE)/internal/version.BuildDate=$(BUILD_DATE)

.PHONY: help build test vet fmt fmt-check check run clean race integration install-local auth-dry-run config-example run-mock run-dry protocol-fixtures protocol-test protocol-report-test protocol-bundle-test protocol-signing-test protocol-research-test protocol-contract-test protocol-dossier-test protocol-expected-results-test policy-offline-test fuzz-policy fuzz-protocol fuzz-protocol-research capture-test capture-integration pcapng-test exchange-test sequence-test parser-test matrix-test analysis-replay-test capture-dossier-test capture-cli-test capture-kit-test capture-kit-cli-test capture-kit-script-test guided-import-test windows-log-test capture-evidence-bundle-test capture-evidence-signing-test capture-fuzz pcapng-fuzz exchange-fuzz sequence-fuzz parser-fuzz matrix-fuzz analysis-fuzz capture-kit-fuzz protocol-offline-check docs-check

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
	  '  protocol-signing-test Ed25519 key/signature/verification tests' \
	  '  protocol-research-test multi-capture comparison/correlation tests' \
	  '  protocol-contract-test candidate contract and safety-review tests' \
	  '  protocol-dossier-test redacted atomic dossier tests' \
	  '  protocol-expected-results-test signed offline expected-result tests' \
	  '  policy-offline-test   offline assignment/policy/classifier tests' \
	  '  fuzz-policy           bounded offline policy fuzz smoke tests' \
	  '  fuzz-protocol         bounded offline protocol fuzz smoke tests' \
	  '  fuzz-protocol-research bounded signing/research fuzz smoke tests' \
	  '  capture-test          bounded HAR/PCAP/normalized import tests' \
	  '  capture-integration   offline capture CLI and persistence tests' \
	  '  pcapng-test           bounded PCAPNG block/packet decoder tests' \
	  '  exchange-test         TCP/HTTP reconstruction and pairing tests' \
	  '  sequence-test         deterministic partial-order tests' \
	  '  parser-test           structural observation/candidate tests' \
	  '  matrix-test           controlled-matrix validation tests' \
	  '  analysis-replay-test deterministic offline re-analysis tests' \
	  '  capture-dossier-test  atomic redacted dossier tests' \
	  '  capture-cli-test      command-tree and offline CLI tests' \
	  '  capture-kit-test      passive kit generation/schema/state tests' \
	  '  capture-kit-cli-test  capture-kit and guided-import CLI tests' \
	  '  capture-kit-script-test static passive PowerShell/shell tests' \
	  '  guided-import-test    reviewed offline guided-import tests' \
	  '  windows-log-test      bounded redacted Windows-log inspection tests' \
	  '  capture-evidence-bundle-test dedicated bundle export/inspect/import tests' \
	  '  capture-evidence-signing-test capture-evidence Ed25519 integrity tests' \
	  '  capture-kit-fuzz      bounded kit metadata/path fuzz smoke tests' \
	  '  protocol-offline-check all capture research tests (no network)' \
	  '  capture-fuzz/sequence-fuzz/parser-fuzz bounded offline fuzz smoke tests' \
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

protocol-signing-test:
	go test ./internal/policy -run '^TestSigning|^TestSignature'

protocol-research-test:
	go test ./internal/policy -run '^TestResearchSet'

protocol-contract-test:
	go test ./internal/policy -run '^TestResearchSetComparisonCandidate|^TestSafetyReview'

protocol-dossier-test:
	go test ./internal/policy -run '^TestResearchSetComparisonCandidateAndDossier$$'

protocol-expected-results-test:
	go test ./internal/policy -run '^TestSigningKeySignVerifyAndExpectedResults$$'

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

fuzz-protocol-research:
	go test ./internal/policy -run '^$$' -fuzz '^FuzzCanonicalSigningManifest$$' -fuzztime=1s
	go test ./internal/policy -run '^$$' -fuzz '^FuzzSignatureEnvelopeParser$$' -fuzztime=1s
	go test ./internal/policy -run '^$$' -fuzz '^FuzzResearchSetParser$$' -fuzztime=1s
	go test ./internal/policy -run '^$$' -fuzz '^FuzzComparisonPlanner$$' -fuzztime=1s
	go test ./internal/policy -run '^$$' -fuzz '^FuzzCandidateContractSerializer$$' -fuzztime=1s
	go test ./internal/policy -run '^$$' -fuzz '^FuzzSequenceParser$$' -fuzztime=1s
	go test ./internal/policy -run '^$$' -fuzz '^FuzzDossierGeneratorInputs$$' -fuzztime=1s
	go test ./internal/policy -run '^$$' -fuzz '^FuzzExpectedAnalysisManifest$$' -fuzztime=1s

capture-test:
	go test ./internal/capture -run 'TestHAR|TestPCAP'

capture-integration:
	go test ./internal/capture ./internal/database -run 'Test.*Import|TestSchemaV[568]'

sequence-test:
	go test ./internal/capture -run 'Test.*Deterministic|Test.*Sequence'

parser-test:
	go test ./internal/capture -run 'TestBinary|TestMatrixAndCandidate'

matrix-test:
	go test ./internal/capture -run 'TestMatrix'

analysis-replay-test:
	go test ./internal/capture -run 'TestHARImportRedactsAndDeterministic'

pcapng-test:
	go test ./internal/capture -run '^TestPCAPNG'

exchange-test:
	go test ./internal/capture -run 'TestPCAP|Test.*Exchange'

capture-dossier-test:
	go test ./internal/capture -run 'TestCorpusReplayAndDossier'

capture-cli-test:
	go test ./internal/buildtool -run '^TestCaptureCLIIntegrationOffline$$|^TestDocumentationConsistency$$'

capture-kit-test:
	go test ./internal/capturekit

capture-kit-cli-test:
	go test ./internal/buildtool -run '^TestCaptureKitCLIOffline$$|^TestDocumentationConsistency$$'

capture-kit-script-test:
	go test ./internal/capturekit -run '^TestCreateLayoutModesAndPassiveScripts$$'

guided-import-test:
	go test ./internal/buildtool -run '^TestCaptureKitCLIOffline$$|^TestCaptureEvidenceBundleCLIOffline$$'

windows-log-test:
	go test ./internal/capturekit -run '^TestInspectLogs'

capture-evidence-bundle-test:
	go test ./internal/capturekit -run '^TestEvidenceBundle'
	go test ./internal/buildtool -run '^TestCaptureEvidenceBundleCLIOffline$$'

capture-evidence-signing-test:
	go test ./internal/capturekit -run '^TestEvidenceBundleExportInspectImportAndSigning$$'

protocol-offline-check: capture-test capture-integration pcapng-test exchange-test sequence-test parser-test matrix-test analysis-replay-test capture-dossier-test capture-cli-test

capture-fuzz:
	go test ./internal/capture -run '^$$' -fuzz '^FuzzHAR$$' -fuzztime=1s

sequence-fuzz:
	go test ./internal/capture -run '^$$' -fuzz '^FuzzSequenceGraph$$' -fuzztime=1s

parser-fuzz:
	go test ./internal/capture -run '^$$' -fuzz '^FuzzBinaryObservations$$' -fuzztime=1s
	go test ./internal/capture -run '^$$' -fuzz '^FuzzXMLStructural$$' -fuzztime=1s
	go test ./internal/capture -run '^$$' -fuzz '^FuzzJSONStructural$$' -fuzztime=1s
	go test ./internal/capture -run '^$$' -fuzz '^FuzzMultipartStructural$$' -fuzztime=1s

pcapng-fuzz:
	go test ./internal/capture -run '^$$' -fuzz '^FuzzPCAPNGBlocks$$' -fuzztime=1s
	go test ./internal/capture -run '^$$' -fuzz '^FuzzPacketDecoder$$' -fuzztime=1s

exchange-fuzz:
	go test ./internal/capture -run '^$$' -fuzz '^FuzzHTTPFraming$$' -fuzztime=1s

matrix-fuzz:
	go test ./internal/capture -run '^$$' -fuzz '^FuzzMatrixValidator$$' -fuzztime=1s

analysis-fuzz:
	go test ./internal/capture -run '^$$' -fuzz '^FuzzCorpusManifest$$' -fuzztime=1s

capture-kit-fuzz:
	go test ./internal/capturekit -run '^$$' -fuzz '^FuzzMetadataParser$$' -fuzztime=1s
	go test ./internal/capturekit -run '^$$' -fuzz '^FuzzSafePath$$' -fuzztime=1s
	go test ./internal/capturekit -run '^$$' -fuzz '^FuzzLogDecoder$$' -fuzztime=1s
	go test ./internal/capturekit -run '^$$' -fuzz '^FuzzLogLineInspector$$' -fuzztime=1s
	go test ./internal/capturekit -run '^$$' -fuzz '^FuzzEvidenceManifest$$' -fuzztime=1s
	go test ./internal/capturekit -run '^$$' -fuzz '^FuzzEvidencePath$$' -fuzztime=1s
	go test ./internal/capturekit -run '^$$' -fuzz '^FuzzStateEvaluator$$' -fuzztime=1s
	go test ./internal/capturekit -run '^$$' -fuzz '^FuzzImportSourceSelector$$' -fuzztime=1s
	go test ./internal/capturekit -run '^$$' -fuzz '^FuzzEvidenceArchiveValidator$$' -fuzztime=1s
	go test ./internal/capturekit -run '^$$' -fuzz '^FuzzEvidenceArchiveExtractor$$' -fuzztime=1s
	go test ./internal/capturekit -run '^$$' -fuzz '^FuzzCaptureKitReportSerializer$$' -fuzztime=1s

docs-check:
	go test ./internal/buildtool -run '^TestDocumentationConsistency$$'
