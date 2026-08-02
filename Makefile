SHELL := /bin/sh

BINARY := bin/cinderpath
PACKAGE := ./cmd/cinderpath
MODULE := github.com/Lmarkussen/CinderPath
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || printf '%s' dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf '%s' unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf '%s' unknown)
LDFLAGS := -X $(MODULE)/internal/version.Version=$(VERSION) -X $(MODULE)/internal/version.Commit=$(COMMIT) -X $(MODULE)/internal/version.BuildDate=$(BUILD_DATE)

.PHONY: help build test vet fmt fmt-check check run clean race integration install-local auth-dry-run config-example run-mock run-dry protocol-fixtures protocol-test protocol-report-test protocol-bundle-test protocol-signing-test protocol-research-test protocol-contract-test protocol-dossier-test protocol-expected-results-test policy-offline-test fuzz-policy fuzz-protocol fuzz-protocol-research capture-test capture-integration pcapng-test exchange-test sequence-test parser-test matrix-test analysis-replay-test capture-dossier-test capture-cli-test capture-kit-test capture-kit-cli-test capture-kit-script-test guided-import-test windows-log-test capture-evidence-bundle-test capture-evidence-signing-test correlation-test timeline-test flow-attribution-test capture-quality-test dns-evidence-test endpoint-attribution-test endpoint-graph-test local-artifact-test local-artifact-cli-test local-artifact-script-test local-artifact-fuzz policy-schema-test policy-instance-selection-test policy-schema-parser-test policy-content-plan-test policy-schema-fuzz policy-preview-test policy-preview-script-test policy-preview-fuzz framework-coverage-test credential-target-test credential-policy-test naa-discovery-test task-sequence-policy-test credential-policy-fuzz pxe-assessment-test pxe-candidate-test pxe-script-test pxe-fuzz capture-fuzz pcapng-fuzz exchange-fuzz sequence-fuzz parser-fuzz matrix-fuzz analysis-fuzz capture-kit-fuzz correlation-fuzz endpoint-correlation-fuzz protocol-offline-check docs-check
.PHONY: pxe-provider-test pxe-deployment-test pxe-deployment-script-test pxe-deployment-fuzz
.PHONY: cli-audit-test cli-public-surface-test cli-compatibility-test cli-workflow-test
.PHONY: cli-complexity-test cli-artifact-context-test cli-flag-budget-test cli-dead-flag-test

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
	  '  correlation-test       offline SCCM log/capture correlation tests' \
	  '  timeline-test          normalized timestamp timeline tests' \
	  '  flow-attribution-test  opaque TLS candidate-ranking tests' \
	  '  capture-quality-test   reassembly and capture-quality tests' \
	  '  dns-evidence-test      bounded offline DNS parsing tests' \
	  '  endpoint-attribution-test passive SCCM endpoint scoring tests' \
	  '  endpoint-graph-test    fingerprint-only endpoint graph tests' \
	  '  endpoint-correlation-fuzz bounded DNS/endpoint fuzz smoke tests' \
	  '  local-artifact-test    bounded local SCCM artifact model tests' \
	  '  local-artifact-cli-test offline local-artifact CLI tests' \
	  '  local-artifact-script-test passive PowerShell static tests' \
	  '  local-artifact-fuzz    bounded metadata/parser fuzz smoke tests' \
	  '  policy-schema-test     schema ranking and family tests' \
	  '  policy-instance-selection-test bounded concrete instance planner tests' \
	  '  policy-schema-parser-test fixture-driven schema parser tests' \
	  '  policy-content-plan-test reviewed preview/export gate tests' \
	  '  policy-schema-fuzz     bounded schema/planner/parser fuzz smoke tests' \
	  '  policy-preview-test    reviewed redacted preview model and dossier tests' \
	  '  policy-preview-script-test exact-allowlist PowerShell safety tests' \
	  '  policy-preview-fuzz    bounded preview parser fuzz smoke test' \
	  '  framework-coverage-test truthful roadmap registry and CLI tests' \
	  '  credential-target-test targeted credential registry tests' \
	  '  credential-policy-test targeted schema/instance/dossier tests' \
	  '  naa-discovery-test    NAA candidate evidence tests' \
	  '  task-sequence-policy-test task-sequence and variable target tests' \
	  '  credential-policy-fuzz bounded credential metadata fuzz smoke test' \
	  '  pxe-assessment-test  bounded PXE/OSD posture analysis tests' \
	  '  pxe-candidate-test   exact one-target candidate evidence tests' \
	  '  pxe-script-test      passive PowerShell collector safety tests' \
	  '  pxe-fuzz             bounded PXE metadata fuzz smoke test' \
	  '  pxe-provider-test    SMS Provider metadata safety tests' \
	  '  pxe-deployment-test  PXE deployment relationship assessment tests' \
	  '  pxe-deployment-script-test provider collector PowerShell safety tests' \
	  '  pxe-deployment-fuzz  bounded provider metadata fuzz smoke test' \
	  '  correlation-fuzz       bounded offline correlation fuzz smoke tests' \
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

correlation-test:
	go test ./internal/capture ./internal/buildtool -run 'TestCorrelation|TestSemantic|TestCaptureCorrelationCLI'

timeline-test:
	go test ./internal/capture -run 'TestTimeline'

flow-attribution-test:
	go test ./internal/capture -run 'TestCorrelation.*Candidate|TestCorrelationEndpoint|TestTCPOverlap'

capture-quality-test:
	go test ./internal/capture -run 'TestCaptureQuality|TestTCPOverlap'

dns-evidence-test:
	go test ./internal/capture -run 'TestDNS'

endpoint-attribution-test:
	go test ./internal/capture -run 'TestEndpointCorrelation|TestEndpointTiming|TestEndpointWinRM|TestEndpointTrust|TestLoadInventory'
	go test ./internal/buildtool -run 'TestCaptureEndpointCorrelationCLI'

endpoint-graph-test:
	go test ./internal/capture -run 'TestEndpointCorrelation|TestEndpointDossier'

local-artifact-test:
	go test ./internal/localartifact

local-artifact-cli-test:
	go test ./internal/buildtool -run '^TestLocalArtifactCLI'

local-artifact-script-test:
	go test ./internal/localartifact -run '^TestCreatePassivePowerShell51$$'

policy-schema-test:
	go test ./internal/localartifact -run 'TestSchemaRanking|TestIntrinsic'

policy-instance-selection-test:
	go test ./internal/localartifact -run 'TestInstancePlan'

policy-schema-parser-test:
	go test ./internal/localartifact -run 'TestFixtureParsers'

policy-content-plan-test:
	go test ./internal/localartifact -run 'TestSchemaRankingSelectionFamiliesAndDossier|TestPasswordName'

policy-schema-fuzz:
	go test ./internal/localartifact -run '^$$' -fuzz '^FuzzSchemaClassifier$$' -fuzztime=1s
	go test ./internal/localartifact -run '^$$' -fuzz '^FuzzSchemaClustering$$' -fuzztime=1s
	go test ./internal/localartifact -run '^$$' -fuzz '^FuzzInstancePlanner$$' -fuzztime=1s
	go test ./internal/localartifact -run '^$$' -fuzz '^FuzzContentGate$$' -fuzztime=1s
	go test ./internal/localartifact -run '^$$' -fuzz '^FuzzPolicyFixtureParser$$' -fuzztime=1s

policy-preview-test:
	go test ./internal/localartifact -run 'TestPreview'

policy-preview-script-test:
	go test ./internal/localartifact -run 'TestPreviewPlanAndPowerShellSafety'

policy-preview-fuzz:
	go test ./internal/localartifact -run '^$$' -fuzz '^FuzzPreviewCollection$$' -fuzztime=1s

framework-coverage-test:
	go test ./internal/framework

credential-target-test:
	go test ./internal/localartifact -run 'TestCredentialRegistry'

credential-policy-test:
	go test ./internal/localartifact -run 'TestCredential'

naa-discovery-test:
	go test ./internal/localartifact -run 'TestCredentialRegistryAndAnalysis'

task-sequence-policy-test:
	go test ./internal/localartifact -run 'TestCredentialRegistryAndAnalysis'

credential-policy-fuzz:
	go test ./internal/localartifact -run '^$$' -fuzz '^FuzzCredentialRuntime$$' -fuzztime=1s

pxe-assessment-test:
	go test ./internal/pxe

pxe-candidate-test:
	go test ./internal/pxe -run 'TestCandidate|TestNoPXE'

pxe-script-test:
	go test ./internal/pxe -run 'TestSafetyAndDossier'

pxe-fuzz:
	go test ./internal/pxe -run '^$$' -fuzz '^FuzzPXERuntime$$' -fuzztime=1s

pxe-provider-test:
	go test ./internal/pxe -run 'TestDeploymentCollectorSafety|TestDeploymentRuntimeSafety'

pxe-deployment-test:
	go test ./internal/pxe -run 'TestDeploymentAssessment'

pxe-deployment-script-test:
	go test ./internal/pxe -run 'TestDeploymentCollectorSafety'

pxe-deployment-fuzz:
	go test ./internal/pxe -run '^$$' -fuzz '^FuzzPXEDeploymentRuntime$$' -fuzztime=1s

cli-audit-test:
	go test ./internal/cli -run 'TestCommandInventory'

cli-public-surface-test:
	go test ./internal/cli -run 'TestPublicSurface'

cli-compatibility-test:
	go test ./internal/cli -run 'TestObsoleteDuplicateAlias|TestUnsupportedExecution'

cli-workflow-test:
	go test ./internal/cli -run 'TestAssessWorkflow|TestCommandInventoryJSON'

cli-complexity-test:
	go test ./internal/cli -run 'TestComplexityBudgets'

cli-artifact-context-test:
	go test ./internal/artifact ./internal/cli -run 'TestRegisterResolve|TestAmbiguous|TestArtifactContext'

cli-flag-budget-test:
	go test ./internal/cli -run 'TestComplexityBudgets|TestNoPublicArtifactPathFlags'

cli-dead-flag-test:
	go test ./internal/cli -run 'TestUnsupportedExecution|TestObsoleteDuplicateAlias'

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

correlation-fuzz:
	go test ./internal/capture -run '^$$' -fuzz '^FuzzLogTimestampParser$$' -fuzztime=1s
	go test ./internal/capture -run '^$$' -fuzz '^FuzzTimelineOrdering$$' -fuzztime=1s
	go test ./internal/capture -run '^$$' -fuzz '^FuzzTCPOverlapResolver$$' -fuzztime=1s
	go test ./internal/capture -run '^$$' -fuzz '^FuzzFlowCandidateScorer$$' -fuzztime=1s
	go test ./internal/capture -run '^$$' -fuzz '^FuzzCaptureQualitySerializer$$' -fuzztime=1s

endpoint-correlation-fuzz:
	go test ./internal/capture -run '^$$' -fuzz '^FuzzDNSNameDecompression$$' -fuzztime=1s
	go test ./internal/capture -run '^$$' -fuzz '^FuzzDNSMessageParser$$' -fuzztime=1s
	go test ./internal/capture -run '^$$' -fuzz '^FuzzEndpointGraphConstruction$$' -fuzztime=1s
	go test ./internal/capture -run '^$$' -fuzz '^FuzzEndpointCandidateScoring$$' -fuzztime=1s
	go test ./internal/capture -run '^$$' -fuzz '^FuzzTLSMetadataCorrelation$$' -fuzztime=1s
	go test ./internal/capture -run '^$$' -fuzz '^FuzzEndpointDossierSerialization$$' -fuzztime=1s

local-artifact-fuzz:
	go test ./internal/localartifact -run '^$$' -fuzz '^FuzzInventoryParser$$' -fuzztime=1s
	go test ./internal/localartifact -run '^$$' -fuzz '^FuzzValueShapeClassifier$$' -fuzztime=1s
	go test ./internal/localartifact -run '^$$' -fuzz '^FuzzCandidateScorer$$' -fuzztime=1s
	go test ./internal/localartifact -run '^$$' -fuzz '^FuzzDossierSerializer$$' -fuzztime=1s

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
