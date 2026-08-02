# Offline SCCM protocol contract research

Capture-level research is documented in [CAPTURE_INGESTION.md](CAPTURE_INGESTION.md),
[SEQUENCE_RESEARCH.md](SEQUENCE_RESEARCH.md), [STRUCTURED_PARSERS.md](STRUCTURED_PARSERS.md),
and [CONTROLLED_CAPTURE_MATRIX.md](CONTROLLED_CAPTURE_MATRIX.md). It consumes
synthetic or authorized-lab files locally and never elevates candidate contracts.
The passive Windows preparation and guided import workflow is documented in
[CAPTURE_KIT.md](CAPTURE_KIT.md); kit metadata/review are operator assertions,
not evidence of registration, retrieval, identity validation, or live approval.
Capture-evidence bundles use `bundle_type: capture_evidence` and intentionally do
not require a protocol contract. Protocol-contract research bundles retain their
existing contract/fixture semantics. Neither command family accepts the other
bundle type, and capture-evidence import or signature verification never creates
or promotes an `approved_live` contract.

Generic XML, JSON, and multipart parsers emit bounded redacted structure, not
SCCM semantics. Parser lifecycle states are `observed_structure`,
`candidate_parser`, `fixture_validated`, `corpus_validated`, `rejected`, and
`conflicting`; none can enable live execution.

This workflow is for synthetic fixtures or reviewed captures from already
registered clients in an explicitly authorized isolated lab. It never sends an
SCCM policy request, creates an identity, registers a client, or approves live
execution.

## Signing and verification

```bash
cinderpath protocol signing-key generate --output ~/.config/cinderpath/research-signing-key
cinderpath protocol bundle sign --input sanitized-policy-bundle.tar.gz \
  --key ~/.config/cinderpath/research-signing-key \
  --output sanitized-policy-bundle.signed.tar.gz
cinderpath protocol bundle verify --input sanitized-policy-bundle.signed.tar.gz
```

All paths are synthetic or authorized-lab examples. Keys are versioned
Ed25519 files. Private keys are atomic mode `0600`, never printed or persisted
in SQLite, and never bundled. Signatures cover canonical bundle/member identity
and expected-analysis fingerprints. They prove integrity under the embedded key
only. Known signers do not establish capture authenticity, sanitization
completeness, safety, or protocol approval.

## Research sets and candidate contracts

```bash
cinderpath protocol research-set create --name lab-policy-baseline \
  --controlled client_identity,site_code --fixed management_point,client_version \
  --output research-set.yaml
cinderpath protocol research-set add --set research-set.yaml \
  --bundle client-a-bundle.tar.gz --label client-a \
  --expected client_identity=CLIENT_A --expected site_code=ABC
cinderpath protocol research-set analyze --set research-set.yaml
cinderpath protocol correlations --research-set research-set.yaml
cinderpath protocol sequences --research-set research-set.yaml
cinderpath protocol contract derive --research-set research-set.yaml --output candidate-contract.yaml
cinderpath protocol contract dossier --contract candidate-contract.yaml \
  --research-set research-set.yaml --output reports/protocol-contract-dossier
```

Controlled variables are operator declarations, never inferences. Generic
analysis stores redacted fingerprints. Comparisons separate constants, subset
presence, unexplained variation, conflicts, and non-comparability. Correlations
report samples and counterexamples, never causation.

`candidate_contract` is offline research evidence only. It retains constants,
variables, conflicts, unknown prerequisites, algorithm version, and coverage.
No normal command promotes it to `approved_live` or uses it for live traffic.

Safety reviews can record `not_reviewed`, `needs_more_evidence`, `rejected`,
`candidate_read_only`, or `approved_for_local_replay`. Dossiers contain no raw
bodies, authorization material, private keys, replacement maps, or plaintext
secrets. `protocol bundle test` verifies a signed bundle before bounded offline
expected-result checks.

Live SCCM execution remains unsupported and unapproved. Eventual review still
requires authorized multi-version captures, exact identity/framing/sequence
evidence, counterexamples, failure behavior, rate limits, and demonstrated
read-only semantics. Research signatures are evidence, not authorization.

The first ten-minute natural-activity Windows baseline decoded 212 PCAPNG
packet records but yielded no supported flows or visible HTTP exchanges.
Opaque-TLS and incomplete/conflicting TCP-reassembly warnings prevent protocol
claims. This capture is metadata-only evidence and does not change the live
blocker. A useful next controlled variable is a separately authorized capture
window around a normal operator-managed client cycle, still without CinderPath
triggering or replaying policy traffic.

The second controlled capture invoked the installed client's standard combined
machine-policy action once and recorded 407 packets over approximately 205
seconds. Allowlisted logs positively record the request and a no-new-assignments
outcome. Offline reconstruction found one partial TCP flow and three ordered
HTTP exchanges, but all visible routes belonged to unrelated Windows trust-list
downloads. Remaining TLS could not be attributed structurally to the policy
cycle, and duplicate, gap, conflict, and incomplete-response warnings remain.
The evidence is therefore `machine_policy_trigger_observed_logs_only`, not a
candidate policy exchange. No sanitized protocol fixture was derived.

## Offline trigger/log/TLS correlation

`cinderpath capture correlate` consumes local PCAP/PCAPNG evidence, a bounded
log directory, and schema-v1 trigger JSON. It normalizes fixture-supported
CMTrace and ISO-like timestamps to UTC while preserving original offsets and
precision. Filenames alone never assign SCCM semantics.

```json
{"schema_version":1,"timestamp":"2026-07-01T10:00:00Z","action":"machine_policy_cycle"}
```

```bash
cinderpath capture correlate --capture synthetic.pcapng --logs synthetic-logs \
  --trigger trigger.json --pre-window 30s --post-window 3m \
  --output reports/correlation --format text
```

Representative redacted synthetic output:

```text
Offline SCCM capture correlation
Trigger: 2026-07-01T10:00:00Z (machine_policy_cycle)
Log events: 2
Candidate TLS flows: 1
Capture quality: partial_but_usable
Correlation: low_confidence_sccm_tls_candidate
Dossier: correlation
Live SCCM policy requests: 0
  tls_candidate_<FINGERPRINT> score=30 confidence=low support=2 contradictions=0
Safety: offline evidence only; timing alone does not prove SCCM protocol identity.
```

The scorer considers temporal distance, fingerprinted log endpoints, visible
ClientHello SNI, and reconstruction gaps. Port 443 and timing alone cannot
produce high confidence. Even a high-ranked opaque flow is attribution evidence,
not a recovered policy exchange. The mode-`0700` dossier contains redacted
timeline, semantic-event, candidate, quality, summary, and gap files; packet
bodies and complete log lines are excluded. Correlation uses existing schema-v8
redacted capture observation/dossier persistence, so no migration is required.
Secret-extraction readiness remains `not_ready_no_policy_evidence`.

Defaults are 30 seconds before and 180 seconds after the trigger, bounded by a
15-minute maximum. Activity within 2 seconds receives strong temporal weight,
within 10 seconds medium weight, and within 60 seconds weak weight. These are
ranking inputs, not proof. Reused connections that begin outside the window,
missing timestamps, indistinguishable candidates, and capture gaps remain
explicit contradictions or warnings.

The retained controlled-capture run verified this redacted result:

```text
Offline SCCM capture correlation
Log events: 431
Candidate TLS flows: 6
Capture quality: partial_but_usable
Correlation: no_correlatable_tls_flow
Live SCCM policy requests: 0
Safety: offline evidence only; timing alone does not prove SCCM protocol identity.
```

Its timeline contains 908 events. Correcting CMTrace UTC-bias handling placed
one assignment request and one no-new-assignments event inside the trigger
window. The closest TLS flow was the known WinRM control channel and is explicit
contradicting evidence. The HTTPS/SNI-bearing flow lacked a matching log endpoint
fingerprint. This does not justify policy framing, encrypted-value, or secret
decoder work.

## Offline endpoint attribution

`cinderpath capture correlate-endpoints` accepts an offline PCAP/PCAPNG,
bounded logs, passive client-inventory JSON, and a controlled trigger record.
It extracts bounded UDP/TCP DNS questions and A/AAAA/CNAME answers, fingerprints
all names and addresses, and joins those observations to TLS SNI, flow endpoint
fingerprints, fixture-supported log hints, and inventory management-point
metadata. It never resolves a name or contacts an endpoint.

```bash
# Synthetic offline paths only.
cinderpath capture correlate-endpoints --capture capture.pcapng \
  --logs client-logs --inventory client-inventory.json \
  --trigger trigger.json --output reports/endpoint-correlation
```

The graph distinguishes exact matches, captured DNS resolution,
address-to-flow links, SNI-to-hostname links, and inventory/log matches. Timing
and common ports remain weak evidence; WinRM control ports are contradictions.
On retained evidence, inventory plus logs supported a medium-confidence
management-point endpoint, while DNS/address and SNI did not link that endpoint
to a TLS flow. The result is `endpoint_identified_but_flow_ambiguous`, not a
policy contract or secret-extraction prerequisite.

Local above-TLS research now begins with `lab client-artifacts`. It records WMI
class schemas and bounded instance value shapes without invoking methods, then
ranks policy candidates and emits an advisory export plan. A property name,
entropy, base64 shape, or timestamp alone cannot establish a secret. See
[`LOCAL_POLICY_ARTIFACTS.md`](LOCAL_POLICY_ARTIFACTS.md). No local content copy,
decryption, or live protocol action is implied.

One authorized Windows Server 2019 / PowerShell 5.1 execution confirmed the
metadata path against an installed Configuration Manager 5.00.9128.1007 client.
It observed accessible policy schemas but no structurally supported encrypted
value, supporting `ready_for_policy_schema_parser`. Intrinsic WMI classes are
excluded from policy scoring. The run did not copy policy bodies, establish a
protection mechanism, recover plaintext, trigger policy, or send a live SCCM
request.
