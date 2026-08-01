# Offline SCCM protocol contract research

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
