# Windows SCCM policy capture preparation

This guide is for synthetic research or an explicitly authorized, isolated SCCM lab. CinderPath does not register clients, trigger policy retrieval, start packet capture, or contact a management point.

Generate a passive workspace first:

```bash
cinderpath lab capture-plan --output capture-plan
```

It creates restricted templates, review instructions, safe offline commands,
synthetic sanitizer sentinels, and ignore rules. It performs no collection or
network activity.

## Preconditions

- Use a disposable Windows 11 or Windows Server VM with a snapshot.
- The Configuration Manager client must already be installed, registered, and assigned by the lab administrator.
- Use a lab-only management point and a restricted output directory.
- Never use customer production data or commit raw captures.

Useful passive inventory commands (availability varies by client version and configuration):

```powershell
Get-CimInstance -Namespace root\ccm -ClassName SMS_Client
Get-ChildItem C:\Windows\CCM\Logs
Get-ChildItem Cert:\LocalMachine\My
```

These commands inventory local state. They do not prove that a source contains the policy request body. Do not export certificate private keys.

## Capture checklist

1. Snapshot the lab machine.
2. Confirm the client is already registered and assigned.
3. Start approved local tracing or isolated packet capture tooling.
4. Trigger an ordinary policy retrieval using supported Configuration Manager administration—not CinderPath.
5. Stop capture and copy it to an encrypted, access-controlled directory.
6. Prepare the documented fixture layout and run metadata-only sanitization first.
7. Review the manifest and manually inspect opaque binary bodies.
8. Use text-region sanitization only after confirming length-preserving replacement is appropriate.
9. Search for real identifiers, credentials, tokens, certificates, hostnames, and sentinel values.
10. Import only the reviewed sanitized fixture.
11. Run local replay and offline analysis.
12. Record body review, run a final leakage scan, inspect the bundle, and only
    then share the reviewed bundle through the authorized channel.

```bash
# Synthetic or explicitly authorized isolated-lab paths only.
cinderpath protocol inspect-binary captures/raw-example/request.body
cinderpath protocol sanitize --input captures/raw-example --output captures/sanitized-example --binary-mode metadata_only
cinderpath protocol review-sanitization --directory captures/sanitized-example \
  --approve-body request.body --approve-body response.body --reviewer-reference LAB_REVIEW_001
cinderpath protocol bundle export --contract CONTRACT_ID \
  --directory captures/sanitized-example --output sanitized-policy-bundle.tar.gz
cinderpath protocol bundle inspect --input sanitized-policy-bundle.tar.gz
```

`metadata_only` never changes opaque bodies. `text_regions` applies only
same-byte-length replacements in detected ASCII/UTF-8/UTF-16 regions.
`structured_known` modifies only supported parsed structures. Review records
inspection, not sanitization, and cannot override leakage detection or approve
live collection.

Captures can contain credentials, cookies, certificates, client identifiers, machine/user SIDs, hostnames, and customer data. Never upload raw captures to a public repository. A sanitizer cannot replace manual review of an unknown binary protocol. Only synthetic or reviewed sanitized fixtures belong in `testdata`.

Current CinderPath sanitization is conservative and does not claim opaque binary bodies are safe. Reviewed bundles may be Ed25519-signed and compared through research sets as described in [`PROTOCOL_RESEARCH.md`](PROTOCOL_RESEARCH.md), but signatures and candidate contracts do not approve live use. Live policy support still requires independently reviewed authorized captures, an exact reproducible contract, identity prerequisites, framing/version rules, demonstrated read-only behavior, and separate safety approval.

Reviewed HAR, PCAP, and PCAPNG files may be imported through offline `capture`
commands. PCAPNG Ethernet decoding does not make TLS plaintext visible, and an
HTTP/1 reconstruction remains evidence with an explicit completeness state—not
authorization or technical support for sending that traffic.
## Generated passive capture kit

Use `cinderpath lab capture-kit create --output DIR` for the guided workflow and read [CAPTURE_KIT.md](CAPTURE_KIT.md). Generated inventory, preparation, and finalization scripts are local and passive. They do not start capture or trigger SCCM behavior. `Get-ComputerInfo`, read-only `Get-CimInstance -Namespace root\ccm -ClassName SMS_Client`, log-directory listing, and certificate metadata listing are examples only; namespaces and classes vary by SCCM version/environment. A policy retrieval must be observed naturally or initiated separately through an approved lab procedure.

After authorized transfer to Linux, `lab capture-kit inspect-logs` performs bounded generic structural inspection only. It does not infer SCCM semantics from filenames or recover passwords. Remove the synthetic leakage sentinel only after confirming the leakage check detects it; unresolved authorization, token, cookie, key, hash, or sentinel evidence blocks capture-evidence export. Windows runtime execution remains optional manual validation; normal CI uses static and golden script tests.

On 2026-08-02 the generated scripts were exercised on one disposable GOAD client running Windows Server 2019 Standard Evaluation build 17763, Windows PowerShell Desktop 5.1.17763.8510, and Configuration Manager client 5.00.9128.1007. Inventory wrote schema-v1 client/tool JSON; preparation wrote the start timestamp and synthetic sentinel; finalization wrote the schema-v1 raw-sensitive manifest without copying logs or creating an archive. The administrator test account used process-scoped execution-policy bypass. Bounded pre/post state was unchanged, and no capture process or script-created network action was observed; these checks are not proof for other environments. The lab-only remote harness used its existing self-signed HTTPS WinRM configuration with certificate verification ignored for that single authorized VM, not a CinderPath setting or supported production practice.

A later authorized passive baseline used the already installed `pktmon` 10.0.17763.3650 for 600 seconds on one active adapter. No client schedule, control-panel action, service restart, or custom SCCM request was invoked. `pktmon` reported 212 packets and zero drops; its ETL was retained and converted locally to PCAPNG. Offline analysis found no visible HTTP exchange and no structurally supported policy exchange. It did report opaque TLS and incomplete/conflicting TCP reconstruction, so the evidence is classified as `sccm_endpoint_metadata_only`. The raw files remain uncommitted and require sanitization plus manual review.

In a separate explicitly authorized run, the locally enumerated Configuration Manager control-panel action `Request & Evaluate Machine Policy` was invoked once. It is a combined request/evaluation action; no second evaluation or other schedule was invoked. A 205-second `pktmon` capture reported 407 packets and zero drops. `CcmMessaging.log` and `PolicyAgent.log` were the only allowlisted logs changed and copied. The policy log records a machine-assignment request and no new assignments. CinderPath found one partial flow and three visible, ordered HTTP exchanges, but those were unrelated Windows trust-list traffic. SCCM transport remained opaque, so the result is logs-only trigger evidence rather than a policy protocol contract. CinderPath itself sent no policy request, changed no identity, and performed no replay.

Returned evidence can be correlated without contacting Windows:

```bash
# Synthetic paths and trigger values only.
cinderpath capture correlate --capture capture.pcapng --logs client-logs \
  --trigger policy-trigger.json --output reports/correlation
```

The timeline preserves timestamp offsets and precision. Capture quality reports
gaps, retransmissions, conflicting overlaps, truncation, link type, direction
confidence, and timestamp resolution. Zero tool-reported drops cannot erase
those limitations, and timing or port 443 alone remains low confidence.
