# Windows SCCM policy capture preparation

This guide is for synthetic research or an explicitly authorized, isolated SCCM lab. CinderPath does not register clients, trigger policy retrieval, start packet capture, or contact a management point.

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

Captures can contain credentials, cookies, certificates, client identifiers, machine/user SIDs, hostnames, and customer data. Never upload raw captures to a public repository. A sanitizer cannot replace manual review of an unknown binary protocol. Only synthetic or reviewed sanitized fixtures belong in `testdata`.

Current CinderPath sanitization is conservative and does not claim opaque binary bodies are safe. Live policy support still requires an independently reviewed exact contract, identity prerequisites, framing rules, and read-only safety approval.
