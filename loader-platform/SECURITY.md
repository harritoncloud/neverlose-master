# Loader Security Model

## Automatic response

The loader reports only a complete SHA-256 mismatch observed through the same
open file handle that protected the staged module or injector. A valid report
must include a fresh server challenge and a P-256 signature from the device key
already bound to the authenticated loader session.

A verified report atomically:

- records an immutable security incident;
- changes the non-admin account to `disabled` (security hold);
- revokes all account sessions;
- invalidates outstanding loader download and automatic enrollment credentials;
- queues a redacted Discord alert for durable retry.

Permanent `banned` status is deliberately an administrator decision. Release a
false alarm with `/user-status status:active`; confirm abuse with
`/user-status status:banned`.

## Signals that never auto-block

- process names, debuggers, virtual machines, or monitoring tools;
- an invalid or missing signature;
- network failures or a Discord outage;
- an incomplete file read or other inconclusive local check;
- changed IP address, user agent, or failed authentication alone;
- a client-provided loader, account, or Discord identifier.

These signals are either unreliable or can be forged to attack another user.

## Discord privacy

Alerts contain only a shortened loader identifier and hash prefixes, a masked
IP prefix, the client version, component, incident number, and timestamp. HWID,
access tokens, enrollment secrets, full hashes, and module bytes are never sent.
Discord mentions are disabled. Failed deliveries remain in the database outbox
and retry every five minutes.

## Limitations

No user-mode loader can make a plaintext DLL impossible for a local
administrator to read or dump. The current path-based injector requires a
readable staged DLL, so read-only copying is not detectable by this integrity
signal. A modified client can also suppress its own telemetry. Closing those
gaps requires a different injection boundary and hardware-backed key
attestation, not process scanning or aggressive anti-debugging heuristics.
