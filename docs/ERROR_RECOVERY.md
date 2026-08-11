# Error handling and recovery — AgentInterdict v0.4

AgentInterdict separates operational failures so recovery does not silently weaken enforcement.

## Port occupied

If the port was not explicitly set, the installer selects a documented high-port fallback. If the user explicitly requested a port, AgentInterdict fails rather than killing the process already using it.

## Dependency installation failure

The installer attempts the release-pinned dependency set, then compatible secure ranges. If package installation is unavailable, it accepts a preinstalled runtime only after verifying every security bound. A host below the release floor (including `cryptography>=50`) fails closed. Optional MCP failure is reported without disabling the core unless `--require-mcp` was requested.

## SQLite busy/locked

The database uses WAL, foreign keys, busy timeout and serialized in-process writes. Lock/busy conditions are classified as retryable storage failures rather than corruption.

## Database corruption

`/health` performs only a lightweight liveness/schema probe. Full `PRAGMA quick_check`, foreign-key checks and cryptographic state verification run during diagnostics/deep integrity. Corruption is fail-closed: stop writes and restore a verified backup; do not auto-delete/recreate the database.

## Wrong local signing secret

The database is bound to the signing secret. An accidental `AGENTINTERDICT_SECRET` change aborts startup/diagnostics rather than presenting a healthy-looking vault whose seals no longer verify. Restore the original secret from the protected deployment secret store; do not “fix” the DB by resealing unknown state.

## Migration failure

Before migrating an existing database, AgentInterdict creates a timestamped pre-migration backup. Migration runs transactionally and aborts on failure rather than resetting state.

## Secret material detected

Recognized private keys, known API/access tokens, bearer/JWT credentials and explicit long credential assignments are rejected before persistence. The audit event stores only a content hash and signal names. If this fires on a legitimate workflow, put the secret in a dedicated secret manager and persist only a reference/identifier; do not disable the guard.

## Malformed expiry or persisted JSON

Malformed new expiry timestamps are rejected at validation. Old/tampered malformed security-critical data is excluded from guarded retrieval and reported by integrity verification.

## Duplicate/retried writes

Use `idempotency_key`. Repeating the same key/payload returns the existing item; reusing a key with altered semantics returns a conflict. Consequential external tools should also use sink-level idempotency because AgentInterdict's action check does not itself guarantee exactly-once external effects.

## Suspected poisoned memory

1. Switch runtime mode to `read_only` to stop new memory writes while preserving recall for investigation, or `lockdown` to block consequential action checks.
2. Use the operator-only contamination report on the suspected memory ID.
3. Review the root and descendants.
4. Use containment to atomically quarantine the root/derived chain. This re-seals enforcement state and records pre-containment signature validity in the audit event.
5. Run deep integrity and create a backup/evidence copy before destructive remediation elsewhere.
6. Restore `normal` mode only after the incident is understood.

## Runtime-mode tampering

`normal`, `read_only` and `lockdown` are signed state. Missing/invalid runtime-mode signatures fail closed to lockdown. Do not manually edit the mode rows in SQLite; use the operator API/dashboard.

## Action authorization mismatch

High/critical actions require a direct authoritative human/system record with signed `metadata.authorization_scope`. If the action does not match, issue a new narrowly-scoped approval; do not broaden an unrelated authorization or promote a derived summary.

## Licence corruption/control-plane outage

Malformed, forged, wrong-installation, expired or stale-offline leases fall back to Community capability. A previously valid signed offline lease can continue only until its signed offline deadline; the customer never receives the vendor signing private key.

## Audit/database tampering

Creation records and request fingerprints are HMAC-signed; mutable authority/status state has a separate HMAC seal; audit events are hash-chained and HMAC-signed. Editing content, immutable provenance, mutable enforcement state or event payloads without the local secret is detected by deep integrity and unsafe records are excluded from guarded recall.

## Remote exposure

Default bind is localhost. Remote binding requires an ordinary API key. Administrative reads/actions additionally require the operator key. If the runtime agent can read those keys from disk, OS/container separation is required; application checks cannot defend against a same-user arbitrary-file-read attacker.
