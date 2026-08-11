# MemoryGuard v0.4 — action-firewall and incident-containment release

Release date: 10 August 2026.

## New security capabilities

- Retrieval/action-time firewall that re-scores the **combined recalled context** before a proposed action.
- L2-style compositional poisoning protection for payloads split across individually allowed memories.
- Direct high/critical action authorization separated from contextual memory.
- **Signed action-scope binding**: an explicit human approval is valid only for its immutable `metadata.authorization_scope`; unrelated authoritative memories are not blank cheques.
- Secret-material preflight and pre-persistence rejection for recognized private keys, API/access tokens, bearer/JWT credentials and explicit long credential assignments, including bounded decoded forms.
- Operator-only contamination graph and atomic descendant-chain containment.
- Signed `normal`, `read_only` and fail-closed `lockdown` runtime modes.
- Scan-only API/tool path.
- Action-check support in MCP, Hermes, OpenClaw skill/CLI and generic REST integration.
- GUI Action Firewall, authorisation-scope entry and incident-response controls.

## Hardening retained from v0.3

- origin-bound, non-amplifying authority;
- machine-derived memories capped below action authority;
- HMAC-signed immutable creation records and mutable state seals;
- database/signing-secret binding;
- keyed hash-chained audit events;
- idempotent writes/conflict detection;
- namespace and ancestry enforcement;
- atomic revision/rollback;
- SQLite WAL/foreign-key/integrity diagnostics and safe migration backups;
- API/operator least-privilege split;
- bounded HTTP/request/metadata handling;
- Ed25519 entitlement verification and vendor/customer key separation;
- one-folder automated installation and version-tolerant agent integration.

## Verification performed before packaging

- 80/80 customer automated tests pass.
- 5/5 vendor-control-plane tests pass.
- Live authenticated HTTP smoke passes: dashboard/security headers, secret rejection, direct poisoning quarantine, split-memory blocking, scoped authorization rejection/acceptance, read-only, lockdown, containment and deep integrity.
- Fresh vendor-issued Pro entitlement verifies in the customer build with installation binding.
- JavaScript syntax check and Python compile/import checks pass.
- Customer distribution is scanned to exclude runtime DBs, local HMAC/operator secrets, logs, caches and vendor private signing material.
- Clean-extracted release is retested before final ZIP creation.

## Deliberate security limits

v0.4 is a hardened single-node MVP, not a formal security proof. The action firewall depends on host integrations calling it before consequential execution. Action scopes prevent unrelated approval reuse, but v0.4 does **not** yet implement a durable Issue/Prepare/Commit consumption ledger for semantic replay/exactly-once external effects. Production deployments still need OS/container isolation, KMS/HSM, production identity/RBAC, remote immutable audit anchoring, independent penetration/red-team review and reproducible public benchmark evaluation.

## Release integrity

The customer ZIP includes `RELEASE_MANIFEST.json` plus `scripts/verify_release.py`. This verifies SHA-256 hashes of shipped files after extraction. It detects modification/packaging corruption but is **not** equivalent to an externally signed publisher release. Production public releases should add offline code/release signing.

## Naming notice

An independent OWASP project currently uses the name **OWASP Agent Memory Guard**. This package is not affiliated with or endorsed by OWASP. Commercial launch should complete name/trademark clearance and strongly consider a distinctive product brand.
