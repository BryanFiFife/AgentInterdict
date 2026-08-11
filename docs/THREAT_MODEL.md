# MemoryGuard v0.4 threat model

## Assets

- Long-term agent memory
- User/organisation facts and preferences
- Agent execution integrity
- Secrets/credentials exposed to an agent
- Provenance/authority labels
- Audit evidence and rollback history
- Runtime incident-response state
- Subscription entitlements

## Threat actors

- Malicious webpages/documents/emails
- Prompt-injection content in tool output
- Malicious or compromised external APIs
- Normal users attempting persistent poisoning
- Compromised or confused runtime agents
- Insider/authenticated user abusing memory state
- Local filesystem/database attacker
- Customer attempting to bypass paid access

## Threats covered

1. Direct persistent memory poisoning
2. Sleeper/context-triggered poisoning
3. Multi-record/compositional poisoning
4. Trust laundering through summaries/rewrites
5. Trusted-tool echo laundering
6. Manufactured corroboration/authority amplification
7. Derived authorization laundering
8. Unauthorized human/system origin claims
9. Cross-namespace derivation/retrieval
10. Expired/revoked-parent reuse
11. Credential/private-key persistence
12. Credential exfiltration instructions
13. Content/state/database tampering
14. Audit-chain rewriting without the HMAC secret
15. Idempotency-key replay with altered semantics
16. HTTP body/resource amplification
17. Storage contention/corruption confusion
18. Runtime-mode tampering
19. Poison propagation into descendants
20. Blank-cheque use of unrelated authoritative approvals
21. Local entitlement modification/replay

## Current controls

- Origin-bound authority and non-amplifying derivation
- Separate operator capability for authority-conferring actions
- Static normalization/risk scanning
- Pre-persistence rejection of definite credential/private-key material
- Quarantine/review/allow lifecycle
- Signed immutable creation record + mutable enforcement state
- Parent lineage and origin roots
- Dynamic ancestry validation during recall/action checks
- Action-time combined-memory rescoring
- Direct authoritative memory requirement for high/critical actions
- Immutable action-scope binding for explicit human approvals
- Signed normal/read-only/lockdown runtime mode
- Atomic descendant-chain containment
- Keyed tamper-evident audit
- Revision/rollback and verified backups
- API/body/metadata bounds and least-privilege read surface
- Ed25519 subscription verification

## Trust assumptions

- The host OS/process is not fully compromised.
- The MemoryGuard HMAC/operator secrets are inaccessible to the ordinary runtime agent.
- Persistent writes that matter are routed through MemoryGuard.
- Consequential agent integrations call `action-check` before execution.
- Host tool permissions/approval remain active after MemoryGuard allows an action.
- Vendor private entitlement keys remain vendor-side.

## Fail-closed behavior

- Wrong database signing secret: startup/diagnostics fail.
- Invalid runtime-mode signature: effective mode is lockdown.
- Invalid creation/state seal: memory is excluded from normal recall/action authority.
- Malformed/expired lineage: derived memory is blocked.
- Definite credential material: candidate is rejected without persistent content storage.
- High/critical action without direct authoritative memory: blocked.
- Lockdown: runtime writes blocked and action checks denied.

## Out of scope / remaining limits

- Root/admin compromise of the host that exposes MemoryGuard secrets
- Formal proof that static/combined scoring detects every semantic attack
- Full semantic intent proof beyond deterministic signed action-scope matching
- Durable prepare/commit authorization consumption needed to prevent semantic replay/exactly-once failures
- Guaranteed deletion from copies outside MemoryGuard, vector stores, caches or backups
- Multi-node/tenant isolation in the SQLite build
- Protection if an integration intentionally skips the action firewall
- Protection against malicious host tools after they are independently authorized
- "Uncrackable" offline licensing
- Independent production penetration-test assurance

## Recommended host policy

Treat MemoryGuard as one layer in a zero-trust agent stack:

1. Run it under a separate service account/container where possible.
2. Give runtime agents only ordinary API capability.
3. Keep operator/key files outside agent-readable paths for higher-assurance deployments.
4. Require the action firewall for consequential tool categories.
5. Require short-lived, narrowly action-scoped human authorization memories for financial, destructive or privileged actions.
6. Use lockdown immediately on suspected poisoning/tampering.
7. Export/anchor audit evidence remotely in production.
