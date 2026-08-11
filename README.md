# MemoryGuard v0.4

MemoryGuard is a local security gateway for persistent AI-agent memory. It sits between an agent and long-term memory, binds authority to origin, scores suspicious content, blocks definite credential material from persistence, quarantines likely poisoning, preserves provenance, evaluates recalled memory combinations at action time, and supports incident containment and rollback.

> **Security claim:** MemoryGuard reduces and contains persistent-memory risk. It does not make prompt injection impossible and it is not a substitute for host permissions, least privilege, sandboxing, or independent human approval for high-impact actions.

## What is new in v0.4

- **Action-time memory firewall**: re-evaluates the actual recalled bundle before a tool action. High/critical actions require direct, sealed, authoritative human/system authorization memories with immutable signed action scopes.
- **Compositional-attack detection**: individually benign records are joined and rescored immediately before execution to catch split L2-style payloads.
- **Secret-material guard**: private keys, recognized API/access tokens, bearer/JWT credentials and explicit long credential assignments are rejected before they can be written to persistent memory. Only a content hash and signal names are audited.
- **Scan-only endpoint**: inspect a candidate without persisting it.
- **Blast-radius containment**: map all descendants of a suspect memory and quarantine the entire derivation chain atomically.
- **Signed runtime modes**: `normal`, `read_only`, and fail-closed `lockdown`; direct database tampering with the mode is detected.
- **Agent integration support** for action checks through MCP, Hermes, OpenClaw CLI/skill, and generic REST.

## Existing security controls

- REST API + browser security console
- Origin-bound authority: `untrusted`, `observed`, `verified`, `authoritative`
- External sources non-authoritative by default
- Derived content cannot outrank its least-trusted parent and is capped below authoritative
- Automatic allow/review/quarantine decisions
- Human review and constrained authority promotion
- Parent lineage and compact origin-root propagation
- Namespace isolation and expiry
- Guarded retrieval with `safe_for_action` and a security envelope
- SHA-256 content hashing
- HMAC-signed immutable creation records
- HMAC-signed mutable enforcement state
- Keyed, hash-chained audit events
- Idempotent retry protection
- Atomic revision/rollback paths
- SQLite foreign keys, integrity diagnostics, WAL and verified backups
- Database-to-signing-secret binding
- API/operator privilege separation
- Ed25519 paid-entitlement verification
- Self-install bundle for automated agents

## Quick start on Windows

Unzip the complete folder and run:

```text
run_windows.bat
```

The preferred dashboard port is **43847**. If it is occupied and the port was not explicitly forced, the installer selects a documented uncommon fallback without killing another process.

Open:

```text
http://127.0.0.1:<selected-port>
http://127.0.0.1:<selected-port>/docs
```

The selected port is written to `.memoryguard-port`.

## Agent-assisted installation

Keep the extracted folder intact, copy its absolute directory, and give your installation agent the prompt in:

```text
INSTALL_WITH_AGENT.txt
```

The installer verifies Python and dependency security floors, initializes/migrates the database, performs backups, runs diagnostics and tests, chooses a safe port, and prepares the appropriate Hermes/OpenClaw/MCP/REST integration.

After installation, an ordinary runtime agent should receive only the MemoryGuard URL and ordinary API capability. It should **not** receive `.memoryguard-secret`, `.memoryguard-operator-key`, vendor signing keys, or direct database access.

## Runtime integration pattern

### Write path

```text
agent/tool/web/email
        |
        v
  scan / write gate
        |
        +--> definite credential -> REJECT (not persisted)
        +--> high poison risk ----> QUARANTINE
        +--> ambiguous -----------> REVIEW
        +--> safe observation ----> ALLOW AS DATA
```

### Read + action path

```text
agent recall
   |
   v
guarded retrieval
   |
   v
recalled memory bundle + proposed action
   |
   v
POST /api/v1/action-check
   |
   +--> compositional poison / invalid lineage / lockdown -> BLOCK
   +--> high/critical without direct matching action-scoped human/system authority -> BLOCK
   +--> passes policy -> ALLOW (host permissions still apply)
```

Important endpoints:

```text
POST /api/v1/scan
POST /api/v1/memories
POST /api/v1/search
POST /api/v1/action-check
GET  /api/v1/stats
```

Operator-only endpoints include full-vault access, review, authority changes, revisions, rollback, contamination reports, containment, runtime-mode changes, audit history, deep integrity, and backup.

## Incident response

If poisoning or tampering is suspected:

1. Set runtime mode to `lockdown` to stop runtime writes and make action checks fail closed.
2. Run deep integrity verification.
3. Use the contamination report on the suspect root memory.
4. Atomically contain the root plus descendants.
5. Review audit history and restore/revise from a known-good state.
6. Return to `read_only` for observation, then `normal` only after remediation.

## Subscription architecture

The customer build contains only public verification material for paid entitlements. Vendor private signing keys stay in the vendor control plane. A patched local GUI cannot create a cryptographically valid entitlement, and premium hosted services should independently verify subscription state server-side.

No locally distributed application can be literally uncrackable. The commercial strategy is to keep high-value threat intelligence, cloud classifiers, policy feeds, managed reporting, and other premium services on infrastructure controlled by the vendor.

## Literature and threat model

- `LITERATURE.md` — research and standards map
- `ARCHITECTURE.md` — technical architecture and invariants
- `docs/THREAT_MODEL.md` — assets, adversaries, controls and remaining gaps
- `docs/ERROR_RECOVERY.md` — operational contingencies
- `docs/AGENT_SELF_INSTALL.md` — one-folder automated deployment
- `RELEASE_NOTES_v0.4.md` — release changes and validation
- `scripts/verify_release.py` — verify packaged SHA-256 manifest after extraction

## Name/affiliation notice

OWASP currently has an open-source project named **OWASP Agent Memory Guard**. MemoryGuard is not affiliated with or endorsed by OWASP. Before a public commercial launch, perform trademark/name clearance and consider a more distinctive commercial brand if counsel or market testing suggests confusion risk.

## Production limitations

v0.4 remains a hardened single-node security MVP, not a formally verified enterprise appliance. Before making strong enterprise assurances, add production tenant/RBAC architecture, Postgres isolation, KMS/HSM-backed keys, TLS termination, remote/WORM audit anchoring, distributed rate/abuse controls, SBOM/signing/CI supply-chain controls, benchmark coverage against public memory-poisoning corpora, and independent penetration/red-team review.
