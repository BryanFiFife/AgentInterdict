# AgentInterdict v0.6 architecture

## Core invariants

1. **Content cannot manufacture its own authority.** Authority is bound to origin at write time.
2. **Derivation cannot amplify authority.** Derived memories inherit the least-trusted parent and are capped below authoritative.
3. **Retrieval relevance is not permission.** A memory can be useful data while remaining unable to authorize an action.
4. **Write-time safety is insufficient.** The actual recalled bundle is re-evaluated at action time for compositional/context-triggered risk.
5. **Definite credentials are not memory.** Recognized private keys, API/access tokens, bearer/JWT credentials and explicit long credential assignments are rejected before persistence.
6. **Tampering fails closed.** Invalid mutable-state/runtime-mode signatures remove authority or force lockdown.

## Trust domains

```text
UNTRUSTED OBSERVATIONS
web / email / docs / APIs / tool output
            |
            v
+----------------------------+
| Scan / write gate          |
| normalize + risk + secret  |
+----------------------------+
   | reject     | review/quarantine
   | credential |
   v            v
 NO STORAGE   ISOLATED STATE
                 |
                 v
         +--------------------+
         | Persistent vault   |
         | origin + lineage   |
         | signed state       |
         +--------------------+
                 |
                 v
         +--------------------+
         | Guarded retrieval  |
         +--------------------+
                 |
                 v
  +--------------------------------+
  | ACTION-TIME MEMORY FIREWALL    |
  | bundle scan + auth separation  |
  +--------------------------------+
        | allow            | block
        v                  v
  host tool policy     audit/incident
```

## Write path

1. Validate bounded request shape and metadata.
2. Normalize Unicode/confusables and bounded encoded payloads for static scanning.
3. Detect high-confidence credential/private-key material. Definite secrets are rejected before storage; the audit stores only the candidate hash and signal names.
4. Compute SHA-256 content hash.
5. Bind immutable origin ID and compact origin-root set.
6. Assign origin authority.
7. Validate parent lineage, namespace, status, expiry, seals and authority.
8. Score candidate risk for triage.
9. Allow, review or quarantine.
10. HMAC-sign immutable creation data and mutable enforcement state.
11. Append a keyed hash-chained audit event.

## Read path

1. Search `allowed` memories unless an operator explicitly requests review items.
2. Verify creation/state seals, namespace, status and expiry.
3. Recursively validate ancestry. A revoked/quarantined/expired/tampered parent dynamically blocks descendants.
4. Return a security envelope and `safe_for_action` flag.
5. Remove internal authenticators from runtime-agent responses.

## Action-time firewall

`POST /api/v1/action-check` accepts:

- proposed action text;
- declared action risk;
- context memory IDs;
- separate authorization memory IDs;
- namespace and actor.

The gateway independently raises the effective risk when the action text contains consequential operations. It then:

- fails closed in lockdown;
- verifies every supplied memory and its ancestry;
- joins recalled context records and rescans the composition;
- blocks unsafe multi-record combinations;
- requires direct `human_verified` or `system_config` authoritative memories for high/critical actions;
- requires the immutable signed `metadata.authorization_scope` on an approval to deterministically match the proposed action family;
- refuses derived memories as action authorization even when their parents were authoritative;
- records only an action hash and policy result in the audit log.

Passing AgentInterdict does **not** bypass the host agent's tool permissions, user confirmations or external policy engine.

## Incident containment

An operator can request a contamination report for a root memory. AgentInterdict builds its descendant graph from stored parent lineage and can atomically:

- quarantine the root and all descendants;
- force their mutable authority to `untrusted`;
- reseal the containment state;
- record pre-containment integrity information in the audit event.

Immutable content tampering remains detectable after containment.

## Runtime modes

The mode is stored in `schema_meta` with an HMAC signature:

- `normal`: runtime writes and action checks operate normally.
- `read_only`: runtime memory writes are blocked; guarded reads remain available.
- `lockdown`: runtime writes are blocked and action checks fail closed.

If the runtime-mode value/signature is directly altered, AgentInterdict reports the mode as invalid and behaves as `lockdown`.

## Cryptographic/integrity design

- SHA-256 content hashes
- HMAC-SHA-256 creation-record signatures
- separate HMAC-SHA-256 mutable-state seals
- HMAC-signed runtime mode
- SHA-256 chained + HMAC-authenticated audit events
- Ed25519 vendor-signed subscription entitlements
- local database-to-secret binding check

Local HMACs cannot protect against a fully privileged attacker who can read the signing secret and rewrite the database. Enterprise deployments should put secrets in KMS/HSM/OS-protected services and anchor audit checkpoints remotely/WORM.

## Privilege model

Ordinary runtime agents can use:

- health
- scan-only
- write candidate memory
- guarded recall
- action check
- stats

Operator authority is required for:

- direct human/system authority writes
- full-vault reads
- review-inclusive search
- allow/quarantine decisions
- authority changes
- revision/rollback
- contamination reports/containment
- runtime-mode changes
- audit/deep integrity
- backup

## Storage and deployment

SQLite/WAL is appropriate for a local single-node MVP. Writes are serialized, operations use explicit transactions, foreign keys are enabled, migrations are backed up and verified, and health probes avoid expensive deep checks.

For production multi-tenant deployment, migrate to Postgres with tenant isolation/RLS and use managed secret storage.

## GUI

The browser console exposes:

- Overview/security posture
- Scan-only + ingest
- Action Firewall
- Memory Vault
- Review Queue
- Integrity/Audit
- Incident response (runtime mode + contamination containment)
- Integrations
- Subscription/entitlements
- Setup/docs

The GUI is a client, not a security boundary.
