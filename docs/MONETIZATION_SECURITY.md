# MemoryGuard monetisation and subscription-security architecture

## Executive recommendation

Do **not** try to win by making a downloadable Python/desktop binary “uncrackable.” If customers possess executable code and control the host, a sufficiently motivated attacker can patch client-side checks.

Instead, make bypassing the local license economically useless:

1. Keep the local Community gateway genuinely useful.
2. Keep high-value paid capabilities on MemoryGuard-operated infrastructure.
3. Drive entitlements from Stripe Billing/Entitlements.
4. Issue short-lived, vendor-signed local leases for integrations that must run on-premise.
5. Never place the entitlement-signing private key, Stripe secret, cloud classifier credentials or premium threat-feed keys inside a customer build.

## Recommended tiers

### Community — free
- Origin-bound local gateway
- Static transparent risk rules
- Single-operator GUI
- Local audit/integrity verification
- Basic REST API

Purpose: adoption, developer trust and integration surface.

### Pro — target £49–99/month
- Continuously updated threat/rule feed
- Hosted advanced semantic memory classifier
- Hermes/MCP managed integration packs
- Audit export/reporting
- Remote policy updates
- Higher scan/agent limits

### Business — target £249–499/month
- Multi-agent / multi-namespace management
- Team accounts and RBAC
- Central policy packs
- Organisation dashboards
- Alerting/webhooks
- Longer retention and audit export

### Enterprise — target £1,500+/month or annual contract
- SSO/SAML
- Private cloud / VPC / on-prem deployment options
- Signed offline leases
- SIEM integration
- Dedicated policy packs
- SLA/support
- Security review / deployment assistance

## The anti-cracking design

### Principle 1 — server is the authority

The customer UI must never decide whether a subscription is paid. Stripe webhook events update a vendor entitlement database. The vendor API checks that database on every paid cloud request.

A cracked JavaScript button can display “Enterprise”; it still cannot cause the server to return Enterprise services.

### Principle 2 — private signing key never ships

For on-prem/local features, the control plane issues an Ed25519-signed lease. Customer software contains only the public key required for verification.

Lease claims should include:

- license ID
- customer/tenant ID
- plan
- explicit feature list
- issued/not-before/expiry times
- offline refresh deadline
- optional installation binding
- plan limits
- key version

### Principle 3 — leases are short lived

For ordinary Pro/Business users, refresh every 12–72 hours. If billing is cancelled or payment ultimately fails, the vendor stops issuing new leases. Keep a grace period so temporary outages do not brick legitimate installations.

Enterprise offline customers can receive longer leases under contract, accepting higher piracy risk in exchange for on-prem requirements.

### Principle 4 — premium value is remote and evolving

The most defensible paid assets should be things a static cracked binary cannot reproduce:

- current threat intelligence
- hosted classifiers
- reputation/origin intelligence
- centrally managed policies
- organisation dashboards
- remote audit anchoring
- alerts
- continuously updated attack signatures
- managed integrations
- compliance reporting

### Principle 5 — do not hide a master secret in obfuscated code

Obfuscation and compiled packaging can raise casual reverse-engineering cost, but they are delay mechanisms, not trust anchors. Never rely on them for authorization.

## Stripe lifecycle

Recommended flow:

```text
Customer → Stripe Checkout
              |
              v
       subscription event
              |
      verified webhook signature
              |
              v
 MemoryGuard entitlement database
              |
      active feature mapping
              |
    +---------+----------+
    |                    |
cloud API check     signed local lease
```

Provision paid access from verified subscription/entitlement state, not from a success-page redirect or customer-supplied plan name.

Events to handle include subscription creation/update/deletion, invoice payment success/failure and active-entitlement changes. Design webhook processing to be idempotent and record Stripe event IDs.

## Replay and sharing resistance

- Bind API access to tenant/account identity and server-issued API credentials.
- Rotate credentials and revoke compromised keys.
- Make local lease expiry short enough that a copied lease has limited value.
- Optionally bind leases to a randomly generated installation ID, not brittle hardware serials.
- Enforce plan limits server-side (agents, seats, scans, organisations, feed access).
- Track suspicious simultaneous use, but avoid invasive fingerprinting.
- Sign software updates and threat-feed packages.

## What not to do

- Do not embed Stripe secret keys in the desktop/local app.
- Do not embed an HMAC “license secret” shared by every customer; extracting it would let attackers mint licenses.
- Do not trust a local database flag such as `paid=true`.
- Do not use the UI as an entitlement boundary.
- Do not permanently unlock a perpetual binary after a single online check if recurring subscription enforcement matters.
- Do not make security-critical memory decisions unavailable when the licensing server is temporarily unreachable; fail safely into the locally available core rather than disabling protection.

## v0.4 entitlement implementation

The customer code verifies Ed25519-signed entitlement leases and falls back to Community when no valid paid lease exists. Development/vendor private material remains outside the customer distribution ZIP. The reference vendor control plane additionally enforces installation-count limits, revocation, bounded request bodies, non-default admin authentication, SQLite safety settings, and a signed/hash-chained vendor audit trail; it is still a reference service rather than a production SaaS control plane.

Before release, rotate the development key pair and move production private-key operations into a controlled server-side KMS/HSM or dedicated signing service.

## Development activation flow included in this release

The owner-only vendor ZIP includes `control_plane.py`. The customer ZIP includes `scripts/activate.py`.

Development sequence:

1. Vendor starts the private control plane on an internal port (example `43849`).
2. Vendor creates a subscription/license record and receives a one-time customer-facing `mgk_...` license key.
3. Customer runs:

```bash
python scripts/activate.py --server https://license.memoryguard.example --license-key mgk_...
```

4. The activation client generates a stable random installation ID locally.
5. The control plane validates subscription state and returns a short-lived Ed25519-signed lease bound to that installation.
6. The customer runtime verifies the lease using the public key embedded in the customer build.
7. Revocation prevents new leases; existing leases expire at their configured offline deadline.

Before production, replace the reference admin-token flow with authenticated operator tooling, add Stripe webhook signature verification/idempotency, PostgreSQL, KMS/HSM signing, distributed rate limits/abuse detection, secure update signing, monitoring/backups and high availability. The current vendor audit trail is local evidence, not a remote immutable/WORM anchor.
