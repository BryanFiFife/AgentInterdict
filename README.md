<div align="center">

# 🛡️ AgentInterdict

### Runtime enforcement for autonomous AI agents

**Trust context. Verify authority. Interdict unsafe action.**

[![Release](https://img.shields.io/github/v/release/BryanFiFife/AgentInterdict?style=for-the-badge&logo=github&label=release)](https://github.com/BryanFiFife/AgentInterdict/releases/latest)
[![CI](https://img.shields.io/github/actions/workflow/status/BryanFiFife/AgentInterdict/ci.yml?branch=main&style=for-the-badge&logo=githubactions&logoColor=white&label=CI)](https://github.com/BryanFiFife/AgentInterdict/actions)
[![Tests](https://img.shields.io/badge/tests-123%20passing-2ea44f?style=for-the-badge&logo=pytest&logoColor=white)](#verified)
[![Benchmark](https://img.shields.io/badge/injection%20benchmark-96.5%25-2ea44f?style=for-the-badge&logo=target&logoColor=white)](#injection-benchmark)

[![Python](https://img.shields.io/badge/Python-3.10--3.13-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Platforms](https://img.shields.io/badge/Windows%20%7C%20Linux%20%7C%20macOS-supported-4f8cff?style=for-the-badge)](#installation)
[![Docker](https://img.shields.io/badge/Docker-smoke%20tested-2496ED?style=for-the-badge&logo=docker&logoColor=white)](#verified)
[![MCP](https://img.shields.io/badge/MCP-v2%20adapter-7C3AED?style=for-the-badge)](#integrations)

[![Local First](https://img.shields.io/badge/LOCAL--FIRST-yes-111827?style=for-the-badge&logo=homeassistant&logoColor=white)](#security-model)
[![Fail Closed](https://img.shields.io/badge/FAIL--CLOSED-default-b91c1c?style=for-the-badge&logo=shield&logoColor=white)](#security-model)
[![Origin Bound](https://img.shields.io/badge/AUTHORITY-origin--bound-0f766e?style=for-the-badge)](#core-invariants)
[![License](https://img.shields.io/badge/License-Community%20%2B%20Commercial-blueviolet?style=for-the-badge)](LICENSE)

**Local-first · origin-bound · tamper-evident · action-time enforcement**

[Live site](https://agentinterdict.pages.dev/) · [Latest release](https://github.com/BryanFiFife/AgentInterdict/releases/latest) · [Security model](docs/THREAT_MODEL.md) · [Architecture](ARCHITECTURE.md)

</div>

---

## Why AgentInterdict exists

Autonomous agents increasingly read documents, browse the web, process email, recall long-term memory and call consequential tools. Every one of those inputs can carry attacker-controlled instructions.

AgentInterdict sits between **context and consequence**. It does not try to make a language model magically immune to prompt injection. It makes untrusted context prove that it has the authority to influence a consequential action.

> **Retrieval is not permission.** A memory can be relevant and still have zero authority to approve an action.

---

## v0.6.0 hardening release

v0.6.0 closes the release and commercial-path gaps identified during a full repository audit.

| Area | v0.6.0 |
|---|---|
| Runtime versioning | One canonical version source across API, installer and MCP |
| Community threat rules | Always loaded as the non-removable baseline |
| Paid threat feed | Selected from the locally verified signed licence |
| Paid feed transport | HTTPS, no redirects, bounded response, entitlement bearer authentication |
| Paid feed authenticity | Ed25519 signature, tier, expiry and minimum-runtime verification |
| Remote failure | Safe fallback to the complete Community baseline, never an empty detector |
| Feed semantics | Paid rules are additive and cannot replace/weaken baked-in Community signals |
| Package integrity | Every ZIP carries a SHA-256 `RELEASE_MANIFEST.json` |
| Release provenance | GitHub build provenance attestation + `SHA256SUMS.txt` |
| CI | Linux 3.10/3.12/3.13 + Windows 3.12 + package smoke + live Docker smoke |
| Current suite | **123 passing tests** |
| Injection benchmark | **193 / 200 blocked (96.5%)** on the published fixed corpus |

---

## Core invariants

AgentInterdict enforces these properties at the runtime boundary:

| Invariant | Enforcement |
|---|---|
| 🔐 **Origin-bound authority** | Content cannot manufacture authority merely by claiming to be trusted. |
| 🧬 **No derivation amplification** | Summaries and derived memories cannot outrank their least-trusted ancestry. |
| 🔍 **Retrieval ≠ permission** | Recall returns security context; relevance never becomes authorization by itself. |
| ⚡ **Action-time re-scoring** | The actual recalled bundle is rescanned immediately before consequential execution. |
| 🔑 **Credentials-not-memory** | Recognized private keys, tokens, JWTs and credential assignments are rejected before persistence. |
| 🧱 **Fail-closed tampering** | Invalid seals, lineage or runtime-mode signatures remove authority or force lockdown. |
| 🧾 **Code-change evidence gate** | AI-generated diffs can be scanned and recorded in the tamper-evident audit chain. |

AgentInterdict is one layer of a zero-trust agent stack. Host permissions, sandboxing and independent approval remain necessary for high-impact tools.

---

## Architecture

### Write path

```text
web / email / document / API / tool
                |
                v
       normalize + decode
                |
                v
        credential detector
          /          \
       reject       continue
                       |
                       v
              risk + provenance gate
               /       |       \
           allow     review   quarantine
                       |
                       v
             signed persistent vault
```

### Action path

```text
recalled memory bundle
        +
proposed tool/action
        |
        v
lineage + seal verification
        |
        v
combined-memory rescoring
        |
        v
authorization-scope matching
        |
   +----+----+
   |         |
 BLOCK      ALLOW
             |
             v
      host policy still applies
```

---

## Installation

### Windows

1. Download the release ZIP.
2. Extract it.
3. Double-click `run_windows.bat`.
4. Open `http://127.0.0.1:43847`.

### Linux / macOS

```bash
python3 scripts/self_install.py --with-mcp --start
```

### Docker

```bash
export AGENTINTERDICT_SECRET='<random 32+ byte signing secret>'
export AGENTINTERDICT_API_KEY='<different random 32+ byte runtime key>'
export AGENTINTERDICT_OPERATOR_KEY='<different random 32+ byte operator key>'
docker compose up --build
```

Docker now declares its internal remote bind explicitly, so startup cannot accidentally treat a `0.0.0.0` listener as loopback-only.

---

## Downloads

Release artifacts are built from the tagged source, manifest-verified, checksummed and provenance-attested.

| Tier | Package |
|---|---|
| **Community** | [agentinterdict-community.zip](https://github.com/BryanFiFife/AgentInterdict/releases/latest/download/agentinterdict-community.zip) |
| **Pro** | [agentinterdict-pro.zip](https://github.com/BryanFiFife/AgentInterdict/releases/latest/download/agentinterdict-pro.zip) |
| **Business** | [agentinterdict-business.zip](https://github.com/BryanFiFife/AgentInterdict/releases/latest/download/agentinterdict-business.zip) |
| **Enterprise** | [agentinterdict-enterprise.zip](https://github.com/BryanFiFife/AgentInterdict/releases/latest/download/agentinterdict-enterprise.zip) |

All tiers contain the same hardened local enforcement engine. The **signed licence**, not an editable local tier flag, determines paid entitlement.

Verify an extracted release before installation:

```bash
python scripts/verify_release.py
```

The release also publishes `SHA256SUMS.txt`. GitHub provenance attestations provide build-origin evidence in addition to the local hash manifest.

---

## Paid threat-feed security

Community enforcement never depends on the network.

A valid paid lease with the `threat_feed` feature enables this flow after restart:

```text
signed local licence
      |
      v
verify Ed25519 entitlement
      |
      v
derive plan: pro/business/enterprise
      |
      v
HTTPS request + bearer lease
      |
      v
receive signed threat bundle
      |
      v
verify publisher signature
verify tier
verify expiry
verify minimum runtime
      |
      v
ADD to Community baseline
```

Any failure in that chain leaves the baked-in Community detector active. A paid remote feed can add rules but cannot remove or replace the local baseline.

The remote bundle is expected to carry an Ed25519 `signature` over canonical JSON and an `expires_at` timestamp. The verification key defaults to the packaged vendor public key and can be independently pinned with `AGENTINTERDICT_THREAT_PUBLIC_KEY_FILE`.

### Scope of this repository

The open-source runtime currently implements and tests **local enforcement, licensing, authenticated signed threat-feed overlays, REST, MCP, Hermes/OpenClaw adapters, audit/integrity, incident response and package verification**.

Entitlement names for hosted classifier, organisational RBAC, SSO/SAML, SIEM or other hosted control-plane services should **not** be interpreted as implementations inside this repository. Those capabilities require separate control-plane components and are not claimed as part of the v0.6.0 local runtime test result.

---

## Verified

### Test matrix

The CI gate runs the complete test suite on:

- Ubuntu + Python 3.10
- Ubuntu + Python 3.12
- Ubuntu + Python 3.13
- Windows + Python 3.12
- package build/extract/manifest verification for all four release tiers
- Docker image build + real container startup + `/health` probe

**Current result: 123 passed.**

The suite covers origin authority, derivation, action scoping, compositional poisoning, credential rejection, Unicode/encoded evasion, tampering, HMAC audit integrity, runtime modes, contamination containment, idempotency semantics, migration atomicity, concurrency, licensing, signed remote feed validation, release manifests and API enforcement.

### Injection benchmark

The public fixed corpus contains 200 payloads.

| Category | Attempts | Blocked | Missed | Block rate |
|---|---:|---:|---:|---:|
| Direct injection | 50 | 48 | 2 | 96% |
| Obfuscated / encoded | 50 | 47 | 3 | 94% |
| Multi-turn / split | 50 | 48 | 2 | 96% |
| Tool-call hijack | 50 | 50 | 0 | 100% |
| **Total** | **200** | **193** | **7** | **96.5%** |

Run it yourself:

```bash
python scripts/benchmark_injection.py
```

This is a reproducible regression corpus, not a claim that 96.5% of every possible future attack will be detected.

---

## Integrations

| Integration | Path | Model |
|---|---|---|
| **MCP** | `integrations/mcp/server.py` | Thin authenticated client of the gateway |
| **Hermes** | `integrations/hermes/agentinterdict/` | External MemoryProvider + pre-action tool |
| **OpenClaw** | `agent_install/openclaw-skill/` | Workspace skill + safe CLI |
| **Generic agents** | `scripts/interdict.py` | REST/CLI integration |
| **Code-change review** | `POST /api/v1/code-change` | Signed evidence verdict |

The GUI and adapters are clients. They are not security boundaries.

---

## API

```text
GET  /health
GET  /api/v1/system
GET  /api/v1/license
POST /api/v1/scan
POST /api/v1/code-change
POST /api/v1/memories
POST /api/v1/search
POST /api/v1/action-check
GET  /api/v1/stats
GET  /api/v1/audit                  operator
GET  /api/v1/integrity              operator
GET  /api/v1/runtime-mode           operator
POST /api/v1/runtime-mode           operator
POST /api/v1/backup                 operator
POST /api/v1/memories/{id}/contain operator
```

Ordinary runtime and operator credentials are intentionally separate.

---

## Security model

AgentInterdict uses:

- SHA-256 content hashes
- HMAC-SHA-256 immutable creation signatures
- separate mutable-state HMAC seals
- signed runtime modes
- HMAC-authenticated hash-chained audit events
- Ed25519 subscription entitlement verification
- Ed25519 paid threat-feed verification
- local DB-to-secret binding
- CSP, frame denial, no-store and referrer hardening
- bounded body, metadata, response and remote-feed sizes
- localhost-by-default deployment
- authenticated remote binding
- SQLite WAL, full synchronous writes and explicit transactions
- verified migration backups
- additive-only paid threat overlays

### Known trust assumptions

AgentInterdict cannot protect itself from a fully privileged host attacker that can read the signing secret and rewrite the process or database. High-assurance deployments should isolate the service account/container, put secrets in an OS secret service/KMS/HSM and anchor audit evidence remotely/WORM.

Integrations must actually route consequential actions through `action-check`. A malicious host tool that bypasses the gateway remains outside the enforcement boundary.

A durable one-use prepare/commit action-capability protocol remains an architectural future-proofing target for exactly-once high-impact execution.

---

## Incident response

1. Set runtime mode to `lockdown`.
2. Run deep integrity verification.
3. Generate a contamination report for the suspected root memory.
4. Atomically quarantine the root and descendants.
5. Review the keyed audit chain.
6. Restore from a known-good backup if necessary.
7. Move to `read_only` for observation.
8. Return to `normal` only after remediation.

---

## Documentation

- [Architecture](ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Windows installation](docs/INSTALL_WINDOWS.md)
- [Docker installation](docs/INSTALL_DOCKER.md)
- [Hermes integration](docs/HERMES_INTEGRATION.md)
- [OpenClaw integration](docs/OPENCLAW_INTEGRATION.md)
- [Generic agent integration](docs/GENERIC_AGENT_INTEGRATION.md)
- [Error recovery](docs/ERROR_RECOVERY.md)
- [Research and standards map](LITERATURE.md)

---

## License

Community use is free under the terms in [LICENSE](LICENSE). Commercial tiers use signed entitlements for paid functionality.

---

<div align="center">

### 🛡️ Trust context. Verify authority. Interdict unsafe action.

[⬇️ Latest release](https://github.com/BryanFiFife/AgentInterdict/releases/latest) · [⭐ Star AgentInterdict](https://github.com/BryanFiFife/AgentInterdict) · [🐛 Report an issue](https://github.com/BryanFiFife/AgentInterdict/issues)

</div>
