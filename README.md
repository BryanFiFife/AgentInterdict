<div align="center">

# 🛡️ AgentInterdict

### Runtime enforcement for autonomous AI agents

**Trust context. Verify authority. Interdict unsafe action.**

AgentInterdict sits at the runtime boundary of your autonomous agent. It **binds authority to origin**, **blocks credential leakage**, **quarantines prompt-injection poisoning**, and **revalidates every action before it executes** — so untrusted context can never become executable authority.

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Commercial-blueviolet?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-4f8cff?style=for-the-badge)](#)
[![CI](https://img.shields.io/github/actions/workflow/status/BryanFiFife/AgentInterdict/ci.yml?style=for-the-badge&label=CI&logo=github)](https://github.com/BryanFiFife/AgentInterdict/actions)
[![Stars](https://img.shields.io/github/stars/BryanFiFife/AgentInterdict?style=for-the-badge&logo=github&color=gold)](https://github.com/BryanFiFife/AgentInterdict)
[![Forks](https://img.shields.io/github/forks/BryanFiFife/AgentInterdict?style=for-the-badge&logo=github)](https://github.com/BryanFiFife/AgentInterdict)
[![Tests](https://img.shields.io/badge/tests-78%20passing-2ea44f?style=for-the-badge)](#)
[![LOC](https://img.shields.io/badge/core-2.7k%20LOC-4f8cff?style=for-the-badge)](#)

**Local-first · Fail-closed · Transparent & auditable**

</div>

---

## 🧠 The problem: your agent's memory is a weapon waiting to be aimed

Autonomous agents persist memory — and that memory is a **prime attack surface**. A single poisoned memory can make an agent leak secrets, ignore its system prompt, or take destructive actions, silently across every future session.

The industry is racing to give agents *more* memory, *more* tools, and *more* autonomy. Almost nobody is securing the boundary where **context becomes action**. That's the gap AgentInterdict closes.

> **The core insight:** *Retrieval is not permission. Reading a memory does not authorise acting on it.*

---

## ✨ What AgentInterdict does

AgentInterdict is a **local, transparent runtime** that sits between your agent and its memory store and enforces six security invariants:

| Invariant | What it means |
|---|---|
| 🔐 **Origin-bound authority** | Derived content can never outrank its source. External sources are non-authoritative by default. |
| 🚫 **No derivation amplification** | A recalled bundle can't gain authority it never had. |
| 🔍 **Retrieval ≠ permission** | Reading a memory doesn't authorise acting on it. |
| ⚡ **Action-time re-scoring** | The actual recalled bundle is re-scored *before* a tool action. |
| 🔑 **Credentials-not-memory** | Private keys, API tokens, JWTs and credential assignments are **rejected before persistence**. |
| 🧱 **Fail-closed tampering** | Direct DB tampering is detected; runtime flips to `lockdown`. |

**Honest scope:** AgentInterdict reduces and contains persistent-memory risk. It does not make prompt injection impossible and is not a substitute for host permissions, least-trust, sandboxing, or independent human approval for high-impact actions.

---

## 🚀 Quick start (Windows)

```text
1. Download your package (see below)
2. Unzip the folder
3. Double-click run_windows.bat
4. Open http://127.0.0.1:43847
```

The installer verifies Python, initialises the database, runs diagnostics, picks a safe port, and prepares the Hermes / OpenClaw / MCP / REST integration for you.

**Agent-assisted install:** copy the prompt in [`INSTALL_WITH_AGENT.txt`](INSTALL_WITH_AGENT.txt) and give it to your installation agent.

---

## 📦 Download

All packages are built from this repository. **One source, one download.**

| Tier | Download | Threat feed | Remote features |
|---|---|---|---|
| **Community** | [⬇️ Download](https://github.com/BryanFiFife/AgentInterdict/archive/refs/heads/main.zip) | Static (baked-in) | — |
| **Pro** · £79/mo | [⬇️ Download](https://github.com/BryanFiFife/AgentInterdict/archive/refs/heads/main.zip) | ✅ Weekly-updated | ✅ Advanced classifier, reputation feed |
| **Business** · £349/mo | [⬇️ Download](https://github.com/BryanFiFife/AgentInterdict/archive/refs/heads/main.zip) | ✅ Weekly-updated | ✅ + Policy packs, compliance packs, model hardening |
| **Enterprise** · £1,500/mo | [⬇️ Download](https://github.com/BryanFiFife/AgentInterdict/archive/refs/heads/main.zip) | ✅ Weekly-updated | ✅ + CVE advisory feed, anomaly detection, remote audit |

> **How it works:** the code is free and open to download. Paid tiers unlock **remotely-controlled features** — the updated threat feed, hosted classifiers, policy packs and more — which are served from the AgentInterdict control plane and gated by your **signed licence lease**. Your agent presents its lease; the control plane verifies it cryptographically and serves the features your plan includes.

---

## 🎚️ Feature comparison

| Feature | Community | Pro | Business | Enterprise |
|---|:---:|:---:|:---:|:---:|
| Origin-bound local runtime | ✅ | ✅ | ✅ | ✅ |
| Static transparent risk rules | ✅ | ✅ | ✅ | ✅ |
| Single-operator GUI | ✅ | ✅ | ✅ | ✅ |
| Local audit & integrity verification | ✅ | ✅ | ✅ | ✅ |
| Basic REST API | ✅ | ✅ | ✅ | ✅ |
| **Weekly-updated threat feed** | — | ✅ | ✅ | ✅ |
| **Hosted advanced semantic classifier** | — | ✅ | ✅ | ✅ |
| **Remote IP/domain/URL reputation feed** | — | ✅ | ✅ | ✅ |
| Hermes / MCP managed integration packs | — | ✅ | ✅ | ✅ |
| Audit export & reporting | — | ✅ | ✅ | ✅ |
| **Curated policy packs** | — | — | ✅ | ✅ |
| **Compliance packs** (GDPR/HIPAA/SOC2/ISO27001) | — | — | ✅ | ✅ |
| **Model-specific hardening** (Claude/GPT/Llama) | — | — | ✅ | ✅ |
| Multi-agent / multi-namespace management | — | — | ✅ | ✅ |
| Team accounts & RBAC | — | — | ✅ | ✅ |
| **CVE advisory feed** | — | — | — | ✅ |
| **Hosted anomaly detection** | — | — | — | ✅ |
| **Centralised remote audit dashboard** | — | — | — | ✅ |
| SSO / SAML | — | — | — | ✅ |
| Signed offline leases | — | — | — | ✅ |
| SLA & priority support | — | — | — | ✅ |

---

## ✅ Verified — measured, honestly

We publish our test suite and its results — passing and failing — so you can run it yourself. A security tool that hides its misses isn't trustworthy.

### Injection benchmark (200-attempt suite)

A fixed suite of **200 real attack payloads** run through the actual enforcement engine. Reproduce it with `python scripts/benchmark_injection.py`.

| Attack category | Attempts | Blocked | Missed | Block rate |
|---|---|---|---|---|
| Direct injection | 50 | 48 | 2 | **96%** |
| Obfuscated / encoded | 50 | 47 | 3 | **94%** |
| Multi-turn / split | 50 | 48 | 2 | **96%** |
| Tool-call hijack | 50 | 50 | 0 | **100%** |
| **Total** | **200** | **193** | **7** | **96.5%** |

The 7 misses are documented with payloads in the benchmark script so you can reproduce and assess them yourself. We do not publish block-rate percentages we can't reproduce.

### Test suite

| Suite | Passed | Failed | Skipped | Status |
|---|---|---|---|---|
| Core enforcement tests | 78 | 0 | 1 | ✅ passing |
| Tamper / fail-closed tests | 9 | 0 | 0 | ✅ passing |

Run the full suite yourself with `pytest tests`. The enforcement invariants (origin-bound authority, no derivation amplification, retrieval ≠ permission, action-time re-scoring, credentials-not-memory, fail-closed tampering) are exercised by these tests.

---

## 🧠 How it works

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
   +--> high/critical without direct matching action-scoped authority -> BLOCK
   +--> passes policy -> ALLOW (host permissions still apply)
```

### Key endpoints
```text
POST /api/v1/scan          # inspect a candidate without persisting
POST /api/v1/memories      # write a memory through the gate
POST /api/v1/search        # guarded retrieval
POST /api/v1/action-check  # action-time firewall
GET  /api/v1/stats         # gateway statistics
```

---

## 🧰 Integrations

- **Hermes** — [`integrations/hermes/agentinterdict/`](integrations/hermes/agentinterdict/)
- **OpenClaw** — [`agent_install/openclaw-skill/`](agent_install/openclaw-skill/)
- **MCP** — [`integrations/mcp/server.py`](integrations/mcp/server.py)
- **Generic REST** — [`examples/client.py`](examples/client.py)

---

## 📚 Documentation

| Doc | Purpose |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Technical architecture & invariants |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Assets, adversaries, controls & gaps |
| [`docs/INSTALL_WINDOWS.md`](docs/INSTALL_WINDOWS.md) | Windows install guide |
| [`docs/INSTALL_DOCKER.md`](docs/INSTALL_DOCKER.md) | Docker install guide |
| [`docs/HERMES_INTEGRATION.md`](docs/HERMES_INTEGRATION.md) | Hermes integration |
| [`docs/OPENCLAW_INTEGRATION.md`](docs/OPENCLAW_INTEGRATION.md) | OpenClaw integration |
| [`docs/ERROR_RECOVERY.md`](docs/ERROR_RECOVERY.md) | Operational contingencies |
| [`LITERATURE.md`](LITERATURE.md) | Research & standards map |

---

## 🛡️ Incident response

If poisoning or tampering is suspected:

1. Set runtime mode to `lockdown` — stops writes, action checks fail closed.
2. Run deep integrity verification.
3. Use the contamination report on the suspect root memory.
4. Atomically contain the root plus descendants.
5. Review audit history and restore from a known-good state.
6. Return to `read_only` for observation, then `normal` after remediation.

---

## 🔒 Security posture

- **Fail-closed everywhere.** Tampering, invalid lineage, and lockdown all block by default.
- **Privilege separation.** Operator vs. ordinary runtime API keys are distinct.
- **Local by construction.** Your agent's context never leaves your machine. No cloud, no telemetry, no data exfiltration.

---

## 📄 License

AgentInterdict is **free for Community use** and commercially licensed for Pro, Business, and Enterprise tiers. See the [LICENSE](LICENSE) for terms.

---

<div align="center">

**Built for safer autonomous agents**

[⬇️ Download Community](https://github.com/BryanFiFife/AgentInterdict/archive/refs/heads/main.zip) · [⭐ Star this repo](https://github.com/BryanFiFife/AgentInterdict) · [🐛 Report an issue](https://github.com/BryanFiFife/AgentInterdict/issues)

</div>
