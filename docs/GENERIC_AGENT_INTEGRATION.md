# Generic agent integration — AgentInterdict v0.4

Use one of three paths, in the preference order supported by the host. The integration objective is **guarded persistent writes + guarded recall + pre-action authorization**, not merely mirroring memory after the host has already committed it.

## 1. MCP v2 stdio

Install optional MCP dependencies:

```bash
python -m pip install -r requirements-mcp.txt
```

Run:

```bash
python integrations/mcp/server.py
```

The MCP process is a thin authenticated client of the already-running AgentInterdict gateway; it does not open SQLite directly. Runtime tools include scan, guarded store/derive/recall, pre-action check, statistics and lightweight health. Administrative containment, audit, deep integrity and runtime-mode changes remain operator-only.

## 2. Local agent CLI

Windows:

```bash
.venv/Scripts/python.exe scripts/interdict.py health
.venv/Scripts/python.exe scripts/interdict.py scan "candidate text" --source-type web
.venv/Scripts/python.exe scripts/interdict.py recall "customer preference" --namespace my-agent
.venv/Scripts/python.exe scripts/interdict.py store "example" --source-type web --namespace my-agent
.venv/Scripts/python.exe scripts/interdict.py check-action "Deploy release 4.2" --risk high --authorization-ids 42 --namespace my-agent
```

On Unix replace `.venv/Scripts/python.exe` with `.venv/bin/python`.

## 3. REST API

Preflight without persistence:

```text
POST /api/v1/scan
```

Write candidate:

```text
POST /api/v1/memories
```

Recall:

```text
POST /api/v1/search
```

Before a consequential action:

```text
POST /api/v1/action-check
```

Operator-only incident/administration paths include:

```text
GET/POST /api/v1/runtime-mode
GET      /api/v1/memories/{id}/contamination
POST     /api/v1/memories/{id}/contain
GET      /api/v1/integrity
```

If `AGENTINTERDICT_API_KEY` is configured, runtime requests send `X-AgentInterdict-Key`. Do **not** give the runtime agent the operator key.

## High/critical authorization rule

A high/critical action must have a direct authoritative `human_verified`/`system_config` record whose **signed metadata** contains `authorization_scope`. Example operator-created memory metadata:

```json
{
  "authorization_scope": ["deploy release"]
}
```

`Deploy release version 4.2` matches that scope; `Transfer funds to supplier` does not. A derived summary cannot become an authorization record.

AgentInterdict v0.4 binds authorization to action scope, but it does not yet implement a full durable prepare/commit consumption ledger. External consequential sinks should still use their own idempotency/transaction controls.

## Integration invariant

A host is fully protected only when every relevant persistent write passes through AgentInterdict **before commitment** and every consequential tool action invokes the action firewall **before execution**. A post-write mirror or dashboard-only check is useful for audit but is not enforcement.

For high-assurance deployments, isolate AgentInterdict secrets/state from the runtime agent at the OS/container boundary.
