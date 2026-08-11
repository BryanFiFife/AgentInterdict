# Agent-assisted self-install — AgentInterdict v0.4

AgentInterdict is designed so the **entire customer runtime can remain in one extracted folder**. Give a capable installation agent that directory plus the root `INSTALL_WITH_AGENT.txt`; it can install the gateway, dashboard, tests and the best compatible host integration without searching for separate application assets.

## What stays in the folder

The extracted directory contains the API service, dashboard, security policies, tests, MCP adapter, Hermes provider, OpenClaw skill template, diagnostic/backup scripts, literature review and documentation. Runtime files also default here: `.venv`, `agentinterdict.db`, `.agentinterdict-secret`, `.agentinterdict-operator-key`, `.agentinterdict-port`, `backups/`, and `installation-result.json`.

The first installation agent is temporarily trusted to create these files. The long-running runtime agent should not be able to read the signing or operator secrets. Paid licence identity may live under the user's normal `~/.agentinterdict` directory. Vendor signing keys never belong in the customer folder.

## Fast automated install

```bash
python scripts/self_install.py --with-mcp
```

Use `python3`/`py -3` when appropriate. To start after all checks:

```bash
python scripts/self_install.py --with-mcp --start
```

The installer finds a Python 3.10+ interpreter, creates `.venv`, enforces secure dependency floors, creates separate signing/operator secrets, chooses 43847 or a safe documented fallback, migrates/backups existing state without deletion, runs diagnostics and the full test suite, then writes `installation-result.json`.

## Required success checks

An installation agent must verify more than “the process started”:

- lightweight `/health` and browser dashboard;
- deep integrity via `scripts/doctor.py` or operator API;
- secret-material preflight/rejection without persistence;
- benign non-authoritative storage and guarded recall;
- direct prompt-injection quarantine;
- split/compositional-memory blocking at action time;
- action-scope binding for high/critical authorization;
- signed read-only and lockdown incident modes, restored to normal after the test;
- descendant contamination report and atomic containment using disposable test records;
- selected host integration can store/recall/pre-check actions without receiving operator/signing secrets;
- existing databases were migrated/backed up rather than overwritten.

## Port conflicts

43847 is preferred. When the user did not explicitly force a port, AgentInterdict may fall back to 43853, 43909, 45137, 47321 or 49157. If `AGENTINTERDICT_PORT` is explicitly set and occupied, startup fails loudly rather than silently moving.

## Remote access

Default binding is `127.0.0.1`. A remote bind requires `AGENTINTERDICT_API_KEY`; diagnostics intentionally fail a configured unauthenticated remote bind. Production remote exposure should also use TLS/reverse-proxy controls and network restriction.

## Restricted/offline package indexes

If pip cannot reach compatible packages, the installer verifies the preinstalled runtime against every documented security version floor. It does not silently accept an older vulnerable dependency. MCP is optional unless `--require-mcp` is passed, so a restricted MCP package mirror does not have to cripple the core gateway.

## Runtime-agent secret isolation

After installation, do **not** give an autonomous runtime agent unrestricted filesystem/shell access to `.agentinterdict-secret`, `.agentinterdict-operator-key`, licence state or SQLite. Runtime integrations need the gateway URL and ordinary API key only.

For stronger deployments, run AgentInterdict under a separate OS service account/container. No application-layer secret scheme can protect a plaintext key from another process with arbitrary same-user file-read privileges.
