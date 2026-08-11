# Docker deployment — AgentInterdict v0.4

## 1. Generate a real signing secret

Do not store the vendor licence-signing private key here. This is only the local HMAC secret used for AgentInterdict creation/audit records.

Example:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Set the signing secret, a separate API key, and a separate operator key in your shell or secret manager:

```bash
export AGENTINTERDICT_SECRET='<generated signing secret>'
export AGENTINTERDICT_API_KEY='<different long random API key>'
export AGENTINTERDICT_OPERATOR_KEY='<different long random operator key>'
```

PowerShell:

```powershell
$env:AGENTINTERDICT_SECRET='<generated signing secret>'
$env:AGENTINTERDICT_API_KEY='<different long random API key>'
$env:AGENTINTERDICT_OPERATOR_KEY='<different long random operator key>'
```

## 2. Start

```bash
docker compose up --build
```

The published host listener is loopback-only by default and maps to port `43847`. API endpoints still require the configured API key; the dashboard will prompt for it on first API request.

Override the port:

```bash
AGENTINTERDICT_PORT=45137 docker compose up --build
```

## 3. Remote access

Do not change the published binding to a public interface without an authenticated reverse proxy or `AGENTINTERDICT_API_KEY`. The container itself binds internally to `0.0.0.0`, but Compose publishes it only on host `127.0.0.1` by default.

## Hardening included

- non-root runtime user;
- read-only application filesystem;
- writable `/data` volume only for database/backups;
- tmpfs `/tmp`;
- startup doctor check;
- container health check;
- no predictable default signing/operator secret;
- release-pinned security dependency baseline;
- restart policy;
- localhost-only host publishing.

For multi-user/enterprise deployment, move state to a production database, put keys in a KMS/HSM or managed secret store, use TLS/authentication/RBAC/rate limits at the ingress, and add a remote immutable audit sink.
