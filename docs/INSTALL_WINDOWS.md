# Windows installation — AgentInterdict v0.4

## Recommended path: one-folder self-install

1. Extract `AgentInterdict-v0.4-customer.zip` to a writable directory such as `C:\AgentInterdict`.
2. Either give an automation agent the absolute folder path and `INSTALL_WITH_AGENT.txt`, or double-click `run_windows.bat`.
3. The installer selects a Python 3.10+ interpreter, creates `.venv`, enforces secure dependency versions, generates local signing/operator secrets, initializes/migrates the database and runs diagnostics/tests.
4. Preferred local URL: `http://127.0.0.1:43847`. If that port is occupied and you did not explicitly force it, an uncommon documented fallback is selected and recorded in `.agentinterdict-port` / `installation-result.json`.

## Requirements

- Windows 10/11
- current supported CPython; 3.11+ recommended
- package-index access on first install unless compatible secure dependencies are already available

## Manual start after installation

```powershell
.\.venv\Scripts\python.exe -m uvicorn agentinterdict.app:app --host 127.0.0.1 --port 43847
```

Use the actual selected port if the installer chose a fallback.

## Explicit port override

```powershell
$env:AGENTINTERDICT_PORT="45137"
.\run_windows.ps1
```

An explicitly requested occupied port fails loudly; AgentInterdict does not kill the existing process.

## Security files

`.agentinterdict-secret` protects local creation/state/audit seals. `.agentinterdict-operator-key` protects privileged administration. They are generated separately and must not be copied into normal runtime-agent configuration. For high-assurance agent deployments, isolate the AgentInterdict folder/service under a separate OS account/container.

## Paid entitlement

A vendor-issued entitlement may live at:

```text
%USERPROFILE%\.agentinterdict\license.mglic
```

or a path provided through `AGENTINTERDICT_LICENSE_FILE`. Production licences are signed vendor-side; the customer package contains only the verification public key.

Activation example:

```powershell
.\.venv\Scripts\python.exe scripts\activate.py --server https://license.example.invalid --license-key mgk_your_key
```

Use the real vendor URL supplied with a production service.

## Troubleshooting

Run:

```powershell
.\.venv\Scripts\python.exe scripts\doctor.py
```

Then follow `docs/ERROR_RECOVERY.md`. Do not delete `agentinterdict.db` or disable signature/security checks as a troubleshooting shortcut.
