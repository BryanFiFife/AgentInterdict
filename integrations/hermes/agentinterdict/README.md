# AgentInterdict provider for Hermes Agent

This integration follows Hermes' current `MemoryProvider` plugin contract. It provides guarded prefetch, explicit secure-store/recall tools, optional turn capture, and an audit mirror of built-in memory writes.

## Important v0.6 integration limitation

Hermes documents external memory providers as **additive**: its built-in `MEMORY.md` / `USER.md` memory remains active. The `on_memory_write` hook fires to mirror a built-in memory write; it is not a documented pre-write veto hook. Therefore this plugin can secure AgentInterdict-backed memory and audit Hermes' native writes, but it cannot truthfully claim to prevent every poisoned write to Hermes' built-in files without a small Hermes core write-gate patch.

For strongest enforcement, the installed Hermes write path must be wrapped/gated so every native persistent write is checked before commitment. The v0.6 provider also exposes an action-check tool for consequential operations.

## Configure

1. Run AgentInterdict on `http://127.0.0.1:43847`.
2. Install/copy this plugin into the active Hermes external plugin location according to your Hermes version.
3. Put `AGENTINTERDICT_URL=http://127.0.0.1:43847` in the Hermes profile `.env`.
4. Set the provider to `agentinterdict` through Hermes' memory/plugin configuration.
5. Restart Hermes and check `hermes memory status`.

Optional: `AGENTINTERDICT_NAMESPACE=personal-hermes`, `AGENTINTERDICT_AUTO_CAPTURE=true`.
