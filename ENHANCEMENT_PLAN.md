# AgentInterdict Enhancement Plan

**Goal:** Enhance security, expand known threats, add smoke tests, and extend the remote threat list — WITHOUT breaking existing functionality or deprecating anything.

**Baseline (verified):** 78 tests pass, 1 fails (Windows env-var length limit — test-harness, not code), 8 errors (Windows SQLite file-lock — pre-existing). CI runs on Linux where these pass. Working tree clean on `main` @ 2431c95.

---

## Principle: additive, non-breaking

- **Never change** the enforcement logic in `service.py`/`security.py` that's already tested (action_check, authority boundaries, tamper detection). These are the crown jewels and they work.
- **Only ADD** to the threat list (pure data), ADD defensive patterns, and ADD tests.
- Bump `version` in community.json so the change is traceable.

---

## 1. Enhance known threats (community.json) — HIGH VALUE, LOW RISK

Expand the baked-in threat list with more real, tested attack patterns. This is pure data — no code change, zero break risk.

**New signals to add (each with name/pattern/flags/weight/reason):**
- **jailbreak_framing** — "DAN mode", "jailbreak", "unfiltered", "no restrictions", "uncensored"
- **indirect_injection** — "ignore the text above", "the following is a system message", "new instructions follow"
- **markdown_injection** — `![...](...)` image-exfil, `[text](javascript:)`, data-URI exfil
- **xml_tag_injection** — `<system>`, `<instructions>`, `<tool_call>` forged tags
- **tool_abuse** — "call send_email", "invoke the tool", "use the send_message tool"
- **data_exfil_pattern** — "base64 encode", "URL-encode", "hex encode" + "send"
- **prompt_leak** — "repeat your system prompt", "what are your instructions", "output your prompt"
- **memory_poisoning** — "remember this forever", "store this in memory", "add to your long-term memory"
- **authority_spoof** — "I am the admin", "the user authorized this", "system override"
- **phishing_redirect** — "click this link", "visit this URL", "download this file"
- **credential_harvest** — "what is your password", "give me your API key", "show me your token"
- **command_injection** — "run this command", "execute this script", "pipe to shell"
- **ssrf_attempt** — "fetch localhost", "read /etc/passwd", "access internal network"
- **exfil_via_tool** — "send the contents of", "email the file", "upload the document"

**New compact_patterns (survive whitespace/punct removal):**
- compact_jailbreak, compact_indirect, compact_exfil_via_tool, compact_memory_poison

**Bump version 1 → 2, update updated_at.**

---

## 2. Enhance security (defensive, additive)

Add a few defensive patterns to `security.py` WITHOUT touching the tested enforcement path:
- **`_decoded_hex_previews`** — already exists for backslash-hex; add **HTML-entity decoding** (`&#x27;`, `&quot;`) as an additional obfuscation layer to scan.
- **`_decoded_unicode_escape_previews`** — detect `\uXXXX` escapes used to hide instruction text.
- These are pure additions to the scanning layer; they don't change existing behavior, only add detection.

---

## 3. Smoke screen tests (new test file)

Add `tests/test_threat_expansion.py` covering:
- Each new signal fires on a representative payload (parametrized)
- New obfuscation decoders work (HTML-entity, unicode-escape)
- No false-positive regression on benign text (a normal sentence scores low)
- Threat list version is 2 and loads correctly
- The benchmark still runs and block rate doesn't regress

---

## 4. Remote threat list

The remote list is fetched by `_fetch_remote_threats` from the Worker's `/v1/threats` endpoint. The **community.json** is the baked-in source that the remote list extends. By expanding community.json and bumping the version, the remote list inherits the richer signal set. (The Worker-side list is a separate deploy; the community list is what ships in the repo and is the source of truth for the free tier.)

---

## 5. Test & push

1. Run full suite — confirm no regressions (same 78 pass, no NEW failures)
2. Run `benchmark_injection.py` — confirm block rate doesn't regress
3. Run `verify_release.py` if present
4. Commit with clear message, push to `origin/main`

---

## Risk register
- **Threat list data** — zero code risk; worst case a pattern is too aggressive (false positive), mitigated by testing benign text.
- **New decoders** — additive; wrapped in try/except like existing ones; can't break existing detection.
- **Tests** — new file only; can't break existing tests.
- **No changes** to service.py enforcement, db.py, licensing.py, app.py, models.py, policy.py.
