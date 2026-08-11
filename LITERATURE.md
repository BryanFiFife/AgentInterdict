# MemoryGuard literature review — persistent AI-agent memory security

Last curated: 10 August 2026.

This document is a practical research map for MemoryGuard v0.4. It summarises public research, standards activity and security guidance; it does not reproduce papers, certify those papers, or claim MemoryGuard implements every proposed defence. Preprints should be treated as research evidence, not standards.

## 1. Why persistent memory is a distinct security problem

Ordinary prompt injection can disappear when a context window ends. Persistent memory changes the threat model because attacker-influenced content can be written in one session, retrieved later, combined with other memories and then affect an action. The security lifecycle is therefore write → store → retrieve → compose → authorize/act → propagate → contain/rollback.

### Foundational and recent papers

1. **Memory Poisoning Attack and Defense on LLM Agents** — arXiv:2601.05504  
   https://arxiv.org/abs/2601.05504  
   Studies persistent query-driven poisoning and establishes ordinary interaction channels as a route into long-term memory.

2. **A Survey on Long-Term Memory Security in LLM Agents: Attacks, Defenses, and Governance Across the Memory Lifecycle** — arXiv:2604.16548  
   https://arxiv.org/abs/2604.16548  
   Frames security across write, store, retrieve, execute, share/propagate and forget/rollback phases. This is directly relevant to MemoryGuard's lifecycle controls, containment and rollback.

3. **Sleeper Memory Poisoning in LLM Agents** — arXiv:2605.15338  
   https://arxiv.org/abs/2605.15338  
   Demonstrates persistent sleeper payloads that can remain dormant until later activation, supporting retrieval/action-time checks rather than write-time filtering alone.

4. **The Misattribution Gap: When Memory Poisoning Looks Benign** — arXiv:2605.22842  
   https://arxiv.org/abs/2605.22842  
   Examines harmful retrieval from benign-looking artifacts and the attribution problem. Relevant to MemoryGuard's rule that textual appearance never creates authority.

5. **Hijacking Agent Memory: Stealthy Trojan Attacks Through Persistent State / Conversational Interaction** — arXiv:2605.29960  
   https://arxiv.org/abs/2605.29960  
   Studies attacks that account for selective extraction and rewriting rather than assuming arbitrary direct memory writes.

6. **From Untrusted Input to Trusted Memory: A Systematic Study of Memory Poisoning Attacks in LLM Agents** — arXiv:2606.04329  
   https://arxiv.org/abs/2606.04329  
   Identifies memory-write channels and structural weaknesses and introduces MPBench. Useful as a future adversarial-benchmark target.

7. **Triggered Poisoning of Multimodal Memories in Web Agents** — arXiv:2606.10742  
   https://arxiv.org/abs/2606.10742  
   Extends the threat beyond plain text. MemoryGuard v0.4 is still text/metadata-centric and therefore does not claim complete multimodal protection.

8. **When Agents Remember Too Much: Memory Poisoning Attacks on Large Language Model Agents** — arXiv:2607.06595  
   https://arxiv.org/abs/2607.06595  
   Evaluates persistent attacks against tool-using personal agents and motivates both write-time and retrieval-time screening.

9. **Bad Memory: Evaluating Prompt Injection Risks from Memory in Agentic Systems** — arXiv:2607.14611  
   https://arxiv.org/abs/2607.14611  
   Evaluates memory-file/behavioral-state risks across agentic coding systems and supports treating agent-authored memory as security-sensitive state.

10. **MemPoison: Uncovering Persistent Memory Threats and Structural Blind Spots in LLM Agents** — arXiv:2607.14651  
    https://arxiv.org/abs/2607.14651  
    Introduces L1 direct, L2 compositional multi-record and L3 context-triggered dormant corruption. Its central result for MemoryGuard is that write-time defenses can suppress direct attacks yet miss records that become harmful only when jointly retrieved or triggered. v0.4 therefore adds a retrieval/action-time firewall that rescans the combined context selected for an action.

11. **MemSecBench: Tracking Agent Memory Poisoning from Injection to Impact** — arXiv:2607.27080  
    https://arxiv.org/abs/2607.27080  
    Adds lifecycle-oriented benchmarking across memory poisoning and related failure modes. It is a useful candidate for a future reproducible public evaluation suite.

## 2. Provenance, lineage and non-amplifying authority

12. **MemLineage: Lineage-Guided Enforcement for LLM Agent Memory** — arXiv:2605.14421  
    https://arxiv.org/abs/2605.14421  
    Treats memory security as chain-of-custody, attaching provenance/derivation lineage and gating sensitive actions that descend from external ancestry. MemoryGuard implements compact parent/root provenance and tamper-evident seals, but not MemLineage's full proposed construction.

13. **Securing LLM-Agent Long-Term Memory Against Poisoning: Non-Malleable, Origin-Bound Authority with Machine-Checked Guarantees** — arXiv:2606.24322  
    https://arxiv.org/abs/2606.24322  
    Shows why content scoring and ordinary derivation history can be malleable under summarization, trusted-tool echoes and manufactured corroboration. It motivates MemoryGuard's core invariant: derivation may preserve or reduce authority, never amplify it, and machine-derived memories cannot become direct human authorization.

14. **Evidence Tracing and Execution Provenance in LLM Agents** — arXiv:2606.04990  
    https://arxiv.org/abs/2606.04990  
    Relevant to tracing evidence and linking retrieved information to downstream execution decisions.

15. **Memory Provenance Laundering in LLM Agents: A Non-Amplification Firewall for Persistent Memory** — arXiv:2607.29167  
    https://arxiv.org/abs/2607.29167  
    Describes provenance laundering during memory consolidation and proposes platform-maintained provenance plus an action-risk/authority gate. This directly supports v0.4's separation between contextual memories and direct action authorization, and its requirement that high/critical actions have a sealed direct authority record rather than a summary or derived echo.

## 3. Action authorization and replay-resistant state

16. **Beyond Single-Use Tokens: Durable Authorization State for Replay-Resistant LLM Agent Actions** — arXiv:2608.01710  
    https://arxiv.org/abs/2608.01710  
    Identifies “semantic replay”: retries, replanning, delegation and crash recovery can exceed the intended execution budget even when token identifiers are single-use. It argues for canonical action binding and durable, monotonic authorization state. MemoryGuard v0.4 implements deterministic **action-scope binding** for high/critical approvals, but it does not yet implement a full Issue/Prepare/Commit consumption ledger; that remains an explicit production gap.

17. **NIST/NCCoE — Accelerating the Adoption of Software and AI Agent Identity and Authorization (Concept Paper)**  
    https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization  
    Focuses on identification, authentication, authorization, access delegation/non-repudiation, logging and transparency for software/AI agents. This supports separating runtime-agent capability from operator authority and keeping consequential authorization explicit.

18. **NIST — AI Agent Standards Initiative**  
    https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative  
    NIST's 2026 initiative explicitly includes agent security and identity/authorization as areas for standards and research. MemoryGuard treats these as external ecosystem signals, not certification.

## 4. Certified / robustness-oriented defenses

19. **SMSR: Certified Defence Against Runtime Memory Poisoning in Persistent LLM Agent Systems** — arXiv:2606.12703  
    https://arxiv.org/abs/2606.12703  
    Combines write-time HMAC provenance with randomized memory ablation and verdict voting. MemoryGuard v0.4 uses HMAC-backed local integrity controls but does not implement SMSR's certified retrieval procedure or claim certified robustness.

## 5. Broader agent-security guidance and adjacent projects

20. **The Attack and Defense Landscape of Agentic AI** — arXiv:2603.11088  
    https://arxiv.org/abs/2603.11088  
    Broad landscape connecting indirect prompt injection, external data, memory and tool use.

21. **OWASP AI Agent Security Cheat Sheet**  
    https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html  
    Covers memory poisoning, excessive autonomy, least privilege, isolation, validation and monitoring. These are complementary to MemoryGuard's memory-specific boundary.

22. **OWASP LLM Prompt Injection Prevention Cheat Sheet**  
    https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html  
    Useful for upstream injection defenses. MemoryGuard assumes upstream filters can fail and therefore applies persistent-state controls too.

23. **OWASP RAG Security Cheat Sheet**  
    https://cheatsheetseries.owasp.org/cheatsheets/RAG_Security_Cheat_Sheet.html  
    Relevant where persistent memory is backed by retrieval/vector stores or document corpora.

24. **OWASP Agent Memory Guard**  
    https://owasp.org/www-project-agent-memory-guard/  
    An independent OWASP project focused on protecting agent memory from poisoning. It overlaps conceptually with this product in areas such as integrity, leakage detection, policy and rollback. **MemoryGuard v0.4 in this package is not affiliated with, endorsed by, or derived from the OWASP project.** The name overlap is a commercial naming/trademark-clearance issue that should be resolved before public launch.

25. **NCSC — Thinking carefully before adopting agentic AI**  
    https://www.ncsc.gov.uk/blogs/thinking-carefully-before-adopting-agentic-ai  
    Recommends constrained scope, least privilege, secure defaults and temporary credentials. MemoryGuard's runtime/operator split is designed to complement those controls.

26. **NCSC — Guidelines for secure AI system development / secure design**  
    https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development/guidelines/secure-design  
    Reinforces secure defaults, API controls and least privilege.

## 6. Cryptography, secret handling and commercial licensing

27. **OWASP Key Management Cheat Sheet**  
    https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html  
    Relevant to production signing keys, lifecycle, rotation, compromise recovery and secure storage.

28. **OWASP Cryptographic Storage Cheat Sheet**  
    https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html  
    Supports separating keys from protected data and avoiding hard-coded secrets.

29. **OWASP Secrets Management Cheat Sheet**  
    https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html  
    Relevant to vendor API keys, webhook secrets and HMAC/KMS operations. v0.4 additionally rejects recognized secret material before memory persistence.

30. **Stripe Billing — Entitlements / subscription webhooks**  
    https://docs.stripe.com/billing/entitlements  
    https://docs.stripe.com/billing/subscriptions/webhooks  
    Relevant to mapping paid products to server-side feature entitlements. Customer builds should verify signed short-lived entitlements; the vendor private key must remain vendor-side.

## 7. Current v0.4 research-to-control mapping

| Research problem | v0.4 control | Residual risk |
|---|---|---|
| Direct poisoning (L1) | normalized write-time scan; origin-bound authority; quarantine | novel/semantic attacks can evade static signatures |
| Compositional poisoning (L2) | combined-memory action-time rescoring | requires host to call the pre-action gate consistently |
| Dormant/context-triggered poisoning (L3) | action-time context check + authority gate | cannot prove all latent triggers are detectable |
| Provenance laundering | signed origin roots; derived authority cap | external/host-native stores outside the gate remain separate |
| Blank-cheque authorization | immutable action scopes on explicit human approvals | no full transaction/consumption ledger yet |
| Secret persistence | recognized credential/private-key rejection before write, including decoded forms | entropy-only/novel credentials may evade signatures |
| Poison propagation | descendant graph + atomic chain containment | external copies outside MemoryGuard require separate cleanup |
| Incident response | signed normal/read-only/lockdown modes | same-user root/admin compromise can still bypass process boundaries |
| Direct database tampering | immutable creation signatures + mutable state seals + signed/hash-chained audit | local HMAC key compromise defeats local authenticity |
| Retry duplication | idempotency-key/fingerprint conflict checks | consequential external effects need sink-level idempotency |

## 8. Security conclusions

The literature supports several durable architectural conclusions:

- **Write-time provenance matters, but is insufficient by itself.**
- **Textual safety is not authority.** A benign paraphrase of attacker-controlled data remains attacker-originated.
- **Derivation must not amplify authority.** Summaries/tool echoes are transformations, not fresh user permission.
- **Retrieval must be evaluated in context.** Multiple benign-looking memories can form a malicious composite.
- **Consequential actions need an explicit authorization plane.** Memory may provide facts; it must not mint privileges.
- **Authorization needs scope and eventually durable consumption state.** Signed approval without action binding is a blank cheque; action binding without durable consumption does not fully solve semantic replay.
- **Secrets should be prevented from becoming memory where possible.** Detection is still heuristic and should be complemented by dedicated secret stores.
- **Containment/rollback are first-class security features.** Prevention is not perfect, so blast-radius analysis and recovery must be engineered.
- **No single classifier is a sufficient trust boundary.** MemoryGuard's transparent scorer is triage; cryptographic provenance and deterministic policy remain separate controls.

## 9. Research-to-product gaps still open

Before making high-assurance or “enterprise security” claims, the project should still:

- run reproducible benchmark suites against MPBench, MemPoison, MemSecBench and GhostWriter-style cases;
- implement durable authorization consumption / prepare-commit state for replay-resistant consequential actions;
- add principal/user-scoped multi-tenant retrieval and RBAC backed by a production identity provider;
- add verified deletion across every configured storage substrate;
- anchor audit evidence to a remote append-only/WORM destination;
- use managed KMS/HSM-backed production keys rather than local HMAC files;
- add model-assisted/remote threat classifiers only as supplementary detectors, never as authority sources;
- test multimodal memory substrates separately;
- undergo independent cryptographic review, penetration testing and adversarial red-team evaluation;
- perform legal/name clearance before commercial launch because an independent OWASP project currently uses “Agent Memory Guard.”
