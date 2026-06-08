# CLAUDE.md — Sanctuary & Concordia Security and Sovereignty Review Context

This file is a briefing for every Claude Code session that touches these codebases. Read it before making any changes.

### Attribution Rule (MANDATORY)

**No public-facing document, README, blog post, plugin manifest, package metadata, or software artifact may reference or attribute CIMC as author or creator of Sanctuary or Concordia.** Erik Newton is the sole author. CIMC may be mentioned in internal/biographical context only.

### Commit discipline — test baseline enforcement (MANDATORY)

Every commit to Sanctuary main MUST run `npm run typecheck && npm test` against a clean working tree before staging; block the commit if either fails, if any transform/collection error appears in vitest output, or if the passing-test count drops below the integer in `.test-baseline` at repo root.

**This rule is now backed by structural enforcement, not just instruction:**

- **Pre-commit hook** at `.githooks/pre-commit` runs both gates locally on every `git commit`. Install once with `cd server && npm run install-hooks` (copies the hook into `.git/hooks/pre-commit`). The hook takes ~21 seconds on a modern Mac. Emergency bypass: `SKIP_TEST_BASELINE=1 git commit ...` (logged to `.test-baseline-overrides.log` for audit).
- **CI check** at `.github/workflows/test-baseline-guard.yml` runs the same two gates on every PR and every push to main. This is the belt-and-suspenders layer for commits that bypass the local hook with `--no-verify` or from uninstalled environments. See `docs/audit/branch-protection-setup.md` for the Git branch-protection runbook required to make this check a hard merge gate.
- **Written instruction (this block)** remains the human-facing contract. The structural layers make violations hard; this rule makes the intent explicit so a reviewer or auditor can cite it.

See `docs/audit/test-baseline-hardening-plan.md` for the full three-layer hardening plan, `docs/audit/commit-4ac95830-postmortem.md` for the trigger incident, and `docs/audit/branch-protection-setup.md` for the GitHub branch-protection runbook.

---

## Architecture & reference (load on demand)

What these tools are, the one-page architecture (entry points, data flow, auth/trust model, dependencies), the testable sovereignty-property assertions, known complexity/risk areas, the review context, and the 2026-03-31 context-gating delta are in [`SANCTUARY_ARCHITECTURE.md`](SANCTUARY_ARCHITECTURE.md). Read it when doing deep Sanctuary work; the MANDATORY rules below stay here because they must fire without a lookup.

## WHAT THESE TOOLS MUST NEVER DO

These are hard constraints. Violation of any of these is a security defect.

1. **Never transmit user data to an external endpoint without explicit, confirmed user intent.** Sanctuary's webhook channel sends HMAC-signed approval *requests* to a user-configured URL — but the payload is operation metadata, not state content. Actual state data (encrypted namespaces, private keys, reputation bundles) must never leave the local storage path except through an explicit export operation that has passed the Tier 1 approval gate.

2. **Never persist agent-generated output that the user cannot inspect, export, or delete.** Every piece of persisted state in Sanctuary is in `~/.sanctuary/state/` and is accessible via `state_read`, `state_list`, `state_export`, or `state_delete`. The audit log is queryable. Concordia's in-memory state is ephemeral by design. If a persistent storage backend is added to Concordia, this constraint must carry forward.

3. **Never execute an irreversible operation without a confirmation gate.** Key rotation, identity deletion, state export, state import, and reputation import are all Tier 1 operations — they require human approval before execution. Secure deletion (3-pass random overwrite) is irreversible and must remain gated.

4. **Never assume trust across the Sanctuary-Concordia boundary.** Sanctuary's bridge accepts any object that matches the `ConcordiaOutcome` shape — it does not trust that the object came from a legitimate Concordia session. Verification is cryptographic: signature checks, commitment recomputation, terms hash matching. Concordia's bridge produces payloads but never directly modifies Sanctuary state. Neither tool should implicitly elevate the other's trust level.

5. **Never silently degrade to a less-secure behavior on error.** If encryption fails, the operation must fail — not fall back to plaintext storage. If the approval channel is unreachable, the operation must be denied — not auto-approved. If signature verification fails, the message must be rejected — not accepted without verification. If Argon2id derivation fails, the server must not start with a weaker KDF.

6. **Never expose private keys in any MCP response, log entry, error message, or diagnostic output.** Ed25519 private keys exist only encrypted at rest and decrypted transiently in memory for signing operations. This applies to both Sanctuary's identity keys and Concordia's agent key pairs.

7. **Never allow the agent to read or modify the Principal Policy at runtime.** The policy file (`~/.sanctuary/principal-policy.yaml`) is loaded once at startup and frozen. The agent must not be able to infer policy rules from denial responses — denials return generic messages without revealing which tier or rule triggered them.

8. **Never allow Concordia attestations to include raw deal terms.** Attestations record behavioral signals (offers_made, concession_magnitude, reasoning_provided) — not the actual prices, quantities, or terms of a negotiation. This is a privacy invariant.

---

## Skill routing

When the user's request matches an available skill, ALWAYS invoke it using the Skill
tool as your FIRST action. Do NOT answer directly, do NOT use other tools first.
The skill has specialized workflows that produce better results than ad-hoc answers.

Key routing rules:
- Product ideas, "is this worth building", brainstorming → invoke office-hours
- Bugs, errors, "why is this broken", 500 errors → invoke investigate
- Ship, deploy, push, create PR → invoke ship
- QA, test the site, find bugs → invoke qa
- Code review, check my diff → invoke review
- Update docs after shipping → invoke document-release
- Weekly retro → invoke retro
- Design system, brand → invoke design-consultation
- Visual audit, design polish → invoke design-review
- Architecture review → invoke plan-eng-review
- Save progress, checkpoint, resume → invoke checkpoint
- Code quality, health check → invoke health
