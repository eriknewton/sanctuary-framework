# AGENTS.md: Sanctuary & Concordia Security and Sovereignty Review Context

This file is a briefing for any AI coding agent working in these codebases. Read it before making any changes. It is the canonical, model-neutral source of truth for how to work in this repo; tool-specific files (for example `CLAUDE.md`) import this file rather than duplicating it.

### Attribution Rule (MANDATORY)

**No public-facing document, README, blog post, plugin manifest, package metadata, or software artifact may reference or attribute CIMC as author or creator of Sanctuary or Concordia.** Erik Newton is the sole author. CIMC may be mentioned in internal/biographical context only.

### Commit discipline: test baseline enforcement (MANDATORY)

Every commit to Sanctuary main MUST run `npm run typecheck && npm test` against a clean working tree before staging; block the commit if either fails, if any transform/collection error appears in vitest output, or if the passing-test count drops below the integer in `.test-baseline` at repo root.

**This rule is now backed by structural enforcement, not just instruction:**

- **Pre-commit hook** at `.githooks/pre-commit` runs both gates locally on every `git commit`. Install once with `cd server && npm run install-hooks` (copies the hook into `.git/hooks/pre-commit`). The hook takes ~21 seconds on a modern Mac. Emergency bypass: `SKIP_TEST_BASELINE=1 git commit ...` (logged to `.test-baseline-overrides.log` for audit).
- **CI check** at `.github/workflows/test-baseline-guard.yml` runs the same two gates on every PR and every push to main. This is the second enforcement layer for commits that bypass the local hook with `--no-verify` or from uninstalled environments. See `docs/audit/branch-protection-setup.md` for the Git branch-protection runbook required to make this check a hard merge gate.
- **Written instruction (this block)** remains the human-facing contract. The structural layers make violations hard; this rule makes the intent explicit so a reviewer or auditor can cite it.

See `docs/audit/test-baseline-hardening-plan.md` for the full three-layer hardening plan, `docs/audit/commit-4ac95830-postmortem.md` for the trigger incident, and `docs/audit/branch-protection-setup.md` for the GitHub branch-protection runbook.

### Test isolation: the operator's machine is not a fixture (MANDATORY)

Tests must never read from or write to the operator's real login keychain, real `~/.sanctuary` state, or any other operator-owned credential store. Under test, credential access goes through the keychain chokepoint with an injected in-memory store, so no `security` subprocess is spawned at all. Tests that genuinely exercise keychain integration (including any that spawn the real CLI as a subprocess) use a per-run temporary keychain created in a temp path, scoped to the run's search list, and deleted on teardown; teardown must also reap every server and worker the test spawned, and both must happen even when the test fails or times out. A timed-out test that leaves a live process or a keychain entry behind poisons every later run on the same machine, and the damage looks like unrelated flakes. A structural guard in the suite enforces the no-login-keychain rule; this text records the intent so a reviewer can cite it.

---

## Architecture & reference (load on demand)

What these tools are, the one-page architecture (entry points, data flow, auth/trust model, dependencies), the testable sovereignty-property assertions, known complexity/risk areas, the review context, and the 2026-03-31 context-gating delta are in [`SANCTUARY_ARCHITECTURE.md`](SANCTUARY_ARCHITECTURE.md). Read it when doing deep Sanctuary work; the MANDATORY rules below stay here because they must fire without a lookup.

## Codebase conventions (read before touching `server/src`)

The TypeScript MCP server is large (56 modules) and several names collide. Before changing server code, orient with the map and hold these conventions:

- **Module map first.** [`server/src/README.md`](server/src/README.md) is a 56-module index with a "distinct from" and "do-not-touch" column per module, plus the confusable-cluster disambiguations (the four "audit" things, the `mesh`/`federation` split-brain, `key-17`, and more). Read it before navigating `server/src`. If you add, remove, or rename a module, update its row in the SAME PR; the map's whole value is that it never drifts from the tree.
- **Barrel convention.** Every module exposes a thin re-export `index.ts` so consumers import the module surface, not its internal layout (48/56 today; the 8 exceptions, the four `l1`-`l4` layer dirs, `cli`, `v1`, `compliance`, `contracts`, are listed in the map). A new module adds a barrel or documents why it is an exception.
- **Frozen surfaces never move.** A reorganization may move directory names and relative import paths; the surfaces in [`server/reorg-surface-manifest.md`](server/reorg-surface-manifest.md) must survive byte-for-byte: MCP tool names and schemas, route paths, HKDF/crypto labels, persisted at-rest keys, the `L1Status..L4Status` exports, and user-visible display strings. Rule of thumb: paths and imports move; anything on the wire, on disk, or on screen does not. The `l1`-`l4` tokens are LIVE wire and at-rest contracts even though the L-number numbering is being retired in prose; never edit the token itself.
- **Forward documentation rule.** New public surface gets a consumer-written doc-comment. MCP tool `description` fields are product copy for an AI-agent audience (an agent reads them to decide whether and how to call a tool); keep them accurate and never overclaim. See the forward rule in [CONTRIBUTING.md](CONTRIBUTING.md).
- **Structural-health snapshot.** `npm run refresh-reorg-evidence` (live module / importer / god-file counts) and `npm run check-import-cycles` (dependency-cycle baseline) report the codebase's structural health; run them before any reorg PR.

### Prose hygiene (adopted 2026-08-04)

These apply to every edit, new code and retrofits alike. They govern the words around the code; none of them changes behavior.

- **Invariant comments live at the enforcement site.** Where a line enforces a security or trust invariant, it carries a one-sentence rationale stating why the code must be this way, at that line. Example shape: "verification recomputes the commitment from the terms; a hash claimed in the payload is never trusted." Central docs explain the architecture; the enforcement site explains itself. A comment that narrates what the next line does is still noise; this rule is about *why*, at the exact place the *why* binds.
- **Cross-file contracts are pinned on both sides.** Wherever two files must agree (mirrored constants, wire field names, HKDF/crypto labels, paired client/server validation), each side carries a "must match `<name>` in `<file>`" comment. [`server/reorg-surface-manifest.md`](server/reorg-surface-manifest.md) remains the authoritative inventory; the pin comments are in-place tripwires so an editor touching one side is warned before CI has to catch it.
- **Runbooks state the failure mode.** In operational docs (deploy guides, drill docs, `docs/audit/` runbooks), every step that can be done subtly wrong gets a one-line note on what the mistake looks like from the outside, e.g. "a misowned database reads fine and fails only on the first write." Procedure tells you what to type; the failure-mode note is what you need at 2am.
- **No bare magic numbers.** A numeric literal is either computed from named constants or annotated with its derivation (e.g. "87 = base64url length of a 65-byte raw P-256 point, no padding"). If you cannot write the derivation, that is a finding, not a comment to skip.
- **Protocol state machines name their states.** Multi-step handshake, approval, and federation flows use explicit state-named handlers (`state_CHALLENGE`, `state_AUTHENTICATED`) or equivalent state-labeled structure, so the flow reads as a diagram without a debugger.

[`SANCTUARY_ARCHITECTURE.md`](SANCTUARY_ARCHITECTURE.md) is the *why* (architecture, data flow, trust model); the module map is the *where*.

### Branch hygiene

Keep the branch list legible; it accumulates dead weight fast otherwise.
- **Merged-PR head branches auto-delete on merge** (repo setting `delete_branch_on_merge=true`). Do not re-disable it.
- A weekly **`stale-branch-report`** workflow (`.github/workflows/stale-branch-report.yml`) surfaces branches with no open PR and no commits in 60 days. Prune the dead ones promptly.
- **Never delete an unmerged branch that has no PR without first checking it for wanted work**; that is the one case where deletion can lose something.

## WHAT THESE TOOLS MUST NEVER DO

These are hard constraints. Violation of any of these is a security defect.

1. **Never transmit user data to an external endpoint without explicit, confirmed user intent.** Sanctuary's webhook channel sends HMAC-signed approval *requests* to a user-configured URL, but the payload is operation metadata, not state content. Actual state data (encrypted namespaces, private keys, reputation bundles) must never leave the local storage path except through an explicit export operation that has passed the Tier 1 approval gate.

2. **Never persist agent-generated output that the user cannot inspect, export, or delete.** Every piece of persisted state in Sanctuary is in `~/.sanctuary/state/` and is accessible via `state_read`, `state_list`, `state_export`, or `state_delete`. Exception: Sovereign Data Warehouse vault output is not exportable until **IC-15** closes, so new SDW claims must preserve that bound. The audit log is queryable. Concordia's in-memory state is ephemeral by design. If a persistent storage backend is added to Concordia, this constraint must carry forward.

3. **Never execute an irreversible operation without a confirmation gate.** Key rotation, identity deletion, state export, state import, and reputation import are all Tier 1 operations; they require human approval before execution. Secure deletion (3-pass random overwrite) is irreversible and must remain gated.

4. **Never assume trust across the Sanctuary-Concordia boundary.** Sanctuary's bridge accepts any object that matches the `ConcordiaOutcome` shape; it does not trust that the object came from a legitimate Concordia session. Verification is cryptographic: signature checks, commitment recomputation, terms hash matching. Concordia's bridge produces payloads but never directly modifies Sanctuary state. Neither tool should implicitly elevate the other's trust level.

5. **Never silently degrade to a less-secure behavior on error.** If encryption fails, the operation must fail, not fall back to plaintext storage. If the approval channel is unreachable, the operation must be denied, not auto-approved. If signature verification fails, the message must be rejected, not accepted without verification. If Argon2id derivation fails, the server must not start with a weaker KDF.

6. **Never expose private keys in any MCP response, log entry, error message, or diagnostic output.** Ed25519 private keys exist only encrypted at rest and decrypted transiently in memory for signing operations. This applies to both Sanctuary's identity keys and Concordia's agent key pairs.

7. **Never allow the agent to read or modify the Principal Policy at runtime.** The policy file (`~/.sanctuary/principal-policy.yaml`) is loaded once at startup and frozen. The agent must not be able to infer policy rules from denial responses; denials return generic messages without revealing which tier or rule triggered them.

8. **Never allow Concordia attestations to include raw deal terms.** Attestations record behavioral signals (offers_made, concession_magnitude, reasoning_provided), not the actual prices, quantities, or terms of a negotiation. This is a privacy invariant.

9. **Never publish vulnerability detail to a public surface.** Public surfaces include `docs/` (the GitHub Pages source for the marketing site), `README.md` and every `*/README.md`, `ROADMAP.md`, `CHANGELOG.md`, release notes, package descriptions, plugin and marketplace manifests, MCP tool descriptions, and anything else that ships in the repo or on a registry. **Never publish:** a `file:line` anchor into vulnerable code, a reproduction or invocation that triggers the defect, a statement that a specific defect is live in the current release, or a severity-ranked defect table an attacker could prioritize from.

   A **capability bound** is different and is required: stating that a capability is absent, partial, or unproven ("Linux egress enforcement is not implemented") is an honesty obligation and must never be softened. A **vulnerability description** tells a reader how to exploit what is there. When an honest bound and non-disclosure appear to conflict, **non-disclosure wins and the bound becomes vaguer**, never the reverse: cite a bare defect id that resolves only in the private register.

   This rule exists because it was violated. A defect register naming all open findings with `file:line` anchors, an exact unauthenticated-bind invocation, and a "live on main today" note was published to `docs/` and served publicly before it was retracted. It had been flagged twice as needing the owner's decision, and the change merged before the answer arrived. **Raising a question does not authorize the action.**
