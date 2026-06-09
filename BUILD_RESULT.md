# Build Result

Date: 2026-06-08
Branch: harden/cred-return-tier1
Base verified: a9c1c6d8e9345d3b7b0b0ef610d119e66a8a77eb

## Audit Findings Verified

- P1 `sovereignty_profile_get`: confirmed current main returned the full profile, including upstream transport and tier-policy fields. Fixed by returning an agent-facing profile summary that omits `transport.url`, `transport.env`, `default_tier`, and `tool_overrides`.
- P2 `context_gate_set_policy` / `context_gate_apply_template`: confirmed current main classified them Tier 3 and returned live rules/default actions. Fixed by force-migrating both tools to Tier 1 and returning only policy IDs/metadata/rule counts from mutation handlers.
- P3 `monitor_audit_log`: confirmed current main returned raw audit entries. Fixed by redacting operator handles and tier/policy metadata from agent-facing audit-log reads.
- #413 invariants checked: `principal_policy_view`, `principal_baseline_view`, and `sanctuary_policy_status` remain forced Tier 1 and pruned from Tier 3.

## Remaining Review Findings Closed

- P1 `context_gate_set_policy` / `context_gate_apply_template`: removed both mutation tools from the agent-visible MCP catalog and from `WRITE_MCP_TOOLS`. They remain registered as operator-terminal-only write tools so legitimate terminal/internal use still works.
- P1 `monitor_audit_log`: redacts top-level `identity_id` and nested `identity_id`/operator-handle fields from agent-facing audit-log responses.
- P2 `context_gate_list_policies`: redacts live policy posture from the agent-facing response. Agents can see policy IDs, names, rule counts, and timestamps, but not rules, providers, default actions, or identity bindings.
- #413 invariants rechecked: `principal_policy_view`, `principal_baseline_view`, and `sanctuary_policy_status` remain Tier 1 and out of Tier 3.

## Verification

- `cd server && npm run typecheck`: passed
- Focused regression tests:
  - `test/sovereignty-profile-tools.test.ts`
  - `test/l2/context-gate-tools.test.ts`
  - `test/principal-policy/policy-loader.test.ts`
  - `test/principal-policy/loader-required-keys.test.ts`
  - `test/security/cred-return-hardening.test.ts`
  - `test/system-prompt-generator-v2.test.ts`
- `cd server && npm test`: passed
  - Test files: 445 passed, 1 skipped
  - Tests: 5467 passed, 8 skipped
  - `.test-baseline`: 5423
- `cd server && npm run typecheck && npm test`: passed
  - Test files: 445 passed, 1 skipped
  - Tests: 5467 passed, 8 skipped
  - `.test-baseline`: 5423

## Notes

- No push or merge performed.
- The first sandboxed full run completed typecheck/build but Vitest could not write `server/node_modules/.vite-temp`; the same command passed when rerun with approved escalation.
