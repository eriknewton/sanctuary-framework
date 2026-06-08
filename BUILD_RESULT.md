# Build Result

Date: 2026-06-08
Branch: harden/cred-return-tier1
Base verified: a9c1c6d8e9345d3b7b0b0ef610d119e66a8a77eb

## Audit Findings Verified

- P1 `sovereignty_profile_get`: confirmed current main returned the full profile, including upstream transport and tier-policy fields. Fixed by returning an agent-facing profile summary that omits `transport.url`, `transport.env`, `default_tier`, and `tool_overrides`.
- P2 `context_gate_set_policy` / `context_gate_apply_template`: confirmed current main classified them Tier 3 and returned live rules/default actions. Fixed by force-migrating both tools to Tier 1 and returning only policy IDs/metadata/rule counts from mutation handlers.
- P3 `monitor_audit_log`: confirmed current main returned raw audit entries. Fixed by redacting operator handles and tier/policy metadata from agent-facing audit-log reads.
- #413 invariants checked: `principal_policy_view`, `principal_baseline_view`, and `sanctuary_policy_status` remain forced Tier 1 and pruned from Tier 3.

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
  - Tests: 5465 passed, 8 skipped
  - `.test-baseline`: 5423

## Notes

- No push or merge performed.
- First full test run exposed two stale exact expectations in `loader-required-keys.test.ts`; those were updated to include the new forced Tier 1 operations before the passing full run.
