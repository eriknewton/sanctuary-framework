# Codex Hardening Verdict

Scope: competitor-readiness hardening wave, 2026-06-27.

## Lens 1: Security

Verdict: PASS.

Refute-by-default checks:

- Policy replay and rollback: a mesh policy bundle is rejected when its version is not strictly newer than the locally held bundle. Rejected bundles are not installed, not broadcast, and emit `mesh_policy_bundle_rejected` audit metadata through the mesh node rejection path.
- Policy validity downgrade: policy bundles now require `valid_from` and `valid_until`; missing, inverted, not-yet-valid, or expired windows fail closed before local install or publish.
- Policy activation downgrade: English-policy activation refuses operation-tier downgrades, Tier 2 action downgrades, Tier 2 threshold weakening, and approval redirect disablement before persistence. The refusal path emits `ACTIVATION_REFUSED` with downgrade fields and reasons.
- Config downgrade bypass: the initial self-gate found that `saveConfig` protections alone could be bypassed by manually editing `sanctuary.json` before `loadConfig`. This was fixed by a local `sanctuary.json.security-baseline.json` posture floor. It stores only nonsecret posture fields and booleans, then rejects weaker load-time or save-time configs with `ConfigDowngradeError`.
- Secret exposure: config posture baselines store dashboard and webhook secret presence as booleans only. Tests prove dashboard and webhook secret values are not copied into the baseline.
- Signed self-update: the codebase has a notice-only npm version checker, not a self-applying updater. Building a blind updater would expand the attack surface. This branch therefore lands the signed self-update design only.

Residual condition:

- Existing installs that have no security baseline yet seed the baseline from the first valid config observed by this build. After that observation, weaker config loads are refused.

## Lens 2: Correctness

Verdict: PASS.

Checks:

- Tests are not vacuous: they bypass the normal save path where needed, publish rejected policy bundles through the real mesh node path, and assert persisted state remains unchanged on refusal.
- The same downgrade comparator backs config save-time and load-time enforcement.
- Existing stale `sanctuary.json` version stamping is preserved; lower stored config versions are still normalized on load, while programmatic persisted version rollback is rejected on save.
- Signed self-update remains design-only and does not add dead verifier code or a fake update path.

## Gates

- `npm run lint`: PASS.
- `npm run typecheck`: PASS.
- `npm test`: PASS, 660 files passed, 1 skipped, 8378 tests passed, 12 skipped.
- `.test-baseline`: 8364. Main floor was 8355; this branch adds 9 tests.
