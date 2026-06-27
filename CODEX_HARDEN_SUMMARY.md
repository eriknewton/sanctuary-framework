# Codex Hardening Summary

## Completed

- Completed mesh policy anti-rollback enforcement: only strictly newer policy bundle versions install, and rejected bundles are audited and not broadcast.
- Added policy validity-window enforcement: `valid_from` and `valid_until` are mandatory and fail closed when missing, inverted, not yet valid, or expired.
- Completed principal policy downgrade rejection for English-policy activation: weaker operation tiers, Tier 2 actions, thresholds, and approval redirect posture are refused before persistence and audited.
- Added general config downgrade rejection for security-relevant fields: key protection, execution attestation, dashboard TLS/auth, webhook gate, privacy filter mode, and privacy fail mode.
- Closed the direct-file-edit config bypass with a nonsecret `sanctuary.json.security-baseline.json` posture floor checked by `loadConfig` and maintained by `saveConfig`.
- Bumped `.test-baseline` to 8364, which is the Linux floor from main 8355 plus 9 new tests.

## Design-Only

- Signed self-update remains design-only in `docs/audit/signed-self-update-design-2026-06-27.md`.
- Actual update surface found: `server/src/update-check.ts` is notice-only for npm package versions. It does not download or apply updates, and no server-side self-update path exists today.
- Proposed future fix: a pinned Ed25519 release signing key, a signed canonical JSON release manifest, artifact SHA-256 checks, expiry/channel/package binding, and version monotonicity before any future updater can apply an artifact.

## Tests Added

- Mesh local policy store rejects lower-version replay and expired/missing validity windows.
- Mesh node publish refuses locally rejected policy bundles.
- Config save rejects lower persisted versions and security-field downgrades.
- Config load rejects manual security-field downgrades by consulting the posture baseline.
- English-policy activation rejects Tier 2 action downgrades after conflicts are acknowledged.
- Policy envelope packing emits validity windows.

## Gates

- `npm run lint`: PASS.
- `npm run typecheck`: PASS.
- `npm test`: PASS, 660 files passed, 1 skipped, 8378 tests passed, 12 skipped.

## Self-Gate

- Lens 1 security: PASS after fixing the load-time config bypass found during the adversarial pass.
- Lens 2 correctness: PASS. The tests exercise real persistence and rejection paths, and signed self-update was not stubbed.

## Follow-Ups For Erik Review

- Decide whether to implement the signed self-update verifier as a new feature, using the design doc in this branch.
- Decide whether a future operator-approved, audited config downgrade override is desirable. This branch defaults to fail-closed rejection.
