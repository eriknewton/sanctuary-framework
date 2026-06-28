# Codex Banner Summary

## Scope

Fixed two adversarial sweep findings on branch `fix/honest-federation-banner`.

## Findings fixed

- HIGH: the posture dashboard banner always said `single-machine view (federation off)` even when the Fleet panel below showed admitted federation machines and policy distribution.
- LOW: `classifyPolicyDrift` could return `in_sync` if a future caller supplied an operator policy marker whose equality fields were null.

## Changes

- Added `home.federation` to the Posture Home payload with `available`, `enabled`, and `fleet_node_count`, derived from the same `buildFleetRoster` path used by `/api/posture/fleet`.
- Updated the banner copy:
  - no available roster: `single-machine view (federation off)`;
  - enabled roster: `federation: N machines`;
  - provisioned but disabled roster: `federation provisioned, disabled` with the node count.
- Added an operator-policy null-field guard in `classifyPolicyDrift`, returning `unknown` before any equality comparison.
- Added 3 tests and bumped `.test-baseline` from `8360` to `8363`.
- Added root-allowlist entries for the requested root-level `CODEX_BANNER_*` review files.

## Validation

- `npm ci` passed.
- `npm run lint` passed.
- `npm run typecheck` passed.
- Focused tests passed: `npm test -- --run test/principal-policy/posture-home-html.test.ts test/principal-policy/fleet-roster.test.ts` with 68 tests.
- Composition sidecar repair: created `sidecars/concordia/.venv` with Python 3.12 and installed `sidecars/concordia/requirements.txt` using `--require-hashes`, per the sidecar README. The venv is gitignored.
- Full `npm test` passed after sidecar setup: 660 files passed, 8377 tests passed, 12 skipped.

## Follow-ups

- None required for this PR.
