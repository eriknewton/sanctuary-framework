# Codex Banner Self-Gate Verdict

## Lens 1: honesty

Verdict: PASS.

The banner no longer derives federation copy from `origin_machine` alone. The
home payload now carries a factual federation summary from the same
federation-backed roster that powers `/api/posture/fleet`.

Refutation checks:

- No federation roster available: banner says `single-machine view (federation off)`.
- Federation available and enabled: banner says `federation: N machines` and does not say `federation off`.
- Federation available but disabled: banner says `federation provisioned, disabled` with the node count, so it does not hide a real provisioned fleet or call it off.
- The full roster is still fetched separately; the home payload carries only the banner summary.

Evidence:

- `server/test/principal-policy/posture-home-html.test.ts` executes the embedded browser `renderBanner` and pins both federated and no-federation cases.
- Full gate: `npm test` passed with 8377 tests passed and 12 skipped after installing the documented Concordia sidecar venv.

## Lens 2: drift correctness

Verdict: PASS.

`classifyPolicyDrift` now treats missing operator policy marker fields the same
way it already treated missing node policy marker fields: `unknown`, never
`in_sync`.

Refutation checks:

- If `operatorPolicy` is null, drift is `unknown`.
- If any operator marker field used for equality is null, drift is `unknown`.
- Only three populated equality fields on both sides can produce `in_sync`.
- The regression test is not vacuous: it sends null operator fields through the public `buildFleetRoster` seam and asserts the node state plus distribution rollup.

Evidence:

- `server/test/principal-policy/fleet-roster.test.ts` covers null operator marker fields returning `unknown`, with `in_sync: 0`.
- Focused gate: `npm test -- --run test/principal-policy/posture-home-html.test.ts test/principal-policy/fleet-roster.test.ts` passed with 68 tests.

## Final verdict

PASS.
