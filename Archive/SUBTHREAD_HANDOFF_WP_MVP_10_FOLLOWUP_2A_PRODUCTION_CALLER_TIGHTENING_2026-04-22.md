---
title: "WP-MVP-10 Follow-up #2a — Composition Production-Caller Surface Tightening (Subthread Handoff)"
status: subthread_handoff
review_status: pending_coordinator_review
created: 2026-04-22
base_sha: "2a02ad372f7c3e32c97463c58f21ead6eb305fae"
base_short: "2a02ad3"
branch: wp-mvp-10-followup-2a-production-caller-tightening
worktree: ~/Code/Claude/sanctuary-worktrees/wp-mvp-10-followup-2a-production-caller-tightening
work_package: WP-MVP-10 Follow-up #2a
parent_prs:
  - PR #47 WP-MVP-10 Concordia + Verascore Optional Composition v1.0 @ c2f90fd
  - PR #48 WP-MVP-11 Follow-up #1 @ 05efae3
  - PR #49 WP-MVP-10 Follow-up #1 @ 2a02ad3
spawn_prompt: Review/Sanctuary/WP-MVP-10_Followup_2a_Composition_Production_Caller_Tightening_Spawn_Prompt_2026-04-22.md
---

# WP-MVP-10 Follow-up #2a — Subthread Handoff

## TL;DR

Build thread executed cleanly against the spawn prompt. Three commits on
`wp-mvp-10-followup-2a-production-caller-tightening` branched from `2a02ad3`
(PR #49 squash-merge SHA on `main`). +14 real-crypto regression tests,
`.test-baseline` bumped 2581 → 2595. Typecheck clean, `npm audit` 0 vulns,
all 9 hard gates PASS, all 6 invariant-holdout items PASS, every A1/A2/A3
sub-criterion traceable to a file + line range in this handoff.

No deviations from the spawn prompt's acceptance criteria. One minor framing
note on commit count (3 commits delivered exactly; spawn text is consistent
with that plan).

## Commits (3)

| # | SHA | Subject | Files |
|---|-----|---------|-------|
| 1 | `2a4f9b2` | WP-MVP-10 Follow-up #2a: tighten composition production-caller surface | 4 files +156 −5 |
| 2 | `f4453e0` | WP-MVP-10 Follow-up #2a: production-caller-tightening regression tests | 1 file +313 |
| 3 | `7736a68` | .test-baseline: 2581 -> 2595 (WP-MVP-10 Follow-up #2a) | 1 file +1 −1 |

Total: 6 files changed, +470 / −6 lines.

## File-by-file change summary

| Path | Change | Acceptance criterion |
|------|--------|---------------------|
| `server/src/composition/errors.ts` | Added `MissingSidecarSigningKeyError` class with `callSite` discriminator (`publishVerascoreSignal \| emitForCommitment`) | A1 + A2 |
| `server/src/composition/composition-service.ts` | `publishVerascoreSignal` `signingKey` became optional (A1). New `emitForCommitment` method (A2). New `EmitForCommitmentInput` and `EmitForCommitmentResult` interfaces. New private `resolveSigningKey` helper. Class-header docstring updated to list `emitForCommitment` as canonical. | A1 + A2 |
| `server/src/composition/verascore-hook.ts` | JSDoc `@deprecated` block on the free-function `publishVerascoreSignal` pointing callers at the class method. No runtime behavior change. | A3 |
| `server/src/composition/index.ts` | Added `EmitForCommitmentInput` and `EmitForCommitmentResult` type-exports. `MissingSidecarSigningKeyError` is exported transitively via the existing `export * from "./errors.js"`. | A1 + A2 |
| `server/test/composition/production-caller-tightening.test.ts` | New test file with 14 tests (5 A1 + 8 A2 + 1 A3). | A4 |
| `.test-baseline` | 2581 → 2595 | A5 |

## Test-count delta and baseline delta

- Test count: **+14** (macOS and Linux both, all platform-agnostic).
- `.test-baseline`: **2581 → 2595** (Linux-CI-safe floor).
- Local pre-commit baseline-guard output on the tests commit: `172 test files loaded, 2595 tests passed (baseline: 2581)`. Pre-commit on the baseline commit: `2595 tests passed (baseline: 2595)`.

## Declared deviations

None.

Minor framing note: spawn prompt §"Estimated scope" asked for "3 commits (the three acceptance items, in any sensible order; final commit is the `.test-baseline` bump)". The three acceptance items were grouped as:

- Commit 1 = all surface changes across A1 + A2 + A3 (coherent diff that can be reviewed as a single API-shape evolution).
- Commit 2 = all regression tests covering A1 + A2 + A3 together (one new test file).
- Commit 3 = dedicated `.test-baseline` bump.

This produces exactly 3 commits and matches the spawn's instruction that "final commit is the `.test-baseline` bump." Not a deviation; a disambiguation.

## Invariant holdout check (6 items)

Per `Review/Sanctuary/Public_Pool_Federation_Mode_V1.x_Design_Stub_2026-04-22.md` §"v1.0 invariants that must be preserved":

| # | Invariant | Status | Evidence |
|---|-----------|--------|----------|
| 1 | Multi-principal data model | **PASS** | `EmitForCommitmentInput.principal_id?: string` accepted at v1.0 (composition-service.ts:91); test asserts the field is accepted but does NOT appear in the emitted signal (production-caller-tightening.test.ts:246-259). No schema break for v1.x call sites. |
| 2 | Agent-locator separable from principal-locator at v1.x | **PASS** | No new field couples agent and principal. `EmitForCommitmentInput` accepts `principal_id?` as a separate optional field alongside `agent_id` which flows through the receipt, not the input. |
| 3 | Patron-scope key branches under operator-scope | **PASS** | HKDF derivation chain is unchanged in this thread. The `HKDF_COMPOSITION_SIDECAR_SIGNING_INFO` constant and the `deriveSidecarSigningKey` function are untouched, preserving PR #49's v1.x-patron-scope-subkey branch admissibility. |
| 4 | Policy-engine scope hierarchy | **PASS** | No policy-engine surface touched. Verified by grep: `git diff main..HEAD -- server/src/policy-engine/` is empty. |
| 5 | Per-principal attestation UX | **PASS** | No signal field added that would foreclose a per-principal attestation badge. `EmitForCommitmentResult.audit_event_ids` is reserved empty at v1.0, so a v1.x badge-surface update can add per-principal event ids without a schema break. |
| 6 | Capacity separable from custody | **PASS** | No capacity primitive touched. Verified by grep: no changes to mesh, fortress, or recovery surfaces. Composition sidecar is custody; capacity primitive remains a separate v1.x layer. |

No FLAGs. Nothing to surface before coordinator review.

## Hard-gate self-check (9 items)

| # | Hard gate | Status | Evidence |
|---|-----------|--------|----------|
| 1 | Non-dependency principle | **PASS** | No new imports from standalone `concordia/` or `verascore/` packages. `git diff main..HEAD -- server/` imports are all from `../src/composition/`, `../src/core/`, `../src/mesh/`, or `@noble/*` (already in the dependency graph). |
| 2 | Federation v0.1 §10 reservation | **PASS** | No new reserved envelope keys, event_type prefixes, capability bits, or certificate fields. `composition_*` namespace unchanged. `audit_event_ids` is an internal return field on `EmitForCommitmentResult`, not a wire-level envelope key. |
| 3 | `signature_scheme: 'ed25519-v1'` mandatory | **PASS** | A2 test at production-caller-tightening.test.ts:193-202 asserts `result.signal.signature_scheme` is exactly `ed25519-v1` and triple-equals `SIGNATURE_SCHEME_V1` and `SIDECAR_SIGNATURE_SCHEME`. Signal field is carried through `hookPublishSignal`, which was untouched in this PR. |
| 4 | Naming-discipline rule | **PASS** | No competitor names in any new public-facing artifact. Partners (Concordia, Verascore) named correctly. JSDoc deprecation text uses only canonical method names. |
| 5 | No-em-dash rule | **PASS** | `grep —` across all modified source files and the new test file: zero matches. (Internal handoff doc may use em-dashes freely per CLAUDE.md.) |
| 6 | MLS dead-claims watch | **PASS** | `grep -iE "MLS\|RFC 9420\|forward secrecy"` across the PR diff: zero matches in added lines. |
| 7 | Attribution | **PASS** | No CIMC references in new artifacts. |
| 8 | Baseline discipline | **PASS** | Floor moves 2581 → 2595 in a dedicated commit (`7736a68`) whose message documents the reason and declares the tests platform-agnostic. Pre-commit baseline-guard output on that commit confirmed `2595 tests passed (baseline: 2595)`. |
| 9 | CI clean | **PASS (local)** | `npm run typecheck` = zero errors. `npm audit --audit-level=high` = `found 0 vulnerabilities`. Full test suite: `172 test files loaded, 2595 tests passed`. CI run pending PR push. |

## Acceptance criteria traceability

### A1 — `publishVerascoreSignal` `signingKey` becomes optional

| Spec requirement | File:line |
|---|---|
| New method signature `signingKey?: Uint8Array` | server/src/composition/composition-service.ts:318-323 (signature), line 321 is the `signingKey?:` parameter |
| Default to `this.getSidecarSigningKey()` when omitted | server/src/composition/composition-service.ts:514-531 (private `resolveSigningKey` helper); the `this.getSidecarSigningKey()` call is at line 519, private-key bytes used at line 520 |
| Throw `MissingSidecarSigningKeyError` when both absent (publishVerascoreSignal branch) | server/src/composition/composition-service.ts:521-525 |
| Error message references FortressContextInput and explicit-key paths | server/src/composition/composition-service.ts:523 |
| `publishVerascoreSignal` calls the resolver | server/src/composition/composition-service.ts:326-329 |
| PR #47 explicit-key tests still pass | server/test/composition/composition-v1.test.ts passes locally (53/53). Confirmed via `npx vitest run test/composition/composition-v1.test.ts`. |
| New test: omit signingKey with fortress context | server/test/composition/production-caller-tightening.test.ts:89-104 |
| New test: byte-equal-to-explicit via independent service determinism | server/test/composition/production-caller-tightening.test.ts:105-131 |
| New test: omit signingKey without fortress context throws | server/test/composition/production-caller-tightening.test.ts:132-138 |
| New test: `MissingSidecarSigningKeyError` carries `callSite` and code | server/test/composition/production-caller-tightening.test.ts:140-155 |
| New test: explicit signingKey still works (PR #47 back-compat) | server/test/composition/production-caller-tightening.test.ts:156-171 |

### A2 — New canonical entry point `emitForCommitment`

| Spec requirement | File:line |
|---|---|
| `EmitForCommitmentInput` with `principal_id?: string` reserved | server/src/composition/composition-service.ts:84-96; `principal_id` optional field at line 91 |
| `EmitForCommitmentResult` with `audit_event_ids` reserved extension | server/src/composition/composition-service.ts:105-109; `audit_event_ids: readonly string[]` at line 108 |
| Method always uses `getSidecarSigningKey()` via resolver | server/src/composition/composition-service.ts:353-370; resolver call at line 356 |
| No `signingKey` parameter exposed | server/src/composition/composition-service.ts:353 (signature has no signingKey parameter) |
| Throws without fortress context | server/src/composition/composition-service.ts:527-530 (via `resolveSigningKey(undefined, "emitForCommitment")`) |
| Test: signature verifies under HKDF-derived pubkey | server/test/composition/production-caller-tightening.test.ts:178-191 |
| Test: signature_scheme is ed25519-v1 | server/test/composition/production-caller-tightening.test.ts:193-202 |
| Test: throws cleanly without fortress context | server/test/composition/production-caller-tightening.test.ts:204-219 |
| Test: audit_event_ids empty | server/test/composition/production-caller-tightening.test.ts:221-229 |
| Test: signal shape (fortress_id, agent_id, scope default, behavioral_metrics) | server/test/composition/production-caller-tightening.test.ts:231-244 |
| Test: principal_id accepted but ignored at v1.0 | server/test/composition/production-caller-tightening.test.ts:246-259 |
| Test: composition disabled throws CompositionDisabledError | server/test/composition/production-caller-tightening.test.ts:261-272 |
| Test: public scope with explicit opt-in | server/test/composition/production-caller-tightening.test.ts:274-283 |

### A3 — JSDoc deprecation pointer on the free function

| Spec requirement | File:line |
|---|---|
| JSDoc `@deprecated` block | server/src/composition/verascore-hook.ts:57-66; `@deprecated` tag at line 57 |
| Points at `CompositionService.emitForCommitment` (canonical) and `publishVerascoreSignal` class method | server/src/composition/verascore-hook.ts:59-63 |
| No runtime deprecation warning | No `console.warn` or code-level `@deprecated` decorator added. JSDoc-only. |
| Signature unchanged | server/src/composition/verascore-hook.ts:73-76 (unchanged parameter list and return type) |
| Export preserved | server/src/composition/verascore-hook.ts:73 (still `export function`). `index.ts:25` re-export unchanged. |
| Sanity test: import + call works | server/test/composition/production-caller-tightening.test.ts:291-308 |

### A4 — Test file naming and count

| Spec requirement | Actual |
|---|---|
| Path: `server/test/composition/production-caller-tightening.test.ts` | Matches |
| A1 tests: 3-5 cases | 5 cases (tests 1-5 in file) |
| A2 tests: 5-8 cases | 8 cases (tests 6-13 in file) |
| A3 sanity test | 1 case (test 14 in file) |
| Total: 9-14 new tests | 14 tests |
| Platform-agnostic | Yes: no Keychain, no filesystem, no sidecar spawn. Pure `@noble/curves` Ed25519 sign + verify against in-memory fortress contexts. |

### A5 — `.test-baseline` floor bumped

| Spec requirement | Actual |
|---|---|
| Bump by exact test-count delta | 2581 + 14 = 2595. Matches. |
| Dedicated final commit | Commit 3 (`7736a68`) contains only `.test-baseline`. |
| Commit title format `.test-baseline: 2581 -> <new floor> (WP-MVP-10 Follow-up #2a)` | Matches. |
| Linux-CI-safe | All 14 new tests are platform-agnostic. |

### A6 — Handoff doc

This document, `Archive/SUBTHREAD_HANDOFF_WP_MVP_10_FOLLOWUP_2A_PRODUCTION_CALLER_TIGHTENING_2026-04-22.md`, models on the PR #49 handoff structure.

## CI verification

Pre-commit baseline-guard ran on every commit:

- Commit 1 (surface): `171 test files loaded, 2581 tests passed (baseline: 2581)` — surface changes do not add tests, floor held.
- Commit 2 (tests): `172 test files loaded, 2595 tests passed (baseline: 2581)` — 14 new tests, exceeds floor. Baseline-guard printed the "update in a follow-up commit" reminder.
- Commit 3 (baseline): `172 test files loaded, 2595 tests passed (baseline: 2595)` — floor locked to the new count.

Typecheck: clean on all 3 commits.
`npm audit --audit-level=high`: `found 0 vulnerabilities`.
Full composition suite: `107 tests passed` across 5 test files (composition-v1, sidecar-signing-key, sidecar-requirements-hash-pin, sidecar-size-cap, production-caller-tightening).

Full CI run pending PR push. Expected: green on Linux; the new tests are `@noble/curves`-only and do not exercise any macOS-specific code path.

## Follow-up backlog carried forward

- **Follow-up #2b**: actual broker / commitment-boundary production wire-up. This PR built the surface; #2b builds the caller. The canonical entry point is now `CompositionService.emitForCommitment(input)` and the broker pipeline should call it directly with fortress context pre-installed on the singleton `CompositionService` at fortress boot.
- **Follow-up #2b (sub-item)**: populate `EmitForCommitmentResult.audit_event_ids` with the ids of `composition_*` signed-event envelopes emitted alongside the verascore signal.
- **v1.x**: start populating `EmitForCommitmentInput.principal_id` at the commitment-boundary layer when multi-principal support lands (per-principal attestation UX invariant).

## Outstanding questions for coordinator

None. No spec gaps surfaced during implementation. Every acceptance-criterion sub-requirement has a file + line-range pointer above.

## How to verify locally

```bash
cd ~/Code/Claude/sanctuary-worktrees/wp-mvp-10-followup-2a-production-caller-tightening
git log --oneline main..HEAD
# 7736a68 .test-baseline: 2581 -> 2595 (WP-MVP-10 Follow-up #2a)
# f4453e0 WP-MVP-10 Follow-up #2a: production-caller-tightening regression tests
# 2a4f9b2 WP-MVP-10 Follow-up #2a: tighten composition production-caller surface

cd server
npm run typecheck                                                 # 0 errors
npm audit --audit-level=high                                      # 0 vulns
npx vitest run test/composition/production-caller-tightening.test.ts  # 14/14 pass
npx vitest run test/composition/                                  # 107/107 pass
```
