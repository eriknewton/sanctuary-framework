# MERGE_GATE_REPORT.md — Sanctuary Framework

> Historical record - 2026-03-28 security-review sprint. Point-in-time gate artifact; not current state. The repo path below is stale and preserved as-recorded.

**Date:** 2026-03-28
**Branch:** `security-review`
**Repo:** sanctuary-framework (~/Desktop/Claude/Sanctuary)
**Gate runner posture:** Independent verification — confirming all merge prerequisites are met before PR to main.

---

## Step 1 — Critical and High Finding Status

All Critical and High findings affecting the Sanctuary repo have reached **PASS** in SPRINT_EVAL.md. No CONDITIONAL PASS conditions remain open.

### Critical Findings

| ID | Title | Fix Commit | Eval Commit | Grade |
|----|-------|------------|-------------|-------|
| SEC-001 | state_delete in tier3_always_allow — agent can irreversibly destroy all user state | `4f2274a` | `998d3d4` | PASS |
| SEC-002 | Webhook auto-approve on timeout inverts the security model | `7f68d5a` | `318d345` | PASS |

### High Findings (Sanctuary-scoped)

| ID | Title | Fix Commit | Eval Commit | Grade |
|----|-------|------------|-------------|-------|
| SEC-005 | Import skips Ed25519 signature verification | `d2fd381` + `94a8567` | `9455545` + `5b2e9aa` | PASS (condition closed) |
| SEC-011 | Gate defaults to allow for unlisted operations (reclassified Medium → High) | `4a72000` | `33d586f` | PASS |
| SEC-012 | Dashboard auth token in URL query strings (reclassified Medium → High) | `91b2740` | `13f1589` | PASS |
| SEC-016 | Stderr channel auto-resolves in 100ms | `6c0516e` | `6985633` | PASS |
| SEC-019 | Config silently accepts unimplemented features | `0633836` | `cf453dc` | PASS |
| SEC-020 | Recovery key path regenerates master key on restart | `d44997d` | `94dff96` | PASS |

### Cross-Repo High Findings (Sanctuary side)

| ID | Title | Fix Commit | Eval Commit | Grade |
|----|-------|------------|-------------|-------|
| SEC-003 | Canonical JSON divergence between TS and Python | `82f3321` | `d48d7a8` → `3a7ebb5` (condition closed) | PASS |
| SEC-ADDENDUM | Prompt injection surfaces (ADD-01/02/03) | `82f3321` (shared w/ SEC-003) | `0014316` → `387780b` (conditions closed) | PASS |

### Verification of Fix Commits in Git Log

All fix commits confirmed present in `git log --oneline security-review`:

- `4f2274a` — SEC-001 ✓
- `7f68d5a` — SEC-002 ✓
- `d2fd381` + `94a8567` — SEC-005 ✓
- `4a72000` — SEC-011 ✓
- `91b2740` — SEC-012 ✓
- `6c0516e` — SEC-016 ✓
- `0633836` — SEC-019 ✓
- `d44997d` — SEC-020 ✓
- `82f3321` — SEC-003 + SEC-ADD-03 ✓

All eval commits confirmed present:

- `998d3d4`, `318d345`, `9455545`, `5b2e9aa`, `33d586f`, `13f1589`, `6985633`, `cf453dc`, `94dff96`, `d48d7a8`, `3a7ebb5`, `0014316`, `387780b` — all ✓

---

## Step 2 — Regression Check

**Full test suite output:**

```
 Test Files  30 passed (30)
      Tests  310 passed (310)
   Duration  20.10s
```

**Test count comparison:**

| Metric | Count |
|--------|-------|
| Tests at audit start | 236 |
| Tests at gate | 310 |
| Delta | +74 |

Test count **exceeds** the baseline. No regressions. All 310 tests pass.

---

## Step 3 — Collateral Closure Audit

No findings in the Sanctuary repo were closed by collateral. All Sanctuary findings were addressed by dedicated sprint commits with independent evaluations.

Note: SEC-007 (Concordia zero caller authentication) produced collateral closures of SEC-008, SEC-009, and SEC-015 — these are Concordia-scoped findings and do not affect this Sanctuary merge gate.

The SEC-003 fix commit `82f3321` bundles SEC-ADD-03 changes (process violation acknowledged and logged in SPRINT_EVAL.md and RETROSPECTIVES.md). The SEC-ADD-03 changes were independently evaluated as part of the SEC-ADDENDUM evaluation cycle and reached PASS. This is a sprint discipline issue, not a correctness issue.

---

## Step 4 — Evaluator Parking Lot

All non-blocking observations from evaluators are either addressed or tracked in REMEDIATION_PLAN.md Section 4:

| Observation | Source | Status |
|-------------|--------|--------|
| Three stale comments referencing "(or auto-approve)" in webhook.ts, dashboard.ts, approval-channel.ts | SEC-002 eval | Non-blocking; cosmetic. Tracked for cleanup. |
| `auto_deny` field retained in three TS interfaces | SEC-002 eval | Non-blocking; cosmetic. Tracked for cleanup. |
| `AutoApproveChannel` exists as exported test class | SEC-002 eval | Non-blocking; not policy-reachable. |
| `reputation_export` is Tier 3 while `state_export` is Tier 1 — asymmetric | SEC-001 eval | Logged in COWORK_CONTEXT.md Evaluator Parking Lot and REMEDIATION_PLAN.md Section 4. |
| No rate limiting on dashboard endpoints | SEC-012 eval | Logged in SPRINT_EVAL.md parking lot. Pre-existing; mitigated by 127.0.0.1 default bind. |
| Encoding bypass in sanitization safe under MCP JSON transport assumption | SEC-ADDENDUM eval | Non-blocking; assumption documented. |
| `reputation_query_weighted` tagging consistency | SEC-ADDENDUM eval | Resolved — tool was tagged in condition closure sprint. |
| SEC-ADD-04 (dependency CVE lockfile) | SEC-ADDENDUM eval | Open — tracked in REMEDIATION_PLAN.md H-08. Out of scope for code sprint. |

No parking lot item is blocking.

---

## Step 5 — Open Items Not Fixed Before Merge

The following items remain open and will not be fixed before merge. All are tracked in REMEDIATION_PLAN.md:

**Section 2 (High Priority — non-security):** Functional bugs (BUG-001 through BUG-016) in REMEDIATION_PLAN.md HP-03 through HP-15. These are functional correctness issues (cache staleness, bridge protocol incompleteness, off-by-one errors), not security vulnerabilities. None create exploitable attack vectors.

**Section 4 (Hardening):** Medium and Low security findings (SEC-004, SEC-006, SEC-013, SEC-015, SEC-017, SEC-018, SEC-021, SEC-022, SEC-023, SEC-024) and SEC-ADD-04. These are defense-in-depth improvements, not exploitable vulnerabilities at current deployment scale.

**Rationale:** The playbook merge gate criteria require all Critical and High security findings to reach PASS. All 10 Critical/High findings affecting Sanctuary have reached PASS with no open conditions. Medium, Low, and Informational findings are tracked for post-merge hardening.

---

## Merge Gate Verdict: PASS

All merge prerequisites are satisfied:

1. **All Critical findings:** 2/2 PASS ✓
2. **All High findings:** 8/8 PASS ✓
3. **No open CONDITIONAL PASS conditions** ✓
4. **Test count meets baseline:** 310 ≥ 236 ✓
5. **All evaluator parking lot items tracked** ✓
6. **All fix and eval commits present in git log** ✓

The `security-review` branch is ready for a PR to `main`.
