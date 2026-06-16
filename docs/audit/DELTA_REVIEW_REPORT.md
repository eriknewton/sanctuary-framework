# Delta Security Review Report — Sanctuary Framework

**Review Date:** 2026-04-03
**Last Audited Commit:** `6535adc` (Merge branch 'security-review')
**Review Head:** `6123a7b` (Fix silent startup failure when passphrase is missing)
**Commits in Delta:** 53
**Changed Source Files:** 32 of 67 (~48%)
**Date Range:** ~2026-03-28 → 2026-04-03

---

## Scope

This delta review audited all changes to `server/src/` since the previous full audit (completed 2026-03-28) and its context gating delta (2026-03-31). The delta includes 16 new source files and 16 modified files, touching ~48% of the codebase.

### Major New Subsystems Audited

| Subsystem | Files | Risk Level |
|-----------|-------|------------|
| Standalone Dashboard | `dashboard-standalone.ts` | Medium — new entry point with auth |
| Injection Detector | `security/injection-detector.ts` | Medium — security subsystem |
| Context Gate Enforcer | `operational/context-gate-enforcer.ts` | Medium — wraps all tools |
| Handshake Attestation | `handshake/attestation.ts` | Low — Ed25519 signing, well-structured |
| L2 Hardening | `operational/hardening.ts`, `hardening-tools.ts` | Low — read-only diagnostic |
| Model Provenance | `operational/model-provenance.ts` | Low — types + in-memory store |
| Decommissioning | `shr/decommission-*.ts` | Low — certificate generation |
| Gateway Adapter | `shr/gateway-adapter.ts` | Low — SHR transformation |
| Update Checker | `update-check.ts` | Low — hardcoded URL, 32KB cap |
| Verascore Publish | `reputation/tools.ts` (reputation_publish) | **High** — outbound HTTP, signing |

---

## New Findings by Severity

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| SEC-036 | **High** | reputation_publish signs with derived key, publishes identity public key + placeholder fallback | **FIXED** |
| SEC-037 | Medium | reputation_publish SSRF via user-controlled verascore_url | **FIXED** |
| SEC-038 | Medium | Long-lived auth token embedded in dashboard HTML source | **FIXED** |
| SEC-039 | Low | reputation_publish and dashboard_open not explicitly classified in policy tiers | **FIXED** |
| SEC-040 | Low | Injection detector safe-field bypass for private_key paths | Deferred (Low risk) |

### Findings Fixed

**SEC-036 (High):** The `reputation_publish` tool derived a separate signing key via `derivePurposeKey(masterKey, "verascore-publish")` but included the identity's public key in the request — making signature verification impossible. On signing failure, it fell back to an all-zeros placeholder signature and still published. **Fix:** Sign with the identity's actual Ed25519 key (same key used for SHR signing). Remove placeholder fallback — signing failure returns an error.

**SEC-037 (Medium):** The `verascore_url` parameter accepted any URL, creating an SSRF vector. **Fix:** Validate against an allowlist of known Verascore domains. Reject non-HTTPS and unknown hostnames.

**SEC-038 (Medium):** The dashboard HTML embedded the long-lived auth token as a JavaScript literal, accessible to browser extensions and XSS. **Fix:** Remove the token from HTML source. The client now relies on sessionStorage (set during the login flow).

**SEC-039 (Low):** New tools added without explicit policy tier classification. **Fix:** Added `reputation_publish` to Tier 1 (requires human approval) and `dashboard_open` to Tier 3 (auto-allow).

### Findings Deferred

**SEC-040 (Low):** The injection detector's `isSafeField()` skips scanning for fields matching `private_key` or `encrypted`. A field named `private_key` with injection text would bypass detection. Deferred because no current tool accepts free-text in a `private_key` field — the field name is schema-enforced.

---

## Re-Audited Files (Prior Fix Verification)

14 files touched areas covered by prior security fixes. All prior fixes verified intact:

| Prior Fix | Status | Verification |
|-----------|--------|--------------|
| SEC-001 (state_delete Tier 1) | ✅ Holds | `state_delete` remains in `tier1_always_approve` |
| SEC-002 (auto_deny hardcoded) | ✅ Holds | `auto_deny` deleted from policy; timeout always denies |
| SEC-003 (canonical JSON) | ✅ Holds | No changes to bridge canonical serialization |
| SEC-005 (import sigs) | ✅ Holds | `reputation_import` signature verification unchanged |
| SEC-007 (relay auth) | ✅ Holds | No Concordia changes in this delta |
| SEC-011 (default deny) | ✅ Holds | Unlisted ops → Tier 1 in gate.ts:149-163 |
| SEC-012 (token in URL) | ✅ Holds | Sessions replace URL tokens. (Strengthened by SEC-038 fix) |
| SEC-016 (stderr timing) | ✅ Holds | No changes to stderr channel |
| SEC-019 (config validation) | ✅ Holds | `validateConfig()` throws on unimplemented features |
| SEC-020 (recovery key) | ✅ Holds | Requires credentials for existing installations |

---

## Test Counts

| Phase | Test Files | Tests |
|-------|-----------|-------|
| Baseline (start) | 45 | 653 |
| After fixes | 47 | 661 |
| Delta | +2 | +8 |

All tests passing. TypeScript typecheck clean.

---

## Recommendation

**MERGE.** All Critical and High findings fixed. Both Medium findings fixed. Prior fixes verified intact. Test count increased. No regressions.

The one deferred finding (SEC-040, Low) can be addressed in normal development.
