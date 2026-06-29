# SPRINT RESULT — SEC-003: Canonical JSON for Cross-Repo Signature Verification

> Historical record - 2026-03-28 SEC-003 security-review sprint. Point-in-time artifact; not current state.

**Sprint Date:** 2026-03-28
**Finding ID:** SEC-003
**Repos:** Sanctuary (TypeScript) + Concordia (Python)

---

## What Changed and Why

### Root Cause
Sanctuary's TypeScript bridge and Concordia's Python signing module independently implemented canonical JSON serialization with different formatting rules. Additionally, both repos had code paths that bypassed their own canonical serializer, using vanilla `JSON.stringify` / `json.dumps` on signature-critical data.

### Sanctuary Changes (TypeScript)

**`server/src/bridge/bridge.ts`:**
1. Added `-0` (negative zero) rejection to `stableStringify`: `Object.is(value, -0)` check throws. Previously V8 silently coerced `-0` to `"0"`, creating asymmetry with Python.
2. Replaced `JSON.stringify` with `stableStringify` at commitment signing (line 135) and verification (line 195) — ensures deterministic key ordering.

**`server/test/bridge/bridge.test.ts`:**
- Added 16 cross-language canonical JSON test vectors.

### Concordia Changes (Python)

**`concordia/signing.py`:**
1. Rewrote `canonical_json` as manual recursive builder (`_stable_stringify`) producing byte-identical output to TypeScript's `stableStringify`.
2. Added `_format_number_ecmascript`: formats numbers per ECMAScript Number::toString rules (integer-valued floats drop decimal: `1.0` -> `"1"`).
3. Added `_stable_stringify`: recursive JSON builder with sorted keys, compact separators, `ensure_ascii=False` for strings.

**`concordia/sanctuary_bridge.py`:**
- Replaced `json.dumps(agreement, sort_keys=True, separators=(",",":"))` with `canonical_json(agreement).decode("utf-8")` — fixes `ensure_ascii` divergence.

**`tests/test_signing.py`:**
- Added `TestCrossLanguageCanonicalJSON` (17 tests): shared vectors + Python-specific number formatting tests.

**`tests/test_sanctuary_bridge.py`:**
- Added 2 tests: Unicode preservation and integer formatting in commitment payloads.

---

## Test Suite Results

**Sanctuary:** 303 passed, 0 failed (baseline 287, +16 new)
**Concordia:** 517 passed, 0 failed (baseline 483, +34 new)

---

## New Risk Introduced

Minimal. Changes make serialization stricter (reject `-0`, enforce canonical path). No signatures in persistent storage to invalidate (pre-merge-gate).

---

## Adjacent Findings Noticed

The test helper `stableStringify` in `bridge.test.ts` is a simplified copy without security checks. Not a vulnerability but should be tracked for cleanup.

---

## Sprint Contract Criteria

| Criterion | Status |
|-----------|--------|
| Byte-identical output for shared test vectors | PASS (14 vectors in both repos) |
| No vanilla JSON.stringify/json.dumps on signature paths | PASS (3 call sites fixed) |
| Both repos reject -0.0 | PASS |
| Test suites pass (>=287 Sanctuary, >=483 Concordia) | PASS (303 / 517) |
| No new prompt injection surface | PASS |
