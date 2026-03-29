# SPRINT_CONTRACT.md — SEC-003: Canonical JSON Divergence (Cross-Repo)

**Sprint Date:** 2026-03-28
**Finding ID:** SEC-003
**Repos:** Sanctuary (TypeScript) + Concordia (Python)
**Scope:** Coordinated fix — both repos must produce byte-identical canonical JSON

---

## Step 1 — Pre-Implementation Analysis

### a) What is the exact divergence?

Five concrete divergence points between TypeScript (`stableStringify` in `server/src/bridge/bridge.ts:53-73`) and Python (`canonical_json` in `concordia/signing.py:70-80`):

**1. Number formatting (HIGH risk):**
- TypeScript uses V8's `JSON.stringify(value)` following ECMAScript `Number.prototype.toString()`:
  - Integer-valued floats: `1.0` → `"1"`
  - Decimal notation up to 10^21: `1e20` → `"100000000000000000000"`
  - Exponential from 10^21: `1e21` → `"1e+21"`
- Python uses `json.dumps` default float formatting:
  - Preserves decimal: `1.0` → `"1.0"`
  - Scientific notation earlier: `1e20` → `"1e+20"`
- **Same numeric value → different bytes → different hash**

**2. Unicode handling (HIGH risk):**
- TypeScript's `JSON.stringify()`: does NOT escape non-ASCII (raw UTF-8)
- Python's `canonical_json` uses `ensure_ascii=False`: matches TypeScript
- **BUT** `sanctuary_bridge.py:113` uses vanilla `json.dumps()` WITHOUT `ensure_ascii=False` (defaults to `True`): escapes all non-ASCII as `\uXXXX`
- **`"café"` → TS: `"café"`, Python bridge: `"caf\u00e9"` → different bytes**

**3. Negative zero (MEDIUM risk):**
- Python: explicitly rejects `-0.0`
- TypeScript: does NOT check for `-0`. V8 produces `"0"`, silently coercing.
- **Asymmetric validation**

**4. Inconsistent use of canonical functions (HIGH risk):**
- `bridge.ts:131` uses `JSON.stringify(commitmentPayload)` for signing — NOT `stableStringify`
- `bridge.ts:189` uses `JSON.stringify(commitmentPayload)` for verification — NOT `stableStringify`
- `sanctuary_bridge.py:113` uses `json.dumps()` — NOT `canonical_json`
- **Key ordering depends on insertion order, not sort**

**5. undefined vs None:**
- TypeScript maps `undefined` → `"null"` explicitly
- Python has no `undefined`; `None` → `null`
- Not a practical cross-repo divergence, but a spec gap

### b) Source of truth for canonical format

**Both repos conform to a shared internal spec inspired by RFC 8785, using ECMAScript number formatting as the authoritative format.**

TypeScript already follows ECMAScript natively. Python must align. This is the smallest total change.

**Canonical format:**
- Keys: sorted alphabetically (lexicographic by code points)
- Separators: `","` and `":"` (no whitespace)
- Strings: UTF-8, `ensure_ascii=False`, standard JSON escaping for control chars/quote/backslash
- Numbers: ECMAScript `Number.prototype.toString()` rules
- Rejected: `NaN`, `Infinity`, `-Infinity`, `-0.0`
- Encoding: UTF-8

### c) Migration impact

**Zero.** Both repos are on `security-review`. Merge gate has not passed. No production deployment, no existing signatures in storage.

---

## Fix Specification

### Files to modify — Sanctuary (TypeScript)

| File | Change |
|------|--------|
| `server/src/bridge/bridge.ts:57` | Add `-0` detection: `if (Object.is(value, -0)) throw` |
| `server/src/bridge/bridge.ts:131` | Replace `JSON.stringify(commitmentPayload)` with `stableStringify(commitmentPayload)` |
| `server/src/bridge/bridge.ts:189` | Replace `JSON.stringify(commitmentPayload)` with `stableStringify(commitmentPayload)` |
| `server/test/bridge/bridge.test.ts` | Add canonical JSON cross-language test vectors |

### Files to modify — Concordia (Python)

| File | Change |
|------|--------|
| `concordia/signing.py` | Rewrite `canonical_json` as manual recursive builder with `_stable_stringify` + `_format_number_ecmascript` |
| `concordia/sanctuary_bridge.py:113` | Replace `json.dumps(agreement, ...)` with `canonical_json(agreement).decode("utf-8")` |
| `tests/test_signing.py` | Add canonical JSON cross-language test vectors |
| `tests/test_sanctuary_bridge.py` | Add test that bridge commitment uses canonical_json |

### Behavior before → after

| Scenario | Before | After |
|----------|--------|-------|
| `{a: 1.0}` | TS: `{"a":1}`, PY: `{"a":1.0}` | Both: `{"a":1}` |
| Bridge signing payload | Vanilla `JSON.stringify` (unsorted) | `stableStringify` (sorted) |
| Bridge commitment value | `json.dumps` (ASCII-escaped) | `canonical_json` (raw UTF-8) |
| `-0` input | TS accepts, PY rejects | Both reject |

### Definition of done (evaluator criteria)
1. Both `stableStringify` and `canonical_json` produce byte-identical output for all shared test vectors
2. No vanilla `JSON.stringify` or `json.dumps` on any signature/hash path
3. Both repos reject `-0.0`
4. Full test suites pass: ≥287 Sanctuary, ≥483 Concordia
5. No new prompt injection surface
