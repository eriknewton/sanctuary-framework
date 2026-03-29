# SPRINT CONTRACT — SEC-019: Config Silently Accepts Unimplemented Features

**Sprint Date:** 2026-03-28
**Finding:** SEC-019 (High)
**Branch:** `security-review`
**Implementer:** Claude (sprint session)

---

## Step 2 — Architecture Decision

### a) Root Cause

The root cause is that `loadConfig()` in `server/src/config.ts` performs no semantic validation after merging the config file into defaults. The TypeScript type `SanctuaryConfig` defines union types that include unimplemented values (`"groth16" | "plonk"` for `proof_system`, `"hardware-key"` for `key_protection`, `"tee"` for `environment`), but the type system is erased at runtime. The `deepMerge` function accepts any JSON values from the config file without checking whether the resulting config references features the codebase actually implements.

The symptom is silent degradation: a user sets `proof_system: "groth16"` and the code paths check `=== "commitment-only"` — when that check is false, they proceed as if a real ZK system is available, but the actual proof operations still produce commitment-only results. The user believes they have SNARK proofs; they do not.

### b) Smallest Change That Closes the Vulnerability

Add a `validateConfig()` function called at the end of `loadConfig()` that checks the three unimplemented feature fields and throws a clear error if any unimplemented value is specified. The implemented (allowed) values are:

- `state.key_protection`: `"passphrase"` and `"none"` (implemented). `"hardware-key"` is NOT implemented.
- `execution.environment`: `"local-process"` and `"docker"` (implemented). `"tee"` is NOT implemented.
- `disclosure.proof_system`: `"commitment-only"` (implemented). `"groth16"` and `"plonk"` are NOT implemented.

The error message must clearly state which feature is not implemented, preventing silent fallback.

### c) Interaction with Other Findings

None. SEC-019 has no dependencies per REMEDIATION_PLAN.md.

### d) New Risk Introduced

Minimal. Users who previously had unimplemented values in their config will now get an error at startup instead of silent operation. This is the intended behavior — it converts a silent security misrepresentation into an explicit failure. The error message will guide users to the correct implemented value.

---

## Step 3 — Sprint Contract

### Fix Chosen

Add a `validateConfig()` function in `config.ts` that is called at the end of `loadConfig()` (after merging defaults with file/env overrides). This function checks the three affected fields against a whitelist of implemented values and throws a descriptive `Error` if any unimplemented value is found.

This is preferred over removing the unimplemented values from the TypeScript union types because: (1) the type union documents the roadmap intent, and (2) the runtime check catches config file values that bypass TypeScript entirely (raw JSON).

### Files Modified

| File | Change |
|------|--------|
| `server/src/config.ts` | Add `validateConfig()` function; call from `loadConfig()` |
| `server/test/security/reject-unimplemented-features.test.ts` | New: regression tests for SEC-019 |

### Behavior Before and After

**Before:** `loadConfig()` with `{ disclosure: { proof_system: "groth16" } }` returns a config object silently. The system starts and operates as if it has SNARK proof support, but all proof operations produce commitment-only results.

**After:** `loadConfig()` with `{ disclosure: { proof_system: "groth16" } }` throws: `Unimplemented config value: disclosure.proof_system = "groth16". Only "commitment-only" is currently implemented. Using an unimplemented proof system would silently degrade security.`

Same pattern for `key_protection: "hardware-key"` and `environment: "tee"`.

### Regression Tests

1. `loadConfig` with `proof_system: "groth16"` throws with descriptive error
2. `loadConfig` with `proof_system: "plonk"` throws with descriptive error
3. `loadConfig` with `key_protection: "hardware-key"` throws with descriptive error
4. `loadConfig` with `environment: "tee"` throws with descriptive error
5. `loadConfig` with all implemented values (`"commitment-only"`, `"passphrase"`, `"local-process"`) succeeds
6. `loadConfig` with default config (no overrides) succeeds
7. `loadConfig` with multiple unimplemented features reports all of them

### Definition of Done

The evaluator will verify:
1. `loadConfig()` rejects all three unimplemented feature values with clear error messages
2. Error messages name the specific unimplemented feature and its current value
3. All implemented values continue to be accepted without error
4. Default config (no file) continues to work
5. Regression tests cover all unimplemented values and all implemented values
6. Full test suite passes with count >= 265

### Prompt Injection Assessment

This fix does not touch any input/output path that reaches a model prompt. Config values come from a local JSON file or environment variables, not from agent-controlled input. No prompt injection concern.
