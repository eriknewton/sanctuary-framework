import { scannerMcpServersView } from "../../src/wrap/hermes-yaml.js";
import { __hermesParityTestHook } from "../../src/wrap/cli.js";
import type { ParseParityOptions } from "../../src/wrap/hermes-yaml-parse-parity.js";

/**
 * A Hermes config.yaml parse-parity dep that always AGREES with the line
 * scanner. Wrap end-to-end tests that touch an EXISTING Hermes config.yaml
 * exercise the wrap mechanics (backup, rewrite, unwrap, meta, rollback),
 * NOT the parse-parity guard, and must not depend on the CI host carrying
 * PyYAML in the python3 that `spawn` resolves. This stub runs the scanner
 * over the same bytes the guard would parse and echoes that view back as
 * the "PyYAML" result, so the guard's field-by-field comparison always
 * passes and the mechanics test proceeds exactly as before the guard
 * existed.
 *
 * The guard's REAL refusal behaviour (disagreement -> refuse; sidecar
 * unavailable -> refuse fail-closed) is proven separately, against both a
 * mock and a real python3 + PyYAML sidecar, in
 * test/wrap/hermes-yaml-parse-parity.test.ts and the CLI-level
 * fail-before/pass-after tests there.
 */
export const agreeingHermesParity: ParseParityOptions = {
  exec: async (_command, _args, input) => {
    const view = scannerMcpServersView(input);
    return {
      stdout: JSON.stringify({
        hasBlock: view.hasBlock,
        entryNames: view.entryNames,
      }),
      stderr: "",
      code: 0,
    };
  },
};

/**
 * Install a parse-parity override into the test-only injection hook. The
 * sidecar seam is NOT a public runWrap dep (that would let a production
 * caller bypass the real PyYAML validator; DI-bypass closed 2026-07-03), so
 * tests reach the seam through this module-level hook. Call in beforeEach /
 * before driving runWrap; ALWAYS pair with clearHermesParityHook() in
 * afterEach so the override never leaks into another test whose expectation
 * is the real sidecar.
 */
export function installHermesParityHook(parity: ParseParityOptions): void {
  __hermesParityTestHook.parity = parity;
}

/** Clear the test-only parse-parity override. Pair with install in afterEach. */
export function clearHermesParityHook(): void {
  delete __hermesParityTestHook.parity;
}
