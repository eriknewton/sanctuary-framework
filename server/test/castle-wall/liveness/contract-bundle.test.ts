/** The built liveness contract bundle: closed imports, and evaluator parity with the source on every states.json row. */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import * as source from "../../../src/castle-wall/liveness/contract.js";
import type { LivenessInput } from "../../../src/castle-wall/liveness/evaluate.js";

// Must match LIVENESS_CONTRACT_ARTIFACT in server/tsup.config.ts.
const LIVENESS_CONTRACT_ARTIFACT = "dist/liveness-contract.v1.mjs";
const SERVER = join(__dirname, "..", "..", "..");
const ARTIFACT = join(SERVER, LIVENESS_CONTRACT_ARTIFACT);

type Patch = { op: "set" | "add" | "delete"; path: string; value?: unknown };
const STATES = JSON.parse(readFileSync(join(__dirname, "fixtures", "states.json"), "utf8")) as { base: LivenessInput; rows: Array<{ name: string; patches: Patch[] }> };
function patched(patches: readonly Patch[]): LivenessInput {
  const input = structuredClone(STATES.base) as unknown as Record<string, unknown>;
  for (const patch of patches) {
    const keys = patch.path.split(".");
    const last = keys.pop()!;
    let target = input;
    for (const key of keys) target = target[key] as Record<string, unknown>;
    if (patch.op === "delete") delete target[last];
    else if (patch.op === "add") target[last] = (target[last] as number) + (patch.value as number);
    else target[last] = structuredClone(patch.value);
  }
  return input as unknown as LivenessInput;
}

describe("liveness contract bundle", () => {
  it("is built at its shipped name and names the artifact in the build config", () => {
    expect(existsSync(ARTIFACT), `${LIVENESS_CONTRACT_ARTIFACT} is built`).toBe(true);
    expect(readFileSync(join(SERVER, "tsup.config.ts"), "utf8")).toContain(`"${LIVENESS_CONTRACT_ARTIFACT}"`);
  });

  it("imports no filesystem, network, process or HTTP module and no module at all", () => {
    const text = readFileSync(ARTIFACT, "utf8");
    expect(text).not.toMatch(/\bimport\s*[\s{*("'`]|\bimport\(/);
    expect(text).not.toMatch(/\brequire\s*\(/);
    for (const module of ["fs", "net", "child_process", "http", "https", "dgram", "os"]) {
      expect(text, module).not.toMatch(new RegExp(`["'\`](node:)?${module}["'\`]`));
    }
  });

  it("evaluates every states.json row exactly as the source evaluator does", async () => {
    const bundle = await import(pathToFileURL(ARTIFACT).href) as typeof source;
    expect(bundle.REASON_SLOTS).toBe(source.REASON_SLOTS);
    expect(bundle.REASON_REGISTRY).toEqual(source.REASON_REGISTRY);
    expect(STATES.rows.length).toBeGreaterThan(0);
    for (const row of STATES.rows) {
      expect(bundle.evaluateLiveness(patched(row.patches)), row.name).toEqual(source.evaluateLiveness(patched(row.patches)));
    }
  });
});
