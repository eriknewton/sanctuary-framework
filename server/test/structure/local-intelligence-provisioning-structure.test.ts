import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { INTEL_OPS } from "../../src/intelligence/audit-events.js";

const source = (path: string) =>
  readFileSync(new URL(`../../src/${path}`, import.meta.url), "utf8");

describe("local intelligence provisioning structural inventory", () => {
  it("keeps protect and init on the one shared ceremony adapter", () => {
    const adapter = source("wrap/local-intelligence.ts");
    const wrap = source("wrap/cli.ts");
    const init = source("wrap/init.ts");
    expect(adapter).toContain("runLocalIntelligenceProvisioning");
    expect(wrap).toContain('from "./local-intelligence.js"');
    expect(init).toContain('from "./local-intelligence.js"');
    expect(wrap).not.toContain('from "../intelligence/provisioning.js"');
    expect(init).not.toContain('from "../intelligence/provisioning.js"');
  });

  it("inventories both flags, both audit ops, and the registry provider category", () => {
    const wrap = source("wrap/cli.ts");
    const init = source("wrap/init.ts");
    const contextGate = source("operational/context-gate.ts");
    for (const flag of [
      "--provision-local-intelligence",
      "--no-provision-local-intelligence",
    ]) {
      expect(wrap).toContain(flag);
      expect(init).toContain(flag);
    }
    expect(INTEL_OPS.MODEL_PULL).toBe("intelligence_model_pull");
    expect(INTEL_OPS.MODEL_PROVISION_REFUSED).toBe(
      "intelligence_model_provision_refused",
    );
    expect(contextGate).toContain('| "model-registry"');
  });

  it("keeps the production manifest loader and host installer explicitly inert", () => {
    const adapter = source("wrap/local-intelligence.ts");
    expect(adapter).toContain("async () => null");
    expect(adapter).toContain("async () => false");
    expect(adapter).not.toMatch(/https:\/\//);
    expect(adapter).not.toMatch(/execFile|spawn|curl|brew install/);
  });
});
