/**
 * Hybrid Per-Surface Router — Behavioral Tests
 *
 * Verifies:
 *   - resolveHybridChoice returns the configured rule for a surface
 *   - resolveHybridChoice returns null when rules absent or surface missing
 *   - buildHybridRules fills unset surfaces with `disabled` (visible row in UI)
 *   - validateHybridRules accepts complete records, rejects partial / recursive
 *   - SubstrateSelector.setHybridRules persists + validates
 *   - SubstrateSelector.getSubstrate routes through hybrid rules per surface
 *   - hybrid + missing rule -> disabled handle (not a silent re-route)
 *   - hybrid + present rule pointing at venice (without API key) -> disabled
 *   - hybrid + present rule pointing at frontier-with-filter (without keys) -> disabled
 */

import { describe, it, expect } from "vitest";
import {
  resolveHybridChoice,
  buildHybridRules,
  validateHybridRules,
} from "../../src/intelligence/substrates/hybrid/per-surface-router.js";
import { SubstrateSelector } from "../../src/intelligence/selector.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import type { HybridRoutingRules, Surface } from "../../src/intelligence/types.js";

function buildSelector() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const selector = new SubstrateSelector({
    storage,
    masterKey,
    auditLog,
    identityId: "test-identity",
  });
  return { storage, masterKey, auditLog, selector };
}

describe("resolveHybridChoice", () => {
  it("returns the configured rule for a surface", () => {
    const rules: HybridRoutingRules = {
      perSurface: {
        concierge: "venice",
        "direct-agent-gate-advisor": "local",
        "sentinel-scoring": "local",
        "gate-explanation": "disabled",
        "privacy-filter-tier-2": "local",
        "template-suggestion": "local",
      },
    };
    expect(resolveHybridChoice(rules, "concierge")).toBe("venice");
    expect(resolveHybridChoice(rules, "sentinel-scoring")).toBe("local");
  });

  it("returns null when rules are absent", () => {
    expect(resolveHybridChoice(undefined, "concierge")).toBeNull();
  });
});

describe("buildHybridRules", () => {
  it("fills unset surfaces with disabled so the dashboard surfaces visible rows", () => {
    const rules = buildHybridRules({ concierge: "venice" });
    expect(rules.perSurface.concierge).toBe("venice");
    expect(rules.perSurface["sentinel-scoring"]).toBe("disabled");
    expect(rules.perSurface["gate-explanation"]).toBe("disabled");
  });

  it("returns a record covering all six surfaces", () => {
    const rules = buildHybridRules({});
    const surfaces: Surface[] = [
      "concierge",
      "direct-agent-gate-advisor",
      "sentinel-scoring",
      "gate-explanation",
      "privacy-filter-tier-2",
      "template-suggestion",
    ];
    for (const surface of surfaces) {
      expect(rules.perSurface[surface]).toBe("disabled");
    }
  });
});

describe("validateHybridRules", () => {
  it("accepts a complete rules record", () => {
    const rules = buildHybridRules({ concierge: "local" });
    const result = validateHybridRules(rules);
    expect(result.ok).toBe(true);
  });

  it("rejects a partial record", () => {
    const rules = {
      perSurface: { concierge: "local" },
    } as unknown as HybridRoutingRules;
    const result = validateHybridRules(rules);
    expect(result.ok).toBe(false);
  });

  it("rejects a record with a recursive hybrid rule", () => {
    const rules = buildHybridRules({});
    // Force recursion at runtime; the type system blocks this at the API
    // surface but persisted state can be corrupt.
    (rules.perSurface as Record<Surface, string>).concierge = "hybrid";
    const result = validateHybridRules(rules);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("recursion");
    }
  });
});

describe("SubstrateSelector.setHybridRules", () => {
  it("persists the rules + the change is visible via getConfig", async () => {
    const { selector } = buildSelector();
    await selector.load();
    const rules = buildHybridRules({ concierge: "venice", "sentinel-scoring": "local" });
    await selector.setHybridRules(rules);

    const persisted = selector.getConfig().hybridRules;
    expect(persisted?.perSurface.concierge).toBe("venice");
    expect(persisted?.perSurface["sentinel-scoring"]).toBe("local");
  });

  it("throws on invalid rules", async () => {
    const { selector } = buildSelector();
    await selector.load();
    const partial = { perSurface: { concierge: "local" } } as unknown as HybridRoutingRules;
    await expect(selector.setHybridRules(partial)).rejects.toThrow(/invalid hybrid rules/);
  });
});

describe("SubstrateSelector.getSubstrate — hybrid routing", () => {
  it("routes a hybrid surface through its per-surface rule", async () => {
    const { selector } = buildSelector();
    await selector.load();
    await selector.setHybridRules(buildHybridRules({ concierge: "local" }));
    await selector.setPerSurfaceChoice("concierge", "hybrid");

    const handle = await selector.getSubstrate("concierge");
    expect(handle.substrate).toBe("local");
  });

  it("hybrid with no rule for surface yields disabled handle (no silent re-route)", async () => {
    const { selector } = buildSelector();
    await selector.load();
    // Operator picks hybrid but never sets rules
    await selector.setPerSurfaceChoice("concierge", "hybrid");

    const handle = await selector.getSubstrate("concierge");
    expect(handle.substrate).toBe("disabled");
  });

  it("hybrid -> venice without API key yields disabled (key gate fires)", async () => {
    const { selector } = buildSelector();
    await selector.load();
    await selector.setHybridRules(buildHybridRules({ concierge: "venice" }));
    await selector.setPerSurfaceChoice("concierge", "hybrid");

    const handle = await selector.getSubstrate("concierge");
    expect(handle.substrate).toBe("disabled");
  });

  it("hybrid -> venice with API key yields venice handle", async () => {
    const { selector } = buildSelector();
    await selector.load();
    await selector.setHybridRules(buildHybridRules({ concierge: "venice" }));
    await selector.setVeniceApiKey("test-key");
    await selector.setPerSurfaceChoice("concierge", "hybrid");

    const handle = await selector.getSubstrate("concierge");
    expect(handle.substrate).toBe("venice");
  });

  it("hybrid -> frontier-with-filter without provider key yields disabled", async () => {
    const { selector } = buildSelector();
    await selector.load();
    await selector.setHybridRules(buildHybridRules({ concierge: "frontier-with-filter" }));
    await selector.setPerSurfaceChoice("concierge", "hybrid");

    const handle = await selector.getSubstrate("concierge");
    expect(handle.substrate).toBe("disabled");
  });

  it("hybrid status report reflects misconfiguration when rules absent", async () => {
    const { selector } = buildSelector();
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "hybrid");

    const report = await selector.getOperatorVisibleStatus();
    const concierge = report.surfaces.find((s) => s.surface === "concierge");
    expect(concierge?.health).toBe("unavailable");
    expect(concierge?.failureClass).toBe("substrate_misconfigured");
  });
});
