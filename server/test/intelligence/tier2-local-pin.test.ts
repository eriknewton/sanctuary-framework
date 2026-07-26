/**
 * Ratified posture (2026-07-23): the `privacy-filter-tier-2` surface is
 * pinned local-only. This suite proves the pin at every layer:
 *
 *   - config-write refusal (`setPerSurfaceChoice`) with the typed,
 *     posture-naming error; `local` and `disabled` still allowed
 *   - bulk fan-out (`applyChoiceToAllSurfaces`) skips the pinned
 *     surface, reports the skip, and stamps it on the bulk audit event
 *   - invoke-time chokepoint: a persisted (tampered / pre-existing)
 *     non-local binding resolves to `local`, with a ONE-time
 *     `query_anonymity_tier2_binding_pinned` audit event
 *   - the fallback chain never carries the pinned surface past local
 *     (no venice attempt even with a key configured)
 *   - the Rho-2 degrade contract is intact: with no local substrate
 *     available the rewrite returns the regex-only result, it never
 *     blocks the query (the pin means never-remote, not must-LLM)
 */

import { describe, it, expect } from "vitest";
import { SubstrateSelector } from "../../src/intelligence/selector.js";
import { IntelligenceConfigStore } from "../../src/intelligence/policy-store.js";
import { INTEL_OPS } from "../../src/intelligence/audit-events.js";
import {
  TIER2_PINNED_SURFACE,
  Tier2BindingPinnedError,
  isTier2PinViolation,
} from "../../src/intelligence/types.js";
import { rewritePiiWithLlm } from "../../src/query-anonymity/pii-rewrite.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

function buildSelector(opts: { fetchImpl?: typeof fetch } = {}) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const selector = new SubstrateSelector({
    storage,
    masterKey,
    auditLog,
    identityId: "pin-test-identity",
    fetchImpl: opts.fetchImpl,
  });
  return { storage, masterKey, auditLog, selector };
}

/** fetch stub that records every requested URL and 404s everything. */
function recordingFailFetch(): { fetchImpl: typeof fetch; urls: string[] } {
  const urls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL): Promise<Response> => {
    const url =
      input instanceof Request
        ? input.url
        : typeof input === "string"
          ? input
          : input.toString();
    urls.push(url);
    return new Response("", { status: 404 });
  }) as typeof fetch;
  return { fetchImpl, urls };
}

describe("tier-2 local pin: config-write gate", () => {
  it("refuses every non-local binding for privacy-filter-tier-2", async () => {
    const { selector, auditLog } = buildSelector();
    await selector.load();
    for (const substrate of ["venice", "frontier-with-filter", "hybrid"] as const) {
      await expect(
        selector.setPerSurfaceChoice(TIER2_PINNED_SURFACE, substrate),
      ).rejects.toThrow(Tier2BindingPinnedError);
      await expect(
        selector.setPerSurfaceChoice(TIER2_PINNED_SURFACE, substrate),
      ).rejects.toThrow(/pinned local-only/);
    }
    // Nothing persisted, nothing audited as chosen.
    expect(selector.getConfig().perSurface[TIER2_PINNED_SURFACE]).toBe("local");
    const chosen = await auditLog.query({
      operation_type: INTEL_OPS.SUBSTRATE_CHOSEN,
    });
    expect(chosen.entries.length).toBe(0);
  });

  it("still allows local and disabled for the pinned surface", async () => {
    const { selector } = buildSelector();
    await selector.load();
    await selector.setPerSurfaceChoice(TIER2_PINNED_SURFACE, "disabled");
    expect(selector.getConfig().perSurface[TIER2_PINNED_SURFACE]).toBe("disabled");
    await selector.setPerSurfaceChoice(TIER2_PINNED_SURFACE, "local");
    expect(selector.getConfig().perSurface[TIER2_PINNED_SURFACE]).toBe("local");
    expect(isTier2PinViolation(TIER2_PINNED_SURFACE, "local")).toBe(false);
    expect(isTier2PinViolation(TIER2_PINNED_SURFACE, "disabled")).toBe(false);
    expect(isTier2PinViolation("concierge", "venice")).toBe(false);
  });
});

describe("tier-2 local pin: bulk fan-out", () => {
  it("skips the pinned surface, reports it, and stamps the audit event", async () => {
    const { selector, auditLog } = buildSelector();
    await selector.load();
    const result = await selector.applyChoiceToAllSurfaces("venice");
    expect(result.skippedPinnedSurfaces).toEqual([TIER2_PINNED_SURFACE]);
    const cfg = selector.getConfig();
    expect(cfg.perSurface[TIER2_PINNED_SURFACE]).toBe("local");
    expect(cfg.perSurface.concierge).toBe("venice");
    expect(cfg.perSurface["sentinel-scoring"]).toBe("venice");
    const bulk = await auditLog.query({
      operation_type: INTEL_OPS.BULK_SUBSTRATE_CHOSEN,
    });
    expect(bulk.entries.length).toBe(1);
    const details = bulk.entries[0]!.details as {
      surface_count: number;
      pinned_surfaces_skipped?: string[];
    };
    expect(details.surface_count).toBe(5);
    expect(details.pinned_surfaces_skipped).toEqual([TIER2_PINNED_SURFACE]);
  });

  it("applies to all surfaces when the substrate satisfies the pin", async () => {
    const { selector, auditLog } = buildSelector();
    await selector.load();
    const result = await selector.applyChoiceToAllSurfaces("local");
    expect(result.skippedPinnedSurfaces).toEqual([]);
    const bulk = await auditLog.query({
      operation_type: INTEL_OPS.BULK_SUBSTRATE_CHOSEN,
    });
    const details = bulk.entries[0]!.details as {
      surface_count: number;
      pinned_surfaces_skipped?: string[];
    };
    expect(details.surface_count).toBe(6);
    expect(details.pinned_surfaces_skipped).toBeUndefined();
  });
});

describe("tier-2 local pin: invoke-time chokepoint", () => {
  it("overrides a tampered persisted binding to local with a one-time audit", async () => {
    const { selector, auditLog, storage, masterKey } = buildSelector();
    await selector.load();
    // Tamper the persisted config directly (bypassing the config-write
    // gate) the way a corrupted or grandfathered record would look.
    const store = new IntelligenceConfigStore(storage, masterKey);
    const tampered = {
      ...selector.getConfig(),
      perSurface: {
        ...selector.getConfig().perSurface,
        [TIER2_PINNED_SURFACE]: "venice" as const,
      },
    };
    await store.save(tampered);

    const reloaded = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: "pin-test-identity",
    });
    await reloaded.load();
    // The persisted value survives for operator correction...
    expect(reloaded.getConfig().perSurface[TIER2_PINNED_SURFACE]).toBe("venice");
    // ...but resolution is pinned local.
    const handle = await reloaded.getSubstrate(TIER2_PINNED_SURFACE);
    expect(handle.substrate).toBe("local");

    // One audit event on first override; repeated resolutions do not
    // flood the log.
    await reloaded.getSubstrate(TIER2_PINNED_SURFACE);
    await reloaded.invokeRedact(TIER2_PINNED_SURFACE, {
      kind: "redact",
      text: "probe",
    });
    const pinned = await auditLog.query({
      operation_type: INTEL_OPS.TIER2_BINDING_PINNED,
    });
    expect(pinned.entries.length).toBe(1);
    const details = pinned.entries[0]!.details as {
      kind: string;
      surface: string;
      persisted_substrate: string;
      pinned_to: string;
    };
    expect(details.kind).toBe("tier2_binding_pinned");
    expect(details.surface).toBe(TIER2_PINNED_SURFACE);
    expect(details.persisted_substrate).toBe("venice");
    expect(details.pinned_to).toBe("local");
  });

  it("never escapes local via the fallback chain, even with a venice key", async () => {
    const { fetchImpl, urls } = recordingFailFetch();
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    await selector.setVeniceApiKey("venice-key-for-fallback-test");
    // setVeniceApiKey validates the key against the venice API; that
    // call is not the one under test. Only fetches AFTER this point
    // would be fallback egress.
    urls.length = 0;
    // Pinned surface stays local (the default); local invocations fail
    // (every fetch 404s). Without the pin, degrade-silent fallback
    // would walk local -> venice and egress the request remotely.
    const response = await selector.invokeRedact(TIER2_PINNED_SURFACE, {
      kind: "redact",
      text: "residual-bearing text",
    });
    expect(response.failureClass).not.toBeNull();
    expect(response.servedBy).not.toBe("venice");
    const veniceCalls = urls.filter((u) => u.includes("venice.ai"));
    expect(veniceCalls).toEqual([]);
  });

  it("keeps the Rho-2 degrade contract: regex-only result, query never blocked", async () => {
    const { fetchImpl } = recordingFailFetch();
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    const result = await rewritePiiWithLlm(
      "email erik@example.com about the rent for Erik Newton",
      selector,
      { identityId: "pin-test-identity" },
    );
    expect(result.llm_assist_ran).toBe(false);
    expect(result.rewritten).toContain("[EMAIL_0]");
    expect(result.rewritten).toContain("[NAME_0]");
    expect(result.rewritten).not.toContain("erik@example.com");
  });
});
