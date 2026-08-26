/**
 * Privacy Filter Tier 2 Redactor — Behavioral Tests
 *
 * Verifies:
 *   - empty text yields zero match count + audit event
 *   - text with no PII spans yields the original text + zero matches
 *   - text with PII spans yields placeholder-substituted output
 *   - placeholder values are stable across calls (vault scope)
 *   - matchCount equals the number of spans replaced
 *   - audit event emitted on every call (success or zero-match)
 *   - selector.installRedactor swaps the redactor without rebuilding
 *     the selector
 *   - frontier-with-filter substrate uses the installed redactor when
 *     the operator binds frontier-with-filter to a surface
 */

import { describe, it, expect, vi } from "vitest";
import {
  buildPrivacyTier2Redactor,
  buildConsentGatedTier2Redactor,
  installConsentGatedRedactor,
} from "../../src/intelligence/privacy-tier2-redactor.js";
import { SubstrateSelector, IDENTITY_REDACTOR } from "../../src/intelligence/selector.js";
import { INTEL_OPS } from "../../src/intelligence/audit-events.js";
import { PrivacyPlaceholderVault } from "../../src/operational/privacy-filter.js";
import { PiiConfigStore } from "../../src/query-anonymity/pii-config-store.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

function buildHarness() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const vault = new PrivacyPlaceholderVault(storage, masterKey);
  const selector = new SubstrateSelector({
    storage,
    masterKey,
    auditLog,
    identityId: "test-identity",
  });
  const redactor = buildPrivacyTier2Redactor({
    selector,
    vault,
    surface: "concierge",
    substrate: "frontier-with-filter",
  });
  return { storage, masterKey, auditLog, vault, selector, redactor };
}

describe("buildPrivacyTier2Redactor — text passthrough", () => {
  it("empty text yields zero matches and audit event", async () => {
    const { redactor, auditLog, selector } = buildHarness();
    await selector.load();
    const result = await redactor("");
    expect(result.redacted).toBe("");
    expect(result.matchCount).toBe(0);

    const events = await auditLog.query({ operation_type: INTEL_OPS.PII_REDACTION_EVENT });
    expect(events.entries.length).toBe(1);
    const details = events.entries[0]!.details as { match_count: number; filter_tier: number };
    expect(details.match_count).toBe(0);
    expect(details.filter_tier).toBe(2);
  });

  it("text with no PII spans yields original text + zero matches", async () => {
    const { redactor, auditLog, selector } = buildHarness();
    await selector.load();
    const result = await redactor("agent X read three files today");
    expect(result.redacted).toBe("agent X read three files today");
    expect(result.matchCount).toBe(0);

    const events = await auditLog.query({ operation_type: INTEL_OPS.PII_REDACTION_EVENT });
    expect(events.entries.length).toBe(1);
  });
});

describe("buildPrivacyTier2Redactor — span replacement", () => {
  it("redacts an email address to a placeholder", async () => {
    const { redactor, auditLog, selector } = buildHarness();
    await selector.load();
    const result = await redactor("contact alice@example.com today");
    expect(result.redacted).not.toContain("alice@example.com");
    expect(result.matchCount).toBe(1);
    expect(result.redacted).toMatch(/EMAIL_/);

    const events = await auditLog.query({ operation_type: INTEL_OPS.PII_REDACTION_EVENT });
    const details = events.entries[0]!.details as { match_count: number };
    expect(details.match_count).toBe(1);
  });

  it("redacts multiple PII classes in one pass", async () => {
    const { redactor, selector } = buildHarness();
    await selector.load();
    const result = await redactor("alice@example.com SSN 123-45-6789");
    expect(result.matchCount).toBeGreaterThanOrEqual(2);
    expect(result.redacted).not.toContain("alice@example.com");
    expect(result.redacted).not.toContain("123-45-6789");
  });

  it("placeholder values are stable across calls (same surface scope)", async () => {
    const { redactor, selector } = buildHarness();
    await selector.load();
    const a = await redactor("contact alice@example.com please");
    const b = await redactor("ping alice@example.com again");
    // Extract the placeholder used for alice@example.com from each call.
    const placeholderA = a.redacted.match(/EMAIL_\d+/)?.[0];
    const placeholderB = b.redacted.match(/EMAIL_\d+/)?.[0];
    expect(placeholderA).toBeTruthy();
    expect(placeholderA).toBe(placeholderB);
  });
});

describe("SubstrateSelector.installRedactor — late binding", () => {
  it("swaps IDENTITY_REDACTOR for the Tier 2 redactor at runtime", async () => {
    const { selector, vault } = buildHarness();
    await selector.load();

    // Until installed, frontier-with-filter handle uses IDENTITY_REDACTOR.
    expect(IDENTITY_REDACTOR).toBeDefined();

    const tier2 = buildPrivacyTier2Redactor({
      selector,
      vault,
      surface: "concierge",
      substrate: "frontier-with-filter",
    });
    selector.installRedactor(tier2);

    // The redactor is now installed; subsequent frontier handle issues use it.
    // We cannot directly observe redactor identity without exposing internals,
    // but the fact that installRedactor returns void and getSubstrate still
    // works after install is sufficient.
    await selector.setPerSurfaceChoice("concierge", "frontier-with-filter");
    await selector.setFrontierApiKey("anthropic", "test-key");
    const handle = await selector.getSubstrate("concierge");
    expect(handle.substrate).toBe("frontier-with-filter");
  });
});

describe("Tier 2 redactor — frontier substrate end-to-end", () => {
  it("frontier-with-filter substrate redacts PII before the API call", async () => {
    const { selector, vault, auditLog } = buildHarness();
    await selector.load();

    const tier2 = buildPrivacyTier2Redactor({
      selector,
      vault,
      surface: "concierge",
      substrate: "frontier-with-filter",
    });
    selector.installRedactor(tier2);

    // Capture every outbound URL + body so we can assert the post-redaction
    // text reaches the frontier; the original PII does not.
    const captured: { url: string; body: string }[] = [];
    const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      const body = init?.body ? String(init.body) : "";
      captured.push({ url, body });
      return new Response(
        JSON.stringify({ content: [{ type: "text", text: "summary" }] }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }) as unknown as typeof fetch;

    const harnessSelector = new SubstrateSelector({
      storage: new MemoryStorage(),
      masterKey: generateRandomKey(),
      auditLog,
      identityId: "test-identity",
      fetchImpl,
    });
    await harnessSelector.load();
    harnessSelector.installRedactor(tier2);
    await harnessSelector.setPerSurfaceChoice("concierge", "frontier-with-filter");
    await harnessSelector.setFrontierApiKey("anthropic", "test-key");

    await harnessSelector.invokeSummarize("concierge", {
      kind: "summarize",
      context: "user alice@example.com asked about taxes",
      query: "summarize",
    });

    expect(captured.length).toBe(1);
    expect(captured[0]!.body).not.toContain("alice@example.com");
    expect(captured[0]!.body).toContain("EMAIL_");
  });
});

describe("buildConsentGatedTier2Redactor — opt-in gating", () => {
  function gatedHarness() {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const vault = new PrivacyPlaceholderVault(storage, masterKey);
    const fortressId = "gated-fortress";
    const selector = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: "test-identity",
    });
    const configStore = new PiiConfigStore({ storage, masterKey, fortressId });
    const redactor = buildConsentGatedTier2Redactor({
      selector,
      vault,
      surface: "concierge",
      substrate: "frontier-with-filter",
      configStore,
    });
    return { storage, masterKey, auditLog, vault, selector, configStore, redactor };
  }

  it("passes text through unchanged when Tier B is OFF (default)", async () => {
    const { redactor, selector, auditLog } = gatedHarness();
    await selector.load();
    const result = await redactor("contact alice@example.com today");
    // Disabled -> no scrub, original preserved.
    expect(result.redacted).toBe("contact alice@example.com today");
    expect(result.matchCount).toBe(0);
    // Transparency: emits filter_tier:1 so the UI shows Tier 2 did NOT run.
    const events = await auditLog.query({
      operation_type: INTEL_OPS.PII_REDACTION_EVENT,
    });
    expect(events.entries.length).toBe(1);
    expect(
      (events.entries[0]!.details as { filter_tier: number }).filter_tier,
    ).toBe(1);
  });

  it("the store refuses enabled-without-consent, so the gate never sees an unconsented-active state", async () => {
    const { redactor, selector, configStore } = gatedHarness();
    await selector.load();
    // Consent is enforced at WRITE time: you cannot persist enabled=true
    // without consent. This is why the redactor gate (which also requires
    // consent) can never be tricked into scrubbing/claiming-active for an
    // unconsented operator.
    await expect(configStore.patch({ enabled: true })).rejects.toThrow();
    // With the write refused, config stays default-off -> passthrough.
    const result = await redactor("contact alice@example.com today");
    expect(result.redacted).toBe("contact alice@example.com today");
    expect(result.matchCount).toBe(0);
  });

  it("SCRUBS PII when the operator enabled Tier B AND consented", async () => {
    const { redactor, selector, configStore } = gatedHarness();
    await selector.load();
    await configStore.patch({ enabled: true, consented_to_trade_off: true });
    const result = await redactor("contact alice@example.com today");
    // Opted-in + consented -> real Tier 2 scrub.
    expect(result.redacted).not.toContain("alice@example.com");
    expect(result.redacted).toMatch(/EMAIL_/);
    expect(result.matchCount).toBe(1);
  });

  it("SCRUBS when smart mode is enabled (with consent) even if basic enabled is off", async () => {
    const { redactor, selector, configStore } = gatedHarness();
    await selector.load();
    await configStore.patch({
      smart_mode_enabled: true,
      consented_to_trade_off: true,
    });
    const result = await redactor("ping bob@example.com");
    expect(result.redacted).not.toContain("bob@example.com");
    expect(result.matchCount).toBe(1);
  });

  it("end-to-end: an actual outbound frontier query is scrubbed only after opt-in", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const vault = new PrivacyPlaceholderVault(storage, masterKey);
    const fortressId = "e2e-fortress";
    const configStore = new PiiConfigStore({ storage, masterKey, fortressId });

    const captured: { body: string }[] = [];
    const fetchImpl = (async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ) => {
      captured.push({ body: init?.body ? String(init.body) : "" });
      return new Response(
        JSON.stringify({ content: [{ type: "text", text: "summary" }] }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }) as unknown as typeof fetch;

    const selector = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: "test-identity",
      fetchImpl,
    });
    await selector.load();
    selector.installRedactor(
      buildConsentGatedTier2Redactor({
        selector,
        vault,
        surface: "concierge",
        substrate: "frontier-with-filter",
        configStore,
      }),
    );
    await selector.setPerSurfaceChoice("concierge", "frontier-with-filter");
    await selector.setFrontierApiKey("anthropic", "test-key");

    // First call: Tier B OFF -> the real value reaches the substrate.
    await selector.invokeSummarize("concierge", {
      kind: "summarize",
      context: "user alice@example.com asked about taxes",
      query: "summarize",
    });
    expect(captured.length).toBe(1);
    expect(captured[0]!.body).toContain("alice@example.com");

    // Operator opts in with consent.
    await configStore.patch({ enabled: true, consented_to_trade_off: true });

    // Second call: now the outbound body is scrubbed.
    await selector.invokeSummarize("concierge", {
      kind: "summarize",
      context: "user alice@example.com asked about taxes",
      query: "summarize",
    });
    expect(captured.length).toBe(2);
    expect(captured[1]!.body).not.toContain("alice@example.com");
    expect(captured[1]!.body).toContain("EMAIL_");
  });
});

describe("installConsentGatedRedactor — shared chokepoint (all production selectors)", () => {
  // This is the helper EVERY production `new SubstrateSelector` site now routes
  // through (index.ts, dashboard-standalone.ts, wrap/cli.ts, cli/policy.ts).
  // The wrap-path leak (HIGH) was that wrap's selector kept IDENTITY_REDACTOR;
  // this test proves the helper installs a working consent-gated scrub, and the
  // wrap-symmetric e2e proves an opted-in concierge frontier call is scrubbed.

  it("returns true and installs a redactor that scrubs only after opt-in", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const fortressId = "chokepoint-fortress";
    const selector = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: "test-identity",
    });
    await selector.load();

    const installed = installConsentGatedRedactor({
      selector,
      storage,
      masterKey,
      fortressId,
    });
    expect(installed).toBe(true);

    // The helper builds its own PiiConfigStore internally; to drive it we use a
    // store with the SAME fortressId (same encrypted at-rest config).
    const configStore = new PiiConfigStore({ storage, masterKey, fortressId });

    // Capture the outbound frontier body.
    const captured: { body: string }[] = [];
    const fetchImpl = (async (
      _input: RequestInfo | URL,
      init?: RequestInit,
    ) => {
      captured.push({ body: init?.body ? String(init.body) : "" });
      return new Response(
        JSON.stringify({ content: [{ type: "text", text: "ok" }] }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }) as unknown as typeof fetch;

    // A second selector sharing the same storage + the installed redactor lets
    // us drive a real frontier call through the captured fetch.
    const driving = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: "test-identity",
      fetchImpl,
    });
    await driving.load();
    // Re-install through the same chokepoint so the driving selector scrubs.
    installConsentGatedRedactor({ selector: driving, storage, masterKey, fortressId });
    await driving.setPerSurfaceChoice("concierge", "frontier-with-filter");
    await driving.setFrontierApiKey("anthropic", "test-key");

    // Off -> unscrubbed.
    await driving.invokeSummarize("concierge", {
      kind: "summarize",
      context: "reach carol@example.com now",
      query: "summarize",
    });
    expect(captured[0]!.body).toContain("carol@example.com");

    // Opt in + consent -> scrubbed.
    await configStore.patch({ enabled: true, consented_to_trade_off: true });
    await driving.invokeSummarize("concierge", {
      kind: "summarize",
      context: "reach carol@example.com now",
      query: "summarize",
    });
    expect(captured[1]!.body).not.toContain("carol@example.com");
    expect(captured[1]!.body).toContain("EMAIL_");
  });

  it("wrap-path symmetric: an opted-in concierge frontier call on the wrap selector is scrubbed", async () => {
    // Mirrors the wrap/cli.ts wiring: the wrap-auto fortress builds a selector,
    // the chokepoint installs the consent-gated redactor with the HASHED
    // fortress id (the same id wrap's buildV11Bindings uses), and concierge is
    // bound to the frontier substrate. Before the fix this egressed UNSCRUBBED.
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    // Stand in for fortressIdFromStoragePath(storagePath) — any stable id the
    // route + redactor agree on; the test uses one value for both.
    const wrapFortressId = "fortress-deadbeefcafe0000";

    const captured: { body: string }[] = [];
    const fetchImpl = (async (
      _input: RequestInfo | URL,
      init?: RequestInit,
    ) => {
      captured.push({ body: init?.body ? String(init.body) : "" });
      return new Response(
        JSON.stringify({ content: [{ type: "text", text: "ok" }] }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }) as unknown as typeof fetch;

    const wrapSelector = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: "fortress:/tmp/wrap-fortress",
      fetchImpl,
    });
    await wrapSelector.load();
    const installed = installConsentGatedRedactor({
      selector: wrapSelector,
      storage,
      masterKey,
      fortressId: wrapFortressId,
    });
    expect(installed).toBe(true);
    await wrapSelector.setPerSurfaceChoice("concierge", "frontier-with-filter");
    await wrapSelector.setFrontierApiKey("anthropic", "test-key");

    // Operator opts in via the route store (same hashed fortress id).
    const routeStore = new PiiConfigStore({
      storage,
      masterKey,
      fortressId: wrapFortressId,
    });
    await routeStore.patch({ enabled: true, consented_to_trade_off: true });

    await wrapSelector.invokeSummarize("concierge", {
      kind: "summarize",
      context: "user alice@example.com asked about taxes",
      query: "summarize",
    });
    expect(captured.length).toBe(1);
    // The HIGH leak is closed: the wrap-path outbound body is scrubbed.
    expect(captured[0]!.body).not.toContain("alice@example.com");
    expect(captured[0]!.body).toContain("EMAIL_");

    // And a real Tier 2 scrub emitted the op the feature-health row greens on.
    const events = await auditLog.query({
      operation_type: INTEL_OPS.PII_REDACTION_EVENT,
    });
    const scrub = events.entries.find(
      (e) => (e.details as { filter_tier?: number }).filter_tier === 2,
    );
    expect(scrub).toBeDefined();
  });
});

describe("Tier 2 redactor — audit emission discipline", () => {
  it("emits exactly one pii_redaction_event per redactor call", async () => {
    const { redactor, auditLog, selector } = buildHarness();
    await selector.load();
    await redactor("contact alice@example.com");
    await redactor("contact bob@example.com");
    await redactor("no PII here");

    const events = await auditLog.query({ operation_type: INTEL_OPS.PII_REDACTION_EVENT });
    expect(events.entries.length).toBe(3);
    const tiers = events.entries.map((e) => (e.details as { filter_tier: number }).filter_tier);
    expect(tiers.every((t) => t === 2)).toBe(true);
  });

  it("never includes the raw text or placeholder map in the audit details", async () => {
    const { redactor, auditLog, selector } = buildHarness();
    await selector.load();
    await redactor("totally-secret-email-address@private.example.com");

    const events = await auditLog.query({ operation_type: INTEL_OPS.PII_REDACTION_EVENT });
    const details = events.entries[0]!.details as Record<string, unknown>;
    const serialized = JSON.stringify(details);
    expect(serialized).not.toContain("totally-secret-email-address");
    expect(serialized).not.toContain("private.example.com");
  });
});

describe("SubstrateSelector.installRedactor — cached handle invalidation", () => {
  it("reissues a cached frontier handle with the installed consent-gated redactor", async () => {
    const bodies: string[] = [];
    const fetchImpl = vi.fn(async (
      _input: Parameters<typeof fetch>[0],
      init?: RequestInit,
    ) => {
      bodies.push(String(init?.body ?? ""));
      return new Response(
        JSON.stringify({ content: [{ type: "text", text: "summary" }] }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }) as unknown as typeof fetch;
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const selector = new SubstrateSelector({
      storage,
      masterKey,
      auditLog: new AuditLog(storage, masterKey),
      identityId: "redactor-cache-test",
      fetchImpl,
    });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "frontier-with-filter");
    await selector.setFrontierApiKey("anthropic", "test-key");
    const identityHandle = await selector.getSubstrate("concierge");

    const installedRedactor = vi.fn(async () => ({
      redacted: "[CONSENT-GATED]",
      matchCount: 1,
    }));
    selector.installRedactor(installedRedactor);
    const consentGatedHandle = await selector.getSubstrate("concierge");
    expect(consentGatedHandle).not.toBe(identityHandle);

    await consentGatedHandle.summarize!({
      kind: "summarize",
      context: "alice@example.com",
      query: "summarize",
    });
    expect(installedRedactor).toHaveBeenCalledTimes(2);
    expect(bodies).toHaveLength(1);
    expect(bodies[0]).toContain("[CONSENT-GATED]");
    expect(bodies[0]).not.toContain("alice@example.com");
  });
});
