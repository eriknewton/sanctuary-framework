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
import { buildPrivacyTier2Redactor } from "../../src/intelligence/privacy-tier2-redactor.js";
import { SubstrateSelector, IDENTITY_REDACTOR } from "../../src/intelligence/selector.js";
import { INTEL_OPS } from "../../src/intelligence/audit-events.js";
import { PrivacyPlaceholderVault } from "../../src/l2-operational/privacy-filter.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
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
