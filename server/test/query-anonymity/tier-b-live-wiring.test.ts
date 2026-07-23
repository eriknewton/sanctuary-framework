/**
 * Rho-2.5 Tier B live-wiring regression suite.
 *
 * Asserts the two load-bearing properties of the live substrate-selector
 * query path:
 *   1. DISABLED (the default): the substrate query is byte-identical to
 *      the operator's text and no `query_anonymity_pii_rewritten` audit
 *      event fires (no behavior change for un-opted-in fortresses).
 *   2. ENABLED (opt-in + consent): the substrate-selector calls never
 *      carry the original PII text; the query is rewritten BEFORE
 *      invocation and the `query_anonymity_pii_rewritten` audit event
 *      fires with per-category counts + the consent snapshot.
 *
 * Castle-walking: no new outbound surface is exercised; the stub
 * selector stands in for the single existing outbound channel and every
 * call it receives is inspected for PII leakage.
 */

import { describe, expect, it, vi } from "vitest";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AuditLog } from "../../src/operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { OperatorChatStore } from "../../src/chat/operator-chat-store.js";
import { OperatorChatService } from "../../src/chat/operator-chat-service.js";
import type { SubstrateSelector } from "../../src/intelligence/selector.js";
import type {
  ClassifyRequest,
  RedactRequest,
  SubstrateHandle,
  SubstrateResponse,
  SummarizeRequest,
} from "../../src/intelligence/types.js";
import {
  PII_REWRITE_AUDIT_OPS,
  type RedactionCounts,
} from "../../src/query-anonymity/pii-rewrite.js";
import { SMART_REWRITE_AUDIT_OPS } from "../../src/query-anonymity/smart-rewriter.js";
import { ReverseMappingStore } from "../../src/query-anonymity/reverse-mapping-store.js";
import { PiiConfigStore } from "../../src/query-anonymity/pii-config-store.js";

const IDENTITY = "rho25-operator";
const FORTRESS = "rho25-fortress";
const PII_QUERY = "email Erik Newton at erik@example.com about the rent";

function selectorResponse(
  body: SubstrateResponse["body"],
): SubstrateResponse {
  return {
    servedBy: "local",
    failureClass: null,
    body,
    completedAt: new Date().toISOString(),
    latencyMs: 1,
  };
}

function makeSelector(opts: { summarizeText?: string } = {}) {
  const calls: Array<{ method: string; surface: string; req: unknown }> = [];
  const handle: SubstrateHandle = {
    surface: "concierge",
    substrate: "local",
    badge: {
      surface: "concierge",
      substrate: "local",
      labelKey: "test",
      tradeoffKey: "test",
      status: "green",
    },
    capability: { summarize: true, classify: true, redact: true },
    displayLabel: "Test Local",
  };
  const selector = {
    getSubstrate: vi.fn().mockResolvedValue(handle),
    invokeClassify: vi.fn(async (surface: string, req: ClassifyRequest) => {
      calls.push({ method: "classify", surface, req });
      return selectorResponse({
        kind: "classify",
        results: [{ category: "generic", confidence: 0.9 }],
      });
    }),
    invokeRedact: vi.fn(async (surface: string, req: RedactRequest) => {
      calls.push({ method: "redact", surface, req });
      return selectorResponse({
        kind: "redact",
        redacted: req.text,
        placeholders: {},
      });
    }),
    invokeSummarize: vi.fn(async (surface: string, req: SummarizeRequest) => {
      calls.push({ method: "summarize", surface, req });
      return selectorResponse({
        kind: "summarize",
        text: opts.summarizeText ?? "reply",
      });
    }),
  } as unknown as SubstrateSelector;
  return { selector, calls };
}

function makeStubStore(): OperatorChatStore {
  return {
    appendMessage: vi.fn().mockImplementation((_surface, _thread, message) => ({
      messages: [message],
    })),
    loadThread: vi.fn().mockResolvedValue(null),
  } as unknown as OperatorChatStore;
}

function emptyProviders() {
  return {
    recentActivity: async () => "",
    agentInventory: async () => "",
    openInbox: async () => "",
  };
}

interface HarnessOptions {
  patch?: Parameters<PiiConfigStore["patch"]>[0];
  withReverseStore?: boolean;
  summarizeText?: string;
}

async function makeHarness(opts: HarnessOptions = {}) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const config = new PiiConfigStore({ storage, masterKey, fortressId: FORTRESS });
  if (opts.patch) await config.patch(opts.patch);
  const { selector, calls } = makeSelector({ summarizeText: opts.summarizeText });
  const service = new OperatorChatService({
    store: makeStubStore(),
    auditLog,
    identityId: IDENTITY,
    substrateSelector: selector,
    conciergeContextProviders: emptyProviders(),
    queryAnonymityConfig: config,
    queryAnonymityFortressId: FORTRESS,
    ...(opts.withReverseStore === false
      ? {}
      : {
          queryAnonymityReverseMappingStore: new ReverseMappingStore({
            fortressPath: join(tmpdir(), `rho25-${Math.random()}`),
            masterKey: Buffer.from(masterKey),
            storage,
          }),
        }),
  });
  return { service, config, auditLog, calls };
}

async function auditedOps(auditLog: AuditLog) {
  await auditLog.flush();
  return (await auditLog.query({ layer: "l2", limit: 200 })).entries;
}

describe("Rho-2.5 gate evaluation (PiiConfigStore.evaluateForQuery)", () => {
  it("derives gates from one read and stays in parity with the should* helpers", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const config = new PiiConfigStore({ storage, masterKey, fortressId: FORTRESS });

    // Untouched fortress: everything off.
    expect(await config.evaluateForQuery()).toEqual({
      rewrite: false,
      smart: false,
      consented: false,
    });
    expect(await config.shouldRewrite()).toBe(false);
    expect(await config.shouldRewriteSmartMode()).toBe(false);

    // Basic Tier B on.
    await config.patch({ consented_to_trade_off: true, enabled: true });
    expect(await config.evaluateForQuery()).toEqual({
      rewrite: true,
      smart: false,
      consented: true,
    });
    expect(await config.shouldRewrite()).toBe(true);
    expect(await config.shouldRewriteSmartMode()).toBe(false);

    // Smart mode implies the rewrite gate.
    await config.patch({ enabled: false, smart_mode_enabled: true });
    expect(await config.evaluateForQuery()).toEqual({
      rewrite: true,
      smart: true,
      consented: true,
    });
    expect(await config.shouldRewrite()).toBe(true);
    expect(await config.shouldRewriteSmartMode()).toBe(true);
  });
});

describe("Rho-2.5 disabled path (the default)", () => {
  it("leaves the substrate query byte-identical and fires no pii_rewritten audit", async () => {
    const { service, auditLog, calls } = await makeHarness();
    await service.sendConcierge(PII_QUERY);
    const summarize = calls.find((c) => c.method === "summarize");
    expect((summarize?.req as SummarizeRequest).query).toBe(PII_QUERY);
    // No redact / classify round-trips fire either: byte-identical means
    // the selector sees exactly the calls it saw before Tier B existed.
    expect(calls.map((c) => c.method)).toEqual(["summarize"]);
    const ops = (await auditedOps(auditLog)).map((e) => e.operation);
    expect(ops).not.toContain(PII_REWRITE_AUDIT_OPS.PII_REWRITTEN);
  });

  it("does not rewrite when enabled was persisted without consent (defense in depth)", async () => {
    const { service, config, auditLog, calls } = await makeHarness();
    // Bypass the patch() consent gate deliberately (simulates a tampered
    // or hand-written config). The live gate must fail toward NO rewrite
    // and NO protection claim.
    await config.set({
      enabled: true,
      smart_mode_enabled: false,
      consented_to_trade_off: false,
      updated_at: new Date().toISOString(),
    });
    await service.sendConcierge(PII_QUERY);
    const summarize = calls.find((c) => c.method === "summarize");
    expect((summarize?.req as SummarizeRequest).query).toBe(PII_QUERY);
    const ops = (await auditedOps(auditLog)).map((e) => e.operation);
    expect(ops).not.toContain(PII_REWRITE_AUDIT_OPS.PII_REWRITTEN);
  });
});

describe("Rho-2.5 basic Tier B live path", () => {
  it("never sends the original PII text to the substrate selector", async () => {
    const { service, calls } = await makeHarness({
      patch: { consented_to_trade_off: true, enabled: true },
    });
    await service.sendConcierge(PII_QUERY);
    expect(calls.length).toBeGreaterThan(0);
    for (const call of calls) {
      const serialized = JSON.stringify(call.req);
      expect(serialized).not.toContain("erik@example.com");
      expect(serialized).not.toContain("Erik Newton");
    }
    const summarize = calls.find((c) => c.method === "summarize");
    const query = (summarize?.req as SummarizeRequest).query;
    expect(query).toContain("[EMAIL_0]");
    expect(query).toContain("[NAME_0]");
    expect(query).toContain("about the rent");
  });

  it("fires query_anonymity_pii_rewritten with counts and the consent snapshot", async () => {
    const { service, auditLog } = await makeHarness({
      patch: { consented_to_trade_off: true, enabled: true },
    });
    await service.sendConcierge(PII_QUERY);
    const entries = await auditedOps(auditLog);
    const rewritten = entries.find(
      (e) => e.operation === PII_REWRITE_AUDIT_OPS.PII_REWRITTEN,
    );
    expect(rewritten).toBeDefined();
    const details = rewritten!.details as {
      fortress_id: string;
      redaction_counts: RedactionCounts;
      llm_assist_ran: boolean;
      consented_to_trade_off: boolean;
    };
    expect(details.fortress_id).toBe(FORTRESS);
    expect(details.redaction_counts.email).toBe(1);
    expect(details.redaction_counts.name).toBe(1);
    expect(details.consented_to_trade_off).toBe(true);
  });
});

describe("Rho-2.5 smart-mode live path", () => {
  it("fires query_anonymity_pii_rewritten alongside the smart-mode audit ops", async () => {
    const { service, auditLog, calls } = await makeHarness({
      patch: { consented_to_trade_off: true, smart_mode_enabled: true },
    });
    await service.sendConcierge(PII_QUERY);
    const summarize = calls.find((c) => c.method === "summarize");
    expect((summarize?.req as SummarizeRequest).query).not.toContain(
      "erik@example.com",
    );
    const ops = (await auditedOps(auditLog)).map((e) => e.operation);
    expect(ops).toContain(PII_REWRITE_AUDIT_OPS.PII_REWRITTEN);
    expect(ops).toContain(SMART_REWRITE_AUDIT_OPS.SMART_REWRITE_APPLIED);
  });

  it("falls back to basic anonymize-all when no reverse-mapping store is bound", async () => {
    const { service, auditLog, calls } = await makeHarness({
      patch: { consented_to_trade_off: true, smart_mode_enabled: true },
      withReverseStore: false,
    });
    await service.sendConcierge(PII_QUERY);
    // The basic path runs: no intent classification, but the substrate
    // query is still fully anonymized and the rewrite audit still fires.
    expect(calls.some((c) => c.method === "classify")).toBe(false);
    const summarize = calls.find((c) => c.method === "summarize");
    const query = (summarize?.req as SummarizeRequest).query;
    expect(query).not.toContain("erik@example.com");
    expect(query).not.toContain("Erik Newton");
    const ops = (await auditedOps(auditLog)).map((e) => e.operation);
    expect(ops).toContain(PII_REWRITE_AUDIT_OPS.PII_REWRITTEN);
    expect(ops).not.toContain(SMART_REWRITE_AUDIT_OPS.SMART_REWRITE_APPLIED);
  });
});
