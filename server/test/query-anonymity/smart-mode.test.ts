/**
 * Rho-3 Tier B smart-mode query anonymity regression suite.
 *
 * Castle-walking: the classifier uses substrate-selector classify on
 * the existing privacy-filter-tier-2 surface; reverse mappings are
 * encrypted server-local state; placeholder restoration happens in the
 * concierge service before operator display.
 */

import { describe, expect, it, vi } from "vitest";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { bytesToString } from "../../src/core/encoding.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { AuditLog as AuditLogType } from "../../src/l2-operational/audit-log.js";
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
  QUERY_INTENT_CLASSIFIER_SURFACE,
  classifyQueryIntent,
  type QueryIntent,
} from "../../src/query-anonymity/intent-classifier.js";
import {
  SMART_REWRITE_AUDIT_OPS,
  restoreReverseMappings,
  smartRewrite,
} from "../../src/query-anonymity/smart-rewriter.js";
import {
  REVERSE_MAPPING_NAMESPACE,
  ReverseMappingStore,
} from "../../src/query-anonymity/reverse-mapping-store.js";
import { PiiConfigStore } from "../../src/query-anonymity/pii-config-store.js";

const IDENTITY = "rho3-operator";
const FORTRESS = "rho3-fortress";

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

function makeSelector(opts: {
  classifyCategory?: string;
  classifyConfidence?: number;
  summarizeText?: string;
  throwClassify?: boolean;
}) {
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
      if (opts.throwClassify) throw new Error("classifier down");
      return selectorResponse({
        kind: "classify",
        results: [
          {
            category: opts.classifyCategory ?? "generic",
            confidence: opts.classifyConfidence ?? 0.92,
          },
        ],
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

function fixedClassifier(intent: QueryIntent) {
  return { classify: vi.fn().mockResolvedValue(intent) };
}

describe("Rho-3 intent classifier", () => {
  it("routes through substrate-selector privacy-filter-tier-2", async () => {
    const { selector, calls } = makeSelector({
      classifyCategory: "location_grounded",
      classifyConfidence: 0.91,
    });
    const intent = await classifyQueryIntent(
      "show me restaurants in Seattle",
      selector,
    );
    expect(calls[0]?.surface).toBe(QUERY_INTENT_CLASSIFIER_SURFACE);
    expect(intent.intent_category).toBe("location_grounded");
    expect(intent.preserve_pii_classes).toEqual(["street_address"]);
  });

  it("classifies identity-grounded queries and preserves identity classes", async () => {
    const { selector } = makeSelector({
      classifyCategory: "identity_grounded",
      classifyConfidence: 0.88,
    });
    const intent = await classifyQueryIntent("who is Erik Newton", selector);
    expect(intent.preserve_pii_classes).toContain("name");
  });

  it("classifies temporal-grounded queries without preserving PII", async () => {
    const { selector } = makeSelector({
      classifyCategory: "temporal_grounded",
      classifyConfidence: 0.82,
    });
    const intent = await classifyQueryIntent("what happened on 2026-05-10", selector);
    expect(intent.intent_category).toBe("temporal_grounded");
    expect(intent.preserve_pii_classes).toEqual([]);
  });

  it("classifies generic queries with an empty preservation set", async () => {
    const { selector } = makeSelector({
      classifyCategory: "generic",
      classifyConfidence: 0.75,
    });
    const intent = await classifyQueryIntent("summarize this workflow", selector);
    expect(intent.intent_category).toBe("generic");
    expect(intent.preserve_pii_classes).toEqual([]);
  });
});

describe("Rho-3 smart rewrite", () => {
  it("location-grounded mode keeps Seattle but anonymizes Erik Newton", async () => {
    const { selector } = makeSelector({});
    const classifier = fixedClassifier({
      intent_category: "location_grounded",
      preserve_pii_classes: ["street_address"],
      confidence: 0.93,
      reasoning: "location",
    });
    const result = await smartRewrite(
      "what restaurants are near Erik Newton in Seattle?",
      { selector, classifier },
    );
    expect(result.rewritten_query).toContain("Seattle");
    expect(result.rewritten_query).not.toContain("Erik Newton");
    expect(result.reverse_map[0]?.original).toBe("Erik Newton");
  });

  it("identity-grounded mode preserves the name class", async () => {
    const { selector } = makeSelector({});
    const classifier = fixedClassifier({
      intent_category: "identity_grounded",
      preserve_pii_classes: ["name"],
      confidence: 0.9,
      reasoning: "identity",
    });
    const result = await smartRewrite("who is Erik Newton?", {
      selector,
      classifier,
    });
    expect(result.rewritten_query).toContain("Erik Newton");
    expect(result.reverse_map).toEqual([]);
  });

  it("generic mode anonymizes detected PII", async () => {
    const { selector } = makeSelector({});
    const classifier = fixedClassifier({
      intent_category: "generic",
      preserve_pii_classes: [],
      confidence: 0.8,
      reasoning: "generic",
    });
    const result = await smartRewrite("email Erik Newton at erik@example.com", {
      selector,
      classifier,
    });
    expect(result.rewritten_query).not.toContain("erik@example.com");
    expect(result.anonymized_classes).toContain("email");
  });

  it("low confidence falls back to anonymize-all basic Tier B behavior", async () => {
    const { selector } = makeSelector({});
    const classifier = fixedClassifier({
      intent_category: "identity_grounded",
      preserve_pii_classes: ["name"],
      confidence: 0.42,
      reasoning: "weak",
    });
    const result = await smartRewrite("who is Erik Newton?", {
      selector,
      classifier,
    });
    expect(result.intent.intent_category).toBe("generic");
    expect(result.rewritten_query).not.toContain("Erik Newton");
  });

  it("classifier failure falls back to anonymize-all basic Tier B behavior", async () => {
    const { selector } = makeSelector({});
    const classifier = { classify: vi.fn().mockRejectedValue(new Error("down")) };
    const result = await smartRewrite("who is Erik Newton?", {
      selector,
      classifier,
    });
    expect(result.intent.confidence).toBe(0);
    expect(result.rewritten_query).not.toContain("Erik Newton");
  });
});

describe("Rho-3 reverse mapping store", () => {
  it("round-trips encrypted reverse mappings", async () => {
    const storage = new MemoryStorage();
    const store = new ReverseMappingStore({
      fortressPath: join(tmpdir(), "rho3-a"),
      masterKey: Buffer.from(generateRandomKey()),
      storage,
    });
    await store.store("query-1", [
      {
        placeholder: "[NAME_0]",
        original: "Erik Newton",
        pii_class: "name",
        observed_at: new Date().toISOString(),
      },
    ]);
    expect(await store.get("query-1")).toMatchObject([
      { placeholder: "[NAME_0]", original: "Erik Newton" },
    ]);
    const raw = await storage.read(REVERSE_MAPPING_NAMESPACE, "query.query-1");
    expect(bytesToString(raw!)).not.toContain("Erik Newton");
  });

  it("AAD binding rejects cross-query tampering", async () => {
    const storage = new MemoryStorage();
    const masterKey = Buffer.from(generateRandomKey());
    const store = new ReverseMappingStore({
      fortressPath: join(tmpdir(), "rho3-aad"),
      masterKey,
      storage,
    });
    await store.store("query-1", [
      {
        placeholder: "[NAME_0]",
        original: "Erik Newton",
        pii_class: "name",
        observed_at: new Date().toISOString(),
      },
    ]);
    const raw = await storage.read(REVERSE_MAPPING_NAMESPACE, "query.query-1");
    await storage.write(REVERSE_MAPPING_NAMESPACE, "query.query-2", raw!);
    expect(await store.get("query-2")).toBeNull();
  });

  it("prunes expired query records", async () => {
    const storage = new MemoryStorage();
    const store = new ReverseMappingStore({
      fortressPath: join(tmpdir(), "rho3-prune"),
      masterKey: Buffer.from(generateRandomKey()),
      storage,
      retentionDays: 1,
    });
    await store.store("query-1", []);
    const result = await store.pruneExpired(new Date(Date.now() + 2 * 24 * 60 * 60 * 1000));
    expect(result.pruned).toBe(1);
  });
});

describe("Rho-3 concierge render-time mapping", () => {
  it("replaces placeholders with originals server-side", () => {
    const result = restoreReverseMappings(
      "restaurants near [NAME_0] in Seattle include...",
      [
        {
          placeholder: "[NAME_0]",
          original: "Erik Newton",
          pii_class: "name",
          observed_at: new Date().toISOString(),
        },
      ],
    );
    expect(result.text).toContain("Erik Newton");
    expect(result.replacements).toBe(1);
  });

  it("smart-mode disabled leaves concierge substrate query unchanged", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const config = new PiiConfigStore({ storage, masterKey, fortressId: FORTRESS });
    await config.patch({ consented_to_trade_off: true, smart_mode_enabled: false });
    const reverse = new ReverseMappingStore({
      fortressPath: join(tmpdir(), "rho3-service-off"),
      masterKey: Buffer.from(masterKey),
      storage,
    });
    const { selector, calls } = makeSelector({ summarizeText: "ok" });
    const service = new OperatorChatService({
      store: makeStubStore(),
      auditLog,
      identityId: IDENTITY,
      substrateSelector: selector,
      conciergeContextProviders: emptyProviders(),
      queryAnonymityConfig: config,
      queryAnonymityReverseMappingStore: reverse,
      queryAnonymityFortressId: FORTRESS,
    });
    await service.sendConcierge("who is Erik Newton?");
    const summarize = calls.find((c) => c.method === "summarize");
    expect((summarize?.req as SummarizeRequest).query).toBe("who is Erik Newton?");
  });

  it("smart mode implies Tier B and restores operator display text", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const config = new PiiConfigStore({ storage, masterKey, fortressId: FORTRESS });
    await config.patch({ consented_to_trade_off: true, smart_mode_enabled: true });
    const reverse = new ReverseMappingStore({
      fortressPath: join(tmpdir(), "rho3-service-on"),
      masterKey: Buffer.from(masterKey),
      storage,
    });
    const { selector, calls } = makeSelector({
      summarizeText: "restaurants near [NAME_0] in Seattle include...",
    });
    const service = new OperatorChatService({
      store: makeStubStore(),
      auditLog,
      identityId: IDENTITY,
      substrateSelector: selector,
      conciergeContextProviders: emptyProviders(),
      queryAnonymityConfig: config,
      queryAnonymityReverseMappingStore: reverse,
      queryAnonymityFortressId: FORTRESS,
      queryAnonymityIntentClassifier: fixedClassifier({
        intent_category: "location_grounded",
        preserve_pii_classes: ["street_address"],
        confidence: 0.95,
        reasoning: "location",
      }),
    });
    const response = await service.sendConcierge(
      "what restaurants are near Erik Newton in Seattle?",
    );
    const summarize = calls.find((c) => c.method === "summarize");
    expect((summarize?.req as SummarizeRequest).query).not.toContain("Erik Newton");
    expect(response.message.body).toContain("Erik Newton");
    expect(await config.shouldRewrite()).toBe(true);
  });

  it("store read failure leaves placeholders with an inline notice", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const config = new PiiConfigStore({ storage, masterKey, fortressId: FORTRESS });
    await config.patch({ consented_to_trade_off: true, smart_mode_enabled: true });
    const reverse = {
      store: vi.fn().mockResolvedValue(undefined),
      get: vi.fn().mockRejectedValue(new Error("read failed")),
      pruneExpired: vi.fn(),
    } as unknown as ReverseMappingStore;
    const { selector } = makeSelector({
      summarizeText: "restaurants near [NAME_0] in Seattle include...",
    });
    const service = new OperatorChatService({
      store: makeStubStore(),
      auditLog,
      identityId: IDENTITY,
      substrateSelector: selector,
      conciergeContextProviders: emptyProviders(),
      queryAnonymityConfig: config,
      queryAnonymityReverseMappingStore: reverse,
      queryAnonymityFortressId: FORTRESS,
      queryAnonymityIntentClassifier: fixedClassifier({
        intent_category: "location_grounded",
        preserve_pii_classes: ["street_address"],
        confidence: 0.95,
        reasoning: "location",
      }),
    });
    const response = await service.sendConcierge(
      "what restaurants are near Erik Newton in Seattle?",
    );
    expect(response.message.body).toContain("[NAME_0]");
    expect(response.message.body).toContain("reverse mapping unavailable");
  });
});

describe("Rho-3 audit events", () => {
  it("emits smart rewrite and reverse mapping audit events", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const config = new PiiConfigStore({ storage, masterKey, fortressId: FORTRESS });
    await config.patch({ consented_to_trade_off: true, smart_mode_enabled: true });
    const reverse = new ReverseMappingStore({
      fortressPath: join(tmpdir(), "rho3-audit"),
      masterKey: Buffer.from(masterKey),
      storage,
    });
    const { selector } = makeSelector({ summarizeText: "near [NAME_0]" });
    const service = new OperatorChatService({
      store: makeStubStore(),
      auditLog,
      identityId: IDENTITY,
      substrateSelector: selector,
      conciergeContextProviders: emptyProviders(),
      queryAnonymityConfig: config,
      queryAnonymityReverseMappingStore: reverse,
      queryAnonymityFortressId: FORTRESS,
      queryAnonymityIntentClassifier: fixedClassifier({
        intent_category: "location_grounded",
        preserve_pii_classes: ["street_address"],
        confidence: 0.95,
        reasoning: "location",
      }),
    });
    await service.sendConcierge("near Erik Newton in Seattle");
    await auditLog.flush();
    const ops = (await auditLog.query({ layer: "l2", limit: 100 })).entries.map(
      (e) => e.operation,
    );
    expect(ops).toContain(SMART_REWRITE_AUDIT_OPS.INTENT_CLASSIFIED);
    expect(ops).toContain(SMART_REWRITE_AUDIT_OPS.SMART_REWRITE_APPLIED);
    expect(ops).toContain(SMART_REWRITE_AUDIT_OPS.REVERSE_MAPPING_USED);
  });

  it("emits smart-mode fallback on low confidence", async () => {
    const calls: Array<{ operation: string; result: string }> = [];
    const auditLog = {
      append: (_layer: string, operation: string, _id: string, _details: Record<string, unknown>, result = "success") => {
        calls.push({ operation, result });
      },
    } as unknown as AuditLogType;
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const config = new PiiConfigStore({ storage, masterKey, fortressId: FORTRESS });
    await config.patch({ consented_to_trade_off: true, smart_mode_enabled: true });
    const reverse = new ReverseMappingStore({
      fortressPath: join(tmpdir(), "rho3-fallback"),
      masterKey: Buffer.from(masterKey),
      storage,
    });
    const { selector } = makeSelector({ summarizeText: "reply" });
    const service = new OperatorChatService({
      store: makeStubStore(),
      auditLog,
      identityId: IDENTITY,
      substrateSelector: selector,
      conciergeContextProviders: emptyProviders(),
      queryAnonymityConfig: config,
      queryAnonymityReverseMappingStore: reverse,
      queryAnonymityFortressId: FORTRESS,
      queryAnonymityIntentClassifier: fixedClassifier({
        intent_category: "identity_grounded",
        preserve_pii_classes: ["name"],
        confidence: 0.2,
        reasoning: "weak",
      }),
    });
    await service.sendConcierge("who is Erik Newton?");
    expect(calls).toContainEqual({
      operation: SMART_REWRITE_AUDIT_OPS.SMART_MODE_FALLBACK,
      result: "failure",
    });
  });
});

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
