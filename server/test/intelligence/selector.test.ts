/**
 * SubstrateSelector — Behavioral Tests
 *
 * Verifies the selector's core invariants:
 *   - load() emits config_loaded audit event with correct was_default
 *   - setPerSurfaceChoice persists + audit-emits substrate_chosen with the
 *     tradeoff text hash + prior substrate
 *   - getSubstrate returns the correct handle for each substrate choice
 *     including the disabled / missing-key fallbacks
 *   - invokeSummarize / invokeClassify / invokeRedact emit substrate_invoked
 *     and (on failure) substrate_failure with the right details
 *   - audit details payloads match the v1.2 contract shapes
 *   - hardware probe returns the right shape and reflects stubbed Ollama
 *   - frontier substrate refuses construction without an API key for any
 *     provider (returns disabled handle)
 *   - resetToDefaults clears bindings + emits config_reset
 *   - identity-redactor default leaves text unchanged
 */

import { describe, it, expect, vi } from "vitest";
import { SubstrateSelector, IDENTITY_REDACTOR } from "../../src/intelligence/selector.js";
import { INTEL_OPS } from "../../src/intelligence/audit-events.js";
import { tradeoffTextHash } from "../../src/intelligence/templates.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import type { Surface } from "../../src/intelligence/types.js";

function makeFetchStub(responses: Record<string, { status: number; body: unknown }>): typeof fetch {
  return (async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    for (const [pattern, resp] of Object.entries(responses)) {
      if (url.includes(pattern)) {
        return new Response(JSON.stringify(resp.body), {
          status: resp.status,
          headers: { "Content-Type": "application/json" },
        });
      }
    }
    return new Response("", { status: 404 });
  }) as typeof fetch;
}

function buildSelector(opts: { fetchImpl?: typeof fetch; redactor?: typeof IDENTITY_REDACTOR } = {}) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const selector = new SubstrateSelector({
    storage,
    masterKey,
    auditLog,
    identityId: "test-identity",
    fetchImpl: opts.fetchImpl,
    redactor: opts.redactor,
  });
  return { storage, masterKey, auditLog, selector };
}

describe("SubstrateSelector — load / config", () => {
  it("load() emits config_loaded with was_default=true on first load", async () => {
    const { selector, auditLog } = buildSelector();
    await selector.load();
    const events = await auditLog.query({ operation_type: INTEL_OPS.CONFIG_LOADED });
    expect(events.entries.length).toBe(1);
    expect(events.entries[0]!.layer).toBe("l2");
    expect(events.entries[0]!.identity_id).toBe("test-identity");
    expect(events.entries[0]!.result).toBe("failure"); // first load = no record found
    const details = events.entries[0]!.details as { kind: string; was_default: boolean; overridden_surface_count: number; version: string };
    expect(details.kind).toBe("config_loaded");
    expect(details.was_default).toBe(true);
    expect(details.overridden_surface_count).toBe(0);
    expect(details.version).toBe("1.2");
  });

  it("load() emits was_default=false after a config has been persisted", async () => {
    const { selector, auditLog, storage, masterKey } = buildSelector();
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");

    // New selector instance against the same storage simulates a reload.
    const reloaded = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: "test-identity",
    });
    await reloaded.load();

    const events = await auditLog.query({ operation_type: INTEL_OPS.CONFIG_LOADED });
    const last = events.entries[events.entries.length - 1]!;
    const details = last.details as { was_default: boolean; overridden_surface_count: number };
    expect(details.was_default).toBe(false);
    expect(details.overridden_surface_count).toBe(1);
  });

  it("getConfig returns defaults if load not called yet", () => {
    const { selector } = buildSelector();
    const cfg = selector.getConfig();
    expect(cfg.version).toBe(1);
    expect(cfg.perSurface.concierge).toBe("local");
  });
});

describe("SubstrateSelector — setPerSurfaceChoice", () => {
  it("persists the change and emits substrate_chosen with prior substrate", async () => {
    const { selector, auditLog } = buildSelector();
    await selector.load();

    await selector.setPerSurfaceChoice("concierge", "venice");

    const events = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_CHOSEN });
    expect(events.entries.length).toBe(1);
    const details = events.entries[0]!.details as {
      kind: string;
      surface: Surface;
      substrate: string;
      tradeoff_text_hash: string;
      was_default: boolean;
      prior_substrate: string;
    };
    expect(details.kind).toBe("substrate_chosen");
    expect(details.surface).toBe("concierge");
    expect(details.substrate).toBe("venice");
    expect(details.prior_substrate).toBe("local");
    expect(details.was_default).toBe(true);
    expect(details.tradeoff_text_hash).toBe(tradeoffTextHash("venice"));
  });

  it("preserves perSurface bindings across multiple changes", async () => {
    const { selector } = buildSelector();
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setPerSurfaceChoice("sentinel-scoring", "frontier-with-filter");

    expect(selector.getConfig().perSurface.concierge).toBe("venice");
    expect(selector.getConfig().perSurface["sentinel-scoring"]).toBe("frontier-with-filter");
  });

  it("subsequent change records was_default=false", async () => {
    const { selector, auditLog } = buildSelector();
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setPerSurfaceChoice("concierge", "frontier-with-filter");

    const events = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_CHOSEN });
    expect(events.entries.length).toBe(2);
    const second = events.entries[1]!.details as { was_default: boolean; prior_substrate: string };
    expect(second.was_default).toBe(false);
    expect(second.prior_substrate).toBe("venice");
  });
});

describe("SubstrateSelector — getSubstrate handle shape", () => {
  it("local choice yields a handle with full capability", async () => {
    const { selector } = buildSelector();
    await selector.load();
    const handle = await selector.getSubstrate("concierge");
    expect(handle.substrate).toBe("local");
    expect(handle.capability.summarize).toBe(true);
    expect(handle.capability.classify).toBe(true);
    expect(handle.capability.redact).toBe(true);
    expect(typeof handle.summarize).toBe("function");
    expect(handle.displayLabel).toContain("Local model");
    expect(handle.displayLabel).toContain("Gemma");
  });

  it("disabled choice yields a handle with zero capability and no methods", async () => {
    const { selector } = buildSelector();
    await selector.load();
    // gate-explanation defaults to disabled per Erik ratification.
    const handle = await selector.getSubstrate("gate-explanation");
    expect(handle.substrate).toBe("disabled");
    expect(handle.capability.summarize).toBe(false);
    expect(handle.summarize).toBeUndefined();
    expect(handle.classify).toBeUndefined();
    expect(handle.redact).toBeUndefined();
    expect(handle.badge.status).toBe("red");
  });

  it("venice choice without API key falls back to disabled handle", async () => {
    const { selector } = buildSelector();
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    const handle = await selector.getSubstrate("concierge");
    expect(handle.substrate).toBe("disabled");
  });

  it("venice choice with API key yields a venice handle", async () => {
    const { selector } = buildSelector();
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("test-venice-key");
    const handle = await selector.getSubstrate("concierge");
    expect(handle.substrate).toBe("venice");
    expect(handle.displayLabel).toContain("Venice");
  });

  it("frontier-with-filter choice without any provider key falls back to disabled", async () => {
    const { selector } = buildSelector();
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "frontier-with-filter");
    const handle = await selector.getSubstrate("concierge");
    expect(handle.substrate).toBe("disabled");
  });

  it("frontier-with-filter with anthropic key yields anthropic-bound handle", async () => {
    const { selector } = buildSelector();
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "frontier-with-filter");
    await selector.setFrontierApiKey("anthropic", "test-anthropic-key");
    const handle = await selector.getSubstrate("concierge");
    expect(handle.substrate).toBe("frontier-with-filter");
    expect(handle.displayLabel).toContain("anthropic");
  });

  it("hybrid choice without rules falls back to disabled", async () => {
    const { selector } = buildSelector();
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "hybrid");
    const handle = await selector.getSubstrate("concierge");
    expect(handle.substrate).toBe("disabled");
  });
});

describe("SubstrateSelector — invoke + audit emission", () => {
  it("invokeSummarize on disabled surface emits substrate_invoked with failure", async () => {
    const { selector, auditLog } = buildSelector();
    await selector.load();
    // gate-explanation is default-disabled.
    const resp = await selector.invokeSummarize("gate-explanation", {
      kind: "summarize",
      context: "test context",
      query: "test query",
    });
    expect(resp.failureClass).toBe("substrate_capability_unsupported");
    expect(resp.body.kind).toBe("failure");

    const invoked = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_INVOKED });
    expect(invoked.entries.length).toBe(0); // disabled short-circuits before invoke event
    const failures = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_FAILURE });
    expect(failures.entries.length).toBe(1);
  });

  it("invokeSummarize on local surface with reachable Ollama emits substrate_invoked success", async () => {
    const fetchImpl = makeFetchStub({
      "/api/generate": { status: 200, body: { response: "agent X read 3 files today" } },
    });
    const { selector, auditLog } = buildSelector({ fetchImpl });
    await selector.load();

    const resp = await selector.invokeSummarize("concierge", {
      kind: "summarize",
      context: "audit log tail",
      query: "what did agent X do today",
    });
    expect(resp.failureClass).toBeNull();
    expect(resp.body.kind).toBe("summarize");

    const events = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_INVOKED });
    expect(events.entries.length).toBe(1);
    const details = events.entries[0]!.details as {
      kind: string;
      surface: Surface;
      substrate: string;
      served_by: string;
      request_hash: string;
      response_hash: string | null;
      latency_ms: number;
      failure_class: string | null;
    };
    expect(details.kind).toBe("substrate_invoked");
    expect(details.surface).toBe("concierge");
    expect(details.substrate).toBe("local");
    expect(details.served_by).toBe("local");
    // SHA-256 hash encoded as base64url (no padding) is exactly 43 chars
    // from the [A-Za-z0-9_-] alphabet.
    expect(details.request_hash).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(details.response_hash).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(details.latency_ms).toBeGreaterThanOrEqual(0);
    expect(details.failure_class).toBeNull();
  });

  it("invokeSummarize on local surface with unreachable Ollama emits invoked + failure", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("connection refused");
    }) as unknown as typeof fetch;
    const { selector, auditLog } = buildSelector({ fetchImpl });
    await selector.load();

    const resp = await selector.invokeSummarize("concierge", {
      kind: "summarize",
      context: "ctx",
      query: "q",
    });
    expect(resp.failureClass).toBe("substrate_unavailable");

    const invoked = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_INVOKED });
    expect(invoked.entries.length).toBe(1);
    expect(invoked.entries[0]!.result).toBe("failure");

    const failures = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_FAILURE });
    expect(failures.entries.length).toBe(1);
    const fdetails = failures.entries[0]!.details as { fallback_taken: string };
    // concierge default fallback is degrade-silent which maps to next-substrate
    expect(fdetails.fallback_taken).toBe("next-substrate");
  });

  it("sentinel-scoring failure maps to deny fallback per default", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("connection refused");
    }) as unknown as typeof fetch;
    const { selector, auditLog } = buildSelector({ fetchImpl });
    await selector.load();

    await selector.invokeSummarize("sentinel-scoring", {
      kind: "summarize",
      context: "ctx",
      query: "q",
    });

    const failures = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_FAILURE });
    const fdetails = failures.entries[failures.entries.length - 1]!.details as { fallback_taken: string };
    expect(fdetails.fallback_taken).toBe("deny");
  });
});

describe("SubstrateSelector — resetToDefaults", () => {
  it("emits config_reset with the prior overridden_surface_count", async () => {
    const { selector, auditLog } = buildSelector();
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setPerSurfaceChoice("sentinel-scoring", "frontier-with-filter");

    await selector.resetToDefaults();

    const events = await auditLog.query({ operation_type: INTEL_OPS.CONFIG_RESET });
    expect(events.entries.length).toBe(1);
    const details = events.entries[0]!.details as { overridden_surface_count: number };
    expect(details.overridden_surface_count).toBe(2);

    expect(selector.getConfig().perSurface.concierge).toBe("local");
    expect(selector.getConfig().perSurface["sentinel-scoring"]).toBe("local");
  });
});

describe("SubstrateSelector — operator-visible status report", () => {
  it("returns shape with version 1.2 and one row per surface", async () => {
    const fetchImpl = makeFetchStub({
      "/api/tags": { status: 200, body: { models: [{ name: "gemma2:2b" }] } },
    });
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();

    const report = await selector.getOperatorVisibleStatus();
    expect(report.version).toBe("1.2");
    expect(report.surfaces.length).toBe(6);
    expect(report.hardware.totalRamGb).toBeGreaterThan(0);
    expect(report.hardware.tier).toMatch(/below-baseline|baseline|mid|pro/);
    expect(report.hardware.ollamaReachable).toBe(true);
    expect(report.hardware.ollamaModels).toContain("gemma2:2b");
  });

  it("local concierge with reachable Ollama + correct model is green", async () => {
    const fetchImpl = makeFetchStub({
      "/api/tags": { status: 200, body: { models: [{ name: "gemma2:2b" }, { name: "phi4-mini" }] } },
    });
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();

    const report = await selector.getOperatorVisibleStatus();
    const concierge = report.surfaces.find((s) => s.surface === "concierge");
    expect(concierge?.health).toBe("ok");
    expect(concierge?.failureClass).toBeNull();
  });

  it("local concierge with reachable Ollama but model missing is degraded", async () => {
    const fetchImpl = makeFetchStub({
      "/api/tags": { status: 200, body: { models: [{ name: "phi4-mini" }] } },
    });
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();

    const report = await selector.getOperatorVisibleStatus();
    const concierge = report.surfaces.find((s) => s.surface === "concierge");
    expect(concierge?.health).toBe("degraded");
    expect(concierge?.failureClass).toBe("substrate_misconfigured");
  });

  it("local concierge with unreachable Ollama is unavailable", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof fetch;
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();

    const report = await selector.getOperatorVisibleStatus();
    const concierge = report.surfaces.find((s) => s.surface === "concierge");
    expect(concierge?.health).toBe("unavailable");
    expect(concierge?.failureClass).toBe("substrate_unavailable");
  });

  it("disabled gate-explanation reports unavailable + substrate_disabled", async () => {
    const fetchImpl = makeFetchStub({
      "/api/tags": { status: 200, body: { models: [] } },
    });
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();

    const report = await selector.getOperatorVisibleStatus();
    const gate = report.surfaces.find((s) => s.surface === "gate-explanation");
    expect(gate?.health).toBe("unavailable");
    expect(gate?.failureClass).toBe("substrate_disabled");
  });
});

describe("SubstrateSelector — IDENTITY_REDACTOR default", () => {
  it("returns the input unchanged with zero match count", async () => {
    const out = await IDENTITY_REDACTOR("hello world");
    expect(out.redacted).toBe("hello world");
    expect(out.matchCount).toBe(0);
  });
});

describe("SubstrateSelector — emitRedactionEvent", () => {
  it("emits pii_redaction_event with the right shape", async () => {
    const { selector, auditLog } = buildSelector();
    await selector.load();
    selector.emitRedactionEvent({
      surface: "concierge",
      substrate: "frontier-with-filter",
      matchCount: 3,
      filterTier: 2,
    });

    const events = await auditLog.query({ operation_type: INTEL_OPS.PII_REDACTION_EVENT });
    expect(events.entries.length).toBe(1);
    const details = events.entries[0]!.details as {
      kind: string;
      surface: string;
      substrate: string;
      match_count: number;
      filter_tier: number;
    };
    expect(details.kind).toBe("pii_redaction_event");
    expect(details.match_count).toBe(3);
    expect(details.filter_tier).toBe(2);
  });
});
