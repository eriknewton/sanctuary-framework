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
import { AuditLog } from "../../src/operational/audit-log.js";
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

  // Finding ZZ (v1.2.0-rc.6): Ollama defaults the tag to `latest` when a
  // model is pulled without an explicit tag. `/api/tags` returns the full
  // `name:tag` form, so the probe must accept `phi4-mini:latest` as the
  // operator-equivalent of `expectedTag = "phi4-mini"`. Without this, the
  // operator-visible badge stays yellow / "Degraded" with `failureClass:
  // substrate_misconfigured` and `recentFailures: []`, even though chat
  // against the same model succeeds.
  it("local probe accepts Ollama-default `:latest` suffix when expectedTag lacks one (Finding ZZ rc.6)", async () => {
    const fetchImpl = makeFetchStub({
      "/api/tags": { status: 200, body: { models: [{ name: "phi4-mini:latest" }] } },
    });
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "local");
    await selector.setLocalModelPick("concierge", "phi-4-mini");

    const report = await selector.getOperatorVisibleStatus();
    const concierge = report.surfaces.find((s) => s.surface === "concierge");
    expect(concierge?.health).toBe("ok");
    expect(concierge?.failureClass).toBeNull();
    expect(concierge?.badge.status).toBe("green");
    expect(concierge?.recentFailures).toHaveLength(0);
  });

  it("local probe still reports misconfigured when expectedTag is genuinely missing (regression guard)", async () => {
    const fetchImpl = makeFetchStub({
      "/api/tags": { status: 200, body: { models: [{ name: "phi4-mini:latest" }] } },
    });
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    // concierge default is gemma-2-2b (LOCAL_MODEL_TAGS = "gemma2:2b").
    // Ollama only has phi4-mini:latest. Genuine misconfiguration must
    // still surface as substrate_misconfigured even after rc.6 leniency.
    const report = await selector.getOperatorVisibleStatus();
    const concierge = report.surfaces.find((s) => s.surface === "concierge");
    expect(concierge?.health).toBe("degraded");
    expect(concierge?.failureClass).toBe("substrate_misconfigured");
  });

  it("local probe with explicit-tag expectedTag (e.g. gemma2:2b) still requires exact match (regression guard)", async () => {
    // expectedTag = "gemma2:2b" already carries a colon, so the rc.6
    // lenient `${expectedTag}:latest` extension MUST NOT fire. Ollama
    // would never return `gemma2:2b:latest`; doubly-tagged forms are
    // not legal Ollama tag strings.
    const fetchImpl = makeFetchStub({
      "/api/tags": { status: 200, body: { models: [{ name: "gemma2:2b:latest" }] } },
    });
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    const report = await selector.getOperatorVisibleStatus();
    const concierge = report.surfaces.find((s) => s.surface === "concierge");
    expect(concierge?.health).toBe("degraded");
    expect(concierge?.failureClass).toBe("substrate_misconfigured");
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

// v1.2.0-rc.1 Finding TT: Venice model drift
describe("VeniceClient.validateKey, Finding TT (v1.2.0-rc.1)", () => {
  it("returns 'invalid-model' when Venice returns 404 with model-not-found body", async () => {
    const { VeniceClient } = await import("../../src/intelligence/substrates/venice.js");
    const fetchImpl = (async () => {
      return new Response(
        JSON.stringify({
          error: "Specified model not found: llama-3.1-70b. Did you mean: llama-3.3-70b, llama-3.2-3b, hermes-3-llama-3.1-405b?",
        }),
        { status: 404, headers: { "Content-Type": "application/json" } },
      );
    }) as typeof fetch;
    const client = new VeniceClient({ apiKey: "test", fetchImpl });
    const result = await client.validateKey();
    expect(result).toBe("invalid-model");
  });

  it("returns 'invalid-key' on 401", async () => {
    const { VeniceClient } = await import("../../src/intelligence/substrates/venice.js");
    const fetchImpl = (async () => new Response("", { status: 401 })) as typeof fetch;
    const client = new VeniceClient({ apiKey: "test", fetchImpl });
    expect(await client.validateKey()).toBe("invalid-key");
  });

  it("returns 'invalid-key' on 403", async () => {
    const { VeniceClient } = await import("../../src/intelligence/substrates/venice.js");
    const fetchImpl = (async () => new Response("", { status: 403 })) as typeof fetch;
    const client = new VeniceClient({ apiKey: "test", fetchImpl });
    expect(await client.validateKey()).toBe("invalid-key");
  });

  it("returns 'ok' on 200", async () => {
    const { VeniceClient } = await import("../../src/intelligence/substrates/venice.js");
    const fetchImpl = (async () =>
      new Response(JSON.stringify({ choices: [] }), { status: 200, headers: { "Content-Type": "application/json" } })
    ) as typeof fetch;
    const client = new VeniceClient({ apiKey: "test", fetchImpl });
    expect(await client.validateKey()).toBe("ok");
  });

  it("returns 'unreachable' on 404 without model-not-found body shape", async () => {
    const { VeniceClient } = await import("../../src/intelligence/substrates/venice.js");
    const fetchImpl = (async () =>
      new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: { "Content-Type": "application/json" } })
    ) as typeof fetch;
    const client = new VeniceClient({ apiKey: "test", fetchImpl });
    expect(await client.validateKey()).toBe("unreachable");
  });

  it("returns 'unreachable' on transport error", async () => {
    const { VeniceClient } = await import("../../src/intelligence/substrates/venice.js");
    const fetchImpl = (async () => {
      throw new Error("ECONNREFUSED");
    }) as typeof fetch;
    const client = new VeniceClient({ apiKey: "test", fetchImpl });
    expect(await client.validateKey()).toBe("unreachable");
  });

  it("VENICE_DEFAULT_MODEL is bumped to llama-3.3-70b", async () => {
    const { VENICE_DEFAULT_MODEL } = await import("../../src/intelligence/substrates/venice.js");
    expect(VENICE_DEFAULT_MODEL).toBe("llama-3.3-70b");
  });
});

// v1.2.0-rc.2 Finding YY: VENICE_DEFAULT_MODEL env-override path
describe("VENICE_DEFAULT_MODEL env override, Finding YY (v1.2.0-rc.2)", () => {
  const ENV_KEY = "VENICE_DEFAULT_MODEL";
  const original = process.env[ENV_KEY];

  function restoreEnv(): void {
    if (original === undefined) {
      delete process.env[ENV_KEY];
    } else {
      process.env[ENV_KEY] = original;
    }
  }

  it("reads VENICE_DEFAULT_MODEL from env when set", async () => {
    vi.resetModules();
    process.env[ENV_KEY] = "operator-pinned-model-v9";
    try {
      const { VENICE_DEFAULT_MODEL } = await import(
        "../../src/intelligence/substrates/venice.js"
      );
      expect(VENICE_DEFAULT_MODEL).toBe("operator-pinned-model-v9");
    } finally {
      restoreEnv();
      vi.resetModules();
    }
  });

  it("falls back to llama-3.3-70b when env is unset", async () => {
    vi.resetModules();
    delete process.env[ENV_KEY];
    try {
      const { VENICE_DEFAULT_MODEL } = await import(
        "../../src/intelligence/substrates/venice.js"
      );
      expect(VENICE_DEFAULT_MODEL).toBe("llama-3.3-70b");
    } finally {
      restoreEnv();
      vi.resetModules();
    }
  });

  it("falls back to llama-3.3-70b when env is empty string", async () => {
    vi.resetModules();
    process.env[ENV_KEY] = "";
    try {
      const { VENICE_DEFAULT_MODEL } = await import(
        "../../src/intelligence/substrates/venice.js"
      );
      expect(VENICE_DEFAULT_MODEL).toBe("llama-3.3-70b");
    } finally {
      restoreEnv();
      vi.resetModules();
    }
  });

  // Acceptance-drill Phase 2.6 path A: operator sets a deliberately bogus
  // model identifier as the trigger for a runtime failure. Without the
  // env-override read, validateKey() ignores the env entirely and reports
  // "ok" against whatever the shipped default is, making the drill a no-op.
  // With the override, the bogus identifier reaches Venice and returns the
  // 404 model-not-found shape, so validateKey reports "invalid-model" and
  // the operator badge surfaces the real cause.
  it("env value of 'this-model-does-not-exist' reaches validateKey and yields invalid-model", async () => {
    vi.resetModules();
    process.env[ENV_KEY] = "this-model-does-not-exist";
    try {
      const { VeniceClient, VENICE_DEFAULT_MODEL } = await import(
        "../../src/intelligence/substrates/venice.js"
      );
      expect(VENICE_DEFAULT_MODEL).toBe("this-model-does-not-exist");

      let capturedBody: string | null = null;
      const fetchImpl = (async (
        _input: RequestInfo | URL,
        init?: RequestInit,
      ): Promise<Response> => {
        capturedBody = init?.body as string;
        return new Response(
          JSON.stringify({
            error:
              "Specified model not found: this-model-does-not-exist. Did you mean: llama-3.3-70b, llama-3.2-3b?",
          }),
          { status: 404, headers: { "Content-Type": "application/json" } },
        );
      }) as typeof fetch;

      const client = new VeniceClient({ apiKey: "test", fetchImpl });
      const result = await client.validateKey();
      expect(result).toBe("invalid-model");
      expect(capturedBody).toContain("this-model-does-not-exist");
    } finally {
      restoreEnv();
      vi.resetModules();
    }
  });
});

describe("VeniceClient.chat, Finding TT runtime classification", () => {
  it("classifies 404 with model-not-found body as substrate_misconfigured", async () => {
    const { VeniceClient, VeniceSubstrate } = await import("../../src/intelligence/substrates/venice.js");
    const fetchImpl = (async () =>
      new Response(
        JSON.stringify({ error: "Specified model not found: llama-3.3-70b. Did you mean: llama-3.4-70b" }),
        { status: 404, headers: { "Content-Type": "application/json" } },
      )
    ) as typeof fetch;
    const client = new VeniceClient({ apiKey: "k", fetchImpl });
    const sub = new VeniceSubstrate(client);
    const resp = await sub.summarize({ kind: "summarize", context: "c", query: "q" });
    expect(resp.failureClass).toBe("substrate_misconfigured");
  });

  it("classifies plain 404 as substrate_unavailable", async () => {
    const { VeniceClient, VeniceSubstrate } = await import("../../src/intelligence/substrates/venice.js");
    const fetchImpl = (async () =>
      new Response(JSON.stringify({ error: "endpoint deprecated" }), { status: 404, headers: { "Content-Type": "application/json" } })
    ) as typeof fetch;
    const client = new VeniceClient({ apiKey: "k", fetchImpl });
    const sub = new VeniceSubstrate(client);
    const resp = await sub.summarize({ kind: "summarize", context: "c", query: "q" });
    expect(resp.failureClass).toBe("substrate_unavailable");
  });
});

// v1.2.0-rc.1 Finding VV: status truth-telling
describe("SubstrateSelector, Finding VV recent failures + badge degrade", () => {
  it("runtime failure on a surface flips badge from green to degraded and surfaces in /status", async () => {
    // Concierge defaults to local Gemma; arrange Ollama to be reachable
    // with the expected model so the static probe says ok, then have
    // /api/generate fail at runtime to trigger the recentFailures path.
    let calls = 0;
    const fetchImpl = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.includes("/api/tags")) {
        return new Response(JSON.stringify({ models: [{ name: "gemma2:2b" }] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (url.includes("/api/generate")) {
        calls++;
        return new Response("", { status: 500 });
      }
      return new Response("", { status: 404 });
    }) as typeof fetch;
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();

    // Pre-runtime status: green for concierge.
    const before = await selector.getOperatorVisibleStatus();
    const beforeConcierge = before.surfaces.find((s) => s.surface === "concierge");
    expect(beforeConcierge?.health).toBe("ok");
    expect(beforeConcierge?.recentFailures).toEqual([]);

    // Trigger one runtime failure.
    await selector.invokeSummarize("concierge", { kind: "summarize", context: "c", query: "q" });
    expect(calls).toBe(1);

    // Post-runtime status: degraded for concierge, recentFailures has one entry.
    const after = await selector.getOperatorVisibleStatus();
    const afterConcierge = after.surfaces.find((s) => s.surface === "concierge");
    expect(afterConcierge?.health).toBe("degraded");
    expect(afterConcierge?.recentFailures.length).toBe(1);
    expect(afterConcierge?.recentFailures[0]!.failureClass).toBeDefined();
    expect(typeof afterConcierge?.recentFailures[0]!.snippet).toBe("string");
    expect(typeof afterConcierge?.recentFailures[0]!.ts).toBe("string");
  });

  it("entries older than the 24h window are pruned on read", async () => {
    const fetchImpl = makeFetchStub({
      "/api/tags": { status: 200, body: { models: [{ name: "gemma2:2b" }] } },
    });
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();

    // Inject a stale recent failure directly via the test seam, then
    // read recentFailures and expect zero (pruned).
    const stale: { surface: import("../../src/intelligence/types.js").Surface; failureClass: import("../../src/intelligence/types.js").SubstrateFailureClass; snippet: string } = {
      surface: "concierge",
      failureClass: "substrate_unavailable",
      snippet: "stale",
    };
    // Force-record a failure, then mutate the entry's timestamp to older
    // than 24h via a new failure followed by a private prune. Instead,
    // assert the public path via a fresh selector seeded with a stale ts.
    // Cleanest: record failure with frozen Date.now then advance time.
    const realNow = Date.now;
    let now = realNow();
    Date.now = () => now;
    try {
      // Simulate runtime failure (fail Ollama) so a real entry lands.
      const failingFetch = (async (input: RequestInfo | URL): Promise<Response> => {
        const url = typeof input === "string" ? input : input.toString();
        if (url.includes("/api/tags")) {
          return new Response(JSON.stringify({ models: [{ name: "gemma2:2b" }] }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        return new Response("", { status: 500 });
      }) as typeof fetch;
      const { selector: sel2 } = buildSelector({ fetchImpl: failingFetch });
      await sel2.load();
      await sel2.invokeSummarize("concierge", { kind: "summarize", context: "c", query: "q" });
      expect(sel2.getRecentFailuresForTest("concierge").length).toBe(1);

      // Advance virtual clock by 25h.
      now += 25 * 60 * 60 * 1000;
      // Pruning happens on read.
      expect(sel2.getRecentFailuresForTest("concierge").length).toBe(0);
    } finally {
      Date.now = realNow;
    }
    void stale;
  });

  it("recentFailures is capped at 5 entries (FIFO eviction)", async () => {
    const failingFetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.includes("/api/tags")) {
        return new Response(JSON.stringify({ models: [{ name: "gemma2:2b" }] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("", { status: 500 });
    }) as typeof fetch;
    const { selector } = buildSelector({ fetchImpl: failingFetch });
    await selector.load();
    for (let i = 0; i < 8; i++) {
      await selector.invokeSummarize("concierge", { kind: "summarize", context: "c", query: `q${i}` });
    }
    expect(selector.getRecentFailuresForTest("concierge").length).toBe(5);
  });

  it("setVeniceApiKey with invalid model flips badge even before any chat call", async () => {
    // Probe the local-tags Ollama call to reachable + correct model so
    // the static probe would normally green-badge, then validate Venice
    // with model-not-found body. Concierge is on 'local' by default; we
    // bind it to Venice so the post-set probe records to that surface.
    const fetchImpl = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.includes("/api/tags")) {
        return new Response(JSON.stringify({ models: [{ name: "gemma2:2b" }] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (url.includes("api.venice.ai")) {
        return new Response(
          JSON.stringify({ error: "Specified model not found: llama-3.3-70b. Did you mean: llama-3.4-70b" }),
          { status: 404, headers: { "Content-Type": "application/json" } },
        );
      }
      return new Response("", { status: 404 });
    }) as typeof fetch;
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("validation-probe-key");

    const status = await selector.getOperatorVisibleStatus();
    const concierge = status.surfaces.find((s) => s.surface === "concierge");
    // Badge degraded: validation-probe entry pushed onto recentFailures.
    expect(concierge?.recentFailures.length).toBeGreaterThan(0);
    const last = concierge?.recentFailures[concierge.recentFailures.length - 1]!;
    expect(last.failureClass).toBe("substrate_misconfigured");
    expect(last.snippet).toMatch(/venice configured model/i);
    // Badge degrade fires from recentFailures even when static probe would have been ok.
    expect(concierge?.health === "degraded" || concierge?.health === "unavailable").toBe(true);
  });

  it("setVeniceApiKey with invalid key (401) flips badge to degraded", async () => {
    const fetchImpl = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.includes("/api/tags")) {
        return new Response(JSON.stringify({ models: [] }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      if (url.includes("api.venice.ai")) {
        return new Response("", { status: 401 });
      }
      return new Response("", { status: 404 });
    }) as typeof fetch;
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("bad-key");

    const status = await selector.getOperatorVisibleStatus();
    const concierge = status.surfaces.find((s) => s.surface === "concierge");
    expect(concierge?.recentFailures.length).toBeGreaterThan(0);
    const last = concierge?.recentFailures[concierge.recentFailures.length - 1]!;
    expect(last.failureClass).toBe("substrate_auth_failed");
  });
});

// v1.2.0-rc.1 Finding SS: Apply-to-all-surfaces
describe("SubstrateSelector, Finding SS bulk apply", () => {
  it("applyChoiceToAllSurfaces sets every surface to the same substrate", async () => {
    const { selector } = buildSelector();
    await selector.load();
    await selector.applyChoiceToAllSurfaces("venice");
    const cfg = selector.getConfig();
    for (const surface of [
      "concierge",
      "direct-agent-gate-advisor",
      "sentinel-scoring",
      "gate-explanation",
      "privacy-filter-tier-2",
      "template-suggestion",
    ] as const) {
      expect(cfg.perSurface[surface]).toBe("venice");
    }
    expect(cfg.applyToAllSurfaces).toBe(true);
  });

  it("applyChoiceToAllSurfaces emits a single bulk_substrate_chosen audit event", async () => {
    const { selector, auditLog } = buildSelector();
    await selector.load();
    await selector.applyChoiceToAllSurfaces("venice");
    const bulk = await auditLog.query({ operation_type: INTEL_OPS.BULK_SUBSTRATE_CHOSEN });
    expect(bulk.entries.length).toBe(1);
    const details = bulk.entries[0]!.details as {
      kind: string;
      substrate: string;
      surface_count: number;
      tradeoff_text_hash: string;
      prior_substrates: Record<string, string | null>;
    };
    expect(details.kind).toBe("bulk_substrate_chosen");
    expect(details.substrate).toBe("venice");
    expect(details.surface_count).toBe(6);
    expect(details.tradeoff_text_hash).toBe(tradeoffTextHash("venice"));
    expect(details.prior_substrates.concierge).toBe("local");
    expect(details.prior_substrates["gate-explanation"]).toBe("disabled");

    // No per-surface chosen events should fire for the bulk path.
    const single = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_CHOSEN });
    expect(single.entries.length).toBe(0);
  });

  it("applyChoiceToAllSurfaces with local + localModelPick applies pick to every surface", async () => {
    const { selector } = buildSelector();
    await selector.load();
    await selector.applyChoiceToAllSurfaces("local", { localModelPick: "llama-3.1-8b" });
    const cfg = selector.getConfig();
    for (const surface of [
      "concierge",
      "direct-agent-gate-advisor",
      "sentinel-scoring",
      "gate-explanation",
      "privacy-filter-tier-2",
      "template-suggestion",
    ] as const) {
      expect(cfg.perSurface[surface]).toBe("local");
      expect(cfg.localModelPicks[surface]).toBe("llama-3.1-8b");
    }
  });

  it("setApplyToAllPreference persists and survives reload", async () => {
    const { selector, storage, masterKey, auditLog } = buildSelector();
    await selector.load();
    await selector.setApplyToAllPreference(false);
    expect(selector.getConfig().applyToAllSurfaces).toBe(false);

    const reloaded = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: "test-identity",
    });
    await reloaded.load();
    expect(reloaded.getConfig().applyToAllSurfaces).toBe(false);
  });

  it("after bulk apply, per-surface override still works (operator reverts one surface)", async () => {
    const { selector } = buildSelector();
    await selector.load();
    await selector.applyChoiceToAllSurfaces("venice");
    await selector.setPerSurfaceChoice("sentinel-scoring", "disabled");
    const cfg = selector.getConfig();
    expect(cfg.perSurface.concierge).toBe("venice");
    expect(cfg.perSurface["sentinel-scoring"]).toBe("disabled");
    expect(cfg.perSurface["template-suggestion"]).toBe("venice");
  });
});

// v1.2.0-rc.2 Finding ZZ: clear recent-failures buffer on substrate change
// or on confirmed-ok Venice key re-save.
describe("SubstrateSelector, Finding ZZ recent-failures buffer clearing", () => {
  it("setPerSurfaceChoice clears the surface's recent-failures buffer when the substrate actually changes", async () => {
    const { selector } = buildSelector();
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    selector.recordRecentFailureForTest(
      "concierge",
      "substrate_misconfigured",
      "venice configured model not found",
    );
    expect(selector.getRecentFailuresForTest("concierge").length).toBe(1);

    await selector.setPerSurfaceChoice("concierge", "local");

    expect(selector.getRecentFailuresForTest("concierge").length).toBe(0);
  });

  it("setPerSurfaceChoice does NOT clear the buffer when the operator re-saves the same substrate", async () => {
    const { selector } = buildSelector();
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    selector.recordRecentFailureForTest(
      "concierge",
      "substrate_auth_failed",
      "venice key rejected on validation probe",
    );
    expect(selector.getRecentFailuresForTest("concierge").length).toBe(1);

    await selector.setPerSurfaceChoice("concierge", "venice");

    expect(selector.getRecentFailuresForTest("concierge").length).toBe(1);
  });

  it("applyChoiceToAllSurfaces clears every surface's recent-failures buffer", async () => {
    const { selector } = buildSelector();
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setPerSurfaceChoice("sentinel-scoring", "venice");
    await selector.setPerSurfaceChoice("template-suggestion", "venice");
    selector.recordRecentFailureForTest(
      "concierge",
      "substrate_misconfigured",
      "venice model not found",
    );
    selector.recordRecentFailureForTest(
      "sentinel-scoring",
      "substrate_auth_failed",
      "venice key rejected",
    );
    selector.recordRecentFailureForTest(
      "template-suggestion",
      "substrate_unavailable",
      "venice transport error",
    );
    expect(selector.getRecentFailuresForTest("concierge").length).toBe(1);
    expect(selector.getRecentFailuresForTest("sentinel-scoring").length).toBe(1);
    expect(selector.getRecentFailuresForTest("template-suggestion").length).toBe(1);

    await selector.applyChoiceToAllSurfaces("local", {});

    expect(selector.getRecentFailuresForTest("concierge").length).toBe(0);
    expect(selector.getRecentFailuresForTest("sentinel-scoring").length).toBe(0);
    expect(selector.getRecentFailuresForTest("template-suggestion").length).toBe(0);
    expect(selector.getRecentFailuresForTest("direct-agent-gate-advisor").length).toBe(0);
    expect(selector.getRecentFailuresForTest("gate-explanation").length).toBe(0);
    expect(selector.getRecentFailuresForTest("privacy-filter-tier-2").length).toBe(0);
  });

  it("setVeniceApiKey with a probe that returns ok clears every Venice-bound surface's buffer", async () => {
    const fetchImpl = (async () =>
      new Response(JSON.stringify({ choices: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    ) as typeof fetch;
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setPerSurfaceChoice("sentinel-scoring", "venice");
    await selector.setPerSurfaceChoice("template-suggestion", "local");
    selector.recordRecentFailureForTest(
      "concierge",
      "substrate_auth_failed",
      "venice key rejected",
    );
    selector.recordRecentFailureForTest(
      "sentinel-scoring",
      "substrate_misconfigured",
      "venice model not found",
    );
    selector.recordRecentFailureForTest(
      "template-suggestion",
      "substrate_unavailable",
      "local model down",
    );

    await selector.setVeniceApiKey("operator-fixed-key");

    expect(selector.getRecentFailuresForTest("concierge").length).toBe(0);
    expect(selector.getRecentFailuresForTest("sentinel-scoring").length).toBe(0);
    expect(selector.getRecentFailuresForTest("template-suggestion").length).toBe(1);
  });

  it("setVeniceApiKey with a probe that returns invalid-key does NOT clear; existing failure remains and a fresh one is recorded", async () => {
    const fetchImpl = (async () =>
      new Response("", { status: 401 })
    ) as typeof fetch;
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    selector.recordRecentFailureForTest(
      "concierge",
      "substrate_auth_failed",
      "prior failure",
    );
    expect(selector.getRecentFailuresForTest("concierge").length).toBe(1);

    await selector.setVeniceApiKey("still-bad-key");

    const failures = selector.getRecentFailuresForTest("concierge");
    expect(failures.length).toBe(2);
    expect(failures[0]!.snippet).toBe("prior failure");
    expect(failures[1]!.snippet).toContain("venice key rejected");
  });

  it("setVeniceApiKey with a probe that returns invalid-model does NOT clear; existing failure remains and a fresh one is recorded", async () => {
    const fetchImpl = (async () =>
      new Response(
        JSON.stringify({
          error:
            "Specified model not found: llama-3.3-70b. Did you mean: llama-3.4-70b?",
        }),
        { status: 404, headers: { "Content-Type": "application/json" } },
      )
    ) as typeof fetch;
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    selector.recordRecentFailureForTest(
      "concierge",
      "substrate_misconfigured",
      "prior misconfiguration",
    );
    expect(selector.getRecentFailuresForTest("concierge").length).toBe(1);

    await selector.setVeniceApiKey("good-key-bad-model");

    const failures = selector.getRecentFailuresForTest("concierge");
    expect(failures.length).toBe(2);
    expect(failures[0]!.snippet).toBe("prior misconfiguration");
    expect(failures[1]!.snippet).toContain("not found on validation probe");
  });

  it("setVeniceApiKey with a probe that returns unreachable preserves the existing buffer; runtime path will surface", async () => {
    const fetchImpl = (async () => {
      throw new Error("ECONNREFUSED");
    }) as typeof fetch;
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    selector.recordRecentFailureForTest(
      "concierge",
      "substrate_auth_failed",
      "prior failure pre-key-rotation",
    );

    await selector.setVeniceApiKey("rotated-key");

    expect(selector.getRecentFailuresForTest("concierge").length).toBe(1);
    expect(selector.getRecentFailuresForTest("concierge")[0]!.snippet).toBe(
      "prior failure pre-key-rotation",
    );
  });
});
