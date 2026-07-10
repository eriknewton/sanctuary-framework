/**
 * Hermetic tests for the operator-side enforcement-event exporter.
 *
 * These tests NEVER touch a real ~/.sanctuary, a real filesystem sink path, or a
 * real network endpoint: the file sink writes to an in-memory array, and the
 * HTTP sink's fetch is always a mock. The honesty regression (a secret injected
 * into `details` must never appear in output) is the load-bearing test.
 */

import { describe, expect, it, vi } from "vitest";

import type { AuditEntry } from "../../../src/operational/audit-log.js";
import {
  DEFAULT_EXPORT_SINK,
  EnforcementExportConfigError,
  ENFORCEMENT_EXPORT_EMITTED,
  ENFORCEMENT_EXPORT_ENABLED,
  ENFORCEMENT_EXPORT_REFUSED,
  ENFORCEMENT_EVENT_SCHEMA,
  EnforcementExporter,
  FileExportSink,
  HttpCollectorSink,
  mapAuditEntryToEnforcementEvent,
  mapEntriesToEnforcementEvents,
  validateExportConfig,
  type EnforcementExportConfig,
  type ExportApprover,
} from "../../../src/castle-wall/export/index.js";

// ── Fixtures ────────────────────────────────────────────────────────────────

/** An egress-deny entry in the UNSIGNED/channel shape (nested destination/agent). */
function egressDenyEntry(extraDetails: Record<string, unknown> = {}): AuditEntry {
  return {
    timestamp: "2026-07-10T00:00:00.000Z",
    layer: "l1",
    operation: "egress_blocked",
    identity_id: "system",
    result: "success",
    details: {
      destination: { host: "evil.example.com", ip: "203.0.113.5", port: 443, protocol: "tcp" },
      agent: { id: "claude-code-1", template: "coding-assistant" },
      rule_id: "rule-deny-evil",
      decision: "deny_always",
      ...extraDetails,
    },
  };
}

/** An egress-allow entry in the SIGNED/flat shape (dest_host / agent_id / rule_id_matched). */
function egressAllowFlatEntry(): AuditEntry {
  return {
    timestamp: "2026-07-10T00:01:00.000Z",
    layer: "l1",
    operation: "egress_allowed",
    identity_id: "system",
    result: "success",
    details: {
      dest_host: "api.anthropic.com",
      dest_ip: "160.79.104.10",
      dest_port: 443,
      dest_protocol: "tcp",
      agent_id: "claude-code-1",
      rule_id_matched: "rule-allow-anthropic",
      cw_producer_signed_canonical: "SECRET-SIGNED-BLOB-should-not-leak",
    },
  };
}

function policyLoadedEntry(): AuditEntry {
  return {
    timestamp: "2026-07-10T00:02:00.000Z",
    layer: "l1",
    operation: "policy_loaded",
    identity_id: "operator",
    result: "success",
    details: {
      signer_kid: "cw-audit-producer-v1",
      manifest_digest: "sha256:abc123",
      loaded_rule_count: 7,
      // Contents that must NEVER be forwarded:
      rules: [{ host: "secret-internal.example", note: "confidential rule text" }],
      reason: "loaded internal policy bundle v9 with 7 confidential rules",
    },
  };
}

function distressEntry(): AuditEntry {
  return {
    timestamp: "2026-07-10T00:03:00.000Z",
    layer: "l2",
    operation: "sanctuary_distress",
    identity_id: "agent",
    result: "success",
    details: {
      envelope: {
        schema: "sanctuary.distress.v1",
        event_id: "distress:deadbeef",
        emitted_at: "2026-07-10T00:03:00.000Z",
        actor: "claude-code-1",
        reason: "external_coercion",
        severity: "critical",
        detail: "operator unreachable for 3h",
        sequence_in_window: 2,
      },
      // A signature blob and a webhook secret that MUST NOT leak:
      signature: { signature: "SECRET-SIG", public_key: "SECRET-PUBKEY" },
      webhook_secret: "SECRET-HMAC-KEY",
    },
  };
}

const noopAudit = async (): Promise<void> => {};
const alwaysApprove: ExportApprover = async () => ({ allowed: true });
const alwaysDeny: ExportApprover = async () => ({ allowed: false, reason: "operator denied" });

// ── Closed mapping ────────────────────────────────────────────────────────────

describe("mapAuditEntryToEnforcementEvent", () => {
  it("maps an egress deny (nested shape) to a frozen egress_decision event", () => {
    const event = mapAuditEntryToEnforcementEvent(egressDenyEntry());
    expect(event).toEqual({
      schema: ENFORCEMENT_EVENT_SCHEMA,
      event_class: "egress_decision",
      timestamp: "2026-07-10T00:00:00.000Z",
      decision: "deny",
      destination_host: "evil.example.com",
      destination_ip: "203.0.113.5",
      destination_port: 443,
      destination_protocol: "tcp",
      rule_id: "rule-deny-evil",
      agent_id: "claude-code-1",
      agent_template: "coding-assistant",
      enforcement_point: "castle_wall",
    });
  });

  it("maps an egress allow (flat signed shape) reading dest_host / rule_id_matched", () => {
    const event = mapAuditEntryToEnforcementEvent(egressAllowFlatEntry());
    expect(event).toMatchObject({
      event_class: "egress_decision",
      decision: "allow",
      destination_host: "api.anthropic.com",
      destination_ip: "160.79.104.10",
      destination_port: 443,
      destination_protocol: "tcp",
      rule_id: "rule-allow-anthropic",
      agent_id: "claude-code-1",
    });
  });

  it("maps a policy_loaded entry to a policy_change carrying attribution but NO contents", () => {
    const event = mapAuditEntryToEnforcementEvent(policyLoadedEntry());
    expect(event).toEqual({
      schema: ENFORCEMENT_EVENT_SCHEMA,
      event_class: "policy_change",
      timestamp: "2026-07-10T00:02:00.000Z",
      change_type: "loaded",
      signer_ref: "cw-audit-producer-v1",
      manifest_digest: "sha256:abc123",
      rule_count: 7,
      enforcement_point: "castle_wall",
    });
  });

  it("maps a distress entry from its closed envelope", () => {
    const event = mapAuditEntryToEnforcementEvent(distressEntry());
    expect(event).toMatchObject({
      event_class: "distress",
      distress_schema: "sanctuary.distress.v1",
      event_id: "distress:deadbeef",
      actor: "claude-code-1",
      reason: "external_coercion",
      severity: "critical",
      detail: "operator unreachable for 3h",
      sequence_in_window: 2,
    });
  });

  it("drops entries that are not one of the three forwarded classes", () => {
    const entry: AuditEntry = {
      timestamp: "2026-07-10T00:04:00.000Z",
      layer: "l1",
      operation: "filter_started",
      identity_id: "system",
      result: "success",
      details: { pid: 1234 },
    };
    expect(mapAuditEntryToEnforcementEvent(entry)).toBeNull();
  });

  it("drops a distress entry with a malformed / wrong-schema envelope (never guesses)", () => {
    const entry = distressEntry();
    (entry.details!.envelope as Record<string, unknown>).schema = "not.the.distress.schema";
    expect(mapAuditEntryToEnforcementEvent(entry)).toBeNull();
  });

  it("drops a distress entry whose reason is outside the closed vocabulary", () => {
    const entry = distressEntry();
    (entry.details!.envelope as Record<string, unknown>).reason = "arbitrary_reason";
    expect(mapAuditEntryToEnforcementEvent(entry)).toBeNull();
  });

  it("collapses a redacted rule-id to null rather than resurfacing a sibling key", () => {
    const entry = egressDenyEntry({ rule_id: "[redacted]", rule_id_matched: "leaked-rule" });
    const event = mapAuditEntryToEnforcementEvent(entry);
    expect(event).toMatchObject({ event_class: "egress_decision", rule_id: null });
  });
});

// ── THE HONESTY REGRESSION ────────────────────────────────────────────────────

describe("closed schema drops anything not on the allowlist (honesty regression)", () => {
  it("never emits an injected secret planted in details", () => {
    const SECRET = "sk-super-secret-token-DO-NOT-LEAK";
    const entry = egressDenyEntry({
      api_key: SECRET,
      reason: `threshold 5/min; ${SECRET}`,
      free_text_note: SECRET,
      nested: { deep: { secret: SECRET } },
    });
    const event = mapAuditEntryToEnforcementEvent(entry);
    const serialized = JSON.stringify(event);
    expect(serialized).not.toContain(SECRET);
    // Only the frozen field set is present.
    expect(Object.keys(event as object).sort()).toEqual(
      [
        "agent_id",
        "agent_template",
        "decision",
        "destination_host",
        "destination_ip",
        "destination_port",
        "destination_protocol",
        "enforcement_point",
        "event_class",
        "rule_id",
        "schema",
        "timestamp",
      ].sort(),
    );
  });

  it("never emits policy rule contents or the free-text reason", () => {
    const event = mapAuditEntryToEnforcementEvent(policyLoadedEntry());
    const serialized = JSON.stringify(event);
    expect(serialized).not.toContain("confidential");
    expect(serialized).not.toContain("secret-internal.example");
    expect(serialized).not.toContain("reason");
  });

  it("never emits the distress signature blob or webhook secret", () => {
    const event = mapAuditEntryToEnforcementEvent(distressEntry());
    const serialized = JSON.stringify(event);
    expect(serialized).not.toContain("SECRET-SIG");
    expect(serialized).not.toContain("SECRET-PUBKEY");
    expect(serialized).not.toContain("SECRET-HMAC-KEY");
  });

  it("never emits the producer-signed canonical blob from a flat signed entry", () => {
    const event = mapAuditEntryToEnforcementEvent(egressAllowFlatEntry());
    expect(JSON.stringify(event)).not.toContain("SECRET-SIGNED-BLOB");
  });
});

// ── Config validation (fail closed) ───────────────────────────────────────────

describe("validateExportConfig", () => {
  it("defaults to the network-free file sink", () => {
    expect(validateExportConfig(undefined)).toEqual({ sink: DEFAULT_EXPORT_SINK, enabled: false });
  });

  it("rejects unknown keys", () => {
    expect(() => validateExportConfig({ sink: "file", bogus: 1 })).toThrow(
      EnforcementExportConfigError,
    );
  });

  it("requires a pinned destination_url for the http sink", () => {
    expect(() => validateExportConfig({ sink: "http", enabled: true })).toThrow(
      /destination_url is required/,
    );
  });

  it("rejects a non-loopback http (non-https) destination", () => {
    expect(() =>
      validateExportConfig({ sink: "http", enabled: true, destination_url: "http://collector.example/x" }),
    ).toThrow(/https/);
  });

  it("accepts a loopback http destination (local collector / test)", () => {
    const config = validateExportConfig({
      sink: "http",
      enabled: true,
      destination_url: "http://127.0.0.1:9999/collector",
    });
    expect(config.destination_url).toBe("http://127.0.0.1:9999/collector");
  });

  it("rejects a destination_url paired with the file sink", () => {
    expect(() =>
      validateExportConfig({ sink: "file", destination_url: "https://collector.example/x" }),
    ).toThrow(/only valid with sink/);
  });
});

// ── Default sink: no network ──────────────────────────────────────────────────

describe("default file sink never touches the network", () => {
  it("delivers to the injected writer and never calls fetch", async () => {
    const lines: string[] = [];
    const fetchSpy = vi.fn();
    const exporter = new EnforcementExporter({
      config: { sink: "file", enabled: false },
      approve: alwaysApprove,
      audit: noopAudit,
      fileWriter: (line) => {
        lines.push(line);
      },
      fetchImpl: fetchSpy as unknown as typeof fetch,
    });

    const enabled = await exporter.enable();
    expect(enabled).toEqual({ status: "enabled", touchesNetwork: false });
    expect(exporter.touchesNetwork()).toBe(false);

    const outcome = await exporter.exportEntries([egressDenyEntry(), policyLoadedEntry(), distressEntry()]);
    expect(outcome).toEqual({ status: "delivered", count: 3 });
    expect(lines).toHaveLength(3);
    expect(fetchSpy).not.toHaveBeenCalled();
    // Each line is a valid frozen event.
    for (const line of lines) {
      expect(JSON.parse(line).schema).toBe(ENFORCEMENT_EVENT_SCHEMA);
    }
  });

  it("the file sink reports touchesNetwork=false structurally", () => {
    const sink = new FileExportSink(() => {});
    expect(sink.touchesNetwork).toBe(false);
  });
});

// ── HTTP push: opt-in + pinned + Tier-1 gate ──────────────────────────────────

describe("HTTP push refuses without opt-in + pinned destination + Tier-1 approval", () => {
  const httpConfig: EnforcementExportConfig = {
    sink: "http",
    enabled: true,
    destination_url: "https://collector.example/xsiam",
  };

  it("refuses when the opt-in flag is false", async () => {
    const audits: string[] = [];
    const exporter = new EnforcementExporter({
      config: { ...httpConfig, enabled: false },
      approve: alwaysApprove,
      audit: async (op) => {
        audits.push(op);
      },
    });
    const outcome = await exporter.enable();
    expect(outcome.status).toBe("refused");
    expect(audits).toContain(ENFORCEMENT_EXPORT_REFUSED);
    expect(exporter.touchesNetwork()).toBeNull();
  });

  it("refuses when the Tier-1 approval is denied (arms nothing)", async () => {
    const fetchSpy = vi.fn();
    const audits: string[] = [];
    const exporter = new EnforcementExporter({
      config: httpConfig,
      approve: alwaysDeny,
      audit: async (op) => {
        audits.push(op);
      },
      fetchImpl: fetchSpy as unknown as typeof fetch,
    });
    const outcome = await exporter.enable();
    expect(outcome).toEqual({ status: "refused", reason: "operator denied" });
    expect(audits).toContain(ENFORCEMENT_EXPORT_REFUSED);
    // Nothing armed => export refuses and never pushes.
    const exported = await exporter.exportEvents([]);
    expect(exported.status).toBe("refused");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("passes the pinned destination (and no secret) into the Tier-1 approval context", async () => {
    const approve = vi.fn(async () => ({ allowed: true as const }));
    const exporter = new EnforcementExporter({
      config: httpConfig,
      approve,
      audit: noopAudit,
      fetchImpl: (async () => new Response(null, { status: 200 })) as unknown as typeof fetch,
    });
    await exporter.enable();
    expect(approve).toHaveBeenCalledWith(
      ENFORCEMENT_EXPORT_ENABLED,
      expect.objectContaining({ pinned_destination_url: "https://collector.example/xsiam", touches_network: true }),
    );
    const context = approve.mock.calls[0][1];
    expect(JSON.stringify(context)).not.toMatch(/secret|token|key/i);
  });

  it("arms and delivers a batch to the pinned collector on approval", async () => {
    const seen: { url: string; body: string }[] = [];
    const fetchImpl = (async (url: string, init: RequestInit) => {
      seen.push({ url: String(url), body: String(init.body) });
      return new Response(null, { status: 200 });
    }) as unknown as typeof fetch;
    const audits: string[] = [];
    const exporter = new EnforcementExporter({
      config: httpConfig,
      approve: alwaysApprove,
      audit: async (op) => {
        audits.push(op);
      },
      fetchImpl,
    });
    await exporter.enable();
    const outcome = await exporter.exportEntries([egressDenyEntry()]);
    expect(outcome).toEqual({ status: "delivered", count: 1 });
    expect(seen).toHaveLength(1);
    expect(seen[0].url).toBe("https://collector.example/xsiam");
    expect(JSON.parse(seen[0].body).events[0].destination_host).toBe("evil.example.com");
    expect(audits).toContain(ENFORCEMENT_EXPORT_ENABLED);
    expect(audits).toContain(ENFORCEMENT_EXPORT_EMITTED);
  });
});

// ── Fail loud on unreachable pinned destination ───────────────────────────────

describe("unreachable pinned destination FAILS LOUD (never falls back, never silent drop)", () => {
  const httpConfig: EnforcementExportConfig = {
    sink: "http",
    enabled: true,
    destination_url: "https://collector.example/xsiam",
  };

  it("re-throws and audits a refusal when the collector is unreachable", async () => {
    const fetchImpl = (async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof fetch;
    const audits: { op: string; result: string }[] = [];
    const exporter = new EnforcementExporter({
      config: httpConfig,
      approve: alwaysApprove,
      audit: async (op, _details, result) => {
        audits.push({ op, result });
      },
      fetchImpl,
    });
    await exporter.enable();
    await expect(exporter.exportEntries([egressDenyEntry()])).rejects.toThrow(/delivery failed|ECONNREFUSED/);
    expect(audits.some((a) => a.op === ENFORCEMENT_EXPORT_REFUSED && a.result === "failure")).toBe(true);
    // Crucially: no EMITTED audit was written (never reports success on failure).
    expect(audits.some((a) => a.op === ENFORCEMENT_EXPORT_EMITTED)).toBe(false);
  });

  it("re-throws on a non-2xx collector response (a failed delivery is not a success)", async () => {
    const fetchImpl = (async () => new Response("nope", { status: 503 })) as unknown as typeof fetch;
    const exporter = new EnforcementExporter({
      config: httpConfig,
      approve: alwaysApprove,
      audit: noopAudit,
      fetchImpl,
    });
    await exporter.enable();
    await expect(exporter.exportEvents(mapEntriesToEnforcementEvents([egressDenyEntry()]))).rejects.toThrow(
      /HTTP 503/,
    );
  });

  it("does not follow a redirect off the pinned host", async () => {
    const sink = new HttpCollectorSink({
      destinationUrl: "https://collector.example/xsiam",
      fetchImpl: (async (_url: string, init: RequestInit) => {
        expect(init.redirect).toBe("error");
        return new Response(null, { status: 200 });
      }) as unknown as typeof fetch,
    });
    await sink.deliver([]);
  });
});
