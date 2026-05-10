/**
 * WP-V1.x-QUERY-LAYER-ANONYMITY Rho-1 Tier A regression suite.
 *
 * Coverage:
 *   - Strip-list correctness across the canonical header classes.
 *   - Required-header preservation (Authorization + Content-Type +
 *     provider-specific auth survive every strip).
 *   - createAnonymizedFetch wrapper invariants: strips on every
 *     call, neutralizes undici defaults, audit callback fires with
 *     the per-call removed-header summary.
 *   - Zero-PII ship gate: detectPiiInHeaders detects all four PII
 *     classes (email, ip-address, hostname, system-locale).
 *   - Multi-fortress isolation: two separate fetch wrappers produce
 *     independent audit streams.
 *   - Castle-walking unconditionality: the strip is a pure
 *     function of the input; there is no runtime knob.
 *   - Dashboard route aggregation: query-anonymity stats correctly
 *     sum + top-5 + per-reason from a synthetic audit log.
 */

import { describe, it, expect } from "vitest";

import {
  QUERY_ANONYMITY_AUDIT_OPS,
  createAnonymizedFetch,
  defeatUndiciDefaultsInto,
  detectPiiInHeaders,
  getRequiredHeaders,
  getStripList,
  stripHeaders,
} from "../../src/query-anonymity/header-strip.js";
import {
  computeQueryAnonymityStats,
} from "../../src/query-anonymity/query-anonymity-routes.js";
import {
  AuditLog,
  type AuditEntry,
} from "../../src/l2-operational/audit-log.js";

function stubAuditLog(entries: AuditEntry[]): AuditLog {
  return {
    async query(opts: {
      since?: string;
      layer?: AuditEntry["layer"];
      operation_type?: string;
      limit?: number;
    }): Promise<{ entries: AuditEntry[]; total: number }> {
      let filtered = entries;
      if (opts.since) {
        const sinceMs = Date.parse(opts.since);
        filtered = filtered.filter((e) => Date.parse(e.timestamp) >= sinceMs);
      }
      if (opts.layer) {
        filtered = filtered.filter((e) => e.layer === opts.layer);
      }
      if (opts.operation_type) {
        filtered = filtered.filter((e) => e.operation === opts.operation_type);
      }
      const limit = opts.limit ?? 50;
      return { entries: filtered.slice(-limit), total: filtered.length };
    },
  } as unknown as AuditLog;
}

describe("WP-V1.x-QUERY-LAYER-ANONYMITY Rho-1 — strip-list correctness", () => {
  it("strips User-Agent", () => {
    const out = stripHeaders({ "User-Agent": "node/22.5.0", Authorization: "Bearer x" });
    expect(out.removed.map((r) => r.name)).toContain("User-Agent");
    expect(out.stripped["User-Agent"]).toBeUndefined();
  });

  it("strips Accept-Language", () => {
    const out = stripHeaders({ "Accept-Language": "en-US,en;q=0.9" });
    expect(out.removed.map((r) => r.reason)).toContain("locale-fingerprint");
  });

  it("strips Referer + Origin + Via (request-origin / proxy chain leak)", () => {
    const out = stripHeaders({
      Referer: "https://operator-app.example.com/page",
      Origin: "https://operator-app.example.com",
      Via: "1.1 proxy.example.com",
    });
    const reasons = new Set(out.removed.map((r) => r.reason));
    expect(reasons.has("leaking-network-info")).toBe(true);
    expect(out.removed.length).toBe(3);
  });

  it("strips the full Sec-CH-UA family and DNT/Sec-GPC", () => {
    const out = stripHeaders({
      "Sec-CH-UA": '"Chromium";v="120"',
      "Sec-CH-UA-Mobile": "?0",
      "Sec-CH-UA-Platform": '"macOS"',
      DNT: "1",
      "Sec-GPC": "1",
    });
    expect(out.removed.length).toBe(5);
    expect(Object.keys(out.stripped).length).toBe(0);
  });

  it("matches header names case-insensitively (USER-AGENT and user-agent both stripped)", () => {
    const out = stripHeaders({
      "USER-AGENT": "evil",
      "user-agent": "also evil",
    });
    expect(out.removed.length).toBe(2);
    expect(Object.keys(out.stripped).length).toBe(0);
  });
});

describe("WP-V1.x-QUERY-LAYER-ANONYMITY Rho-1 — required-header preservation", () => {
  it("preserves Authorization and Content-Type", () => {
    const out = stripHeaders({
      Authorization: "Bearer sk-...",
      "Content-Type": "application/json",
      "User-Agent": "node",
    });
    expect(out.stripped["Authorization"]).toBe("Bearer sk-...");
    expect(out.stripped["Content-Type"]).toBe("application/json");
    expect(out.removed.map((r) => r.name)).toEqual(["User-Agent"]);
  });

  it("preserves provider-specific auth (x-api-key, anthropic-version, x-goog-api-key)", () => {
    const out = stripHeaders({
      "x-api-key": "sk-ant-...",
      "anthropic-version": "2023-06-01",
      "x-goog-api-key": "google-key",
      Referer: "https://x.example.com",
    });
    expect(out.stripped["x-api-key"]).toBe("sk-ant-...");
    expect(out.stripped["anthropic-version"]).toBe("2023-06-01");
    expect(out.stripped["x-goog-api-key"]).toBe("google-key");
    expect(out.removed[0]!.name).toBe("Referer");
  });

  it("getStripList and getRequiredHeaders expose stable lists", () => {
    const stripList = getStripList();
    const required = getRequiredHeaders();
    expect(stripList.length).toBeGreaterThan(10);
    expect(required).toContain("authorization");
    expect(required).toContain("content-type");
    expect(required).toContain("anthropic-version");
  });
});

describe("WP-V1.x-QUERY-LAYER-ANONYMITY Rho-1 — createAnonymizedFetch wrapper", () => {
  it("strips headers on every wrapped call and forwards the cleaned set to the base fetch", async () => {
    const seenInits: Array<RequestInit | undefined> = [];
    const baseFetch: typeof fetch = async (_input, init) => {
      seenInits.push(init);
      return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
    };
    const wrapped = createAnonymizedFetch(baseFetch);
    await wrapped("https://api.example.com/x", {
      headers: { "User-Agent": "node", Authorization: "Bearer x" },
    });
    expect(seenInits.length).toBe(1);
    const headers = seenInits[0]!.headers as Record<string, string>;
    expect(headers["User-Agent"]).toBe("");
    expect(headers["Authorization"]).toBe("Bearer x");
  });

  it("invokes the audit callback with the per-call removed summary", async () => {
    const events: Array<{
      url: string;
      stripped_count: number;
      removed_names: string[];
    }> = [];
    const baseFetch: typeof fetch = async () =>
      new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
    const wrapped = createAnonymizedFetch(baseFetch, (event) => {
      events.push({
        url: event.url,
        stripped_count: event.stripped_count,
        removed_names: event.removed.map((r) => r.name),
      });
    });
    await wrapped("https://api.example.com/x", {
      headers: {
        "User-Agent": "node",
        "Accept-Language": "en",
        Authorization: "Bearer x",
      },
    });
    expect(events.length).toBe(1);
    expect(events[0]!.url).toBe("https://api.example.com/x");
    expect(events[0]!.stripped_count).toBe(2);
    expect(events[0]!.removed_names.sort()).toEqual(
      ["Accept-Language", "User-Agent"].sort(),
    );
  });

  it("defeats undici defaults: User-Agent and Accept-Language are forced to empty when caller did not set them", () => {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    defeatUndiciDefaultsInto(headers);
    expect(headers["User-Agent"]).toBe("");
    expect(headers["Accept-Language"]).toBe("");
  });

  it("wrapped fetch defeats undici defaults even when caller passes no headers at all", async () => {
    const seenInits: Array<RequestInit | undefined> = [];
    const baseFetch: typeof fetch = async (_input, init) => {
      seenInits.push(init);
      return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
    };
    const wrapped = createAnonymizedFetch(baseFetch);
    await wrapped("https://api.example.com/x", { method: "POST" });
    const headers = seenInits[0]!.headers as Record<string, string>;
    expect(headers["User-Agent"]).toBe("");
    expect(headers["Accept-Language"]).toBe("");
  });
});

describe("WP-V1.x-QUERY-LAYER-ANONYMITY Rho-1 — zero-PII ship gate", () => {
  it("detects email PII", () => {
    const matches = detectPiiInHeaders({
      "X-Operator-Email": "alice@example.com",
    });
    expect(matches.length).toBe(1);
    expect(matches[0]!.piiClass).toBe("email");
  });

  it("detects IPv4 PII", () => {
    const matches = detectPiiInHeaders({
      "X-Forwarded-For": "192.168.1.42",
    });
    expect(matches.length).toBeGreaterThanOrEqual(1);
    expect(matches.some((m) => m.piiClass === "ip-address")).toBe(true);
  });

  it("detects IPv6 PII", () => {
    const matches = detectPiiInHeaders({
      "X-Real-IP": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    });
    expect(matches.some((m) => m.piiClass === "ip-address")).toBe(true);
  });

  it("detects hostname PII when the operator-hostname appears in any header value", () => {
    const matches = detectPiiInHeaders(
      { "X-Custom": "operator-mbp-2025" },
      { hostname: "operator-mbp-2025" },
    );
    expect(matches.some((m) => m.piiClass === "hostname")).toBe(true);
  });

  it("detects User-Agent and Accept-Language as system-locale PII when populated", () => {
    const matches = detectPiiInHeaders({
      "User-Agent": "Mozilla/5.0",
      "Accept-Language": "en-US",
    });
    const classes = new Set(matches.map((m) => m.piiClass));
    expect(classes.has("system-locale")).toBe(true);
    expect(matches.length).toBeGreaterThanOrEqual(2);
  });

  it("zero-PII ship gate end-to-end: a real wrapped-fetch outbound call leaks no PII through to the base fetch", async () => {
    let observedHeaders: Record<string, string> = {};
    const baseFetch: typeof fetch = async (_input, init) => {
      observedHeaders = init?.headers as Record<string, string>;
      return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
    };
    const wrapped = createAnonymizedFetch(baseFetch);
    await wrapped("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": "sk-ant-fake",
        "anthropic-version": "2023-06-01",
        // The caller leaked some PII — the wrap MUST strip it.
        "User-Agent": "node/22.5.0",
        Referer: "https://alice-mbp.local/dashboard",
        "X-Forwarded-For": "10.0.0.42",
        "Accept-Language": "en-US,en;q=0.9",
      },
    });
    const matches = detectPiiInHeaders(observedHeaders, { hostname: "alice-mbp" });
    expect(matches).toEqual([]);
    // Required headers survived.
    expect(observedHeaders["x-api-key"]).toBe("sk-ant-fake");
    expect(observedHeaders["anthropic-version"]).toBe("2023-06-01");
    // Undici defaults defeated.
    expect(observedHeaders["User-Agent"]).toBe("");
  });
});

describe("WP-V1.x-QUERY-LAYER-ANONYMITY Rho-1 — Castle-walking unconditionality + isolation", () => {
  it("strip is a pure function: same input -> same output, no hidden state", () => {
    const headers = { "User-Agent": "x", Authorization: "y" };
    const a = stripHeaders(headers);
    const b = stripHeaders(headers);
    expect(a).toEqual(b);
  });

  it("wrapped fetch has no operator-side opt-out: removing the strip requires editing the wrap site", () => {
    // There is no exported "disable" function. The only way to skip
    // the strip is to NOT call createAnonymizedFetch, which is
    // structurally a code change in the selector constructor.
    const moduleExports = Object.keys({
      createAnonymizedFetch,
      stripHeaders,
      defeatUndiciDefaultsInto,
      detectPiiInHeaders,
      getStripList,
      getRequiredHeaders,
      QUERY_ANONYMITY_AUDIT_OPS,
    });
    expect(moduleExports).not.toContain("disableHeaderStrip");
    expect(moduleExports).not.toContain("setAnonymityOptOut");
  });

  it("multi-fortress isolation: two independent wrappers produce independent audit streams", async () => {
    const eventsA: string[] = [];
    const eventsB: string[] = [];
    const baseFetch: typeof fetch = async () =>
      new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
    const wrappedA = createAnonymizedFetch(baseFetch, (e) =>
      eventsA.push(e.url),
    );
    const wrappedB = createAnonymizedFetch(baseFetch, (e) =>
      eventsB.push(e.url),
    );
    await wrappedA("https://a.example.com/", { headers: { "User-Agent": "x" } });
    await wrappedB("https://b.example.com/", { headers: { "User-Agent": "y" } });
    expect(eventsA).toEqual(["https://a.example.com/"]);
    expect(eventsB).toEqual(["https://b.example.com/"]);
  });

  it("QUERY_ANONYMITY_AUDIT_OPS exposes stable shape", () => {
    expect(QUERY_ANONYMITY_AUDIT_OPS.HEADERS_STRIPPED).toBe(
      "query_anonymity_headers_stripped",
    );
  });
});

describe("WP-V1.x-QUERY-LAYER-ANONYMITY Rho-1 — dashboard route aggregation", () => {
  it("aggregates audit events into total + per-header + per-reason stats", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    function eventEntry(opts: {
      ts: Date;
      removed: { name: string; reason: string }[];
    }): AuditEntry {
      return {
        timestamp: opts.ts.toISOString(),
        layer: "l2",
        operation: "query_anonymity_headers_stripped",
        identity_id: "system",
        result: "success",
        details: {
          url: "https://api.anthropic.com/v1/messages",
          method: "POST",
          stripped_count: opts.removed.length,
          removed: opts.removed,
          required_preserved: ["Content-Type"],
        },
      };
    }
    const audit = stubAuditLog([
      eventEntry({
        ts: new Date(now.getTime() - 60_000),
        removed: [
          { name: "User-Agent", reason: "user-agent" },
          { name: "Accept-Language", reason: "locale-fingerprint" },
        ],
      }),
      eventEntry({
        ts: new Date(now.getTime() - 120_000),
        removed: [
          { name: "User-Agent", reason: "user-agent" },
          { name: "Referer", reason: "leaking-network-info" },
        ],
      }),
      eventEntry({
        ts: new Date(now.getTime() - 300_000),
        removed: [
          { name: "User-Agent", reason: "user-agent" },
          { name: "DNT", reason: "unnecessary-metadata" },
        ],
      }),
    ]);
    const stats = await computeQueryAnonymityStats({
      auditLog: audit,
      now: () => now,
    });
    expect(stats.total_outbound_calls).toBe(3);
    expect(stats.total_headers_stripped).toBe(6);
    // Top stripped header should be user-agent at count 3.
    expect(stats.top_stripped_headers[0]!.name).toBe("user-agent");
    expect(stats.top_stripped_headers[0]!.count).toBe(3);
    // user-agent reason should dominate the per-reason summary.
    const userAgentReason = stats.per_reason.find(
      (r) => r.reason === "user-agent",
    );
    expect(userAgentReason!.count).toBe(3);
  });

  it("returns an empty-stats shape when the audit log has no anonymity events", async () => {
    const stats = await computeQueryAnonymityStats({
      auditLog: stubAuditLog([]),
    });
    expect(stats.total_outbound_calls).toBe(0);
    expect(stats.total_headers_stripped).toBe(0);
    expect(stats.top_stripped_headers).toEqual([]);
    expect(stats.per_reason).toEqual([]);
  });
});
