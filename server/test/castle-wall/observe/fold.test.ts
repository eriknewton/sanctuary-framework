/**
 * Castle Wall Observe / Learn Allow-List v1 -- fold tests.
 *
 * CI DoD test 1: recorded flows fold into the expected suggestion list
 * (dedup, counts, first/last seen).
 */

import { describe, it, expect } from "vitest";
import { foldObservations, flagExfilRisk, mergeCandidateObservations } from "../../../src/castle-wall/observe/fold.js";
import { candidateKey, type FlowObservationEvent } from "../../../src/castle-wall/observe/types.js";

function flow(overrides: Partial<FlowObservationEvent> = {}): FlowObservationEvent {
  return {
    timestamp: "2026-07-07T10:00:00.000Z",
    agent: { id: "agent-1", template: "claude-code" },
    destination: { host: "api.example.com", ip: "203.0.113.5", port: 443, protocol: "tcp" },
    hostname_source: "sni",
    disposition: "denied",
    ...overrides,
  };
}

describe("foldObservations", () => {
  it("dedups repeated flows to the same destination into one candidate with a bumped times_seen", () => {
    const events = [
      flow({ timestamp: "2026-07-07T10:00:00.000Z" }),
      flow({ timestamp: "2026-07-07T10:05:00.000Z" }),
      flow({ timestamp: "2026-07-07T10:02:00.000Z" }),
    ];
    const candidates = foldObservations(events);
    expect(candidates).toHaveLength(1);
    expect(candidates[0]!.times_seen).toBe(3);
    expect(candidates[0]!.first_seen).toBe("2026-07-07T10:00:00.000Z");
    expect(candidates[0]!.last_seen).toBe("2026-07-07T10:05:00.000Z");
  });

  it("keeps distinct (agent template, host, port, protocol) tuples as separate candidates", () => {
    const events = [
      flow(),
      flow({ destination: { host: "pypi.org", ip: "151.101.0.1", port: 443, protocol: "tcp" } }),
      flow({ agent: { id: "agent-2", template: "research-assistant" } }),
      flow({ destination: { host: "api.example.com", ip: "203.0.113.5", port: 8443, protocol: "tcp" } }),
    ];
    const candidates = foldObservations(events);
    expect(candidates).toHaveLength(4);
  });

  it("dedups an IP-only observation (no hostname) by ip+port+protocol", () => {
    const events = [
      flow({ destination: { host: null, ip: "198.51.100.9", port: 22, protocol: "tcp" }, hostname_source: null }),
      flow({ destination: { host: null, ip: "198.51.100.9", port: 22, protocol: "tcp" }, hostname_source: null }),
    ];
    const candidates = foldObservations(events);
    expect(candidates).toHaveLength(1);
    expect(candidates[0]!.times_seen).toBe(2);
    expect(candidates[0]!.host).toBeNull();
    expect(candidates[0]!.ip).toBe("198.51.100.9");
  });

  it("only folds DENIED flows -- an allowed flow contributes no candidate (enforce-preserving posture, D-Q1)", () => {
    const events = [flow({ disposition: "allowed" })];
    expect(foldObservations(events)).toHaveLength(0);
  });

  it("marks would_be_disposition as denied for every folded candidate", () => {
    const candidates = foldObservations([flow()]);
    expect(candidates[0]!.would_be_disposition).toBe("denied");
  });

  it("drops a malformed flow event (no host AND no ip) rather than guessing", () => {
    const events = [flow({ destination: { host: null, ip: "", port: 443, protocol: "tcp" } })];
    expect(foldObservations(events)).toHaveLength(0);
  });

  it("drops a flow event with an out-of-range port", () => {
    const events = [flow({ destination: { host: "x.example.com", ip: "203.0.113.9", port: 0, protocol: "tcp" } })];
    expect(foldObservations(events)).toHaveLength(0);
  });

  it("upgrades hostname_source from socket to a more confident source on a later event, never downgrades", () => {
    const events = [
      flow({ timestamp: "2026-07-07T10:00:00.000Z", hostname_source: "socket" }),
      flow({ timestamp: "2026-07-07T10:01:00.000Z", hostname_source: "dns" }),
      flow({ timestamp: "2026-07-07T10:02:00.000Z", hostname_source: "socket" }),
    ];
    const candidates = foldObservations(events);
    expect(candidates[0]!.hostname_source).toBe("dns");
  });

  it("produces deterministic, sorted output for the same fixture", () => {
    const events = [
      flow({ destination: { host: "b.example.com", ip: "203.0.113.2", port: 443, protocol: "tcp" }, timestamp: "2026-07-07T10:00:01.000Z" }),
      flow({ destination: { host: "a.example.com", ip: "203.0.113.1", port: 443, protocol: "tcp" }, timestamp: "2026-07-07T10:00:00.000Z" }),
    ];
    const once = foldObservations(events);
    const again = foldObservations(events);
    expect(once).toEqual(again);
    expect(once[0]!.host).toBe("a.example.com");
  });
});

describe("flagExfilRisk (D-Q3)", () => {
  it("flags a known messaging-platform host", () => {
    expect(flagExfilRisk("hooks.slack.com")).toBe(true);
    expect(flagExfilRisk("api.telegram.org")).toBe(true);
    expect(flagExfilRisk("t.me")).toBe(true);
  });

  it("flags a regional/versioned sibling by substring match", () => {
    expect(flagExfilRisk("api2.telegram.org")).toBe(true);
  });

  it("does not flag an ordinary API host", () => {
    expect(flagExfilRisk("api.anthropic.com")).toBe(false);
    expect(flagExfilRisk("pypi.org")).toBe(false);
  });

  it("does not flag a null host (opaque/IP-only observation)", () => {
    expect(flagExfilRisk(null)).toBe(false);
  });

  it("stamps exfil_risk on the folded candidate for a messaging-platform destination", () => {
    const candidates = foldObservations([
      flow({ destination: { host: "hooks.slack.com", ip: "18.0.0.1", port: 443, protocol: "tcp" } }),
    ]);
    expect(candidates[0]!.exfil_risk).toBe(true);
  });
});

describe("mergeCandidateObservations", () => {
  it("bumps times_seen and extends first/last seen when merging into an existing candidate", () => {
    const first = foldObservations([flow({ timestamp: "2026-07-07T10:00:00.000Z" })]);
    const existing = new Map([[candidateKey(first[0]!), first[0]!]]);
    const fresh = foldObservations([flow({ timestamp: "2026-07-07T11:00:00.000Z" })]);

    const merged = mergeCandidateObservations(existing, fresh);
    const key = candidateKey(first[0]!);
    expect(merged.get(key)!.times_seen).toBe(2);
    expect(merged.get(key)!.first_seen).toBe("2026-07-07T10:00:00.000Z");
    expect(merged.get(key)!.last_seen).toBe("2026-07-07T11:00:00.000Z");
  });

  it("inserts a new row for a key not already present, without touching existing rows", () => {
    const first = foldObservations([flow()]);
    const existing = new Map([[candidateKey(first[0]!), first[0]!]]);
    const fresh = foldObservations([
      flow({ destination: { host: "pypi.org", ip: "151.101.0.1", port: 443, protocol: "tcp" } }),
    ]);

    const merged = mergeCandidateObservations(existing, fresh);
    expect(merged.size).toBe(2);
    expect(merged.get(candidateKey(first[0]!))).toEqual(first[0]);
  });
});
