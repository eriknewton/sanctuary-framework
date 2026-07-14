/**
 * Sanctuary MCP Server - Evidence Pack inventory-collector tests
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pure, hermetic tests for the inventory collector: the mapping from the three
 * shipped enumeration sources into a per-source {@link ReadOutcome}, including
 * the ok+empty vs failed+reason distinction that the typed chokepoint enforces.
 */

import { describe, it, expect } from "vitest";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import type { CandidateObservation } from "../../src/castle-wall/observe/types.js";
import {
  buildInventorySnapshot,
  emptyInventorySnapshot,
  notCollectedInventorySnapshot,
  type ProxyServerView,
} from "../../src/evidence-pack/inventory.js";
import type {
  InventoryAgentRow,
  InventoryMcpServerRow,
  InventoryObservedDestinationRow,
} from "../../src/evidence-pack/types.js";
import type { ReadOutcome } from "../../src/evidence-pack/read-outcome.js";

function rowsOf<T>(o: ReadOutcome<T[]>): T[] {
  return o.status === "populated" ? o.value : [];
}

function agentRecord(over: Partial<LocalAgentRecord>): LocalAgentRecord {
  return {
    version: "1.1",
    agent_id: "agent-x",
    identity_id: "id-1",
    harness: "claude_code",
    model_provider: { vendor: "anthropic", model_id: "claude-opus-4", runs_locally: false },
    policy_id: "pol-1",
    status: "active",
    budget_summary: { last_refreshed_at: "2026-08-01T00:00:00.000Z" },
    last_activity_at: "2026-08-10T00:00:00.000Z",
    wrapped_at: "2026-07-15T00:00:00.000Z",
    capabilities: {
      can_pause: true,
      can_resume: true,
      can_restart: true,
      can_unwrap: true,
      can_lockdown: true,
      can_chat: true,
      can_change_template: true,
    },
    ...over,
  };
}

function candidate(over: Partial<CandidateObservation>): CandidateObservation {
  return {
    agent_id: "agent-x",
    agent_template: "coding-assistant",
    host: "api.openai.com",
    ip: "1.2.3.4",
    port: 443,
    protocol: "tcp",
    hostname_source: "sni",
    times_seen: 3,
    first_seen: "2026-08-01T00:00:00.000Z",
    last_seen: "2026-08-10T00:00:00.000Z",
    would_be_disposition: "denied",
    exfil_risk: false,
    ...over,
  };
}

describe("buildInventorySnapshot", () => {
  it("maps agent records to a populated outcome and sorts the rows", () => {
    const snap = buildInventorySnapshot({
      agents: {
        ok: true,
        records: [
          agentRecord({ agent_id: "zeta", harness: "cursor" }),
          agentRecord({ agent_id: "alpha", harness: "hermes" }),
        ],
      },
    });
    expect(snap.agents.status).toBe("populated");
    const rows = rowsOf<InventoryAgentRow>(snap.agents);
    expect(rows.map((a) => a.agent_id)).toEqual(["alpha", "zeta"]);
    const alpha = rows[0]!;
    expect(alpha.harness).toBe("hermes");
    expect(alpha.model_vendor).toBe("anthropic");
    expect(alpha.model_id).toBe("claude-opus-4");
    expect(alpha.wrapped_at).toBe("2026-07-15T00:00:00.000Z");
  });

  it("maps proxy servers to a populated outcome and sorts them", () => {
    const servers: ProxyServerView[] = [
      { name: "weather", transport: "stdio", enabled: true },
      { name: "email", transport: "http", enabled: false },
    ];
    const snap = buildInventorySnapshot({ proxyServers: { ok: true, records: servers } });
    expect(rowsOf<InventoryMcpServerRow>(snap.mcp_servers).map((s) => s.name)).toEqual([
      "email",
      "weather",
    ]);
  });

  it("maps observed destinations, falling back to the IP when no hostname was seen", () => {
    const snap = buildInventorySnapshot({
      observedDestinations: {
        ok: true,
        records: [
          candidate({ host: "api.openai.com", port: 443, exfil_risk: true }),
          candidate({ host: null, ip: "9.9.9.9", port: 8080 }),
        ],
      },
    });
    const rows = rowsOf<InventoryObservedDestinationRow>(snap.observed_destinations);
    expect(rows.map((d) => d.host)).toEqual(["9.9.9.9", "api.openai.com"]);
    const openai = rows.find((d) => d.host === "api.openai.com")!;
    expect(openai.exfil_risk).toBe(true);
  });

  it("a failed source is read_failed with a reason and NO rows (never a partial list)", () => {
    const snap = buildInventorySnapshot({
      agents: { ok: false, records: [], reason: "profile could not be read" },
    });
    expect(snap.agents.status).toBe("read_failed");
    if (snap.agents.status === "read_failed") {
      expect(snap.agents.reason).toBe("profile could not be read");
    }
    expect(rowsOf(snap.agents)).toEqual([]);
  });

  it("a successful empty read is empty_verified (a genuine 'none', the only definitive-negative source)", () => {
    const snap = buildInventorySnapshot({ agents: { ok: true, records: [] } });
    expect(snap.agents.status).toBe("empty_verified");
  });

  it("R3-5: an undefined (not-collected) source is a FAILED read, never a minted EmptyVerified witness", () => {
    const snap = buildInventorySnapshot({});
    for (const source of [snap.agents, snap.mcp_servers, snap.observed_destinations]) {
      expect(source.status).toBe("read_failed");
      if (source.status === "read_failed") {
        expect(source.reason).toContain("not collected");
      }
    }
  });

  it("emptyInventorySnapshot stays all empty_verified (an EXPLICIT verified-empty constructor, never a not-collected default)", () => {
    const empty = emptyInventorySnapshot();
    expect(empty.agents.status).toBe("empty_verified");
    expect(empty.mcp_servers.status).toBe("empty_verified");
    expect(empty.observed_destinations.status).toBe("empty_verified");
  });

  it("R3-5: notCollectedInventorySnapshot is all read_failed with the not-collected reason", () => {
    const snap = notCollectedInventorySnapshot();
    for (const source of [snap.agents, snap.mcp_servers, snap.observed_destinations]) {
      expect(source.status).toBe("read_failed");
      if (source.status === "read_failed") {
        expect(source.reason).toContain("not collected");
      }
    }
  });

  it("a populated section carries only { status, value } - no completeness/total flag", () => {
    const snap = buildInventorySnapshot({
      agents: { ok: true, records: [agentRecord({ agent_id: "a" })] },
    });
    expect(Object.keys(snap.agents).sort()).toEqual(["status", "value"]);
  });
});
