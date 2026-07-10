/**
 * Sanctuary MCP Server - Evidence Pack inventory-collector tests (slice 2)
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pure, hermetic tests for the inventory collector: the mapping from the three
 * shipped enumeration sources (agent registry, proxy servers, observe
 * candidates) into the InventorySnapshot the section renderer consumes,
 * including the per-source read outcome (ok+empty vs failed+reason). No server
 * boot, no real fortress.
 */

import { describe, it, expect } from "vitest";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import type { CandidateObservation } from "../../src/castle-wall/observe/types.js";
import {
  buildInventorySnapshot,
  emptyInventorySnapshot,
  type ProxyServerView,
} from "../../src/evidence-pack/inventory.js";

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
  it("maps agent records to inventory rows and sorts them (read_ok)", () => {
    const snap = buildInventorySnapshot({
      agents: {
        ok: true,
        records: [
          agentRecord({ agent_id: "zeta", harness: "cursor" }),
          agentRecord({ agent_id: "alpha", harness: "hermes" }),
        ],
      },
    });
    expect(snap.agents.read_ok).toBe(true);
    expect(snap.agents.rows.map((a) => a.agent_id)).toEqual(["alpha", "zeta"]);
    const alpha = snap.agents.rows[0]!;
    expect(alpha.harness).toBe("hermes");
    expect(alpha.model_vendor).toBe("anthropic");
    expect(alpha.model_id).toBe("claude-opus-4");
    expect(alpha.wrapped_at).toBe("2026-07-15T00:00:00.000Z");
    expect(alpha.status).toBe("active");
  });

  it("maps proxy servers to rows and sorts them", () => {
    const servers: ProxyServerView[] = [
      { name: "weather", transport: "stdio", enabled: true },
      { name: "email", transport: "http", enabled: false },
    ];
    const snap = buildInventorySnapshot({
      proxyServers: { ok: true, records: servers },
    });
    expect(snap.mcp_servers.rows.map((s) => s.name)).toEqual(["email", "weather"]);
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
    const rows = snap.observed_destinations.rows;
    expect(rows.map((d) => d.host)).toEqual(["9.9.9.9", "api.openai.com"]);
    const openai = rows.find((d) => d.host === "api.openai.com")!;
    expect(openai.port).toBe(443);
    expect(openai.exfil_risk).toBe(true);
  });

  it("MED-2: a failed source is read_ok=false with a reason and NO rows (never a partial list)", () => {
    const snap = buildInventorySnapshot({
      agents: { ok: false, records: [], reason: "profile could not be read" },
      proxyServers: { ok: false, records: [], reason: "boom" },
    });
    expect(snap.agents.read_ok).toBe(false);
    expect(snap.agents.rows).toEqual([]);
    expect(snap.agents.reason).toBe("profile could not be read");
    expect(snap.mcp_servers.read_ok).toBe(false);
  });

  it("a successful empty read is read_ok=true with no rows (a genuine 'none')", () => {
    const snap = buildInventorySnapshot({ agents: { ok: true, records: [] } });
    expect(snap.agents.read_ok).toBe(true);
    expect(snap.agents.rows).toEqual([]);
    expect(snap.agents.reason).toBeUndefined();
  });

  it("an undefined source defaults to a successful empty read; emptyInventorySnapshot is all-ok-empty", () => {
    const snap = buildInventorySnapshot({});
    expect(snap.agents.read_ok).toBe(true);
    expect(snap.mcp_servers.read_ok).toBe(true);
    expect(snap.observed_destinations.read_ok).toBe(true);
    const empty = emptyInventorySnapshot();
    expect(empty.agents.rows).toEqual([]);
    expect(empty.mcp_servers.read_ok).toBe(true);
    expect(empty.observed_destinations.rows).toEqual([]);
  });

  it("the snapshot section shape carries no completeness/total flag", () => {
    const snap = buildInventorySnapshot({
      agents: { ok: true, records: [agentRecord({ agent_id: "a" })] },
    });
    // Each section is exactly { read_ok, rows, reason? } - no "complete" /
    // "total" / "exhaustive" field the report could render as a coverage claim.
    expect(Object.keys(snap.agents).sort()).toEqual(["read_ok", "rows"]);
  });
});
