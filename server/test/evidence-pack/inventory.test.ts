/**
 * Sanctuary MCP Server - Evidence Pack inventory-collector tests (slice 2)
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pure, hermetic tests for the inventory collector: the mapping from the three
 * shipped enumeration sources (agent registry, proxy servers, observe
 * candidates) into the InventorySnapshot the section renderer consumes. No
 * server boot, no real fortress.
 */

import { describe, it, expect } from "vitest";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import type { CandidateObservation } from "../../src/castle-wall/observe/types.js";
import {
  buildInventorySnapshot,
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
  it("maps agent records to inventory rows and sorts them", () => {
    const snap = buildInventorySnapshot({
      agentRecords: [
        agentRecord({ agent_id: "zeta", harness: "cursor" }),
        agentRecord({ agent_id: "alpha", harness: "hermes" }),
      ],
    });
    expect(snap.agents?.map((a) => a.agent_id)).toEqual(["alpha", "zeta"]);
    const alpha = snap.agents![0]!;
    expect(alpha.harness).toBe("hermes");
    expect(alpha.model_vendor).toBe("anthropic");
    expect(alpha.model_id).toBe("claude-opus-4");
    expect(alpha.wrapped_at).toBe("2026-07-15T00:00:00.000Z");
    expect(alpha.status).toBe("active");
  });

  it("maps proxy servers to rows and sorts them", () => {
    const servers: ProxyServerView[] = [
      { name: "weather", transport: "stdio", enabled: true, connection_state: "connected", tool_count: 4 },
      { name: "email", transport: "http", enabled: false, connection_state: "disconnected", tool_count: 0 },
    ];
    const snap = buildInventorySnapshot({ proxyServers: servers });
    expect(snap.mcp_servers?.map((s) => s.name)).toEqual(["email", "weather"]);
    expect(snap.mcp_servers![1]!.tool_count).toBe(4);
  });

  it("maps observed destinations, falling back to the IP when no hostname was seen", () => {
    const snap = buildInventorySnapshot({
      observedDestinations: [
        candidate({ host: "api.openai.com", port: 443, exfil_risk: true }),
        candidate({ host: null, ip: "9.9.9.9", port: 8080 }),
      ],
    });
    const rows = snap.observed_destinations!;
    // Sorted by host (the null-host row falls back to its IP "9.9.9.9").
    expect(rows.map((d) => d.host)).toEqual(["9.9.9.9", "api.openai.com"]);
    const openai = rows.find((d) => d.host === "api.openai.com")!;
    expect(openai.port).toBe(443);
    expect(openai.protocol).toBe("tcp");
    expect(openai.exfil_risk).toBe(true);
  });

  it("yields an empty snapshot (no source keys) when there is nothing to enumerate", () => {
    const snap = buildInventorySnapshot({});
    expect(snap.agents).toBeUndefined();
    expect(snap.mcp_servers).toBeUndefined();
    expect(snap.observed_destinations).toBeUndefined();
  });

  it("never adds a completeness flag or total to the snapshot", () => {
    const snap = buildInventorySnapshot({
      agentRecords: [agentRecord({ agent_id: "a" })],
    });
    // The snapshot shape is exactly the three optional row arrays; there is no
    // "complete" / "total" / "exhaustive" field the report could render as a
    // coverage claim.
    expect(Object.keys(snap).sort()).toEqual(["agents"]);
  });
});
