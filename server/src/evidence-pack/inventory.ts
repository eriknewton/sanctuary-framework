/**
 * Sanctuary MCP Server - Law-firm Evidence Pack: inventory collector
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Slice 2: turns the AI-tool inventory (CNA Question 1) from a labeled
 * placeholder into REAL enumerated content. This module is the PURE mapping
 * from the three shipped enumeration sources into the `InventorySnapshot` the
 * section renderer already consumes:
 *
 *  1. Wrapped harnesses / agents  -> the hub agent registry `LocalAgentRecord`.
 *  2. Connected MCP tool servers  -> the proxy router's per-server view.
 *  3. Observed egress destinations -> the #897 deny-and-record observe engine's
 *     `CandidateObservation` rows (destination metadata only, never payloads).
 *
 * It is pure over injected raw sources, so tests exercise the real mapping with
 * fixtures and never touch a live fortress. The CLI (`cli.ts`) resolves the raw
 * sources from a running server and passes them here.
 *
 * PARAMOUNT HONESTY BOUND (carried from slice 1, must never regress): a
 * POPULATED inventory is STILL not exhaustive. Sanctuary enumerates only what
 * it wraps, what flows through its gates, and (on enforced machines) what its
 * observe engine records. Browser ChatGPT, Copilot inside Office, and phones
 * are invisible. This collector only shapes rows; the coverage-basis disclosure
 * that says exactly this lives in the inventory section renderer and is printed
 * whether the inventory is empty OR full. This module never adds a
 * completeness claim, a total, or a "fully covered" flag.
 */

import type { LocalAgentRecord } from "../contracts/v1.1/local-agent-records.js";
import type { CandidateObservation } from "../castle-wall/observe/types.js";
import type {
  InventoryAgentRow,
  InventoryMcpServerRow,
  InventoryObservedDestinationRow,
  InventorySnapshot,
} from "./types.js";

/**
 * A connected upstream MCP server as seen by the proxy router. Mirrors the
 * fields `GET /api/proxy/servers` exposes (name, transport, enabled,
 * connection state, tool count); defined here so the pure collector does not
 * couple to the proxy module's internal types. The CLI maps the proxy router's
 * output into this shape.
 */
export interface ProxyServerView {
  name: string;
  transport?: string;
  enabled?: boolean;
  connection_state?: string;
  tool_count?: number;
}

/** Raw enumeration sources fed into {@link buildInventorySnapshot}. */
export interface InventorySources {
  /** Wrapped-harness / agent records from the hub registry (or empty). */
  agentRecords?: readonly LocalAgentRecord[];
  /** Connected MCP servers from the proxy router (or empty). */
  proxyServers?: readonly ProxyServerView[];
  /** Observed egress destinations from the observe engine (or empty). */
  observedDestinations?: readonly CandidateObservation[];
}

/** Map one `LocalAgentRecord` to the inventory row shape. */
function agentRow(record: LocalAgentRecord): InventoryAgentRow {
  return {
    agent_id: record.agent_id,
    harness: record.harness,
    model_vendor: record.model_provider?.vendor,
    model_id: record.model_provider?.model_id,
    wrapped_at: record.wrapped_at,
    status: record.status,
  };
}

/** Map one proxy server view to the inventory row shape. */
function mcpServerRow(server: ProxyServerView): InventoryMcpServerRow {
  return {
    name: server.name,
    transport: server.transport,
    enabled: server.enabled,
    connection_state: server.connection_state,
    tool_count: server.tool_count,
  };
}

/**
 * Map one observed destination to the inventory row shape. `host` is null when
 * only an IP was seen (no hostname resolved), so the row falls back to the IP;
 * this is destination metadata only, never payload content.
 */
function destinationRow(
  candidate: CandidateObservation
): InventoryObservedDestinationRow {
  return {
    host: candidate.host ?? candidate.ip,
    port: candidate.port,
    protocol: candidate.protocol,
    times_seen: candidate.times_seen,
    exfil_risk: candidate.exfil_risk,
  };
}

/**
 * Build an {@link InventorySnapshot} from the raw enumeration sources. Any
 * absent/empty source yields an absent section (the renderer then prints its
 * honest placeholder + coverage-basis note). This function NEVER asserts
 * completeness; it only shapes the rows Sanctuary can actually see. Rows are
 * sorted for stable, deterministic output.
 */
export function buildInventorySnapshot(
  sources: InventorySources
): InventorySnapshot {
  const snapshot: InventorySnapshot = {};

  const agents = (sources.agentRecords ?? []).map(agentRow);
  if (agents.length > 0) {
    agents.sort((a, b) => a.agent_id.localeCompare(b.agent_id));
    snapshot.agents = agents;
  }

  const servers = (sources.proxyServers ?? []).map(mcpServerRow);
  if (servers.length > 0) {
    servers.sort((a, b) => a.name.localeCompare(b.name));
    snapshot.mcp_servers = servers;
  }

  const destinations = (sources.observedDestinations ?? []).map(destinationRow);
  if (destinations.length > 0) {
    destinations.sort(
      (a, b) =>
        a.host.localeCompare(b.host) || (a.port ?? 0) - (b.port ?? 0)
    );
    snapshot.observed_destinations = destinations;
  }

  return snapshot;
}
