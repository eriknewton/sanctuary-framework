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
  InventorySection,
  InventorySnapshot,
} from "./types.js";

/**
 * A configured upstream MCP server as read from the sovereignty profile.
 * Mirrors the fields `GET /api/proxy/servers` exposes (name, transport,
 * enabled, connection state, tool count); defined here so the pure collector
 * does not couple to the proxy module's internal types. The CLI populates only
 * the configured fields (name/transport/enabled) because pack generation does
 * NOT open a live connection to probe state or tool counts.
 */
export interface ProxyServerView {
  name: string;
  transport?: string;
  enabled?: boolean;
  connection_state?: string;
  tool_count?: number;
}

/**
 * The read outcome for one source: whether the store was read successfully,
 * the raw records read (empty when genuinely none OR unread), and a reason on
 * failure. Undefined for a source means "not collected" and is treated as a
 * successful empty read (see {@link buildInventorySnapshot}).
 */
export interface InventorySourceRead<T> {
  ok: boolean;
  records: readonly T[];
  reason?: string;
}

/** Raw enumeration sources + their read outcomes, fed into {@link buildInventorySnapshot}. */
export interface InventorySources {
  /** Wrapped-harness / agent records from the hub registry. */
  agents?: InventorySourceRead<LocalAgentRecord>;
  /** Configured MCP servers from the sovereignty profile. */
  proxyServers?: InventorySourceRead<ProxyServerView>;
  /** Observed egress destinations from the observe engine. */
  observedDestinations?: InventorySourceRead<CandidateObservation>;
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
 * Map one source read outcome to an {@link InventorySection}, preserving the
 * read_ok / reason so the renderer can distinguish a genuine empty from a read
 * failure. A read failure yields NO rows (never a partial list presented as
 * complete). An undefined source is treated as a successful empty read.
 */
function toSection<TRaw, TRow>(
  read: InventorySourceRead<TRaw> | undefined,
  map: (raw: TRaw) => TRow,
  sort: (a: TRow, b: TRow) => number
): InventorySection<TRow> {
  if (read === undefined) {
    return { read_ok: true, rows: [] };
  }
  if (!read.ok) {
    return { read_ok: false, rows: [], reason: read.reason };
  }
  const rows = read.records.map(map);
  rows.sort(sort);
  return { read_ok: true, rows };
}

/**
 * Build an {@link InventorySnapshot} from the source read outcomes. Each output
 * section carries its own read_ok so the renderer prints honest language per
 * source. This function NEVER asserts completeness and NEVER presents a partial
 * read as a full one; it only shapes the rows Sanctuary actually read, sorted
 * for stable, deterministic output.
 */
export function buildInventorySnapshot(
  sources: InventorySources
): InventorySnapshot {
  return {
    agents: toSection(sources.agents, agentRow, (a, b) =>
      a.agent_id.localeCompare(b.agent_id)
    ),
    mcp_servers: toSection(sources.proxyServers, mcpServerRow, (a, b) =>
      a.name.localeCompare(b.name)
    ),
    observed_destinations: toSection(
      sources.observedDestinations,
      destinationRow,
      (a, b) => a.host.localeCompare(b.host) || (a.port ?? 0) - (b.port ?? 0)
    ),
  };
}

/** An all-sections successful-empty snapshot (for callers that pass no inventory). */
export function emptyInventorySnapshot(): InventorySnapshot {
  return {
    agents: { read_ok: true, rows: [] },
    mcp_servers: { read_ok: true, rows: [] },
    observed_destinations: { read_ok: true, rows: [] },
  };
}
