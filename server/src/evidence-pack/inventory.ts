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
import {
  emptyVerified,
  populated,
  readFailed,
  type ReadOutcome,
} from "./read-outcome.js";

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
 * FAILED read (R3-5, round-3 sweep 2026-07-14): an `EmptyVerified` witness
 * asserts "read to completion, zero records", and a source nobody read can
 * never mint that witness -- otherwise a caller omitting a source would
 * render the definitive "No wrapped AI harnesses are recorded ..." census
 * line from nothing (see {@link buildInventorySnapshot}).
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
  /**
   * R4-2: true when the observe store held candidate rows but NO fold
   * watermark at read time -- a store that has NOT completed a reconciling
   * refresh (a legacy pre-#931 additive store, OR the narrow window of a
   * post-#931 recompute-heal that crashed after writing rows but before
   * advancing the watermark). Surfaced onto
   * {@link InventorySnapshot.observed_destinations_pre_idempotency} (only when
   * the observed-destinations read is populated) so the renderer can disclose
   * that the rows may not reflect a reconciled state. The CLI derives it from
   * `observeStore.getFoldWatermark()`; test fixtures set it directly. See
   * {@link InventorySnapshot} for the full semantics.
   */
  observedStorePreIdempotency?: boolean;
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
 * Map one source read outcome to a {@link ReadOutcome} over its row list,
 * preserving the failure/empty distinction so the renderer prints honest
 * language through the typed chokepoint. A read failure yields `read_failed`
 * with the reason (NEVER a partial list presented as complete); a successful
 * empty read yields `empty_verified` (the only state from which the renderer
 * may assert a definitive "none"); a non-empty read yields `populated` with
 * sorted rows. An undefined (not-collected) source is a FAILED read: only an
 * actual completed read may mint the `EmptyVerified` witness the renderer
 * turns into a definitive "none recorded" census line (R3-5).
 */
function toOutcome<TRaw, TRow>(
  read: InventorySourceRead<TRaw> | undefined,
  map: (raw: TRaw) => TRow,
  sort: (a: TRow, b: TRow) => number
): ReadOutcome<TRow[]> {
  if (read === undefined) {
    return readFailed(NOT_COLLECTED_REASON);
  }
  if (!read.ok) {
    return readFailed(read.reason ?? "the source could not be read.");
  }
  if (read.records.length === 0) {
    return emptyVerified();
  }
  const rows = read.records.map(map);
  rows.sort(sort);
  return populated(rows);
}

/**
 * Build an {@link InventorySnapshot} from the source read outcomes. Each output
 * section is a {@link ReadOutcome} so the renderer prints honest language per
 * source through the typed chokepoint. This function NEVER asserts completeness
 * and NEVER presents a partial read as a full one.
 */
export function buildInventorySnapshot(
  sources: InventorySources
): InventorySnapshot {
  const observed_destinations = toOutcome(
    sources.observedDestinations,
    destinationRow,
    (a, b) => a.host.localeCompare(b.host) || (a.port ?? 0) - (b.port ?? 0)
  );
  return {
    agents: toOutcome(sources.agents, agentRow, (a, b) =>
      a.agent_id.localeCompare(b.agent_id)
    ),
    mcp_servers: toOutcome(sources.proxyServers, mcpServerRow, (a, b) =>
      a.name.localeCompare(b.name)
    ),
    observed_destinations,
    // R4-2: the pre-idempotency staleness disclosure is meaningful ONLY when
    // there are rendered Seen counts to caveat -- i.e. a populated read. A
    // failed/empty observe read renders no counts, so the flag is dropped
    // there to avoid an orphan caveat with no table.
    observed_destinations_pre_idempotency:
      observed_destinations.status === "populated" &&
      sources.observedStorePreIdempotency === true,
  };
}

/** The honest reason rendered for an inventory source this pack run never read (R3-5). */
export const NOT_COLLECTED_REASON =
  "this inventory source was not collected by this pack run, so no census claim is made for it.";

/**
 * An all-sources VERIFIED-EMPTY snapshot. `EmptyVerified` is a witness that a
 * read COMPLETED and found zero records, so this constructor is only for
 * callers (and test fixtures) that genuinely mean "every source was read and
 * each was empty" -- it must never be a default for an inventory nobody
 * collected. For that case use {@link notCollectedInventorySnapshot}, which
 * renders hedged could-not-be-determined language instead of a definitive
 * "none recorded" census (R3-5, round-3 sweep 2026-07-14).
 */
export function emptyInventorySnapshot(): InventorySnapshot {
  return {
    agents: emptyVerified(),
    mcp_servers: emptyVerified(),
    observed_destinations: emptyVerified(),
  };
}

/**
 * The snapshot for a pack built WITHOUT collecting the inventory: every
 * source is a failed (not-collected) read, so the renderer prints "could not
 * be fully determined ... NOT a count of zero" language and never a
 * definitive census line minted from nothing (R3-5). This is the fallback
 * `renderSections` uses when no inventory is supplied.
 */
export function notCollectedInventorySnapshot(): InventorySnapshot {
  return {
    agents: readFailed(NOT_COLLECTED_REASON),
    mcp_servers: readFailed(NOT_COLLECTED_REASON),
    observed_destinations: readFailed(NOT_COLLECTED_REASON),
  };
}
