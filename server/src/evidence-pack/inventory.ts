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

import { isIP } from "node:net";

import type { LocalAgentRecord } from "../contracts/v1.1/local-agent-records.js";
import {
  candidateKey,
  candidateKeyDigest,
  flagExfilRisk,
  type CandidateObservation,
  type HostnameSource,
  type ObserveProvenance,
} from "../castle-wall/observe/index.js";
import {
  claimFromVerifiedEmpty,
  verifiedEmptyFrom,
  type SourceReadOutcome,
  type VerifiedEmpty,
} from "../claim-witness.js";
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

type InventorySourceId =
  | "inventory.agents"
  | "inventory.mcp_servers"
  | "inventory.observed_destinations";

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

export const MALFORMED_OBSERVED_DESTINATIONS_REASON =
  "the observe store contained malformed candidate evidence, so observed destinations could not be rendered safely.";

const OBSERVE_CANDIDATE_STORAGE_KEY_PREFIX = "candidate:";
const HOST_LABEL_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/;

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isObservedDeniedCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1;
}

function isValidPort(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 1 &&
    value <= 65535
  );
}

function isValidHost(value: unknown): value is string | null {
  if (value === null) return true;
  if (typeof value !== "string" || value.length === 0 || value.length > 253) {
    return false;
  }
  return (
    !value.startsWith(".") &&
    !value.endsWith(".") &&
    value
      .split(".")
      .every((label) => label.length <= 63 && HOST_LABEL_PATTERN.test(label))
  );
}

function isValidIp(value: unknown): value is string {
  return typeof value === "string" && isIP(value) !== 0;
}

function isValidHostnameSource(value: unknown): value is HostnameSource {
  return (
    value === "dns" ||
    value === "sni" ||
    value === "url" ||
    value === "socket" ||
    value === null
  );
}

function isValidProvenance(value: unknown): value is ObserveProvenance | undefined {
  return value === undefined || value === "macos" || value === "linux_daemon";
}

function isParseableTimestamp(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

/**
 * Strict validation for observe candidates as they cross into a SIGNED evidence
 * pack. The observe consumer keeps its best-effort legacy semantics; this
 * boundary is stricter because every accepted row backs denied-flow prose.
 */
export function validatePersistedObservedDestinationCandidate(
  value: unknown,
  storageKey?: string
): CandidateObservation | null {
  if (!isObject(value)) return null;
  const firstSeen = value.first_seen;
  const lastSeen = value.last_seen;
  if (
    !isNonEmptyString(value.agent_id) ||
    !isNonEmptyString(value.agent_template) ||
    !isValidHost(value.host) ||
    !isValidIp(value.ip) ||
    !isValidPort(value.port) ||
    (value.protocol !== "tcp" && value.protocol !== "udp") ||
    !isValidHostnameSource(value.hostname_source) ||
    !isObservedDeniedCount(value.times_seen) ||
    !isParseableTimestamp(firstSeen) ||
    !isParseableTimestamp(lastSeen) ||
    Date.parse(lastSeen) < Date.parse(firstSeen) ||
    value.would_be_disposition !== "denied" ||
    typeof value.exfil_risk !== "boolean" ||
    !isValidProvenance(value.provenance)
  ) {
    return null;
  }
  const candidate: CandidateObservation = {
    agent_id: value.agent_id,
    agent_template: value.agent_template,
    host: value.host,
    ip: value.ip,
    port: value.port,
    protocol: value.protocol,
    hostname_source: value.hostname_source,
    times_seen: value.times_seen,
    first_seen: firstSeen,
    last_seen: lastSeen,
    would_be_disposition: "denied",
    exfil_risk: value.exfil_risk,
    ...(value.provenance !== undefined ? { provenance: value.provenance } : {}),
  };
  if (candidate.exfil_risk !== flagExfilRisk(candidate.host)) {
    return null;
  }
  if (
    storageKey !== undefined &&
    storageKey !==
      `${OBSERVE_CANDIDATE_STORAGE_KEY_PREFIX}${candidateKeyDigest(candidateKey(candidate))}`
  ) {
    return null;
  }
  return candidate;
}

function validatedObservedDestinationsRead(
  read: InventorySourceRead<CandidateObservation> | undefined
): InventorySourceRead<CandidateObservation> | undefined {
  if (read === undefined || !read.ok) return read;
  if (!Array.isArray(read.records)) {
    return { ok: false, records: [], reason: MALFORMED_OBSERVED_DESTINATIONS_REASON };
  }
  const records: CandidateObservation[] = [];
  for (const raw of read.records as readonly unknown[]) {
    const candidate = validatePersistedObservedDestinationCandidate(raw);
    if (!candidate) {
      return { ok: false, records: [], reason: MALFORMED_OBSERVED_DESTINATIONS_REASON };
    }
    records.push(candidate);
  }
  return { ok: true, records };
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
    exfil_risk: flagExfilRisk(candidate.host),
  };
}

function inventorySourceOutcome<TRaw>(
  sourceId: InventorySourceId,
  read: InventorySourceRead<TRaw> | undefined,
): SourceReadOutcome {
  if (read === undefined) {
    return {
      status: "not-read",
      source_id: sourceId,
      reason: NOT_COLLECTED_REASON,
    };
  }
  if (!read.ok) {
    return {
      status: "read-failed",
      source_id: sourceId,
      reason: read.reason ?? "the source could not be read.",
    };
  }
  return {
    status: "read-and-verified",
    source_id: sourceId,
    record_count: read.records.length,
  };
}

function emptyVerifiedInventory(witness: VerifiedEmpty): ReadOutcome<never[]> {
  return claimFromVerifiedEmpty(witness, emptyVerified());
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
  sourceId: InventorySourceId,
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
  const source = inventorySourceOutcome(sourceId, read);
  if (read.records.length === 0) {
    const witness = verifiedEmptyFrom("evidence-pack.inventory.empty-verified", [source]);
    if (witness === undefined) {
      return readFailed("the inventory source did not produce a verified-empty witness.");
    }
    return emptyVerifiedInventory(witness);
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
  const observedDestinationsRead = validatedObservedDestinationsRead(
    sources.observedDestinations
  );
  const observed_destinations = toOutcome(
    "inventory.observed_destinations",
    observedDestinationsRead,
    destinationRow,
    (a, b) => a.host.localeCompare(b.host) || (a.port ?? 0) - (b.port ?? 0)
  );
  return {
    agents: toOutcome("inventory.agents", sources.agents, agentRow, (a, b) =>
      a.agent_id.localeCompare(b.agent_id)
    ),
    mcp_servers: toOutcome("inventory.mcp_servers", sources.proxyServers, mcpServerRow, (a, b) =>
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
  const agents = verifiedEmptyFrom("evidence-pack.inventory.empty-verified", [
    { status: "read-and-verified", source_id: "inventory.agents", record_count: 0 },
  ]);
  const mcpServers = verifiedEmptyFrom("evidence-pack.inventory.empty-verified", [
    { status: "read-and-verified", source_id: "inventory.mcp_servers", record_count: 0 },
  ]);
  const observedDestinations = verifiedEmptyFrom("evidence-pack.inventory.empty-verified", [
    { status: "read-and-verified", source_id: "inventory.observed_destinations", record_count: 0 },
  ]);
  if (
    agents === undefined ||
    mcpServers === undefined ||
    observedDestinations === undefined
  ) {
    throw new Error("empty inventory snapshot did not produce verified-empty witnesses");
  }
  return {
    agents: emptyVerifiedInventory(agents),
    mcp_servers: emptyVerifiedInventory(mcpServers),
    observed_destinations: emptyVerifiedInventory(observedDestinations),
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
