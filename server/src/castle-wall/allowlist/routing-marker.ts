/**
 * The exclusive-routing MODE MARKER (Unified Protect Slice 5 S5-6): the
 * durable, fortress-persisted declaration that an agent was provisioned in
 * FINE-GRAINED (exclusive-egress) mode, and the principals the manifest must
 * be composed for.
 *
 * WHY A MARKER FILE: the S5-4 exclusive composition
 * (`composeExclusiveRoutingRules`) is a pure library; the signing daemon
 * (`castle-wall/runtime/macos-daemon.ts`) is the ONLY real manifest producer.
 * For the compose-time assertion ("no agent-reachable direct endpoint allow
 * survives in exclusive mode -- fail-closed: no manifest") to be a real
 * chokepoint rather than a flow-side courtesy check, the daemon itself must
 * know the routing mode at every compose (initial load AND every reload).
 * This marker is that knowledge: written by the S5-6 install flow when the
 * exclusive bring-up publishes the manifest (G4), removed by the degrade-loud
 * coarse restore and by unprotect. It also serves as S5-P's
 * `fine_grained_declared` durable intent for the posture producer.
 *
 * FAIL-CLOSED PARSE CONTRACT: a PRESENT-but-malformed marker THROWS (the
 * daemon then refuses to compose a manifest at all) -- never "ignore and
 * compose coarse", because composing coarse without the gate rule while the
 * pf anchor confines the agent's loopback to a gate port would silently
 * confine the agent into non-functionality with a green-looking manifest, and
 * composing coarse with agent-scoped rules while exclusive intent stands
 * would be the exact silent widening BLOCKER-1 forbids. Absent marker =
 * coarse mode (today's behavior, byte-unchanged).
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";

/** Marker filename under `<fortress>/policy/egress/`. */
export const EXCLUSIVE_ROUTING_MARKER_FILENAME = "exclusive-routing.json";

/** On-disk schema version. */
export const EXCLUSIVE_ROUTING_MARKER_VERSION = 1 as const;

/** The marker payload. */
export interface ExclusiveRoutingMarker {
  version: typeof EXCLUSIVE_ROUTING_MARKER_VERSION;
  mode: "exclusive";
  /** The confined agent service-account uid. */
  agent_uid: number;
  /** The dedicated sanctuary-gate service-account uid (the S5-0 second principal). */
  gate_uid: number;
  /**
   * The confined agent's id + template identity (the S5-4 assertion needs
   * them to classify `agent_ids`/`template_ids`-scoped rules -- fail-closed
   * means no guessing).
   */
  agent_id: string;
  agent_template: string;
}

const SAFE_IDENTITY_RE = /^[A-Za-z0-9._-]{1,128}$/;

/** Absolute marker path for a fortress. */
export function exclusiveRoutingMarkerPath(fortressPath: string): string {
  return join(fortressPath, "policy", "egress", EXCLUSIVE_ROUTING_MARKER_FILENAME);
}

/** A present marker failed validation. The daemon must refuse to compose. */
export class ExclusiveRoutingMarkerError extends Error {
  constructor(message: string) {
    super(`exclusive-routing marker: ${message}`);
    this.name = "ExclusiveRoutingMarkerError";
  }
}

/**
 * Strict-parse a marker document. Throws {@link ExclusiveRoutingMarkerError}
 * on ANY deviation (unknown version, wrong mode literal, non-positive or
 * colliding uids) -- a malformed marker must never be read as either mode.
 */
export function parseExclusiveRoutingMarker(text: string, path: string): ExclusiveRoutingMarker {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new ExclusiveRoutingMarkerError(
      `${path} is not valid JSON (${(err as Error).message}); refusing to compose a manifest under an unreadable routing mode`,
    );
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new ExclusiveRoutingMarkerError(`${path} is not a JSON object`);
  }
  const record = parsed as Record<string, unknown>;
  if (record.version !== EXCLUSIVE_ROUTING_MARKER_VERSION) {
    throw new ExclusiveRoutingMarkerError(
      `${path} has unsupported version ${String(record.version)} (expected ${EXCLUSIVE_ROUTING_MARKER_VERSION})`,
    );
  }
  if (record.mode !== "exclusive") {
    throw new ExclusiveRoutingMarkerError(
      `${path} has mode ${JSON.stringify(record.mode)} (only "exclusive" is valid; coarse mode is marker-ABSENT)`,
    );
  }
  const agentUid = record.agent_uid;
  const gateUid = record.gate_uid;
  if (typeof agentUid !== "number" || !Number.isInteger(agentUid) || agentUid <= 0) {
    throw new ExclusiveRoutingMarkerError(`${path} agent_uid must be a positive integer`);
  }
  if (typeof gateUid !== "number" || !Number.isInteger(gateUid) || gateUid <= 0) {
    throw new ExclusiveRoutingMarkerError(`${path} gate_uid must be a positive integer`);
  }
  if (agentUid === gateUid) {
    throw new ExclusiveRoutingMarkerError(
      `${path} agent_uid and gate_uid are both ${agentUid}; the two confined principals must be distinct`,
    );
  }
  const agentId = record.agent_id;
  const agentTemplate = record.agent_template;
  if (typeof agentId !== "string" || !SAFE_IDENTITY_RE.test(agentId)) {
    throw new ExclusiveRoutingMarkerError(`${path} agent_id is missing or not a safe identifier`);
  }
  if (typeof agentTemplate !== "string" || !SAFE_IDENTITY_RE.test(agentTemplate)) {
    throw new ExclusiveRoutingMarkerError(`${path} agent_template is missing or not a safe identifier`);
  }
  return {
    version: EXCLUSIVE_ROUTING_MARKER_VERSION,
    mode: "exclusive",
    agent_uid: agentUid,
    gate_uid: gateUid,
    agent_id: agentId,
    agent_template: agentTemplate,
  };
}

/** Render the canonical marker document (validates by round-trip). */
export function renderExclusiveRoutingMarker(marker: {
  agent_uid: number;
  gate_uid: number;
  agent_id: string;
  agent_template: string;
}): string {
  const text = JSON.stringify(
    {
      version: EXCLUSIVE_ROUTING_MARKER_VERSION,
      mode: "exclusive",
      agent_uid: marker.agent_uid,
      gate_uid: marker.gate_uid,
      agent_id: marker.agent_id,
      agent_template: marker.agent_template,
    },
    null,
    2,
  );
  parseExclusiveRoutingMarker(text, "(render)");
  return `${text}\n`;
}

/**
 * Load the marker for a fortress: `null` when ABSENT (coarse mode, today's
 * behavior); the parsed marker when present and valid; THROWS when present
 * but malformed (the caller must refuse to compose -- fail-closed).
 */
export async function loadExclusiveRoutingMarker(
  fortressPath: string,
): Promise<ExclusiveRoutingMarker | null> {
  const path = exclusiveRoutingMarkerPath(fortressPath);
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new ExclusiveRoutingMarkerError(
      `cannot read ${path} (${(err as Error).message}); refusing to compose a manifest under an unknown routing mode`,
    );
  }
  return parseExclusiveRoutingMarker(text, path);
}
