/**
 * Adapter: already-decrypted, operator-context `AuditEntry` rows (as
 * returned by `AuditLog.query({ layer: "l1" })`) -> `FlowObservationEvent`,
 * the shape `fold.ts`'s pure core consumes.
 *
 * This is the ONLY place that knows the on-disk shape of a recorded Castle
 * Wall flow event. Real flows are already written to the audit log by
 * `runtime/macos-flow-events.ts` (`handleFlowDecisionRecorded`) and the
 * equivalent Linux daemon audit-drain path (`runtime/audit-consumer.ts`) --
 * this feature adds no new emission, only a reader over what already exists
 * (scoping doc section 2.1).
 *
 * TWO on-disk `details` shapes exist for the SAME `egress_blocked` operation,
 * and this reader handles BOTH (the #897 flat-shape defect: the original
 * reader knew only the nested shape, so it folded ZERO Linux-daemon egress
 * events):
 *
 *   - NESTED (`details.agent` + `details.destination` objects): the macOS
 *     NEFilterDataProvider default-resolver path (`macos-flow-events.ts`
 *     unsigned append). PROVENANCE => `"macos"`.
 *   - FLAT (`details.agent_id` / `details.dest_host` / `details.dest_ip` /
 *     `details.dest_port` / `details.dest_protocol`): the Rust daemon
 *     (`castle-wall-daemon/src/policy.rs` `build_audit_event_canonical_json`)
 *     AND the macOS producer-SIGNED body (`AuditProducerSigning.swift`
 *     `signedDetailsFor`), both preserved verbatim into `entry.details` by
 *     `audit-consumer.ts` `buildDetailsForEvent`. The two flat producers are
 *     told apart by fingerprint: the Rust daemon ALWAYS writes
 *     `decision_provenance` (a field the macOS body never carries) and NEVER a
 *     `source` marker, while the macOS producer-signed body is the inverse
 *     (`source: "macos_extension"`, no `decision_provenance`). A flat row is
 *     `"linux_daemon"` ONLY when it carries `decision_provenance` AND is not
 *     macOS-sourced; a positive `source: "macos_extension"` is an
 *     authoritative macOS override (so even a malformed row carrying both
 *     stays `"macos"`, keeping the safe `"unknown"` exemption). Any other flat
 *     row is `"macos"`. The flat arm keys STRICTLY
 *     on the daemon's `dest_*` destination field names, which the
 *     credential-honeypot audit body (`honeypot/credential-trap-runtime.ts`,
 *     which writes a flat `destination_host` -- the FULL word -- and NO
 *     `dest_port`/`dest_protocol`) does NOT carry, so the honeypot's
 *     `egress_blocked` rows are still dropped, never folded (the anti-honeypot
 *     exclusion is preserved by construction).
 *
 * v1 only extracts `egress_blocked` entries: a denied novel destination is
 * exactly what the enforce-preserving observe posture (D-Q1) needs to
 * propose. An `egress_allowed` entry already has a live rule and is never a
 * promote candidate. Malformed / incomplete entries are skipped, never
 * guessed -- an entry that cannot yield every required field contributes NO
 * candidate rather than a candidate with fabricated data.
 */

import type { AuditEntry } from "../../operational/audit-log.js";
import {
  verifiedCastleWallAuditAttribution,
  type AuditAttributionOptions,
} from "../audit-attribution.js";
import type { FlowObservationEvent, HostnameSource, ObserveProvenance } from "./types.js";

/** The stored `operation` tag for a denied flow (see `runtime/macos-flow-events.ts` / `audit/events.ts` CastleWallEventType). */
const BLOCKED_OPERATION = "egress_blocked";

export type FlowEventAdapterOptions = AuditAttributionOptions;

interface VerifiedFlowAttribution {
  agentId: string;
  agentTemplate: string;
}

function isHostnameSource(value: unknown): value is HostnameSource {
  return value === "dns" || value === "sni" || value === "url" || value === "socket";
}

function isProtocol(value: unknown): value is "tcp" | "udp" {
  return value === "tcp" || value === "udp";
}

/**
 * Adapt a batch of raw audit entries into flow-observation events. Entries
 * whose `operation` is not `egress_blocked`, or whose `details.agent` /
 * `details.destination` do not carry the minimum required fields, are
 * silently skipped (this mirrors `attributeFlows` in
 * `audit/per-rule-report.ts`, which drops entries it cannot attribute rather
 * than guessing).
 *
 * SECURITY (property #11, no-policy-inference): the caller MUST supply
 * operator-context entries only (unredacted `details`). This module has no
 * read-boundary of its own -- it is a pure transform, like
 * `per-rule-report.ts`'s `attributeFlows`.
 */
export function flowEventsFromAuditEntries(
  entries: readonly AuditEntry[],
  options: FlowEventAdapterOptions = {},
): FlowObservationEvent[] {
  const events: FlowObservationEvent[] = [];
  for (const entry of entries) {
    const event = flowEventFromAuditEntry(entry, options);
    if (event) events.push(event);
  }
  return events;
}

/**
 * Adapt ONE raw audit entry, or `null` when it is not an adaptable
 * `egress_blocked` flow record (wrong operation, or missing required
 * fields -- skipped, never guessed). Single-entry form of
 * {@link flowEventsFromAuditEntries}, used by the streaming refresh
 * chokepoint (`refresh.ts`) so entries are adapted-or-dropped as the
 * verified chain streams past instead of materializing an `AuditEntry[]`.
 */
export function flowEventFromAuditEntry(
  entry: AuditEntry,
  options: FlowEventAdapterOptions = {},
): FlowObservationEvent | null {
  if (entry.operation !== BLOCKED_OPERATION) return null;
  const details = entry.details;
  if (!details) return null;
  const attribution = verifiedCastleWallAuditAttribution(entry, options);
  if (attribution === null || attribution.agentTemplate === null) return null;
  const flowAttribution: VerifiedFlowAttribution = {
    agentId: attribution.agentId,
    agentTemplate: attribution.agentTemplate,
  };

  // Try the NESTED shape first (macOS default-resolver path). If its required
  // objects are absent, fall through to the FLAT shape (Linux daemon / macOS
  // producer-signed). The two shapes are mutually exclusive on the wire -- a
  // nested row carries no `dest_*` fields and a flat row carries no
  // `agent`/`destination` objects -- so at most one arm ever yields an event
  // (no double-fold). See the module header for the honeypot exclusion.
  return (
    flowEventFromNestedDetails(entry, details, flowAttribution) ??
    flowEventFromFlatDetails(entry, details, flowAttribution)
  );
}

/**
 * NESTED arm: `details.agent` + `details.destination` objects (the macOS
 * NEFilterDataProvider default-resolver path, `macos-flow-events.ts`).
 * PROVENANCE `"macos"`.
 */
function flowEventFromNestedDetails(
  entry: AuditEntry,
  details: NonNullable<AuditEntry["details"]>,
  attribution: VerifiedFlowAttribution,
): FlowObservationEvent | null {
  const destination = details.destination as
    | {
        host?: unknown;
        ip?: unknown;
        port?: unknown;
        protocol?: unknown;
        hostname_source?: unknown;
      }
    | undefined;
  if (!destination) return null;
  if (typeof destination.port !== "number") return null;
  if (!isProtocol(destination.protocol)) return null;

  const host =
    typeof destination.host === "string" && destination.host.length > 0 ? destination.host : null;
  const ip = typeof destination.ip === "string" ? destination.ip : "";
  if (!host && ip.length === 0) return null;

  return {
    timestamp: entry.timestamp,
    agent: { id: attribution.agentId, template: attribution.agentTemplate },
    destination: { host, ip, port: destination.port, protocol: destination.protocol },
    hostname_source: isHostnameSource(destination.hostname_source) ? destination.hostname_source : null,
    disposition: "denied",
    provenance: "macos",
  };
}

/**
 * FLAT arm: the Rust daemon's / macOS producer-signed body's flat destination
 * fields (`dest_host`/`dest_ip`/`dest_port`/`dest_protocol` + `agent_id`/
 * `agent_template`). Keyed STRICTLY on the daemon's `dest_*` names so the
 * honeypot's flat `destination_host` (no `dest_*`) can never match here
 * (module header). PROVENANCE is `"linux_daemon"` when the daemon's
 * unconditional `decision_provenance` fingerprint is present, else `"macos"`
 * (e.g. a macOS producer-signed body, which carries `source: "macos_extension"`
 * and no `decision_provenance`) -- the conservative direction for the
 * `"unknown"`-template exemption (only a POSITIVELY-identified daemon row loses
 * it; see refresh.ts).
 */
function flowEventFromFlatDetails(
  entry: AuditEntry,
  details: NonNullable<AuditEntry["details"]>,
  attribution: VerifiedFlowAttribution,
): FlowObservationEvent | null {
  const port = details.dest_port;
  if (typeof port !== "number") return null;
  const protocol = details.dest_protocol;
  // v1 SCOPE (parity with the nested arm + fold.ts + the `"tcp" | "udp"`
  // schema): observe models only TCP/UDP egress destinations. The daemon's
  // numeric-string `dest_protocol` fallback for a non-TCP/UDP packet
  // (`nfqueue.rs` protocol_str) is therefore DROPPED here, exactly as the
  // nested arm drops it -- a dropped row is NOT allowed: the wall keeps
  // denying that flow; it simply is not surfaced as a promote candidate (the
  // allowlist rule shape is host/ip:port over tcp/udp). Fails safe.
  if (!isProtocol(protocol)) return null;

  const host =
    typeof details.dest_host === "string" && details.dest_host.length > 0 ? details.dest_host : null;
  const ip = typeof details.dest_ip === "string" ? details.dest_ip : "";
  if (!host && ip.length === 0) return null;

  // The Rust daemon writes `decision_provenance` on EVERY audit body
  // (`policy.rs` build_audit_event_canonical_json, unconditional) and NEVER a
  // `source` marker; the macOS producer-signed body is the inverse -- it
  // carries `source: "macos_extension"` and no `decision_provenance`
  // (`AuditProducerSigning.swift` signedDetailsFor). Classify as the daemon
  // ONLY on the daemon's positive fingerprint AND the ABSENCE of the macOS
  // marker: a positive `source: "macos_extension"` is an authoritative macOS
  // override, so even a malformed/future macOS flat row that also carried a
  // string `decision_provenance` stays `"macos"` and keeps the unattributed
  // `"unknown"` exemption (Codex gate finding 3 -- fail toward NOT suppressing
  // on any macOS-attributable row).
  const provenance: ObserveProvenance =
    typeof details.decision_provenance === "string" && details.source !== "macos_extension"
      ? "linux_daemon"
      : "macos";

  return {
    timestamp: entry.timestamp,
    agent: { id: attribution.agentId, template: attribution.agentTemplate },
    destination: { host, ip, port, protocol },
    // The flat producers carry no per-flow hostname_source field (the daemon's
    // generic destination has none); mirror the nested arm's null default.
    hostname_source: null,
    disposition: "denied",
    provenance,
  };
}
