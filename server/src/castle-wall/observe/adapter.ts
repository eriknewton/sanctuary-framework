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
 * v1 only extracts `egress_blocked` entries: a denied novel destination is
 * exactly what the enforce-preserving observe posture (D-Q1) needs to
 * propose. An `egress_allowed` entry already has a live rule and is never a
 * promote candidate. Malformed / incomplete entries are skipped, never
 * guessed -- an entry that cannot yield every required field contributes NO
 * candidate rather than a candidate with fabricated data.
 */

import type { AuditEntry } from "../../operational/audit-log.js";
import type { FlowObservationEvent, HostnameSource } from "./types.js";

/** The stored `operation` tag for a denied flow (see `runtime/macos-flow-events.ts` / `audit/events.ts` CastleWallEventType). */
const BLOCKED_OPERATION = "egress_blocked";

function isHostnameSource(value: unknown): value is HostnameSource {
  return value === "dns" || value === "sni" || value === "url" || value === "socket";
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
): FlowObservationEvent[] {
  const events: FlowObservationEvent[] = [];

  for (const entry of entries) {
    if (entry.operation !== BLOCKED_OPERATION) continue;
    const details = entry.details;
    if (!details) continue;

    const agent = details.agent as { id?: unknown; template?: unknown } | undefined;
    if (!agent || typeof agent.id !== "string" || typeof agent.template !== "string") continue;

    const destination = details.destination as
      | {
          host?: unknown;
          ip?: unknown;
          port?: unknown;
          protocol?: unknown;
          hostname_source?: unknown;
        }
      | undefined;
    if (!destination) continue;
    if (typeof destination.port !== "number") continue;
    if (destination.protocol !== "tcp" && destination.protocol !== "udp") continue;

    const host =
      typeof destination.host === "string" && destination.host.length > 0 ? destination.host : null;
    const ip = typeof destination.ip === "string" ? destination.ip : "";
    if (!host && ip.length === 0) continue;

    events.push({
      timestamp: entry.timestamp,
      agent: { id: agent.id, template: agent.template },
      destination: { host, ip, port: destination.port, protocol: destination.protocol },
      hostname_source: isHostnameSource(destination.hostname_source) ? destination.hostname_source : null,
      disposition: "denied",
    });
  }

  return events;
}
