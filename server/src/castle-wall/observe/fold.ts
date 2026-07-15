/**
 * Pure fold: recorded flow-audit events -> deduped candidate observations
 * (scoping doc section 2.4; CI DoD test 1). No I/O.
 *
 * v1 folds ONLY denied flows into a candidate. Under the enforce-preserving
 * observe posture (D-Q1) an already-allowed flow already matched a live
 * rule, so it is never a promote candidate -- folding only what the wall
 * actually blocked keeps the candidate store an honest "what does my agent
 * still need" list, never a shadow ledger of already-granted traffic.
 */

import { MESSAGING_HOST_DENYLIST } from "../runtime/curated-allowlist.js";
import {
  candidateKey,
  type CandidateObservation,
  type FlowObservationEvent,
  type HostnameSource,
  type ObserveProvenance,
} from "./types.js";

/**
 * D-Q3: flag a candidate whose host matches the messaging-platform exfil
 * denylist. Substring match (case-insensitive), mirroring the documented
 * intent of `MESSAGING_HOST_DENYLIST` (curated-allowlist.ts): a regional or
 * versioned sibling (e.g. `api2.telegram.org`) is caught the same as the
 * canonical host. A null host (opaque/IP-only observation) is never flagged
 * risky by this check -- there is no hostname to compare.
 */
export function flagExfilRisk(host: string | null): boolean {
  if (!host) return false;
  const lower = host.toLowerCase();
  return MESSAGING_HOST_DENYLIST.some((denied) => lower.includes(denied));
}

/** Reject a flow event that is missing the minimum fields a candidate needs. Never guessed, only dropped. */
function isWellFormedFlowEvent(event: FlowObservationEvent): boolean {
  if (!event.agent || typeof event.agent.id !== "string" || event.agent.id.length === 0) return false;
  if (typeof event.agent.template !== "string" || event.agent.template.length === 0) return false;
  const dest = event.destination;
  if (!dest) return false;
  if (typeof dest.port !== "number" || !Number.isInteger(dest.port) || dest.port < 1 || dest.port > 65535) {
    return false;
  }
  if (dest.protocol !== "tcp" && dest.protocol !== "udp") return false;
  // Need SOMETHING to key/match on: a host string, or a non-empty resolved IP.
  const hasHost = typeof dest.host === "string" && dest.host.length > 0;
  const hasIp = typeof dest.ip === "string" && dest.ip.length > 0;
  if (!hasHost && !hasIp) return false;
  return true;
}

/** A later-seen event's hostname_source upgrades the stored one only when it is MORE confident (never downgrades dns/sni/url back to the opaque "socket" source, and never invents a source that was never observed). */
function upgradedHostnameSource(
  stored: HostnameSource,
  incoming: HostnameSource,
): HostnameSource {
  if (stored === "socket" && incoming && incoming !== "socket") return incoming;
  return stored;
}

/**
 * Fold two contributing events' provenance for the SAME candidate key
 * (`candidateKey` intentionally excludes provenance, so a destination the
 * agent hit on both platforms coalesces into one row). CONSERVATIVE:
 * `"linux_daemon"` -- the only value that DROPS the `"unknown"`-template
 * suppression exemption (refresh.ts) -- survives ONLY when BOTH contributors
 * were the Linux daemon. Any macOS or unattributed (`undefined`) contribution
 * keeps the row non-daemon, so a mixed-origin `"unknown"` row is never
 * suppressed on the strength of the daemon half alone. A positive macOS marker
 * is preferred over `undefined` for label fidelity; the exemption only ever
 * checks `!== "linux_daemon"`, so all non-daemon results behave identically.
 */
function mergedProvenance(
  a: ObserveProvenance | undefined,
  b: ObserveProvenance | undefined,
): ObserveProvenance | undefined {
  if (a === b) return a;
  if (a === "macos" || b === "macos") return "macos";
  // Remaining: exactly one side is "linux_daemon" and the other is undefined.
  // Not positively macOS, but not purely daemon either -> conservative unknown.
  return undefined;
}

/**
 * Fold a batch of flow-audit events into deduped candidate rows. Dedup key
 * is (agent template, host-or-ip, port, protocol) per scoping doc section
 * 2.1. Deterministic output order (sorted by first_seen, then key) so
 * repeated folds of the same fixture are byte-comparable in tests.
 */
export function foldObservations(
  events: readonly FlowObservationEvent[],
): CandidateObservation[] {
  const byKey = new Map<string, CandidateObservation>();

  for (const event of events) {
    if (event.disposition !== "denied") continue;
    if (!isWellFormedFlowEvent(event)) continue;

    const dest = event.destination;
    const key = candidateKey({
      agent_template: event.agent.template,
      host: dest.host,
      ip: dest.ip,
      port: dest.port,
      protocol: dest.protocol,
    });

    const existing = byKey.get(key);
    if (existing) {
      existing.times_seen += 1;
      if (event.timestamp < existing.first_seen) existing.first_seen = event.timestamp;
      if (event.timestamp > existing.last_seen) existing.last_seen = event.timestamp;
      existing.hostname_source = upgradedHostnameSource(existing.hostname_source, event.hostname_source);
      existing.provenance = mergedProvenance(existing.provenance, event.provenance);
      continue;
    }

    byKey.set(key, {
      agent_id: event.agent.id,
      agent_template: event.agent.template,
      host: dest.host,
      ip: dest.ip,
      port: dest.port,
      protocol: dest.protocol,
      hostname_source: event.hostname_source,
      times_seen: 1,
      first_seen: event.timestamp,
      last_seen: event.timestamp,
      would_be_disposition: "denied",
      exfil_risk: flagExfilRisk(dest.host),
      provenance: event.provenance,
    });
  }

  return [...byKey.values()].sort((a, b) => {
    if (a.first_seen !== b.first_seen) return a.first_seen < b.first_seen ? -1 : 1;
    const aKey = candidateKey(a);
    const bKey = candidateKey(b);
    return aKey < bKey ? -1 : aKey > bKey ? 1 : 0;
  });
}

/**
 * Merge freshly folded observations into an EXISTING candidate map (keyed by
 * `candidateKey`). Pure: takes and returns plain data, no I/O. Bumps
 * times_seen and extends first/last-seen for a key that already exists;
 * inserts a new row otherwise. Never touches anything outside the returned
 * map -- callers own persistence.
 *
 * PRECONDITION (sweep finding R3-1): the merge is ADDITIVE, so it is only
 * correct when every underlying flow event is folded EXACTLY ONCE across
 * all merges. The refresh chokepoint (`refresh.ts`) guarantees that with
 * its persisted fold watermark; do not call this with a re-fold of history
 * that a previous merge already consumed -- that is precisely the
 * times_seen-inflation defect the watermark exists to prevent.
 */
export function mergeCandidateObservations(
  existing: ReadonlyMap<string, CandidateObservation>,
  freshlyFolded: readonly CandidateObservation[],
): Map<string, CandidateObservation> {
  const merged = new Map(existing);
  for (const incoming of freshlyFolded) {
    const key = candidateKey(incoming);
    const prior = merged.get(key);
    if (!prior) {
      merged.set(key, { ...incoming });
      continue;
    }
    merged.set(key, {
      ...prior,
      times_seen: prior.times_seen + incoming.times_seen,
      first_seen: incoming.first_seen < prior.first_seen ? incoming.first_seen : prior.first_seen,
      last_seen: incoming.last_seen > prior.last_seen ? incoming.last_seen : prior.last_seen,
      hostname_source: upgradedHostnameSource(prior.hostname_source, incoming.hostname_source),
      provenance: mergedProvenance(prior.provenance, incoming.provenance),
    });
  }
  return merged;
}
