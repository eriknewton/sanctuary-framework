/**
 * Neutral type home for the composed posture-home payload (`PostureHome`).
 *
 * This module breaks the `posture-routes` <-> `posture-stream`
 * import cycle. Both the route layer (which builds the payload) and the SSE
 * stream handler (which pushes it) need the `PostureHome` shape; if the shape
 * lived in `posture-routes.ts`, the stream's `type`-only import of it would
 * close a cycle (`posture-routes` imports the stream handler; the stream would
 * import the type back). It cannot live in `posture.ts` either, because the
 * payload draws field types from `feature-health.ts` and
 * `posture-query-privacy.ts`, both of which already import `posture.ts` -
 * pulling those into `posture.ts` would just relocate the cycle.
 *
 * So `PostureHome` lives here, importing its field types from the three shaper
 * modules that all sit strictly LOWER in the dependency DAG (`posture.ts`,
 * `feature-health.ts`, `posture-query-privacy.ts`, none of which import
 * `posture-routes.ts` or `posture-stream.ts`). The result is one-directional
 * and acyclic: routes and stream both depend on this module; this module
 * depends only on the shapers.
 *
 * The shared audit display-age bound and browser timestamp parser live here
 * so the three renderers do not depend on each other. It adds no member to the payload.
 */

import type { ProducerKeyObservation, PosturePanelId, PosturePanelStatus } from "./panel-producer.js";

import type {
  CastleWallPosture,
  AuditDigest,
  UnwrappedRoster,
  PostureAgentRow,
  CustodyExitPanel,
} from "./posture.js";
import type { FeatureHealthPanel } from "./feature-health.js";
import type { QueryPrivacySection } from "./posture-query-privacy.js";

/** Maximum observation age accepted by the three posture audit displays. */
// Must match AUDIT_CHAIN_VERIFIED_MAX_AGE_MS embedded by dashboard/v1_1/client.ts,
// auditChainPill in posture-home-html.ts and the audit line in posture-agent-html.ts.
export const AUDIT_CHAIN_VERIFIED_MAX_AGE_MS = 10 * 60 * 1000; // Ten minutes, in milliseconds.

/** Strict observation parser embedded by the SPA and both posture HTML renderers. */
// Must match parseIsoInstantWithOffset in core/time.ts; the existing client-time-parity test
// executes this through getClientScript, and all audit consumers embed these same bytes.
export const POSTURE_AUDIT_TIMESTAMP_PARSER_SOURCE = String.raw`function parseEvidenceTimestamp(value) {
  if (typeof value !== "string") return undefined;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|([+-])(\d{2}):(\d{2}))$/.exec(value);
  if (match === null) return undefined;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const writtenMs = Number((match[7] || "").padEnd(3, "0").slice(0, 3));
  const offsetSign = match[8];
  const offsetHours = offsetSign ? Number(match[9]) : 0;
  const offsetMinutes = offsetSign ? Number(match[10]) : 0;
  // Mirrors the server predicate's finite Date.parse refusal for in-shape but out-of-range offsets.
  if (offsetHours > 23 || offsetMinutes > 59) return undefined;
  const offsetMs = (offsetSign === "-" ? -1 : 1) * (offsetHours * 60 + offsetMinutes) * 60 * 1000;
  const wall = new Date(0);
  // Set year/month/day together so years 0000..0099 stay proleptic instead of remapping through 1900..1999.
  wall.setUTCFullYear(year, month - 1, day);
  wall.setUTCHours(hour, minute, second, writtenMs);
  const timestamp = wall.getTime() - offsetMs;
  if (!Number.isFinite(timestamp)) return undefined;
  const rendered = new Date(timestamp + offsetMs);
  const calendarFieldsMatch =
    rendered.getUTCFullYear() === year &&
    rendered.getUTCMonth() + 1 === month &&
    rendered.getUTCDate() === day &&
    rendered.getUTCHours() === hour &&
    rendered.getUTCMinutes() === minute &&
    rendered.getUTCSeconds() === second &&
    rendered.getUTCMilliseconds() === writtenMs;
  return calendarFieldsMatch ? timestamp : undefined;
}`;

/**
 * One composed payload for the posture home screen, served by
 * `GET /api/posture/home` and pushed verbatim by the `/api/posture/stream` SSE
 * endpoint. Built by `buildHome` in `posture-routes.ts`.
 */
export interface PostureHome {
  /** Must match the key-observation copy rendered by the posture-home consumers. */
  producer_keys?: { producer: ProducerKeyObservation; broker: ProducerKeyObservation; message: string | null };
  panels: Record<PosturePanelId, PosturePanelStatus>;
  /** Must match audit_verification in all three posture-home clients. */
  audit_verification: { cached_entries: number; cache_cap: number; verified_uncached_last_pass: number };
  origin_machine: string;
  /**
   * Factual federation summary for the banner. This is not the full roster and
   * never creates a fleet claim by itself: `available:false` means there is no
   * provisioned fleet to present, while `available:true` mirrors the same
   * federation-backed roster the Fleet panel renders.
   */
  federation: {
    available: boolean;
    enabled: boolean;
    fleet_node_count: number;
  };
  /**
   * Whether this dashboard mount has the posture SSE live-refresh registry
   * wired. False on folded wrap-auto mounts that intentionally omit the stream;
   * the client must keep polling there instead of opening a doomed EventSource.
   */
  stream_available: boolean;
  castle_wall: CastleWallPosture;
  digest: AuditDigest;
  unwrapped: UnwrappedRoster;
  /** Per-feature usage health (evidence-based; unknown when unconfirmed). */
  feature_health: FeatureHealthPanel;
  /**
   * Custody & Exit posture (Slice 3). Custody is never green (amber unconfirmed
   * or red damaged); exit is the honest CLI-gated export capability without a
   * clean-exit guarantee.
   */
  custody_exit: CustodyExitPanel;
  /**
   * Query-privacy posture (Phase 2, Opacity principle 4). Tier A header-strip
   * count (metadata hygiene, NOT anonymity) from real audit evidence, plus the
   * Tier B PII-rewrite state (never green from config; `unconfirmed` until the
   * deferred rewrite emitter wiring lands).
   */
  query_privacy: QueryPrivacySection;
  /**
   * Count of agents the operator has REQUESTED protection for (policy intent).
   * This is the honest banner number: it counts policy_protected, NOT confirmed
   * enforcement. Renamed in intent from the old flat "protected" count, which
   * implied enforcement it could not prove (#634 fake-green fix).
   */
  protection_requested_count: number;
  /** Registry records plus unprotected harness kinds detected by config-file presence;
   * each kind counts as its records or one unprotected entry, not an enforcement claim. */
  protection_detected_count: number;
  /**
   * Count of agents with CONFIRMED live enforcement (`enforcement_active ===
   * "active"`). `0` today: no per-agent enforcement signal exists yet, so the
   * banner never overstates confirmed enforcement.
   */
  enforcement_confirmed_count: number;
  /**
   * Derived agent rows carrying the honest policy-vs-enforcement split (#634).
   * Replaces the raw `LocalAgentRecord[]`: the UI must render green only on
   * confirmed enforcement, amber on policy-only protection.
   */
  agents: PostureAgentRow[];
}
