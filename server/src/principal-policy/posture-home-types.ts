/**
 * Neutral type home for the composed posture-home payload (`PostureHome`).
 *
 * This module exists ONLY to break the `posture-routes` <-> `posture-stream`
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
 * This is a pure type module (no runtime exports), so it adds no behavior and
 * no new green path.
 */

import type {
  CastleWallPosture,
  AuditDigest,
  UnwrappedRoster,
  PostureAgentRow,
  CustodyExitPanel,
} from "./posture.js";
import type { FeatureHealthPanel } from "./feature-health.js";
import type { QueryPrivacySection } from "./posture-query-privacy.js";

/**
 * One composed payload for the posture home screen, served by
 * `GET /api/posture/home` and pushed verbatim by the `/api/posture/stream` SSE
 * endpoint. Built by `buildHome` in `posture-routes.ts`.
 */
export interface PostureHome {
  origin_machine: string;
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
