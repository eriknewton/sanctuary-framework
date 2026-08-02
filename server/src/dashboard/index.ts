/**
 * Sanctuary Sovereignty Dashboard — public surface.
 *
 * RETIRED FROM PRODUCTION SPAWNING (dashboard one-surface fold PR-4,
 * ratified decision 1, 2026-08-02): `sanctuary protect`/`wrap` no longer
 * starts this server. The ONE production dashboard is the principal-policy
 * `DashboardApprovalChannel` (`principal-policy/dashboard.ts`, booted by
 * `sanctuary dashboard` / `dashboard-standalone.ts` and the MCP-server boot
 * path), which now also serves everything this server was the only home of:
 * the fleet-roster read, the `/api/templates` routes (init behind the Tier-1
 * approval gate), the `/api/approvals/:id/(allow|deny)` wire shape, and the
 * mobile companion PWA at `/m/*`.
 *
 * `startDashboard`/`startDashboardServer` remain EXPORTED: they are pinned
 * public surface (`exported-names.json`) with live test anchors, and
 * embedders may still construct this server deliberately. Deleting the
 * module is a coordinator-scoped disposition (counted test removal), not a
 * drive-by. Do not wire NEW production callers here; add routes to the
 * principal-policy dashboard instead.
 */

import type { AuditLog } from "../operational/audit-log.js";
import type { IdentityManager } from "../cognitive/tools.js";
import type { ClientManager } from "../proxy/client-manager.js";
import type { BaselineTracker } from "../principal-policy/baseline.js";
import type { PrincipalPolicy } from "../principal-policy/types.js";
import type {
  ActivityEntry,
  PendingApproval,
  ReputationLookup,
} from "./aggregator.js";
import type { ReputationEvidence } from "../shr/generator.js";
import {
  startDashboardServer,
  type DashboardHandle,
  type DashboardServerOptions,
} from "./server.js";
import type { ApprovalHandlers } from "./api.js";
import { composeAggregatorSources } from "./aggregator.js";
import type { FleetRoster } from "../principal-policy/fleet-roster.js";
import type { ResolvedEnforcementAvailability } from "../castle-wall/runtime/enforcement-availability.js";

export { getProtectionSnapshot, composeAggregatorSources } from "./aggregator.js";
export type { AggregatorSourcesInput } from "./aggregator.js";
export { renderDashboardHTML, HERO_COPY } from "./html.js";
export { handleRequest, isAuthorized, extractToken, constantTimeEquals } from "./api.js";
export { startDashboardServer } from "./server.js";

export type {
  ActivityEntry,
  PendingApproval,
  ProtectionSnapshot,
  ReputationLookup,
} from "./aggregator.js";
export type {
  AggregatorSources,
  CognitiveStatus,
  OperationalStatus,
  DisclosureStatus,
  ReputationStatus,
  // Back-compat aliases (L1-L4 rename PR-3): kept exported so downstream
  // imports keep working.
  L1Status,
  L2Status,
  L3Status,
  L4Status,
} from "./aggregator.js";
export type { DashboardHandle, DashboardServerOptions } from "./server.js";
export type { ApprovalHandlers, StreamEvent } from "./api.js";

export interface StartDashboardOptions {
  port?: number;
  host?: string;
  authToken?: string;
  mode: "co-located" | "standalone";
  serverVersion: string;
  auditLog?: AuditLog;
  identityManager?: IdentityManager;
  clientManager?: ClientManager;
  baseline?: BaselineTracker;
  policy?: PrincipalPolicy;
  reputation?: ReputationLookup;
  teeAvailable?: boolean;
  approvals?: ApprovalHandlers;
  /** Seed activity entries (most recent first). Runtime entries arrive via publishActivity. */
  initialActivity?: ActivityEntry[];
  /** Seed pending approvals. Runtime approvals arrive via publishApproval. */
  initialPendingApprovals?: PendingApproval[];
  /**
   * Pre-computed L4 reputation evidence. When provided the dashboard
   * renders the L4 evidence widget (attestation count, tier distribution,
   * disputes, freshness, active degradations). Typically supplied by the
   * server after L4 tools are constructed.
   */
  l4Evidence?: ReputationEvidence;
  /**
   * HIGH never-overclaim fix (honesty/dashboard-rollup seam #2): the reader's
   * pinned producer public key (base64url-no-pad), resolved lazily so a
   * post-provision write is observed. Threaded straight into the
   * AggregatorSources `getProtectionSnapshot` consumes, so the wrap-auto /
   * standalone snapshot server arms the hero shield on the SAME cryptographic
   * basis as the `DashboardApprovalChannel` (MCP-boot / `sanctuary dashboard`)
   * path. Without this, a key-bearing host reached via THIS server read the
   * wall posture on the bare channel basis, so a forged marker-only audit entry
   * could arm the shield green. Returns null on macOS / pre-provision Linux
   * (no key published) → the honest channel-authenticated floor, never claimed
   * as per-producer authenticated.
   */
  resolvePinnedProducerKey?: () => string | null;
  /**
   * HIGH never-overclaim fix fail-honest signal: a producer key is EXPECTED for
   * this fortress (the daemon published one) but the dashboard could NOT load it
   * (present but unreadable / malformed). When true the wall reader refuses to
   * render green on the channel basis (posture forces `degraded`, not armed), so
   * the hero shield goes amber rather than claiming a weaker basis than the
   * consumer wrote with. Mutually exclusive with a non-null
   * `resolvePinnedProducerKey()`.
   */
  producerKeyExpectedButUnavailable?: boolean;
  /** Pinned public key for broker daemon liveness producer verification. */
  resolveBrokerPinnedProducerKey?: () => string | null;
  /** Broker liveness producer key exists or is expected but could not be read. */
  brokerProducerKeyExpectedButUnavailable?: boolean;
  /** Canonical confined-agent protection subject (`fortress/uid-N`). */
  resolveProtectionClaimSubject?: () => string | null | Promise<string | null>;
  /** Node platform for Castle Wall surface shaping; defaults to the host. */
  platform?: NodeJS.Platform;
  /** macOS v3 level-triggered enforcement availability resolver. */
  resolveEnforcementAvailability?: () =>
    | Promise<ResolvedEnforcementAvailability>
    | ResolvedEnforcementAvailability;
  /**
   * Read-only fleet-roster provider (wrap "Protect" dashboard). Forwarded to the
   * dashboard server, where it feeds both `GET /api/fleet/roster` and the
   * posture-route `GET /api/posture/fleet` that the posture-home fleet panel
   * fetches. MAY be async (the wrap process reads the roster from the at-rest
   * fortress records). When omitted the fleet panel stays absent (honest "no
   * fleet"). See `DashboardServerOptions.fleetRoster`.
   */
  fleetRoster?: () => FleetRoster | Promise<FleetRoster>;
}

/**
 * High-level entry point used by callers (CLI, standalone service).
 * Returns a DashboardHandle that exposes `stop()` and `publish*`
 * helpers for driving live updates.
 */
export async function startDashboard(
  options: StartDashboardOptions
): Promise<DashboardHandle> {
  const activity: ActivityEntry[] = options.initialActivity
    ? [...options.initialActivity]
    : [];
  const pending: PendingApproval[] = options.initialPendingApprovals
    ? [...options.initialPendingApprovals]
    : [];

  // Dashboard-fold PR-1: the sources bundle is assembled by the ONE shared
  // builder (`composeAggregatorSources`), so this call site and the
  // principal-policy dashboard's snapshot path share identical include-or-omit
  // semantics. The producer-key threading (HIGH never-overclaim fix, seam #2)
  // is unchanged: the resolver rides through by identity so a forged
  // marker-only entry on a key-bearing host still fails closed to amber.
  const sources = composeAggregatorSources({
    mode: options.mode,
    serverVersion: options.serverVersion,
    auditLog: options.auditLog,
    identityManager: options.identityManager,
    clientManager: options.clientManager,
    baseline: options.baseline,
    policy: options.policy,
    reputation: options.reputation,
    teeAvailable: options.teeAvailable,
    l4Evidence: options.l4Evidence,
    resolvePinnedProducerKey: options.resolvePinnedProducerKey,
    producerKeyExpectedButUnavailable: options.producerKeyExpectedButUnavailable,
    resolveBrokerPinnedProducerKey: options.resolveBrokerPinnedProducerKey,
    brokerProducerKeyExpectedButUnavailable:
      options.brokerProducerKeyExpectedButUnavailable,
    resolveProtectionClaimSubject: options.resolveProtectionClaimSubject,
    platform: options.platform,
    resolveEnforcementAvailability: options.resolveEnforcementAvailability,
    activity,
    pendingApprovals: pending,
  });

  const serverOpts: DashboardServerOptions = {
    mode: options.mode,
    sources,
    ...(options.port != null ? { port: options.port } : {}),
    ...(options.host ? { host: options.host } : {}),
    ...(options.authToken ? { authToken: options.authToken } : {}),
    ...(options.approvals ? { approvals: options.approvals } : {}),
    ...(options.fleetRoster ? { fleetRoster: options.fleetRoster } : {}),
  };

  const handle = await startDashboardServer(serverOpts);

  // Wrap publish* helpers so buffered lists stay in sync with SSE pushes.
  // setV11Bindings + setV11LoopbackAutoAuth are passed through unchanged
  // (no buffered state to maintain; the underlying server stores them).
  const wrapped: DashboardHandle = {
    ...handle,
    publishActivity: (entry: ActivityEntry) => {
      activity.unshift(entry);
      if (activity.length > 50) activity.length = 50;
      handle.publishActivity(entry);
    },
    publishApproval: (approval: PendingApproval) => {
      pending.push(approval);
      handle.publishApproval(approval);
    },
    updateSources: handle.updateSources,
  };

  return wrapped;
}
