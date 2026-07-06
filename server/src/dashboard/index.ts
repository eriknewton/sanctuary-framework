/**
 * Sanctuary Sovereignty Dashboard — public surface.
 *
 * Consumers import `startDashboard` to bring up the hero-shield UI
 * on port 3501 (default). The rest of the exports are types + utilities
 * for tests and callers that want to wire in live events.
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
import type { ApprovalHandlers, FleetActivationResult } from "./api.js";
import type { FleetRoster } from "../principal-policy/fleet-roster.js";

export { getProtectionSnapshot } from "./aggregator.js";
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
  /**
   * Read-only fleet-roster provider (wrap "Protect" dashboard). Forwarded to the
   * dashboard server, where it feeds both `GET /api/fleet/roster` and the
   * posture-route `GET /api/posture/fleet` that the posture-home fleet panel
   * fetches. MAY be async (the wrap process reads the roster from the at-rest
   * fortress records). When omitted the fleet panel stays absent (honest "no
   * fleet"). See `DashboardServerOptions.fleetRoster`.
   */
  fleetRoster?: () => FleetRoster | Promise<FleetRoster>;
  /**
   * Fleet activation handler (paid fleet control plane PR-2). Forwarded to the
   * dashboard server; feeds `POST /api/fleet/activate`. When omitted the route
   * reports the honest `activation_unavailable` shape. See
   * `DashboardServerOptions.activateFleetLicense`.
   */
  activateFleetLicense?: (
    pastedLicense: string,
  ) => Promise<FleetActivationResult>;
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

  const sources = {
    mode: options.mode,
    server_version: options.serverVersion,
    ...(options.auditLog ? { auditLog: options.auditLog } : {}),
    ...(options.identityManager ? { identityManager: options.identityManager } : {}),
    ...(options.clientManager ? { clientManager: options.clientManager } : {}),
    ...(options.baseline ? { baseline: options.baseline } : {}),
    ...(options.policy ? { policy: options.policy } : {}),
    ...(options.reputation ? { reputation: options.reputation } : {}),
    ...(options.teeAvailable != null ? { teeAvailable: options.teeAvailable } : {}),
    ...(options.l4Evidence ? { l4Evidence: options.l4Evidence } : {}),
    // HIGH never-overclaim fix (seam #2): thread the producer-key re-verification
    // basis into the snapshot sources the same way the DashboardApprovalChannel
    // path does, so a forged marker-only entry on a key-bearing host fails closed
    // to amber here too. Absent on macOS / pre-provision → channel basis (honest).
    ...(options.resolvePinnedProducerKey
      ? { resolvePinnedProducerKey: options.resolvePinnedProducerKey }
      : {}),
    ...(options.producerKeyExpectedButUnavailable
      ? { producerKeyExpectedButUnavailable: true }
      : {}),
    ...(options.resolveBrokerPinnedProducerKey
      ? { resolveBrokerPinnedProducerKey: options.resolveBrokerPinnedProducerKey }
      : {}),
    ...(options.brokerProducerKeyExpectedButUnavailable
      ? { brokerProducerKeyExpectedButUnavailable: true }
      : {}),
    activity,
    pendingApprovals: pending,
  };

  const serverOpts: DashboardServerOptions = {
    mode: options.mode,
    sources,
    ...(options.port != null ? { port: options.port } : {}),
    ...(options.host ? { host: options.host } : {}),
    ...(options.authToken ? { authToken: options.authToken } : {}),
    ...(options.approvals ? { approvals: options.approvals } : {}),
    ...(options.fleetRoster ? { fleetRoster: options.fleetRoster } : {}),
    ...(options.activateFleetLicense
      ? { activateFleetLicense: options.activateFleetLicense }
      : {}),
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
