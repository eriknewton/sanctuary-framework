/**
 * Fleet Console Slice 1 - the federation-backed fleet-roster presenter.
 *
 * This is a THIN read-only presenter over the proven federation control-plane.
 * It composes on the `/v1` read seam (`V1FederationDeps`) and adds NO new trust
 * logic: every trust verdict is read from the federation layer's own
 * cryptographic projection (`isNodeRevoked`), never re-derived from the shape of
 * a `/v1/nodes` row. The console SEES and MONITORS the fleet; it never manages
 * trust here (no mutation path, no key material). The in-console trust actions
 * (admit / revoke / rotate) are a deliberately later slice.
 *
 * Non-negotiable seam rules carried from AGENTS.md (the Fleet Console must honor
 * the same hard constraints as the federation layer it presents):
 *
 *  - Trust is the federation layer's verdict, not ours (constraint 4). We call
 *    `deps.isNodeRevoked(node_id)` - the SAME grow-only projection every sync
 *    path routes through - and present its answer. We do not infer "trusted"
 *    from `attestation_status: "verified"` or any other response field.
 *
 *  - Fail closed on an unevaluable node (constraint 5). If `isNodeRevoked`
 *    THROWS for a node (revocation state momentarily unavailable), that node
 *    renders `untrusted`, NOT amber and NEVER `admitted`. An operator who cannot
 *    prove a machine is in good standing must see it as untrusted, the same way
 *    the sync chokepoint rejects on an unevaluable revocation state.
 *
 *  - No key material, ever (constraint 6). The presenter reads only public
 *    identifiers and posture metadata already on the `/v1/nodes` view. There is
 *    no private-key field anywhere in the roster shape.
 *
 *  - Honest absence over a fabricated roster. When federation is not provisioned
 *    (`getContext()` is null), there IS no fleet to present: the roster is
 *    `available: false` with an empty node list, never a green "all admitted"
 *    shell over a fortress that has no federation.
 *
 * The rotation serial is the operator-signed monotonic eviction serial from the
 * federation status posture - the same serial that orders revocation events in
 * the signed log. It is surfaced as fleet-wide context (the operator can see the
 * fleet has advanced to serial N), not re-derived per node.
 */

import type {
  FederationNodeView,
  V1FederationDeps,
} from "../v1/federation.js";
import type { FederationAppliedPolicyVersion } from "../v1/federation-policy-bundle.js";

/**
 * The trust state the console renders per machine. This is the operator-facing
 * vocabulary; it maps 1:1 to a federation verdict and never to a response shape.
 *
 *  - `admitted`   - the federation layer evaluated the node and it is NOT in the
 *                   grow-only revoked set. Green.
 *  - `revoked`    - the node is in the operator-signed revoked set. Red.
 *  - `untrusted`  - the node's revocation state could not be evaluated
 *                   (fail-closed). Red. NEVER amber, never silently admitted.
 */
export type FleetNodeTrustState = "admitted" | "revoked" | "untrusted";

/**
 * A reach/health indicator derived ONLY from observed sync activity already on
 * the `/v1/nodes` view. This is liveness telemetry, NOT a trust signal: a
 * `revoked` node can still have a recent `last_sync`, and a freshly `admitted`
 * node may show `never` until it first syncs. The console keeps the two axes
 * separate so reach can never launder a node into looking trusted.
 *
 *  - `recent`  - a sync was received from this node inside the freshness window.
 *  - `stale`   - a sync was seen, but not inside the freshness window.
 *  - `never`   - no sync has ever been received from this node.
 */
export type FleetNodeReach = "recent" | "stale" | "never";

/**
 * Per-node signed operator-policy drift. Unknown is deliberately separate from
 * in-sync and must never render green: when the operator version or node marker
 * is missing, the console cannot prove the node applied the current bundle.
 */
export type FleetPolicyDriftState = "in_sync" | "drifted" | "unknown";

/** Policy version marker as the console presents it. No raw policy contents. */
export interface FleetPolicyMarker {
  version: number | null;
  hash: string | null;
  hash_algorithm: string | null;
  applied_at: string | null;
  source_event_id: string | null;
}

/** Per-node signed policy state plus the computed drift verdict. */
export interface FleetNodePolicyStatus extends FleetPolicyMarker {
  drift_state: FleetPolicyDriftState;
}

/** One machine as the console presents it. Read-only; no key material. */
export interface FleetRosterNode {
  node_id: string;
  /** Operator-set display label, or null. */
  label: string | null;
  /** Federation trust verdict for this node (fail-closed). */
  trust_state: FleetNodeTrustState;
  /**
   * True only when the revocation projection successfully EVALUATED this node.
   * When false, `trust_state` is `untrusted` because the verdict was unprovable,
   * not because the node is known-bad. Surfaced so the operator can tell a
   * proven-revoked machine from an unevaluable one.
   */
  trust_evaluable: boolean;
  /** Reach/liveness indicator from observed sync activity (never a trust input). */
  reach: FleetNodeReach;
  /** Node trust-boundary mode (local / operator_cloud / sovereign_tee / unknown). */
  node_mode: FederationNodeView["node_mode"];
  /** Whether the provider sits inside this node's trust boundary (honest disclosure). */
  provider_in_trust_boundary: boolean;
  /** Last time a sync was received from this node, or null if never. */
  last_sync_received_at: string | null;
  /** Signed operator-policy marker and drift verdict. No raw policy contents. */
  policy: FleetNodePolicyStatus;
  first_seen: string;
  last_seen: string;
}

/**
 * Fleet-wide sync-health rollup (Marquee A1).
 *
 * This is a LIVENESS rollup over the per-node `reach` axis the presenter already
 * computes; it is NOT a trust signal and never an input to any trust verdict. It
 * answers the operator's "is my whole fleet currently in touch?" question at a
 * glance, derived ONLY from data already on the per-node view, so it cannot
 * launder a revoked node into looking healthy: a `revoked` node with a `recent`
 * reach still counts as `reachable` here AND stays `revoked` in the trust summary.
 * The two axes stay separate by construction.
 *
 * `oldest_last_sync` is the earliest `last_sync_received_at` across nodes that
 * have ever synced (null when no node has ever synced), so the operator can see
 * the staleness frontier without scanning every row.
 */
export interface FleetSyncHealth {
  /** Nodes whose last sync was inside the freshness window. */
  reachable: number;
  /** Nodes that have synced before but not inside the freshness window. */
  stale: number;
  /** Nodes that have never been heard from. */
  never: number;
  /**
   * The earliest `last_sync_received_at` across nodes that have EVER synced, or
   * null when no node has ever synced. The staleness frontier of the fleet.
   */
  oldest_last_sync: string | null;
  /** The freshness window (ms) the `reachable`/`stale` split was computed with. */
  freshness_window_ms: number;
}

/**
 * Signed-policy-distribution status (Marquee A2).
 *
 * This is custody-state distribution, not portable audit evidence. The console
 * shows the operator-signed policy hash/version currently known to this node and
 * each node's applied marker. It never carries raw policy contents, policy
 * secrets, or private keys. Unknown is never counted as in-sync.
 */
export interface FleetPolicyDistribution {
  /** True when the federation presenter can evaluate signed-policy state. */
  available: boolean;
  /** Current operator-signed policy marker known to this node, or null. */
  operator_policy: FleetPolicyMarker | null;
  /** Per-node rollup. Unknown is not in-sync and must not render green. */
  summary: {
    in_sync: number;
    drifted: number;
    unknown: number;
  };
}

/** The full fleet roster the console renders. */
export interface FleetRoster {
  /**
   * False when federation is not provisioned on this fortress: there is no fleet
   * to present, and the console shows an honest "no fleet configured" state
   * rather than a fabricated roster.
   */
  available: boolean;
  /** Whether the operator has the fleet turned ON (enable switch + provisioned). */
  enabled: boolean;
  /** This fortress's own federation id, or null when unprovisioned. */
  fortress_id: string | null;
  /** This fortress's own node id, or null when unprovisioned. */
  node_id: string | null;
  /**
   * The fleet-wide operator-signed EVICTION serial: the highest monotonic serial
   * the revocation projection has advanced to. Fleet context, not a per-node
   * value, and DISTINCT from the issuer-side root-rotation serial (which lives in
   * the trust-root record and is NOT surfaced here). 0 when nothing has been
   * evicted yet.
   */
  eviction_serial: number;
  /** One entry per admitted-or-revoked machine the federation layer knows. */
  nodes: FleetRosterNode[];
  /** Roll-up counts for the at-a-glance fleet badge. */
  summary: {
    total: number;
    admitted: number;
    revoked: number;
    /** Nodes whose trust could not be evaluated (fail-closed to untrusted). */
    untrusted: number;
  };
  /**
   * Fleet-wide sync-health rollup (A1). Liveness only, never a trust input; see
   * `FleetSyncHealth`. Present whenever the roster is `available`.
   */
  sync_health: FleetSyncHealth;
  /**
   * Signed-policy-distribution status (A2). Custody-state distribution only;
   * no raw policy contents and no audit-evidence parity claim.
   */
  policy_distribution: FleetPolicyDistribution;
}

/**
 * Default freshness window for the reach indicator: a sync received inside this
 * window reads `recent`, older reads `stale`. This is a display heuristic for
 * liveness only; it never affects trust.
 */
export const FLEET_REACH_FRESHNESS_WINDOW_MS = 10 * 60 * 1000;

function classifyReach(
  node: FederationNodeView,
  now: number,
  freshnessWindowMs: number,
): FleetNodeReach {
  const receivedAt = node.last_sync.received_at;
  if (receivedAt === null) return "never";
  const receivedMs = Date.parse(receivedAt);
  if (Number.isNaN(receivedMs)) return "never";
  return now - receivedMs <= freshnessWindowMs ? "recent" : "stale";
}

/**
 * Build the fleet-wide sync-health rollup (A1) from the already-classified
 * presenter rows. Pure over the rows: it counts the per-node `reach` axis and
 * finds the staleness frontier (`oldest_last_sync`). Liveness only; it touches no
 * trust field and so cannot affect any trust verdict. A node with an unparseable
 * `last_sync_received_at` is treated as never-synced for the frontier (it already
 * classified as `never` in `classifyReach`, which uses the same parse guard), so
 * the two stay consistent and a malformed timestamp can never masquerade as the
 * oldest real sync.
 */
function buildSyncHealth(
  rows: FleetRosterNode[],
  freshnessWindowMs: number,
): FleetSyncHealth {
  let reachable = 0;
  let stale = 0;
  let never = 0;
  let oldestMs: number | null = null;
  let oldestIso: string | null = null;

  for (const row of rows) {
    if (row.reach === "recent") reachable += 1;
    else if (row.reach === "stale") stale += 1;
    else never += 1;

    const iso = row.last_sync_received_at;
    if (iso === null) continue;
    const ms = Date.parse(iso);
    if (Number.isNaN(ms)) continue;
    if (oldestMs === null || ms < oldestMs) {
      oldestMs = ms;
      oldestIso = iso;
    }
  }

  return {
    reachable,
    stale,
    never,
    oldest_last_sync: oldestIso,
    freshness_window_ms: freshnessWindowMs,
  };
}

function markerFromAppliedPolicy(
  marker: FederationAppliedPolicyVersion | null | undefined,
): FleetPolicyMarker | null {
  if (!marker) return null;
  return {
    version: marker.version,
    hash: marker.hash,
    hash_algorithm: marker.hash_algorithm,
    applied_at: marker.applied_at,
    source_event_id: marker.source_event_id,
  };
}

function markerFromNode(node: FederationNodeView): FleetPolicyMarker {
  return {
    version: node.applied_policy.version,
    hash: node.applied_policy.hash,
    hash_algorithm: node.applied_policy.hash_algorithm,
    applied_at: node.applied_policy.applied_at,
    source_event_id: node.applied_policy.source_event_id,
  };
}

function classifyPolicyDrift(
  nodePolicy: FleetPolicyMarker,
  operatorPolicy: FleetPolicyMarker | null,
): FleetPolicyDriftState {
  if (operatorPolicy === null) return "unknown";
  if (
    nodePolicy.version === null ||
    nodePolicy.hash === null ||
    nodePolicy.hash_algorithm === null
  ) {
    return "unknown";
  }
  if (
    operatorPolicy.version === null ||
    operatorPolicy.hash === null ||
    operatorPolicy.hash_algorithm === null
  ) {
    return "unknown";
  }
  if (
    nodePolicy.version === operatorPolicy.version &&
    nodePolicy.hash === operatorPolicy.hash &&
    nodePolicy.hash_algorithm === operatorPolicy.hash_algorithm
  ) {
    return "in_sync";
  }
  return "drifted";
}

function buildPolicyStatus(
  node: FederationNodeView,
  operatorPolicy: FleetPolicyMarker | null,
): FleetNodePolicyStatus {
  const marker = markerFromNode(node);
  return {
    ...marker,
    drift_state: classifyPolicyDrift(marker, operatorPolicy),
  };
}

function buildPolicyDistribution(
  nodes: FleetRosterNode[],
  operatorPolicy: FleetPolicyMarker | null,
  available: boolean,
): FleetPolicyDistribution {
  return {
    available,
    operator_policy: operatorPolicy,
    summary: {
      in_sync: nodes.filter((n) => n.policy.drift_state === "in_sync").length,
      drifted: nodes.filter((n) => n.policy.drift_state === "drifted").length,
      unknown: nodes.filter((n) => n.policy.drift_state === "unknown").length,
    },
  };
}

/**
 * Resolve the federation trust verdict for ONE node, fail-closed.
 *
 * The verdict comes from `deps.isNodeRevoked`, the same grow-only projection the
 * sync chokepoint consults. The `throw`/`false` distinction is
 * security-significant (it is documented as such on `V1FederationDeps`): a throw
 * means the revocation state could not be evaluated, and an unevaluable node is
 * `untrusted`, never silently admitted. We never look at `attestation_status` or
 * any other response field to decide trust.
 */
function resolveTrust(
  deps: V1FederationDeps,
  nodeId: string,
): { trust_state: FleetNodeTrustState; trust_evaluable: boolean } {
  let revoked: boolean;
  try {
    revoked = deps.isNodeRevoked(nodeId);
  } catch {
    // Fail closed: an unevaluable revocation state is untrusted, not amber.
    return { trust_state: "untrusted", trust_evaluable: false };
  }
  if (revoked) {
    return { trust_state: "revoked", trust_evaluable: true };
  }
  return { trust_state: "admitted", trust_evaluable: true };
}

/**
 * Build the fleet roster the console renders, from the `/v1` read seam.
 *
 * Pure over `deps`: it calls only the read methods of `V1FederationDeps`
 * (`getContext`, `isEnabled`, `listNodes`, `isNodeRevoked`) and constructs a
 * presentation object. It performs NO mutation and reads NO key material. `now`
 * and `evictionSerial` are injectable for deterministic tests.
 */
export function buildFleetRoster(
  deps: V1FederationDeps,
  options?: {
    now?: () => number;
    freshnessWindowMs?: number;
    /**
     * The fleet-wide operator-signed EVICTION serial (the highest monotonic
     * serial the revocation projection has advanced to). Supplied by the
     * dashboard, which owns the projection; the presenter never re-derives it.
     * Defaults to 0 (honest "nothing evicted yet") when not supplied. Distinct
     * from the issuer-side root-rotation serial, which is not surfaced here.
     */
    evictionSerial?: number;
    /**
     * Current operator-signed policy hash/version known to this node. Supplied
     * by the dashboard's verified event projection, not re-derived here.
     */
    operatorPolicy?: FederationAppliedPolicyVersion | null;
  },
): FleetRoster {
  const now = options?.now?.() ?? Date.now();
  const freshnessWindowMs =
    options?.freshnessWindowMs ?? FLEET_REACH_FRESHNESS_WINDOW_MS;

  const ctx = deps.getContext();
  const operatorPolicy = markerFromAppliedPolicy(options?.operatorPolicy);

  // Honest absence: an unprovisioned fortress has no fleet. Do not fabricate a
  // green "all admitted" roster over a fortress with no federation root.
  if (ctx === null) {
    return {
      available: false,
      enabled: false,
      fortress_id: null,
      node_id: null,
      eviction_serial: 0,
      nodes: [],
      summary: { total: 0, admitted: 0, revoked: 0, untrusted: 0 },
      // Honest zeros for an absent fleet: no nodes => no reach, and the
      // distribution rail is unbuilt regardless of provisioning.
      sync_health: {
        reachable: 0,
        stale: 0,
        never: 0,
        oldest_last_sync: null,
        freshness_window_ms: freshnessWindowMs,
      },
      policy_distribution: buildPolicyDistribution([], null, false),
    };
  }

  const enabled = deps.isEnabled();
  const evictionSerial = normalizeEvictionSerial(options?.evictionSerial);

  const nodes: FleetRosterNode[] = deps.listNodes().map((node) => {
    const { trust_state, trust_evaluable } = resolveTrust(deps, node.node_id);
    return {
      node_id: node.node_id,
      label: node.label,
      trust_state,
      trust_evaluable,
      reach: classifyReach(node, now, freshnessWindowMs),
      node_mode: node.node_mode,
      provider_in_trust_boundary: node.trust_boundary.provider_in_trust_boundary,
      last_sync_received_at: node.last_sync.received_at,
      policy: buildPolicyStatus(node, operatorPolicy),
      first_seen: node.first_seen,
      last_seen: node.last_seen,
    };
  });

  const summary = {
    total: nodes.length,
    admitted: nodes.filter((n) => n.trust_state === "admitted").length,
    revoked: nodes.filter((n) => n.trust_state === "revoked").length,
    untrusted: nodes.filter((n) => n.trust_state === "untrusted").length,
  };

  return {
    available: true,
    enabled,
    fortress_id: ctx.fortressId,
    node_id: ctx.nodeId,
    eviction_serial: evictionSerial,
    nodes,
    summary,
    sync_health: buildSyncHealth(nodes, freshnessWindowMs),
    policy_distribution: buildPolicyDistribution(nodes, operatorPolicy, true),
  };
}

/**
 * Normalize the supplied fleet-wide eviction serial. The serial is fleet context
 * only (no per-node trust decision depends on it), so a missing or malformed
 * value degrades to an honest 0 ("nothing evicted yet") rather than fabricating a
 * serial.
 */
function normalizeEvictionSerial(serial: number | undefined): number {
  if (
    typeof serial === "number" &&
    Number.isSafeInteger(serial) &&
    serial >= 0
  ) {
    return serial;
  }
  return 0;
}
