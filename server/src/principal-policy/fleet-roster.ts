/**
 * Fleet Console Slice 1 — the federation-backed fleet-roster presenter.
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
 *    `deps.isNodeRevoked(node_id)` — the SAME grow-only projection every sync
 *    path routes through — and present its answer. We do not infer "trusted"
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
 * federation status posture — the same serial that orders revocation events in
 * the signed log. It is surfaced as fleet-wide context (the operator can see the
 * fleet has advanced to serial N), not re-derived per node.
 */

import type {
  FederationNodeView,
  V1FederationDeps,
} from "../v1/federation.js";

/**
 * The trust state the console renders per machine. This is the operator-facing
 * vocabulary; it maps 1:1 to a federation verdict and never to a response shape.
 *
 *  - `admitted`   — the federation layer evaluated the node and it is NOT in the
 *                   grow-only revoked set. Green.
 *  - `revoked`    — the node is in the operator-signed revoked set. Red.
 *  - `untrusted`  — the node's revocation state could not be evaluated
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
 *  - `recent`  — a sync was received from this node inside the freshness window.
 *  - `stale`   — a sync was seen, but not inside the freshness window.
 *  - `never`   — no sync has ever been received from this node.
 */
export type FleetNodeReach = "recent" | "stale" | "never";

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
  first_seen: string;
  last_seen: string;
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
  },
): FleetRoster {
  const now = options?.now?.() ?? Date.now();
  const freshnessWindowMs =
    options?.freshnessWindowMs ?? FLEET_REACH_FRESHNESS_WINDOW_MS;

  const ctx = deps.getContext();

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
