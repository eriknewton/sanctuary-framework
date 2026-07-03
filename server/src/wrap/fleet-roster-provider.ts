/**
 * Wrap dashboard fleet-roster provider - the REAL, read-only, disk-backed seam.
 *
 * The wrap ("Protect") dashboard is a short-lived HTTP server: it does NOT run
 * the long-lived federation sync daemon, so it holds no LIVE in-memory node
 * roster (that roster is populated only by join ceremonies and accepted syncs on
 * the running MCP-server / `sanctuary dashboard` daemon). What the wrap process
 * CAN read honestly, from the same at-rest records the daemon boots from, is:
 *
 *   - whether federation is PROVISIONED on this fortress (a trust root on disk:
 *     issuer, joiner, or operator_cloud joined-node), and this fortress's own
 *     fortress_id / node_id;
 *   - the DURABLE folded revocation projection (the grow-only revoked-node set +
 *     the operator-authority eviction serial) and the current operator policy
 *     marker, from the durable federation sync-state record.
 *
 * This builder returns the `() => FleetRoster` provider the wrap dashboard passes
 * to its posture routes (`GET /api/posture/fleet`, the panel `renderPostureHomeHTML`
 * already serves) and to `GET /api/fleet/roster`. It composes the SAME
 * `buildFleetRoster` presenter the daemon uses, over a MINIMAL read-only
 * `V1FederationDeps`. It is strictly read-only: it opens no sync loop, mutates no
 * state, signs nothing, and exposes no key material. The mutation methods of
 * `V1FederationDeps` are present only to satisfy the type and THROW if ever
 * called - the presenter never calls them, and there is no admit/revoke/rotate
 * seam here (that is a deliberately separate, later slice).
 *
 * Honest states, all fail-closed:
 *
 *   1. Federation NOT provisioned (no trust root) -> `absentFleetRoster()`: the
 *      one honest "no fleet" shape. Never a fabricated roster, never a
 *      greyed-green "all admitted" shell.
 *   2. A rotate-root journal is present (the signing master is mid-rotation) ->
 *      federation is held off, so the wrap dashboard also reports absent. A
 *      half-rotated root must never present as a live fleet.
 *   3. Federation provisioned -> `buildFleetRoster` over the read-only deps:
 *      `available: true`, this fortress's ids, an EMPTY node list (the live
 *      roster is not durable and this process runs no sync loop; the panel
 *      renders "No other machines admitted to this fleet yet"), the durable
 *      eviction serial + operator policy. `enabled` is honestly `false`: the
 *      operator on/off switch is a live daemon flag this read-only process
 *      cannot observe, so the panel shows "Fleet off" rather than claiming the
 *      operator turned it on.
 *   4. The durable sync-state record is PRESENT-BUT-CORRUPT (at-rest tamper) ->
 *      `isNodeRevoked` THROWS, which `buildFleetRoster`/`resolveTrust` fail-close
 *      to `untrusted`. Because the node list is empty here that path carries no
 *      node today, but the fail-closed contract is wired so a future durable
 *      roster cannot silently launder a node to `admitted` over a corrupt record.
 *
 * The provider closure is resolved lazily per request by the route, so a
 * federation that is provisioned AFTER the wrap dashboard started is observed on
 * the next fetch without a restart.
 */

import type { StorageBackend } from "../storage/interface.js";
import type {
  FederationContext,
  FederationEvent,
  V1FederationDeps,
} from "../v1/federation.js";
import { FederationSyncStateStore } from "../v1/federation-sync-state-store.js";
import { federationRotateRootInProgress } from "../mesh/federation-rotate-root.js";
import { provisionOrLoadFederationTrustRoot } from "../mesh/federation-trust-root-store.js";
import { loadFederationJoinerTrustRoot } from "../mesh/federation-joiner-trust-root-store.js";
import { provisionOrLoadOperatorCloudJoinedNode } from "../mesh/operator-cloud-joined-node-store.js";
import {
  absentFleetRoster,
  buildFleetRoster,
  type FleetRoster,
} from "../principal-policy/fleet-roster.js";
import type { FederationAppliedPolicyVersion } from "../v1/federation-policy-bundle.js";

/**
 * The minimal federation-context shape `buildFleetRoster` actually reads:
 * whether a context exists at all (provisioned) plus this fortress's own ids.
 * The at-rest trust-root loaders return a richer context WITHOUT the live join
 * `approver` (the daemon adds that later for the join ceremony). This read-only
 * fleet presenter runs no ceremony and never touches `approver`, so it carries
 * only this narrow projection and never needs the full `FederationContext`.
 */
interface WrapReadContext {
  fortressId: string;
  nodeId: string;
}

/**
 * A read-only projection of the durable federation state the wrap process can
 * honestly read from disk. `null` when federation is not provisioned (or held
 * off during a root rotation) - the caller renders the honest absent roster.
 */
interface WrapFederationReadState {
  context: WrapReadContext;
  /**
   * The durable revoked-node set from the sync-state record, or `null` when the
   * record is PRESENT-BUT-CORRUPT. `null` latches fail-closed: `isNodeRevoked`
   * throws so any node fail-closes to `untrusted`, never silently `admitted`.
   */
  revokedNodeIds: Set<string> | null;
  evictionSerial: number;
  operatorPolicy: FederationAppliedPolicyVersion | null;
}

/**
 * Load the read-only federation state from the at-rest records, mirroring the
 * daemon boot's load-only, fail-closed posture. Never mints, never mutates.
 */
async function loadWrapFederationReadState(
  storage: StorageBackend,
  masterKey: Uint8Array,
): Promise<WrapFederationReadState | null> {
  // A rotate-root journal means the signing master is mid-rotation: a
  // half-rotated root must NEVER serve. Report absent (fail closed) until the
  // operator completes `sanctuary federation rotate-root --resume`.
  if (await federationRotateRootInProgress(storage)) return null;

  // Load-only trust-root resolution, in the same precedence the daemon uses:
  // issuer, then local joiner, then operator_cloud joined-node. Absence at every
  // tier means federation is honestly off (no fleet). `mint: false` guarantees
  // this read never creates a root.
  let context: WrapReadContext | null = null;
  const issuer = await provisionOrLoadFederationTrustRoot({
    storage,
    masterKey,
    mint: false,
  });
  if (issuer !== null) {
    context = {
      fortressId: issuer.context.fortressId,
      nodeId: issuer.context.nodeId,
    };
  } else {
    const joiner = await loadFederationJoinerTrustRoot({ storage, masterKey });
    if (joiner !== null) {
      context = {
        fortressId: joiner.context.fortressId,
        nodeId: joiner.context.nodeId,
      };
    } else {
      const operatorCloud = await provisionOrLoadOperatorCloudJoinedNode({
        storage,
        masterKey,
      });
      if (operatorCloud !== null) {
        context = {
          fortressId: operatorCloud.context.fortressId,
          nodeId: operatorCloud.context.nodeId,
        };
      }
    }
  }

  if (context === null) return null;

  // Durable folded revocation projection + eviction serial + operator policy.
  // A present-but-corrupt record latches `revokedNodeIds: null` so trust
  // fail-closes; a genuinely fresh (absent) record loads an empty projection and
  // serves normally.
  let revokedNodeIds: Set<string> | null;
  let evictionSerial = 0;
  let operatorPolicy: FederationAppliedPolicyVersion | null = null;
  try {
    const snapshot = await new FederationSyncStateStore({
      storage,
      masterKey,
    }).load();
    revokedNodeIds = snapshot.revokedNodeIds;
    evictionSerial = snapshot.highestEvictionSerial;
    operatorPolicy = snapshot.operatorPolicy;
  } catch {
    // Present-but-corrupt sync-state: fail closed. Federation stays provisioned
    // (context is real) but trust is unprovable, so `isNodeRevoked` throws.
    revokedNodeIds = null;
  }

  return { context, revokedNodeIds, evictionSerial, operatorPolicy };
}

/**
 * A minimal, strictly READ-ONLY `V1FederationDeps` for the fleet-roster
 * presenter. Only the four read methods `buildFleetRoster` calls
 * (`getContext`, `isEnabled`, `listNodes`, `isNodeRevoked`) do real work; every
 * mutation / signing / sync method THROWS so a mis-wire is loud, never a silent
 * fabrication. The wrap process has no live node roster, so `listNodes` is
 * empty by construction.
 */
function readOnlyFederationDeps(state: WrapFederationReadState): V1FederationDeps {
  const notReadOnly = (): never => {
    throw new Error(
      "wrap fleet-roster provider is read-only: no mutation/sync/sign method may be called",
    );
  };
  return {
    // The presenter reads ONLY `fortressId` / `nodeId` off the context (plus
    // its non-null-ness to mean "provisioned"); it never touches the live join
    // `approver` or any signing material. Narrowed to `WrapReadContext` above
    // and asserted at this boundary so the read-only deps satisfy the type
    // without fabricating join authority this process does not have.
    getContext: () => state.context as unknown as FederationContext,
    // The operator on/off switch is a LIVE daemon flag; a read-only wrap process
    // cannot observe it, so it reports honestly OFF rather than claiming ON.
    isEnabled: () => false,
    // No live roster is durable and this process runs no sync loop: honestly no
    // other machines are currently visible. The presenter renders the empty
    // state, never a fabricated node.
    listNodes: () => [],
    // Fail-closed: a corrupt sync-state record (revokedNodeIds === null) throws,
    // so any node fail-closes to `untrusted`. Never silently `admitted`.
    isNodeRevoked: (nodeId: string): boolean => {
      if (state.revokedNodeIds === null) {
        throw new Error(
          "federation revocation state unavailable (durable record corrupt)",
        );
      }
      return state.revokedNodeIds.has(nodeId);
    },
    // Root-revocation is likewise unprovable read-only: fail closed (deny).
    isRootRevoked: (): boolean => {
      throw new Error("federation root-revocation state not evaluated read-only");
    },
    // ── Everything below is mutation / signing / sync: never called by the
    // presenter. Throwing keeps a mis-wire loud rather than silently wrong. ──
    setEnabled: notReadOnly,
    resolveOperatorPublicKey: () => null,
    audit: async () => {},
    rosterNodeIds: () => [],
    recordJoin: notReadOnly,
    listFederationEvents: (): FederationEvent[] => [],
    appendFederationEvents: notReadOnly,
    acceptedHighWaterFor: () => null,
    recordAcceptedHighWater: notReadOnly,
    nextOutboundHighWater: notReadOnly,
    renewLocalNodeCertificate: () => {},
    issueReissueChallenge: notReadOnly,
    consumeReissueChallenge: notReadOnly,
    federationPosture: notReadOnly,
  };
}

/**
 * Build the wrap dashboard's read-only fleet-roster provider from the at-rest
 * fortress records. Returns a `() => Promise<FleetRoster>` the wrap dashboard's
 * routes resolve lazily per request. The heavy lifting (trust-root + sync-state
 * disk reads) happens per call so a post-start `sanctuary federation provision`
 * is observed without a wrap restart; the reads are small, local, and cheap.
 *
 * Every path returns a real, honest roster: absent when unprovisioned or
 * mid-rotation, the provisioned shape (with an empty node list) otherwise. It
 * never fabricates a roster and never renders green from absence.
 */
export function buildWrapFleetRosterProvider(params: {
  storage: StorageBackend;
  masterKey: Uint8Array;
}): () => Promise<FleetRoster> {
  return async (): Promise<FleetRoster> => {
    const state = await loadWrapFederationReadState(
      params.storage,
      params.masterKey,
    );
    if (state === null) return absentFleetRoster();
    return buildFleetRoster(readOnlyFederationDeps(state), {
      evictionSerial: state.evictionSerial,
      operatorPolicy: state.operatorPolicy,
    });
  };
}
