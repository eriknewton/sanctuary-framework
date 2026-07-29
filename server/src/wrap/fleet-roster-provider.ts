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
 *   4. The durable sync-state record is PRESENT-BUT-CORRUPT (at-rest tamper /
 *      decrypt / decode failure) -> the whole roster is UNAVAILABLE
 *      (`absentFleetRoster()` / `available: false`), NOT `available: true`. A
 *      corrupt revocation projection means the fleet's trust standing is
 *      UNREADABLE, so the honest answer is "cannot show the fleet" (fail closed),
 *      never a green-looking "Fleet off / no machines" panel that reads as
 *      fine-but-empty over an unreadable record. This is the SAME honest
 *      `available: false` shape as unprovisioned / mid-rotation; the panel does
 *      not distinguish "no fleet" from "fleet unreadable" because both mean the
 *      operator has no proven fleet to act on.
 *
 * The provider closure is resolved lazily per request by the route, so a
 * federation that is provisioned AFTER the wrap dashboard started is observed on
 * the next fetch without a restart.
 */

import type { StorageBackend } from "../storage/interface.js";
import type {
  FederationContext,
  V1FederationDeps,
} from "../v1/federation.js";
import { FederationSyncStateStore } from "../v1/federation-sync-state-store.js";
import { federationRotateRootInProgress } from "../mesh/federation-rotate-root.js";
import { provisionOrLoadFederationTrustRoot } from "../mesh/federation-trust-root-store.js";
import { loadFederationJoinerTrustRoot } from "../mesh/federation-joiner-trust-root-store.js";
import {
  OperatorCloudJoinedNodeStore,
  operatorCloudContextFromRecord,
} from "../mesh/operator-cloud-joined-node-store.js";
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
 * honestly read from disk. Only ever constructed when BOTH the trust root AND
 * the durable sync-state record loaded cleanly, so every field is proven-real:
 * `revokedNodeIds` is the successfully-decoded grow-only projection, never a
 * fail-closed placeholder. A corrupt sync-state does NOT produce this shape (see
 * {@link loadWrapFederationReadState}, which returns `"unavailable"` instead).
 *
 * Exported ONLY so the read-only-deps fail-loud contract can be unit-tested; it
 * is not part of the wrap dashboard's public surface.
 */
export interface WrapFederationReadState {
  context: WrapReadContext;
  /** The durable, successfully-decoded revoked-node set. Never a placeholder. */
  revokedNodeIds: Set<string>;
  evictionSerial: number;
  operatorPolicy: FederationAppliedPolicyVersion | null;
}

/**
 * The three honest outcomes of a read-only federation load:
 *
 *   - `WrapFederationReadState` -> federation is provisioned AND its durable
 *     sync-state read cleanly; the caller builds the real provisioned roster.
 *   - `"absent"` -> federation is not provisioned, or held off mid root-rotation;
 *     the caller renders the honest absent roster.
 *   - `"unavailable"` -> federation IS provisioned but its durable sync-state
 *     record is PRESENT-BUT-CORRUPT (at-rest tamper / decrypt / decode failure).
 *     The fleet's trust standing is UNREADABLE, so the caller fails CLOSED and
 *     renders the same `available: false` shape rather than a green-looking
 *     "Fleet off / no machines" panel over an unreadable record.
 *
 * `"absent"` and `"unavailable"` both render `available: false`; they are kept
 * distinct in the loader so the fail-closed reason is explicit at the call site
 * (and so a future surface could disclose "unreadable" separately if desired).
 */
type WrapFederationReadOutcome =
  | WrapFederationReadState
  | "absent"
  | "unavailable";

/**
 * Load the read-only federation state from the at-rest records, mirroring the
 * daemon boot's load-only, fail-closed posture. Never mints, never mutates.
 */
async function loadWrapFederationReadState(
  storage: StorageBackend,
  masterKey: Uint8Array,
): Promise<WrapFederationReadOutcome> {
  // A rotate-root journal means the signing master is mid-rotation: a
  // half-rotated root must NEVER serve. Report absent (fail closed) until the
  // operator completes `sanctuary federation rotate-root --resume`.
  if (await federationRotateRootInProgress(storage)) return "absent";

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
      // Operator-cloud tier, LOAD-ONLY BY CONSTRUCTION. We call the store's
      // `load()` primitive directly rather than `provisionOrLoadOperatorCloudJoinedNode`
      // so that read-only intent is STRUCTURAL, not merely a comment: even if a
      // future change gave the `provisionOrLoad*` wrapper a provision/mint path
      // (the way `provisionOrLoadFederationTrustRoot` mints when `mint: true`),
      // this read-only GET could never reach it. `OperatorCloudJoinedNodeStore.load()`
      // only ever calls `storage.read` (proven above), so a read against an EMPTY
      // or PARTIAL store creates or modifies nothing. Absence -> null (federation
      // honestly off at this tier); a present-but-corrupt joined-node blob THROWS,
      // which we fail-close to `"unavailable"` (federation is provisioned-shaped
      // but its trust anchor is unreadable), never a silently-minted replacement.
      try {
        const operatorCloudRecord = await new OperatorCloudJoinedNodeStore(
          storage,
          masterKey,
        ).load();
        // Derive the context INSIDE the try: `operatorCloudContextFromRecord`
        // re-runs `validateJoinedNodeRecord`, so a record that decoded but fails
        // the pinned-master cert-chain / issuer-field checks must ALSO fail
        // closed here, never propagate an uncaught exception out of the provider.
        if (operatorCloudRecord !== null) {
          const operatorCloudContext =
            operatorCloudContextFromRecord(operatorCloudRecord);
          context = {
            fortressId: operatorCloudContext.fortressId,
            nodeId: operatorCloudContext.nodeId,
          };
        }
      } catch {
        // Present-but-unreadable operator-cloud trust anchor (corrupt / tampered
        // / cross-operator): federation is provisioned-shaped but its anchor is
        // unprovable. Fail closed, never a silently-minted replacement.
        return "unavailable";
      }
    }
  }

  if (context === null) return "absent";

  // Durable folded revocation projection + eviction serial + operator policy.
  // A genuinely fresh (absent) record loads an empty projection and serves
  // normally. A PRESENT-BUT-CORRUPT record THROWS `FederationSyncStateStoreError`:
  // the fleet's trust standing is unreadable, so we fail CLOSED to `"unavailable"`
  // (the whole roster reports `available: false`) rather than serving an
  // `available: true` roster over an unreadable revocation projection.
  try {
    const snapshot = await new FederationSyncStateStore({
      storage,
      masterKey,
    }).load();
    return {
      context,
      revokedNodeIds: snapshot.revokedNodeIds,
      evictionSerial: snapshot.highestEvictionSerial,
      operatorPolicy: snapshot.operatorPolicy,
    };
  } catch {
    return "unavailable";
  }
}

/**
 * A minimal, strictly READ-ONLY `V1FederationDeps` for the fleet-roster
 * presenter. EXACTLY the four read methods `buildFleetRoster` calls
 * (`getContext`, `isEnabled`, `listNodes`, `isNodeRevoked`) do real work; EVERY
 * OTHER method throws the SAME shared `notReadOnly()` error so a mis-wire is
 * LOUD (a thrown mustNotCall), never a silent no-op or a fabricated empty/null
 * that could quietly launder a wrong roster. The wrap process has no live node
 * roster, so `listNodes` is empty by construction.
 *
 * The allow-list is deliberately narrow: only a method PROVEN to be called by
 * the presenter (verified against `buildFleetRoster` / `resolveTrust` in
 * ../principal-policy/fleet-roster.ts, which touches only those four) and safe
 * to answer read-only is exempted from the throw. Nothing here signs, mutates,
 * appends events, advances a high-water, renews a cert, or discloses posture;
 * all of those throw. `isRootRevoked` is NOT called by the presenter, so it
 * throws too (it is not one of the four) - a read-only wrap process cannot
 * evaluate root revocation, and failing loud is safer than a fail-closed `false`
 * that some future caller might read as "root known-good".
 *
 * Exported ONLY so the fail-loud enumeration can be unit-tested; it is not part
 * of the wrap dashboard's public surface.
 */
export function readOnlyFederationDeps(
  state: WrapFederationReadState,
): V1FederationDeps {
  const notReadOnly = (): never => {
    throw new Error(
      "wrap fleet-roster provider is read-only: only getContext/isEnabled/listNodes/isNodeRevoked may be called",
    );
  };
  return {
    // ── The FOUR presenter reads (the only intentionally-allowed methods). ──
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
    // The durable, successfully-decoded revoked-node set. A corrupt sync-state
    // never reaches here: it fails closed to `"unavailable"` in the loader BEFORE
    // any roster is built, so `state.revokedNodeIds` is always the real projection.
    isNodeRevoked: (nodeId: string): boolean => state.revokedNodeIds.has(nodeId),
    // ── EVERYTHING BELOW is NOT one of the four presenter reads. Each throws the
    // shared notReadOnly() so a mis-wire is loud, never silently wrong. This
    // includes read-shaped methods (isRootRevoked, resolveOperatorPublicKey,
    // rosterNodeIds, listFederationEvents, acceptedHighWaterFor, federationPosture)
    // AND the mutation/sign/sync methods: none is on the proven presenter path. ──
    isRootRevoked: notReadOnly,
    setEnabled: notReadOnly,
    resolveOperatorPublicKey: notReadOnly,
    audit: notReadOnly,
    rosterNodeIds: notReadOnly,
    recordJoin: notReadOnly,
    listFederationEvents: notReadOnly,
    appendFederationEvents: notReadOnly,
    acceptedHighWaterFor: notReadOnly,
    recordAcceptedHighWater: notReadOnly,
    nextOutboundHighWater: notReadOnly,
    renewLocalNodeCertificate: notReadOnly,
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
 * Every path returns a real, honest roster: the `available: false` absent shape
 * when unprovisioned, mid-rotation, OR when the durable sync-state is present
 * but corrupt (fail closed - unreadable trust standing is never shown green);
 * the provisioned shape (with an empty node list) only when the trust root AND
 * sync-state both read cleanly. It never fabricates a roster and never renders
 * green from absence or from an unreadable record.
 */
export function buildWrapFleetRosterProvider(params: {
  storage: StorageBackend;
  masterKey: Uint8Array;
}): () => Promise<FleetRoster> {
  return async (): Promise<FleetRoster> => {
    const outcome = await loadWrapFederationReadState(
      params.storage,
      params.masterKey,
    );
    // "absent" (not provisioned / mid-rotation) AND "unavailable" (provisioned
    // but the durable sync-state is corrupt) BOTH fail closed to the honest
    // `available: false` roster. Only a fully-clean read builds the real one.
    if (outcome === "absent" || outcome === "unavailable") {
      return absentFleetRoster();
    }
    return buildFleetRoster(readOnlyFederationDeps(outcome), {
      evictionSerial: outcome.evictionSerial,
      operatorPolicy: outcome.operatorPolicy,
    });
  };
}
