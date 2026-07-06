/**
 * Fleet control plane PR-3: SCHEDULED LICENSE RE-RESOLVE + AUTO-CAPTURE.
 *
 * The activation record persists a SIGNED license and re-resolves it against the
 * current clock on every read (so expiry/grace are honored live). But two things
 * still need a periodic, actively-driven pass rather than a lazy per-request read:
 *
 *   1. REVOCATION. A license valid by its own claims can be REVOKED by the issuer
 *      after activation (refund, compromise, kill). The signed revocation list is
 *      consulted here so a revoked license fails CLOSED to Community even though
 *      its token still verifies and is in-window.
 *   2. AUTO-CAPTURE (Erik 2026-07-06). A fleet that NEVER activated a license (so
 *      #889's grandfather-at-first-activation never fired) must, when this
 *      enforcing version first boots and finds itself OVER the free cap, record
 *      its CURRENT durable node count as its permanent grandfather baseline -
 *      zero operator action, one-time, grow-only. That capture is a WRITE, so it
 *      belongs in an actively-driven pass, not a read.
 *
 * And the transition itself (Community <-> paid, a changed cap) is what the
 * downgrade LOG + banner record, so the re-resolve pass is the natural place to
 * detect a transition and append the log entry.
 *
 * This module is the ORCHESTRATION. The cap arithmetic is
 * {@link resolveFleetCap} / {@link applyFleetCap} (pure, already shipped); the
 * revocation lookup is {@link isLicenseRevoked}; the persistence is the
 * activation + revocation + downgrade-log `_meta` records. The DECISION of what
 * changed is the pure {@link diffCapTransition} so it is exhaustively testable.
 *
 * ── FAIL-CLOSED ─────────────────────────────────────────────────────────────
 * Any resolve/verify/read failure resolves to Community; a revoked license
 * resolves to Community; a PRESENT-but-CORRUPT revocation list (revocation state
 * unverifiable) ALSO drops a paid grant to Community (coordinator-adjudicated
 * 2026-07-06 - an ABSENT list keeps the grant, since nothing is revoked). This
 * pass can only ever REMOVE paid capacity, never grant it, and NEVER touches a
 * node's wall (there is no wall/enforcement code on this path). Auto-capture is
 * grow-only + idempotent: it captures ONCE, from the durable count, and never
 * LOWERS an existing baseline.
 */

import type { StorageBackend } from "../storage/interface.js";
import {
  resolveFleetCap,
  COMMUNITY_FREE_NODE_CAP,
  type FleetCap,
  type ResolvedEntitlementView,
} from "./fleet-cap.js";
import {
  readFleetActivation,
  writeFleetActivation,
} from "./activation.js";
import { resolveEntitlement } from "./token.js";
import { isLicenseRevoked } from "./revocation-list.js";
import { revocationVerifiability } from "./revocation-antirollback.js";
import {
  appendDowngradeLog,
  type DowngradeLogEntry,
  type DowngradeTransitionKind,
} from "./downgrade-log.js";

/**
 * A minimal snapshot of the last cap the fortress presented, so a re-resolve can
 * tell whether anything CHANGED (and therefore whether to log a transition). The
 * caller holds this across ticks (in-memory is fine; it is advisory).
 */
export interface PriorCapState {
  tier: string;
  maxNodes: number | null;
}

/** The absolute set of node ids a re-resolve pass has to work from. */
export interface ReResolveRosterView {
  /** Whether the roster is provisioned/available (false = no fleet to cap). */
  available: boolean;
  /** The active (admitted, non-revoked) node count on the DURABLE roster. */
  admittedCount: number;
  /**
   * The ordered node ids as the central roster presents them (stable order). The
   * cap retains the first `maxNodes`; the REST are the ones that leave the
   * console. Used to compute `droppedNodeIds` for the log.
   */
  orderedNodeIds: string[];
}

/** The classified transition between a prior cap and a freshly-resolved cap. */
export interface CapTransition {
  changed: boolean;
  kind: DowngradeTransitionKind;
  droppedNodeIds: string[];
}

/**
 * Classify the transition from `prior` to `next` given the roster, PURE. Decides
 * whether the cap changed and, if it shrank, which node ids left the console.
 *
 *  - No prior state (first pass) OR identical (tier, maxNodes): `changed: false`.
 *  - A LOWER effective cap (fewer nodes manageable) OR a drop to a lower tier:
 *    `downgrade`, with `droppedNodeIds` = the roster nodes beyond the new cap.
 *  - A HIGHER cap / restored paid tier: `upgrade` (no dropped ids).
 *
 * `null` maxNodes (unlimited) is treated as the largest possible cap. The dropped
 * set is computed from the NEW cap over the CURRENT roster order, so it names the
 * nodes that are out of console RIGHT NOW under the new cap.
 */
export function diffCapTransition(
  prior: PriorCapState | null,
  next: FleetCap,
  roster: ReResolveRosterView,
): CapTransition {
  const nextMax = next.maxNodes;
  // Nodes beyond the new cap, in stable roster order, are the ones out of console.
  const droppedNodeIds =
    nextMax === null || !roster.available
      ? []
      : roster.orderedNodeIds.slice(Math.max(0, nextMax));

  if (prior === null) {
    // First observed state: only LOG it as a transition if it is a real
    // downgrade (nodes are actually being dropped right now); a first-boot
    // Community fortress with <=cap nodes is not a "transition" worth a row.
    if (droppedNodeIds.length > 0) {
      return { changed: true, kind: "downgrade", droppedNodeIds };
    }
    return { changed: false, kind: "upgrade", droppedNodeIds: [] };
  }

  const priorMax = prior.maxNodes;
  const sameTier = prior.tier === next.tier;
  const sameCap = priorMax === nextMax;
  if (sameTier && sameCap) {
    return { changed: false, kind: "upgrade", droppedNodeIds: [] };
  }

  // A shrink in capacity (either the numeric cap dropped, or unlimited -> finite,
  // or the tier fell) is a downgrade; otherwise it is an upgrade.
  const priorEffective = priorMax === null ? Number.POSITIVE_INFINITY : priorMax;
  const nextEffective = nextMax === null ? Number.POSITIVE_INFINITY : nextMax;
  const isDowngrade = nextEffective < priorEffective;
  return {
    changed: true,
    kind: isDowngrade ? "downgrade" : "upgrade",
    droppedNodeIds: isDowngrade ? droppedNodeIds : [],
  };
}

/** Project an EntitlementResolution to the minimal cap-gate view (mirror activation.toView). */
function toView(resolution: {
  granted: boolean;
  tier: string;
  entitledCount?: number | null;
  pricingUnit?: string;
  graceActive?: boolean;
  reason?: string;
}): ResolvedEntitlementView {
  return {
    granted: resolution.granted,
    tier: resolution.tier,
    ...(resolution.entitledCount !== undefined
      ? { entitledCount: resolution.entitledCount }
      : {}),
    ...(resolution.pricingUnit !== undefined
      ? { pricingUnit: resolution.pricingUnit }
      : {}),
    ...(resolution.graceActive !== undefined
      ? { graceActive: resolution.graceActive }
      : {}),
    ...(resolution.reason !== undefined ? { reason: resolution.reason } : {}),
  };
}

/** A human-readable line for the downgrade log / banner (no secrets). */
function transitionMessage(
  kind: DowngradeTransitionKind,
  cap: FleetCap,
  droppedCount: number,
): string {
  if (kind === "grandfather_capture") {
    return (
      `This fleet was managing ${cap.maxNodes ?? "an unlimited number of"} nodes ` +
      "before licensing was introduced; that count is now grandfathered free, " +
      "indefinitely. No action needed."
    );
  }
  if (kind === "revocation_list_unreadable") {
    return (
      "The stored license revocation list could not be authenticated " +
      "(it may be corrupt), so revocation state is unverifiable and central " +
      "management has dropped to Community until a fresh signed revocation list " +
      "is re-pushed. No node's Castle Wall protection is affected."
    );
  }
  if (kind === "upgrade") {
    return (
      `Central fleet management restored (${cap.tier}). ` +
      (cap.maxNodes === null
        ? "Unlimited nodes can now be managed centrally."
        : `Up to ${cap.maxNodes} nodes can be managed centrally.`)
    );
  }
  // downgrade
  const reasonPhrase =
    cap.reason === "expired"
      ? "the plan expired"
      : cap.reason === "invalid"
        ? "the license could not be verified"
        : cap.reason === "unreadable"
          ? "the activation record could not be read"
          : cap.reason === "no_license"
            ? "no active plan"
            : "the plan lapsed";
  const nodePart =
    droppedCount > 0
      ? `${droppedCount} node${droppedCount === 1 ? "" : "s"} left the central ` +
        "console. Their Castle Wall protection is unaffected."
      : "Central management capacity was reduced.";
  return (
    `Fleet downgraded to ${cap.tier} because ${reasonPhrase}. ${nodePart} ` +
    "Renew to restore central console management."
  );
}

/** The outcome of one re-resolve pass. */
export interface ReResolveResult {
  /** The freshly-resolved, revocation-aware, fail-closed cap. */
  cap: FleetCap;
  /** True when the effective license was REVOKED (forced to Community). */
  revoked: boolean;
  /** True when the stored revocation list failed to authenticate (surfaced). */
  revocationListUnreadable: boolean;
  /** True when auto-capture recorded a NEW grandfather baseline this pass. */
  grandfatherCaptured: boolean;
  /** The transition classified against `prior` (for the caller's banner + state). */
  transition: CapTransition;
}

/**
 * Run one scheduled license re-resolve pass, FAIL-CLOSED. This is what the daemon
 * tick calls. It:
 *   1. reads the activation record + re-resolves the token at `now`;
 *   2. consults the SIGNED revocation list - a revoked license is forced to
 *      Community regardless of its own validity;
 *   3. AUTO-CAPTURES a never-activated over-cap fleet's grandfather baseline
 *      (one-time, grow-only, durable) so it is not force-capped at the flip;
 *   4. classifies the transition vs `prior` and appends a downgrade-log entry
 *      (best-effort; a log failure never reverses the cap).
 *
 * NEVER throws. NEVER grants a paid cap on any failure. Touches no wall path.
 */
export async function runFleetReResolve(args: {
  storage: StorageBackend;
  master: Uint8Array;
  issuerPublicKey: Uint8Array;
  now: number;
  nowIso?: () => Date;
  roster: ReResolveRosterView;
  prior: PriorCapState | null;
}): Promise<ReResolveResult> {
  const { storage, master, issuerPublicKey, now, roster, prior } = args;
  const nowIso = args.nowIso ?? (() => new Date());

  const record = await readFleetActivation(storage, master);

  // ── Auto-capture: a never-activated (absent) over-cap fleet grandfathers its
  // CURRENT durable count, ONCE. An absent record means no license was ever
  // activated, so #889's first-activation capture never fired. Grow-only:
  // captured only when the durable admitted count exceeds the free cap.
  let grandfatherCaptured = false;
  if (
    record.status === "absent" &&
    roster.available &&
    roster.admittedCount > COMMUNITY_FREE_NODE_CAP
  ) {
    // Persist a grandfather baseline WITHOUT a token: writeFleetActivation is
    // token+baseline; but an absent-license fleet has no token to store. We use a
    // dedicated capture that records ONLY the baseline (see captureGrandfather).
    grandfatherCaptured = await captureGrandfatherBaseline(
      storage,
      master,
      roster.admittedCount,
      nowIso,
    );
  }

  // Re-read after a possible capture so the baseline is reflected.
  const capRecord = grandfatherCaptured
    ? await readFleetActivation(storage, master)
    : record;

  // ── Resolve the cap at `now` (honors expiry/grace) from the (re-read) record.
  let cap: FleetCap;
  let licenseId: string | null = null;
  if (capRecord.status === "absent") {
    cap = resolveFleetCap({ granted: false, tier: "community", reason: "absent" }, 0);
  } else if (capRecord.status === "invalid") {
    cap = {
      maxNodes: COMMUNITY_FREE_NODE_CAP,
      paid: false,
      tier: "community",
      reason: "unreadable",
      graceActive: false,
    };
  } else {
    const resolution = resolveEntitlement({
      token: capRecord.data.token,
      issuerPublicKey,
      now,
    });
    licenseId = typeof resolution.licenseId === "string" ? resolution.licenseId : null;
    cap = resolveFleetCap(toView(resolution), capRecord.data.grandfatheredBaseline);
  }

  // ── Revocation: a revoked license is forced to Community. This consults the
  // SINGLE {@link revocationVerifiability} chokepoint, which fails closed UNIFORMLY
  // on every way the revocation record can lie: CORRUPT (present, MAC fail),
  // ABSENT-after-a-push (list deleted while the custody-MAC'd witness floor /
  // standalone anchor proves a version-N revocation existed - the delete bypass
  // this fix closes), and ROLLED-BACK (present below the established floor). Any of
  // those => revocation state UNVERIFIABLE => drop a paid grant to Community. An
  // ABSENT list with NO established floor keeps the grant (the legit case). A
  // TRANSIENT storage error is FLOOR-CONDITIONED grace: grace only when floor === 0
  // (nothing ever revoked); a transient that never clears on an ESTABLISHED floor
  // (> 0) is itself `unverifiable` (transient_below_floor) -> drop, because we
  // cannot confirm the license is un-revoked. The id-on-list check (`revoked`) is
  // consulted ONLY on a verifiably-clean list.
  const verifiability = await revocationVerifiability(storage, master);
  const revocationListUnverifiable = verifiability.status === "unverifiable";
  let revoked = false;
  if (verifiability.status === "clean") {
    const status = await isLicenseRevoked(storage, master, licenseId);
    revoked = status.revoked;
  }
  if (cap.paid && (revoked || revocationListUnverifiable)) {
    // Force to the community floor, preserving the (authenticated) grandfather
    // baseline so a revoked/corrupt-but-grandfathered fleet keeps its count.
    const baseline =
      capRecord.status === "valid" ? capRecord.data.grandfatheredBaseline : 0;
    cap = resolveFleetCap(
      { granted: false, tier: "community", reason: "invalid" },
      baseline,
    );
  }

  // ── Classify the transition + append the log (best-effort).
  const transition = grandfatherCaptured
    ? { changed: true, kind: "grandfather_capture" as const, droppedNodeIds: [] }
    : diffCapTransition(prior, cap, roster);

  if (transition.changed) {
    const entry: DowngradeLogEntry = {
      at: nowIso().toISOString(),
      kind: transition.kind,
      fromTier: prior?.tier ?? cap.tier,
      toTier: cap.tier,
      fromMaxNodes: prior?.maxNodes ?? cap.maxNodes,
      toMaxNodes: cap.maxNodes,
      reason: cap.reason,
      droppedNodeIds: transition.droppedNodeIds,
      message: transitionMessage(
        transition.kind,
        cap,
        transition.droppedNodeIds.length,
      ),
    };
    await safeAppend(storage, master, entry);
  }

  // Surface an unverifiable revocation list as its own log row (once per pass it
  // is seen), so the operator knows to re-push. Best-effort, never blocks. This
  // now fires for the deletion + rollback cases too, not only present-corruption.
  if (revocationListUnverifiable) {
    await safeAppend(storage, master, {
      at: nowIso().toISOString(),
      kind: "revocation_list_unreadable",
      fromTier: cap.tier,
      toTier: cap.tier,
      fromMaxNodes: cap.maxNodes,
      toMaxNodes: cap.maxNodes,
      reason: cap.reason,
      droppedNodeIds: [],
      message: transitionMessage("revocation_list_unreadable", cap, 0),
    });
  }

  return {
    cap,
    revoked,
    revocationListUnreadable: revocationListUnverifiable,
    grandfatherCaptured,
    transition,
  };
}

/** Append without ever letting a log failure escape (observability is best-effort). */
async function safeAppend(
  storage: StorageBackend,
  master: Uint8Array,
  entry: DowngradeLogEntry,
): Promise<void> {
  try {
    await appendDowngradeLog(storage, master, entry);
  } catch {
    // Best-effort: a failed log append must never reverse the cap transition.
  }
}

/**
 * Capture a grandfather baseline for a NEVER-ACTIVATED (absent) over-cap fleet,
 * ONCE. Because the activation record shape is `token + baseline`, and an
 * absent-license fleet has no token, we persist a SYNTHETIC baseline-only record
 * via {@link writeGrandfatherOnlyActivation}. Grow-only + idempotent:
 *
 *   - only runs when the record is ABSENT (a valid/paid record already carries
 *     its own baseline; we never touch it);
 *   - only when `admittedCount > COMMUNITY_FREE_NODE_CAP` (a small fleet needs no
 *     grandfather);
 *   - re-entrancy safe: once written, the record is no longer absent, so a later
 *     pass takes the valid branch and does not re-capture.
 *
 * Returns true when a NEW baseline was written this call. Never throws (a write
 * failure returns false - the fleet is simply not grandfathered yet and will be
 * re-attempted next tick, never force-capped incorrectly because the read path
 * still honors the durable count on the NEXT successful capture).
 */
async function captureGrandfatherBaseline(
  storage: StorageBackend,
  master: Uint8Array,
  admittedCount: number,
  nowIso: () => Date,
): Promise<boolean> {
  try {
    await writeGrandfatherOnlyActivation(storage, master, admittedCount, nowIso);
    return true;
  } catch {
    return false;
  }
}

/**
 * Re-export the activation writer specialized for the token-less grandfather
 * capture. See {@link writeFleetActivation}: it requires a token. For an
 * absent-license fleet we have no token, so we synthesize a NON-GRANTING sentinel
 * token whose claims can never resolve to a paid tier (it is a community-tier v1
 * token with a zero window), carrying ONLY the grandfather baseline. On resolve,
 * the sentinel token denies (community) but its authenticated baseline is
 * honored - exactly the "keep your current count free, no paid grant" semantics.
 */
async function writeGrandfatherOnlyActivation(
  storage: StorageBackend,
  master: Uint8Array,
  baseline: number,
  nowIso: () => Date,
): Promise<void> {
  // A sentinel token that CANNOT resolve to a paid tier under any key: a v1
  // community-tier token with an empty validity window. resolveEntitlement will
  // deny it (bad_signature / expired), so it never grants; only the
  // master-authenticated baseline it is stored alongside takes effect.
  const sentinelToken = {
    claims: {
      version: 1,
      subject: "grandfather-capture",
      tier: "community" as const,
      notBefore: 0,
      notAfter: 0,
    },
    signature: "",
  };
  await writeFleetActivation(storage, master, sentinelToken, baseline, nowIso);
}
