/**
 * Sanctuary MCP Server — Anti-Rollback Epoch Anchoring (Stage 1)
 *
 * Closes the freshness residual documented in #496: every custody artifact is
 * integrity-protected, but integrity is not freshness. An attacker with disk
 * write but WITHOUT the current master cannot forge anything — so instead they
 * restore an older, internally-valid snapshot (old envelope + old wraps + old
 * state + old audit + old anchors, all mutually consistent because they once
 * WERE the fortress). The headline attack: resurrecting a rotated-away
 * credential post-#501 — restore the pre-rotation snapshot and the leaked
 * passphrase unlocks the fortress again, silently undoing F7 rotation.
 *
 * STAGE 1 (this module) — the on-disk, offline-first, no-new-trust-root
 * detector. It maintains a monotonic `epoch` witness and cross-checks it at
 * boot against the witnesses that already exist on disk:
 *   (a) the #501 master-rotation epoch record (`__custody_epoch_keys`),
 *   (b) the audit head anchor (`__head_anchor`),
 *   (c) the transparency counter floor (when transparency is enabled).
 *
 * The epoch is also carried in the custody envelope (additive field, bound
 * into the envelope MAC; absent reads as epoch 0 for pre-Stage-1 fortresses),
 * so a partial/spliced rollback that grafts an old envelope onto newer audit
 * (or vice versa) shows up as a pairwise epoch regression.
 *
 * ── FAIL POSTURE (Erik-ratified, F3 precedent) ─────────────────────────────
 * On detected rollback (on-disk epoch < the highest witness):
 *   1. WARN LOUD + emit a P1-shaped `custody_rollback_suspected` audit finding.
 *   2. FREEZE trust-bearing writes (the CustodyFloorError / enforceCustodyFloor
 *      chokepoint from #496) — no new identity, reputation import, Castle-pin
 *      provisioning, or transparency checkpoint emission from a suspected-
 *      rolled-back fortress.
 *   3. NEVER refuse boot. A false-positive rollback detector that bricks a
 *      fortress is worse than the attack: legitimate restores (Time Machine,
 *      backup, dotfile sync, cloning to a new machine) are GUARANTEED false
 *      positives. F3's lesson governs — no lockout generators.
 *   4. `restore-attest` (passphrase-required, audited operator action) re-
 *      baselines the epoch witness and clears the freeze, turning the rollback
 *      into an honest, permanently-recorded event rather than a hidden one.
 *
 * ── FAIL DIRECTION ─────────────────────────────────────────────────────────
 * A tampered or missing epoch witness fails in the FREEZE direction, never the
 * brick direction: a witness that does not authenticate is treated as
 * suspected-rollback (freeze + warn), not as "no rollback" and not as "refuse
 * boot". The attacker's cheapest move — deleting the witness — must not become
 * either a silent bypass or a denial-of-service that locks the operator out.
 *
 * ── INTERACTION WITH MASTER ROTATION (#501) ────────────────────────────────
 * A legitimate rotation ADVANCES the epoch: the rotation engine bumps the
 * witness (and the staged envelope's epoch) at finalize, so a freshly-rotated
 * fortress has witness.epoch == envelope.epoch == rotation_count and trips
 * nothing. The epoch is the #501 rotation count; epoch_id is the last
 * rotation_id (or a creation nonce at epoch 0).
 *
 * ── HONEST RESIDUAL (preserve — do not over-claim) ─────────────────────────
 * A full-disk rollback that restores the ENTIRE `~/.sanctuary` tree to a
 * self-consistent earlier snapshot — old custody + old state + old audit (incl.
 * the old audit head anchor, MAC'd under the old master, which therefore
 * authenticates) + deleted/old witnesses — stays LOCALLY UNDETECTABLE on an
 * unanchored (no-transparency) fortress until the hardware stage. Everything
 * Stage 1 anchors lives under the same tree, so a self-consistent full-tree
 * restore is, by construction, invisible to an on-disk-only detector. In
 * particular, a full rollback to the genuine epoch-0 pre-rotation snapshot
 * looks identical to a fortress that simply never rotated.
 *
 * What Stage 1 DOES close is the SPLICE class — a custody-files-only rollback
 * (the cheapest, most likely A1 move to resurrect a retired credential): the
 * attacker restores only `_meta/custody-*` to swap in an old master, but the
 * CURRENT audit head anchor (MAC'd under the current master) survives and fails
 * to authenticate under the swapped-in old master. That mismatch is detected
 * EVEN IF the attacker also deletes the epoch witness, the #501 epoch record,
 * the head anchor itself, AND its plaintext established-marker (codex r1/r2/r3
 * HIGH fixes): `probeAuditHeadAnchor` treats a missing head anchor as the splice
 * signature whenever ANY independent "was-established" evidence survives — the
 * established marker OR surviving `_audit` entries OR `_audit_checkpoints`
 * records. To erase the detector's memory the attacker must therefore WIPE THE
 * ENTIRE AUDIT TRAIL (every `_audit` entry + every checkpoint + the marker),
 * which is no longer a quiet splice but a wholesale audit destruction — itself
 * glaring and separately surfaced (reset-history / empty-chain). The remaining
 * residual is exactly that full wipe on an unanchored fortress, bounded
 * externally by Stage 2 (transparency floor / Rekor) and eliminated only by
 * Stage 4 hardware.
 *
 * ── DEFERRED STAGES (named, not built) ─────────────────────────────────────
 *   Stage 2 — Rekor counter-floor: when transparency anchoring is on, require
 *     the on-disk counter floor ≥ the highest externally-anchored counter, and
 *     wire it into `verify-transparency --check-anchors`. The only defense that
 *     survives a full-snapshot rollback for an anchored fortress. See
 *     {@link STAGE_2_REKOR_COUNTER_FLOOR}.
 *   Stage 3 — OS keychain stamp: an advisory second witness outside the
 *     fortress tree, never boot-blocking. See {@link STAGE_3_KEYCHAIN_STAMP}.
 *   Stage 4 — hardware monotonic counter (SE post-login / TPM): the only thing
 *     that survives a full-disk restore including the keyring. See
 *     {@link STAGE_4_HARDWARE_COUNTER}.
 */

import type { StorageBackend } from "../storage/interface.js";
import { derivePurposeKey } from "./key-derivation.js";
import { hmacSha256 } from "./hashing.js";
import { canonicalJson } from "../audit/chain.js";
import {
  toBase64url,
  fromBase64url,
  stringToBytes,
  bytesToString,
  constantTimeEqual,
} from "./encoding.js";

// ── Deferred-stage name stubs (Stage 2/3/4 are NOT implemented here) ────────

/** Stage 2: Rekor counter-floor cross-check. NOT in scope for Stage 1. */
export const STAGE_2_REKOR_COUNTER_FLOOR =
  "anti-rollback-stage-2-rekor-counter-floor" as const;
/** Stage 3: OS keychain advisory stamp. NOT in scope for Stage 1. */
export const STAGE_3_KEYCHAIN_STAMP =
  "anti-rollback-stage-3-keychain-stamp" as const;
/** Stage 4: hardware monotonic counter (SE/TPM). NOT in scope for Stage 1. */
export const STAGE_4_HARDWARE_COUNTER =
  "anti-rollback-stage-4-hardware-counter" as const;

// ── Epoch witness record (`_meta/custody-epoch-witness-v1`) ─────────────────

/** `_meta` key holding the master-MAC'd monotonic epoch witness. */
export const EPOCH_WITNESS_META_KEY = "custody-epoch-witness-v1";
/** `_meta` key holding the rollback-freeze marker (set on detection). */
export const ROLLBACK_FREEZE_META_KEY = "custody-rollback-freeze-v1";

const EPOCH_WITNESS_MARKER = "__sanctuary_custody_epoch_witness_v1";
const EPOCH_WITNESS_MAC_DOMAIN = "sanctuary.custody-epoch-witness.v1\n";
const EPOCH_WITNESS_MAC_PURPOSE = "custody-epoch-witness-mac";

const FREEZE_MARKER = "__sanctuary_custody_rollback_freeze_v1";
const FREEZE_MAC_DOMAIN = "sanctuary.custody-rollback-freeze.v1\n";
const FREEZE_MAC_PURPOSE = "custody-rollback-freeze-mac";

export interface EpochWitnessData {
  /** Monotonic epoch = #501 master-rotation count (0 at creation). */
  epoch: number;
  /** Last rotation_id, or a creation nonce at epoch 0. Advisory provenance. */
  epoch_id: string;
  witnessed_at: string;
}

function epochWitnessMac(master: Uint8Array, data: EpochWitnessData): Uint8Array {
  const macKey = derivePurposeKey(master, EPOCH_WITNESS_MAC_PURPOSE);
  const mac = hmacSha256(
    macKey,
    stringToBytes(EPOCH_WITNESS_MAC_DOMAIN + canonicalJson(data))
  );
  macKey.fill(0);
  return mac;
}

/**
 * Read + authenticate the epoch witness.
 *  - "valid": authenticates under the master → trustworthy floor.
 *  - "absent": no witness record at all → pre-Stage-1 fortress (or first boot).
 *  - "invalid": present but tampered/malformed/wrong-key → treat as suspected
 *    rollback (FREEZE direction), never as absent and never as a boot refusal.
 *
 * "absent" and "invalid" are deliberately DISTINCT: an attacker who deletes the
 * witness produces "absent", which `observeWitnessEpoch` resolves by falling
 * back to the OTHER on-disk witnesses (epoch record) — so deletion cannot
 * launder a rollback that those witnesses still expose.
 */
export async function readEpochWitness(
  storage: StorageBackend,
  master: Uint8Array
): Promise<
  | { status: "valid"; data: EpochWitnessData }
  | { status: "absent" }
  | { status: "invalid" }
> {
  let raw: Uint8Array | null;
  try {
    raw = await storage.read("_meta", EPOCH_WITNESS_META_KEY);
  } catch {
    // Unreadable storage is a witness we cannot trust → suspected, not absent.
    return { status: "invalid" };
  }
  if (!raw) return { status: "absent" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToString(raw));
  } catch {
    return { status: "invalid" };
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    (parsed as Record<string, unknown>)[EPOCH_WITNESS_MARKER] !== true
  ) {
    return { status: "invalid" };
  }
  const obj = parsed as Record<string, unknown>;
  const data = obj.data as Partial<EpochWitnessData> | undefined;
  const mac = obj.mac;
  if (
    !data ||
    typeof data !== "object" ||
    typeof data.epoch !== "number" ||
    !Number.isSafeInteger(data.epoch) ||
    data.epoch < 0 ||
    typeof data.epoch_id !== "string" ||
    typeof data.witnessed_at !== "string" ||
    typeof mac !== "string"
  ) {
    return { status: "invalid" };
  }
  const fullData: EpochWitnessData = {
    epoch: data.epoch,
    epoch_id: data.epoch_id,
    witnessed_at: data.witnessed_at,
  };
  let provided: Uint8Array;
  try {
    provided = fromBase64url(mac);
  } catch {
    return { status: "invalid" };
  }
  if (!constantTimeEqual(provided, epochWitnessMac(master, fullData))) {
    return { status: "invalid" };
  }
  return { status: "valid", data: fullData };
}

/**
 * Persist (or raise) the epoch witness. The witness is MONOTONIC: it never
 * regresses. Callers establishing the witness pass the epoch they observe;
 * this function refuses to write a LOWER epoch than an already-valid witness
 * (that would itself be a rollback-laundering write). A higher epoch (a
 * legitimate rotation) or an equal epoch (re-stamp) is accepted.
 *
 * `force` (restore-attest only) re-baselines to an explicit epoch even when it
 * is lower than the current witness — the audited, passphrase-gated escape
 * hatch. Without it, witness writes are strictly non-decreasing.
 */
export async function writeEpochWitness(
  storage: StorageBackend,
  master: Uint8Array,
  data: EpochWitnessData,
  opts?: { force?: boolean }
): Promise<void> {
  if (!opts?.force) {
    const current = await readEpochWitness(storage, master);
    if (current.status === "valid" && data.epoch < current.data.epoch) {
      throw new Error(
        "Sanctuary: refusing to lower the custody epoch witness " +
          `(${current.data.epoch} → ${data.epoch}) without an explicit restore ` +
          "attestation. Use `sanctuary restore-attest`."
      );
    }
  }
  const record = {
    [EPOCH_WITNESS_MARKER]: true,
    data,
    mac: toBase64url(epochWitnessMac(master, data)),
  };
  await storage.write(
    "_meta",
    EPOCH_WITNESS_META_KEY,
    stringToBytes(JSON.stringify(record))
  );
}

// ── Rollback-freeze marker ──────────────────────────────────────────────────

export interface FreezeData {
  /** The witness floor at the moment of detection. */
  witnessed_epoch: number;
  /** The (lower) on-disk epoch that tripped the detector. */
  observed_epoch: number;
  /** Which witness exposed the regression (for the operator banner). */
  witness_source: string;
  frozen_at: string;
}

function freezeMac(master: Uint8Array, data: FreezeData): Uint8Array {
  const macKey = derivePurposeKey(master, FREEZE_MAC_PURPOSE);
  const mac = hmacSha256(
    macKey,
    stringToBytes(FREEZE_MAC_DOMAIN + canonicalJson(data))
  );
  macKey.fill(0);
  return mac;
}

/**
 * Whether trust-bearing writes are currently frozen by a suspected rollback.
 * Fails CLOSED (frozen) on an unreadable/tampered freeze marker: an attacker
 * must not be able to clear the freeze by corrupting its own marker. A marker
 * that is genuinely absent means no freeze. A present marker that does not
 * authenticate is treated as frozen — the only legitimate way out is
 * `restore-attest`, which deletes the marker under the master.
 */
export async function isRollbackFrozen(
  storage: StorageBackend,
  master: Uint8Array
): Promise<{ frozen: boolean; data?: FreezeData }> {
  let raw: Uint8Array | null;
  try {
    raw = await storage.read("_meta", ROLLBACK_FREEZE_META_KEY);
  } catch {
    // Cannot read the marker → cannot prove it is absent → stay frozen.
    return { frozen: true };
  }
  if (!raw) return { frozen: false };
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToString(raw));
  } catch {
    return { frozen: true };
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    (parsed as Record<string, unknown>)[FREEZE_MARKER] !== true
  ) {
    return { frozen: true };
  }
  const obj = parsed as Record<string, unknown>;
  const data = obj.data as Partial<FreezeData> | undefined;
  const mac = obj.mac;
  if (
    !data ||
    typeof data !== "object" ||
    typeof data.witnessed_epoch !== "number" ||
    typeof data.observed_epoch !== "number" ||
    typeof data.witness_source !== "string" ||
    typeof data.frozen_at !== "string" ||
    typeof mac !== "string"
  ) {
    return { frozen: true };
  }
  const fullData: FreezeData = {
    witnessed_epoch: data.witnessed_epoch,
    observed_epoch: data.observed_epoch,
    witness_source: data.witness_source,
    frozen_at: data.frozen_at,
  };
  let provided: Uint8Array;
  try {
    provided = fromBase64url(mac);
  } catch {
    return { frozen: true };
  }
  if (!constantTimeEqual(provided, freezeMac(master, fullData))) {
    return { frozen: true };
  }
  return { frozen: true, data: fullData };
}

/**
 * Freeze gate for the trust-bearing-write chokepoint (enforceCustodyFloor),
 * codex r2 MEDIUM: the freeze marker is a CACHE, not the boundary. If a
 * filesystem attacker DELETES the marker (making isRollbackFrozen read
 * "absent" → not frozen), this RECOMPUTES the rollback verdict from the same
 * witness set the boot detector uses (epoch witness + #501 epoch record + audit
 * head anchor splice probe vs the on-disk envelope epoch). On a re-detected
 * rollback it re-writes the freeze and reports frozen — so a marker deletion
 * cannot unfreeze trust-bearing writes even within a single running process.
 *
 * A present marker short-circuits to {@link isRollbackFrozen} (fail-closed on
 * tamper). Only an ABSENT marker triggers the (slightly costlier) recompute.
 */
export async function isRollbackFrozenWithRecompute(
  storage: StorageBackend,
  master: Uint8Array
): Promise<{ frozen: boolean; data?: FreezeData }> {
  const marker = await isRollbackFrozen(storage, master);
  let rawMarker: Uint8Array | null;
  try {
    rawMarker = await storage.read("_meta", ROLLBACK_FREEZE_META_KEY);
  } catch {
    // Unreadable marker already returned frozen above; keep it.
    return marker;
  }
  if (rawMarker !== null) return marker; // present (or tampered) → trust the gate

  // Marker genuinely absent. Recompute from the witnesses so a freeze cannot be
  // bypassed by deleting the cache. Lazy imports avoid a static cycle with
  // master-custody (which dynamically imports this module).
  const { readEnvelopeEpoch } = await import("./master-custody.js");
  const { readCustodyEpochCount, probeAuditHeadAnchor, deriveAuditEpochKeys } =
    await import("../l2-operational/audit-log.js");

  const epochKeys = deriveAuditEpochKeys(master);
  let rotationEpochCount = 0;
  let rotationEpochTampered = false;
  try {
    const rec = await readCustodyEpochCount(storage, {
      epochMacKey: epochKeys.epochMacKey,
    });
    if (rec.status === "present") rotationEpochCount = rec.count;
    else if (rec.status === "tampered") rotationEpochTampered = true;
  } finally {
    epochKeys.epochWrapKey.fill(0);
    epochKeys.epochMacKey.fill(0);
  }
  const headAnchor = await probeAuditHeadAnchor(storage, master);
  const observation = await observeWitnessEpoch({
    storage,
    master,
    rotationEpochCount,
    rotationEpochTampered,
    headAnchor: { status: headAnchor.status },
  });
  const envelopeEpoch = await readEnvelopeEpoch(storage);
  const verdict = evaluateRollback({ envelopeEpoch, observation });
  if (verdict.kind === "rollback-suspected") {
    const data: FreezeData = {
      witnessed_epoch: verdict.witnessedEpoch,
      observed_epoch: verdict.observedEpoch,
      witness_source: verdict.witnessSource,
      frozen_at: new Date().toISOString(),
    };
    // Re-establish the deleted freeze so it persists for subsequent checks.
    await writeFreeze(storage, master, data);
    return { frozen: true, data };
  }
  return { frozen: false };
}

async function writeFreeze(
  storage: StorageBackend,
  master: Uint8Array,
  data: FreezeData
): Promise<void> {
  const record = {
    [FREEZE_MARKER]: true,
    data,
    mac: toBase64url(freezeMac(master, data)),
  };
  await storage.write(
    "_meta",
    ROLLBACK_FREEZE_META_KEY,
    stringToBytes(JSON.stringify(record))
  );
}

async function clearFreeze(storage: StorageBackend): Promise<void> {
  await storage.delete("_meta", ROLLBACK_FREEZE_META_KEY);
}

// ── Witness observation (the on-disk freshness floor) ───────────────────────

export interface WitnessObservation {
  /** Highest epoch observed across all on-disk witnesses. */
  highestEpoch: number;
  /** Which witness produced `highestEpoch` (operator-facing). */
  source: string;
  /**
   * True when any witness was present-but-untrustworthy (tampered/missing in a
   * way that authenticates as suspicious). Forces the FREEZE direction even if
   * the trustworthy witnesses agree, so a tampered witness cannot be ignored.
   */
  suspect: boolean;
  /** Detail lines for the audit finding (never key material). */
  notes: string[];
}

/**
 * Observe the freshness floor from the witnesses that ALREADY exist on disk —
 * the #501 master-rotation epoch record and the authenticated epoch witness
 * record. Returns the highest epoch any of them attests, and whether any was
 * tampered (forcing the freeze direction).
 *
 * Rotation epoch = number of rotation entries in `__custody_epoch_keys`
 * (#501 grows it by one per rotation). The head anchor and transparency floor
 * are MONOTONIC COUNTERS, not epochs — they cannot give an epoch number, but a
 * head anchor that authenticates proves the fortress reached at least its
 * highest_sequence; that splice witness is consumed by the caller in
 * {@link evaluateAndEnforceRollback} via the `extraWitnessSuspect` flag (an old
 * envelope grafted onto a newer audit head shows up as a head-anchor that
 * fails to authenticate under the spliced-in master), not as an epoch source.
 */
export async function observeWitnessEpoch(args: {
  storage: StorageBackend;
  master: Uint8Array;
  /** Rotation count from the #501 epoch record (entries.length). -1 means
   * "could not read"; 0 means "no rotation has happened" (epoch 0). */
  rotationEpochCount: number;
  /** True when the #501 epoch record was present but failed authentication. */
  rotationEpochTampered: boolean;
  /**
   * SPLICE witness (codex r1 HIGH fix): the audit head anchor probed under the
   * SAME master that unlocked this boot.
   *  - "valid": the head belongs to this master (its highest_sequence is real
   *    work this master did). Not suspicious.
   *  - "absent": no head anchor (never-audited / brand-new fortress). Neutral.
   *  - "tampered": PRESENT but does NOT authenticate under this master → an old
   *    custody envelope (old master) was grafted onto a newer audit head. This
   *    is the custody-files-only splice that resurrects a retired credential
   *    EVEN IF the attacker also deleted the epoch witness + epoch record. The
   *    head anchor survives the splice and exposes it → suspect.
   *
   * Optional: defaults to "absent" (neutral) so unit tests and callers that do
   * not have an audit head anchor to probe behave as before. The boot detector
   * ALWAYS passes it.
   */
  headAnchor?: { status: "absent" | "valid" | "tampered" };
}): Promise<WitnessObservation> {
  const headAnchor = args.headAnchor ?? { status: "absent" as const };
  const notes: string[] = [];
  let highestEpoch = 0;
  let source = "creation";
  let suspect = false;

  // (a) #501 rotation epoch record.
  if (args.rotationEpochTampered) {
    suspect = true;
    notes.push(
      "the master-rotation epoch record (__custody_epoch_keys) is present but " +
        "failed authentication; treating as suspected rollback"
    );
  } else if (
    args.rotationEpochCount >= 0 &&
    args.rotationEpochCount > highestEpoch
  ) {
    highestEpoch = args.rotationEpochCount;
    source = "master-rotation epoch record (#501)";
  }

  // (b) the authenticated epoch witness record itself.
  const witness = await readEpochWitness(args.storage, args.master);
  if (witness.status === "invalid") {
    suspect = true;
    notes.push(
      "the custody epoch witness record is present but failed authentication; " +
        "treating as suspected rollback"
    );
  } else if (witness.status === "valid" && witness.data.epoch > highestEpoch) {
    highestEpoch = witness.data.epoch;
    source = "custody epoch witness record";
  }

  // (c) the audit head anchor SPLICE witness. A head anchor that does not
  // authenticate under the unlocked master is the custody-files-only splice
  // signature — it catches the codex r1 exploit (restore old custody +
  // DELETE both epoch witnesses), because the head anchor cannot be deleted
  // without also losing the current audit chain the attacker is trying to keep.
  if (headAnchor.status === "tampered") {
    suspect = true;
    if (source === "creation") source = "audit head anchor (splice signature)";
    notes.push(
      "the audit head anchor is present but does NOT authenticate under the " +
        "unlocked master; the custody files appear to be from a different " +
        "(older) master grafted onto this fortress's audit chain — a custody " +
        "splice that can resurrect a retired credential"
    );
  }

  return { highestEpoch, source, suspect, notes };
}

// ── The boot detector (Stage 1 composite) ───────────────────────────────────

export type RollbackVerdict =
  | { kind: "ok"; epoch: number }
  | {
      kind: "rollback-suspected";
      observedEpoch: number;
      witnessedEpoch: number;
      witnessSource: string;
      notes: string[];
    };

/**
 * Compare the on-disk custody epoch (`envelopeEpoch`) against the highest
 * witness. A regression — or any tampered witness — is a rollback verdict.
 * Pure function over already-read inputs so it is trivially unit-testable and
 * side-effect free; {@link evaluateAndEnforceRollback} does the I/O.
 */
export function evaluateRollback(args: {
  envelopeEpoch: number;
  observation: WitnessObservation;
}): RollbackVerdict {
  const { envelopeEpoch, observation } = args;
  // A tampered witness forces the freeze direction regardless of the numbers:
  // we cannot trust the comparison, so we fail closed toward freeze (not boot
  // refusal, not silent pass).
  if (observation.suspect) {
    return {
      kind: "rollback-suspected",
      observedEpoch: envelopeEpoch,
      witnessedEpoch: Math.max(observation.highestEpoch, envelopeEpoch),
      witnessSource: observation.source,
      notes: observation.notes,
    };
  }
  if (envelopeEpoch < observation.highestEpoch) {
    return {
      kind: "rollback-suspected",
      observedEpoch: envelopeEpoch,
      witnessedEpoch: observation.highestEpoch,
      witnessSource: observation.source,
      notes: [
        `on-disk custody epoch (${envelopeEpoch}) is older than the highest ` +
          `surviving witness (${observation.highestEpoch}); a snapshot may have ` +
          "been restored or the custody files spliced back",
        ...observation.notes,
      ],
    };
  }
  return { kind: "ok", epoch: envelopeEpoch };
}

export interface RollbackBootResult {
  verdict: RollbackVerdict;
  /** True when a freeze marker is now in effect (this boot or a prior one). */
  frozen: boolean;
  /** Operator-facing banner text when frozen/suspected; undefined otherwise. */
  banner?: string;
}

/**
 * The boot entry point. Reads every witness, runs {@link evaluateRollback}, and
 * on a rollback verdict: raises the freeze marker, returns a loud banner, and
 * the caller emits the P1 audit finding. On an OK verdict it advances the
 * monotonic witness to the current epoch (so the witness tracks forward without
 * a rotation) and, if a STALE freeze marker survives from a prior suspected
 * boot that the operator has NOT yet attested, keeps the freeze in effect.
 *
 * BOOT IS NEVER REFUSED here. The strict-mode opt-out (refuse boot) is a
 * deliberately separate, non-default operator choice and is NOT implemented in
 * Stage 1 — the default and only posture here is warn-loud + freeze.
 */
export async function evaluateAndEnforceRollback(args: {
  storage: StorageBackend;
  master: Uint8Array;
  envelopeEpoch: number;
  observation: WitnessObservation;
  now?: () => Date;
}): Promise<RollbackBootResult> {
  const now = args.now ?? (() => new Date());
  const verdict = evaluateRollback({
    envelopeEpoch: args.envelopeEpoch,
    observation: args.observation,
  });

  // A freeze from a prior suspected boot stays in effect until restore-attest.
  const priorFreeze = await isRollbackFrozen(args.storage, args.master);

  if (verdict.kind === "rollback-suspected") {
    // Preserve the ORIGINAL detection timestamp if a freeze is already set, so
    // re-boots don't reset the clock on an operator's outstanding attestation.
    if (!priorFreeze.frozen || !priorFreeze.data) {
      const freezeData: FreezeData = {
        witnessed_epoch: verdict.witnessedEpoch,
        observed_epoch: verdict.observedEpoch,
        witness_source: verdict.witnessSource,
        frozen_at: now().toISOString(),
      };
      await writeFreeze(args.storage, args.master, freezeData);
    }
    return {
      verdict,
      frozen: true,
      banner: rollbackBanner(verdict),
    };
  }

  // OK verdict. Advance the witness forward (monotonic; never lowers).
  await writeEpochWitness(args.storage, args.master, {
    epoch: args.envelopeEpoch,
    epoch_id: epochIdFor(args.observation, args.envelopeEpoch),
    witnessed_at: now().toISOString(),
  });

  // An OK verdict does NOT auto-clear a freeze: a freeze can only be cleared by
  // an explicit, passphrase-gated restore-attest. (If the operator restored
  // and the witness now happens to agree, they still attest — that is the
  // audited record. This prevents a re-roll-forward from silently laundering a
  // freeze that was set on a genuine rollback.)
  if (priorFreeze.frozen) {
    return {
      verdict,
      frozen: true,
      banner: priorFreeze.data
        ? staleFreezeBanner(priorFreeze.data)
        : tamperedFreezeBanner(),
    };
  }

  return { verdict, frozen: false };
}

function epochIdFor(obs: WitnessObservation, epoch: number): string {
  return epoch === 0 ? "epoch-0-creation" : `epoch-${epoch}:${obs.source}`;
}

function rollbackBanner(
  verdict: Extract<RollbackVerdict, { kind: "rollback-suspected" }>
): string {
  return (
    "\nSanctuary: WARNING — SUSPECTED CUSTODY ROLLBACK.\n" +
    `  on-disk custody epoch: ${verdict.observedEpoch}\n` +
    `  highest surviving witness: ${verdict.witnessedEpoch} (${verdict.witnessSource})\n` +
    "\n" +
    "This fortress looks OLDER than something on disk attests it should be. That\n" +
    "happens when a snapshot is restored (Time Machine, backup, dotfile sync,\n" +
    "cloning to a new machine) — all legitimate — or when an attacker with disk\n" +
    "access rolled custody back to resurrect a retired credential.\n" +
    "\n" +
    "Sanctuary is NOT refusing to boot. It HAS frozen trust-bearing writes (new\n" +
    "identities, reputation import, Castle-pin provisioning, transparency\n" +
    "checkpoint emission) until you acknowledge what happened:\n" +
    "\n" +
    "  sanctuary restore-attest   (requires the fortress passphrase)\n" +
    "\n" +
    "That records an honest, permanent audit entry that this fortress was restored\n" +
    "from an earlier epoch, and unfreezes writes. If you did NOT restore anything,\n" +
    "treat this as a possible attack: rotate the master before attesting.\n"
  );
}

function staleFreezeBanner(data: FreezeData): string {
  return (
    "\nSanctuary: trust-bearing writes remain FROZEN from an earlier suspected\n" +
    `rollback (detected ${data.frozen_at}; epoch ${data.observed_epoch} vs witness ` +
    `${data.witnessed_epoch}).\n` +
    "Run `sanctuary restore-attest` (fortress passphrase required) to acknowledge\n" +
    "and unfreeze.\n"
  );
}

function tamperedFreezeBanner(): string {
  return (
    "\nSanctuary: a rollback-freeze marker is present but did not authenticate.\n" +
    "Trust-bearing writes stay FROZEN (fail-closed). Run `sanctuary restore-attest`\n" +
    "to clear it under your passphrase.\n"
  );
}

// ── restore-attest (the operator escape hatch) ──────────────────────────────

export interface RestoreAttestResult {
  /** Epoch the witness was re-baselined to. */
  attestedEpoch: number;
  /** True when a freeze was actually in effect and has now been cleared. */
  unfroze: boolean;
}

/**
 * The audited, passphrase-gated operator action that re-baselines the epoch
 * witness to the current on-disk epoch and clears the freeze. This is the ONLY
 * sanctioned way down: it is gated on the master (the caller must have unwrapped
 * it from a real credential) and the AUDIT RECORD IS WRITTEN FIRST, before any
 * witness/freeze mutation, so the rollback becomes a permanent, honest record
 * rather than a silent laundering path.
 *
 * ATOMICITY (codex r2 HIGH): `recordAttestation` is invoked and AWAITED before
 * the witness is lowered or the freeze cleared. If it throws (audit append /
 * flush failure, tampered chain), restoreAttest propagates and mutates NOTHING
 * — there is no window where the freeze is cleared without the durable
 * attestation. The caller passes a callback that appends + flushes the
 * `custody_restore_attested` entry.
 *
 * It is NOT a rollback-laundering path because (a) it requires the passphrase —
 * an attacker without the current master cannot invoke it, which is exactly the
 * attacker Stage 1 defends against; and (b) every invocation is audited, so a
 * MALICIOUS operator's use of it (the A2 threat) is visible to any second
 * reader of the audit chain. It re-baselines to the CURRENT epoch (it cannot
 * fabricate a higher one), so it cannot be used to forge freshness.
 */
export async function restoreAttest(args: {
  storage: StorageBackend;
  master: Uint8Array;
  /** The current on-disk custody epoch the operator is attesting to. */
  currentEpoch: number;
  epochId: string;
  /**
   * Durable-audit callback (codex r2 HIGH): write + FLUSH the
   * `custody_restore_attested` entry. Invoked and awaited BEFORE any witness or
   * freeze mutation; if it throws, restoreAttest aborts having mutated nothing.
   * Receives the resolved freeze context so the caller can record the detection
   * detail in the same entry.
   */
  recordAttestation: (ctx: {
    attestedEpoch: number;
    epochId: string;
    willUnfreeze: boolean;
    priorFreeze?: FreezeData;
  }) => Promise<void>;
  now?: () => Date;
}): Promise<RestoreAttestResult> {
  const now = args.now ?? (() => new Date());
  const priorFreeze = await isRollbackFrozen(args.storage, args.master);
  const unfroze = priorFreeze.frozen && priorFreeze.data !== undefined;

  // Durable audit FIRST — fail closed: if this throws, nothing is mutated, so a
  // failed audit append can never leave the freeze cleared without a record.
  await args.recordAttestation({
    attestedEpoch: args.currentEpoch,
    epochId: args.epochId,
    willUnfreeze: unfroze,
    ...(priorFreeze.data ? { priorFreeze: priorFreeze.data } : {}),
  });

  // Force-write the witness to the attested epoch (this is the one place a
  // LOWER epoch is legitimate — the operator is asserting the restore is real).
  // A caller WITHOUT the current master writes a witness keyed to its own wrong
  // master; the real master reads that as "invalid" → suspect → re-freeze at
  // next boot, so a forged attestation cannot launder a rollback.
  await writeEpochWitness(
    args.storage,
    args.master,
    {
      epoch: args.currentEpoch,
      epoch_id: args.epochId,
      witnessed_at: now().toISOString(),
    },
    { force: true }
  );
  // Clear the freeze ONLY when the caller's master AUTHENTICATES the existing
  // freeze marker (priorFreeze.data is present only when the MAC verified under
  // this master). A wrong-master caller gets `frozen: true` with NO `data`
  // (fail-closed read) and therefore does NOT clear the marker — the freeze
  // survives for the real operator. The freeze marker is a CACHE of a prior
  // detection, not the security boundary: even if an attacker with raw disk
  // write deletes it outright, the boot detector (and enforceCustodyFloor's
  // marker-absent recompute) re-derives the verdict from the witness floor +
  // on-disk epoch + head anchor and re-freezes. The witness + envelope MAC
  // (master-keyed) are the actual boundary.
  if (unfroze) {
    await clearFreeze(args.storage);
  }
  return { attestedEpoch: args.currentEpoch, unfroze };
}
