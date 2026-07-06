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
 * ── STAGE 2 — REKOR COUNTER-FLOOR (built; the anchored-fortress defense) ────
 * For a fortress that has anchored, the external Rekor log holds counters
 * outside the attacker's disk. Stage 2 requires the on-disk transparency
 * counter floor ≥ the HIGHEST LOCALLY-RECORDED ANCHORED COUNTER (the highest
 * counter for which this fortress holds a cryptographically valid local anchor
 * receipt — resolved OFFLINE, no live network query). A floor BELOW that
 * highest locally-recorded anchored counter means the checkpoint store was
 * rolled back to before an anchoring the local receipts (and, behind them, the
 * external log) still remember: same posture as Stage 1 (warn-loud + the
 * `custody_rollback_suspected` finding + FREEZE via the SAME marker, never
 * refuse boot, `restore-attest` clears it).
 *
 * Stage 2 APPLIES when anchoring config reads ENABLED *or* any anchor receipt
 * is present on disk (codex FIX 1): a disk-write attacker WITHOUT the master
 * can delete or roll the config back to a validly-MAC'd `disabled` state while
 * PRESERVING the receipts, so "config not enabled" alone must not switch the
 * check off when receipts prove anchoring happened. A legitimately
 * disabled-after-anchoring fortress is NOT a false positive: its on-disk floor
 * is still ≥ its highest locally-recorded anchored counter, so the verdict is
 * CONSISTENT, not suspected — only a rolled-back floor trips the freeze. Only a
 * fortress with NO receipts AND a not-enabled config is genuinely
 * NOT-APPLICABLE.
 *
 * Exposed both at boot (composed with the Stage 1 witness cross-check when
 * Stage 2 applies) and on demand via `verify-transparency --check-anchors` /
 * `--check-counter-floor`.
 *
 * ── HONEST RESIDUAL — what offline Stage 2 does and does NOT catch ──────────
 * The "highest anchored counter" is derived from the LOCAL anchor receipts. A
 * disk-write attacker can DELETE those receipts. So offline Stage 2:
 *   - DOES catch a transparency-floor rollback that PRESERVES the local anchor
 *     receipts — the splice / tampered-floor / disabled-while-anchored cases
 *     (the floor regresses below receipts that are still on disk), plus a
 *     tampered/unreadable receipt store (fails toward freeze).
 *   - does NOT, by itself, catch a COORDINATED rollback that also DELETES the
 *     higher local receipts: with both the floor and the higher receipts gone,
 *     the offline witness is gone too. Catching that requires ONLINE Rekor log
 *     enumeration (a future "Stage 2b" that asks the external log directly what
 *     this anchoring key committed), or the Stage-4 hardware monotonic counter.
 * Stage 2 is a real INCREMENTAL defense on an anchored fortress, not a complete
 * one; the unanchored full-disk-rollback residual (above) also stays for Stage
 * 2b / Stage 4. See {@link STAGE_2_REKOR_COUNTER_FLOOR}.
 *
 * ── DEFERRED STAGES (named, not built) ─────────────────────────────────────
 *   Stage 2b — ONLINE Rekor log enumeration: ask the external log directly
 *     what this fortress's anchoring key committed, so a coordinated rollback
 *     that ALSO deletes the higher local receipts cannot hide the anchoring
 *     from the offline witness. Closes the residual that offline Stage 2 leaves
 *     open. Not built (network query is out of scope; Erik decides).
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

// ── Stage identifiers (Stage 2 implemented below; Stage 3/4 deferred) ───────

/**
 * Stage 2: Rekor counter-floor cross-check (implemented below). Used as the
 * `witness_source` identifier on a Stage-2 freeze and in the operator-facing
 * verdict. Stage 2 reuses Stage 1's freeze marker + finding chokepoint; it
 * does NOT introduce a parallel freeze path.
 */
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
  /**
   * Monotonic "a config-security baseline has been established" latch (DEBT-1
   * close-out for the #805/#791 config-downgrade gate). Once a fortress has
   * sealed a config-security baseline (`core/config-baseline.ts`), this is
   * raised to `true` in the master-MAC'd witness and NEVER lowered. It lets the
   * config gate detect the DELETION (or older-schema reseed) of the
   * single-deletable baseline record as a rollback: a missing/reseed baseline
   * on a fortress whose witness says one was established is a downgrade-replay
   * attempt, not a genuine first run. ADDITIVE: absent reads as `false`
   * (pre-DEBT-1 / legacy witnesses), bound into the witness MAC because the MAC
   * covers `canonicalJson(data)`. The latch lives in the epoch-witness record,
   * a SEPARATE deletable location from the config-baseline record, so laundering
   * the deletion requires the attacker to ALSO delete the master-MAC'd witness;
   * on a fortress that has done real work the rotation/head-anchor splice
   * witnesses independently expose that (see the deletion-of-both residual on
   * `readBaselineEstablishedLatch`).
   */
  baseline_established?: boolean;
  /**
   * Monotonic floor on the HIGHEST config-baseline schema version this fortress
   * has ever sealed (DEBT-1, the reseed leg). It distinguishes a legitimate
   * forward schema UPGRADE reseed from a backward DOWNGRADE reseed attack:
   *  - legit upgrade: the running binary seals a HIGHER schema than this floor →
   *    the floor advances, reseed allowed.
   *  - downgrade-reseed attack: an attacker presents an OLDER-schema record on a
   *    fortress whose floor already recorded a higher sealed schema → the
   *    presented schema is BELOW the floor → fail closed.
   * Like `baseline_established` it is ADDITIVE (absent reads as "no floor",
   * legacy/pre-DEBT-1), never lowered, and bound into the witness MAC. It is set
   * together with the establishment latch.
   */
  baseline_schema?: number;
  /**
   * Monotonic floor on the HIGHEST fleet-license REVOCATION-LIST version this
   * fortress has ever had pushed (fleet control plane PR-3, the revocation
   * chokepoint). It is the custody-MAC'd BINDING that makes "a version-N
   * revocation existed" survive deletion of BOTH the plain revocation-list file
   * AND the standalone `entitlement/revocation-antirollback.ts` `_meta` anchor:
   * once the issuer pushes a revocation list at version N, this floor is raised to
   * `max(current, N)` in the master-MAC'd witness and NEVER lowered. The
   * revocation ENFORCEMENT path consults it so that a list which is absent (deleted)
   * on a fortress whose witness says a revocation was established, or which is
   * present below this floor, or which is corrupt, is UNVERIFIABLE -> fail closed
   * (drop paid -> Community), exactly like a corrupt list. A fortress that never
   * pushed a revocation has no floor here, so an absent list keeps the grant (the
   * legit case). ADDITIVE: absent reads as "no floor" (pre-PR-3 / legacy witnesses),
   * bound into the witness MAC because the MAC covers `canonicalJson(data)`. The
   * floor lives in the epoch-witness record, a SEPARATE deletable location from
   * both the list file and the standalone version anchor, so laundering a deletion
   * requires the attacker to ALSO delete the master-MAC'd witness, which the
   * splice/rotation witnesses independently expose on any fortress with real
   * history. The irreducible residual (delete the list + the anchor + the witness
   * on a purely-offline, never-rotated fortress) is the SAME full-wipe residual
   * this module already documents for Stage 1, bounded only by Stage 2/4.
   */
  revocation_floor?: number;
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
    // `baseline_established` / `baseline_schema` are additive: a record either
    // omits them (legacy) or carries an explicit boolean / non-negative integer.
    // Any other type is a forged/garbled record → fail the MAC path (invalid),
    // never silently coerce.
    (data.baseline_established !== undefined &&
      typeof data.baseline_established !== "boolean") ||
    (data.baseline_schema !== undefined &&
      (typeof data.baseline_schema !== "number" ||
        !Number.isSafeInteger(data.baseline_schema) ||
        data.baseline_schema < 0)) ||
    (data.revocation_floor !== undefined &&
      (typeof data.revocation_floor !== "number" ||
        !Number.isSafeInteger(data.revocation_floor) ||
        data.revocation_floor < 0)) ||
    typeof mac !== "string"
  ) {
    return { status: "invalid" };
  }
  const fullData: EpochWitnessData = {
    epoch: data.epoch,
    epoch_id: data.epoch_id,
    witnessed_at: data.witnessed_at,
    // Carry the latch fields through so the recomputed MAC covers exactly the
    // bytes that were signed. Omitting a field that WAS set computes the wrong
    // MAC and rejects a legitimate witness; attaching a field a legacy record
    // never had ALSO changes the canonical bytes, so only attach when the key
    // is actually present.
    ...(data.baseline_established !== undefined
      ? { baseline_established: data.baseline_established }
      : {}),
    ...(data.baseline_schema !== undefined
      ? { baseline_schema: data.baseline_schema }
      : {}),
    ...(data.revocation_floor !== undefined
      ? { revocation_floor: data.revocation_floor }
      : {}),
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
  let toWrite = data;
  if (!opts?.force) {
    const current = await readEpochWitness(storage, master);
    if (current.status === "valid" && data.epoch < current.data.epoch) {
      throw new Error(
        "Sanctuary: refusing to lower the custody epoch witness " +
          `(${current.data.epoch} → ${data.epoch}) without an explicit restore ` +
          "attestation. Use `sanctuary restore-attest`."
      );
    }
    // The `baseline_established` latch and the `baseline_schema` floor are
    // monotonic too: a non-force write must never DROP an already-set latch nor
    // LOWER the sealed-schema floor (either would launder a baseline deletion /
    // downgrade by re-stamping the witness). Carry them forward unless the caller
    // is explicitly raising them. `force` (restore-attest) preserves them via its
    // own read, so it is excluded here.
    if (current.status === "valid") {
      if (current.data.baseline_established === true && data.baseline_established !== true) {
        toWrite = { ...toWrite, baseline_established: true };
      }
      const priorSchema = current.data.baseline_schema;
      if (
        typeof priorSchema === "number" &&
        (typeof toWrite.baseline_schema !== "number" ||
          toWrite.baseline_schema < priorSchema)
      ) {
        toWrite = { ...toWrite, baseline_schema: priorSchema };
      }
      const priorRevocationFloor = current.data.revocation_floor;
      if (
        typeof priorRevocationFloor === "number" &&
        (typeof toWrite.revocation_floor !== "number" ||
          toWrite.revocation_floor < priorRevocationFloor)
      ) {
        toWrite = { ...toWrite, revocation_floor: priorRevocationFloor };
      }
    }
  }
  const record = {
    [EPOCH_WITNESS_MARKER]: true,
    data: toWrite,
    mac: toBase64url(epochWitnessMac(master, toWrite)),
  };
  await storage.write(
    "_meta",
    EPOCH_WITNESS_META_KEY,
    stringToBytes(JSON.stringify(record))
  );
}

// ── Config-baseline establishment latch (DEBT-1 close-out) ──────────────────

/**
 * Read the boot-anchored "a config-security baseline was established" latch from
 * the master-MAC'd epoch witness. The config-downgrade gate
 * (`core/config-baseline.ts`) consults this to tell a GENUINE first run (no
 * baseline ever) apart from a DELETION/older-schema REPLAY (a baseline existed,
 * its single deletable record is now gone or downgraded). It threads the
 * config-baseline residual through the SAME witness the custody anti-rollback
 * floor already uses (no parallel mechanism, no new freeze path).
 *
 * Verdicts:
 *  - `{ established: true, sealedSchema }`: the authenticated witness latch is
 *    set; a fortress that has sealed a baseline before, at highest schema
 *    `sealedSchema` (undefined for a pre-schema-floor latch). A subsequent boot
 *    whose config-baseline record is absent is a deletion-replay → fail closed;
 *    a reseed presenting a schema BELOW `sealedSchema` is a downgrade-reseed →
 *    fail closed; a reseed at a schema AT-OR-ABOVE `sealedSchema` is a legit
 *    forward upgrade → allowed.
 *  - `{ established: false }`: the witness authenticates and the latch is
 *    unset (genuine never-seeded fortress, or a legacy pre-DEBT-1 witness).
 *  - `{ established: false, witnessUntrusted: true }`: NO authenticated witness
 *    exists (absent or tampered). The caller MUST NOT read this as "no baseline
 *    was ever established"; it composes this with the OTHER surviving witnesses
 *    (rotation epoch record / audit head anchor) exactly as the boot detector
 *    does, so deleting the witness to erase the latch does not launder a
 *    deletion on a fortress that has done real work.
 *
 * HONEST RESIDUAL (do not over-claim): the ONLY way to fully erase the latch is
 * to delete BOTH the config-baseline record AND the master-MAC'd epoch witness.
 * On a fortress that has rotated or audited, that joint deletion is itself a
 * detected rollback (the rotation/head-anchor witnesses regress), but on a
 * brand-new fortress that booted once and never rotated/audited, a joint
 * deletion of both records is indistinguishable from a genuine first run. That
 * is the same irreducible full-wipe residual the module documents for Stage 1
 * (a self-consistent full-tree restore), bounded only by Stage 2/4. The latch
 * raises the attacker's cost from "delete one plaintext-shaped record" to
 * "delete the master-MAC'd witness too," which the splice witnesses then expose
 * on any fortress with real history.
 */
export async function readBaselineEstablishedLatch(
  storage: StorageBackend,
  master: Uint8Array
): Promise<{
  established: boolean;
  sealedSchema?: number;
  witnessUntrusted?: boolean;
}> {
  const witness = await readEpochWitness(storage, master);
  if (witness.status === "valid") {
    const established = witness.data.baseline_established === true;
    return {
      established,
      ...(established && typeof witness.data.baseline_schema === "number"
        ? { sealedSchema: witness.data.baseline_schema }
        : {}),
    };
  }
  // absent (deleted/never-written) OR invalid (tampered). Either way there is no
  // trustworthy latch to read; surface that so the caller composes the other
  // witnesses rather than treating it as a clean "never established".
  return { established: false, witnessUntrusted: true };
}

/**
 * Raise the monotonic baseline-established latch AND advance the sealed-schema
 * floor on the epoch witness. Called by the config gate every time it seals a
 * baseline (first run, reseed, or a clean authenticated advance), passing the
 * schema version it just sealed, so both the latch and the schema floor track
 * forward without a rotation.
 *
 * It preserves the current epoch/epoch_id (it raises the latch, it does not
 * touch the rollback floor) and routes through `writeEpochWitness`, whose
 * monotonic guards keep the epoch non-decreasing and never lower the latch or
 * the schema floor. When NO authenticated witness exists yet (genuine first run,
 * before any rotation), it establishes a fresh epoch-0 witness carrying the
 * latch, so a fortress that has sealed a baseline always has a witness saying
 * so. Idempotent: a no-op when the latch is already set at an equal-or-higher
 * schema floor.
 */
export async function raiseBaselineEstablishedLatch(
  storage: StorageBackend,
  master: Uint8Array,
  sealedSchema: number,
  now: () => Date = () => new Date()
): Promise<void> {
  const witness = await readEpochWitness(storage, master);
  if (
    witness.status === "valid" &&
    witness.data.baseline_established === true &&
    typeof witness.data.baseline_schema === "number" &&
    witness.data.baseline_schema >= sealedSchema
  ) {
    return; // already raised at this schema or higher (monotonic), nothing to do
  }
  const base: EpochWitnessData =
    witness.status === "valid"
      ? witness.data
      : { epoch: 0, epoch_id: "epoch-0-creation", witnessed_at: now().toISOString() };
  const priorSchema =
    witness.status === "valid" && typeof witness.data.baseline_schema === "number"
      ? witness.data.baseline_schema
      : -1;
  await writeEpochWitness(storage, master, {
    ...base,
    baseline_established: true,
    baseline_schema: Math.max(priorSchema, sealedSchema),
    witnessed_at: now().toISOString(),
  });
}

// ── Revocation-floor latch (fleet control plane PR-3 chokepoint) ────────────

/**
 * Read the custody-MAC'd revocation-list version FLOOR from the epoch witness.
 * This is the BINDING the fleet revocation enforcement path consults so that a
 * revocation list which was pushed (floor > 0) but is now ABSENT (deleted),
 * present below the floor, or corrupt is UNVERIFIABLE -> fail closed. It threads
 * the revocation floor through the SAME master-MAC'd witness the custody
 * anti-rollback floor and the config-baseline latch already use (no parallel
 * mechanism, no new freeze path).
 *
 * Verdicts:
 *  - `{ floor: N }` (N > 0): the authenticated witness records a revocation was
 *    established at version >= N. A subsequent enforcement pass whose stored list
 *    is absent, below N, or corrupt is a deletion/rollback -> fail closed.
 *  - `{ floor: 0 }`: the witness authenticates and no revocation floor is set
 *    (a fortress that never had a revocation pushed, or a legacy witness). An
 *    absent list keeps the paid grant (the legit case).
 *  - `{ floor: 0, witnessUntrusted: true }`: NO authenticated witness exists
 *    (absent or tampered). The caller MUST NOT read this as "no revocation was
 *    ever established"; it composes this with the OTHER surviving revocation
 *    signal (the standalone version anchor) exactly as the boot detector composes
 *    witnesses, so deleting the witness to erase the floor does not launder a
 *    deletion on a fortress whose standalone anchor still proves a push happened.
 *
 * HONEST RESIDUAL (do not over-claim): the ONLY way to fully erase the floor is
 * to delete the revocation-list file AND the standalone version anchor AND the
 * master-MAC'd epoch witness. That triple deletion is the SAME irreducible
 * full-wipe residual this module documents for Stage 1 (a self-consistent
 * full-tree restore), bounded only by Stage 2/4. Raising the attacker's cost from
 * "delete one plaintext-shaped list file" to "delete the master-MAC'd witness too"
 * is exactly the improvement the config-baseline latch already makes.
 */
export async function readRevocationFloorLatch(
  storage: StorageBackend,
  master: Uint8Array
): Promise<{ floor: number; witnessUntrusted?: boolean }> {
  const witness = await readEpochWitness(storage, master);
  if (witness.status === "valid") {
    const floor =
      typeof witness.data.revocation_floor === "number"
        ? witness.data.revocation_floor
        : 0;
    return { floor };
  }
  // absent (deleted/never-written) OR invalid (tampered). No trustworthy floor to
  // read; surface that so the caller composes the standalone anchor rather than
  // treating it as a clean "never established".
  return { floor: 0, witnessUntrusted: true };
}

/**
 * Raise the monotonic revocation-list version floor on the epoch witness. Called
 * by BOTH revocation push paths (HTTP + CLI) every time an authenticated newer
 * list is persisted, passing the pushed version, so the floor tracks forward
 * without a rotation. Preserves the current epoch/epoch_id (it raises the floor,
 * it does not touch the rollback floor) and routes through {@link writeEpochWitness},
 * whose monotonic guards keep the epoch non-decreasing and never lower the floor.
 * When NO authenticated witness exists yet (a fortress that never rotated), it
 * establishes a fresh epoch-0 witness carrying the floor. Idempotent: a no-op when
 * the floor is already at or above `version`. Never lowers.
 */
export async function raiseRevocationFloorLatch(
  storage: StorageBackend,
  master: Uint8Array,
  version: number,
  now: () => Date = () => new Date()
): Promise<void> {
  if (!Number.isSafeInteger(version) || version < 0) {
    throw new Error(
      `raiseRevocationFloorLatch: version must be a non-negative safe integer (got ${version})`
    );
  }
  const witness = await readEpochWitness(storage, master);
  if (
    witness.status === "valid" &&
    typeof witness.data.revocation_floor === "number" &&
    witness.data.revocation_floor >= version
  ) {
    return; // already at or above this floor (monotonic), nothing to do
  }
  const base: EpochWitnessData =
    witness.status === "valid"
      ? witness.data
      : { epoch: 0, epoch_id: "epoch-0-creation", witnessed_at: now().toISOString() };
  const priorFloor =
    witness.status === "valid" && typeof witness.data.revocation_floor === "number"
      ? witness.data.revocation_floor
      : 0;
  await writeEpochWitness(storage, master, {
    ...base,
    revocation_floor: Math.max(priorFloor, version),
    witnessed_at: now().toISOString(),
  });
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
 * witness set the boot detector uses and re-writes the freeze on a re-detected
 * rollback — so a marker deletion cannot unfreeze trust-bearing writes even
 * within a single running process.
 *
 * STAGE 1 + STAGE 2 PARITY (codex FIX 4): the recompute re-derives BOTH the
 * Stage-1 epoch verdict (epoch witness + #501 epoch record + audit head anchor
 * splice probe vs the on-disk envelope epoch) AND, when Stage 2 applies
 * (config enabled OR receipts present), the Stage-2 floor-vs-local-anchored
 * verdict from surviving on-disk evidence. Either suspected verdict re-freezes.
 * This closes the mid-session bypass where deleting ONLY the Stage-2 freeze
 * marker would otherwise lift a Stage-2 freeze until the next boot.
 *
 * NEVER-REFUSE-BOOT / NEVER-THROW: a Stage-2 recompute I/O error fails TOWARD
 * frozen (consistent with FIX 2), never escapes this function. A present marker
 * short-circuits to {@link isRollbackFrozen} (fail-closed on tamper); only an
 * ABSENT marker triggers the (slightly costlier) recompute.
 */
export async function isRollbackFrozenWithRecompute(
  storage: StorageBackend,
  master: Uint8Array,
  /** fortressId for the Stage-2 recompute. When absent it is derived from the
   * surviving checkpoint records, so callers without it still get parity. */
  fortressId?: string
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
    await import("../operational/audit-log.js");

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

  // FIX 4: Stage-2 parity. Re-derive the Stage-2 verdict from surviving on-disk
  // evidence so a deleted Stage-2 freeze marker is reconstructed here too, not
  // only at the next boot. The orchestrator itself re-writes the freeze marker
  // on a suspected verdict, so this just reports its result. Fail TOWARD frozen
  // on any recompute I/O error; never throw out of the enforcement path.
  return recomputeStage2Freeze(storage, master, fortressId);
}

/**
 * Re-derive a Stage-2 freeze (FIX 4) from surviving on-disk evidence, for the
 * marker-absent recompute in {@link isRollbackFrozenWithRecompute}. Mirrors
 * Stage 1's reconstruction: it reads the witnesses fresh and, via the same
 * {@link evaluateAndEnforceRekorCounterFloor} orchestrator, RE-WRITES the
 * Stage-2 freeze marker on a suspected verdict (so the deleted marker is
 * reconstructed). Fail-toward-frozen on any I/O error — it NEVER throws, so the
 * enforcement path stays never-refuse-boot.
 *
 * A consistent or not-applicable Stage-2 verdict returns `{ frozen: false }`.
 */
async function recomputeStage2Freeze(
  storage: StorageBackend,
  master: Uint8Array,
  fortressId?: string
): Promise<{ frozen: boolean; data?: FreezeData }> {
  try {
    const resolvedFortressId =
      fortressId ?? (await deriveFortressIdFromCheckpoints(storage));
    const result = await evaluateAndEnforceRekorCounterFloor({
      storage,
      master,
      fortressId: resolvedFortressId,
    });
    if (result.verdict.kind === "rollback-suspected") {
      // The orchestrator already wrote the freeze marker; report it frozen.
      return {
        frozen: true,
        data: {
          witnessed_epoch: result.verdict.highestAnchoredCounter,
          observed_epoch: result.verdict.onDiskFloor,
          witness_source: REKOR_COUNTER_FLOOR_WITNESS_SOURCE,
          frozen_at: new Date().toISOString(),
        },
      };
    }
    return { frozen: false };
  } catch {
    // Recompute I/O error: fail toward frozen (consistent with FIX 2's
    // unreadable-store posture). Persist a synthetic, honest freeze record so
    // the freeze survives subsequent checks too.
    const data: FreezeData = {
      witnessed_epoch: 0,
      observed_epoch: 0,
      witness_source:
        REKOR_COUNTER_FLOOR_WITNESS_SOURCE +
        " (recompute I/O error — failing toward frozen)",
      frozen_at: new Date().toISOString(),
    };
    try {
      await writeFreeze(storage, master, data);
    } catch {
      // Even the freeze write failed; still report frozen (fail-closed). The
      // in-memory verdict is enough to block this write attempt.
    }
    return { frozen: true, data };
  }
}

/**
 * Best-effort fortressId for the Stage-2 recompute when the caller does not
 * pass one: the persisted checkpoints carry their own fortress_id, and the
 * Stage-2 anchor verification compares the anchors-export fortress_id against
 * the checkpoint records' own id — so deriving it FROM the records keeps them
 * consistent. Returns "" when there is nothing to derive from (no checkpoints
 * → nothing anchored → Stage 2 will resolve not-applicable/consistent anyway).
 */
async function deriveFortressIdFromCheckpoints(
  storage: StorageBackend
): Promise<string> {
  const { readPersistedCheckpoints } = await import(
    "../transparency/emitter.js"
  );
  const records = await readPersistedCheckpoints(storage);
  for (const record of records) {
    const id = (record as { fortress_id?: unknown }).fortress_id;
    if (typeof id === "string" && id.length > 0) return id;
  }
  return "";
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
  /** fortressId for the Stage-2 floor re-baseline (FIX 4). Optional — when
   * absent it is derived from the surviving checkpoint records. */
  fortressId?: string;
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

  // Preserve the baseline-established latch across the force re-baseline: the
  // operator is attesting to a custody EPOCH restore, not un-establishing a
  // config baseline that genuinely existed. (`force` skips writeEpochWitness's
  // monotonic latch-preserve, so carry it explicitly.) A wrong-master caller
  // reads the witness as "invalid" → `established: false` here, which is the
  // safe direction: it does not re-assert a latch it cannot authenticate.
  const priorLatch = await readBaselineEstablishedLatch(
    args.storage,
    args.master
  );
  // Also carry the REVOCATION FLOOR across the force re-baseline (fleet control
  // plane PR-3): a custody restore-attestation attests to a custody EPOCH restore,
  // NOT to un-establishing a fleet revocation that genuinely happened. `force`
  // skips writeEpochWitness's monotonic revocation_floor-preserve, so carry it
  // explicitly (never lower it) exactly as baseline_established/baseline_schema are
  // carried. If we dropped it, restore-attest would ZERO the revocation floor and
  // an attacker could then delete the list+anchor -> floor 0 -> un-revoke every
  // killed license. A wrong-master caller reads the witness as "invalid" ->
  // { floor: 0, witnessUntrusted: true }, so it carries floor 0 (the safe
  // direction: it does not re-assert a floor it cannot authenticate).
  const priorRevocationFloor = await readRevocationFloorLatch(
    args.storage,
    args.master
  );
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
      ...(priorLatch.established ? { baseline_established: true } : {}),
      ...(priorLatch.established && typeof priorLatch.sealedSchema === "number"
        ? { baseline_schema: priorLatch.sealedSchema }
        : {}),
      ...(priorRevocationFloor.floor > 0
        ? { revocation_floor: priorRevocationFloor.floor }
        : {}),
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

  // STAGE-2 RE-BASELINE (codex FIX 4 consequence): clearing the freeze marker
  // is not enough when the freeze was a Stage-2 floor regression — the FIX-4
  // recompute in enforceCustodyFloor would re-detect the same floor-below-
  // anchored condition and re-freeze. So, as the Stage-2 analogue of the epoch
  // re-baseline above, raise the on-disk transparency floor to ≥ the highest
  // locally-recorded anchored counter, making the attested state internally
  // consistent. Only raises (monotonic), only when Stage 2 applies, best-effort
  // and NEVER throws out of restore-attest (a re-baseline failure leaves the
  // freeze cleared but the floor as-is; the next recompute simply re-freezes,
  // which is the safe direction — it never silently launders a real rollback).
  await rebaselineStage2FloorBestEffort(args.storage, args.master, args.fortressId);

  return { attestedEpoch: args.currentEpoch, unfroze };
}

/**
 * Best-effort Stage-2 floor re-baseline for {@link restoreAttest}. Resolves the
 * highest locally-recorded anchored counter offline and raises the on-disk
 * floor to it (monotonic; never lowers). Swallows all errors — restore-attest
 * must never throw because the transparency stack hiccuped, and failing to
 * raise the floor only means the next recompute re-freezes (safe direction).
 */
async function rebaselineStage2FloorBestEffort(
  storage: StorageBackend,
  master: Uint8Array,
  fortressId?: string
): Promise<void> {
  try {
    const { readAnchorConfig, anchorReceiptsPresentOnDisk } = await import(
      "../transparency/anchoring.js"
    );
    // Only re-baseline when Stage 2 applies (config enabled OR receipts present).
    let applies = false;
    try {
      const state = await readAnchorConfig({ storage, masterKey: master });
      applies = state.status === "enabled";
    } catch {
      applies = true; // tampered/unreadable config → treat as applies
    }
    if (!applies) applies = await anchorReceiptsPresentOnDisk(storage);
    if (!applies) return;

    const resolvedFortressId =
      fortressId ?? (await deriveFortressIdFromCheckpoints(storage));
    const { computeHighestVerifiedAnchoredCounter } = await import(
      "../transparency/anchoring.js"
    );
    const anchored = await computeHighestVerifiedAnchoredCounter({
      storage,
      masterKey: master,
      fortressId: resolvedFortressId,
    });
    if (anchored.highestAnchoredCounter <= 0) return;
    const { rebaselineTransparencyCounterFloor } = await import(
      "../transparency/emitter.js"
    );
    await rebaselineTransparencyCounterFloor(
      storage,
      master,
      anchored.highestAnchoredCounter
    );
  } catch {
    // Swallow: never throw out of restore-attest.
  }
}

// ── Stage 2 — Rekor counter-floor cross-check ───────────────────────────────

/**
 * The operator-facing source label on a Stage-2 freeze and verdict. It is
 * distinct from Stage 1's witness sources so the banner and audit finding name
 * the LOCALLY-RECORDED Rekor anchor receipts (whose counters the external log
 * also remembers), not an epoch witness, as what exposed the regression.
 */
export const REKOR_COUNTER_FLOOR_WITNESS_SOURCE =
  "transparency counter floor vs locally-recorded Rekor anchor receipts (Stage 2)";

export type RekorFloorVerdict =
  /** Stage 2 does not apply: no receipts on disk AND config not enabled. */
  | { kind: "not-applicable"; reason: string }
  /** Floor ≥ highest locally-recorded anchored counter (or nothing anchored). */
  | {
      kind: "consistent";
      onDiskFloor: number;
      highestAnchoredCounter: number;
    }
  /** Floor < highest locally-recorded anchored counter, or an unverifiable
   * anchor while Stage 2 applies → suspected rollback (FREEZE direction). */
  | {
      kind: "rollback-suspected";
      onDiskFloor: number;
      highestAnchoredCounter: number;
      notes: string[];
    };

/**
 * Inputs for the Stage-2 verdict, all already read by the caller so this is a
 * pure, side-effect-free function (mirrors {@link evaluateRollback}).
 */
export interface RekorFloorInputs {
  /**
   * Whether Stage 2 APPLIES to this fortress (codex FIX 1). True when anchoring
   * config reads ENABLED *or* any anchor receipt is present on disk — a
   * disk-write attacker without the master can roll the config back to a
   * validly-MAC'd `disabled` (or delete it) while preserving receipts, so the
   * config bit alone must not switch Stage 2 off when receipts prove anchoring
   * happened. When false (no receipts AND config not enabled) Stage 2 does not
   * apply: a clean not-applicable verdict, never a freeze.
   */
  stage2Applies: boolean;
  /**
   * The authenticated on-disk transparency counter floor:
   *  - "valid": a trustworthy on-disk lower bound on emitted checkpoints.
   *  - "absent": no floor record — no checkpoint emitted yet (floor 0).
   *  - "invalid": present but tampered/forged → fail toward FREEZE.
   */
  onDiskFloor:
    | { status: "valid"; highest_counter: number }
    | { status: "absent" }
    | { status: "invalid" };
  /** Highest counter for which this fortress holds a cryptographically valid
   * LOCAL anchor receipt, resolved OFFLINE (0 = nothing locally recorded as
   * anchored yet). This is a LOCAL witness: a coordinated rollback that also
   * deletes the higher receipts lowers it (see module HONEST RESIDUAL). */
  highestAnchoredCounter: number;
  /** True when an anchored receipt was present but failed its offline checks
   * (tampered receipt, divergent history, anchor-beyond-bundle) OR the receipt
   * store was present-but-unreadable/malformed. */
  unverifiableAnchorPresent: boolean;
  /** Carried into the finding/banner. Never key material. */
  notes: string[];
}

/**
 * Pure Stage-2 verdict. Fail DIRECTION matches Stage 1 exactly:
 *  - Stage 2 does not apply (no receipts + config not enabled)
 *                                          → not-applicable (clean, no freeze)
 *  - floor invalid (tampered)              → suspected (FREEZE)
 *  - an anchored receipt is unverifiable   → suspected (FREEZE)
 *  - floor < highest locally-recorded anchored counter → suspected (FREEZE)
 *  - floor absent but something IS anchored→ suspected (floor 0 < anchored)
 *  - floor ≥ highest locally-recorded anchored counter → consistent (PASS)
 *  - nothing locally anchored (highest==0) → consistent (PASS; no witness)
 *
 * The comparison value is the highest LOCALLY-RECORDED anchored counter, not an
 * external query result; see the module HONEST RESIDUAL for what a coordinated
 * receipt-deletion can still hide from this offline check.
 *
 * INFLATION (FIX 3): a forged self-consistent `consistent` receipt at a high
 * counter raises highestAnchoredCounter and can trip a false freeze. That is a
 * DELIBERATE, recoverable false-positive direction under the fail-toward-freeze
 * posture (the operator clears it with `restore-attest`), not a bug — it is
 * strictly safer than reading a forged receipt as "no witness".
 *
 * It NEVER returns "refuse boot": the only postures are not-applicable,
 * consistent, and suspected (which the caller turns into warn + freeze).
 */
export function evaluateRekorCounterFloor(
  input: RekorFloorInputs
): RekorFloorVerdict {
  if (!input.stage2Applies) {
    return {
      kind: "not-applicable",
      reason:
        "no anchor receipts are present and transparency anchoring is not " +
        "enabled on this fortress; Stage 2 (Rekor counter-floor) does not apply",
    };
  }
  const floorValue =
    input.onDiskFloor.status === "valid" ? input.onDiskFloor.highest_counter : 0;
  const notes = [...input.notes];

  // A tampered floor cannot be trusted as a number; fail toward freeze.
  if (input.onDiskFloor.status === "invalid") {
    notes.unshift(
      "the on-disk transparency counter floor is present but failed " +
        "authentication (tampered, forged, or wrong key); treating as a " +
        "suspected rollback of the checkpoint store"
    );
    return {
      kind: "rollback-suspected",
      onDiskFloor: floorValue,
      highestAnchoredCounter: input.highestAnchoredCounter,
      notes,
    };
  }

  // An anchored receipt that does not verify offline, with transparency on,
  // must not silently read as "no external witness".
  if (input.unverifiableAnchorPresent) {
    return {
      kind: "rollback-suspected",
      onDiskFloor: floorValue,
      highestAnchoredCounter: input.highestAnchoredCounter,
      notes,
    };
  }

  // The core comparison. floorValue is 0 when the floor is absent; if
  // anything is externally anchored (highest > 0) that is itself a
  // regression (the floor that anchored it is gone). If nothing is anchored
  // (highest == 0) this is a clean PASS — no external witness exists yet.
  if (input.highestAnchoredCounter > floorValue) {
    notes.unshift(
      `the on-disk transparency counter floor (${floorValue}) is BELOW the ` +
        `highest checkpoint this fortress holds a valid local anchor receipt ` +
        `for (${input.highestAnchoredCounter}); the local anchor receipts ` +
        "(whose counters the external Rekor log also remembers) prove an " +
        "anchoring the on-disk checkpoint store no longer reflects — a " +
        "transparency-floor rollback of an anchored fortress that preserved " +
        "those receipts"
    );
    return {
      kind: "rollback-suspected",
      onDiskFloor: floorValue,
      highestAnchoredCounter: input.highestAnchoredCounter,
      notes,
    };
  }
  return {
    kind: "consistent",
    onDiskFloor: floorValue,
    highestAnchoredCounter: input.highestAnchoredCounter,
  };
}

export interface RekorFloorCheckResult {
  verdict: RekorFloorVerdict;
  /** True when a freeze marker is now in effect (this check or a prior one). */
  frozen: boolean;
  /** Operator-facing banner when suspected; undefined otherwise. */
  banner?: string;
}

/**
 * The Stage-2 entry point (boot AND `verify-transparency --check-counter-floor`).
 * Determines whether Stage 2 applies (config enabled OR receipts on disk —
 * codex FIX 1), then reads the on-disk floor and the highest LOCALLY-RECORDED
 * anchored counter (all offline), runs {@link evaluateRekorCounterFloor}, and
 * on a suspected verdict raises the SAME freeze marker Stage 1 uses
 * ({@link writeFreeze} → ROLLBACK_FREEZE_META_KEY), so the existing
 * `enforceCustodyFloor` chokepoint freezes trust-bearing writes and
 * `restore-attest` clears it — NO new freeze path, NO new finding type.
 *
 * BOOT IS NEVER REFUSED. The dependency reads are injected so this stays
 * testable without a live transparency stack; defaults wire the real
 * transparency modules via lazy import (avoids a static cycle and keeps the
 * core module free of a hard transparency dependency).
 *
 * FAIL-TOWARD-FREEZE on an UNREADABLE existing receipt store (codex FIX 2): the
 * `readHighestAnchoredCounter` default catches a present-but-malformed/
 * unreadable receipt store and resolves it to `unverifiableAnchorPresent`
 * (→ suspected → freeze) instead of letting the exception escape to the boot
 * catch and silently skip the check. A genuinely-ABSENT store (no receipts dir
 * / empty) stays "nothing anchored" (counter 0), not a freeze.
 *
 * HONEST RESIDUAL (do not over-claim): the freeze marker is a CACHE. A Stage-2
 * freeze whose marker an attacker deletes is re-derived BOTH at the next boot/
 * `--check-counter-floor` run AND inside `enforceCustodyFloor` (codex FIX 4 now
 * re-runs this Stage-2 verdict in the marker-absent recompute, with parity to
 * Stage 1). Offline Stage 2 catches a floor rollback that PRESERVES the local
 * receipts; a coordinated rollback that also DELETES the higher receipts needs
 * online Rekor enumeration (Stage 2b) or Stage-4 hardware (see module comment).
 */
export async function evaluateAndEnforceRekorCounterFloor(args: {
  storage: StorageBackend;
  master: Uint8Array;
  fortressId: string;
  /** Override the dependency reads (tests). Defaults to the real modules. */
  deps?: RekorFloorDeps;
  now?: () => Date;
}): Promise<RekorFloorCheckResult> {
  const now = args.now ?? (() => new Date());
  const deps = args.deps ?? defaultRekorFloorDeps(args);

  const stage2Applies = await deps.readStage2Applies();
  if (!stage2Applies) {
    // Stage 2 does not apply (no receipts AND config not enabled). Preserve any
    // standing Stage-1 freeze, but never create one here.
    const prior = await isRollbackFrozen(args.storage, args.master);
    return {
      verdict: {
        kind: "not-applicable",
        reason:
          "no anchor receipts are present and transparency anchoring is not " +
          "enabled; Stage 2 does not apply",
      },
      frozen: prior.frozen,
      ...(prior.frozen
        ? {
            banner: prior.data
              ? staleFreezeBanner(prior.data)
              : tamperedFreezeBanner(),
          }
        : {}),
    };
  }

  const onDiskFloor = await deps.readOnDiskFloor();
  const anchored = await deps.readHighestAnchoredCounter();
  const verdict = evaluateRekorCounterFloor({
    stage2Applies,
    onDiskFloor,
    highestAnchoredCounter: anchored.highestAnchoredCounter,
    unverifiableAnchorPresent: anchored.unverifiableAnchorPresent,
    notes: anchored.notes,
  });

  const priorFreeze = await isRollbackFrozen(args.storage, args.master);

  if (verdict.kind === "rollback-suspected") {
    // Reuse Stage 1's freeze marker. witnessed_epoch/observed_epoch carry the
    // two counters so the operator banner + audit finding show them; the
    // distinct witness_source names the external log as the exposing witness.
    if (!priorFreeze.frozen || !priorFreeze.data) {
      const freezeData: FreezeData = {
        witnessed_epoch: verdict.highestAnchoredCounter,
        observed_epoch: verdict.onDiskFloor,
        witness_source: REKOR_COUNTER_FLOOR_WITNESS_SOURCE,
        frozen_at: now().toISOString(),
      };
      await writeFreeze(args.storage, args.master, freezeData);
    }
    return {
      verdict,
      frozen: true,
      banner: rekorFloorBanner(verdict),
    };
  }

  // Consistent. Like Stage 1's OK path, a clean Stage-2 verdict does NOT
  // auto-clear a standing freeze — only restore-attest does.
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

/** The injectable Stage-2 dependency reads (real modules by default). */
export interface RekorFloorDeps {
  /** Stage 2 applies when config==enabled OR any receipt is on disk (FIX 1). */
  readStage2Applies: () => Promise<boolean>;
  readOnDiskFloor: () => Promise<RekorFloorInputs["onDiskFloor"]>;
  readHighestAnchoredCounter: () => Promise<{
    highestAnchoredCounter: number;
    unverifiableAnchorPresent: boolean;
    notes: string[];
  }>;
}

/** Default dependency reads: wire the real transparency modules (lazy). */
function defaultRekorFloorDeps(args: {
  storage: StorageBackend;
  master: Uint8Array;
  fortressId: string;
}): RekorFloorDeps {
  return {
    // FIX 1: Stage 2 applies if the config reads enabled OR any anchor receipt
    // is present on disk. A disk-write attacker without the master can delete /
    // roll the config back to a validly-MAC'd `disabled` while preserving the
    // receipts; the receipts prove anchoring happened, so the check still runs.
    // A tampered config that THROWS is treated as "applies" (fail toward the
    // check, never toward silently skipping Stage 2). receiptsPresentOnDisk is
    // a cheap listing that does NOT parse the receipts — a malformed store is
    // still "present" and is surfaced later by readHighestAnchoredCounter.
    readStage2Applies: async () => {
      const { readAnchorConfig, anchorReceiptsPresentOnDisk } = await import(
        "../transparency/anchoring.js"
      );
      let configEnabled: boolean;
      try {
        const state = await readAnchorConfig({
          storage: args.storage,
          masterKey: args.master,
        });
        configEnabled = state.status === "enabled";
      } catch {
        // Tampered/unreadable config: cannot prove "not enabled". Fall through
        // to the receipts probe; if receipts exist OR we cannot rule the config
        // out, Stage 2 applies. Treat the throw as "applies".
        return true;
      }
      if (configEnabled) return true;
      return anchorReceiptsPresentOnDisk(args.storage);
    },
    readOnDiskFloor: async () => {
      const { readTransparencyCounterFloor } = await import(
        "../transparency/emitter.js"
      );
      return readTransparencyCounterFloor(args.storage, args.master);
    },
    // FIX 2: an EXISTING-but-unreadable/malformed receipt store must FREEZE,
    // not let the exception escape to the boot catch (which only logs → no
    // freeze). computeHighestVerifiedAnchoredCounter throws on a malformed
    // store (readAnchorReceipts / buildAnchorsExport); catch it here and
    // resolve to unverifiableAnchorPresent → suspected → freeze. A genuinely
    // ABSENT store yields counter 0 (nothing anchored), never a freeze.
    readHighestAnchoredCounter: async () => {
      const { computeHighestVerifiedAnchoredCounter } = await import(
        "../transparency/anchoring.js"
      );
      try {
        const result = await computeHighestVerifiedAnchoredCounter({
          storage: args.storage,
          masterKey: args.master,
          fortressId: args.fortressId,
        });
        return {
          highestAnchoredCounter: result.highestAnchoredCounter,
          unverifiableAnchorPresent: result.unverifiableAnchorPresent,
          notes: result.notes,
        };
      } catch (err) {
        // Present-but-unreadable receipt store (or config/export read error):
        // fail toward freeze. We cannot read the witness, so we must not read
        // it as "no witness". highestAnchoredCounter stays 0 but the
        // unverifiable flag forces the suspected verdict regardless of the
        // floor numbers.
        return {
          highestAnchoredCounter: 0,
          unverifiableAnchorPresent: true,
          notes: [
            "the anchor receipt store is present but could not be read or " +
              "parsed (corrupt, tampered, or otherwise unverifiable); treating " +
              "as a suspected rollback (fail toward freeze): " +
              (err instanceof Error ? err.message : String(err)),
          ],
        };
      }
    },
  };
}

function rekorFloorBanner(
  verdict: Extract<RekorFloorVerdict, { kind: "rollback-suspected" }>
): string {
  return (
    "\nSanctuary: WARNING — SUSPECTED CUSTODY ROLLBACK (transparency anchors).\n" +
    `  on-disk transparency counter floor: ${verdict.onDiskFloor}\n` +
    `  highest locally-recorded anchored checkpoint: ${verdict.highestAnchoredCounter}\n` +
    "\n" +
    "This fortress holds a valid anchor receipt (whose counter the public Rekor\n" +
    "transparency log also remembers) for a checkpoint the on-disk checkpoint\n" +
    "store no longer reflects. That is the signature of a rollback of an ANCHORED\n" +
    "fortress that left the receipts behind: the floor regressed below an\n" +
    "anchoring still proven on disk.\n" +
    "\n" +
    "Sanctuary is NOT refusing to boot. It HAS frozen trust-bearing writes\n" +
    "until you acknowledge what happened:\n" +
    "\n" +
    "  sanctuary restore-attest   (requires the fortress passphrase)\n" +
    "\n" +
    "If you did NOT restore anything, treat this as a possible attack: rotate\n" +
    "the master before attesting. Note: a coordinated rollback that ALSO deletes\n" +
    "the higher anchor receipts cannot be caught offline — that needs online\n" +
    "Rekor enumeration or the hardware counter (future stages).\n"
  );
}
