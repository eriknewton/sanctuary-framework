/**
 * Fleet control plane PR-3 fix: EXTERNAL monotonic anti-rollback anchor for the
 * signed license REVOCATION LIST version.
 *
 * The revocation-list record ({@link readRevocationList}) is master-MAC'd and its
 * own writer refuses to LOWER the stored version - but ONLY when the stored record
 * still AUTHENTICATES. A disk-write attacker who CORRUPTS the stored list (flips a
 * byte so its MAC fails) collapses the readable version to 0, and BOTH push paths
 * then treat the current floor as 0. An OLD, genuinely-issuer-signed list (a lower
 * version, e.g. from before the last `revoke-push`) now verifies as "newer" than 0
 * and overwrites the higher authentic version, UN-REVOKING every license the newer
 * list had added. Corrupting the file is thus a targeted rollback primitive.
 *
 * This closes the gap by MIRRORING the proven #805 / guardian-custody /
 * ledger-generation anti-rollback pattern ({@link readLedgerGenerationAnchor}): a
 * monotonic `version` witness, master-MAC'd, persisted in a SEPARATE `_meta` record
 * from the list file it protects. The effective monotonic floor a push must exceed
 * is `max(storedListVersion, anchorVersion)`, where a CORRUPT stored list supplies
 * 0 but the anchor still supplies the true floor - so a corrupt file can never
 * enable a rollback. Because the anchor is MAC'd under the master (which a
 * disk-write-only attacker WITHOUT the passphrase does not have), the attacker can
 * neither forge a lower anchor to match a stale list nor authenticate a tampered
 * anchor.
 *
 * ── WRITE ORDERING (LATCH BEFORE BLOB BEFORE ANCHOR) ───────────────────────────
 * The serialized push is: re-read the WRITABLE floor (list ∪ anchor, NOT the
 * custody latch) -> verify + monotonicity (fail-closed) -> raise the custody
 * revocation-floor LATCH to the new version FIRST -> writeRevocationList -> advance
 * the anchor. Raising the DURABLE latch first guarantees the custody floor can
 * never LAG the list/anchor: a crash after the latch but before the list/anchor
 * leaves the floor AHEAD of the list, which is FAIL-SAFE - enforcement sees
 * floor > list-version (or list absent) and drops to Community (conservative,
 * never an un-revoke). The retry that completes the interrupted list/anchor write
 * re-verifies against the WRITABLE floor (list ∪ anchor), so it is NOT refused
 * `not_newer` by its own already-raised latch. An earlier LATCH-LAST ordering had
 * a hole: a crash after the anchor but before the latch left the durable latch
 * BELOW the pushed version, the retry was refused `not_newer` (list+anchor already
 * carried it), the latch NEVER rose, and a later `rm` of list+anchor dropped the
 * floor to 0 -> un-revoke. Per memory
 * `persist-throw-does-not-prove-noncommit-antirollback`, we do NOT infer
 * commit/non-commit from throw/no-throw; latch-first + the `max()` enforcement
 * floor make every partial persist safe: never a rollback, retry can complete.
 *
 * ── FAIL POSTURE (mirror readEpochWitness / ledger anchor: valid/absent/invalid) ─
 *  - "valid": authenticates under the master -> a trustworthy version floor.
 *  - "absent": no anchor record -> a pre-fix fortress / first boot before any push.
 *    Reads as version 0 (ADDITIVE: a legacy fortress trips nothing).
 *  - "invalid": present but tampered/malformed/wrong-key/unreadable -> SUSPECT.
 *    The floor helper treats an invalid anchor as 0 for FLOOR purposes but pairs it
 *    with the stored-list version via `max()`, so it can only ever RAISE the floor,
 *    never lower a legitimate one; and the writer re-establishes an authentic anchor.
 *
 * No new cryptography: `derivePurposeKey` -> `hmacSha256`, marker + base64url MAC,
 * exactly like the ledger-generation anchor and the activation record.
 */

import type { StorageBackend } from "../storage/interface.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { hmacSha256 } from "../core/hashing.js";
import { canonicalJson } from "../audit/chain.js";
import {
  toBase64url,
  fromBase64url,
  stringToBytes,
  bytesToString,
  constantTimeEqual,
} from "../core/encoding.js";
import {
  readRevocationList,
  writeRevocationList,
  verifyPushedRevocationList,
  REVOCATION_LIST_META_KEY,
  type RevocationListVerifyReason,
} from "./revocation-list.js";
import {
  readRevocationFloorLatch,
  raiseRevocationFloorLatch,
} from "../core/anti-rollback.js";
import { readTransientError } from "../storage/transient-read.js";
import { withCrossProcessLock } from "../storage/cross-process-lock.js";

/** `_meta` key holding the master-MAC'd monotonic revocation-list version anchor. */
export const REVOCATION_VERSION_ANCHOR_META_KEY =
  "fleet-revocation-list-version-anchor-v1";

const REVOCATION_VERSION_ANCHOR_MARKER =
  "__sanctuary_fleet_revocation_version_anchor_v1";
/** Fresh domain for the anchor MAC (distinct from every other MAC domain). */
const REVOCATION_VERSION_ANCHOR_MAC_DOMAIN =
  "sanctuary.fleet.revocation-list.version-anchor.v1\n";
/** HKDF purpose label for the anchor MAC key (distinct from every other purpose). */
const REVOCATION_VERSION_ANCHOR_MAC_PURPOSE = "fleet-revocation-version-mac";

/** The MAC'd payload of the anchor: just the monotonic list version. */
export interface RevocationVersionAnchorData {
  version: number;
}

function revocationVersionAnchorMac(
  master: Uint8Array,
  data: RevocationVersionAnchorData,
): Uint8Array {
  const macKey = derivePurposeKey(master, REVOCATION_VERSION_ANCHOR_MAC_PURPOSE);
  const mac = hmacSha256(
    macKey,
    stringToBytes(REVOCATION_VERSION_ANCHOR_MAC_DOMAIN + canonicalJson(data)),
  );
  macKey.fill(0);
  return mac;
}

/**
 * Read + authenticate the external revocation-version anchor. Tri-state, mirror
 * of {@link readLedgerGenerationAnchor}:
 *  - "valid": authenticates under the master -> a trustworthy version floor.
 *  - "absent": no anchor record -> pre-fix fortress / first boot. Reads as 0.
 *  - "invalid": present but tampered / malformed / wrong-key / unreadable -> SUSPECT.
 */
export async function readRevocationVersionAnchor(
  storage: StorageBackend,
  master: Uint8Array,
): Promise<
  | { status: "valid"; data: RevocationVersionAnchorData }
  | { status: "absent" }
  | { status: "invalid" }
> {
  let raw: Uint8Array | null;
  try {
    raw = await storage.read("_meta", REVOCATION_VERSION_ANCHOR_META_KEY);
  } catch {
    // Unreadable storage is an anchor we cannot trust -> suspected, not absent.
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
    (parsed as Record<string, unknown>)[REVOCATION_VERSION_ANCHOR_MARKER] !== true
  ) {
    return { status: "invalid" };
  }
  const obj = parsed as Record<string, unknown>;
  const data = obj.data as Partial<RevocationVersionAnchorData> | undefined;
  const mac = obj.mac;
  if (
    !data ||
    typeof data !== "object" ||
    typeof data.version !== "number" ||
    !Number.isSafeInteger(data.version) ||
    data.version < 0 ||
    typeof mac !== "string"
  ) {
    return { status: "invalid" };
  }
  const fullData: RevocationVersionAnchorData = { version: data.version };
  let provided: Uint8Array;
  try {
    provided = fromBase64url(mac);
  } catch {
    return { status: "invalid" };
  }
  if (!constantTimeEqual(provided, revocationVersionAnchorMac(master, fullData))) {
    return { status: "invalid" };
  }
  return { status: "valid", data: fullData };
}

/**
 * Persist (or raise) the revocation-version anchor. MONOTONIC (mirror
 * {@link writeLedgerGenerationAnchor}): it never regresses. A write of a version
 * LOWER than an already-valid anchor is refused (that would itself be a
 * rollback-laundering write). An equal version (idempotent re-stamp of the same
 * push) or a higher version (the normal advance after a push) is accepted. A
 * present-but-invalid anchor is not a valid floor to compare against; we overwrite
 * it with an authentic record under the current master (the caller has already
 * failed-closed where it matters via the `max()` floor helper).
 */
export async function writeRevocationVersionAnchor(
  storage: StorageBackend,
  master: Uint8Array,
  version: number,
): Promise<void> {
  if (!Number.isSafeInteger(version) || version < 0) {
    throw new Error(
      `writeRevocationVersionAnchor: version must be a non-negative safe integer (got ${version})`,
    );
  }
  const current = await readRevocationVersionAnchor(storage, master);
  if (current.status === "valid" && version < current.data.version) {
    throw new Error(
      "Sanctuary: refusing to lower the fleet revocation-list version anchor " +
        `(${current.data.version} -> ${version}); a lower version is a ` +
        "rollback-laundering write.",
    );
  }
  const record = {
    [REVOCATION_VERSION_ANCHOR_MARKER]: true,
    data: { version },
    mac: toBase64url(revocationVersionAnchorMac(master, { version })),
  };
  await storage.write(
    "_meta",
    REVOCATION_VERSION_ANCHOR_META_KEY,
    stringToBytes(JSON.stringify(record)),
  );
}

/**
 * The EFFECTIVE monotonic floor a pushed revocation list must strictly exceed:
 * `max(storedListVersion, anchorVersion, witnessFloorLatch)`. This is the ONE
 * place both push paths compute their floor so they agree, and it is ALSO the
 * floor the enforcement chokepoint ({@link revocationVerifiability}) compares the
 * stored list against.
 *
 *  - A VALID stored list contributes its own version (the anchor should equal it,
 *    but `max` is safe if the anchor lags a crash-interrupted write).
 *  - A CORRUPT/absent stored list contributes 0 - but the ANCHOR and the
 *    custody-MAC'd WITNESS FLOOR LATCH still contribute the true floor, so a
 *    corrupt/deleted file cannot roll the floor back to 0.
 *  - A VALID anchor contributes its version; an absent/invalid anchor contributes
 *    0.
 *  - The WITNESS FLOOR LATCH (custody-MAC'd, in the epoch witness) contributes its
 *    floor. It is the binding that survives deletion of BOTH the list file AND the
 *    standalone anchor: deleting them both drops list+anchor to 0, but the witness
 *    still proves a version-N revocation existed.
 * Because all three are combined with `max`, no single deleted/tampered signal can
 * LOWER a floor another still establishes. The floor is the safe upper bound of
 * every signal. Never throws.
 */
export async function effectiveRevocationVersionFloor(
  storage: StorageBackend,
  master: Uint8Array,
): Promise<number> {
  let listVersion = 0;
  try {
    const list = await readRevocationList(storage, master);
    if (list.status === "valid") listVersion = list.payload.version;
  } catch {
    listVersion = 0;
  }
  let anchorVersion = 0;
  try {
    const anchor = await readRevocationVersionAnchor(storage, master);
    if (anchor.status === "valid") anchorVersion = anchor.data.version;
  } catch {
    anchorVersion = 0;
  }
  let witnessFloor = 0;
  try {
    const latch = await readRevocationFloorLatch(storage, master);
    witnessFloor = latch.floor;
  } catch {
    // Unreadable witness contributes 0 to the floor (max() keeps the true floor
    // from the list/anchor); never lowers a floor another signal establishes.
  }
  return Math.max(listVersion, anchorVersion, witnessFloor);
}

/**
 * The floor over the two WRITABLE data records only - `max(storedListVersion,
 * anchorVersion)` - EXCLUDING the custody witness latch. This is the floor the
 * SERIALIZED PUSH re-verifies monotonicity against (NOT the full enforcement floor
 * {@link effectiveRevocationVersionFloor}, which includes the latch).
 *
 * WHY EXCLUDE THE LATCH ON THE WRITE PATH (the latch-first crash-recovery fix):
 * the push raises the custody latch FIRST (so the durable floor can never LAG the
 * list/anchor). If a crash then interrupts the push AFTER the latch but BEFORE the
 * list/anchor write, the latch is AHEAD of the list. A retry of the SAME version
 * must be able to COMPLETE the interrupted list/anchor write; if the re-verify
 * floor included the latch (already == the pushed version) the retry would be
 * refused `not_newer` and the list would NEVER be written - permanently wedging
 * enforcement in the fail-closed `absent_below_floor` state (fail-safe, but it
 * bricks the legit fleet's re-push). Verifying against list ∪ anchor lets the
 * retry finish the write; the latch is raised idempotently (never lowered), and
 * ENFORCEMENT still consults the full floor incl. the latch, so an OLD list pushed
 * below the latch is still `rolled_back` -> drop. Never throws.
 */
export async function writableRevocationVersionFloor(
  storage: StorageBackend,
  master: Uint8Array,
): Promise<number> {
  let listVersion = 0;
  try {
    const list = await readRevocationList(storage, master);
    if (list.status === "valid") listVersion = list.payload.version;
  } catch {
    listVersion = 0;
  }
  let anchorVersion = 0;
  try {
    const anchor = await readRevocationVersionAnchor(storage, master);
    if (anchor.status === "valid") anchorVersion = anchor.data.version;
  } catch {
    anchorVersion = 0;
  }
  return Math.max(listVersion, anchorVersion);
}

/**
 * The SINGLE revocation-verifiability signal the ENFORCEMENT path consults. It is
 * the chokepoint that uniformly fails closed on every way the revocation record
 * can be made to lie about a revoked license: ABSENT-after-a-push, CORRUPT, and
 * ROLLED-BACK-below-floor all collapse to ONE `unverifiable` verdict, exactly
 * like a corrupt list. It reuses the codebase's OWN "absent-but-anchor-proves-
 * existence -> fail closed" template ({@link readRevocationFloorLatch} +
 * {@link effectiveRevocationVersionFloor}) rather than inventing a parallel one.
 *
 * The rule, in one place:
 *  - Compute the EFFECTIVE floor = max(list, standalone anchor, custody-MAC'd
 *    witness latch). This is > 0 iff a revocation was EVER established on this
 *    fortress (and survives deletion of the list AND the standalone anchor,
 *    because the witness latch is in the master-MAC'd epoch witness).
 *  - If the effective floor is 0 (no revocation was ever pushed): `clean`. An
 *    ABSENT list here keeps the paid grant - the legit never-revoked fleet.
 *  - If the floor is > 0 (a revocation WAS established) then the stored list must
 *    be VALID and at a version >= the floor. Otherwise the revocation state is
 *    UNVERIFIABLE -> `unverifiable`:
 *      - list ABSENT (deleted) while floor > 0  -> `absent_below_floor`
 *      - list CORRUPT (present, MAC/parse fail), or a non-transient/unclassifiable
 *        read throw (symlink / directory / chmod-000 / EACCES swap)  -> `corrupt`
 *      - list VALID but version < floor (rolled back) -> `rolled_back`
 *      - a genuine transient that never clears while floor > 0 -> `transient_below_floor`
 *  - A TRANSIENT storage-read error is ONLY one of the allowlisted transient IO
 *    codes (`transient-read.ts`: EIO/EAGAIN/EBUSY/...); it is retried a bounded
 *    number of times. Its handling is FLOOR-CONDITIONED (the un-revoke-window fix):
 *      - floor === 0 (no revocation was EVER established): a transient that never
 *        clears returns `transient` -> the caller applies grace. There is nothing
 *        to revoke, so a benign IO blip must not drop a legit never-revoked fleet.
 *      - floor > 0 (a revocation WAS established): a transient that never clears
 *        returns `unverifiable` (`transient_below_floor`). "I cannot confirm this
 *        license is un-revoked" is a DROP, not indefinite grace: an attacker must
 *        not be able to hold a killed license paid forever by making the list read
 *        keep throwing a transient code.
 *  - A NON-transient / unclassifiable read throw (symlink / directory /
 *    chmod-000 / EACCES / EPERM / EISDIR / ELOOP swap of the record) is NEVER
 *    laundered as transient - it is `unverifiable` (`corrupt`), fail closed,
 *    exactly like a MAC/parse failure.
 *
 * NEVER throws.
 */
export type RevocationVerifiability =
  | { status: "clean"; floor: number; listVersion: number }
  | {
      status: "unverifiable";
      reason:
        | "absent_below_floor"
        | "corrupt"
        | "rolled_back"
        | "transient_below_floor";
      floor: number;
      listVersion: number;
    }
  | { status: "transient"; code: string };

/** Bounded retry budget for a transient revocation-list read before grace. */
export const REVOCATION_READ_RETRY_ATTEMPTS = 3;
/** Delay between transient-read retries (ms). Small: this is on the request path. */
export const REVOCATION_READ_RETRY_DELAY_MS = 25;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Read the raw revocation-list `_meta` bytes with a TRANSIENT-error grace, so a
 * one-off EIO/EAGAIN is retried rather than laundered into "corrupt". Returns a
 * tri-state PLUS a `transient` state distinct from `readRevocationList`'s
 * absent/invalid (which swallow the throw). ENOENT is `null` from `storage.read`
 * (absent), never a throw, so absent is reported cleanly.
 */
async function readRevocationListBytesWithGrace(
  storage: StorageBackend,
  attempts = REVOCATION_READ_RETRY_ATTEMPTS,
  delayMs = REVOCATION_READ_RETRY_DELAY_MS,
): Promise<
  | { status: "present"; raw: Uint8Array }
  | { status: "absent" }
  | { status: "transient"; code: string }
  | { status: "unreadable"; code: string }
> {
  let lastCode = "unknown";
  for (let attempt = 0; attempt < Math.max(1, attempts); attempt += 1) {
    try {
      const raw = await storage.read("_meta", REVOCATION_LIST_META_KEY);
      if (raw === null) return { status: "absent" };
      return { status: "present", raw };
    } catch (err) {
      const transient = readTransientError(err);
      if (transient === null) {
        // A NON-transient throw is NOT one of the allowlisted `TRANSIENT_IO_CODES`
        // (`transient-read.ts`): it is a symlink/directory/permission/loop swap of
        // the record (EACCES / EPERM / EISDIR / ELOOP / symlink_rejected /
        // not_regular_file / ...) or any unclassifiable IO failure. Such a throw is
        // NOT retried and MUST NOT be laundered into the grace path - that would
        // re-open the un-revoke bypass (replace the list with a chmod-000 file /
        // symlink -> non-transient throw -> mislabeled `transient` -> killed
        // license stays paid). Report it as `unreadable` (a present-but-suspect
        // record) so `revocationVerifiability` fails CLOSED (corrupt), NEVER as
        // `transient`. ONLY genuinely allowlisted transient codes reach grace.
        const code =
          err instanceof Error && "code" in err
            ? String((err as NodeJS.ErrnoException).code)
            : "non_transient_error";
        return { status: "unreadable", code };
      }
      lastCode = transient;
      if (attempt < Math.max(1, attempts) - 1) await sleep(delayMs);
    }
  }
  return { status: "transient", code: lastCode };
}

export async function revocationVerifiability(
  storage: StorageBackend,
  master: Uint8Array,
): Promise<RevocationVerifiability> {
  // The effective floor is > 0 iff a revocation was EVER established, surviving
  // deletion of the list AND the standalone anchor (the witness latch remains).
  const floor = await effectiveRevocationVersionFloor(storage, master);

  // Read the list bytes with transient grace so a benign IO hiccup does not drop
  // a legit paid fleet. ENOENT is `null` (absent), never a throw.
  const bytes = await readRevocationListBytesWithGrace(storage);
  if (bytes.status === "unreadable") {
    // A non-transient / unclassifiable read throw (symlink / directory /
    // chmod-000 / EACCES swap of the record). This is NOT grace: fail CLOSED
    // exactly like a corrupt list, so replacing the list with an unreadable inode
    // cannot keep a killed license paid. (`floor` is irrelevant - an unreadable
    // record is suspect whether or not a revocation was ever established.)
    return { status: "unverifiable", reason: "corrupt", floor, listVersion: 0 };
  }
  if (bytes.status === "transient") {
    // A GENUINE allowlisted transient that never cleared. Floor-conditioned:
    //  - floor > 0 (a revocation WAS established): fail CLOSED. We cannot confirm
    //    the license is un-revoked, and an attacker must not hold a killed license
    //    paid forever by making the read keep throwing a transient code.
    //  - floor === 0 (nothing ever revoked): grace. A benign IO blip must not drop
    //    a legit never-revoked fleet, and there is nothing to un-revoke.
    if (floor > 0) {
      return {
        status: "unverifiable",
        reason: "transient_below_floor",
        floor,
        listVersion: 0,
      };
    }
    return { status: "transient", code: bytes.code };
  }

  if (bytes.status === "absent") {
    // No list on disk. If a revocation was ever established (floor > 0) the list's
    // absence is a DELETION -> unverifiable. If nothing was ever established
    // (floor 0) an absent list is the legit never-revoked fleet -> clean.
    if (floor > 0) {
      return {
        status: "unverifiable",
        reason: "absent_below_floor",
        floor,
        listVersion: 0,
      };
    }
    return { status: "clean", floor: 0, listVersion: 0 };
  }

  // Present. Authenticate it (readRevocationList re-does the MAC over the exact
  // bytes; it returns valid/absent/invalid - absent is impossible here since we
  // just read present bytes, so we only distinguish valid vs invalid).
  const record = await readRevocationList(storage, master);
  if (record.status === "valid") {
    if (record.payload.version < floor) {
      // Rolled back below an established floor (an old genuinely-signed list
      // replayed under the floor). Unverifiable.
      return {
        status: "unverifiable",
        reason: "rolled_back",
        floor,
        listVersion: record.payload.version,
      };
    }
    return { status: "clean", floor, listVersion: record.payload.version };
  }

  // Present but does not authenticate (MAC/parse fail) -> corrupt, fail closed.
  return { status: "unverifiable", reason: "corrupt", floor, listVersion: 0 };
}

// ── Serialized push (the ONE write path both callers use) ────────────────────

/** The lockfile name for the cross-process revocation-list push lock. */
export const REVOCATION_PUSH_LOCK_FILE = "fleet-revocation-list.push.lock";

/**
 * The RESULT of a serialized revocation-list push. `not_newer` here means the
 * pushed version did not exceed the floor observed INSIDE the lock (so a
 * concurrent push already advanced it) - a benign no-op, not a failure to persist
 * the winner.
 */
export type SerializedRevocationPushResult =
  | { ok: true; version: number; revokedCount: number }
  | { ok: false; reason: RevocationListVerifyReason };

/**
 * Persist a pushed signed revocation list ATOMICALLY under a cross-process push
 * lock - the SINGLE write path both the HTTP route and the CLI use, so two
 * overlapping pushes (v6 + v7) cannot both read the same stale floor (v5), both
 * verify, and interleave the list vs the anchor/latch. Mirrors the #871 lock
 * lesson: a plain fail-closed O_EXCL lock ({@link withCrossProcessLock}), NOT a
 * stat-then-unlink race.
 *
 * Under the lock, in order (crash-safe ordering, LATCH BEFORE BLOB BEFORE ANCHOR):
 *   1. RE-READ the WRITABLE floor (list ∪ anchor, {@link writableRevocationVersionFloor},
 *      EXCLUDING the custody latch) INSIDE the lock (so it reflects any push that
 *      won the lock first) and RE-VERIFY monotonicity against THAT floor. A push
 *      that raced in and is no longer strictly-newer is refused `not_newer` here,
 *      even though it passed the caller's optimistic pre-check outside the lock.
 *   2. raiseRevocationFloorLatch (the custody-MAC'd witness binding) to the new
 *      version FIRST, so the DURABLE floor can never LAG the list/anchor. A crash
 *      after this but before the list/anchor write leaves the latch AHEAD of the
 *      list, which is FAIL-SAFE: enforcement ({@link revocationVerifiability})
 *      reads floor > list-version (or list absent) -> `rolled_back` /
 *      `absent_below_floor` -> drop to Community (conservative, NEVER an un-revoke).
 *   3. writeRevocationList (the authenticated newer list).
 *   4. writeRevocationVersionAnchor to the new version.
 *
 * The old ordering (blob -> anchor -> LATCH LAST) had a hole: a crash after the
 * anchor but before the latch left the durable latch BELOW the pushed version, and
 * a retry of the same version was refused `not_newer` (the list+anchor already
 * carried it), so the latch NEVER rose - a later `rm` of list+anchor then dropped
 * the floor to 0 and UN-REVOKED. Raising the latch FIRST closes that: the durable
 * floor leads, and because the re-verify uses the WRITABLE floor (list ∪ anchor,
 * not the latch) a retry can still COMPLETE the list/anchor write it was
 * interrupted mid-way through (the latch is raised idempotently, never lowered).
 *
 * The caller passes the ALREADY-VERIFIED payload (verified against the pinned
 * issuer key + an optimistic floor) AND the raw `signed` + issuer key so this can
 * RE-VERIFY under the lock against the fresh floor. NEVER throws for a
 * monotonicity/verify failure (returns `ok:false`); a genuine persist/IO error
 * still throws to the caller (the push failed, nothing partially trusted - the
 * max() enforcement floor keeps any partial write safe, and a latch-ahead-of-list
 * partial is fail-closed).
 */
export async function persistPushedRevocationListSerialized(args: {
  storage: StorageBackend;
  master: Uint8Array;
  signed: unknown;
  issuerPublicKey: Uint8Array;
}): Promise<SerializedRevocationPushResult> {
  const { storage, master, signed, issuerPublicKey } = args;
  return withCrossProcessLock(
    storage,
    "_meta",
    REVOCATION_PUSH_LOCK_FILE,
    async (): Promise<SerializedRevocationPushResult> => {
      // Re-read the WRITABLE floor (list ∪ anchor, NOT the custody latch) INSIDE
      // the lock: a push that won the lock first may have advanced it. Excluding
      // the latch here lets a latch-first crash be COMPLETED by a retry (see the
      // ordering note above); enforcement still consults the full floor incl. the
      // latch, so an old list below the latch is `rolled_back` -> drop.
      const freshFloor = await writableRevocationVersionFloor(storage, master);
      const verification = verifyPushedRevocationList(
        signed,
        issuerPublicKey,
        freshFloor,
      );
      if (!verification.ok) {
        return { ok: false, reason: verification.reason };
      }
      // LATCH -> BLOB -> ANCHOR. The custody latch (the DURABLE floor) is raised
      // FIRST so it can never lag the list/anchor; a crash after it leaves the
      // floor AHEAD of the list, which is fail-closed at enforcement (drop, never
      // an un-revoke). raiseRevocationFloorLatch is monotonic (never lowers), so a
      // retry of the same version is an idempotent no-op here.
      await raiseRevocationFloorLatch(
        storage,
        master,
        verification.payload.version,
      );
      await writeRevocationList(storage, master, verification.payload);
      await writeRevocationVersionAnchor(
        storage,
        master,
        verification.payload.version,
      );
      return {
        ok: true,
        version: verification.payload.version,
        revokedCount: verification.payload.revokedLicenseIds.length,
      };
    },
  );
}
