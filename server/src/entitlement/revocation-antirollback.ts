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
 * ── WRITE ORDERING (mirror ledger-antirollback: BLOB BEFORE ANCHOR) ────────────
 * The push path is: read effective floor -> verify + monotonicity (fail-closed) ->
 * writeRevocationList (the authenticated newer list) FIRST -> THEN advance the
 * anchor to the new version. A crash between the two leaves the anchor LAGGING the
 * list (anchor <= list.version), which is BENIGN: the floor is `max(list, anchor)`
 * so it never regresses and never false-blocks a legitimate newer push. The
 * dangerous order (bump the anchor first) would, on a crash, leave the anchor ABOVE
 * a not-yet-written list and could refuse a legitimate re-push at the intended
 * version. Per memory `persist-throw-does-not-prove-noncommit-antirollback`, we do
 * NOT infer commit/non-commit from throw/no-throw; the `max()` floor + this ordering
 * make a partial persist ALWAYS safe: never a rollback, never a false-block.
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
import { readRevocationList } from "./revocation-list.js";

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
 * `max(storedListVersion, anchorVersion)`. This is the ONE place both push paths
 * compute their floor so they agree.
 *
 *  - A VALID stored list contributes its own version (the anchor should equal it,
 *    but `max` is safe if the anchor lags a crash-interrupted write).
 *  - A CORRUPT/absent stored list contributes 0 - but the ANCHOR still contributes
 *    the true floor, so a corrupt file cannot roll the floor back to 0.
 *  - A VALID anchor contributes its version; an absent/invalid anchor contributes
 *    0. Because the two are combined with `max`, an invalid anchor can never LOWER
 *    a floor the stored list already establishes, and a corrupt list can never
 *    lower a floor the anchor establishes. The floor is the safe upper bound of
 *    both signals. Never throws.
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
  return Math.max(listVersion, anchorVersion);
}
