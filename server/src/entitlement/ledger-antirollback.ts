/**
 * Fleet license ledger: EXTERNAL monotonic anti-rollback anchor (PR-1
 * fast-follow). Closes the freshness residual that the within-chain integrity
 * check (`verifyLedgerIntegrity`) cannot: the head anchor catches truncation of
 * the CURRENT chain, but it is not MONOTONIC across snapshots. Two attacks slip
 * past a pure within-file check even though every signature in the file is
 * genuine:
 *
 *   1. OLD-SNAPSHOT REPLAY. An attacker swaps in an older, genuinely
 *      issuer-signed copy of the ledger (e.g. from before a `revoke`, or before
 *      the last few issuances). Its head signature was validly produced by the
 *      issuer at the time, so it verifies. The stale view (a revoked license
 *      shown active, or an issuance erased) is issuer-local-records mislead.
 *   2. EMPTY-LEDGER SUBSTITUTION. An empty `{ rows: [] }` has no head to anchor
 *      (the genesis floor), so `verifyLedgerIntegrity` returns ok, and an attacker
 *      erases the whole issuance record and `list` shows "No licenses issued".
 *
 * The fix MIRRORS the PROVEN #805 / guardian custody anti-rollback pattern
 * (`core/anti-rollback.ts`): a monotonic `generation` witness, master-MAC'd,
 * persisted OUTSIDE the attacker-writable ledger file in the storage `_meta`
 * namespace (the same place the epoch witness lives). The ledger carries a
 * signed `generation` (bound into its issuer head); this anchor carries the
 * SAME generation MAC'd under the master. A verifier requires
 * `(ledger.generation ?? 0) >= anchor.generation`:
 *
 *   - an old snapshot has a LOWER generation than the anchor -> rollback;
 *   - an empty ledger has generation 0 < a non-zero anchor -> rollback,
 *     independent of the row-count>0 head guard;
 *   - a legitimate fortress (anchor tracks the ledger) satisfies `>=`.
 *
 * Because the anchor is MAC'd under the master (which a disk-write-only attacker
 * WITHOUT the passphrase does not have), the attacker can neither forge a lower
 * anchor to match their stale ledger nor authenticate a tampered anchor.
 *
 * ── FAIL POSTURE (mirror `readEpochWitness` valid/absent/invalid) ───────────
 *   - "valid": authenticates under the master -> trustworthy floor.
 *   - "absent": no anchor record at all -> a pre-feature fortress (or first
 *     boot before any issuance). Reads as generation 0 (ADDITIVE: a fortress
 *     from before this feature trips nothing).
 *   - "invalid": present but tampered/malformed/wrong-key/unreadable -> SUSPECT.
 *     Fail TOWARD "tampered" for list/enforcement (never brick, never silently
 *     pass), exactly as the epoch witness treats an invalid record.
 *
 * ── WRITE ORDERING (the F1 failure class, build carefully) ──────────────────
 * The CLI mutate path is: load ledger + read anchor -> verify + freshness
 * (fail-closed) -> mutate + sign head with
 * `generation = max(ledger.generation ?? 0, anchor.generation) + 1` ->
 * saveLedger (durable rename) FIRST -> THEN advance the anchor. BLOB BEFORE
 * ANCHOR: a crash between the two leaves `ledger.generation >= anchor.generation`
 * (verify uses `>=`), which is a BENIGN lag, never a false-brick. The dangerous
 * order (bump anchor first) would leave `ledger.generation < anchor.generation`
 * on a crash and FALSE-BRICK a legitimate fortress. Per memory
 * `persist-throw-does-not-prove-noncommit-antirollback`, we do NOT infer
 * commit/non-commit from throw/no-throw; the `>=` comparison + the ordering make
 * a partial persist ALWAYS benign: never a bypass and never a brick.
 *
 * The anchor is MONOTONIC (mirror `writeEpochWitness`): it refuses to LOWER the
 * stored generation. So even though the mutate path advances it AFTER the blob,
 * a concurrent or retried lower write cannot regress the floor.
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
import { verifyLedgerIntegrity, type Ledger } from "./ledger.js";
// the generation anchor is read back from storage and JSON-parsed, so its
// fields are attacker-influenced; diagnostics go through the untrusted-
// diagnostic chokepoint (STATE-STORE-ERRMSG-INTERP-01).
import { describeUntrusted } from "../errors/index.js";

/** `_meta` key holding the master-MAC'd monotonic ledger-generation anchor. */
export const LEDGER_GENERATION_ANCHOR_META_KEY =
  "fleet-license-ledger-generation-anchor-v1";

const LEDGER_GENERATION_ANCHOR_MARKER =
  "__sanctuary_fleet_ledger_generation_anchor_v1";
/** Fresh domain for the anchor MAC (distinct from every other MAC domain). */
const LEDGER_GENERATION_ANCHOR_MAC_DOMAIN =
  "sanctuary.fleet.ledger.generation-anchor.v1\n";
/** HKDF purpose label for the anchor MAC key (distinct from the epoch witness). */
const LEDGER_GENERATION_ANCHOR_MAC_PURPOSE = "fleet-ledger-generation-mac";

/** The MAC'd payload of the anchor: just the monotonic generation. */
export interface LedgerGenerationAnchorData {
  generation: number;
}

function ledgerGenerationAnchorMac(
  master: Uint8Array,
  data: LedgerGenerationAnchorData,
): Uint8Array {
  const macKey = derivePurposeKey(master, LEDGER_GENERATION_ANCHOR_MAC_PURPOSE);
  const mac = hmacSha256(
    macKey,
    stringToBytes(LEDGER_GENERATION_ANCHOR_MAC_DOMAIN + canonicalJson(data)),
  );
  macKey.fill(0);
  return mac;
}

/**
 * Read + authenticate the external ledger-generation anchor. Tri-state, mirror
 * of {@link readEpochWitness}:
 *  - "valid": authenticates under the master -> a trustworthy generation floor.
 *  - "absent": no anchor record -> pre-feature fortress / first boot. Callers
 *    read this as generation 0 (ADDITIVE; trips nothing on a legacy fortress).
 *  - "invalid": present but tampered / malformed / wrong-key / unreadable ->
 *    SUSPECT. Callers fail TOWARD tampered (never silently pass, never brick).
 */
export async function readLedgerGenerationAnchor(
  storage: StorageBackend,
  master: Uint8Array,
): Promise<
  | { status: "valid"; data: LedgerGenerationAnchorData }
  | { status: "absent" }
  | { status: "invalid" }
> {
  let raw: Uint8Array | null;
  try {
    raw = await storage.read("_meta", LEDGER_GENERATION_ANCHOR_META_KEY);
  } catch {
    // Unreadable storage is a witness we cannot trust -> suspected, not absent.
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
    (parsed as Record<string, unknown>)[LEDGER_GENERATION_ANCHOR_MARKER] !== true
  ) {
    return { status: "invalid" };
  }
  const obj = parsed as Record<string, unknown>;
  const data = obj.data as Partial<LedgerGenerationAnchorData> | undefined;
  const mac = obj.mac;
  if (
    !data ||
    typeof data !== "object" ||
    typeof data.generation !== "number" ||
    !Number.isSafeInteger(data.generation) ||
    data.generation < 0 ||
    typeof mac !== "string"
  ) {
    return { status: "invalid" };
  }
  const fullData: LedgerGenerationAnchorData = { generation: data.generation };
  let provided: Uint8Array;
  try {
    provided = fromBase64url(mac);
  } catch {
    return { status: "invalid" };
  }
  if (
    !constantTimeEqual(provided, ledgerGenerationAnchorMac(master, fullData))
  ) {
    return { status: "invalid" };
  }
  return { status: "valid", data: fullData };
}

/**
 * Persist (or raise) the ledger-generation anchor. MONOTONIC (mirror
 * {@link writeEpochWitness}): it never regresses. A write of a generation LOWER
 * than an already-valid anchor is refused (that would itself be a
 * rollback-laundering write). An equal generation (idempotent re-stamp of the
 * same mutation) or a higher generation (the normal advance after a mutation) is
 * accepted.
 *
 * There is deliberately NO `force` escape hatch here: unlike the custody epoch
 * witness (which needs `restore-attest` for legitimate full-disk restores), a
 * ledger-generation regression has no legitimate cause on the issuer's own
 * machine: the ledger is issuer-local bookkeeping the operator only ever
 * appends to. A re-baseline path is explicitly OUT OF SCOPE for this fast-follow
 * (the operator restores from an off-host backup at a higher generation, or
 * accepts the tampered verdict); keeping the anchor strictly non-decreasing is
 * the safe default.
 */
export async function writeLedgerGenerationAnchor(
  storage: StorageBackend,
  master: Uint8Array,
  generation: number,
): Promise<void> {
  if (
    !Number.isSafeInteger(generation) ||
    generation < 0
  ) {
    throw new Error(
      `writeLedgerGenerationAnchor: generation must be a non-negative safe integer (got ${generation})`,
    );
  }
  const current = await readLedgerGenerationAnchor(storage, master);
  if (current.status === "valid" && generation < current.data.generation) {
    throw new Error(
      "Sanctuary: refusing to lower the fleet license ledger generation anchor " +
        `(${describeUntrusted(current.data.generation)} -> ${generation}); a lower generation is a ` +
        "rollback-laundering write.",
    );
  }
  // A present-but-invalid anchor (tampered/wrong-key) is NOT a valid floor we
  // can compare against; we still overwrite it with an authentic record under
  // the current master (the caller has already failed-closed on the invalid
  // read where it matters; this write re-establishes a trustworthy anchor).
  const record = {
    [LEDGER_GENERATION_ANCHOR_MARKER]: true,
    data: { generation },
    mac: toBase64url(ledgerGenerationAnchorMac(master, { generation })),
  };
  await storage.write(
    "_meta",
    LEDGER_GENERATION_ANCHOR_META_KEY,
    stringToBytes(JSON.stringify(record)),
  );
}

/** The freshness + integrity verdict for a loaded ledger. */
export type LedgerFreshnessVerdict =
  | { ok: true; ledgerGeneration: number; anchorGeneration: number }
  | {
      ok: false;
      tampered: true;
      reason: string;
      /** Present for a within-chain integrity failure. */
      rowIndex?: number;
    };

/**
 * The composed anti-rollback + integrity check for a loaded ledger. It runs the
 * within-chain integrity check ({@link verifyLedgerIntegrity}, pinned to the
 * fortress issuer key) AND the external freshness comparison against the
 * master-MAC'd generation anchor. Both must pass.
 *
 * Freshness rule: `(ledger.generation ?? 0) >= anchorGeneration`, where a valid
 * anchor supplies its generation, an ABSENT anchor supplies 0 (a legacy fortress
 * trips nothing), and an INVALID anchor forces a tampered verdict (fail-closed).
 * A ledger generation BELOW the anchor is an old/empty-snapshot replay ->
 * tampered.
 *
 * Order: integrity FIRST (so a structurally broken ledger is reported as such),
 * then freshness. An empty ledger passes integrity (genesis floor) but its
 * generation is 0, so an empty substitution is caught here when the anchor > 0.
 */
export async function checkLedgerFreshness(
  ledger: Ledger,
  issuerPublicKey: Uint8Array,
  storage: StorageBackend,
  master: Uint8Array,
): Promise<LedgerFreshnessVerdict> {
  const integrity = verifyLedgerIntegrity(ledger, issuerPublicKey);
  if (!integrity.ok) {
    return {
      ok: false,
      tampered: true,
      reason: integrity.reason,
      ...(integrity.rowIndex !== undefined
        ? { rowIndex: integrity.rowIndex }
        : {}),
    };
  }

  const anchor = await readLedgerGenerationAnchor(storage, master);
  if (anchor.status === "invalid") {
    // A present-but-unauthenticated anchor is SUSPECT; fail toward tampered
    // rather than silently trusting a ledger whose freshness floor we cannot
    // read (mirror the epoch-witness invalid posture).
    return {
      ok: false,
      tampered: true,
      reason:
        "ledger generation anchor is present but did not authenticate " +
        "(tampered/wrong-key); refusing to trust the ledger's freshness",
    };
  }
  const anchorGeneration = anchor.status === "valid" ? anchor.data.generation : 0;
  const ledgerGeneration = ledger.generation ?? 0;
  if (ledgerGeneration < anchorGeneration) {
    return {
      ok: false,
      tampered: true,
      reason:
        `ledger generation (${ledgerGeneration}) is below the external anchor ` +
        `(${anchorGeneration}); an older or empty ledger snapshot appears to ` +
        "have been restored (rollback)",
    };
  }
  return { ok: true, ledgerGeneration, anchorGeneration };
}
