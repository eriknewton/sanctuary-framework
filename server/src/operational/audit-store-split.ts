/**
 * Sanctuary MCP Server: F2 Option A, fortress audit store split by writer
 *
 * Fixes drill-verified finding F2 (2026-07-14, Mini1): on an armed fortress
 * the root Castle Wall daemon and the (non-root) operator CLI both wrote into
 * the SAME `_audit` chain (`operational/audit-log.ts`). The daemon's
 * root-owned entries are unreadable by the operator uid, so the operator's
 * own `AuditLog.ensureLoaded()` threw `AuditIntegrityError` on every armed
 * box with any daemon history, and `file-grant mint` (which requires a
 * durable audit write) failed closed on the exact machines that are most
 * locked down. See `Review/Sanctuary/FileGrant_F2_Audit_Contamination_Decision_2026-07-14.md`
 * (Erik-ratified Option A) for the full decision record.
 *
 * This module owns:
 *   - the daemon's OWN root-owned audit namespace (`_audit-daemon`), reached
 *     via a thin `StorageBackend` remapping wrapper so `operational/audit-log.ts`
 *     itself needs no namespace-parameterization surgery;
 *   - the one-time, idempotent, crash-safe migration that seals an existing
 *     (possibly contaminated) `_audit` chain as a legacy segment and hands
 *     the daemon its own chain going forward (`migrateFortressAuditStoreSplit`);
 *   - the honest dual-chain reader (`verifyFortressAuditFullPicture`) that
 *     reports each chain's verdict SEPARATELY and never calls an
 *     unreadable-at-this-privilege chain "verified".
 *
 * The actual split-boundary record (the MAC-authenticated marker that seals
 * the legacy chain) is defined in `audit-log.ts` itself
 * (`writeAuditStoreSplitBoundary` / `readAuditStoreSplitBoundary`) since the
 * class's own load path needs the identical envelope/MAC logic; see that
 * module's doc comment for the full design rationale: why a hard seal rather
 * than a surgical extraction, why the record is operator-readable, why it is
 * NOT stored via the encrypted StorageBackend contract.
 */

import { readdir, stat } from "node:fs/promises";
import type { FilesystemStorage } from "../storage/filesystem.js";
import type {
  StorageBackend,
  StorageEntryMeta,
  FilesystemStorageCapabilities,
} from "../storage/interface.js";
import { assertSdwRawWriteAuthorized, isSdwNamespace } from "../sdw/write-gate.js";
import { bytesToString } from "../core/encoding.js";
import { computeAuditEntryHash } from "../audit/chain.js";
import {
  AuditLog,
  deriveAuditStoreSplitBoundaryMacKey,
  auditStoreSplitBoundaryPath,
  writeAuditStoreSplitBoundary,
  readAuditStoreSplitBoundary,
  type AuditLogConfig,
  type AuditIntegrityFinding,
  type AuditStoreSplitBoundary,
} from "./audit-log.js";

/** The root daemon's own audit namespace. Independently tamper-evident from
 * the operator's `_audit` chain, root-owned (0700-class: whichever uid
 * creates the directory owns it, which is always root once a daemon runs
 * against a fortress, since this namespace's FIRST writer is always the
 * migration, which only ever runs from the root daemon startup path). */
export const AUDIT_DAEMON_NAMESPACE = "_audit-daemon";
/** The daemon chain's own checkpoint/rotation-anchor namespace, mirroring
 * `AUDIT_CHECKPOINT_NAMESPACE` in audit-log.ts one-for-one so the daemon's
 * own rotation/checkpoint machinery never collides with the operator's. */
export const AUDIT_DAEMON_CHECKPOINT_NAMESPACE = "_audit-daemon_checkpoints";
/** The daemon chain's own `_meta` remap. `AuditLog` reads/writes exactly one
 * plaintext key here (`audit-head-anchor-established-v1`, the "has this
 * chain ever been established" TOFU signal), via `_meta` directly rather
 * than through a named constant. The real `_meta` namespace also holds the
 * fortress's master custody envelope and other cross-subsystem records that
 * must NEVER be reachable through this adapter, so this gets its own
 * dedicated, fully isolated namespace rather than passing `_meta` through
 * unmapped. */
export const AUDIT_DAEMON_META_NAMESPACE = "_audit-daemon_meta";

/**
 * Distinct, LOCAL operation string for the migration marker entry the
 * daemon's chain begins with. This is an `AuditLog` entry `operation` value
 * ONLY, like file-grant's `file_grant_recorded` precedent: it is never
 * dispatched to `ApprovalGate.evaluate`/`classifyOperation` and carries no
 * principal-policy tier of its own. Do NOT add this to any shared/global
 * tier enum (the prior lesson: widening a shared security enum fans out;
 * a distinct value in a local field is the safe pattern).
 */
export const AUDIT_STORE_SPLIT_MIGRATION_OP = "audit_store_split_migration";

const REMAPPED_NAMESPACES: Readonly<Record<string, string>> = {
  _audit: AUDIT_DAEMON_NAMESPACE,
  _audit_checkpoints: AUDIT_DAEMON_CHECKPOINT_NAMESPACE,
  _meta: AUDIT_DAEMON_META_NAMESPACE,
};

function remapNamespace(namespace: string): string {
  const mapped = REMAPPED_NAMESPACES[namespace];
  if (!mapped) {
    // Defense in depth: `AuditLog` is only ever supposed to touch these three
    // namespaces (`_audit` for entries, `_audit_checkpoints` for anchors and
    // checkpoints, `_meta` for the plaintext "chain ever established" marker;
    // verified against the class source, see the module map). A future
    // `AuditLog` change that touches a fourth namespace must fail LOUD here
    // rather than silently writing operator-chain data into the daemon-owned
    // store, or vice versa.
    throw new Error(
      `DaemonAuditStorageAdapter: refusing to touch unexpected namespace "${namespace}" ` +
        `(only "_audit", "_audit_checkpoints", and "_meta" are remapped for the daemon audit chain)`
    );
  }
  return mapped;
}

/**
 * Thin `StorageBackend` wrapper that transparently redirects the two
 * namespaces `AuditLog` touches (`_audit`, `_audit_checkpoints`) onto the
 * daemon's own (`_audit-daemon`, `_audit-daemon_checkpoints`), delegating
 * everything else to the real underlying `FilesystemStorage`. This lets a
 * SECOND, fully independent `AuditLog` instance exist against the exact same
 * fortress without any change to `AuditLog`'s own namespace handling: the
 * class always thinks it is writing `_audit`; this wrapper is the only thing
 * that knows the daemon's entries actually land under `_audit-daemon`.
 *
 * Because the wrapped `FilesystemStorage.write`/`writeDurable` create their
 * namespace directory with the OS default owner (the calling process's uid),
 * every file this adapter's `AuditLog` produces on an armed box is
 * root-owned: the daemon process only ever constructs this adapter when it
 * is itself running as root (see `cli/castle-wall.ts`'s daemon command).
 */
// Exported (not just used internally by `createDaemonAuditLog`) so the
// namespace-remap defense-in-depth guard is directly unit-testable without
// standing up a full `AuditLog`.
export class DaemonAuditStorageAdapter
  implements StorageBackend, FilesystemStorageCapabilities
{
  constructor(private readonly inner: FilesystemStorage) {}

  // Every method below is declared `async` (not a plain function returning
  // `this.inner.<method>(...)`), specifically so `remapNamespace`'s throw on
  // an unexpected namespace is always delivered as a REJECTED PROMISE, never
  // a synchronous throw. `StorageBackend` callers are entitled to rely on the
  // Promise contract (`.catch(...)`, `Promise.all([...])`, etc.), not only on
  // `await` inside a `try`.
  //
  // `write`/`writeDurable` also call `assertSdwRawWriteAuthorized` directly
  // (not just via the delegated `this.inner.write`, which already enforces
  // it too). `remapNamespace` never lets an SDW namespace (`_sdw_*`) reach
  // this adapter at all (only `_audit`/`_audit_checkpoints`/`_meta` are
  // allowlisted; anything else throws), so this call is always a structural
  // no-op passthrough in practice, but `test/sdw/sdw-architecture.test.ts`
  // requires EVERY `StorageBackend` implementer to enforce the SDW gate
  // independently of any inner delegate, on the reasonable assumption that a
  // future implementer might not delegate to a gate-enforcing backend. Same
  // reasoning for the explicit `isSdwNamespace` check in `namespacePath`.
  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    const remapped = remapNamespace(namespace);
    const checkedData = assertSdwRawWriteAuthorized(remapped, key, data);
    return this.inner.write(remapped, key, checkedData);
  }
  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    return this.inner.read(remapNamespace(namespace), key);
  }
  async delete(
    namespace: string,
    key: string,
    secureOverwrite?: boolean
  ): Promise<boolean> {
    return this.inner.delete(remapNamespace(namespace), key, secureOverwrite);
  }
  async list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]> {
    return this.inner.list(remapNamespace(namespace), prefix);
  }
  async exists(namespace: string, key: string): Promise<boolean> {
    return this.inner.exists(remapNamespace(namespace), key);
  }
  async totalSize(): Promise<number> {
    return this.inner.totalSize();
  }
  namespacePath(namespace: string): string {
    // Synchronous by interface contract (mirrors `FilesystemStorage.namespacePath`,
    // which also throws synchronously for a rejected namespace).
    const remapped = remapNamespace(namespace);
    if (isSdwNamespace(remapped)) {
      throw new Error(
        "Filesystem paths for SDW namespaces are not exposed"
      );
    }
    return this.inner.namespacePath(remapped);
  }
  async writeDurable(namespace: string, key: string, data: Uint8Array): Promise<void> {
    const remapped = remapNamespace(namespace);
    const checkedData = assertSdwRawWriteAuthorized(remapped, key, data);
    return this.inner.writeDurable(remapped, key, checkedData);
  }
}

/**
 * Construct the `AuditLog` instance for the root daemon's own chain. Always
 * passes `consultSplitBoundary: false`: this instance's local sequence
 * numbers start fresh at 1 in its own namespace and must never be compared
 * against the operator `_audit` chain's sealed tip sequence (that comparison
 * is meaningless across two independent chains; see `audit-log.ts`'s
 * `AuditLogConfig.consultSplitBoundary` doc comment).
 */
export function createDaemonAuditLog(
  storage: FilesystemStorage,
  masterKey: Uint8Array,
  config?: AuditLogConfig
): AuditLog {
  return new AuditLog(new DaemonAuditStorageAdapter(storage), masterKey, {
    ...config,
    consultSplitBoundary: false,
  });
}

export class AuditStoreSplitMigrationError extends Error {
  constructor(
    message: string,
    readonly findings: readonly AuditIntegrityFinding[] = []
  ) {
    super(message);
    this.name = "AuditStoreSplitMigrationError";
  }
}

export type AuditStoreSplitMigrationResult =
  | { status: "already-migrated"; boundary: AuditStoreSplitBoundary }
  | { status: "migrated"; boundary: AuditStoreSplitBoundary };

/**
 * Root-context, idempotent, crash-safe migration: seal the operator's
 * existing `_audit` chain as a legacy segment (a MAC-authenticated
 * split-boundary record capturing its tip) and hand the daemon a genesis
 * marker entry in its own `_audit-daemon` chain that references that sealed
 * tip. See `audit-log.ts`'s module doc comment for the full design
 * rationale: why a hard seal of the WHOLE prior chain, rather than a
 * surgical per-entry extraction, is the only design that keeps both "the
 * operator chain stays verifiable" and "no history becomes silently
 * unverifiable" true at once.
 *
 * MUST be called from the root daemon startup path, before the daemon's own
 * `AuditLog` (from {@link createDaemonAuditLog}) is used as an audit sink;
 * see `cli/castle-wall.ts`. Safe to call on every startup: idempotent
 * (returns `already-migrated` once a valid boundary exists) and crash-safe
 * (see the per-step ordering below).
 *
 * Ordering (blob-before-anchor, matching the codebase's existing
 * anti-rollback idiom):
 *   1. Fully re-verify the CURRENT (pre-split) `_audit` chain. Because this
 *      runs as root, root bypasses ordinary file-permission checks, so a
 *      clean read here proves there is no genuine tamper, NOT just that
 *      the daemon's own entries happen to be readable by root. Any
 *      integrity finding at this step is a REAL problem (this migration is
 *      the one reader that should never see `entry_unreadable`), so it
 *      aborts loudly rather than sealing a chain it cannot fully account
 *      for.
 *   2. If the daemon's own chain is still empty, append its genesis marker
 *      entry (durable, `appendCritical` + `flush`) referencing the sealed
 *      tip. A non-empty daemon chain at this point can ONLY be the result of
 *      a prior crashed migration attempt (nothing else writes to
 *      `_audit-daemon` before the boundary record exists, see the
 *      docstring on {@link createDaemonAuditLog}), so it is safe to skip
 *      re-appending and proceed straight to step 3.
 *   3. Write the split-boundary record. THIS is the commit point: only once
 *      it lands does the operator's own `ensureLoaded()` start skipping the
 *      legacy region. A crash before this step is always safely retried
 *      (steps 1-2 are deterministic / idempotent); a crash after it leaves
 *      both chains already consistent.
 */
export async function migrateFortressAuditStoreSplit(opts: {
  storage: FilesystemStorage;
  masterKey: Uint8Array;
  /** `identity_id` recorded on the daemon's genesis marker entry. */
  identityId?: string;
}): Promise<AuditStoreSplitMigrationResult> {
  const { storage, masterKey, identityId } = opts;
  const auditDir = storage.namespacePath("_audit");
  const statePath = dirnameOf(auditDir);
  const macKey = deriveAuditStoreSplitBoundaryMacKey(masterKey);

  const existing = await readAuditStoreSplitBoundary(statePath, macKey);
  if (existing.status === "valid") {
    return { status: "already-migrated", boundary: existing.boundary };
  }
  if (existing.status === "invalid") {
    throw new AuditStoreSplitMigrationError(
      `the fortress audit store split-boundary record at ` +
        `${auditStoreSplitBoundaryPath(statePath)} is present but failed ` +
        `authentication (tampered, forged, or wrong key). Refusing to ` +
        `re-seal or overwrite it; this requires operator investigation.`
    );
  }

  // Step 1: fully re-verify the pre-split chain, as root. Use
  // `consultSplitBoundary: false`: the probe must read the WHOLE `_audit` chain
  // from genesis to compute its true tip, and it must NOT apply boundary
  // semantics (there is no valid boundary yet; that is what we are about to
  // write). Critically, on a RETRY after a crash between step 2 (daemon genesis
  // written) and step 3 (boundary written), a `consultSplitBoundary: true`
  // probe would see the `_audit-daemon` marker with no boundary and raise a
  // spurious `split_boundary_missing` finding, blocking the legitimate retry.
  const probe = new AuditLog(storage, masterKey, {
    integrityMode: "lenient",
    consultSplitBoundary: false,
  });
  const preSplitFindings = await probe.getIntegrityFindings();
  if (preSplitFindings.length > 0) {
    throw new AuditStoreSplitMigrationError(
      `refusing to seal the fortress audit chain for the writer-split ` +
        `migration: ${preSplitFindings.length} integrity finding(s) on the ` +
        `pre-split "_audit" chain. This migration runs as root and can read ` +
        `every entry regardless of its owner, so these are NOT the routine ` +
        `cross-uid unreadability F2 describes; they indicate a genuine ` +
        `chain problem. Resolve it first (see 'sanctuary castle-wall ` +
        `audit-findings'), then retry.`,
      preSplitFindings
    );
  }
  const head = await probe.getChainHead();

  // Step 2: daemon genesis marker entry (durable, idempotent).
  const daemonAuditLog = createDaemonAuditLog(storage, masterKey);
  const daemonFindings = await daemonAuditLog.getIntegrityFindings();
  if (daemonFindings.length > 0) {
    throw new AuditStoreSplitMigrationError(
      `refusing to seal the fortress audit chain for the writer-split ` +
        `migration: the daemon's own "${AUDIT_DAEMON_NAMESPACE}" chain ` +
        `already has ${daemonFindings.length} integrity finding(s) before ` +
        `any migration entry has been written. This should be impossible ` +
        `on a fresh store; investigate before retrying.`,
      daemonFindings
    );
  }
  const daemonHead = await daemonAuditLog.getChainHead();
  if (daemonHead.sequence === 0) {
    await daemonAuditLog.appendCritical({
      layer: "l2",
      operation: AUDIT_STORE_SPLIT_MIGRATION_OP,
      identity_id: identityId ?? "castle-wall-daemon",
      result: "success",
      details: {
        legacy_namespace: "_audit",
        legacy_tip_sequence: head.sequence,
        legacy_tip_entry_hash: head.entry_hash,
        daemon_namespace: AUDIT_DAEMON_NAMESPACE,
      },
    });
    await daemonAuditLog.flush();
  }
  // else: a prior crashed attempt already landed the genesis entry; see the
  // docstring above for why re-verifying its content is unnecessary (nothing
  // else can have written to this namespace before the boundary exists).

  // Step 3: commit. From this point on, the operator's OWN AuditLog seals
  // the legacy chain and continues from (head.sequence + 1, head.entry_hash).
  await writeAuditStoreSplitBoundary(statePath, macKey, {
    sealed_tip_sequence: head.sequence,
    sealed_tip_entry_hash: head.entry_hash,
    daemon_namespace: AUDIT_DAEMON_NAMESPACE,
  });

  const sealed = await readAuditStoreSplitBoundary(statePath, macKey);
  if (sealed.status !== "valid") {
    // Should be unreachable (we just wrote it with our own key); fail loud
    // rather than report success on an unverifiable claim.
    throw new AuditStoreSplitMigrationError(
      "wrote the fortress audit store split-boundary record but could not " +
        "read it back as valid immediately afterward; refusing to report success."
    );
  }
  return { status: "migrated", boundary: sealed.boundary };
}

function dirnameOf(path: string): string {
  const idx = path.lastIndexOf("/");
  return idx <= 0 ? path : path.slice(0, idx);
}

/**
 * BLOCKER-1(b) (adversarial gate 2026-07-14): the honest verdict for the sealed
 * legacy prefix (the entries at or below the split boundary's tip). Because the
 * routine load skips this region, a separate crypto walk is the only thing that
 * re-verifies it, and it can only do so when the caller can READ the sealed
 * entry files (root, or an operator on a fortress whose sealed entries predate
 * root ownership). The chain check uses `encrypted_payload_bytes` (no decrypt),
 * so it needs no ability to decrypt, only to read the envelope bytes.
 */
export type SealedRegionVerdict =
  /** No VALID boundary present: nothing was sealed by a committed migration. */
  | { status: "not_present" }
  /** The migration sealed an empty chain (`sealed_tip_sequence === 0`). */
  | { status: "empty" }
  /** Every sealed V2 entry re-hashed, chained, and the tip matched the MAC'd
   * `sealed_tip_entry_hash`. */
  | { status: "verified"; entries_verified: number; sealed_tip_sequence: number }
  /** At least one sealed entry could not be read at this privilege (the F2
   * cross-uid case). Honest: NOT verified. Re-run as root. */
  | { status: "unreadable"; note: string }
  /** The sealed V2 entry files are not a gap-free run ending at the tip (a
   * sealed entry was deleted / disappeared). */
  | { status: "incomplete"; expected_tip: number; highest_present: number }
  /** A sealed entry's content was tampered: a recomputed entry hash, a chain
   * link, or the tip hash did not match. */
  | {
      status: "hash_mismatch";
      sequence: number;
      expected: string;
      actual: string;
    };

/** One chain's honest verdict from {@link verifyFortressAuditFullPicture}. */
export interface AuditChainReport {
  chain: "operator" | "daemon";
  status:
    | "verified"
    // BLOCKER-1(c): the post-split suffix verified clean, but the sealed legacy
    // region could not be re-verified at this privilege (unreadable). A bare
    // "verified" is withheld so no consumer reads a green over an unverified
    // sealed region.
    | "verified_suffix_only"
    | "findings"
    | "absent"
    | "present_unreadable"
    | "key_unavailable";
  finding_count?: number;
  findings?: AuditIntegrityFinding[];
  /** F2: the sealed legacy prefix's own verdict (present only on the operator
   * chain, and only when a valid boundary exists). */
  sealed_region?: SealedRegionVerdict;
  /** Always present; human-readable, never overclaims (e.g. an unreadable
   * chain is NEVER described as "verified"). */
  note: string;
}

export interface AuditFullPictureReport {
  generated_at: string;
  operator: AuditChainReport;
  daemon: AuditChainReport;
}

/** Local copy of `audit-log.ts`'s V2 `entry-*` sequence parse (that helper is
 * module-private there; audit-store-split.ts imports FROM audit-log.ts, so it
 * cannot import back). Kept trivial; the format is a frozen at-rest contract. */
function parseSealedEntryKeySequence(key: string): number | null {
  const match = /^entry-(\d{20})-/.exec(key);
  if (!match) return null;
  const seq = Number(match[1]);
  return Number.isSafeInteger(seq) ? seq : null;
}

interface SealedEnvelopeV2 {
  sequence: number;
  prev_hash: string;
  entry_hash: string;
  timestamp: string;
  encrypted_payload_bytes: string;
  schema_version: number;
}

function isSealedEnvelopeV2(value: unknown): value is SealedEnvelopeV2 {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const v = value as Record<string, unknown>;
  return (
    v.schema_version === 2 &&
    typeof v.sequence === "number" &&
    Number.isSafeInteger(v.sequence) &&
    v.sequence > 0 &&
    typeof v.prev_hash === "string" &&
    typeof v.entry_hash === "string" &&
    /^[0-9a-f]{64}$/.test(v.entry_hash) &&
    typeof v.timestamp === "string" &&
    typeof v.encrypted_payload_bytes === "string"
  );
}

/**
 * BLOCKER-1(b) (adversarial gate 2026-07-14): the root-capable sealed-prefix
 * verifier. Reads the split boundary, then walks the sealed V2 entries
 * (seq <= sealed_tip), recomputes each `entry_hash`, checks the chain links
 * among present entries, and compares the sealed tip entry's hash to the MAC'd
 * `sealed_tip_entry_hash`. This is the shipped verifier that backs the
 * "inspectable by root" claim: content tampering, reordering, or top/middle
 * deletion is DETECTED whenever the caller can read the files. Needs no
 * decryption (chain covers ciphertext bytes), only read access to the entry
 * files and the master key to authenticate the boundary MAC.
 *
 * Residual (documented): deletion of the LOWEST sealed entry keeps a
 * contiguous-and-tip-matching run and is not distinguishable from a legitimate
 * pre-split rotation floor (the same "delete the bottom" class as the
 * rotation anchor). Pre-V2 (null-sequence) sealed legacy keys are not walked
 * here (no parseable sequence); a fortress that mixes pre-V2 sealed entries
 * gets `verified` over its V2 sealed entries only.
 */
export async function verifySealedLegacyPrefix(
  storage: FilesystemStorage,
  masterKey: Uint8Array
): Promise<SealedRegionVerdict> {
  const statePath = dirnameOf(storage.namespacePath("_audit"));
  const macKey = deriveAuditStoreSplitBoundaryMacKey(masterKey);
  const boundary = await readAuditStoreSplitBoundary(statePath, macKey);
  if (boundary.status !== "valid") return { status: "not_present" };
  const tip = boundary.boundary.sealed_tip_sequence;
  if (tip <= 0) return { status: "empty" };

  let metas: StorageEntryMeta[];
  try {
    metas = await storage.list("_audit");
  } catch {
    return { status: "unreadable", note: "could not list the _audit namespace" };
  }

  const bySeq = new Map<number, SealedEnvelopeV2>();

  for (const meta of metas) {
    const seq = parseSealedEntryKeySequence(meta.key);
    if (seq === null || seq > tip) continue;
    let raw: Uint8Array | null;
    try {
      raw = await storage.read("_audit", meta.key);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "EACCES" || code === "EPERM") {
        return {
          status: "unreadable",
          note: `sealed entry ${meta.key} is not readable at this privilege (re-run as root)`,
        };
      }
      return {
        status: "unreadable",
        note: `sealed entry ${meta.key} could not be read: ${
          err instanceof Error ? err.message : String(err)
        }`,
      };
    }
    if (!raw) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(bytesToString(raw));
    } catch {
      return {
        status: "hash_mismatch",
        sequence: seq,
        expected: "<valid V2 envelope>",
        actual: "<unparseable>",
      };
    }
    if (!isSealedEnvelopeV2(parsed)) {
      return {
        status: "hash_mismatch",
        sequence: seq,
        expected: "<valid V2 envelope>",
        actual: "<malformed envelope>",
      };
    }
    bySeq.set(parsed.sequence, parsed);
  }

  const presentSeqs = [...bySeq.keys()].sort((a, b) => a - b);
  const highest = presentSeqs.length > 0 ? presentSeqs[presentSeqs.length - 1]! : 0;
  // Completeness: a gap-free run ending exactly at the tip.
  if (presentSeqs.length === 0 || highest !== tip) {
    return { status: "incomplete", expected_tip: tip, highest_present: highest };
  }
  for (let i = 1; i < presentSeqs.length; i++) {
    if (presentSeqs[i]! !== presentSeqs[i - 1]! + 1) {
      return { status: "incomplete", expected_tip: tip, highest_present: highest };
    }
  }

  // Crypto walk: recompute each entry hash, verify chain links among present
  // entries, and match the tip to the MAC'd sealed_tip_entry_hash.
  let prevHash: string | null = null; // null = first present entry (its prev
  // points at a possibly-rotated-away predecessor we cannot check)
  for (const seq of presentSeqs) {
    const env = bySeq.get(seq)!;
    const recomputed = computeAuditEntryHash({
      sequence: env.sequence,
      prev_hash: env.prev_hash,
      timestamp: env.timestamp,
      encrypted_payload_bytes: env.encrypted_payload_bytes,
      schema_version: env.schema_version,
    });
    if (recomputed !== env.entry_hash) {
      return {
        status: "hash_mismatch",
        sequence: seq,
        expected: env.entry_hash,
        actual: recomputed,
      };
    }
    if (prevHash !== null && env.prev_hash !== prevHash) {
      return {
        status: "hash_mismatch",
        sequence: seq,
        expected: prevHash,
        actual: env.prev_hash,
      };
    }
    prevHash = env.entry_hash;
  }

  const tipEnv = bySeq.get(tip)!;
  if (tipEnv.entry_hash !== boundary.boundary.sealed_tip_entry_hash) {
    return {
      status: "hash_mismatch",
      sequence: tip,
      expected: boundary.boundary.sealed_tip_entry_hash,
      actual: tipEnv.entry_hash,
    };
  }
  return {
    status: "verified",
    entries_verified: presentSeqs.length,
    sealed_tip_sequence: tip,
  };
}

/**
 * Probe whether the daemon audit directory exists and, if so, whether THIS
 * process can actually list it. Distinguishes three states the caller must
 * report honestly:
 *   - `absent`: no root daemon has ever provisioned a chain here (a fresh or
 *     never-armed fortress); nothing to verify, not a failure.
 *   - `present_unreadable`: a chain exists but this process's privilege
 *     cannot read it (the expected result for a non-root reader on an armed
 *     box); MUST be reported as such, never silently skipped, never
 *     conflated with "absent" or "verified".
 *   - `accessible`: this process can list the directory; a full decrypt +
 *     chain-walk verify is attempted next.
 */
export async function probeDaemonChainAccess(
  storage: FilesystemStorage
): Promise<"absent" | "accessible" | "present_unreadable"> {
  const dirPath = storage.namespacePath(AUDIT_DAEMON_NAMESPACE);
  let stats;
  try {
    stats = await stat(dirPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return "absent";
    // Any other stat error (e.g. an EACCES on an ancestor directory) is
    // conservatively "present_unreadable", never "absent": we genuinely do
    // not know, and claiming absence could hide a real store.
    return "present_unreadable";
  }
  if (!stats.isDirectory()) return "absent";
  try {
    await readdir(dirPath);
    return "accessible";
  } catch {
    return "present_unreadable";
  }
}

/**
 * The full-picture reader: verifies BOTH the operator `_audit` chain and the
 * daemon `_audit-daemon` chain and reports each verdict SEPARATELY. Never
 * calls a chain "verified" unless it was actually decrypted and hash-chain
 * verified at THIS process's privilege: an operator-uid reader on an armed
 * box correctly gets `present_unreadable` for the daemon chain, not
 * `verified` and not silence.
 */
export async function verifyFortressAuditFullPicture(opts: {
  storage: FilesystemStorage;
  masterKey?: Uint8Array;
}): Promise<AuditFullPictureReport> {
  const { storage, masterKey } = opts;
  const generatedAt = new Date().toISOString();

  let operator: AuditChainReport;
  if (!masterKey) {
    operator = {
      chain: "operator",
      status: "key_unavailable",
      note: "no master key supplied; cannot verify the operator _audit chain",
    };
  } else {
    const auditLog = new AuditLog(storage, masterKey, {
      integrityMode: "lenient",
    });
    const findings = await auditLog.getIntegrityFindings();
    // BLOCKER-1(b)/(c) + M-2 (adversarial gate 2026-07-14): the routine load
    // skips the sealed region, so getIntegrityFindings() above verifies only
    // the post-split SUFFIX (plus the cheap sealed-completeness listing check).
    // Re-verify the sealed region's CONTENT with the crypto walk and report it
    // honestly and separately, so "full picture" is not an overclaim: a bare
    // operator "verified" is reserved for "suffix verified AND sealed region
    // verified or genuinely empty". An unreadable sealed region downgrades to
    // "verified_suffix_only" (never bare "verified"); a tampered/incomplete
    // sealed region surfaces as findings.
    const sealed = await verifySealedLegacyPrefix(storage, masterKey);
    const sealedIsProblem =
      sealed.status === "hash_mismatch" || sealed.status === "incomplete";

    if (findings.length > 0 || sealedIsProblem) {
      operator = {
        chain: "operator",
        status: "findings",
        finding_count: findings.length,
        findings,
        ...(sealed.status !== "not_present" ? { sealed_region: sealed } : {}),
        note:
          findings.length > 0
            ? "operator _audit chain has integrity findings"
            : "operator _audit post-split suffix verified, but the sealed legacy region failed re-verification",
      };
    } else if (sealed.status === "unreadable") {
      operator = {
        chain: "operator",
        status: "verified_suffix_only",
        finding_count: 0,
        sealed_region: sealed,
        note:
          "operator _audit post-split suffix fully verified; the sealed legacy " +
          "region is NOT readable at this privilege and was NOT re-verified " +
          "(re-run as root, which can read the sealed entries). This is NOT a " +
          "full verified state.",
      };
    } else {
      // sealed is verified / empty / not_present (never migrated).
      operator = {
        chain: "operator",
        status: "verified",
        finding_count: 0,
        ...(sealed.status !== "not_present" ? { sealed_region: sealed } : {}),
        note:
          sealed.status === "verified"
            ? "operator _audit chain fully verified at this privilege, including a crypto re-walk of the sealed legacy region"
            : "operator _audit chain fully verified at this privilege",
      };
    }
  }

  let daemon: AuditChainReport;
  const access = await probeDaemonChainAccess(storage);
  if (access === "absent") {
    daemon = {
      chain: "daemon",
      status: "absent",
      note: "no root daemon audit store has ever been provisioned on this fortress",
    };
  } else if (access === "present_unreadable") {
    daemon = {
      chain: "daemon",
      status: "present_unreadable",
      note:
        "a daemon audit store exists but is not readable at this process's " +
        "privilege (expected for a non-root reader on an armed box); re-run " +
        "as root for a full verify. This is NOT a verified state.",
    };
  } else if (!masterKey) {
    daemon = {
      chain: "daemon",
      status: "key_unavailable",
      note: "daemon audit store is readable but no master key was supplied; cannot decrypt/verify",
    };
  } else {
    const daemonAuditLog = createDaemonAuditLog(storage, masterKey, {
      integrityMode: "lenient",
    });
    const findings = await daemonAuditLog.getIntegrityFindings();
    daemon =
      findings.length === 0
        ? {
            chain: "daemon",
            status: "verified",
            finding_count: 0,
            note: `${AUDIT_DAEMON_NAMESPACE} chain fully verified at this privilege`,
          }
        : {
            chain: "daemon",
            status: "findings",
            finding_count: findings.length,
            findings,
            note: `${AUDIT_DAEMON_NAMESPACE} chain has integrity findings`,
          };
  }

  return { generated_at: generatedAt, operator, daemon };
}
