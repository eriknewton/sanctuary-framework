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
import {
  AuditLog,
  deriveAuditStoreSplitBoundaryMacKey,
  auditStoreSplitBoundaryPath,
  writeAuditStoreSplitBoundary,
  readAuditStoreSplitBoundary,
  writeAuditStoreSplitEstablishedMarker,
  readAuditStoreSplitEstablishedMarker,
  verifySealedRegionAt,
  type AuditLogConfig,
  type AuditIntegrityFinding,
  type AuditStoreSplitBoundary,
  type SealedRegionVerdict,
} from "./audit-log.js";

// F2: the sealed-region verdict type is defined in audit-log.ts (so `AuditLog`
// can produce it without a cycle); re-exported here for the CLI/tests that
// import it from this module.
export type { SealedRegionVerdict } from "./audit-log.js";

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
    // BLOCKER-R2: idempotently ensure the durable established marker exists even
    // for a fortress migrated before this marker was introduced (backfill on the
    // next daemon startup). Harmless when already present (same MAC'd record).
    await writeAuditStoreSplitEstablishedMarker(storage, macKey);
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
  // BLOCKER-R1: the LOWEST surviving V2 sequence in `_audit` at migration time
  // (the pre-split rotation floor, or 1 if never rotated; 0 for an empty chain).
  // Recorded in the boundary so the routine listing check + the root crypto walk
  // can detect deletion of the bottom sealed entry. Computed as root here, so it
  // sees every entry regardless of owner.
  const sealedBase = head.sequence === 0
    ? 0
    : await lowestV2SequenceInAuditNamespace(storage);
  if (head.sequence > 0 && (sealedBase < 1 || sealedBase > head.sequence)) {
    throw new AuditStoreSplitMigrationError(
      `refusing to seal: could not determine a valid sealed base sequence ` +
        `(computed ${sealedBase} for tip ${head.sequence}); the "_audit" chain ` +
        `may be malformed. Investigate before retrying.`
    );
  }

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

  // Step 2b (BLOCKER-R2): write the durable, MAC-authenticated
  // migration-established marker to `_meta` BEFORE the boundary commit. It is
  // NOT co-deletable with the daemon namespaces, so a later boundary deletion
  // (even one that also strips every `_audit-daemon*` namespace) still fails
  // closed (`split_boundary_missing`). Idempotent: a retry re-writes the same
  // MAC'd record. A crash after this but before step 3 leaves the marker with
  // no boundary, which the operator load correctly treats as boundary-missing
  // (fail closed); the retry then completes the boundary.
  await writeAuditStoreSplitEstablishedMarker(storage, macKey);

  // Step 3: commit. From this point on, the operator's OWN AuditLog seals
  // the legacy chain and continues from (head.sequence + 1, head.entry_hash).
  await writeAuditStoreSplitBoundary(statePath, macKey, {
    sealed_tip_sequence: head.sequence,
    sealed_base_sequence: sealedBase,
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

/** BLOCKER-R1: the lowest V2 `entry-*` sequence present in `_audit` (the sealed
 * region's base at migration time). Returns 0 when no V2 entry is present.
 * Metadata-only (`list`), no read/decrypt. */
async function lowestV2SequenceInAuditNamespace(
  storage: FilesystemStorage
): Promise<number> {
  let lowest = 0;
  for (const meta of await storage.list("_audit", "entry-")) {
    const m = /^entry-(\d{20})-/.exec(meta.key);
    if (!m) continue;
    const seq = Number(m[1]);
    if (!Number.isSafeInteger(seq) || seq < 1) continue;
    if (lowest === 0 || seq < lowest) lowest = seq;
  }
  return lowest;
}

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
    // HIGH-R3 (adversarial re-gate 2026-07-14): a VALID boundary proves the
    // migration ran and names the daemon chain, so an absent/renamed daemon
    // directory is a DELETION, not "never provisioned". Reported as `missing`
    // (fail closed), never `absent`.
    | "missing"
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

/**
 * F2: the root-capable sealed-prefix verifier, kept as a stable export for the
 * CLI + tests. Thin wrapper over {@link verifySealedRegionAt} (defined in
 * audit-log.ts so `AuditLog` can produce the same verdict without the master
 * key, via `AuditLog.getAuditChainVerdict()` / `verifySealedRegion()`). It
 * reads the split boundary, walks the sealed V2 entries from the MAC'd base to
 * the MAC'd tip, recomputes each `entry_hash`, checks chain links, and matches
 * the tip hash. No decryption (chain covers ciphertext bytes), only read access
 * plus the master key to derive the boundary MAC key.
 *
 * Deletion of the LOWEST sealed entry IS caught (the MAC'd `sealed_base_sequence`
 * is checked against the lowest surviving sequence). Pre-V2 (null-sequence)
 * sealed keys are not walked here; a chain mixing pre-V2 sealed entries gets
 * `verified` over its V2 sealed region only.
 */
export async function verifySealedLegacyPrefix(
  storage: FilesystemStorage,
  masterKey: Uint8Array
): Promise<SealedRegionVerdict> {
  return verifySealedRegionAt({
    storage,
    statePath: dirnameOf(storage.namespacePath("_audit")),
    macKey: deriveAuditStoreSplitBoundaryMacKey(masterKey),
  });
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
 *
 * This is the plain filesystem probe. It CANNOT distinguish a genuinely fresh
 * fortress from a DELETED daemon store on a migrated one (both stat ENOENT); a
 * caller that needs that distinction must consult the migration-established
 * marker via {@link daemonMigrationEstablished} (as {@link resolveDaemonStorePresence}
 * and {@link verifyFortressAuditFullPicture} do).
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
 * Classify a filesystem access error as a `privilege` limitation (an
 * `EACCES`/`EPERM`, possibly nested on the error's `cause` chain -- re-running
 * as root reads it) or a generic `io` error (root will hit the same failure).
 * The single canonical classifier: `operational` is the lowest layer that owns
 * the daemon store, so every consumer (this module's presence resolver and the
 * evidence-pack's `daemonUnreadableReason`) delegates here rather than
 * re-deriving the walk, so the classification can never drift between surfaces.
 */
export function errnoAccessReason(err: unknown): "privilege" | "io" {
  for (let cur: unknown = err, depth = 0; cur != null && depth < 8; depth++) {
    const code = (cur as NodeJS.ErrnoException).code;
    if (code === "EACCES" || code === "EPERM") return "privilege";
    const next = (cur as { cause?: unknown }).cause;
    if (next === cur) break;
    cur = next;
  }
  return "io";
}

/**
 * True iff the writer-split migration has been ESTABLISHED on this fortress: a
 * valid split-boundary record exists, OR the durable `_meta`
 * migration-established marker is present-but-not-absent (a corrupted/unreadable
 * marker is still migration evidence -- fail closed). This is the single
 * source of the "migration ran" signal, so a DELETED/renamed daemon directory
 * is distinguished from a never-provisioned one identically everywhere. Extracted
 * from {@link verifyFortressAuditFullPicture} (which now calls it) so there is
 * ONE definition, not two that can drift.
 */
export async function daemonMigrationEstablished(
  storage: FilesystemStorage,
  masterKey: Uint8Array
): Promise<boolean> {
  const statePath = dirnameOf(storage.namespacePath("_audit"));
  const macKey = deriveAuditStoreSplitBoundaryMacKey(masterKey);
  // Fail-closed RAW existence check FIRST: `readAuditStoreSplitBoundary`
  // launders an unreadable boundary file (e.g. an EACCES on a root-owned
  // boundary) to `{status:"absent"}`, so relying on its parsed verdict alone
  // would let a destroyed store on a locked-down box read as a never-migrated
  // fortress. A boundary FILE on disk -- readable or not -- proves the
  // migration ran. Any non-ENOENT stat error is treated as present (the file
  // is there but unreadable), never as absent.
  try {
    await stat(auditStoreSplitBoundaryPath(statePath));
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") return true;
    // ENOENT: genuinely no boundary file. Fall through to the parsed reads.
  }
  const boundary = await readAuditStoreSplitBoundary(statePath, macKey);
  // Any PRESENT boundary record (valid OR invalid/tampered) is migration
  // evidence: the migration is the only writer of this record, and a tampered
  // boundary on an armed box is itself a fail-closed signal, so a subsequently
  // deleted daemon store must read as `missing`, never `absent`. Only a
  // genuinely `absent` boundary falls through to the marker.
  if (boundary.status !== "absent") return true;
  // A corrupted/unreadable marker is still migration evidence (fail closed).
  return (await readAuditStoreSplitEstablishedMarker(storage, macKey)) !== "absent";
}

/** The marker-aware daemon-store presence verdict. See {@link resolveDaemonStorePresence}. */
export type DaemonStorePresence =
  | { kind: "absent" }
  | { kind: "missing" }
  | { kind: "present_unreadable"; reason: "privilege" | "io" }
  | { kind: "accessible" };

/**
 * The marker-aware daemon-store presence resolver: the SINGLE census/export
 * chokepoint for "what state is the daemon enforcement store in". Folds the
 * plain filesystem probe together with {@link daemonMigrationEstablished} so a
 * daemon store that is absent WHILE split evidence is present (a deleted/renamed
 * store on a migrated fortress, or present-but-unverifiable split evidence) is
 * reported as `missing`, NOT `absent` (a never-armed fortress) -- mirroring
 * {@link verifyFortressAuditFullPicture}'s dual-reader verdict. It also
 * classifies an unreadable store's reason (`privilege` vs `io`) from the ACTUAL
 * stat/readdir errno via {@link errnoAccessReason}, so the disclosure never
 * advises a futile "re-run as root" for a genuine I/O error.
 *
 * Verdicts:
 *   - `absent`: probe absent AND migration NOT established (fresh/never-armed).
 *   - `missing`: probe absent BUT migration established (deleted/renamed -- the
 *     store was provisioned and is now gone).
 *   - `present_unreadable{reason}`: the directory exists but could not be
 *     stat'd/listed at this privilege; `reason` distinguishes a permission limit
 *     (root can read it) from an I/O error (root cannot).
 *   - `accessible`: the directory listed; the caller reads + integrity-verifies.
 */
export async function resolveDaemonStorePresence(
  storage: FilesystemStorage,
  masterKey: Uint8Array
): Promise<DaemonStorePresence> {
  const dirPath = storage.namespacePath(AUDIT_DAEMON_NAMESPACE);
  const absentOrMissing = async (): Promise<DaemonStorePresence> =>
    (await daemonMigrationEstablished(storage, masterKey))
      ? { kind: "missing" }
      : { kind: "absent" };
  let stats;
  try {
    stats = await stat(dirPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return absentOrMissing();
    // Any other stat error (e.g. EACCES on an ancestor, or an EIO): the store
    // is present-but-unreadable. Classify the reason from the errno so the
    // disclosure only advises "re-run as root" for a privilege limitation.
    return { kind: "present_unreadable", reason: errnoAccessReason(err) };
  }
  // A non-directory at the daemon path is not a provisioned chain; treat it
  // exactly like ENOENT (absent vs. destroyed-on-a-migrated-fortress).
  if (!stats.isDirectory()) return absentOrMissing();
  try {
    await readdir(dirPath);
    return { kind: "accessible" };
  } catch (err) {
    // A readdir ENOENT after a successful stat means the directory was removed
    // between the two calls (a concurrent deletion / TOCTOU): that is an
    // absent-vs-destroyed question, NOT an unreadable-store one, so re-resolve
    // against the migration marker rather than mislabeling it privilege/io.
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return absentOrMissing();
    return { kind: "present_unreadable", reason: errnoAccessReason(err) };
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

  // HIGH-R3: a valid boundary proves the migration ran and names the daemon
  // chain, so an absent daemon directory afterward is a deletion (fail closed),
  // not "never provisioned". The valid-boundary-OR-established-marker signal is
  // shared with the evidence-pack census/export chokepoint via
  // {@link daemonMigrationEstablished} (ONE definition).
  const migrationEstablished = masterKey
    ? await daemonMigrationEstablished(storage, masterKey)
    : false;

  let daemon: AuditChainReport;
  const access = await probeDaemonChainAccess(storage);
  if (access === "absent") {
    daemon = migrationEstablished
      ? {
          chain: "daemon",
          status: "missing",
          finding_count: 1,
          note:
            "the writer-split migration ran (a valid boundary / established " +
            "marker is present) and names a root daemon audit chain, but its " +
            "namespace is ABSENT (deleted or renamed). This is evidence " +
            "destruction, NOT a never-provisioned fortress.",
        }
      : {
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
