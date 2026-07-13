/**
 * Governed File-Grant v1 -- mint orchestration (build spec sections 3-5).
 *
 * `mintFileGrant` turns a mint request into a persisted `FileGrant` plus a
 * box-local tree placement. Every side effect is reached through an injected
 * dependency so the fail-closed / rollback / same-uid-honesty behavior
 * (Invariant #5) is unit-testable with zero real host state. The ordering is
 * chosen so the access-conferring step (`place`) is the LAST fallible step,
 * the grant is DURABLY AUDITED before that step, and NOTHING after it can turn
 * a live grant into a reported failure:
 *
 *   1. Validate `mode === "read"` (v1 hard reject otherwise).
 *   2. Validate `subjectAgentId` is a safe slug (no path traversal) BEFORE any
 *      persistence or placement.
 *   3. Canonicalize the source path via `fsOps.realpath`.
 *   4. Read the uids and compute a conservative pre-place `enforcement`
 *      verdict with `readVerified:false` for the durable recorded audit
 *      (derived from the SOURCE-file owner, never `process.getuid()`).
 *   5. Persist the grant object (`store.put`). A throw here does NOT prove
 *      nothing persisted (`StateStore.write` commits, THEN post-commit awaits
 *      can still throw), so it rolls the record back under a GUARDED remove
 *      (tombstone on remove failure) exactly like step 6, writes a best-effort
 *      failure audit, and throws `FileGrantMintFailedError`. No phantom active
 *      grant survives a put()-throw.
 *   5b. DURABLE pre-placement audit, a DISTINCT operation
 *      `operation: "file_grant_recorded"`, `result: "success"` (round 4:
 *      reverted from the round-3 widened `result: "pending"` -- see below).
 *      Access must never be live without a preceding audit entry (Invariant
 *      #5 + audit-write-completeness), so the authoritative mint audit is
 *      written HERE, before `place`, and is NOT best-effort: if it throws,
 *      `place` has not run (no access exists), so the record is rolled back
 *      and the mint fails closed. It succeeded at RECORDING (hence
 *      `result: "success"` is honest), but it is a DIFFERENT operation than
 *      `file_grant` -- a consumer filtering `operation:"file_grant",
 *      result:"success"` must only ever count CONFIRMED-live grants (R3-1),
 *      so this pre-place record, being a distinct op, can never be mistaken
 *      for one.
 *   6. Place the tree entry (`fsOps.place`) -- the LAST fallible, access-
 *      conferring step. If it throws: scrub any partial entry, roll back the
 *      persisted record under a GUARDED remove (on remove failure persist a
 *      terminal `revoked` tombstone so no dangling `active` survives), write a
 *      best-effort `operation: "file_grant", result: "failure"` audit, and
 *      throw `FileGrantMintFailedError`. So a failed mint leaves NO active
 *      grant, NO tree entry (Invariant #5c), and NO `file_grant` audit with
 *      `result:"success"` -- only `file_grant_recorded`(success) then
 *      `file_grant`(failure).
 *   7. Once `place` has succeeded, attempt the platform ACL primitive against
 *      the canonical source path, persist the applied ACE metadata if the ACL
 *      was applied, and then run a bounded read probe as the agent uid. The
 *      final `enforcement` verdict can become `met` only from a probe that
 *      returns true in this same operation. ACL failure, unsupported platform,
 *      no privilege, probe failure, or timeout all keep the verdict at
 *      `unverified` or `unmet`.
 *   8. Access is LIVE and already durably audited (step 5b,
 *      `file_grant_recorded`/success). The only remaining step is a
 *      BEST-EFFORT post-place confirmation audit, `operation: "file_grant",
 *      result: "success"`: a throw there is swallowed, it must NEVER roll a
 *      live grant back and report failure (the fail-OPEN + false-rollback bug
 *      this ordering exists to prevent), and the grant is never left
 *      unaudited. A successful mint thus yields the `file_grant_recorded`
 *      (success) -> `file_grant`(success) sequence.
 *
 * ROUND 4 (revert of round 3's `AuditEntry.result` widening): round 3 widened
 * the SHARED `AuditEntry.result` (`operational/audit-log.ts`) from
 * `"success" | "failure"` to add a third `"pending"` value so the pre-place
 * audit could stay under the SAME `file_grant` operation name. That widening
 * fanned out to every consumer of the global `result` field -- the SIEM
 * export formatters (`audit/siem-formatter.ts`) treat any non-`"failure"`
 * result as an allowed/successful event, so a `pending` `file_grant` exported
 * as ALLOWED; the chat agent-context-cache rendered a `pending` entry as
 * "performed" (an overclaim of completion); and the posture routes' result
 * filter bucket had no honest third bucket for it. A single-value addition to
 * a globally-shared enum is a large, hard-to-fully-audit surface. This
 * revision REDUCES that surface instead: `AuditEntry.result` stays exactly
 * 2-valued everywhere, and the pre-place record uses a DISTINCT operation
 * name (`file_grant_recorded`) rather than a third result value. `result` is
 * always literally true (recording either succeeded or the mint already
 * failed closed before this point), so every consumer of `result` keeps its
 * original, already-correct 2-valued assumption; the "this is a not-yet-
 * confirmed record" signal now lives entirely in the operation NAME, which
 * every consumer already treats as an opaque string with no assumed
 * exhaustiveness. `file_grant_recorded` is never dispatched to the approval
 * gate (`ApprovalGate.evaluate`/`classifyOperation`) -- it is only ever an
 * audit-log `operation` field value produced directly via
 * `auditLog.appendCritical`, so it needs no tier wiring; the non-relaxable
 * Tier-1 wiring for the real `file_grant` mint operation
 * (`NON_RELAXABLE_FILE_GRANT_TIER1_OPERATIONS` in
 * `principal-policy/loader.ts` + `gate.ts`'s runtime mirror) is unchanged.
 *
 * The `enforcement` verdict is honest: it is `met` only when a distinct agent
 * uid's read of the granted file through the grant tree has actually been
 * verified by the same mint operation. POSIX ACL read is inode-scoped, not
 * grant-tree-path-scoped; the grant tree is the reach path in the confined
 * model. A bare uid split reports `unverified`, and a same-owner / no-uid box
 * reports `unmet`.
 */

import { randomBytes } from "node:crypto";
import type { AuditLog } from "../operational/audit-log.js";
import { computeExpiresAt, determineEnforcement } from "./lifecycle.js";
import {
  FileGrantAgentIdRejectedError,
  FileGrantModeRejectedError,
  FileGrantMintFailedError,
  FILE_GRANT_SCHEMA_VERSION,
  isSafeFileGrantAgentId,
  type FileGrantAclResult,
  type FileGrant,
  type FileGrantEnforcement,
  type FileGrantGrantedReadAce,
  type FileGrantPinnedSource,
  type FileGrantScope,
  type FsOps,
} from "./types.js";

/** Narrow store surface `mintFileGrant` needs; `FileGrantStore` satisfies it. */
export interface FileGrantRecordStore {
  put(grant: FileGrant): Promise<void>;
  remove(grantId: string): Promise<void>;
}

export interface MintFileGrantParams {
  subjectAgentId: string;
  scope: FileGrantScope;
  /** Accepts a bare string so a caller-supplied "write" surfaces the typed reject rather than a type error. */
  mode: string;
  /** Seconds, or null for a standing (no-expiry) grant. */
  ttlSeconds: number | null;
  createdBy: string;
}

export interface MintFileGrantDeps {
  fsOps: FsOps;
  store: FileGrantRecordStore;
  /** Injected clock reading. Never `new Date()` inside this module. */
  now: Date;
  auditLog?: AuditLog;
}

export interface MintFileGrantResult {
  grant: FileGrant;
  enforcement: FileGrantEnforcement;
}

/** "fg_" + 16 hex characters, matching the build spec's grant_id shape. */
export function generateFileGrantId(): string {
  return `fg_${randomBytes(8).toString("hex")}`;
}

export async function mintFileGrant(
  params: MintFileGrantParams,
  deps: MintFileGrantDeps
): Promise<MintFileGrantResult> {
  // Step 1 + 2: reject before ANY persistence or placement.
  if (params.mode !== "read") {
    throw new FileGrantModeRejectedError(params.mode);
  }
  if (!isSafeFileGrantAgentId(params.subjectAgentId)) {
    throw new FileGrantAgentIdRejectedError(params.subjectAgentId);
  }

  // Step 3: canonicalize the source path (throws if it does not exist; no
  // state has been persisted yet, so the throw simply fails the mint closed).
  const canonicalPath = await deps.fsOps.realpath(params.scope.path);
  const pinnedSource = await deps.fsOps.pinSource(canonicalPath);
  try {
    return await mintFileGrantWithPinnedSource(params, deps, canonicalPath, pinnedSource);
  } finally {
    await pinnedSource.close();
  }
}

async function mintFileGrantWithPinnedSource(
  params: MintFileGrantParams,
  deps: MintFileGrantDeps,
  canonicalPath: string,
  pinnedSource: FileGrantPinnedSource
): Promise<MintFileGrantResult> {
  const grantId = generateFileGrantId();
  const treeEntry = `${params.subjectAgentId}/${grantId}`;
  const expiresAt = computeExpiresAt(params.ttlSeconds, deps.now);

  // Step 4: resolve the uids and compute the conservative enforcement verdict BEFORE
  // placement. The same-uid check compares the agent uid against the SOURCE
  // file's owner (never `process.getuid()`), so a `sudo` mint cannot fabricate
  // a false "enforced". The final verdict is recomputed after placement from
  // a same-operation agent-uid readability probe.
  const agentUid = await deps.fsOps.agentUid(params.subjectAgentId);
  const sourceOwnerUid = pinnedSource.source_owner_uid;
  const recordedEnforcement: FileGrantEnforcement = determineEnforcement({
    agentUid,
    sourceOwnerUid,
    readVerified: false,
  });

  let grant: FileGrant = {
    grant_id: grantId,
    schema_version: FILE_GRANT_SCHEMA_VERSION,
    subject_agent_id: params.subjectAgentId,
    scope: { kind: params.scope.kind, path: canonicalPath },
    mode: "read",
    created_by: params.createdBy,
    created_at: deps.now.toISOString(),
    expires_at: expiresAt,
    status: "active",
    revoked_at: null,
    tree_entry: treeEntry,
    granted_read_ace: null,
    audit_refs: [],
  };

  // Step 5: persist the record. A throw here does NOT prove nothing persisted:
  // `StateStore.write` durably commits and THEN post-commit awaits (writer-key
  // memo, version observe, rename->fsyncDir) can still throw, so a put() that
  // throws-AFTER-commit would otherwise leave a phantom `active` record (the
  // `persist-throw-does-not-prove-noncommit` hazard). Roll the record back
  // under the SAME guarded remove as the placement-failure path so no phantom
  // active grant survives, then fail closed. (R2-1.)
  try {
    await deps.store.put(grant);
  } catch (putErr) {
    await rollbackGrantRecord(deps.store, grant, deps.now);
    await bestEffortAudit(deps.auditLog, {
      identity_id: params.createdBy,
      result: "failure",
      details: {
        grant_id: grantId,
        subject_agent_id: params.subjectAgentId,
        reason: "record_persist_failed",
      },
    });
    throw new FileGrantMintFailedError(grantId, putErr);
  }

  // Step 5b: DURABLE audit of the mint BEFORE access is conferred. The
  // invariant (Invariant #5 + audit-write-completeness): access must never be
  // live without a preceding audit entry for the grant. The authoritative mint
  // audit is written here, before `place`, and is NOT best-effort -- if the
  // critical append throws, `place` has not run so NO access exists: roll the
  // record back and fail closed. (R2-3.)
  try {
    await durableMintAudit(deps.auditLog, {
      identity_id: params.createdBy,
      details: {
        grant_id: grantId,
        subject_agent_id: params.subjectAgentId,
        scope_kind: params.scope.kind,
        expires_at: expiresAt,
        enforcement: recordedEnforcement,
        phase: "recorded",
      },
    });
  } catch (auditErr) {
    await rollbackGrantRecord(deps.store, grant, deps.now);
    await bestEffortAudit(deps.auditLog, {
      identity_id: params.createdBy,
      result: "failure",
      details: {
        grant_id: grantId,
        subject_agent_id: params.subjectAgentId,
        reason: "pre_placement_audit_failed",
      },
    });
    throw new FileGrantMintFailedError(grantId, auditErr);
  }

  // Step 6: place the tree entry -- the LAST fallible, access-conferring step.
  try {
    await deps.fsOps.place(canonicalPath, treeEntry);
  } catch (placeErr) {
    // Scrub any partial entry `place` may have created, then roll the record
    // back under a GUARDED remove so a failed mint leaves NO active grant AND
    // NO tree entry (Invariant #5c). Access is NOT live here (place threw), so
    // failing closed is honest. None of the cleanup steps may suppress the
    // `FileGrantMintFailedError` the caller must see.
    try {
      await deps.fsOps.removeEntry(treeEntry);
    } catch {
      // Best-effort: the record rollback below is what makes the grant dead;
      // a lingering tree entry with no active record confers access to nobody
      // the planner will re-place, and a later reconcile/revoke scrubs it.
    }
    await rollbackGrantRecord(deps.store, grant, deps.now);
    await bestEffortAudit(deps.auditLog, {
      identity_id: params.createdBy,
      result: "failure",
      details: {
        grant_id: grantId,
        subject_agent_id: params.subjectAgentId,
        reason: "tree_placement_failed",
      },
    });
    throw new FileGrantMintFailedError(grantId, placeErr);
  }

  const verification = await verifyAgentReadThisOperation({
    fsOps: deps.fsOps,
    treeEntry,
    pinnedSource,
    agentUid,
    sourceOwnerUid,
  });
  if (verification.grantedReadAce) {
    const grantWithAce: FileGrant = {
      ...grant,
      granted_read_ace: verification.grantedReadAce,
    };
    try {
      await deps.store.put(grantWithAce);
      grant = grantWithAce;
    } catch (acePersistErr) {
      try {
        await deps.fsOps.removeEntry(treeEntry, {
          grantedReadAce: verification.grantedReadAce,
        });
      } catch {
        // Best-effort rollback of live access. The revoked tombstone below
        // retains the persisted ACE when storage is still writable.
      }
      await persistRevokedGrantTombstone(deps.store, grantWithAce, deps.now);
      await bestEffortAudit(deps.auditLog, {
        identity_id: params.createdBy,
        result: "failure",
        details: {
          grant_id: grantId,
          subject_agent_id: params.subjectAgentId,
          reason: "granted_read_ace_persist_failed",
        },
      });
      throw new FileGrantMintFailedError(grantId, acePersistErr);
    }
  }
  const enforcement: FileGrantEnforcement = determineEnforcement({
    agentUid,
    sourceOwnerUid,
    readVerified: verification.readVerified,
  });

  // Step 7: access is LIVE and already durably audited (step 5b). This
  // post-place confirmation is BEST-EFFORT: a throw here (e.g. audit-log
  // ENOSPC/EACCES) must NEVER roll back a live grant and report failure -- that
  // would be the fail-OPEN + false-rollback bug -- and the grant is never left
  // unaudited because step 5b already recorded it.
  await bestEffortAudit(deps.auditLog, {
    identity_id: params.createdBy,
    result: "success",
    details: {
      grant_id: grantId,
      subject_agent_id: params.subjectAgentId,
      scope_kind: params.scope.kind,
      expires_at: expiresAt,
      enforcement,
      acl_result: verification.aclResult?.status ?? "not_attempted",
      ...(verification.aclResult?.reason ? { acl_reason: verification.aclResult.reason } : {}),
      phase: "placed",
    },
  });

  return { grant, enforcement };
}

async function verifyAgentReadThisOperation(params: {
  fsOps: FsOps;
  treeEntry: string;
  pinnedSource: FileGrantPinnedSource;
  agentUid: number | null;
  sourceOwnerUid: number | null;
}): Promise<{
  readVerified: boolean;
  aclResult?: FileGrantAclResult;
  grantedReadAce?: FileGrantGrantedReadAce;
}> {
  const { fsOps, treeEntry, pinnedSource, agentUid, sourceOwnerUid } = params;
  if (agentUid === null || sourceOwnerUid === null) return { readVerified: false };
  if (agentUid === sourceOwnerUid) return { readVerified: false };

  let aclResult: FileGrantAclResult;
  try {
    aclResult = await fsOps.grantAgentRead(treeEntry, agentUid, pinnedSource);
  } catch {
    return { readVerified: false };
  }
  if (aclResult.status !== "applied") {
    return { readVerified: false, aclResult };
  }
  const grantedReadAce =
    aclResult.grantedReadAce ??
    ({
      agent_uid: agentUid,
      platform: aclResult.platform,
      source_realpath: pinnedSource.source_realpath,
      source_dev: pinnedSource.source_dev,
      source_ino: pinnedSource.source_ino,
    } satisfies FileGrantGrantedReadAce);

  try {
    return {
      readVerified: (await fsOps.probeAgentRead(treeEntry, agentUid, pinnedSource)) === true,
      aclResult,
      grantedReadAce,
    };
  } catch {
    return { readVerified: false, aclResult, grantedReadAce };
  }
}

/**
 * Roll the persisted grant record back after a failed mint, under a GUARDED
 * remove: attempt `store.remove`; if the delete itself throws (or the record
 * was never durably written), persist a terminal `revoked` tombstone so no
 * dangling `active` record is ever listable after a failed mint (Invariant
 * #5c). Best-effort throughout: if the store is unavailable for BOTH delete
 * and write there is nothing more to persist -- the failure audit + thrown
 * `FileGrantMintFailedError` still surface the problem to the caller. Shared by
 * the put()-throw path (step 5), the pre-placement audit path (step 5b), and
 * the placement-failure path (step 6).
 */
async function rollbackGrantRecord(
  store: FileGrantRecordStore,
  grant: FileGrant,
  now: Date
): Promise<void> {
  try {
    await store.remove(grant.grant_id);
  } catch {
    try {
      await store.put({
        ...grant,
        status: "revoked",
        revoked_at: now.toISOString(),
      });
    } catch {
      // Store unavailable for both delete and write; nothing more to persist.
    }
  }
}

/**
 * After a source-inode ACL has been applied, cleanup metadata matters more
 * than deleting the record. Prefer a terminal revoked tombstone that retains
 * `granted_read_ace`, so a later revoke or reconcile can retry ACL removal if
 * this mint fails after the ACL step.
 */
async function persistRevokedGrantTombstone(
  store: FileGrantRecordStore,
  grant: FileGrant,
  now: Date
): Promise<void> {
  try {
    await store.put({
      ...grant,
      status: "revoked",
      revoked_at: now.toISOString(),
    });
  } catch {
    // Store unavailable; the caller still reports mint failure and has already
    // attempted best-effort live-access cleanup.
  }
}

/**
 * Append the DURABLE pre-placement mint audit. Unlike `bestEffortAudit`, a
 * throw here PROPAGATES so mint (step 5b) can roll back and fail closed --
 * access is never conferred without this audit having been written. A missing
 * `auditLog` (unit tests with no audit wiring) is a no-op.
 *
 * `operation` is the DISTINCT `"file_grant_recorded"` -- NOT `"file_grant"` --
 * with `result: "success"` (round 4: reverted from a `"file_grant"`/`"pending"`
 * entry; see the module doc comment for why a distinct operation name, not a
 * third shared `result` value, is the correct fix). `result: "success"` is
 * honest here: recording the grant durably DID succeed (that is precisely
 * what this append proves by not throwing). What has NOT yet happened is
 * `place()` -- access is not yet live. Using a distinct operation name keeps
 * that distinction legible without touching the shared, 2-valued
 * `AuditEntry.result` type: only the POST-place confirmation (step 7) ever
 * writes `operation: "file_grant", result: "success"`, so a consumer
 * filtering `operation:"file_grant", result:"success"` counts only
 * CONFIRMED-live grants (R3-1), and a consumer that has never heard of
 * `file_grant_recorded` simply does not match it -- no fanout, no third enum
 * value to special-case.
 */
async function durableMintAudit(
  auditLog: AuditLog | undefined,
  entry: { identity_id: string; details: Record<string, unknown> }
): Promise<void> {
  if (!auditLog) return;
  await auditLog.appendCritical({
    layer: "l1",
    operation: "file_grant_recorded",
    identity_id: entry.identity_id,
    result: "success",
    details: entry.details,
  });
}

/**
 * Append a `file_grant` audit entry, swallowing any error. Used for the
 * post-placement success audit (a throw must not roll back a live grant) and
 * for the rollback-path failure audit (a throw must not suppress the
 * `FileGrantMintFailedError` the caller needs to see).
 */
async function bestEffortAudit(
  auditLog: AuditLog | undefined,
  entry: {
    identity_id: string;
    result: "success" | "failure";
    details: Record<string, unknown>;
  }
): Promise<void> {
  try {
    await auditLog?.appendCritical({
      layer: "l1",
      operation: "file_grant",
      identity_id: entry.identity_id,
      result: entry.result,
      details: entry.details,
    });
  } catch {
    // Best-effort audit only; the caller's success/failure outcome stands.
  }
}
