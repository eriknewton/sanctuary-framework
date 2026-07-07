/**
 * Governed File-Grant v1 -- mint orchestration (build spec sections 3-5).
 *
 * `mintFileGrant` is the ONE function that turns a mint request into a
 * persisted `FileGrant` plus (best-effort, POSIX-enforced) tree placement.
 * Every side effect is reached through an injected dependency so the
 * fail-closed / rollback / same-uid-honesty behavior (Invariant #5) is
 * unit-testable with zero real host state:
 *
 *   1. Validate `mode === "read"` (v1 hard reject otherwise).
 *   2. Canonicalize the source path via `fsOps.realpath`.
 *   3. Persist the grant object FIRST (`store.put`).
 *   4. Place the tree entry SECOND (`fsOps.place`).
 *   5. If placement throws, ROLL BACK the persisted object (`store.remove`)
 *      before rethrowing, so a "phantom" grant (object exists, no tree
 *      entry, or vice versa) never survives a failed mint.
 *   6. Report `enforcement: "unmet"` (never claim "governed") when the
 *      agent uid is unknown or equals the operator's own uid -- a same-uid
 *      box has no POSIX isolation to enforce with.
 *
 * Every mint (success or rolled-back failure) appends an audit entry.
 */

import { randomBytes } from "node:crypto";
import type { AuditLog } from "../operational/audit-log.js";
import { computeExpiresAt } from "./lifecycle.js";
import {
  FileGrantModeRejectedError,
  FileGrantMintFailedError,
  FILE_GRANT_SCHEMA_VERSION,
  type FileGrant,
  type FileGrantEnforcement,
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
  if (params.mode !== "read") {
    throw new FileGrantModeRejectedError(params.mode);
  }

  const canonicalPath = await deps.fsOps.realpath(params.scope.path);
  const grantId = generateFileGrantId();
  const treeEntry = `${params.subjectAgentId}/${grantId}`;
  const expiresAt = computeExpiresAt(params.ttlSeconds, deps.now);

  const grant: FileGrant = {
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
    audit_refs: [],
  };

  // Persist first, place second: if placement fails the persisted object is
  // rolled back so no phantom grant (record with no tree entry) survives.
  await deps.store.put(grant);

  try {
    await deps.fsOps.place(canonicalPath, treeEntry);
  } catch (placeErr) {
    await deps.store.remove(grantId);
    await deps.auditLog?.appendCritical({
      layer: "l1",
      operation: "file_grant",
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

  const agentUid = await deps.fsOps.agentUid(params.subjectAgentId);
  const operatorUid = await deps.fsOps.operatorUid();
  const enforcement: FileGrantEnforcement =
    agentUid !== null && operatorUid !== null && agentUid !== operatorUid
      ? "met"
      : "unmet";

  await deps.auditLog?.appendCritical({
    layer: "l1",
    operation: "file_grant",
    identity_id: params.createdBy,
    result: "success",
    details: {
      grant_id: grantId,
      subject_agent_id: params.subjectAgentId,
      scope_kind: params.scope.kind,
      expires_at: expiresAt,
      enforcement,
    },
  });

  return { grant, enforcement };
}
