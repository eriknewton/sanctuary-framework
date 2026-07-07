/**
 * Sanctuary MCP Server -- Governed File-Grant v1 (box-local, read-only)
 *
 * Shared types for the file-grant module. See
 * Review/Sanctuary/Fleet_or_FileGrant_GovernedFileGrant_v1_Build_Spec_2026-07-07.md
 * for the full build spec. This module gives an operator a way to hand an
 * agent read access to a specific file or directory on the SAME box, with the
 * grant recorded as a first-class encrypted state object and (where the
 * dedicated agent uid exists) enforced by real POSIX ownership on a per-agent
 * grant tree.
 *
 * v1 is deliberately narrow: box-local, read-only, mint wired to the truly
 * non-relaxable Tier-1 set. The daily-driver pull surface, `request_file_access`,
 * write-mode grants, and the synced-folder option are explicitly OUT of scope
 * (see the build spec section 8).
 */

/** Schema version tag persisted on every grant record. */
export const FILE_GRANT_SCHEMA_VERSION = "1.0" as const;

/** The dedicated, reserved StateStore namespace grants are persisted under. */
export const FILE_GRANT_NAMESPACE = "_file_grants" as const;

export type FileGrantScopeKind = "file" | "dir";

/** v1 supports read-only grants. Any other value is a hard schema reject. */
export type FileGrantMode = "read";

export type FileGrantStatus = "active" | "revoked" | "expired";

export interface FileGrantScope {
  kind: FileGrantScopeKind;
  /** Absolute, canonicalized (realpath'd at mint) operator-side source path. */
  path: string;
}

/**
 * The persisted grant record (build spec section 3.1). Written to the
 * StateStore's `_file_grants` namespace as an encrypted, signed, monotonic-
 * versioned entry, so `state_read`/`state_list`/`state_export`/`state_delete`
 * reach it at the store-method level (AGENTS.md Invariant #2). Agent-facing
 * MCP tools reject reads of any `_`-prefixed namespace (the reserved-
 * namespace firewall in cognitive/tools.ts already covers `_file_grants` via
 * its catch-all), so the record is never a policy-inference oracle for the
 * agent it describes.
 */
export interface FileGrant {
  grant_id: string;
  schema_version: typeof FILE_GRANT_SCHEMA_VERSION;
  subject_agent_id: string;
  scope: FileGrantScope;
  mode: FileGrantMode;
  created_by: string;
  created_at: string;
  /** ISO 8601, or null for a standing (no-expiry) grant. See Q1. */
  expires_at: string | null;
  status: FileGrantStatus;
  revoked_at: string | null;
  /** Relative path placed under the grant tree; scrubbed on revoke/expiry. */
  tree_entry: string;
  audit_refs: string[];
}

/**
 * Erik-decision defaults (build spec section 1, Q1/Q2). Both knobs are
 * product-policy parameters, not trust-boundary decisions, and are collected
 * behind this single const so a later override is a one-line change, not a
 * refactor.
 *
 * Q1: default read-grant TTL is 24h; a no-TTL standing grant is allowed but
 *     (a) minting it is Tier-1 like every mint and (b) it renders as
 *     "standing (no expiry)" wherever a grant is listed, never invisible.
 * Q2: no hard max-TTL cap in v1. A future soft cap is a validation clamp,
 *     not a re-architecture.
 */
export const FILE_GRANT_DEFAULTS = {
  default_ttl_seconds: 24 * 60 * 60,
  allow_standing_grant: true,
  max_ttl_seconds: null as number | null,
} as const;

/**
 * Injected filesystem operations for the box-local grant tree. The real
 * implementation (`fs-ops.ts`) wires actual POSIX calls; every test in this
 * module passes a fake so the security-relevant orchestration logic in
 * `mint.ts` / `revoke.ts` is unit-tested with zero real host state.
 *
 * `place` / `removeEntry` take a RELATIVE tree-entry path (the grant's
 * `tree_entry` field); the real implementation resolves it against the
 * configured grant-tree root so the orchestration layer never needs to know
 * where that root lives on disk.
 */
export interface FsOps {
  /** Canonicalize (realpath) an operator-supplied source path. Throws if the path does not exist. */
  realpath(path: string): Promise<string>;
  /** Place (symlink) the canonical source at the given relative tree-entry path. */
  place(canonicalSrc: string, relativeTreeEntry: string): Promise<void>;
  /** Remove a tree-entry path. Idempotent: removing an absent entry is a no-op, not an error. */
  removeEntry(relativeTreeEntry: string): Promise<void>;
  /** The dedicated agent uid for `subjectAgentId`, or null if no uid-split origin is configured. */
  agentUid(subjectAgentId: string): Promise<number | null>;
  /** The operator's own uid, or null on a platform without POSIX uids. */
  operatorUid(): Promise<number | null>;
}

/** Whether POSIX ownership on the grant tree actually confines the agent uid. */
export type FileGrantEnforcement = "met" | "unmet";

/** Pure planner output (section 6): what the grant tree SHOULD contain right now. */
export interface TreePlanEntry {
  grant_id: string;
  relative_tree_entry: string;
}

export interface TreePlan {
  toPlace: TreePlanEntry[];
  toScrub: TreePlanEntry[];
}

/** Thrown when a mint is attempted with any mode other than "read" (v1 hard reject). */
export class FileGrantModeRejectedError extends Error {
  constructor(mode: string) {
    super(
      `Governed File-Grant v1 is read-only; mode "${mode}" is rejected. ` +
        `Write-mode grants are out of scope for v1 (see build spec section 8).`
    );
    this.name = "FileGrantModeRejectedError";
  }
}

/**
 * Thrown when a mint fails after the grant object was persisted (tree
 * placement threw). The caller has already rolled back the persisted object
 * before this is thrown, so no phantom grant survives (Invariant #5c).
 */
export class FileGrantMintFailedError extends Error {
  constructor(
    public readonly grantId: string,
    public readonly cause: unknown
  ) {
    super(
      `Governed File-Grant mint failed for ${grantId}: tree placement did not ` +
        `succeed. The grant record has been rolled back; no phantom grant exists. ` +
        `Cause: ${cause instanceof Error ? cause.message : String(cause)}`
    );
    this.name = "FileGrantMintFailedError";
  }
}
