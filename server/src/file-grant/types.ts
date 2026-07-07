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
 * StateStore's `_file_grants` namespace through the SAME encrypted, signed,
 * monotonic-versioned machinery every other piece of Sanctuary state uses.
 *
 * Operator-facing inspect / delete story (AGENTS.md Invariant #2): the
 * operator inspects grants with `sanctuary file-grant list`, ends access with
 * `sanctuary file-grant revoke` (marks the record revoked, scrubs the tree
 * entry, audits), and can read/delete the underlying record directly through
 * the StateStore methods (`store.read`/`store.list`/`store.delete` on the
 * `_file_grants` namespace). The record is NOT reachable through the
 * agent-facing `state_read`/`state_list`/`state_export`/`state_delete` MCP
 * tools: those correctly REJECT any `_`-prefixed namespace via the
 * reserved-namespace firewall in cognitive/tools.ts (same posture as `_audit`
 * and `_identities`), so a grant, which describes exactly what an agent may
 * read, is never a policy-inference oracle for the agent it describes.
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
  /**
   * The uid that OWNS the canonical source file/dir (from `stat`), or null on
   * a platform without POSIX uids. The same-uid honesty check is derived from
   * the source owner, NEVER from `process.getuid()`: running the mint under
   * `sudo` must not let a same-uid box (agent uid == the file's owner) print a
   * false "enforced" -- the boundary that matters is "can the agent uid read
   * the operator's file", which is a property of the FILE's ownership, not of
   * the minting process's effective uid.
   */
  sourceOwnerUid(canonicalPath: string): Promise<number | null>;
}

/**
 * Whether the box-local read-scope boundary is actually enforced for a grant.
 *
 * - `met`       the agent uid is distinct from the source-file owner AND an
 *               agent-uid readability probe has CONFIRMED the placed entry is
 *               readable by that uid (the real primitive applied and was
 *               verified). Only produced on a real dedicated-uid host with the
 *               privilege to apply + verify the primitive; v1's autonomous /
 *               CI path never fabricates it.
 * - `unverified` a real boundary exists (dedicated agent uid, distinct from
 *               the source owner) but on-hardware read-scope has NOT been
 *               verified. v1 records the grant and places the tree entry; the
 *               functional cross-uid read primitive (POSIX ACL / ownership)
 *               and its readability verification are the separate Erik-present
 *               acceptance drill (build spec section 8). This is the honest
 *               "configured, on-hardware read-scope not yet verified" label --
 *               v1 must NEVER upgrade it to "met" from a uid-split alone.
 * - `unmet`     no dedicated agent uid is configured, or the agent uid equals
 *               the source-file owner (the agent already owns / can read the
 *               source, so there is no boundary to enforce). Nothing is
 *               enforced and v1 says so.
 */
export type FileGrantEnforcement = "met" | "unverified" | "unmet";

/** Pure planner output (section 6): what the grant tree SHOULD contain right now. */
export interface TreePlanEntry {
  grant_id: string;
  relative_tree_entry: string;
}

export interface TreePlan {
  toPlace: TreePlanEntry[];
  toScrub: TreePlanEntry[];
}

/**
 * A `subject_agent_id` is used as a single path segment under the grant-tree
 * root (`tree_entry = "<agentId>/<grantId>"`), so it MUST be a safe slug: a
 * hostile `--agent ../../../../tmp/x` must not escape the root. Accept only a
 * conservative slug (letters, digits, `_`, `-`, `.`), and additionally reject
 * any value that could traverse or hide: a `..` sequence, a leading `.`
 * (dotfile / `.`/`..`), a path separator, or the empty string. Directory
 * containment is ALSO re-checked at the filesystem layer (`place` /
 * `removeEntry` resolve-and-verify under the root); this is defence in depth,
 * not the only guard.
 */
export function isSafeFileGrantAgentId(agentId: string): boolean {
  if (typeof agentId !== "string" || agentId.length === 0) return false;
  if (agentId.length > 128) return false;
  if (agentId.startsWith(".")) return false;
  if (agentId.includes("..")) return false;
  if (agentId.includes("/") || agentId.includes("\\")) return false;
  return /^[A-Za-z0-9._-]+$/.test(agentId);
}

/** Thrown when a mint is attempted with an unsafe (path-traversing) subject agent id. */
export class FileGrantAgentIdRejectedError extends Error {
  constructor(agentId: string) {
    super(
      `Governed File-Grant: subject agent id "${agentId}" is not a safe slug. ` +
        `An agent id must be non-empty letters/digits/[._-] with no path ` +
        `separators, no "..", and no leading dot (it is used as a grant-tree ` +
        `path segment and must not escape the tree root).`
    );
    this.name = "FileGrantAgentIdRejectedError";
  }
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
