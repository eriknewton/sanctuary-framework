/**
 * Governed File-Grant v1 -- public module surface.
 *
 * Consumers (the CLI, and any future MCP tool wiring) import from this
 * barrel rather than reaching into individual files, per the repo's barrel
 * convention (see server/src/README.md).
 */

export {
  FILE_GRANT_SCHEMA_VERSION,
  FILE_GRANT_NAMESPACE,
  FILE_GRANT_DEFAULTS,
  FileGrantModeRejectedError,
  FileGrantMintFailedError,
} from "./types.js";
export type {
  FileGrant,
  FileGrantScope,
  FileGrantScopeKind,
  FileGrantMode,
  FileGrantStatus,
  FileGrantEnforcement,
  FsOps,
  TreePlan,
  TreePlanEntry,
} from "./types.js";

export { planGrantTree } from "./planner.js";

export {
  parseFileGrantTtlDuration,
  computeExpiresAt,
  isGrantExpired,
  projectGrantStatus,
  reviseGrantForRevoke,
  reviseGrantForExpiry,
} from "./lifecycle.js";

export { FileGrantStore } from "./store.js";
export type { FileGrantWriteIdentity } from "./store.js";

export { mintFileGrant, generateFileGrantId } from "./mint.js";
export type {
  MintFileGrantParams,
  MintFileGrantDeps,
  MintFileGrantResult,
  FileGrantRecordStore,
} from "./mint.js";

export { revokeFileGrant } from "./revoke.js";
export type {
  RevokeFileGrantDeps,
  RevokeFileGrantResult,
  FileGrantRevokeStore,
} from "./revoke.js";

export { listFileGrants } from "./list.js";
export type { FileGrantListStore, ProjectedFileGrant } from "./list.js";

export { PosixFileGrantFsOps } from "./fs-ops.js";
