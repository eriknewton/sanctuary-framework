/**
 * Auto-provision Step 2 (Build 1): agent re-home adapter interface + Hermes
 * v1 adapter.
 *
 * Re-homing moves an agent's config/keys/file-based tokens from wherever
 * they live today (typically under the operator's own home directory) onto
 * the newly-provisioned dedicated account's home, so the harness daemon
 * (egress-gate/harness-daemon.ts) can start the agent as that uid and find
 * its secrets there.
 *
 * `AgentRehomeAdapter` is deliberately per-harness: the config/secret layout
 * differs (Hermes keeps everything in 0600 files; Claude Code / other
 * harnesses may differ and get their own adapter later, per the ratified
 * scope doc's D2 finding). v1 ships ONLY the Hermes adapter.
 *
 * FIX M4 (folded from the adversarial review): the pre-re-home secrets
 * BACKUP must be root-only (0600) and never an operator-readable plaintext
 * copy sitting somewhere the operator's own login session could read
 * (AGENTS.md invariant #6 -- never expose private keys/secrets outside
 * their proper custody). `planRehome`'s backup step always specifies mode
 * 0600 and a path under the new account's own home (or a root-owned staging
 * dir), never a world- or operator-readable location; `RehomeOps.backup`'s
 * production implementation is responsible for enforcing that mode at write
 * time and, per the scope doc, encrypting the backup or placing it in a
 * dedicated keychain rather than a bare plaintext copy.
 *
 * Grounded in the live Mini2 finding (D2 RESOLVED 2026-07-06): Hermes
 * secrets are FILE-BASED, not login-keychain-bound. Google OAuth refresh
 * tokens are file-portable and survive the move; the MCP scope is
 * `calendar:readonly`, so no calendar-write re-consent is needed today.
 */

/** A single file-tree the re-home must move (source -> new-home-relative destination). */
export interface RehomePathEntry {
  /** Absolute source path under the CURRENT (operator) home. */
  sourcePath: string;
  /** Path relative to the new account's home directory. */
  destRelativePath: string;
  /**
   * Inventory tier. Existing entries are Tier K (keys/config). Tier M (mind)
   * entries are moved only by the journaled copy-verify-swap executor below.
   */
  tier?: "keys" | "mind";
  /** Stable inventory-relative path. Required for Tier M journal/result rows. */
  relPath?: string;
  /** Declared filesystem kind. Required for Tier M; optional for legacy Tier K. */
  kind?: "file" | "dir";
  /** Whether absence is a non-green brain outcome. Required for Tier M. */
  required?: boolean;
  /** Whether this is a secret (drives backup mode / encryption requirements). */
  isSecret: boolean;
  /** Large objects use staging/copy verification and are named in crash tests. */
  largeObject?: boolean;
  /** True for the SQLite state.db family entry. */
  stateDbFamily?: boolean;
}

export interface BrainRehomePathEntry extends RehomePathEntry {
  tier: "mind";
  relPath: string;
  kind: "file" | "dir";
  required: boolean;
  isSecret: boolean;
  largeObject: boolean;
}

/** Content hash for conflict diagnostics and destination provenance. */
export interface RehomePathHash {
  algorithm: "sha256";
  value: string;
}

/** Root-owned proof that Sanctuary previously moved this source to this destination. */
export interface RehomeDestinationProvenance {
  schemaVersion: 1 | 2;
  sourcePath: string;
  destPath: string;
  destHash: RehomePathHash;
  recordedAt: string;
  /** v2: stable id for the Sanctuary run that placed this destination. */
  placingRunId?: string;
  /** v2: placement-time hash, repeated explicitly for divergence-matrix reads. */
  placementHash?: RehomePathHash;
}

/** Result of a recursive ownership change; excluded paths are reported, never silent. */
export interface RehomeChownReport {
  excludedPaths: string[];
}

/** Per-harness adapter: describes what to move and how to verify the move. */
export interface AgentRehomeAdapter {
  /** Harness identifier, e.g. "hermes". */
  readonly harnessId: string;
  /**
   * Enumerate the file trees this harness needs re-homed. Pure: given the
   * operator's home dir, returns the list of paths to move. Does not touch
   * the filesystem itself (existence-checking happens in `planRehome`).
   */
  pathsToRehome(operatorHome: string): RehomePathEntry[];
  /**
   * Tier M operating-mind inventory. Separate from {@link pathsToRehome} so
   * the existing key/config move cannot accidentally apply rename semantics to
   * live brain state.
   */
  brainPathsToRehome?(operatorHome: string): BrainRehomePathEntry[];
  /**
   * Whether this harness has ANY re-consent step that only a human can drive
   * (e.g. an OAuth scope upgrade the platform forces on account change).
   * Hermes v1: always false (Google refresh tokens are file-portable and the
   * MCP scope is calendar:readonly, so no re-consent is forced today).
   */
  requiresInteractiveReconsent(): boolean;
}

/** Operations injected so re-home planning/execution is unit-testable without touching the host. */
export interface RehomeOps {
  /** True when `path` exists (file or directory). */
  pathExists(path: string): Promise<boolean>;
  /** True when the final path component exists, without following symlinks. */
  pathExistsNoFollow(path: string): Promise<boolean>;
  /** Compute a no-follow content hash for a file, symlink, or directory tree. */
  hashPath(path: string): Promise<RehomePathHash>;
  /** Read root-owned provenance for an already-rehomed destination, if present and parseable. */
  readDestinationProvenance(sourcePath: string, destPath: string): Promise<RehomeDestinationProvenance | undefined>;
  /** Record root-owned provenance after a successful move to the destination. */
  recordDestinationProvenance(
    sourcePath: string,
    destPath: string,
    record?: { placingRunId?: string; destHash?: RehomePathHash; recordedAt?: string },
  ): Promise<void>;
  /** Clear provenance when rollback removes the moved destination. */
  clearDestinationProvenance(sourcePath: string, destPath: string): Promise<void>;
  /** Preserve an occupied destination as a dated sibling before an explicit overwrite. */
  displaceDestination(destPath: string): Promise<{ displacedPath: string }>;
  /** Restore a previously displaced destination, without overwriting a new occupant. */
  restoreDisplacedDestination(
    displacedPath: string,
    destPath: string,
  ): Promise<{ restored: boolean; conflictPath?: string }>;
  /**
   * Copy the file tree at `path` into a root-only (0600 file / 0700 dir),
   * reversible backup location, returning the backup's path. Production
   * implementations MUST write in a way that is never operator-readable
   * plaintext (fix M4): root-only permissions plus encryption or a
   * dedicated keychain entry, never a bare copy under a world- or
   * operator-readable directory. FIX F2 (2026-07-07 fix-round): this MUST
   * be a real recursive copy for a directory-shaped path (mode 0700 on the
   * directory), not an empty placeholder dir -- the custody copy is only a
   * genuine backup if it actually contains the data.
   */
  backup(path: string): Promise<{ backupPath: string }>;
  /** Remove an already-backed-up duplicate source after a provenance-backed destination is authoritative. */
  removeSourceDuplicate(path: string): Promise<void>;
  /**
   * Restore a removed source duplicate from its recorded backup without
   * touching the authoritative destination. If the source path has been
   * recreated, restore to a conflict path and report it.
   */
  restoreSourceDuplicate(
    backupPath: string,
    sourcePath: string,
  ): Promise<{ restored: boolean; conflictPath?: string }>;
  /** Move (not copy) the file tree from `sourcePath` to `destPath`, creating parent dirs as needed. */
  move(sourcePath: string, destPath: string): Promise<void>;
  /** chown the path (recursively, if a directory) to the given uid/gid. */
  chown(path: string, uid: number, gid: number): Promise<RehomeChownReport>;
  /**
   * Restore a path back to `sourcePath` (used by `unprovision` and by the
   * orchestrator's fail-closed abort path). FIX F2 (2026-07-07 fix-round):
   * production implementations MUST prefer a REVERSE-MOVE of `destPath`
   * (the path the data actually lives at post-move -- `move` used `rename`,
   * so the data is intact there) back to `sourcePath`; the `backupPath` is
   * the M4 custody copy, used only when `destPath` itself is gone. This is
   * correct for files AND directories, closing the prior defect where a
   * directory-shaped secret's restore silently produced an empty directory.
   * Returns whether the restore actually reproduced the data at
   * `sourcePath`, so callers never report a false "rolled back" on a
   * restore that quietly no-op'd or partially failed.
   *
   * FIX R6 (HIGH, 2026-07-07 fix-round 2): if `sourcePath` was RECREATED
   * (by the operator or some other process) while the secret was re-homed,
   * production implementations MUST NOT silently overwrite it -- they must
   * restore the moved data to a conflict path instead and return
   * `conflictPath` (with `restored: false`), so the caller reports a
   * manual-recovery outcome rather than a false clean restore.
   */
  restore(
    destPath: string,
    sourcePath: string,
    backupPath?: string,
  ): Promise<{ restored: boolean; conflictPath?: string }>;
  /**
   * Restore custody of a recovered secret path to the operator (fix F3):
   * chmod 0600 (file) / 0700 (dir) and chown back to the operator's uid/gid.
   * Called for `isSecret` entries after a successful restore (on the restored
   * `sourcePath`) AND, per fix (round 5, item N6), on the CONFLICT branch (on
   * the `conflictPath`, since the recovered data was reverse-moved from the
   * agent-owned re-home destination and would otherwise be left unreadable by
   * the operator it is being handed back to).
   */
  restoreCustody(path: string, operatorUid: number, operatorGid: number): Promise<void>;
}

/** A single planned move, with its backup companion. */
export interface RehomeStep {
  entry: RehomePathEntry;
  destPath: string;
}

/** The full re-home plan. Pure: no I/O performed while building it. */
export interface RehomePlan {
  harnessId: string;
  steps: RehomeStep[];
  requiresInteractiveReconsent: boolean;
}

/**
 * Build the re-home plan for an adapter. Pure: joins operator-home paths to
 * the new account's home, but performs no filesystem I/O. Existence
 * filtering (skip paths that do not exist on this host) happens in
 * {@link executeRehomePlan}, which DOES need to touch the filesystem.
 */
export function planRehome(
  adapter: AgentRehomeAdapter,
  options: { operatorHome: string; newAccountHome: string },
): RehomePlan {
  const entries = adapter.pathsToRehome(options.operatorHome);
  const steps: RehomeStep[] = entries.map((entry) => ({
    entry,
    destPath: joinPosix(options.newAccountHome, entry.destRelativePath),
  }));
  return {
    harnessId: adapter.harnessId,
    steps,
    requiresInteractiveReconsent: adapter.requiresInteractiveReconsent(),
  };
}

/** Minimal POSIX path join (avoids importing node:path into this pure-planning surface's type signatures; execution below uses the real one). */
function joinPosix(base: string, rel: string): string {
  const trimmedBase = base.endsWith("/") ? base.slice(0, -1) : base;
  const trimmedRel = rel.startsWith("/") ? rel.slice(1) : rel;
  return `${trimmedBase}/${trimmedRel}`;
}

/** Record of one executed (or skipped) re-home step, for reporting + reversal. */
export interface RehomeStepResult {
  entry: RehomePathEntry;
  destPath: string;
  status:
    | "moved"
    | "skipped-absent"
    | "destination-authoritative"
    | "destination-displaced";
  backupPath?: string;
  displacedDestinationPath?: string;
  sourceDuplicateRemoved?: boolean;
  sourceHash?: RehomePathHash;
  destinationHash?: RehomePathHash;
  chownExcludedPaths?: string[];
}

/**
 * FIX R3 (HIGH, 2026-07-07 fix-round 2): thrown by {@link executeRehomePlan}
 * when a step fails mid-loop, carrying the results ALREADY accumulated for
 * every step that completed before the failing one. Before this fix, a
 * mid-loop throw (e.g. `chown` failing on path 3 of 6) discarded the
 * already-moved entries' results entirely -- the function's local `results`
 * array simply never returned. The orchestrator's rehome-abort branch then
 * had an empty `rehomeResults`, so `safeRestore` had nothing to restore and
 * the already-moved secrets (backed up, but now sitting at `destPath` under
 * the not-yet-armed new account) were left with no recorded backup path for
 * the operator to recover from. `partialResults` closes that gap: the
 * orchestrator (via its caller) can now `safeRestore` exactly what actually
 * moved, not an empty array.
 */
export class RehomeExecutionError extends Error {
  readonly partialResults: RehomeStepResult[];
  constructor(message: string, partialResults: RehomeStepResult[], options?: { cause?: unknown }) {
    super(message, options);
    this.name = "RehomeExecutionError";
    this.partialResults = partialResults;
  }
}

export interface ExecuteRehomePlanOptions {
  /** Explicit operator override for dual source+destination presence. */
  overwriteDestination?: boolean;
}

export interface BrainRehomeStep {
  entry: BrainRehomePathEntry;
  destPath: string;
}

export interface BrainRehomePlan {
  harnessId: string;
  steps: BrainRehomeStep[];
}

export type BrainRehomeStepStatus =
  | "moved"
  | "skipped-absent";

export interface BrainRehomeStepResult {
  entry: BrainRehomePathEntry;
  destPath: string;
  status: BrainRehomeStepStatus;
  backupPath?: string;
  sourceHash?: RehomePathHash;
  destinationHash?: RehomePathHash;
  placementRunId?: string;
}

export interface BrainRehomeSummary {
  status: "complete" | "partial";
  results: BrainRehomeStepResult[];
  stranded: string[];
}

export type BrainRehomeJournalItemState = "pending" | "staged" | "swapping" | "swapped" | "backed-up";

export interface BrainRehomeJournalItem {
  relPath: string;
  sourcePath: string;
  destPath: string;
  stagingPath: string;
  kind: BrainRehomePathEntry["kind"];
  required: boolean;
  isSecret: boolean;
  largeObject: boolean;
  stateDbFamily: boolean;
  state: BrainRehomeJournalItemState;
  backupPath?: string;
}

export interface BrainRehomeJournal {
  schemaVersion: 1;
  harnessId: string;
  runId: string;
  createdAt: string;
  items: BrainRehomeJournalItem[];
  /** Operator-facing path to inspect when a prior journal blocks fresh work. */
  journalPath?: string;
}

export interface BrainRehomeOps extends RehomeOps {
  readBrainJournal(): Promise<BrainRehomeJournal | undefined>;
  writeBrainJournal(journal: BrainRehomeJournal): Promise<void>;
  clearBrainJournal(): Promise<void>;
  copyToStaging(sourcePath: string, stagingPath: string, entry: BrainRehomePathEntry, owner: { uid: number; gid: number }): Promise<void>;
  removePath(path: string): Promise<void>;
  swapStagingIntoPlace(stagingPath: string, destPath: string): Promise<void>;
}

export interface ExecuteBrainRehomeOptions {
  runId?: string;
  now?: () => Date;
}

export class BrainRehomeJournalOpenError extends Error {
  constructor(journal?: BrainRehomeJournal) {
    super(
      describeBrainJournalManualRecovery(journal?.journalPath),
    );
    this.name = "BrainRehomeJournalOpenError";
  }
}

function describeBrainJournalManualRecovery(journalPath?: string): string {
  const pathText = journalPath ?? "the Tier-M brain re-home journal path";
  return (
    `Tier-M brain re-home journal exists at ${pathText}; refusing fresh work and never auto-resuming. ` +
    "Recovery is manual: inspect the journal items, their sourcePath/destPath/stagingPath fields, " +
    "the agent-home destination tree, and the root-only re-home backups before removing the journal."
  );
}

export async function assertNoOpenBrainRehomeJournal(
  ops: Pick<BrainRehomeOps, "readBrainJournal">,
): Promise<void> {
  const openJournal = await ops.readBrainJournal();
  if (openJournal !== undefined) {
    throw new BrainRehomeJournalOpenError(openJournal);
  }
}

type BrainRehomePreflightOps = Pick<
  BrainRehomeOps,
  "readBrainJournal" | "pathExistsNoFollow" | "readDestinationProvenance" | "hashPath"
>;

/**
 * Read-only Tier-M refusal gate for fresh provisioning. It mirrors the
 * destination/journal checks inside {@link executeBrainRehomePlan}, but performs
 * no journal writes, backups, copies, removals, ownership changes, or provenance
 * writes, so the orchestrator can run it before account creation or stand-down.
 */
export async function assertBrainRehomePreflight(
  plan: BrainRehomePlan,
  ops: BrainRehomePreflightOps,
): Promise<void> {
  await assertNoOpenBrainRehomeJournal(ops);
  for (const step of plan.steps) {
    await assertStateDbFamilyQuiescent(step, ops);
    const destinationExists = await ops.pathExistsNoFollow(step.destPath);
    const provenance = destinationExists
      ? await ops.readDestinationProvenance(step.entry.sourcePath, step.destPath)
      : undefined;
    const sourceExists = await ops.pathExistsNoFollow(step.entry.sourcePath);
    if (destinationExists) {
      let sourceHash: RehomePathHash | undefined;
      let destinationHash: RehomePathHash | undefined;
      if (sourceExists) sourceHash = await ops.hashPath(step.entry.sourcePath);
      destinationHash = await ops.hashPath(step.destPath);
      throw new Error(
        alreadyPlacedBrainRehomeMessage({
          relPath: step.entry.relPath,
          sourcePath: step.entry.sourcePath,
          destPath: step.destPath,
          hasProvenance: provenance !== undefined,
          sourceHash,
          destinationHash,
        }),
      );
    }
    if (!sourceExists) {
      const sidecars = stateDbSidecarPaths(step.entry.sourcePath);
      if (
        step.entry.stateDbFamily === true &&
        ((await ops.pathExistsNoFollow(sidecars.shm)) || (await ops.pathExistsNoFollow(sidecars.wal)))
      ) {
        throw new Error(
          `state.db family is incomplete: sidecar exists but ${step.entry.sourcePath} is absent; refusing Tier-M re-home`,
        );
      }
    }
  }
}

export function planBrainRehome(
  adapter: AgentRehomeAdapter,
  options: { operatorHome: string; newAccountHome: string },
): BrainRehomePlan {
  const entries = adapter.brainPathsToRehome?.(options.operatorHome) ?? [];
  return {
    harnessId: adapter.harnessId,
    steps: entries.map((entry) => ({
      entry,
      destPath: joinPosix(options.newAccountHome, entry.destRelativePath),
    })),
  };
}

export function summarizeBrainRehomeResults(results: BrainRehomeStepResult[]): BrainRehomeSummary {
  const stranded = results
    .filter((result) => {
      if (result.status === "moved") return false;
      return result.entry.required;
    })
    .map((result) => result.entry.relPath);
  return {
    status: stranded.length === 0 ? "complete" : "partial",
    results,
    stranded,
  };
}

function stateDbSidecarPaths(path: string): { wal: string; shm: string } {
  return { wal: `${path}-wal`, shm: `${path}-shm` };
}

async function assertStateDbFamilyQuiescent(
  step: BrainRehomeStep,
  ops: Pick<BrainRehomeOps, "pathExistsNoFollow">,
): Promise<void> {
  if (step.entry.stateDbFamily !== true) return;
  const sourceSidecars = stateDbSidecarPaths(step.entry.sourcePath);
  const destSidecars = stateDbSidecarPaths(step.destPath);
  const sourceWal = await ops.pathExistsNoFollow(sourceSidecars.wal);
  const sourceShm = await ops.pathExistsNoFollow(sourceSidecars.shm);
  const destWal = await ops.pathExistsNoFollow(destSidecars.wal);
  const destShm = await ops.pathExistsNoFollow(destSidecars.shm);
  if (sourceWal || sourceShm || destWal || destShm) {
    throw new Error(
      `state.db sidecar still exists after quiescence (${[
        sourceWal ? sourceSidecars.wal : undefined,
        sourceShm ? sourceSidecars.shm : undefined,
        destWal ? destSidecars.wal : undefined,
        destShm ? destSidecars.shm : undefined,
      ].filter(Boolean).join(", ")}); refusing Tier-M re-home until SQLite is checkpointed`,
    );
  }
}

function journalItemFor(journal: BrainRehomeJournal, relPath: string): BrainRehomeJournalItem {
  const item = journal.items.find((candidate) => candidate.relPath === relPath);
  if (item === undefined) {
    throw new Error(`Tier-M journal is missing item ${relPath}`);
  }
  return item;
}

async function writeJournalItemState(
  ops: BrainRehomeOps,
  journal: BrainRehomeJournal,
  relPath: string,
  state: BrainRehomeJournalItemState,
  patch: Partial<BrainRehomeJournalItem> = {},
): Promise<void> {
  const item = journalItemFor(journal, relPath);
  Object.assign(item, patch, { state });
  await ops.writeBrainJournal(journal);
}

async function backupAndRemoveBrainSource(
  ops: BrainRehomeOps,
  sourcePath: string,
): Promise<string | undefined> {
  if (!(await ops.pathExistsNoFollow(sourcePath))) return undefined;
  const backup = await ops.backup(sourcePath);
  await ops.removeSourceDuplicate(sourcePath);
  return backup.backupPath;
}

function freshBrainJournal(
  plan: BrainRehomePlan,
  steps: BrainRehomeStep[],
  runId: string,
  now: Date,
): BrainRehomeJournal {
  return {
    schemaVersion: 1,
    harnessId: plan.harnessId,
    runId,
    createdAt: now.toISOString(),
    items: steps.map((step) => ({
      relPath: step.entry.relPath,
      sourcePath: step.entry.sourcePath,
      destPath: step.destPath,
      stagingPath: `${step.destPath}.sanctuary-brain-stage-${runId}`,
      kind: step.entry.kind,
      required: step.entry.required,
      isSecret: step.entry.isSecret,
      largeObject: step.entry.largeObject,
      stateDbFamily: step.entry.stateDbFamily === true,
      state: "pending",
    })),
  };
}

export async function executeBrainRehomePlan(
  plan: BrainRehomePlan,
  ops: BrainRehomeOps,
  newAccountUidGid: { uid: number; gid: number },
  options: ExecuteBrainRehomeOptions = {},
): Promise<BrainRehomeStepResult[]> {
  const openJournal = await ops.readBrainJournal();
  if (openJournal !== undefined) {
    throw new BrainRehomeJournalOpenError(openJournal);
  }

  const results: BrainRehomeStepResult[] = [];
  const candidateSteps: BrainRehomeStep[] = [];
  for (const step of plan.steps) {
    await assertStateDbFamilyQuiescent(step, ops);
    const destinationExists = await ops.pathExistsNoFollow(step.destPath);
    const provenance = destinationExists
      ? await ops.readDestinationProvenance(step.entry.sourcePath, step.destPath)
      : undefined;
    const sourceExists = await ops.pathExistsNoFollow(step.entry.sourcePath);
    if (destinationExists) {
      let sourceHash: RehomePathHash | undefined;
      let destinationHash: RehomePathHash | undefined;
      if (sourceExists) sourceHash = await ops.hashPath(step.entry.sourcePath);
      if (destinationExists) destinationHash = await ops.hashPath(step.destPath);
      throw new Error(
        alreadyPlacedBrainRehomeMessage({
          relPath: step.entry.relPath,
          sourcePath: step.entry.sourcePath,
          destPath: step.destPath,
          hasProvenance: provenance !== undefined,
          sourceHash,
          destinationHash,
        }),
      );
    }
    if (!sourceExists) {
      const sidecars = stateDbSidecarPaths(step.entry.sourcePath);
      if (
        step.entry.stateDbFamily === true &&
        ((await ops.pathExistsNoFollow(sidecars.shm)) || (await ops.pathExistsNoFollow(sidecars.wal)))
      ) {
        throw new Error(
          `state.db family is incomplete: sidecar exists but ${step.entry.sourcePath} is absent; refusing Tier-M re-home`,
        );
      }
      results.push({ entry: step.entry, destPath: step.destPath, status: "skipped-absent" });
      continue;
    }
    candidateSteps.push(step);
  }
  if (candidateSteps.length === 0) return results;

  const runId = options.runId ?? `brain-${Date.now().toString(36)}`;
  const journal = freshBrainJournal(plan, candidateSteps, runId, (options.now ?? (() => new Date()))());
  await ops.writeBrainJournal(journal);

  try {
    for (const step of candidateSteps) {
      const item = journalItemFor(journal, step.entry.relPath);
      const sourceHash = await ops.hashPath(step.entry.sourcePath);
      await ops.removePath(item.stagingPath);
      await assertStateDbFamilyQuiescent(step, ops);
      const destinationExists = await ops.pathExistsNoFollow(step.destPath);
      const provenance = destinationExists
        ? await ops.readDestinationProvenance(step.entry.sourcePath, step.destPath)
        : undefined;
      if (destinationExists) {
        throw new Error(
          alreadyPlacedBrainRehomeMessage({
            relPath: step.entry.relPath,
            sourcePath: step.entry.sourcePath,
            destPath: step.destPath,
            hasProvenance: provenance !== undefined,
            sourceHash,
            destinationHash: destinationExists ? await ops.hashPath(step.destPath) : undefined,
          }),
        );
      }
      await ops.copyToStaging(step.entry.sourcePath, item.stagingPath, step.entry, newAccountUidGid);
      const stagedHash = await ops.hashPath(item.stagingPath);
      if (!hashesMatch(sourceHash, stagedHash)) {
        throw new Error(
          `Tier-M copy verification failed for ${step.entry.relPath}: source ${sourceHash.algorithm}:${sourceHash.value} ` +
            `!= staged ${stagedHash.algorithm}:${stagedHash.value}`,
        );
      }
      await writeJournalItemState(ops, journal, step.entry.relPath, "staged");
      await assertStateDbFamilyQuiescent(step, ops);
      await writeJournalItemState(ops, journal, step.entry.relPath, "swapping");
      await ops.swapStagingIntoPlace(item.stagingPath, step.destPath);
      const destinationHash = await ops.hashPath(step.destPath);
      if (!hashesMatch(sourceHash, destinationHash)) {
        throw new Error(
          `Tier-M swap verification failed for ${step.entry.relPath}: source ${sourceHash.algorithm}:${sourceHash.value} ` +
            `!= destination ${destinationHash.algorithm}:${destinationHash.value}`,
        );
      }
      await writeJournalItemState(ops, journal, step.entry.relPath, "swapped");
      const backupPath = await backupAndRemoveBrainSource(ops, step.entry.sourcePath);
      await writeJournalItemState(ops, journal, step.entry.relPath, "backed-up", { backupPath });
      await ops.chown(step.destPath, newAccountUidGid.uid, newAccountUidGid.gid);
      await ops.recordDestinationProvenance(step.entry.sourcePath, step.destPath, {
        placingRunId: journal.runId,
        destHash: destinationHash,
      });
      results.push({
        entry: step.entry,
        destPath: step.destPath,
        status: "moved",
        backupPath,
        sourceHash,
        destinationHash,
        placementRunId: journal.runId,
      });
    }
    await ops.clearBrainJournal();
    return results;
  } catch (err) {
    for (const step of candidateSteps) {
      const item = journal.items.find((candidate) => candidate.relPath === step.entry.relPath);
      if (item !== undefined && (item.state === "pending" || item.state === "staged")) {
        await ops.removePath(item.stagingPath).catch(() => undefined);
      }
    }
    throw new RehomeExecutionError(err instanceof Error ? err.message : String(err), results, { cause: err });
  }
}

function provenanceMatchesDestination(
  provenance: RehomeDestinationProvenance | undefined,
  sourcePath: string,
  destPath: string,
  destHash: RehomePathHash,
): boolean {
  return (
    provenance !== undefined &&
    (provenance.schemaVersion === 1 || provenance.schemaVersion === 2) &&
    provenance.sourcePath === sourcePath &&
    provenance.destPath === destPath &&
    provenance.destHash.algorithm === destHash.algorithm &&
    provenance.destHash.value === destHash.value
  );
}

function hashesMatch(left: RehomePathHash, right: RehomePathHash): boolean {
  return left.algorithm === right.algorithm && left.value === right.value;
}

function destinationConflictMessage(
  sourcePath: string,
  destPath: string,
  sourceHash: RehomePathHash,
  destHash: RehomePathHash,
  reason = "no current Sanctuary re-home provenance marks the destination as authoritative",
): string {
  return (
    `re-home destination conflict: source ${sourcePath} (${sourceHash.algorithm}:${sourceHash.value}) ` +
    `and destination ${destPath} (${destHash.algorithm}:${destHash.value}) both exist, but ${reason}; ` +
    "refusing before backup/move because content-identical placement was not proven. " +
    "Re-run with --overwrite-destination to preserve the destination as a dated sibling and move the source anyway."
  );
}

function alreadyPlacedBrainRehomeMessage(input: {
  relPath: string;
  sourcePath: string;
  destPath: string;
  hasProvenance: boolean;
  sourceHash?: RehomePathHash;
  destinationHash?: RehomePathHash;
}): string {
  const hashDetail =
    input.sourceHash !== undefined && input.destinationHash !== undefined
      ? ` Source ${input.sourcePath} is ${input.sourceHash.algorithm}:${input.sourceHash.value}; ` +
        `destination ${input.destPath} is ${input.destinationHash.algorithm}:${input.destinationHash.value}; ` +
        "content-identical placement was not proven as a supported migration path."
      : input.destinationHash !== undefined
        ? ` Destination ${input.destPath} is ${input.destinationHash.algorithm}:${input.destinationHash.value}.`
        : "";
  const evidence = input.hasProvenance
    ? "existing Sanctuary placement provenance"
    : "an existing agent-side copy";
  return (
    `Tier-M brain re-home is fresh-provision only: ${input.relPath} already has ${evidence} at ${input.destPath}. ` +
    "Migration of an already-provisioned host is not supported yet; refusing before backup, copy, install, or arm." +
    hashDetail
  );
}

/**
 * Execute a re-home plan against injected ops. Backup-first (fix M4: every
 * secret path is backed up via `ops.backup` -- root-only, reversible --
 * BEFORE it is moved), then move, then chown to the new account. A source
 * path that does not exist on this host is recorded `skipped-absent` (not
 * an error): not every harness install has every optional credential file
 * populated.
 *
 * Fail-closed: if any step throws (backup, move, or chown failure), this
 * function does not swallow the error -- it propagates immediately so the
 * orchestrator can surface the failure and the already-completed steps'
 * backups remain available for `unprovisionRestore`. This module does not
 * attempt automatic rollback-on-partial-failure itself; that is the
 * orchestrator's job (fix: never arm a half-configured state), and
 * `unprovisionRestore` below reverses whatever DID complete.
 *
 * FIX R3 (HIGH, 2026-07-07 fix-round 2): a mid-loop throw is now caught here
 * and re-thrown as a {@link RehomeExecutionError} carrying the `results`
 * accumulated so far, so the caller/orchestrator can `safeRestore` the
 * partial move instead of losing it to an empty array. The ORIGINAL error's
 * message is preserved (via `Error.cause` and by folding it into the new
 * error's own message) so existing failure-reason matching keeps working.
 *
 * FIX G3 (HIGH, 2026-07-07 re-gate 3 / fix-round 3): the R3 fix above still
 * had a one-step-short gap -- `move` -> `chown` -> `push-to-results` left a
 * STRADDLING window: if `chown` throws AFTER `move` already renamed the path
 * onto the new account's home, the entry was never pushed to `results`
 * before the throw, so `RehomeExecutionError.partialResults` omitted it
 * entirely. `safeRestore` (orchestrate.ts) then had no record of that path
 * at all -- the secret was stranded, moved-but-not-chowned, under the new
 * (not-yet-armed) account, with no backup path surfaced to the operator.
 * The fix records the `moved` result IMMEDIATELY after `move()` succeeds,
 * BEFORE `chown` runs, so a chown failure still has the entry already
 * captured in `results` (and therefore in `partialResults`) and
 * `safeRestore` can recover it via `destPath` like any other moved entry.
 */
export async function executeRehomePlan(
  plan: RehomePlan,
  ops: RehomeOps,
  newAccountUidGid: { uid: number; gid: number },
  options: ExecuteRehomePlanOptions = {},
): Promise<RehomeStepResult[]> {
  const results: RehomeStepResult[] = [];
  for (const step of plan.steps) {
    try {
      const exists = await ops.pathExists(step.entry.sourcePath);
      if (!exists) {
        results.push({ entry: step.entry, destPath: step.destPath, status: "skipped-absent" });
        continue;
      }
      const destExists = await ops.pathExistsNoFollow(step.destPath);
      let stepResult: RehomeStepResult | undefined;
      if (destExists) {
        const sourceHash = await ops.hashPath(step.entry.sourcePath);
        const destinationHash = await ops.hashPath(step.destPath);
        const provenance = await ops.readDestinationProvenance(step.entry.sourcePath, step.destPath);
        if (
          options.overwriteDestination !== true &&
          provenanceMatchesDestination(provenance, step.entry.sourcePath, step.destPath, destinationHash)
        ) {
          if (!hashesMatch(sourceHash, destinationHash)) {
            throw new Error(
              destinationConflictMessage(
                step.entry.sourcePath,
                step.destPath,
                sourceHash,
                destinationHash,
                `Sanctuary re-home provenance schema v${provenance?.schemaVersion ?? "unknown"} ` +
                  "marks the destination as previously re-homed, but the current source and destination content hashes diverge",
              ),
            );
          }
          let backupPath: string | undefined;
          let sourceDuplicateRemoved = false;
          if (step.entry.isSecret) {
            const backup = await ops.backup(step.entry.sourcePath);
            backupPath = backup.backupPath;
            await ops.removeSourceDuplicate(step.entry.sourcePath);
            sourceDuplicateRemoved = true;
          }
          results.push({
            entry: step.entry,
            destPath: step.destPath,
            status: "destination-authoritative",
            backupPath,
            sourceDuplicateRemoved,
            sourceHash,
            destinationHash,
          });
          continue;
        }
        if (options.overwriteDestination !== true) {
          throw new Error(destinationConflictMessage(step.entry.sourcePath, step.destPath, sourceHash, destinationHash));
        }
        const { displacedPath } = await ops.displaceDestination(step.destPath);
        stepResult = {
          entry: step.entry,
          destPath: step.destPath,
          status: "destination-displaced",
          displacedDestinationPath: displacedPath,
          sourceHash,
          destinationHash,
        };
        // Record immediately: if backup or move fails, rollback must still
        // know where the displaced destination is.
        results.push(stepResult);
      }
      let backupPath: string | undefined;
      if (step.entry.isSecret) {
        const backup = await ops.backup(step.entry.sourcePath);
        backupPath = backup.backupPath;
      }
      await ops.move(step.entry.sourcePath, step.destPath);
      // FIX G3: record the moved result NOW, before chown -- a chown failure
      // below must not strand this entry outside `results`/`partialResults`.
      if (stepResult === undefined) {
        stepResult = { entry: step.entry, destPath: step.destPath, status: "moved", backupPath };
        results.push(stepResult);
      } else {
        stepResult.status = "moved";
        stepResult.backupPath = backupPath;
      }
      const chownReport = await ops.chown(step.destPath, newAccountUidGid.uid, newAccountUidGid.gid);
      if (chownReport.excludedPaths.length > 0) {
        stepResult.chownExcludedPaths = chownReport.excludedPaths;
      }
      await ops.recordDestinationProvenance(step.entry.sourcePath, step.destPath);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new RehomeExecutionError(message, results, { cause: err });
    }
  }
  return results;
}

/**
 * Per-step outcome of {@link restoreRehomeSteps} (fix F2/F5: honest, not a
 * hardcoded success). FIX R6 (2026-07-07 fix-round 2): `"conflict"` is a
 * distinct status from `"failed"` -- it means the source path was RECREATED
 * while re-homed and the moved data was restored to `conflictPath` instead
 * of overwriting it, never a bare unexplained failure. `conflictPath` is set
 * only for this status.
 */
export interface RestoreStepOutcome {
  entry: RehomePathEntry;
  sourcePath: string;
  status:
    | "restored"
    | "skipped-absent"
    | "skipped-destination-authoritative"
    | "displaced-destination-restored"
    | "displaced-destination-conflict"
    | "failed"
    | "conflict";
  error?: string;
  conflictPath?: string;
}

/** Aggregate result of {@link restoreRehomeSteps}. */
export interface RestoreRehomeResult {
  steps: RestoreStepOutcome[];
  /** True only when every non-skipped step reported `restored` (fix F2/F5: never claim a clean rollback on a partial restore). */
  fullyRestored: boolean;
}

/**
 * Reverse a set of executed re-home steps (H2-a: this PR's `unprovision`
 * scope -- daemon-uninstall + disarm + restore-backup).
 *
 * FIX F2 (2026-07-07 fix-round): restore is now a REVERSE-MOVE of `destPath`
 * back to `sourcePath` -- correct for files AND directories, since `move`
 * used `rename` and the data is intact at `destPath`. This closes the prior
 * defect where a directory-shaped secret (e.g. `.hermes/google-mcp-creds/`)
 * restored from an empty placeholder backup, silently stranding the real
 * data at `destPath` while reporting success. The `backupPath` (the M4
 * custody copy) is the ops layer's fallback source if `destPath` is somehow
 * already gone; the ops implementation decides that, this function always
 * passes `destPath` as the "restore from" argument, matching the updated
 * `RehomeOps.restore` contract.
 *
 * FIX F3: after a successful restore of a secret entry, custody is handed
 * back to the operator (chmod 0600/0700 + chown to `operatorUidGid`).
 * Non-secret runtime trees are chowned back without chmod normalization, so
 * executable bits and virtualenv layout survive rollback.
 *
 * Fail-loud per step, never throws: every step is attempted (a failure on
 * one path must not stop the rest of the operator's secrets from being
 * restored), and the per-step + aggregate outcome tells the caller EXACTLY
 * what did and did not come back, so `orchestrate.ts` can report
 * `rolledBack: false`/`"partial"` honestly instead of a hardcoded `true`.
 */
export async function restoreRehomeSteps(
  results: RehomeStepResult[],
  ops: RehomeOps,
  operatorUidGid: { uid: number; gid: number },
): Promise<RestoreRehomeResult> {
  const steps: RestoreStepOutcome[] = [];
  for (const result of results) {
    if (result.status === "skipped-absent") {
      steps.push({ entry: result.entry, sourcePath: result.entry.sourcePath, status: "skipped-absent" });
      continue;
    }
    if (result.status === "destination-authoritative") {
      if (result.sourceDuplicateRemoved === true) {
        if (result.backupPath === undefined) {
          steps.push({
            entry: result.entry,
            sourcePath: result.entry.sourcePath,
            status: "failed",
            error: "source duplicate was removed but no backupPath was recorded",
          });
          continue;
        }
        try {
          const duplicate = await ops.restoreSourceDuplicate(result.backupPath, result.entry.sourcePath);
          if (!duplicate.restored) {
            let custodyError: string | undefined;
            if (duplicate.conflictPath !== undefined && result.entry.isSecret) {
              try {
                await ops.restoreCustody(duplicate.conflictPath, operatorUidGid.uid, operatorUidGid.gid);
              } catch (custodyErr) {
                custodyError = (custodyErr as Error).message;
              }
            }
            steps.push({
              entry: result.entry,
              sourcePath: result.entry.sourcePath,
              status: duplicate.conflictPath !== undefined ? "conflict" : "failed",
              conflictPath: duplicate.conflictPath,
              error:
                duplicate.conflictPath !== undefined
                  ? `source path was recreated after duplicate cleanup; restored duplicate was placed at ${duplicate.conflictPath} instead of overwriting it` +
                    (custodyError !== undefined
                      ? ` (custody handback to the operator failed: ${custodyError}; the recovered data at ${duplicate.conflictPath} may need a manual chown)`
                      : "")
                  : "source duplicate restore reported no data reproduced at the source path",
            });
            continue;
          }
          if (result.entry.isSecret) {
            await ops.restoreCustody(result.entry.sourcePath, operatorUidGid.uid, operatorUidGid.gid);
          } else {
            await ops.chown(result.entry.sourcePath, operatorUidGid.uid, operatorUidGid.gid);
          }
          steps.push({ entry: result.entry, sourcePath: result.entry.sourcePath, status: "restored" });
        } catch (err) {
          steps.push({
            entry: result.entry,
            sourcePath: result.entry.sourcePath,
            status: "failed",
            error: (err as Error).message,
          });
        }
        continue;
      }
      steps.push({
        entry: result.entry,
        sourcePath: result.entry.sourcePath,
        status: "skipped-destination-authoritative",
      });
      continue;
    }
    if (result.status === "destination-displaced") {
      if (result.displacedDestinationPath === undefined) {
        steps.push({
          entry: result.entry,
          sourcePath: result.entry.sourcePath,
          status: "failed",
          error: "destination was displaced but no displacedDestinationPath was recorded",
        });
        continue;
      }
      try {
        const displaced = await ops.restoreDisplacedDestination(result.displacedDestinationPath, result.destPath);
        if (displaced.restored) {
          steps.push({
            entry: result.entry,
            sourcePath: result.entry.sourcePath,
            status: "displaced-destination-restored",
          });
        } else {
          steps.push({
            entry: result.entry,
            sourcePath: result.entry.sourcePath,
            status: "displaced-destination-conflict",
            conflictPath: displaced.conflictPath,
            error:
              displaced.conflictPath !== undefined
                ? `destination path was occupied during rollback; displaced destination was preserved at ${displaced.conflictPath}`
                : "displaced destination restore reported no data reproduced at the destination path",
          });
        }
      } catch (err) {
        steps.push({
          entry: result.entry,
          sourcePath: result.entry.sourcePath,
          status: "failed",
          error: (err as Error).message,
        });
      }
      continue;
    }
    try {
      const { restored, conflictPath } = await ops.restore(result.destPath, result.entry.sourcePath, result.backupPath);
      await ops.clearDestinationProvenance(result.entry.sourcePath, result.destPath);
      if (!restored) {
        let displacedRestoreNote = "";
        if (result.displacedDestinationPath !== undefined) {
          try {
            const displaced = await ops.restoreDisplacedDestination(result.displacedDestinationPath, result.destPath);
            if (!displaced.restored) {
              displacedRestoreNote =
                displaced.conflictPath !== undefined
                  ? `; displaced destination was preserved at ${displaced.conflictPath} because ${result.destPath} was occupied during rollback`
                  : "; displaced destination restore reported no data reproduced at the destination path";
            }
          } catch (displacedErr) {
            displacedRestoreNote = `; displaced destination restore failed: ${(displacedErr as Error).message}`;
          }
        }
        // FIX R6 (2026-07-07 fix-round 2): a `conflictPath` means the ops
        // layer detected a recreated file/dir at `sourcePath` and restored
        // to a sibling conflict path instead of overwriting it -- report
        // this as its own `"conflict"` status, never folded into the
        // generic `"failed"` bucket, so the operator sees "your recreated
        // file is safe, the recovered data is at <conflictPath>" rather than
        // an unexplained failure.
        if (conflictPath !== undefined) {
          // FIX (round 5, item N6): the recovered data now sitting at
          // `conflictPath` was reverse-moved from the AGENT-owned re-home
          // destination, so it is owned by the agent uid, not the operator.
          // Without a custody handback the operator is pointed at a recovered
          // secret they cannot read. Hand custody of the RECOVERED data (at
          // `conflictPath`, NOT `sourcePath` -- `sourcePath` holds the
          // operator's already-owned recreated file, which must never be
          // touched) back to the operator for secret entries.
          //
          // FIX (round 5 / R2-5): the custody handback runs in its OWN
          // try/catch. If it were left in the outer try, a handback failure
          // would fall to the outer catch and relabel this step
          // "conflict" -> "failed", DROPPING conflictPath -- so the operator
          // would lose the "your recreated file is safe; recovered data is at
          // <conflictPath>" guidance over a mere chown failure. Keep status
          // "conflict" + conflictPath; fold any handback error into the note.
          let custodyError: string | undefined;
          if (result.entry.isSecret) {
            try {
              await ops.restoreCustody(conflictPath, operatorUidGid.uid, operatorUidGid.gid);
            } catch (custodyErr) {
              custodyError = (custodyErr as Error).message;
            }
          } else {
            try {
              await ops.chown(conflictPath, operatorUidGid.uid, operatorUidGid.gid);
            } catch (custodyErr) {
              custodyError = (custodyErr as Error).message;
            }
          }
          steps.push({
            entry: result.entry,
            sourcePath: result.entry.sourcePath,
            status: "conflict",
            conflictPath,
            error:
              `source path was recreated during re-home; restored data was placed at ${conflictPath} instead of overwriting it` +
              (custodyError !== undefined
                ? ` (custody handback to the operator failed: ${custodyError}; the recovered data at ${conflictPath} may need a manual chown)`
                : "") +
              displacedRestoreNote,
          });
        } else {
          steps.push({
            entry: result.entry,
            sourcePath: result.entry.sourcePath,
            status: "failed",
            error: `restore reported no data reproduced at the source path${displacedRestoreNote}`,
          });
        }
        continue;
      }
      if (result.entry.isSecret) {
        await ops.restoreCustody(result.entry.sourcePath, operatorUidGid.uid, operatorUidGid.gid);
      } else {
        await ops.chown(result.entry.sourcePath, operatorUidGid.uid, operatorUidGid.gid);
      }
      steps.push({ entry: result.entry, sourcePath: result.entry.sourcePath, status: "restored" });
      if (result.displacedDestinationPath !== undefined) {
        const displaced = await ops.restoreDisplacedDestination(result.displacedDestinationPath, result.destPath);
        if (!displaced.restored) {
          steps.push({
            entry: result.entry,
            sourcePath: result.entry.sourcePath,
            status: "displaced-destination-conflict",
            conflictPath: displaced.conflictPath,
            error:
              displaced.conflictPath !== undefined
                ? `destination path was occupied during rollback; displaced destination was preserved at ${displaced.conflictPath}`
                : "displaced destination restore reported no data reproduced at the destination path",
          });
        }
      }
    } catch (err) {
      steps.push({
        entry: result.entry,
        sourcePath: result.entry.sourcePath,
        status: "failed",
        error: (err as Error).message,
      });
    }
  }
  // FIX R6: "conflict" is not a clean restore either -- the operator's
  // secret is not back at its original path (it is at conflictPath), so
  // fullyRestored must be false for a conflict just as for a failure.
  const fullyRestored = steps.every(
    (s) => s.status !== "failed" && s.status !== "conflict" && s.status !== "displaced-destination-conflict",
  );
  return { steps, fullyRestored };
}

// ── Hermes v1 adapter ──────────────────────────────────────────────────

/**
 * Hermes CoS re-home adapter (v1; the only adapter this PR ships). Grounded
 * in the live Mini2 read-only inspection (D2 RESOLVED): Hermes keeps ALL
 * secrets in 0600 files, never the login keychain:
 *   - `~/.hermes/.env`, `~/.hermes/auth.json`, `~/.hermes/config.yaml`
 *     (LLM / Telegram / persona config -- secrets)
 *   - `~/.hermes/hermes-agent/` (runtime code; not a secret, but the confined
 *     LaunchDaemon needs it under the dedicated account to import `hermes_cli`)
 *   - `~/.google_workspace_mcp/credentials` (file-based Google OAuth -- secret)
 *   - `~/.workspace-mcp/cli-tokens/mcp-oauth-token*` (secret)
 *   - `~/.hermes/google-mcp-creds/` (secret)
 *
 * Google refresh tokens are file-portable (the move preserves them); the
 * MCP runs `calendar:readonly`, so there is no calendar-write re-consent
 * forced today -- `requiresInteractiveReconsent()` returns false for v1.
 */
export const hermesRehomeAdapter: AgentRehomeAdapter = {
  harnessId: "hermes",
  pathsToRehome(operatorHome: string): RehomePathEntry[] {
    const join = (...parts: string[]): string => `${operatorHome}/${parts.join("/")}`.replace(/\/+/g, "/");
    return [
      { sourcePath: join(".hermes", ".env"), destRelativePath: ".hermes/.env", isSecret: true },
      { sourcePath: join(".hermes", "auth.json"), destRelativePath: ".hermes/auth.json", isSecret: true },
      { sourcePath: join(".hermes", "cli-config.json"), destRelativePath: ".hermes/cli-config.json", isSecret: true },
      { sourcePath: join(".hermes", "config.yaml"), destRelativePath: ".hermes/config.yaml", isSecret: true },
      {
        sourcePath: join(".hermes", "hermes-agent"),
        destRelativePath: ".hermes/hermes-agent",
        isSecret: false,
      },
      {
        sourcePath: join(".google_workspace_mcp", "credentials"),
        destRelativePath: ".google_workspace_mcp/credentials",
        isSecret: true,
      },
      {
        sourcePath: join(".workspace-mcp", "cli-tokens"),
        destRelativePath: ".workspace-mcp/cli-tokens",
        isSecret: true,
      },
      {
        sourcePath: join(".hermes", "google-mcp-creds"),
        destRelativePath: ".hermes/google-mcp-creds",
        isSecret: true,
      },
    ];
  },
  brainPathsToRehome(operatorHome: string): BrainRehomePathEntry[] {
    const join = (...parts: string[]): string => `${operatorHome}/${parts.join("/")}`.replace(/\/+/g, "/");
    const file = (relPath: string, options: Partial<BrainRehomePathEntry> = {}): BrainRehomePathEntry => ({
      tier: "mind",
      relPath,
      sourcePath: join(relPath),
      destRelativePath: relPath,
      kind: "file",
      required: true,
      isSecret: true,
      largeObject: false,
      ...options,
    });
    const dir = (relPath: string, options: Partial<BrainRehomePathEntry> = {}): BrainRehomePathEntry => ({
      tier: "mind",
      relPath,
      sourcePath: join(relPath),
      destRelativePath: relPath,
      kind: "dir",
      required: true,
      isSecret: true,
      largeObject: false,
      ...options,
    });
    return [
      file("SOUL.md"),
      file("IDENTITY.md"),
      dir("memories"),
      dir("skills"),
      dir("sessions", { largeObject: true }),
      file("state.db", { largeObject: true, stateDbFamily: true }),
      dir("kanban"),
      dir("workspace", { largeObject: true }),
      dir("cron"),
      file("channel_directory.json"),
      file("gateway_state.json"),
      file(".skills_prompt_snapshot.json"),
      file(".no-bundled-skills", { isSecret: false }),
    ];
  },
  requiresInteractiveReconsent(): boolean {
    return false;
  },
};
