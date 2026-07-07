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
  /** Whether this is a secret (drives backup mode / encryption requirements). */
  isSecret: boolean;
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
  /** Move (not copy) the file tree from `sourcePath` to `destPath`, creating parent dirs as needed. */
  move(sourcePath: string, destPath: string): Promise<void>;
  /** chown the path (recursively, if a directory) to the given uid/gid. */
  chown(path: string, uid: number, gid: number): Promise<void>;
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
  restore(destPath: string, sourcePath: string): Promise<{ restored: boolean; conflictPath?: string }>;
  /**
   * Restore custody of a restored secret path to the operator (fix F3):
   * chmod 0600 (file) / 0700 (dir) and chown back to the operator's
   * uid/gid. Called only for `isSecret` entries, only after a successful
   * restore.
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
  status: "moved" | "skipped-absent";
  backupPath?: string;
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
): Promise<RehomeStepResult[]> {
  const results: RehomeStepResult[] = [];
  for (const step of plan.steps) {
    try {
      const exists = await ops.pathExists(step.entry.sourcePath);
      if (!exists) {
        results.push({ entry: step.entry, destPath: step.destPath, status: "skipped-absent" });
        continue;
      }
      let backupPath: string | undefined;
      if (step.entry.isSecret) {
        const backup = await ops.backup(step.entry.sourcePath);
        backupPath = backup.backupPath;
      }
      await ops.move(step.entry.sourcePath, step.destPath);
      // FIX G3: record the moved result NOW, before chown -- a chown failure
      // below must not strand this entry outside `results`/`partialResults`.
      const stepResult: RehomeStepResult = { entry: step.entry, destPath: step.destPath, status: "moved", backupPath };
      results.push(stepResult);
      await ops.chown(step.destPath, newAccountUidGid.uid, newAccountUidGid.gid);
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
  status: "restored" | "skipped-absent" | "failed" | "conflict";
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
    try {
      const { restored, conflictPath } = await ops.restore(result.destPath, result.entry.sourcePath);
      if (!restored) {
        // FIX R6 (2026-07-07 fix-round 2): a `conflictPath` means the ops
        // layer detected a recreated file/dir at `sourcePath` and restored
        // to a sibling conflict path instead of overwriting it -- report
        // this as its own `"conflict"` status, never folded into the
        // generic `"failed"` bucket, so the operator sees "your recreated
        // file is safe, the recovered data is at <conflictPath>" rather than
        // an unexplained failure.
        steps.push(
          conflictPath !== undefined
            ? {
                entry: result.entry,
                sourcePath: result.entry.sourcePath,
                status: "conflict",
                conflictPath,
                error: `source path was recreated during re-home; restored data was placed at ${conflictPath} instead of overwriting it`,
              }
            : {
                entry: result.entry,
                sourcePath: result.entry.sourcePath,
                status: "failed",
                error: "restore reported no data reproduced at the source path",
              },
        );
        continue;
      }
      if (result.entry.isSecret) {
        await ops.restoreCustody(result.entry.sourcePath, operatorUidGid.uid, operatorUidGid.gid);
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
  }
  // FIX R6: "conflict" is not a clean restore either -- the operator's
  // secret is not back at its original path (it is at conflictPath), so
  // fullyRestored must be false for a conflict just as for a failure.
  const fullyRestored = steps.every((s) => s.status !== "failed" && s.status !== "conflict");
  return { steps, fullyRestored };
}

// ── Hermes v1 adapter ──────────────────────────────────────────────────

/**
 * Hermes CoS re-home adapter (v1; the only adapter this PR ships). Grounded
 * in the live Mini2 read-only inspection (D2 RESOLVED): Hermes keeps ALL
 * secrets in 0600 files, never the login keychain:
 *   - `~/.hermes/.env`, `~/.hermes/auth.json`, `~/.hermes/config.yaml`
 *     (LLM / Telegram / persona config -- secrets)
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
      { sourcePath: join(".hermes", "config.yaml"), destRelativePath: ".hermes/config.yaml", isSecret: true },
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
  requiresInteractiveReconsent(): boolean {
    return false;
  },
};
