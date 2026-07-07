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
   * operator-readable directory.
   */
  backup(path: string): Promise<{ backupPath: string }>;
  /** Move (not copy) the file tree from `sourcePath` to `destPath`, creating parent dirs as needed. */
  move(sourcePath: string, destPath: string): Promise<void>;
  /** chown the path (recursively, if a directory) to the given uid/gid. */
  chown(path: string, uid: number, gid: number): Promise<void>;
  /** Restore a path from a prior backup (used by `unprovision`). */
  restore(backupPath: string, destPath: string): Promise<void>;
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
 */
export async function executeRehomePlan(
  plan: RehomePlan,
  ops: RehomeOps,
  newAccountUidGid: { uid: number; gid: number },
): Promise<RehomeStepResult[]> {
  const results: RehomeStepResult[] = [];
  for (const step of plan.steps) {
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
    await ops.chown(step.destPath, newAccountUidGid.uid, newAccountUidGid.gid);
    results.push({ entry: step.entry, destPath: step.destPath, status: "moved", backupPath });
  }
  return results;
}

/**
 * Reverse a set of executed re-home steps using their recorded backups
 * (H2-a: this PR's `unprovision` scope -- daemon-uninstall + disarm +
 * restore-backup). Restores every step that has a `backupPath`
 * (secret paths); non-secret moved paths without a backup are restored via
 * the same `move`-back semantics using `ops.restore`, which production
 * implementations back with a plain reverse-move when no encrypted backup
 * exists. Idempotent: a step already `skipped-absent` is a no-op here too.
 */
export async function restoreRehomeSteps(
  results: RehomeStepResult[],
  ops: RehomeOps,
): Promise<void> {
  for (const result of results) {
    if (result.status === "skipped-absent") continue;
    const source = result.backupPath ?? result.destPath;
    await ops.restore(source, result.entry.sourcePath);
  }
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
