/**
 * Sanctuary MCP Server -- `sanctuary castle-wall observe` CLI subcommand.
 *
 * Castle Wall Observe / Learn Allow-List v1. Operator-facing surface for
 * turning on observe mode, reviewing the candidate destinations the wall
 * recorded, and promoting or discarding them. See
 * Review/Sanctuary/ObserveLearn_AllowList_Scoping_2026-07-07.md for the full
 * ratified design; Review/Sanctuary/ObserveLearn_AllowList_Decision_Brief_2026-07-07.md
 * for the ratified D-Q1/D-Q2/D-Q3 decisions.
 *
 * Verbs:
 *   start        Turn observe mode on. Tier-3 auto-allow: never widens the
 *                live ruleset, only changes what happens to a denied novel
 *                destination (coalesce into the candidate store instead of
 *                a per-flow prompt).
 *   status       Show whether observe mode is on and how many candidates
 *                are pending review. Tier-3, read-only.
 *   candidates   Re-read the master audit and boot-audit sources, recompute
 *                the candidate snapshot from retained denied-flow history,
 *                witness each source read outcome, and list every pending
 *                candidate. Tier-3.
 *   promote      Tier-1 FORCED. Synthesizes the selected candidates into
 *                allow rules, fires the SAME non-relaxable approval gate an
 *                MCP-exposed tool would use, and -- ONLY on approval --
 *                re-signs and republishes the manifest. THE RED-LINE
 *                INVARIANT: a denied or unavailable approval channel never
 *                mutates the manifest (see castle-wall/observe/promote.ts).
 *   discard      Drop selected (or all) candidates without promoting them.
 *                Tier-3 auto-allow, safe-direction (never adds a rule).
 *
 * v1 targets the Linux daemon + in-process proxy path first (the shared
 * `decideEgressProxyConnect` evaluator); macOS system-extension wiring of
 * the full observe -> promote loop is a follow-on drill (see the module's
 * PR description).
 */

import { mkdir, open, readdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { createInterface } from "node:readline/promises";
import { basename, isAbsolute, join, resolve } from "node:path";
import { Writable } from "node:stream";
import { createHash, randomBytes } from "node:crypto";

import { resolveStoragePath } from "../paths.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { StateStore } from "../cognitive/state-store.js";
import { IdentityManager } from "../cognitive/tools.js";
import { AuditLog } from "../operational/audit-log.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import type { EncryptedPayload } from "../core/encryption.js";
import { BaselineTracker } from "../principal-policy/baseline.js";
import { ApprovalGate } from "../principal-policy/gate.js";
import { loadPrincipalPolicy } from "../principal-policy/loader.js";
import type { ApprovalChannel } from "../principal-policy/approval-channel.js";
import type { ApprovalRequest, ApprovalResponse } from "../principal-policy/types.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import {
  localManifestSigner,
  publishSignedManifest,
  type ManifestSigner,
  type ManifestStorage,
} from "../castle-wall/runtime/manifest-publisher.js";
import type { SignedManifest } from "../castle-wall/allowlist/manifest.js";
import type { AllowlistRule } from "../castle-wall/allowlist/schema.js";
import {
  castleWallSigningKeyId,
  verifyManifestSignature,
  verifyAndParseRules,
} from "../castle-wall/allowlist/parse.js";
import { preflightManifestRuleEntries } from "../castle-wall/allowlist/rule-identity.js";
import {
  ObserveStore,
  candidatePromotedAwaitingRearm,
  promoteCandidates,
  refreshCandidatesFromAudit,
  type CandidateObservation,
  type ObserveLastRefreshOutcome,
  type ObserveAuditSourceReadOutcome,
  type ObserveModeState,
  type ObserveGranularity,
  type ObserveQuarantinedSourceState,
  type PromoteRouting,
  type PromoteSelectionRow,
  type RefreshAuditSourceDescriptor,
  type RefreshAllowlistRead,
  type RefreshLock,
  type VerifiedManifestRead,
} from "../castle-wall/observe/index.js";
import {
  deriveSafeModeAuditKey,
  readBootToken,
  safeModeAuditStoragePath,
} from "../castle-wall/boot/boot-token.js";
import {
  loadExclusiveRoutingMarker,
  ExclusiveRoutingMarkerError,
} from "../castle-wall/allowlist/index.js";
import {
  EGRESS_GATE_REPAIR_WITH_STAND_DOWN_ADVICE,
  EGRESS_GATE_REPAIR_WITH_STAND_DOWN_COMMAND,
} from "../egress-gate/operator-advice.js";
import { egressPolicyWriterLock } from "../castle-wall/provision/lockfile.js";
import { loadFortressProducerKey } from "../castle-wall/runtime/producer-signature.js";
import {
  claimFromVerifiedEmpty,
  observing,
  verifiedEmptyFrom,
  type Observed,
  type SourceReadOutcome,
  type VerifiedEmpty,
} from "../claim-witness.js";
import { ED25519_PUBLIC_KEY_BYTES } from "../core/crypto-suite-registry.js";
import {
  consumeFlagValue,
  flagValue,
  flagValues,
  FORTRESS_FLAG_USAGE_EXIT_CODE,
  fortressFlagRefusalText,
} from "./argv.js";

/** Same on-disk filenames `runProvisionPin` (cli/castle-wall.ts) establishes under the fortress root. Re-declared here (that module keeps them private) rather than reused, since they are plain filename literals, not secret material. */
const CASTLE_PINNED_PUBKEY = "castle-pinned-pubkey.bin";
const CASTLE_PINNED_PRIVKEY = "castle-pinned-privkey.enc";

export interface ObserveCommandContext {
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  /** Test seam for the root-owned boot-token path. Production uses the default custody path. */
  bootTokenPath?: string;
  /**
   * TEST SEAM ONLY (round-3 R4): overrides the Tier-1 approval channel so the
   * approved-promote CLI paths (candidate retention, exclusive copy) are
   * testable end to end -- the production prompt channel requires an
   * interactive TTY and always denies otherwise. Not reachable from argv;
   * production callers never set it.
   */
  approvalChannel?: ApprovalChannel;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

function hasFlag(argv: string[], name: string): boolean {
  return argv.includes(name);
}

function resolveFortressArg(fortress: string | undefined, env: NodeJS.ProcessEnv): string {
  if (!fortress) return resolveStoragePath(env);
  return isAbsolute(fortress) ? fortress : resolve(process.cwd(), fortress);
}

function destinationLabel(candidate: CandidateObservation): string {
  return `${candidate.host ?? candidate.ip}:${candidate.port}`;
}

const OBSERVE_STATE_SOURCE_ID = "observe-mode-state";
const OBSERVE_CANDIDATE_SOURCE_ID = "observe-candidate-store";

interface ObserveSourceStateRead {
  source: SourceReadOutcome;
  state?: ObserveModeState;
}

interface ObserveCandidateCensus {
  source: SourceReadOutcome;
  candidates: CandidateObservation[];
  emptyVerified?: VerifiedEmpty;
}

function sortCandidates(candidates: CandidateObservation[]): CandidateObservation[] {
  return candidates.sort((a, b) =>
    a.first_seen < b.first_seen ? -1 : a.first_seen > b.first_seen ? 1 : 0,
  );
}

async function observeSourceState(
  observeStore: ObserveStore,
): Promise<Observed<ObserveSourceStateRead>> {
  return observing("observe.source-state", async () => {
    try {
      const state = await observeStore.getState();
      return {
        source: {
          status: "read-and-verified",
          source_id: OBSERVE_STATE_SOURCE_ID,
          record_count: 1,
        },
        state,
      };
    } catch (error) {
      return {
        source: {
          status: "read-failed",
          source_id: OBSERVE_STATE_SOURCE_ID,
          reason: (error as Error).message,
        },
      };
    }
  });
}

async function observeCandidateCensus(
  observeStore: ObserveStore,
): Promise<Observed<ObserveCandidateCensus>> {
  return observing("observe.candidate-census", async () => {
    try {
      const candidates = sortCandidates([...(await observeStore.listCandidates()).values()]);
      const source: SourceReadOutcome = {
        status: "read-and-verified",
        source_id: OBSERVE_CANDIDATE_SOURCE_ID,
        record_count: candidates.length,
      };
      const emptyVerified = verifiedEmptyFrom("observe.candidate-census", [source]);
      return emptyVerified === undefined
        ? { source, candidates }
        : { source, candidates, emptyVerified };
    } catch (error) {
      return {
        source: {
          status: "read-failed",
          source_id: OBSERVE_CANDIDATE_SOURCE_ID,
          reason: (error as Error).message,
        },
        candidates: [],
      };
    }
  });
}

function formatPendingCandidateCount(census: ObserveCandidateCensus): string {
  if (census.source.status !== "read-and-verified") return "could not be determined";
  if (census.candidates.length > 0) return String(census.candidates.length);
  return census.emptyVerified !== undefined
    ? claimFromVerifiedEmpty(census.emptyVerified, "0")
    : "could not be determined";
}

function isEnoent(error: unknown): boolean {
  return (
    error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === "ENOENT"
  );
}

function printUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary castle-wall observe <command> [options]

Castle Wall Observe / Learn Allow-List v1. The wall stays armed and
default-deny the whole time; observe mode records the destinations your
agent reaches so Sanctuary can propose an allow-list you review and approve.
Observing never becomes allowing on its own.

Commands:
  start        Turn observe mode on.
  status       Show whether observe mode is on and pending candidate count.
  candidates   Refresh + list candidate destinations pending review.
  promote      Promote selected candidates into live allow rules. Tier-1
               FORCED (requires approval). Approved rules are published
               into the same rule source the enforcement daemons read;
               a running daemon applies them on its next policy reload.
               On an exclusive-routing fortress the gate daemon applies
               promoted destinations at the next re-arm (for example
               ${EGRESS_GATE_REPAIR_WITH_STAND_DOWN_COMMAND}); the
               destinations stay listed (promoted, awaiting re-arm)
               until you discard them after re-arming.
  discard      Drop selected (or all) candidates without promoting them.

Run "sanctuary castle-wall observe <command> --help" for command-specific options.
`,
  );
}

async function bestEffortAudit(
  auditLog: AuditLog,
  entry: { identity_id: string; operation: string; details: Record<string, unknown> },
): Promise<void> {
  try {
    await auditLog.appendCritical({
      layer: "l1",
      operation: entry.operation,
      identity_id: entry.identity_id,
      result: "success",
      details: entry.details,
    });
  } catch {
    // Best-effort only: a failed audit append never blocks a Tier-3 CLI verb.
  }
}

interface Bootstrapped {
  fortressPath: string;
  storage: FilesystemStorage;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  observeStore: ObserveStore;
  primary: { identity_id: string; encrypted_private_key: EncryptedPayload };
}

/**
 * Shared bootstrap for every observe subcommand. Mirrors `cli/file-grant.ts`'s
 * bootstrap byte-for-byte in shape. A number return means "the caller should
 * exit with this code without running anything else"; `Bootstrapped` is
 * always an object, so `typeof result === "number"` is a safe discriminant at
 * call sites. This lets a --fortress parse refusal exit with the canonical
 * `FORTRESS_FLAG_USAGE_EXIT_CODE` (2) while every other bootstrap failure
 * here keeps its existing exit 1.
 */
async function bootstrap(
  argv: string[],
  err: Writable,
  env: NodeJS.ProcessEnv,
): Promise<Bootstrapped | number> {
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress value must
  // refuse, never silently resolve the default fortress; observing the wrong
  // fortress's Castle Wall state is a constraint-5 violation.
  const consumedFortress = consumeFlagValue(argv, "--fortress");
  if (consumedFortress.error !== undefined) {
    write(err, `${fortressFlagRefusalText(consumedFortress.error)}\n`);
    return FORTRESS_FLAG_USAGE_EXIT_CODE;
  }
  const fortressPath = resolveFortressArg(consumedFortress.value, env);

  const passphrase = flagValue(argv, "--passphrase") ?? env.SANCTUARY_PASSPHRASE;
  const recoveryKey = env.SANCTUARY_RECOVERY_KEY;
  if (!passphrase && !recoveryKey) {
    write(
      err,
      "Error: sanctuary castle-wall observe requires SANCTUARY_PASSPHRASE, --passphrase, or SANCTUARY_RECOVERY_KEY.\n",
    );
    return 1;
  }

  await mkdir(fortressPath, { recursive: true, mode: 0o700 });
  const stateStoragePath = join(fortressPath, "state");
  const storage = new FilesystemStorage(stateStoragePath);

  const masterKey = await resolveCliMasterKey(storage, {
    ...(passphrase !== undefined ? { passphrase } : {}),
    ...(recoveryKey !== undefined ? { recoveryKey } : {}),
    storagePathHint: fortressPath,
  });

  const identityManager = new IdentityManager(storage, masterKey);
  const loadResult = await identityManager.load();
  if (loadResult.loaded === 0) {
    write(
      err,
      loadResult.total > 0
        ? "Error: identity files found but none could be decrypted. Wrong passphrase?\n"
        : "No identities found in this fortress. Run `sanctuary identity create` first.\n",
    );
    return 1;
  }
  const primary = identityManager.getDefault();
  if (!primary) {
    write(err, "No primary identity set.\n");
    return 1;
  }

  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const observeStore = new ObserveStore(stateStore, {
    identityId: primary.identity_id,
    encryptedPrivateKey: primary.encrypted_private_key,
    identityEncryptionKey: identityEncKey,
  });

  return { fortressPath, storage, masterKey, auditLog, observeStore, primary };
}

async function bootAuditRootHasSegments(fortressPath: string): Promise<boolean> {
  try {
    const entries = await readdir(join(fortressPath, "boot-audit"));
    return entries.length > 0;
  } catch (error) {
    if (isEnoent(error)) return false;
    throw error;
  }
}

async function resolveObserveAuditSources(
  boot: Bootstrapped,
  ctx: ObserveCommandContext,
): Promise<RefreshAuditSourceDescriptor[]> {
  const sources: RefreshAuditSourceDescriptor[] = [
    {
      source_id: "master-audit",
      status: "present",
      auditLog: boot.auditLog,
      instance_id: "operator-master",
    },
  ];

  let tokenRead;
  try {
    tokenRead = await readBootToken(ctx.bootTokenPath ? { path: ctx.bootTokenPath } : {});
  } catch (error) {
    sources.push({
      source_id: "boot-audit",
      status: "read_failed",
      reason: `boot token could not be read: ${(error as Error).message}`,
    });
    return sources;
  }

  if (tokenRead.status !== "ok") {
    if (tokenRead.status === "not-found") {
      sources.push(
        (await bootAuditRootHasSegments(boot.fortressPath))
          ? {
              source_id: "boot-audit",
              status: "read_failed",
              reason: "boot token is absent, but boot-audit segment directories exist",
            }
          : {
              source_id: "boot-audit",
              status: "absent",
              reason: "no boot token is provisioned for this fortress",
            },
      );
      return sources;
    }
    sources.push({
      source_id: "boot-audit",
      status: "read_failed",
      reason:
        tokenRead.status === "bad-mode"
          ? `boot token has insecure permissions (mode ${tokenRead.mode.toString(8)})`
          : `boot token has the wrong length (${tokenRead.length} bytes)`,
    });
    return sources;
  }

  const auditStoragePath = safeModeAuditStoragePath(boot.fortressPath, tokenRead.token);
  const instanceId = basename(auditStoragePath);
  try {
    const auditStat = await stat(auditStoragePath);
    if (!auditStat.isDirectory()) {
      sources.push({
        source_id: "boot-audit",
        status: "read_failed",
        reason: "boot-audit segment path is not a directory",
        instance_id: instanceId,
      });
      return sources;
    }
  } catch (error) {
    if (!isEnoent(error)) {
      sources.push({
        source_id: "boot-audit",
        status: "read_failed",
        reason: `boot-audit segment could not be inspected: ${(error as Error).message}`,
        instance_id: instanceId,
      });
      return sources;
    }
    sources.push(
      (await bootAuditRootHasSegments(boot.fortressPath))
        ? {
            source_id: "boot-audit",
            status: "read_failed",
            reason:
              "current boot-audit segment is absent, but other boot-audit segments exist",
            instance_id: instanceId,
          }
        : {
            source_id: "boot-audit",
            status: "absent",
            reason: "current boot-audit segment has not been created",
            instance_id: instanceId,
          },
    );
    return sources;
  }

  sources.push({
    source_id: "boot-audit",
    status: "present",
    auditLog: new AuditLog(
      new FilesystemStorage(auditStoragePath),
      deriveSafeModeAuditKey(tokenRead.token),
      { consultSplitBoundary: false },
    ),
    instance_id: instanceId,
  });
  return sources;
}

export async function runObserveCommand(
  args: { argv: string[] } & ObserveCommandContext,
): Promise<number> {
  const argv = args.argv;
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;

  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    printUsage(out);
    return 0;
  }

  const command = argv[0]!;
  const rest = argv.slice(1);
  const ctx: ObserveCommandContext = {
    out,
    err,
    env,
    ...(args.bootTokenPath !== undefined ? { bootTokenPath: args.bootTokenPath } : {}),
    ...(args.approvalChannel !== undefined ? { approvalChannel: args.approvalChannel } : {}),
  };

  switch (command) {
    case "start":
      return runObserveStart(rest, ctx);
    case "status":
      return runObserveStatus(rest, ctx);
    case "candidates":
      return runObserveCandidates(rest, ctx);
    case "promote":
      return runObservePromote(rest, ctx);
    case "discard":
      return runObserveDiscard(rest, ctx);
    default:
      write(err, `Unknown observe command: ${command}\n`);
      printUsage(err);
      return 2;
  }
}

export async function runObserveStart(
  argv: string[] = [],
  ctx: ObserveCommandContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;

  const boot = await bootstrap(argv, err, env);
  if (typeof boot === "number") return boot;

  const now = new Date();
  const prior = await boot.observeStore.getState();
  const startedAt = prior.enabled ? prior.started_at : now.toISOString();
  await boot.observeStore.setState({
    enabled: true,
    started_at: startedAt,
    updated_at: now.toISOString(),
  });

  await bestEffortAudit(boot.auditLog, {
    identity_id: boot.primary.identity_id,
    operation: "castle_wall_observe_start",
    details: { started_at: startedAt },
  });

  write(
    out,
    "Observe mode is ON. Your wall is still armed. I am recording the destinations your agent reaches so I can suggest allow rules. Nothing new is being permitted.\n",
  );
  write(
    out,
    "Run your agent normally, then review what it reached with `sanctuary castle-wall observe candidates`.\n",
  );
  return 0;
}

export async function runObserveStatus(
  argv: string[] = [],
  ctx: ObserveCommandContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const json = hasFlag(argv, "--json");

  const boot = await bootstrap(argv, err, env);
  if (typeof boot === "number") return boot;

  const stateRead = await observeSourceState(boot.observeStore);
  if (stateRead.source.status !== "read-and-verified") {
    write(
      err,
      `Error: could not read observe mode state (${stateRead.source.reason}).\n`,
    );
    return 1;
  }
  if (stateRead.state === undefined) {
    write(err, "Error: observe mode state read completed without returning state.\n");
    return 1;
  }
  const census = await observeCandidateCensus(boot.observeStore);
  if (census.source.status !== "read-and-verified") {
    write(
      err,
      `Error: could not read pending candidate census (${census.source.reason}).\n`,
    );
    return 1;
  }
  const candidateCount = census.candidates.length;
  if (candidateCount === 0 && census.emptyVerified === undefined) {
    const pendingCandidateWitness = `Pending candidates: ${formatPendingCandidateCount(census)}`;
    write(err, `Error: ${pendingCandidateWitness}; the empty candidate set was not verified.\n`);
    return 1;
  }
  const lastRefresh = await boot.observeStore.getLastRefreshOutcome();
  const structuralUndeterminedReason = await storeOnlyStructuralUndeterminedReason(boot.fortressPath);
  const claim = candidateStoreClaim(candidateCount, lastRefresh, structuralUndeterminedReason);

  if (json) {
    write(
      out,
      JSON.stringify(
        {
          observe_mode: stateRead.state.enabled ? "on" : "off",
          started_at: stateRead.state.started_at,
          pending_candidates: candidateCount,
          candidate_status: claim.status,
          definitive_empty: claim.definitiveEmpty,
          store_state_only: true,
          last_refresh: lastRefreshForJson(lastRefresh),
          gate_denials: gateDenialsForJson(structuralUndeterminedReason),
          ...(claim.undeterminedReason !== null
            ? { undetermined_reason: claim.undeterminedReason }
            : {}),
        },
        null,
        2,
      ) + "\n",
    );
    return 0;
  }

  write(
    out,
    stateRead.state.enabled
      ? `Observe mode: ON (since ${stateRead.state.started_at})\n`
      : "Observe mode: OFF\n",
  );
  writeStoreCandidateClaim(out, candidateCount, lastRefresh, claim);
  return 0;
}

export async function runObserveCandidates(
  argv: string[] = [],
  ctx: ObserveCommandContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;

  const json = hasFlag(argv, "--json");
  const noRefresh = hasFlag(argv, "--no-refresh");

  const boot = await bootstrap(argv, err, env);
  if (typeof boot === "number") return boot;

  let sourceReads: ObserveAuditSourceReadOutcome[] = [];
  let quarantinedSources: ObserveQuarantinedSourceState[] = [];
  let refreshAttempted = false;
  let refreshComplete = false;
  let refreshIncompleteReason: string | null = noRefresh
    ? "refresh was skipped, so audit-source reads were not witnessed"
    : null;

  if (!noRefresh) {
    refreshAttempted = true;
    const producerKey = await loadFortressProducerKey(boot.fortressPath);
    if (producerKey.status === "unreadable") {
      write(
        err,
        `Error: could not refresh candidates -- Castle Wall audit-producer key is unreadable (${producerKey.reason}). ` +
          "Nothing was changed. Refusing to fold agent-scoped candidates without verified producer attribution.\n",
      );
      return 1;
    }
    let outcome;
    let lockHolderDescription = "";
    try {
      outcome = await refreshCandidatesFromAudit({
        auditLog: boot.auditLog,
        auditSources: await resolveObserveAuditSources(boot, ctx),
        store: boot.observeStore,
        readAllowlist: () => readAllowlistForRefresh(boot.fortressPath),
        lock: observeRefreshFileLock(boot.fortressPath, (holder) => {
          lockHolderDescription = holder;
        }),
        now: new Date(),
        pinnedProducerKeyB64url:
          producerKey.status === "present" ? producerKey.keyB64url : null,
        subjectFortressId: fortressIdFromStoragePath(boot.fortressPath),
      });
    } catch (error) {
      // streamVerifiedChain's strict verification failed: the audit chain
      // does not verify. Nothing was folded or written (all refresh writes
      // happen only after a clean verified pass); fail loud, never fold
      // over an unverified chain.
      write(
        err,
        `Error: could not refresh candidates -- the audit log failed verification (${(error as Error).message}). ` +
          "Nothing was changed. Run `sanctuary castle-wall audit-verify` to investigate.\n",
      );
      return 1;
    }
    if (outcome.status === "source_read_incomplete") {
      sourceReads = outcome.source_reads;
      quarantinedSources = outcome.quarantined_sources;
      refreshIncompleteReason = outcome.reason;
      write(
        err,
        `Warning: observe could not read every audit source (${outcome.reason}). ` +
          "No candidate-store changes were made; an empty listing below is UNDETERMINED, not verified empty.\n",
      );
    }
    if (outcome.status === "refresh_in_progress") {
      write(
        err,
        "Error: another `observe candidates` refresh holds this fortress's refresh lock" +
          (lockHolderDescription ? ` (${lockHolderDescription})` : "") +
          ". Nothing was changed (a concurrent double-fold would inflate the Seen counts). " +
          "If the holder is still running, wait for it and re-run. This lock is never broken " +
          "automatically.\n",
      );
      return 1;
    }
    if (outcome.status === "allowlist_unverified") {
      write(
        err,
        `Error: could not refresh candidates -- the live allowlist manifest did not verify (${outcome.reason}). ` +
          "Nothing was changed. Refusing to fold with an unverifiable policy; investigate the egress manifest before reviewing candidates.\n",
      );
      return 1;
    }
    if (outcome.status === "refreshed") {
      sourceReads = outcome.source_reads;
      quarantinedSources = outcome.quarantined_sources;
      refreshComplete = true;
    }
    if (outcome.status === "refreshed" && outcome.removed_now_allowed > 0) {
      write(
        out,
        `Removed ${outcome.removed_now_allowed} candidate(s) your policy now permits (already-allowed destinations are never pending review).\n`,
      );
    }
  }

  const census = await observeCandidateCensus(boot.observeStore);
  if (census.source.status !== "read-and-verified") {
    write(
      err,
      `Error: could not read candidate census (${census.source.reason}).\n`,
    );
    return 1;
  }
  const candidates = census.candidates;

  // Round-3 R2(b): on an exclusive-routing fortress, a candidate whose
  // destination is already covered by an observe-promoted, CURRENT-gate-uid
  // scoped rule was promoted and is awaiting the re-arm that loads the gate's
  // rules snapshot (F2 deliberately keeps such rows visible; without this
  // marking they were indistinguishable from never-promoted rows). Computed
  // before BOTH output modes so scripted `--json` consumers see it too
  // (round-3 L2: additive `promoted_awaiting_rearm` field, present only when
  // true). Best-effort: a malformed marker or unverifiable allowlist skips
  // the marking with a warning (the listing itself still works; promote
  // refuses loud on the same states).
  let awaitingRearmRules: readonly AllowlistRule[] = [];
  let awaitingRearmGateUid: number | null = null;
  let exclusiveGateDenialsUnavailable = false;
  let routingWitnessComplete = true;
  try {
    const marker = await loadExclusiveRoutingMarker(boot.fortressPath);
    if (marker !== null) {
      exclusiveGateDenialsUnavailable = true;
      if (candidates.length > 0) {
        const allowlist = await readAllowlistForRefresh(boot.fortressPath);
        if (allowlist.status === "ok") {
          awaitingRearmRules = allowlist.rules;
          awaitingRearmGateUid = marker.gate_uid;
        } else {
          write(err, "Warning: could not read the verified allowlist; the promoted-awaiting-re-arm marking is unavailable for this listing.\n");
        }
      }
    }
  } catch {
    routingWitnessComplete = false;
    write(err, "Warning: the exclusive-routing marker is unreadable; the promoted-awaiting-re-arm marking is unavailable for this listing.\n");
  }
  const isAwaitingRearm = (candidate: CandidateObservation): boolean =>
    awaitingRearmGateUid !== null &&
    candidatePromotedAwaitingRearm(awaitingRearmRules, candidate, awaitingRearmGateUid);
  const rows = candidates.map((candidate) =>
    isAwaitingRearm(candidate) ? { ...candidate, promoted_awaiting_rearm: true } : candidate,
  );
  const completeReadWitness =
    refreshAttempted &&
    refreshComplete &&
    routingWitnessComplete &&
    sourceReads.every(sourceReadSupportsDefinitiveEmpty) &&
    quarantinedSources.length === 0;
  const canClaimEmpty =
    candidates.length === 0 && completeReadWitness && !exclusiveGateDenialsUnavailable;
  const undeterminedReason = candidateListingUndeterminedReason({
    noRefresh,
    refreshIncompleteReason,
    routingWitnessComplete,
    exclusiveGateDenialsUnavailable,
  });
  let rowsForJson = rows;
  if (canClaimEmpty) {
    if (census.emptyVerified === undefined) {
      write(err, "Error: candidate census could not verify the empty candidate set.\n");
      return 1;
    }
    rowsForJson = claimFromVerifiedEmpty(census.emptyVerified, rows);
  }

  if (json) {
    write(
      out,
      JSON.stringify(
        {
          status:
            candidates.length > 0
              ? completeReadWitness
                ? "populated"
                : "partial"
              : canClaimEmpty
                ? "empty_verified"
                : "undetermined",
          definitive_empty: canClaimEmpty,
          candidates: rowsForJson,
          source_reads: sourceReads,
          quarantined_sources: quarantinedSources,
          gate_denials: exclusiveGateDenialsUnavailable
            ? {
                status: "structurally_unavailable",
                reason: EXCLUSIVE_GATE_DENIALS_UNAVAILABLE,
              }
            : { status: "not_applicable" },
          ...(undeterminedReason !== null ? { undetermined_reason: undeterminedReason } : {}),
        },
        null,
        2,
      ) + "\n",
    );
    return 0;
  }

  if (exclusiveGateDenialsUnavailable) {
    write(out, `Exclusive routing: ${EXCLUSIVE_GATE_DENIALS_UNAVAILABLE}; this listing covers master-audit and boot-audit only.\n`);
  }
  if (candidates.length > 0 && !completeReadWitness) {
    write(out, "UNDETERMINED: observe could not verify every source read, so this candidate listing may be incomplete.\n");
    for (const line of sourceWitnessLines(sourceReads, quarantinedSources)) write(out, `${line}\n`);
  }

  if (candidates.length === 0) {
    if (canClaimEmpty) {
      if (census.emptyVerified === undefined) {
        write(err, "Error: candidate census could not verify the empty candidate set.\n");
        return 1;
      }
      write(
        out,
        claimFromVerifiedEmpty(
          census.emptyVerified,
          "No candidates. Turn on observe mode (`sanctuary castle-wall observe start`), run your agent, then re-run this command.\n",
        ),
      );
    } else {
      write(
        out,
        `UNDETERMINED: no candidates are listed, but this is not verified empty (${undeterminedReason ?? "source reads were not complete"}).\n`,
      );
      for (const line of sourceWitnessLines(sourceReads, quarantinedSources)) write(out, `${line}\n`);
    }
    return 0;
  }

  const col = (value: string, width: number): string => `${value.padEnd(width)}  `;
  write(out, `${col("Destination", 22)}${col("Agent", 15)}${col("Times", 5)}${col("First seen", 20)}${col("Last seen", 20)}Note\n`);
  for (const candidate of candidates) {
    const notes: string[] = [];
    if (candidate.exfil_risk) notes.push("EXFIL-RISK, not pre-selected");
    if (isAwaitingRearm(candidate)) {
      notes.push("promoted, awaiting re-arm");
    }
    write(
      out,
      `${col(destinationLabel(candidate), 22)}${col(candidate.agent_template, 15)}${col(
        String(candidate.times_seen),
        5,
      )}${col(candidate.first_seen, 20)}${col(candidate.last_seen, 20)}${notes.join("; ")}\n`,
    );
  }
  write(
    out,
    "\nPromote with: sanctuary castle-wall observe promote --destination <host:port> [--destination ...] | --all\n",
  );
  return 0;
}

const EXCLUSIVE_GATE_DENIALS_UNAVAILABLE =
  "gate denials are structurally unavailable as an observe source";

function candidateListingUndeterminedReason(input: {
  noRefresh: boolean;
  refreshIncompleteReason: string | null;
  routingWitnessComplete: boolean;
  exclusiveGateDenialsUnavailable: boolean;
}): string | null {
  if (input.noRefresh) return "refresh was skipped, so audit-source reads were not witnessed";
  if (input.refreshIncompleteReason) return input.refreshIncompleteReason;
  if (!input.routingWitnessComplete) return "exclusive-routing state could not be read";
  if (input.exclusiveGateDenialsUnavailable) return EXCLUSIVE_GATE_DENIALS_UNAVAILABLE;
  return null;
}

function sourceWitnessLines(
  sourceReads: readonly ObserveAuditSourceReadOutcome[],
  quarantinedSources: readonly ObserveQuarantinedSourceState[],
): string[] {
  const lines = sourceReads.map((source) => {
    if (source.status === "read_ok") {
      return `Source ${source.source_id}: read_ok (${source.flow_events} flow event(s), ${source.candidate_rows} candidate row(s)).`;
    }
    if (source.status === "absent") {
      return `Source ${source.source_id}: absent (${source.reason}).`;
    }
    return `Source ${source.source_id}: read_failed (${source.failure}: ${source.reason}).`;
  });
  for (const source of quarantinedSources) {
    lines.push(`Source state ${source.key}: quarantined (${source.reason}).`);
  }
  return lines;
}

type StoreCandidateClaimStatus = "populated" | "empty_verified" | "undetermined";

interface StoreCandidateClaim {
  status: StoreCandidateClaimStatus;
  definitiveEmpty: boolean;
  undeterminedReason: string | null;
}

/**
 * R2 predicate shared by every definitive-empty gate: a source read supports a
 * verified-empty claim when it was read_ok, or when it is absent AND has never
 * contributed (the refresh layer downgrades a previously-contributing absent
 * source to missing_after_contribution, so a plain "absent" here is R2-valid).
 * All commands (candidates, status, promote) MUST share this predicate so two
 * surfaces can never disagree about the same store state.
 */
function sourceReadSupportsDefinitiveEmpty(source: { status: string }): boolean {
  return source.status === "read_ok" || source.status === "absent";
}

function lastRefreshSupportsDefinitiveEmpty(lastRefresh: ObserveLastRefreshOutcome | null): boolean {
  return (
    lastRefresh !== null &&
    lastRefresh.status === "refreshed" &&
    lastRefresh.source_reads.length > 0 &&
    lastRefresh.source_reads.every(sourceReadSupportsDefinitiveEmpty) &&
    lastRefresh.quarantined_sources.length === 0
  );
}

function refreshSourceStatusSummary(lastRefresh: ObserveLastRefreshOutcome): string {
  const statuses = lastRefresh.source_reads
    .map((source) => `${source.source_id}=${source.status}`)
    .join(", ");
  return statuses.length > 0 ? statuses : "no source reads recorded";
}

function lastRefreshSummary(lastRefresh: ObserveLastRefreshOutcome | null): string {
  if (lastRefresh === null) return "last refresh: none";
  return `last refresh at ${lastRefresh.refreshed_at}: ${lastRefresh.status} (${refreshSourceStatusSummary(lastRefresh)})`;
}

function lastRefreshUndeterminedReason(lastRefresh: ObserveLastRefreshOutcome | null): string {
  if (lastRefresh === null) return "no observe refresh outcome is recorded";
  if (lastRefresh.status !== "refreshed") {
    return `last refresh at ${lastRefresh.refreshed_at} was ${lastRefresh.status}` +
      (lastRefresh.reason ? ` (${lastRefresh.reason})` : "");
  }
  if (lastRefresh.quarantined_sources.length > 0) {
    return `last refresh at ${lastRefresh.refreshed_at} had quarantined observe source state`;
  }
  return `last refresh at ${lastRefresh.refreshed_at} did not read (or validly-absent) every source (${refreshSourceStatusSummary(lastRefresh)})`;
}

function candidateStoreClaim(
  candidateCount: number,
  lastRefresh: ObserveLastRefreshOutcome | null,
  structuralUndeterminedReason: string | null = null,
): StoreCandidateClaim {
  if (candidateCount > 0) {
    return { status: "populated", definitiveEmpty: false, undeterminedReason: null };
  }
  if (structuralUndeterminedReason !== null) {
    return {
      status: "undetermined",
      definitiveEmpty: false,
      undeterminedReason: structuralUndeterminedReason,
    };
  }
  if (lastRefreshSupportsDefinitiveEmpty(lastRefresh)) {
    return { status: "empty_verified", definitiveEmpty: true, undeterminedReason: null };
  }
  return {
    status: "undetermined",
    definitiveEmpty: false,
    undeterminedReason: lastRefreshUndeterminedReason(lastRefresh),
  };
}

async function storeOnlyStructuralUndeterminedReason(fortressPath: string): Promise<string | null> {
  try {
    return (await loadExclusiveRoutingMarker(fortressPath)) !== null
      ? EXCLUSIVE_GATE_DENIALS_UNAVAILABLE
      : null;
  } catch {
    return "exclusive-routing state could not be read";
  }
}

function gateDenialsForJson(structuralUndeterminedReason: string | null): unknown {
  return structuralUndeterminedReason === EXCLUSIVE_GATE_DENIALS_UNAVAILABLE
    ? { status: "structurally_unavailable", reason: EXCLUSIVE_GATE_DENIALS_UNAVAILABLE }
    : { status: "not_applicable" };
}

function lastRefreshForJson(lastRefresh: ObserveLastRefreshOutcome | null): unknown {
  if (lastRefresh === null) return { status: "none" };
  return {
    status: lastRefresh.status,
    refreshed_at: lastRefresh.refreshed_at,
    source_reads: lastRefresh.source_reads,
    quarantined_sources: lastRefresh.quarantined_sources,
    ...(lastRefresh.definitive_empty !== undefined
      ? { definitive_empty: lastRefresh.definitive_empty }
      : {}),
    ...(lastRefresh.reason !== undefined ? { reason: lastRefresh.reason } : {}),
  };
}

function writeStoreCandidateClaim(
  out: Writable,
  candidateCount: number,
  lastRefresh: ObserveLastRefreshOutcome | null,
  claim: StoreCandidateClaim = candidateStoreClaim(candidateCount, lastRefresh),
): void {
  if (candidateCount > 0) {
    write(out, `Pending candidates in store: ${candidateCount} (store-state-only; ${lastRefreshSummary(lastRefresh)}).\n`);
    return;
  }
  if (claim.status === "empty_verified") {
    write(
      out,
      `Pending candidates in store: 0 (store-state-only; ${lastRefreshSummary(lastRefresh)}; all sources read_ok or validly absent).\n`,
    );
    return;
  }
  write(
    out,
    `UNDETERMINED: pending candidates in store: 0, but this is not verified empty (${claim.undeterminedReason ?? lastRefreshUndeterminedReason(lastRefresh)}).\n`,
  );
  write(out, `Store-state-only witness: ${lastRefreshSummary(lastRefresh)}.\n`);
}

function writePromoteNoSelectionJson(
  out: Writable,
  candidateCount: number,
  lastRefresh: ObserveLastRefreshOutcome | null,
  rescopeChecked: boolean,
  structuralUndeterminedReason: string | null = null,
): void {
  const claim = candidateStoreClaim(candidateCount, lastRefresh, structuralUndeterminedReason);
  write(
    out,
    JSON.stringify(
      {
        status: claim.status === "empty_verified" ? "nothing_to_promote_verified" : claim.status,
        nothing_to_promote: claim.definitiveEmpty,
        pending_candidates: candidateCount,
        store_state_only: true,
        rescope_checked: rescopeChecked,
        last_refresh: lastRefreshForJson(lastRefresh),
        gate_denials: gateDenialsForJson(structuralUndeterminedReason),
        ...(claim.undeterminedReason !== null
          ? { undetermined_reason: claim.undeterminedReason }
          : {}),
      },
      null,
      2,
    ) + "\n",
  );
}

function writePromoteNoSelectionText(
  out: Writable,
  candidateCount: number,
  lastRefresh: ObserveLastRefreshOutcome | null,
  rescopeChecked: boolean,
  structuralUndeterminedReason: string | null = null,
): void {
  const claim = candidateStoreClaim(candidateCount, lastRefresh, structuralUndeterminedReason);
  if (claim.status === "empty_verified") {
    write(
      out,
      `Nothing to promote (store-state-only; ${lastRefreshSummary(lastRefresh)}; all sources read_ok or validly absent).` +
        (rescopeChecked ? " No promoted rules need re-scoping.\n" : "\n"),
    );
    return;
  }
  write(
    out,
    `UNDETERMINED: no candidates are currently stored, but this is not verified empty (${claim.undeterminedReason ?? lastRefreshUndeterminedReason(lastRefresh)}).` +
      (rescopeChecked ? " No promoted rules need re-scoping in the verified manifest.\n" : "\n"),
  );
  write(out, `Store-state-only witness: ${lastRefreshSummary(lastRefresh)}.\n`);
}

/** Lockfile basename for the cross-process refresh mutual exclusion (Codex gate BLOCKER; see castle-wall/observe/refresh.ts guarantee 2). Lives directly under the fortress root (mode 0700). */
const OBSERVE_REFRESH_LOCK_FILE = ".observe-refresh.lock";


/** True iff `pid` names a live process this user could signal (mirrors the audit write-lock's stale-holder detection in operational/audit-log.ts). */
function isLockHolderAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM: the process exists but belongs to another user -- still alive.
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** Best-effort description of who holds the refresh lock, for the operator-facing contention message. Never throws. */
async function describeLockHolder(lockPath: string): Promise<string> {
  try {
    const parsed = JSON.parse(await readFile(lockPath, "utf8")) as {
      pid?: unknown;
      acquired_at?: unknown;
    };
    const pid = typeof parsed.pid === "number" ? parsed.pid : null;
    const at = typeof parsed.acquired_at === "string" ? parsed.acquired_at : "an unknown time";
    if (pid === null) return `held since ${at} by an unrecorded process`;
    return isLockHolderAlive(pid)
      ? `held since ${at} by running process ${pid}`
      : `held since ${at} by process ${pid}, which is NO LONGER RUNNING -- this lock is almost ` +
          `certainly stale from a crashed run; verify with \`ps -p ${pid}\` and then remove ${lockPath}`;
  } catch {
    return `present but unreadable at ${lockPath}`;
  }
}

/**
 * Cross-process refresh lock: O_EXCL create with pid metadata, NEVER
 * auto-broken. Two concurrent `observe candidates` invocations are separate
 * processes, so the in-process lock cannot cover them; whoever loses the
 * O_EXCL race gets a clean "another refresh is in progress" abort instead of
 * a double-folded count.
 *
 * WHY no automatic stale-lock breaking (Codex two-family gate round 2,
 * HIGH): any read-check-unlink-retry scheme has a TOCTOU -- a slow breaker
 * that read the stale file before a peer broke it can unlink the peer's
 * FRESHLY-created lock, and then two refreshes run concurrently, which is
 * exactly the double-count this lock exists to prevent. A lock left by a
 * crashed run is instead surfaced with exact operator guidance (holder pid,
 * liveness, the file to remove); removal is a deliberate human action, never
 * a race. Fail toward not folding, never toward folding twice.
 */
export function observeRefreshFileLock(
  fortressPath: string,
  onContention?: (holderDescription: string) => void,
): RefreshLock {
  return fortressExclusiveFileLock(join(fortressPath, OBSERVE_REFRESH_LOCK_FILE), onContention);
}

/**
 * The promote publish lock (round-3 R1, WIDENED round-4 C1): now the shared
 * fortress EGRESS-POLICY WRITER lock (`.egress-policy.lock`,
 * `castle-wall/provision/lockfile.ts`) that EVERY mutator of the shared
 * `policy/egress/rules/` + `manifest.json` pair serializes on -- the
 * provisioning publish/scrub/restore paths acquire the same lock, so a
 * provision revoke can never interleave with a promote's CAS-and-publish
 * window (the CAS sees only manifest.json bytes, which provisioning never
 * touches). Held by `promoteCandidates` across the publish-time verified
 * re-read, the digest compare-and-set, and the publish + orphan-cleanup.
 * The loser aborts loud (`publish_in_progress`) with nothing published.
 */
export function observePromoteFileLock(
  fortressPath: string,
  onContention?: (holderDescription: string) => void,
): RefreshLock {
  return egressPolicyWriterLock(fortressPath, onContention);
}

/** Shared O_EXCL fortress lockfile implementation behind both locks above. */
function fortressExclusiveFileLock(
  lockPath: string,
  onContention?: (holderDescription: string) => void,
): RefreshLock {
  return {
    async acquire() {
      try {
        const handle = await open(lockPath, "wx", 0o600);
        try {
          await handle.writeFile(
            JSON.stringify({ pid: process.pid, acquired_at: new Date().toISOString() }),
          );
          await handle.sync();
        } finally {
          await handle.close();
        }
        return async () => {
          try {
            await rm(lockPath, { force: true });
          } catch (releaseError) {
            // Round-3 L1: never let a failed unlink throw over the caller's
            // real outcome (a completed promote/refresh must not report as
            // failed). Name the stranded lock so the operator can remove it
            // before the next run reports it held.
            process.stderr.write(
              `Warning: could not remove the lock file ${lockPath} (${(releaseError as Error).message}). ` +
                "The operation itself completed; remove the file manually or the next run will report it as held.\n",
            );
          }
        };
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        if (onContention) onContention(await describeLockHolder(lockPath));
        return null;
      }
    },
  };
}

/**
 * Read + verify the live allowlist for the refresh chokepoint's
 * allowlist-aware fold (see castle-wall/observe/refresh.ts).
 *
 * A genuinely-absent policy is a verified-EMPTY allowlist (fresh install /
 * pre-provision fortress: there are no allow rules, so the filter is
 * vacuous and `observe candidates` keeps working). Anything that EXISTS but
 * cannot be verified -- a manifest with no pinned key to check it against,
 * a truncated pinned key, a bad signature, a failed rule hash -- is
 * `unverified`, which aborts the refresh loud (never a silent unfiltered
 * fold; WHAT THESE TOOLS MUST NEVER DO #5).
 */
export async function readAllowlistForRefresh(fortressPath: string): Promise<RefreshAllowlistRead> {
  const egressDir = join(fortressPath, "policy", "egress");

  let pinnedPublicKey: Uint8Array;
  try {
    const pub = await readFile(join(fortressPath, CASTLE_PINNED_PUBKEY));
    if (pub.length !== ED25519_PUBLIC_KEY_BYTES) {
      return {
        status: "unverified",
        reason: `pinned public key must be 32 bytes (found ${pub.length})`,
      };
    }
    pinnedPublicKey = new Uint8Array(pub);
  } catch (error) {
    if (!isEnoent(error)) {
      return { status: "unverified", reason: `pinned public key unreadable: ${(error as Error).message}` };
    }
    // No pinned key. If no manifest exists either, this fortress simply has
    // no live allowlist yet -- a verified-empty ruleset. If a manifest DOES
    // exist with no key to verify it, that is unverifiable, not empty.
    try {
      await readFile(join(egressDir, "manifest.json"));
    } catch (manifestError) {
      if (isEnoent(manifestError)) return { status: "ok", rules: [] };
      return {
        status: "unverified",
        reason: `manifest unreadable while checking for an unverifiable policy: ${(manifestError as Error).message}`,
      };
    }
    return {
      status: "unverified",
      reason: "an egress manifest exists but there is no pinned Castle Wall public key to verify it against",
    };
  }

  const read = await readVerifiedManifest(egressDir, pinnedPublicKey);
  if (read.status === "tampered") {
    return { status: "unverified", reason: read.reason };
  }
  return { status: "ok", rules: read.status === "ok" ? read.rules : [] };
}

class CastleWallObservePromptApprovalChannel implements ApprovalChannel {
  async requestApproval(request: ApprovalRequest): Promise<ApprovalResponse> {
    write(process.stderr, formatApprovalPrompt(request));

    if (!process.stdin.isTTY) {
      return {
        decision: "deny",
        decided_at: new Date().toISOString(),
        decided_by: "stderr:non-interactive",
      };
    }

    const rl = createInterface({ input: process.stdin, output: process.stderr });
    try {
      const answer = await rl.question("Approve promoting these candidates into live allow rules? [y/N] ");
      const approved = /^y(es)?$/i.test(answer.trim());
      return {
        decision: approved ? "approve" : "deny",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      };
    } finally {
      rl.close();
    }
  }
}

function formatApprovalPrompt(request: ApprovalRequest): string {
  const contextLines = Object.entries(request.context)
    .map(([k, v]) => `  ${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`)
    .join("\n");
  return (
    "\nSanctuary: Tier-1 approval required\n" +
    `  Operation: ${request.operation}\n` +
    `  Reason:    ${request.reason}\n` +
    "  Details:\n" +
    contextLines +
    "\n"
  );
}

export class FilesystemManifestStorage implements ManifestStorage {
  private readonly rulesDir: string;
  /**
   * The rule filenames the PREVIOUS promote-owned manifest referenced,
   * captured from `manifest.json` before this publish overwrites it. This is
   * the publisher's OWNERSHIP LEDGER (fix-round F4): `listRules` returns only
   * these files, so `publishSignedManifest`'s orphan-cleanup can only ever
   * delete a file a previous promote itself published and this publish
   * stopped referencing. Ownership by MEMBERSHIP, not by name: an
   * operator-authored file in the shared `rules/` directory survives even if
   * it happens to be named `derived-observe-*.json`, and provisioning's
   * `provisioned-<harness>-*` files are structurally untouchable (the
   * F-REVOKE blanket-scrub class). Absent/unreadable previous manifest =>
   * owns nothing => cleans nothing (the safe direction).
   */
  private previousOwned: Set<string> | null = null;

  constructor(private readonly egressDir: string) {
    this.rulesDir = join(egressDir, "rules");
  }

  private async captureOwnedOnce(): Promise<void> {
    if (this.previousOwned !== null) return;
    const owned = new Set<string>();
    try {
      const raw = await readFile(join(this.egressDir, "manifest.json"), "utf8");
      const parsed = JSON.parse(raw) as { manifest?: { rules?: Array<{ file?: unknown }> } };
      for (const entry of parsed.manifest?.rules ?? []) {
        if (typeof entry.file === "string" && !entry.file.includes("/") && !entry.file.includes("\\")) {
          owned.add(entry.file);
        }
      }
    } catch {
      // No previous manifest (fresh install) or unreadable/corrupt: own
      // nothing, clean nothing. Promote itself verifies the manifest through
      // `readVerifiedManifest` and aborts on tamper long before publishing;
      // this ledger only bounds DELETION and errs toward deleting less.
    }
    this.previousOwned = owned;
  }

  async writeRule(filename: string, bytes: Uint8Array): Promise<void> {
    // 2026-07-27 enforcement-reach fix (Option A): rule files are written
    // into the `rules/` SUBDIRECTORY, the ONE TRUE rule source every real
    // consumer reads -- the macOS signing daemon's composer scans
    // `policy/egress/rules/` (`runtime/macos-daemon.ts` loadManifestState),
    // provisioning publishes there (`provision/egress.ts` egressRulesDir),
    // and the Linux enforcer resolves each manifest entry as
    // `policy_dir/rules/<entry.file>` (castle-wall-daemon manifest/store.rs).
    // The previous writer put files BESIDE manifest.json, a location no
    // enforcement path reads, so promoted destinations stayed denied while
    // the CLI reported success. `readVerifiedManifest` reads the same
    // `rules/` location, so the published tree stays self-consistent.
    await this.captureOwnedOnce();
    await mkdir(this.rulesDir, { recursive: true, mode: 0o700 });
    await writeFile(join(this.rulesDir, filename), bytes, { mode: 0o600 });
  }

  async atomicRenameManifest(bytes: Uint8Array): Promise<void> {
    // The signed manifest itself stays at `policy/egress/manifest.json`
    // (the location the Linux enforcer and the transparency emitter read).
    // Capture the previous manifest's membership BEFORE overwriting it (the
    // zero-rule publish path reaches here without any writeRule call).
    await this.captureOwnedOnce();
    await mkdir(this.egressDir, { recursive: true, mode: 0o700 });
    const tmpPath = join(
      this.egressDir,
      `.manifest.json.${process.pid}.${randomBytes(6).toString("hex")}.tmp`,
    );
    await writeFile(tmpPath, bytes, { mode: 0o600 });
    await rename(tmpPath, join(this.egressDir, "manifest.json"));
  }

  async listRules(): Promise<string[]> {
    // The ownership ledger (see `previousOwned`): only files the PREVIOUS
    // promote-owned manifest referenced, and only those still present in the
    // shared rules/ directory. `publishSignedManifest` removes the listed
    // files its new manifest no longer references -- exactly the
    // promote-owned delta, nothing else.
    await this.captureOwnedOnce();
    try {
      const names = await readdir(this.rulesDir);
      return names.filter((name) => this.previousOwned!.has(name));
    } catch (error) {
      if (isEnoent(error)) return [];
      throw error;
    }
  }

  async removeRule(filename: string): Promise<void> {
    await rm(join(this.rulesDir, filename), { force: true });
  }
}

/**
 * Read + CRYPTOGRAPHICALLY VERIFY the currently-published signed manifest so
 * promote can carry the existing ruleset forward into the re-signed manifest
 * WITHOUT laundering an unverified on-disk rule (two-family gate FIX 1).
 *
 * FAIL-CLOSED: this uses the shipped `verifyManifestSignature` (Ed25519
 * against the pinned public key) + `verifyAndParseRules` (per-rule sha256 +
 * `validateRule`). Any failure -- unreadable/corrupt manifest JSON, a bad
 * signature, a missing referenced rule file, a sha256 mismatch, or a rule
 * that fails validateRule -- returns `tampered`, which makes promote ABORT
 * and change nothing. We NEVER silently drop-and-continue on a bad manifest:
 * a tampered manifest (e.g. an attacker who can write the egress dir plants a
 * broad rule the daemon already rejects for a bad signature) must stop the
 * promote, never get re-signed under the good pinned key.
 *
 * `digest` is a compare-and-set token (sha256 of the raw manifest.json
 * bytes) promote re-checks immediately before publish to close the
 * read-then-publish lost-update window (FIX 2).
 *
 * A genuinely-absent manifest (fresh install) is `absent`, not tampered.
 */
export async function readVerifiedManifest(
  egressDir: string,
  pinnedPublicKey: Uint8Array,
): Promise<VerifiedManifestRead> {
  const manifestPath = join(egressDir, "manifest.json");
  let rawBytes: Buffer;
  try {
    rawBytes = await readFile(manifestPath);
  } catch (error) {
    if (isEnoent(error)) return { status: "absent" };
    return { status: "tampered", reason: `manifest unreadable: ${(error as Error).message}` };
  }

  const digest = createHash("sha256").update(rawBytes).digest("hex");

  let signed: SignedManifest;
  try {
    signed = JSON.parse(rawBytes.toString("utf8")) as SignedManifest;
  } catch (error) {
    return { status: "tampered", reason: `manifest is not valid JSON: ${(error as Error).message}` };
  }
  if (!signed || typeof signed !== "object" || !signed.manifest || !signed.signature) {
    return { status: "tampered", reason: "manifest is missing its manifest/signature envelope" };
  }

  const sigResult = verifyManifestSignature(signed, pinnedPublicKey);
  if (!sigResult.ok) {
    return { status: "tampered", reason: `manifest signature verification failed: ${sigResult.error}` };
  }

  const identityIssues = preflightManifestRuleEntries(signed.manifest.rules);
  if (identityIssues.length > 0) {
    return {
      status: "tampered",
      reason: `manifest rule identity preflight failed: ${identityIssues.join("; ")}`,
    };
  }

  // Load every referenced rule file's bytes, keyed by the manifest's own
  // `file` field, then re-verify sha256 + validateRule via the shipped
  // verifier. A missing file is a tamper, not a silent drop.
  //
  // 2026-07-27 enforcement-reach fix (Option A): rule files resolve under the
  // `rules/` subdirectory, matching the writer (`FilesystemManifestStorage`),
  // the daemon composer, and the Linux enforcer's `policy_dir/rules/<file>`
  // resolution. A referenced file found ONLY at the legacy location (beside
  // manifest.json, where the pre-fix promote wrote) is an EXPLICIT REFUSAL
  // naming the remedy, never a silent fallback read: adopting the legacy
  // bytes automatically could arm a template-scoped promoted rule on an
  // exclusive-mode fortress, where the compose-time assertion would brick
  // policy reload. Fail closed; the operator decides.
  const ruleFiles = new Map<string, Uint8Array>();
  for (const entry of signed.manifest.rules) {
    try {
      const bytes = await readFile(join(egressDir, "rules", entry.file));
      ruleFiles.set(entry.file, new Uint8Array(bytes));
    } catch (error) {
      if (isEnoent(error)) {
        let legacyExists = false;
        try {
          await readFile(join(egressDir, entry.file));
          legacyExists = true;
        } catch {
          // Genuinely missing everywhere: fall through to the tamper below.
        }
        if (legacyExists) {
          return {
            status: "tampered",
            reason:
              `referenced rule file ${entry.file} sits at the LEGACY location ${join(egressDir, entry.file)} ` +
              `(written by a pre-2026-07-27 promote, which published to a directory no enforcement path reads). ` +
              `Refusing to read it from there. Remedy: to adopt the rule, move the file into ${join(egressDir, "rules")}/ ` +
              `(on an exclusive-routing fortress prefer deleting the legacy rule files AND manifest.json, then re-running ` +
              `promote, so the rule is re-synthesized with the gate-scoped shape the exclusive composer requires); ` +
              `to abandon it, delete the legacy rule files and manifest.json.`,
          };
        }
        // Fix-round F8 (remedy discoverability): a promoted rule file deleted
        // out of rules/ used to surface as a bare "unreadable" tamper with no
        // way forward. Name the recovery: the promote-owned state is
        // manifest.json plus the files it references, and resetting it does
        // not touch enforcement (the daemons compose from the rules directory
        // itself, which still holds every file you did not delete).
        return {
          status: "tampered",
          reason:
            `referenced rule file ${entry.file} is missing from ${join(egressDir, "rules")} ` +
            `(the promote-signed manifest references it, but the file no longer exists). ` +
            `Remedy: if the deletion was deliberate, delete ${join(egressDir, "manifest.json")} as well ` +
            `to reset the promote-owned state, then re-promote what you still want; enforcement is ` +
            `unaffected by that reset (the daemons compose from the rules directory itself). ` +
            `If it was not deliberate, investigate before promoting again.`,
        };
      }
      return {
        status: "tampered",
        reason: `referenced rule file ${entry.file} is unreadable: ${(error as Error).message}`,
      };
    }
  }

  const rulesResult = verifyAndParseRules(signed, ruleFiles);
  if (!rulesResult.ok) {
    return {
      status: "tampered",
      reason: `manifest rule verification failed: ${rulesResult.error}${
        rulesResult.issues ? ` (${rulesResult.issues.join("; ")})` : ""
      }`,
    };
  }

  // Carry the signature-VERIFIED manifest-level descriptors forward (#897 P1).
  // Both `agent_origin` and `operator_baseline` live INSIDE `signed.manifest`,
  // so they are covered by the Ed25519 signature `verifyManifestSignature` just
  // checked -- reading them here is exactly as trustworthy as the rules, and an
  // attacker who plants either on disk breaks the signature and lands in the
  // `tampered` branch above (no laundering vector). Each field is set only when
  // the source manifest carried it, so an absent descriptor stays absent and
  // the re-signed canonical bytes match a manifest built without it.
  const read: VerifiedManifestRead = { status: "ok", rules: [...rulesResult.value], digest };
  if (signed.manifest.agent_origin !== undefined) {
    read.agentOrigin = signed.manifest.agent_origin;
  }
  if (signed.manifest.operator_baseline !== undefined) {
    read.operatorBaseline = signed.manifest.operator_baseline;
  }
  return read;
}

/** Load the pinned Castle Wall public key (32 raw bytes) used to verify the on-disk manifest. */
async function loadPinnedPublicKey(fortressPath: string, err: Writable): Promise<Uint8Array | null> {
  const pubPath = join(fortressPath, CASTLE_PINNED_PUBKEY);
  try {
    const pub = await readFile(pubPath);
    if (pub.length !== ED25519_PUBLIC_KEY_BYTES) {
      write(err, `Error: pinned public key at ${pubPath} must be 32 bytes (found ${pub.length}).\n`);
      return null;
    }
    return new Uint8Array(pub);
  } catch (error) {
    if (isEnoent(error)) {
      write(
        err,
        "Error: no Castle Wall pinned signing key found. Run `sanctuary castle-wall provision-pin` first.\n",
      );
      return null;
    }
    write(err, `Error loading the Castle Wall pinned public key: ${(error as Error).message}\n`);
    return null;
  }
}

async function loadPinnedManifestSigner(
  fortressPath: string,
  masterKey: Uint8Array,
  err: Writable,
): Promise<ManifestSigner | null> {
  const pubPath = join(fortressPath, CASTLE_PINNED_PUBKEY);
  const privPath = join(fortressPath, CASTLE_PINNED_PRIVKEY);
  try {
    const pub = await readFile(pubPath);
    const encryptedPrivateKey = JSON.parse(await readFile(privPath, "utf8")) as EncryptedPayload;
    return localManifestSigner({
      signingKeyId: castleWallSigningKeyId(pub),
      encryptedPrivateKey,
      encryptionKey: masterKey,
    });
  } catch (error) {
    if (isEnoent(error)) {
      write(
        err,
        "Error: no Castle Wall pinned signing key found. Run `sanctuary castle-wall provision-pin` first.\n",
      );
      return null;
    }
    write(err, `Error loading the Castle Wall pinned signing key: ${(error as Error).message}\n`);
    return null;
  }
}

/**
 * Resolve the SCOPE routing a promote must synthesize under, from the
 * fortress's durable exclusive-routing marker (the SAME marker the signing
 * daemon composes by, `allowlist/routing-marker.ts`):
 *
 *   - marker ABSENT: coarse mode. Promoted rules keep the shipped
 *     template/agent scoping.
 *   - marker PRESENT: exclusive mode. Promoted rules are scoped to the gate
 *     principal (`scope.uids = [gate_uid]`), the same axis the provisioned
 *     endpoint rules use, because a template/agent-scoped promoted rule in
 *     the composer's `rules/` source is an agent-reachable direct off-box
 *     allow that `assertExclusiveRoutingComposition` rejects by THROWING --
 *     which would turn every policy reload into a fail-closed outage.
 *   - marker PRESENT but MALFORMED: throws (`ExclusiveRoutingMarkerError`,
 *     the loader's contract). The caller must refuse to promote rather than
 *     guess a mode -- exactly the daemon's own fail-closed posture.
 *
 * Exported so the enforcement-reach end-to-end test drives the same
 * resolution the CLI does, not a test-local reimplementation.
 */
export async function resolvePromoteRouting(fortressPath: string): Promise<PromoteRouting> {
  const marker = await loadExclusiveRoutingMarker(fortressPath);
  return marker !== null
    ? { mode: "exclusive", gate_uid: marker.gate_uid }
    : { mode: "coarse" };
}

const VALID_GRANULARITIES: ReadonlySet<string> = new Set([
  "per_template_domain",
  "per_template_etld1",
  "per_instance_domain",
]);

export async function runObservePromote(
  argv: string[] = [],
  ctx: ObserveCommandContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;

  const destinations = flagValues(argv, "--destination");
  const all = hasFlag(argv, "--all");
  const json = hasFlag(argv, "--json");
  const includeRisky = hasFlag(argv, "--include-risky");
  const granularityFlag = flagValue(argv, "--granularity");

  if (granularityFlag !== undefined && !VALID_GRANULARITIES.has(granularityFlag)) {
    write(
      err,
      `Error: --granularity must be one of per_template_domain, per_template_etld1, per_instance_domain (got ${granularityFlag}).\n`,
    );
    return 2;
  }
  if (!all && destinations.length === 0) {
    write(
      err,
      "Usage: sanctuary castle-wall observe promote --destination <host_or_ip:port> [--destination ...] | --all\n",
    );
    return 2;
  }

  const boot = await bootstrap(argv, err, env);
  if (typeof boot === "number") return boot;

  // Resolve the scope routing FIRST (before even looking at the selection): a
  // malformed exclusive-routing marker refuses the promote outright. The
  // signing daemon refuses to compose a manifest under an unreadable routing
  // marker, so promoting into that state could only make the outage wider;
  // fail closed, never guess a mode (fix-round F7 pins this branch).
  let routing: PromoteRouting;
  try {
    routing = await resolvePromoteRouting(boot.fortressPath);
  } catch (error) {
    const reason =
      error instanceof ExclusiveRoutingMarkerError ? error.message : (error as Error).message;
    write(
      err,
      `Error: could not resolve this fortress's egress routing mode (${reason}). ` +
        "Nothing was changed. The signing daemon refuses to compose a manifest under an unreadable " +
        "routing marker, so promoting would not reach enforcement either; repair the marker first.\n",
    );
    return 1;
  }

  const candidatesByKey = await boot.observeStore.listCandidates();
  const granularity = granularityFlag as ObserveGranularity | undefined;
  const selection: PromoteSelectionRow[] = [];
  // Round-3 R5: a repeated `--destination X --destination X` (or overlapping
  // matches) must select each candidate row ONCE. Duplicate selection rows
  // synthesized two same-id rules, and the publisher's duplicate-rule-id
  // guard then threw AFTER approval (an unhandled crash, nothing published).
  const selectedKeys = new Set<string>();
  const pushSelection = (key: string): void => {
    if (selectedKeys.has(key)) return;
    selectedKeys.add(key);
    selection.push({ key, granularity });
  };

  if (all) {
    for (const [key, candidate] of candidatesByKey) {
      if (candidate.exfil_risk && !includeRisky) {
        write(
          out,
          `Skipping EXFIL-RISK destination ${destinationLabel(candidate)} (pass --include-risky to promote it deliberately).\n`,
        );
        continue;
      }
      pushSelection(key);
    }
  } else {
    for (const destination of [...new Set(destinations)]) {
      const matches = [...candidatesByKey.entries()].filter(
        ([, candidate]) => destinationLabel(candidate) === destination,
      );
      if (matches.length === 0) {
        write(err, `Warning: no pending candidate matches ${destination}\n`);
        continue;
      }
      // FIX 4: a bare host:port can match candidates from more than one agent
      // template or protocol. Echo exactly which (template, protocol) rows a
      // --destination selected so the fan-out is visible BEFORE the approval
      // prompt (the approval context itself also lists every synthesized rule
      // + its scope, so the human sees each grant before approving).
      if (matches.length > 1) {
        const rows = matches
          .map(([, candidate]) => `${candidate.agent_template}/${candidate.protocol}`)
          .join(", ");
        write(out, `Note: ${destination} matches ${matches.length} candidate row(s): ${rows}\n`);
      }
      for (const [key, candidate] of matches) {
        if (candidate.exfil_risk && !includeRisky) {
          write(
            out,
            `Skipping EXFIL-RISK destination ${destination} (pass --include-risky to promote it deliberately).\n`,
          );
          continue;
        }
        pushSelection(key);
      }
    }
  }

  if (selection.length === 0) {
    if (routing.mode !== "exclusive") {
      const lastRefresh = await boot.observeStore.getLastRefreshOutcome();
      if (json) {
        writePromoteNoSelectionJson(out, candidatesByKey.size, lastRefresh, false);
      } else if (candidatesByKey.size === 0) {
        writePromoteNoSelectionText(out, 0, lastRefresh, false);
      } else {
        write(out, "Nothing selected to promote.\n");
      }
      return 0;
    }
    // Round-3 R3: on an exclusive fortress an EMPTY selection still proceeds,
    // because promote is the product path that re-scopes stale (pre-exclusive)
    // promoted rules to the gate principal -- and the coarse-era promote
    // REMOVED its candidates, so the bricked state has nothing to select.
    write(
      out,
      "No pending candidates selected; checking for promoted rules that need re-scoping to this fortress's exclusive routing.\n",
    );
  }

  const egressDir = join(boot.fortressPath, "policy", "egress");

  const pinnedPublicKey = await loadPinnedPublicKey(boot.fortressPath, err);
  if (!pinnedPublicKey) return 1;

  const signer = await loadPinnedManifestSigner(boot.fortressPath, boot.masterKey, err);
  if (!signer) return 1;

  const fortressId = fortressIdFromStoragePath(boot.fortressPath);
  const manifestStorage = new FilesystemManifestStorage(egressDir);

  const policy = await loadPrincipalPolicy(boot.fortressPath);
  const baseline = new BaselineTracker(boot.storage, boot.masterKey);
  const channel = ctx.approvalChannel ?? new CastleWallObservePromptApprovalChannel();
  const gate = new ApprovalGate(policy, baseline, channel, boot.auditLog);

  // Round-3 R1: cross-process publish lock (see promote.ts `publishLock`).
  let promoteLockHolder = "";
  const publishLock = observePromoteFileLock(boot.fortressPath, (holder) => {
    promoteLockHolder = holder;
  });

  const outcome = await promoteCandidates(selection, candidatesByKey, {
    readVerifiedManifest: () => readVerifiedManifest(egressDir, pinnedPublicKey),
    approve: (operation, context) => gate.evaluate(operation, context),
    publish: (rules, descriptors) =>
      publishSignedManifest(
        {
          fortressId,
          issuedAt: new Date().toISOString(),
          rules,
          signer,
          // Carry the VERIFIED manifest-level descriptors through so a re-sign
          // preserves operator_baseline + agent_origin (#897 P1). buildSignedManifest
          // re-runs each through its fail-closed validator (idempotent for an
          // already-signed descriptor), so a carried-forward value is emitted
          // faithfully and a malformed one would still be dropped.
          ...(descriptors.agentOrigin !== undefined ? { agentOrigin: descriptors.agentOrigin } : {}),
          ...(descriptors.operatorBaseline !== undefined
            ? { operatorBaseline: descriptors.operatorBaseline }
            : {}),
        },
        manifestStorage,
      ),
    auditPromotedCandidate: async (row) => {
      await boot.auditLog.appendCritical({
        layer: "l1",
        operation: "castle_wall_observe_promote",
        identity_id: boot.primary.identity_id,
        result: "success",
        details: {
          candidate_key: row.key,
          rule_id: row.rule_id,
          destination: destinationLabel(row.candidate),
          routing_mode: routing.mode,
        },
      });
    },
    now: new Date(),
    routing,
    // Fix-round F5: the Tier-1 approval can block on a human; re-resolve the
    // marker after it returns so a mode flip in that window aborts instead of
    // signing rules scoped for the fortress as it no longer is.
    reresolveRouting: () => resolvePromoteRouting(boot.fortressPath),
    publishLock,
  });

  if (outcome.status === "no_candidates") {
    if (selection.length === 0) {
      // The exclusive-mode empty-selection rescope check (round-3 R3) found
      // nothing needing re-scope: an honest no-op, not an error.
      const lastRefresh = await boot.observeStore.getLastRefreshOutcome();
      if (json) {
        writePromoteNoSelectionJson(
          out,
          candidatesByKey.size,
          lastRefresh,
          true,
          routing.mode === "exclusive" ? EXCLUSIVE_GATE_DENIALS_UNAVAILABLE : null,
        );
      } else {
        writePromoteNoSelectionText(
          out,
          candidatesByKey.size,
          lastRefresh,
          true,
          routing.mode === "exclusive" ? EXCLUSIVE_GATE_DENIALS_UNAVAILABLE : null,
        );
      }
      return 0;
    }
    write(err, "No valid candidates to promote (not found, or the synthesized rule failed validation).\n");
    for (const dropped of outcome.dropped) write(err, `  ${dropped.key}: ${dropped.reason}\n`);
    return 1;
  }
  if (outcome.status === "publish_in_progress") {
    write(
      err,
      "Error: another egress-policy writer (an `observe promote`, or a provisioning publish/revoke/restore) " +
        "is writing to this fortress" +
        (promoteLockHolder ? ` (${promoteLockHolder})` : "") +
        ". Nothing was changed (concurrent writers could silently drop each other's rules). " +
        "Wait for it to finish and re-run. This lock is never broken automatically.\n",
    );
    return 1;
  }
  if (outcome.status === "already_promoted") {
    write(
      out,
      "The selected destination(s) are already in your wall's signed ruleset with the current-mode scope; nothing needed re-signing.\n",
    );
    if (routing.mode === "exclusive") {
      write(
        out,
        "If you have re-armed since promoting, the gate is already serving them; remove the rows with " +
          "`sanctuary castle-wall observe discard`. If you have not re-armed yet, re-arm to apply them " +
          `(for example: ${EGRESS_GATE_REPAIR_WITH_STAND_DOWN_ADVICE}).\n`,
      );
    }
    return 0;
  }
  if (outcome.status === "tampered_manifest") {
    write(
      err,
      `Aborted: the existing Castle Wall manifest did not verify against the pinned key (${outcome.reason}). ` +
        `Nothing changed. Refusing to re-sign an unverified ruleset; investigate ${join(egressDir, "manifest.json")} ` +
        `before promoting.\n`,
    );
    return 1;
  }
  if (outcome.status === "manifest_changed") {
    write(
      err,
      "Aborted: the Castle Wall manifest changed while you were reviewing this promote. Nothing changed. " +
        "Re-run `sanctuary castle-wall observe promote` so your approval applies to the current ruleset.\n",
    );
    return 1;
  }
  if (outcome.status === "denied") {
    write(
      err,
      `Denied: promote was not approved (${outcome.reason}). Nothing changed` +
        (selection.length > 0
          ? "; the selected destinations stay blocked.\n"
          : "; no rules were re-scoped.\n"),
    );
    return 1;
  }
  if (outcome.status === "routing_changed") {
    write(
      err,
      `Aborted: this fortress's egress routing changed while you were reviewing this promote (${outcome.reason}). ` +
        "Nothing changed. Re-run `sanctuary castle-wall observe promote` so the rules are scoped for the " +
        "fortress as it now stands.\n",
    );
    return 1;
  }

  // Fix-round F1(b): in EXCLUSIVE mode the promoted candidates stay in the
  // pending list. The gate daemon loads its destination rules only at arming,
  // gate denials are not folded into the audit chain, and a removed row would
  // therefore vanish with nothing to re-mint it -- reporting "done" for a
  // destination the agent still cannot reach (the original defect's shape).
  // Round-3 R2: NOTHING clears these rows automatically -- no composable
  // rule can cover the agent's direct path on an exclusive fortress (that is
  // exactly what the compose-time assertion forbids), so the refresh prune
  // can never fire for them. The row leaves the list when the OPERATOR
  // discards it after re-arming; the listing marks it "promoted, awaiting
  // re-arm" and the copy below says so plainly.
  if (routing.mode !== "exclusive") {
    for (const key of outcome.promotedKeys) {
      const candidate = candidatesByKey.get(key);
      if (!candidate) continue;
      await boot.observeStore.removeCandidateAfterReview(
        candidate,
        "promote",
        new Date().toISOString(),
      );
    }
  }

  const summary: string[] = [];
  if (outcome.addedRules.length > 0) summary.push(`added ${outcome.addedRules.length} allow rule(s)`);
  if (outcome.rewrittenRules.length > 0) {
    summary.push(
      `re-scoped ${outcome.rewrittenRules.length} existing promoted rule(s) to this fortress's routing mode`,
    );
  }
  write(
    out,
    `Promote complete: ${summary.join(" and ")}. Your wall's manifest was re-signed and republished to the rule source the enforcement daemons read.\n`,
  );
  if (routing.mode === "exclusive") {
    write(
      out,
      "This fortress runs exclusive routing: the rule(s) are bound to the sanctuary-gate principal (your agent's only sanctioned off-box path is the gate).\n",
    );
    write(
      out,
      "IMPORTANT: the running gate daemon loads its destination rules only when the gate is armed, so your agent " +
        "CANNOT reach the approved destination(s) yet. Re-arm to apply them, for example: " +
        `${EGRESS_GATE_REPAIR_WITH_STAND_DOWN_ADVICE}. The destination(s) stay listed in ` +
        "`observe candidates` (marked as promoted, awaiting re-arm); nothing clears them automatically. " +
        "Once the re-armed gate is serving them, remove them with `sanctuary castle-wall observe discard`.\n",
    );
  } else {
    write(
      out,
      "Run `sanctuary castle-wall reload` (or restart the daemon) so a running Castle Wall daemon picks up the new rules immediately.\n",
    );
  }
  if (outcome.dropped.length > 0) {
    write(out, `${outcome.dropped.length} row(s) were skipped:\n`);
    for (const dropped of outcome.dropped) write(out, `  ${dropped.key}: ${dropped.reason}\n`);
  }
  return 0;
}

export async function runObserveDiscard(
  argv: string[] = [],
  ctx: ObserveCommandContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;

  const destinations = flagValues(argv, "--destination");
  const all = hasFlag(argv, "--all");
  if (!all && destinations.length === 0) {
    write(err, "Usage: sanctuary castle-wall observe discard --destination <host_or_ip:port> [--destination ...] | --all\n");
    return 2;
  }

  const boot = await bootstrap(argv, err, env);
  if (typeof boot === "number") return boot;

  const candidatesByKey = await boot.observeStore.listCandidates();
  const keysToRemove = all
    ? [...candidatesByKey.keys()]
    : [...candidatesByKey.entries()]
        .filter(([, candidate]) => destinations.includes(destinationLabel(candidate)))
        .map(([key]) => key);

  if (keysToRemove.length > 0) {
    // The discard audit entry is the REVIEW MARKER the refresh chokepoint's
    // recompute heal depends on to not resurrect discarded candidates from
    // retained history (castle-wall/observe/refresh.ts guarantee 3; Codex
    // two-family gate round 2, HIGH). It is therefore written CRITICALLY and
    // BEFORE the rows are removed: if the append fails, the discard aborts
    // with the rows intact (fail-closed; the operator retries). A crash
    // between the append and the removals is harmless -- the marker only
    // bounds what a recompute may MINT for keys absent from the store, and
    // the still-present rows heal normally.
    const reviewedAt = new Date().toISOString();
    try {
      await boot.auditLog.appendCritical({
        timestamp: reviewedAt,
        layer: "l1",
        operation: "castle_wall_observe_discard",
        identity_id: boot.primary.identity_id,
        result: "success",
        details: { discarded_count: keysToRemove.length },
      });
    } catch (error) {
      write(
        err,
        `Error: the discard could not be recorded in the audit log (${(error as Error).message}). ` +
          "Nothing was discarded; the discard record is what prevents a discarded destination " +
          "from reappearing out of retained history, so it must land first. Re-run after " +
          "resolving the audit-log failure.\n",
      );
      return 1;
    }

    for (const key of keysToRemove) {
      const candidate = candidatesByKey.get(key);
      if (!candidate) continue;
      await boot.observeStore.removeCandidateAfterReview(candidate, "discard", reviewedAt);
    }
  }

  write(out, `Discarded ${keysToRemove.length} candidate(s).\n`);
  return 0;
}
