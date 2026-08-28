/**
 * sanctuary audit-chain repair-plan
 *
 * Read-only. Tells an operator what state a fortress's audit chain is actually
 * in and what a repair would do. It performs no repair, decides nothing, and
 * needs no authority.
 *
 * WHY IT EXISTS AS A SEPARATE, OFFLINE VERB. A fortress whose audit chain has
 * hard integrity findings cannot be inspected through the MCP server, because
 * the strict-mode audit log refuses writes on such a chain and the startup path
 * appends before it serves. So the diagnostic an operator needs in exactly that
 * situation cannot be an MCP tool and cannot require `createSanctuaryServer`;
 * it runs against the fortress DIRECTORY, like `castle-wall audit-findings`.
 * Register id: ABC-NORECOVERY-01.
 *
 * THE THREE THINGS IT DELIBERATELY DOES NOT DO:
 *
 *  1. It does not MUTATE. Not the chain, not the fortress, not any persisted
 *     state, not the OS keyring. This is enforced structurally: every storage
 *     call goes through a {@link ReadOnlyStorageGuard} whose write paths throw,
 *     and custody is read through `readStoredPassphrase` (which never mints a
 *     keyring item) rather than `getOrCreatePassphrase`. Two reachable write
 *     paths bypass the StorageBackend and are therefore refused by their own
 *     read-only declarations rather than the guard: the audit log's
 *     signing-state recovery batch (raw filesystem calls; suppressed by the
 *     AuditLog `readOnly` config) and the legacy fallback-file format-upgrade
 *     rewrite inside `readStoredPassphrase` (skipped under its `readOnly`
 *     option). Convention alone would not hold here, because the machinery
 *     this verb reaches (the audit log's load path, the sealed-region walk,
 *     custody unwrap) writes on some of its paths and does not announce it at
 *     the call site.
 *
 *     The guard is not decorative: loading a chain that HAS findings attempts
 *     one write of its own, appending to the operator-facing integrity-alert
 *     log. Refusing it is the intended behavior here and costs the operator
 *     nothing, because this verb's entire output IS that alert, delivered to
 *     the operator directly. It is called out because a reader who removes the
 *     guard sees nothing break in the clean case and concludes it was
 *     ornamental; the damaged case is where it bites, and there is a test named
 *     for exactly that.
 *
 *  2. It does not ADJUDICATE CAUSE. An interrupted write, a restore from
 *     backup, and a deliberate truncation are not distinguishable from the
 *     on-disk evidence. Every field below reports what was OBSERVED. No field
 *     says what happened, and none may be added that does.
 *
 *  3. It does not AUTHORIZE. There is no flag, no prompt, and no consent
 *     record. The plan is advisory text plus a digest.
 *
 * MUST-NEVER #5: if the state cannot be read, this verb says so and exits
 * non-zero. It never reports a chain clean because it failed to look.
 *
 * MUST-NEVER #2: it creates no state at all, so there is nothing an operator
 * could be unable to inspect or delete.
 */

import { createHash } from "node:crypto";
import { Writable } from "node:stream";
import { establishMaster } from "../core/master-custody.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
// Shared canonicalizer rather than a fourth local copy. `mesh/canonical-json.ts`
// is version-frozen by its own contract ("changing this function invalidates
// every signature ever produced over it; version bumps instead"), which is the
// property the evidence commitment needs: the same chain must digest the same
// way across releases.
import { canonicalize } from "../mesh/canonical-json.js";
import {
  AuditLog,
  foldAuditChainVerdict,
  type AuditChainVerdict,
  type AuditIntegrityFinding,
  type AuditIntegrityFindingKind,
  type SealedRegionVerdict,
} from "../operational/audit-log.js";
import { probeDaemonChainAccess } from "../operational/audit-store-split.js";
import { homeFortressPath } from "../paths.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import type {
  FilesystemStorageCapabilities,
  StorageBackend,
} from "../storage/interface.js";
import {
  ReadOnlyStorageGuard,
  ReadOnlyStorageViolationError,
} from "../storage/read-only-guard.js";
import { getSanctuaryVersion } from "../version.js";
import { readStoredPassphrase } from "../wrap/passphrase.js";
import {
  exportAuditChain,
  fortressRanAuditStoreSplitMigration,
  resolveAuditStoragePath,
  totalRecordsSkipped,
  type AuditChainExportSummary,
} from "./audit-chain-export.js";
import {
  aliasConflictMessage,
  consumeFlagValue,
  flagValue,
  fortressFlagRefusalText,
} from "./argv.js";

// ---- Exit codes -------------------------------------------------------------
//
// Distinct codes, not one "something is wrong" code, because the two non-clean
// outcomes call for OPPOSITE operator actions: a privilege-limited result means
// "re-read this chain with more privilege", and treating it as a damaged chain
// would destroy a chain that was never shown to be damaged.

/** The chain verifies clean at this privilege; no repair is applicable. */
export const REPAIR_PLAN_EXIT_CLEAN = 0;
/** The fortress state could not be read (MUST-NEVER #5 fail-closed) or the run
 *  itself failed. Never emitted alongside a "clean" claim. */
export const REPAIR_PLAN_EXIT_STATE_UNREADABLE = 1;
/** Usage error (unknown flag, missing value). Matches the castle-wall verbs. */
export const REPAIR_PLAN_EXIT_USAGE = 2;
/** Findings are content-shaped: a forward cut is the applicable repair class. */
export const REPAIR_PLAN_EXIT_PLAN_PRODUCED = 3;
/** Some evidence could not be read at THIS privilege, so the chain has not been
 *  shown to be damaged. Refuses to offer a cut; redirects. */
export const REPAIR_PLAN_EXIT_PRIVILEGE_LIMITED = 4;

// ---- Bounds -----------------------------------------------------------------

/**
 * How many findings are embedded verbatim in the report. The finding set is
 * attacker-influenced in size (an agent that can write the fortress directory
 * can manufacture a finding per entry), so an unbounded verbatim embedding
 * turns a diagnostic into a memory-amplification lever (AGENTS rule 8). The
 * evidence commitment covers ALL findings regardless of this cap, so
 * truncating the human-readable list never weakens the digest.
 */
export const REPAIR_PLAN_MAX_VERBATIM_FINDINGS = 100;

/**
 * Schema version of {@link AuditChainRepairPlan} and of the byte layout the
 * evidence commitment digests. A later verifier that binds an authorization to
 * a commitment must refuse a version it does not know; bump this, never edit
 * the layout in place.
 */
export const REPAIR_PLAN_SCHEMA_VERSION = 1;

/** Domain separation for the evidence commitment, so its digest can never
 *  collide with a checkpoint, an anchor, or any other hash in this tree. */
export const REPAIR_PLAN_EVIDENCE_DOMAIN =
  "sanctuary/audit-chain/repair-plan/evidence/v1";

// ---- Named plan states ------------------------------------------------------

/**
 * The plan's terminal states, named rather than derived at each print site so
 * the decision reads as a diagram. Each maps to exactly one exit code.
 */
export type RepairPlanState =
  /** Routine findings empty AND the sealed region verified/empty/not-present. */
  | "PLAN_NO_ACTION_CHAIN_VERIFIES_CLEAN"
  /** Some evidence was unreadable at this privilege. NOT a damage verdict. */
  | "PLAN_NO_ACTION_PRIVILEGE_LIMITED"
  /** Findings present and fully readable here; the forward-cut class applies. */
  | "PLAN_FORWARD_CUT_APPLICABLE";

/**
 * Finding kinds that mean "this reader could not READ something", as opposed to
 * "this reader read something and it was wrong".
 *
 * INVARIANT (the enforcement site is {@link classifyPlanState}): the presence
 * of any of these caps the plan at PRIVILEGE_LIMITED and withholds the
 * forward-cut recommendation, because a chain that was not fully read here has
 * not been shown to be damaged, and a cut destroys a chain. This is a statement
 * about evidence completeness, NOT a claim about cause — the verb never decides
 * whether a read failure was a permissions problem, a migration, or a fault.
 * Under-reading in this direction fails closed (it withholds a destructive
 * path); the opposite error would recommend cutting a healthy chain.
 */
const READ_FAILURE_FINDING_KINDS: ReadonlySet<AuditIntegrityFindingKind> =
  new Set<AuditIntegrityFindingKind>([
    "storage_unavailable",
    "entry_unreadable",
    "checkpoint_signing_state_indeterminate",
  ]);

/**
 * Finding kinds whose remedy is an operator-side MIGRATION step rather than
 * anything in the repair class. They do not change the plan state (they are
 * observations of content, not read failures); they add a redirect to
 * `next_actions` so an operator is not pointed at a cut when the writer-split
 * migration is what is unfinished.
 */
const MIGRATION_SHAPED_FINDING_KINDS: ReadonlySet<AuditIntegrityFindingKind> =
  new Set<AuditIntegrityFindingKind>([
    "split_boundary_missing",
    "split_boundary_invalid",
    "sealed_prefix_incomplete",
  ]);

// ---- Report shape -----------------------------------------------------------

/** One finding as reported. Mirrors the fields `audit-findings` prints, so the
 *  two diagnostics never disagree about what a finding IS. */
export interface RepairPlanFinding {
  kind: AuditIntegrityFindingKind;
  message: string;
  key?: string;
  sequence?: number;
  expected?: string | number;
  actual?: string | number;
  severity?: "warn";
  variant?: string;
}

/**
 * What `audit-chain export` WOULD produce for this fortress right now, computed
 * by running the real exporter into a hashing sink. Nothing is written to disk;
 * the digest is over the exact bytes the export command would emit.
 */
export interface RepairPlanExportManifest {
  entries_listed: number;
  entries_exported: number;
  entries_skipped: number;
  checkpoints_listed: number;
  checkpoints_exported: number;
  checkpoints_skipped: number;
  /** False when any listed record was unreadable/corrupt and therefore SKIPPED;
   *  such an export is not a complete chain and must not be presented as one. */
  complete: boolean;
  /** SHA-256, hex, over the JSONL bytes the export would contain. */
  digest: string;
  bytes: number;
  /** True when a root daemon chain (or its durable migration marker) is
   *  present, so an operator-chain-only export is INCOMPLETE by construction. */
  daemon_chain_present: boolean;
  /** Whether THIS process could list the daemon chain. `present_unreadable` is
   *  the expected operator-uid result on an armed box and is not a failure —
   *  but it does mean the full picture was not read here. */
  daemon_chain_access: "absent" | "accessible" | "present_unreadable";
}

export interface AuditChainRepairPlan {
  schema_version: number;
  generated_at: string;
  fortress_id: string;
  sanctuary_version: string;
  chain_state: {
    verdict: AuditChainVerdict["status"];
    routine_finding_count: number;
    sealed_region: SealedRegionVerdict;
    tip_sequence: number;
    tip_entry_hash: string;
    /** Capped at {@link REPAIR_PLAN_MAX_VERBATIM_FINDINGS}; the commitment
     *  still covers every finding. */
    findings: RepairPlanFinding[];
    findings_truncated: boolean;
  };
  export_manifest: RepairPlanExportManifest;
  plan: {
    state: RepairPlanState;
    /** What was OBSERVED, never what happened. */
    observation: string;
    next_actions: string[];
  };
  /** SHA-256, hex, over the domain-separated canonical evidence document. */
  evidence_commitment: string;
  /** The fixed statement of what the commitment does and does not prove,
   *  stamped into every report so it can never be read as an authorization. */
  evidence_commitment_scope: string;
  /** Honest bounds, always present, never softened. */
  bounds: string[];
}

/**
 * What the evidence commitment is and is not. Modeled on the standalone
 * verifier's `rotation_anchor_scope`: a fixed sentence in the output, so a
 * reader cannot mistake the digest for something it is not.
 */
// Non-disclosure (MUST-NEVER #9): this string ships in public source and is
// stamped into every operator report, so it states the generic capability
// bound only (the same bound REPAIR_PLAN_BOUNDS carries) plus a bare register
// id that resolves only in the private register. It must never describe a
// mechanism by which a chain could be altered.
export const REPAIR_PLAN_EVIDENCE_SCOPE =
  "The evidence commitment is a digest over the observed finding set and the " +
  "export this fortress would produce. It is not a signature, it is not an " +
  "authorization, and it is not evidence that the chain is intact: absence " +
  "of findings is not evidence of an untampered chain (register id " +
  "ABC-EVID-01). It is reproducible, so two runs over an unchanged fortress " +
  "agree, and a later run that disagrees proves the chain changed in between.";

/**
 * Bounds every report carries. These are capability bounds (what is absent,
 * partial, or unproven), which is an honesty obligation and is never softened.
 */
const REPAIR_PLAN_BOUNDS: readonly string[] = [
  "read-only: this command changes no state and needs no authority",
  "it does not repair, and no repair verb exists in this build; the plan is advisory",
  "it reports what is observed and never infers a cause; several causes are " +
    "indistinguishable from the data",
  "absence of findings is not evidence of an untampered chain; an independent " +
    "verification of an export on a second machine is the stronger check",
];

// ---- Evidence commitment ----------------------------------------------------

/**
 * Digest the observed evidence.
 *
 * DELIBERATE SUBTRACTION, recorded here because a reader will look for it: no
 * random nonce. A nonce provides replay resistance only when something durable
 * remembers it, and this verb persists nothing by mandate. Emitting one now
 * would give the output the SHAPE of a challenge-response without any of the
 * mechanism, which reads as an authorization surface that does not exist. What
 * this digest does carry is the binding that matters: it covers the FULL
 * finding set and the exact export bytes, so a later authorization bound to it
 * cannot be widened by changing the chain afterward.
 *
 * Determinism is a feature, not an oversight: two runs over an unchanged
 * fortress produce the same digest, which is itself the operator's cheapest
 * check that nothing moved between them.
 *
 * The finding set is passed in FULL here even when the report truncates its
 * verbatim list, so the digest never depends on a display cap.
 */
export function computeRepairPlanEvidenceCommitment(input: {
  fortressId: string;
  verdict: AuditChainVerdict["status"];
  sealedRegion: SealedRegionVerdict;
  tipSequence: number;
  tipEntryHash: string;
  findings: readonly AuditIntegrityFinding[];
  exportManifest: RepairPlanExportManifest;
}): string {
  const document = {
    domain: REPAIR_PLAN_EVIDENCE_DOMAIN,
    schema_version: REPAIR_PLAN_SCHEMA_VERSION,
    fortress_id: input.fortressId,
    verdict: input.verdict,
    sealed_region: input.sealedRegion,
    tip_sequence: input.tipSequence,
    tip_entry_hash: input.tipEntryHash,
    finding_count: input.findings.length,
    findings: input.findings.map((finding) => toReportFinding(finding)),
    export_manifest: input.exportManifest,
  };
  return createHash("sha256").update(canonicalize(document), "utf8").digest("hex");
}

function toReportFinding(finding: AuditIntegrityFinding): RepairPlanFinding {
  // Field-by-field rather than a spread: the report's shape is a contract the
  // commitment digests, so a new field on AuditIntegrityFinding must be an
  // explicit decision here (and a schema-version bump), never a silent digest
  // change on an unrelated edit elsewhere.
  return {
    kind: finding.kind,
    message: finding.message,
    ...(finding.key !== undefined ? { key: finding.key } : {}),
    ...(finding.sequence !== undefined ? { sequence: finding.sequence } : {}),
    ...(finding.expected !== undefined ? { expected: finding.expected } : {}),
    ...(finding.actual !== undefined ? { actual: finding.actual } : {}),
    ...(finding.severity !== undefined ? { severity: finding.severity } : {}),
    ...(finding.variant !== undefined ? { variant: finding.variant } : {}),
  };
}

// ---- Plan classification ----------------------------------------------------

/**
 * Fold the observed evidence into one named state.
 *
 * The privilege check runs BEFORE the findings check, which is the whole point:
 * an incomplete read must never be reported as a damage verdict. See
 * {@link READ_FAILURE_FINDING_KINDS} for why that ordering is the fail-closed
 * direction.
 */
export function classifyPlanState(input: {
  verdict: AuditChainVerdict;
  findings: readonly AuditIntegrityFinding[];
  daemonAccess: RepairPlanExportManifest["daemon_chain_access"];
}): RepairPlanState {
  const { verdict, findings, daemonAccess } = input;
  const someEvidenceUnread =
    verdict.sealed_region.status === "unreadable" ||
    verdict.status === "verified_suffix_only" ||
    daemonAccess === "present_unreadable" ||
    findings.some((finding) => READ_FAILURE_FINDING_KINDS.has(finding.kind));
  if (someEvidenceUnread) return "PLAN_NO_ACTION_PRIVILEGE_LIMITED";
  if (verdict.status === "findings") return "PLAN_FORWARD_CUT_APPLICABLE";
  return "PLAN_NO_ACTION_CHAIN_VERIFIES_CLEAN";
}

export function repairPlanExitCode(state: RepairPlanState): number {
  switch (state) {
    case "PLAN_NO_ACTION_CHAIN_VERIFIES_CLEAN":
      return REPAIR_PLAN_EXIT_CLEAN;
    case "PLAN_NO_ACTION_PRIVILEGE_LIMITED":
      return REPAIR_PLAN_EXIT_PRIVILEGE_LIMITED;
    case "PLAN_FORWARD_CUT_APPLICABLE":
      return REPAIR_PLAN_EXIT_PLAN_PRODUCED;
  }
}

function observationFor(state: RepairPlanState): string {
  switch (state) {
    case "PLAN_NO_ACTION_CHAIN_VERIFIES_CLEAN":
      return (
        "No integrity findings, and every region this process could read " +
        "verified. Nothing in the repair class applies."
      );
    case "PLAN_NO_ACTION_PRIVILEGE_LIMITED":
      return (
        "Part of the evidence could not be read by this process, so the chain " +
        "has NOT been shown to be damaged. No repair is offered on an " +
        "incomplete read."
      );
    case "PLAN_FORWARD_CUT_APPLICABLE":
      return (
        "Integrity findings are present and every region was readable here. " +
        "This is the state a forward cut addresses: the broken segment is " +
        "preserved and sealed, and a new segment begins with the reason it " +
        "exists. Nothing is re-linked, renumbered, or deleted."
      );
  }
}

function nextActionsFor(
  state: RepairPlanState,
  findings: readonly AuditIntegrityFinding[]
): string[] {
  const actions: string[] = [];
  switch (state) {
    case "PLAN_NO_ACTION_CHAIN_VERIFIES_CLEAN":
      actions.push("no action");
      break;
    case "PLAN_NO_ACTION_PRIVILEGE_LIMITED":
      actions.push(
        "re-run this command with the privilege that owns the unreadable " +
          "region (root, on an armed fortress) and compare the result"
      );
      actions.push(
        "run 'sanctuary castle-wall audit-store-status' as root for both " +
          "chains' verdicts side by side"
      );
      break;
    case "PLAN_FORWARD_CUT_APPLICABLE":
      actions.push(
        "export the chain now and keep the file OFF this host: " +
          "'sanctuary audit-chain export --output <path outside the fortress>'"
      );
      actions.push(
        "verify that export independently on a second machine: " +
          "'sanctuary audit-chain verify --input <path>'"
      );
      actions.push(
        "record the evidence_commitment below somewhere this host cannot reach"
      );
      actions.push(
        "no repair verb exists in this build; a cut requires an authorization " +
          "key held off this host, which is not yet configurable"
      );
      break;
  }
  if (findings.some((finding) => MIGRATION_SHAPED_FINDING_KINDS.has(finding.kind))) {
    actions.push(
      "at least one finding concerns the audit-store writer split; completing " +
        "or re-running that migration as root is a separate step from anything " +
        "in the repair class"
    );
  }
  return actions;
}

// ---- Export manifest --------------------------------------------------------

/**
 * A sink that hashes what it is given and keeps none of it. The exporter writes
 * one JSON line per record, so a buffering sink would hold the entire chain in
 * memory for a fortress whose size an untrusted caller influences; `_write`
 * completes synchronously, so nothing queues (AGENTS rule 8: bounded work per
 * request).
 */
class HashingSink extends Writable {
  private readonly hash = createHash("sha256");
  private byteCount = 0;

  override _write(
    chunk: unknown,
    encoding: BufferEncoding,
    callback: (error?: Error | null) => void
  ): void {
    // The exporter writes strings; `encoding` is only honored for the string
    // case because a Buffer chunk is already bytes.
    const buffer = Buffer.isBuffer(chunk)
      ? chunk
      : Buffer.from(String(chunk), Buffer.isEncoding(encoding) ? encoding : "utf8");
    this.hash.update(buffer);
    this.byteCount += buffer.length;
    callback();
  }

  digest(): string {
    return this.hash.copy().digest("hex");
  }

  bytes(): number {
    return this.byteCount;
  }
}

async function buildExportManifest(
  storage: StorageBackend & FilesystemStorageCapabilities
): Promise<RepairPlanExportManifest> {
  const sink = new HashingSink();
  const summary: AuditChainExportSummary = await exportAuditChain(storage, sink);
  const daemonPresent = await fortressRanAuditStoreSplitMigration(storage);
  const daemonAccess = await probeDaemonChainAccess(storage);
  return {
    entries_listed: summary.entriesListed,
    entries_exported: summary.entriesExported,
    entries_skipped: summary.entriesSkipped,
    checkpoints_listed: summary.checkpointsListed,
    checkpoints_exported: summary.checkpointsExported,
    checkpoints_skipped: summary.checkpointsSkipped,
    complete: totalRecordsSkipped(summary) === 0,
    digest: sink.digest(),
    bytes: sink.bytes(),
    daemon_chain_present: daemonPresent,
    daemon_chain_access: daemonAccess,
  };
}

// ---- Custody (read-only) ----------------------------------------------------

/**
 * Resolve the master key without creating anything.
 *
 * Three differences from the castle-wall verbs' `resolveMasterKey`, each
 * required by this verb's no-mutation contract:
 *
 *  - `readStoredPassphrase`, not `getOrCreatePassphrase`: the latter MINTS a
 *    keyring item (and a fallback file) on a fortress that has none, which is
 *    state this verb must not create. A fortress with no readable passphrase is
 *    reported as unreadable, not quietly provisioned.
 *  - `firstRun` is OMITTED, which `EstablishMasterOptions` documents as "refuse
 *    first runs (existing-state callers)". A diagnostic pointed at a path that
 *    holds no fortress must say so, never establish one there.
 *  - the storage handed to `establishMaster` is the read-only guard, so the
 *    unified custody path's in-place migration and floor-enforcement writes
 *    cannot land either. On a fortress that would need one, the guard throws
 *    and the caller reports STATE_UNREADABLE. The two mechanisms overlap on
 *    purpose: the omitted `firstRun` states the intent, the guard enforces it
 *    even if a future edit re-adds the option.
 */
async function resolveMasterKeyReadOnly(opts: {
  guardedStorage: ReadOnlyStorageGuard;
  fortressPath: string;
  env: NodeJS.ProcessEnv;
}): Promise<Uint8Array> {
  const { guardedStorage, fortressPath, env } = opts;
  if (env.SANCTUARY_RECOVERY_KEY) {
    const result = await establishMaster({
      storage: guardedStorage,
      recoveryKey: env.SANCTUARY_RECOVERY_KEY,
      storagePathHint: fortressPath,
    });
    return result.masterKey;
  }

  // `readOnly` is part of this verb's no-mutation contract, not an
  // optimization: without it, reading custody from a legacy-format fallback
  // file performs an in-place format-upgrade rewrite of
  // `<fortress>/passphrase.enc` — a write the storage guard cannot see
  // because it goes through the filesystem, not the StorageBackend.
  const passphrase =
    env.SANCTUARY_PASSPHRASE ??
    (await readStoredPassphrase({ storagePath: fortressPath, readOnly: true }))
      ?.value;
  if (!passphrase) {
    throw new Error(
      "no stored fortress passphrase is readable here, and this command will " +
        "not create one; supply SANCTUARY_PASSPHRASE or run as the operator " +
        "whose keyring holds it"
    );
  }

  const result = await establishMaster({
    storage: guardedStorage,
    passphrase,
    storagePathHint: fortressPath,
  });
  return result.masterKey;
}

// ---- Args -------------------------------------------------------------------

export interface RepairPlanArgs {
  fortressPath: string;
  statePath: string;
}

export interface RepairPlanParseResult {
  args?: RepairPlanArgs;
  error?: string;
}

export function parseRepairPlanArgs(
  argv: string[],
  env: NodeJS.ProcessEnv = process.env,
  homeFallback?: string
): RepairPlanParseResult {
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress/
  // --fortress-path value must refuse, never silently resolve the default
  // fortress; repairing the wrong fortress's audit chain is a constraint-5
  // violation.
  const consumedFortress = consumeFlagValue(argv, "--fortress");
  if (consumedFortress.error !== undefined) {
    return { error: consumedFortress.error };
  }
  const consumedFortressPath = consumeFlagValue(
    consumedFortress.argv,
    "--fortress-path"
  );
  if (consumedFortressPath.error !== undefined) {
    return { error: consumedFortressPath.error };
  }
  // IC-30 fix-round finding #3: --fortress and --fortress-path are ALIASES
  // for the same value; giving both must refuse rather than let `??` below
  // silently pick --fortress over --fortress-path regardless of which one
  // the operator meant.
  if (consumedFortress.value !== undefined && consumedFortressPath.value !== undefined) {
    return { error: aliasConflictMessage("--fortress", "--fortress-path") };
  }
  const fortressFlag = consumedFortress.value ?? consumedFortressPath.value;
  const storageFlag = flagValue(argv, "--storage-path");
  // Same precedence as `audit-chain export`, so the two verbs can never be
  // pointed at different fortresses by the same invocation.
  const fortressPath =
    fortressFlag ??
    env.SANCTUARY_STORAGE_PATH ??
    env.SANCTUARY_FORTRESS_PATH ??
    homeFallback ??
    homeFortressPath();
  if (!fortressPath) {
    return { error: "a fortress path is required (--fortress <path>)" };
  }
  return {
    args: {
      fortressPath,
      statePath: storageFlag ?? resolveAuditStoragePath(fortressPath),
    },
  };
}

// ---- Entry point ------------------------------------------------------------

export interface RepairPlanContext {
  out?: NodeJS.WritableStream;
  err?: NodeJS.WritableStream;
  env?: NodeJS.ProcessEnv;
  homeFallback?: string;
}

export async function runAuditChainRepairPlan(
  argv: string[] = [],
  ctx: RepairPlanContext = {}
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;

  const parsed = parseRepairPlanArgs(argv, env, ctx.homeFallback);
  if (parsed.error || !parsed.args) {
    // Already the canonical fortress-flag-refusal shape (Error: <message>,
    // exit 2 === FORTRESS_FLAG_USAGE_EXIT_CODE); routed through the shared
    // renderer so the two can never drift apart independently.
    err.write(`${fortressFlagRefusalText(parsed.error ?? "usage error")}\n`);
    return REPAIR_PLAN_EXIT_USAGE;
  }
  const { fortressPath, statePath } = parsed.args;

  let masterKey: Uint8Array | undefined;
  try {
    // Every storage call this verb makes, directly or through the audit log,
    // the sealed-region walk, the exporter, or custody unwrap, goes through
    // this guard. It is the enforcement site for the no-mutation contract in
    // this module's header: a write anywhere on those paths throws here rather
    // than reaching the operator's fortress.
    const guardedStorage = new ReadOnlyStorageGuard(
      new FilesystemStorage(statePath)
    );

    masterKey = await resolveMasterKeyReadOnly({
      guardedStorage,
      fortressPath,
      env,
    });

    // Lenient: findings must be SURFACED, not thrown. A strict log would throw
    // on exactly the chains this verb exists to describe. `readOnly` closes
    // the one write path the storage guard cannot: the load path's
    // signing-state recovery batch reaches raw filesystem calls (namespace
    // mkdir, stale-temp sweep, lock create/unlink) that bypass the
    // StorageBackend entirely, so only the audit log itself can refuse them.
    const auditLog = new AuditLog(guardedStorage, masterKey, {
      integrityMode: "lenient",
      readOnly: true,
    });
    const findings = await auditLog.getIntegrityFindings();
    const sealedRegion = await auditLog.verifySealedRegion();
    // The single audit-chain verdict chokepoint: the clean/unclean decision is
    // folded from the routine finding count AND the sealed-region crypto
    // verdict via the shared `foldAuditChainVerdict`, never derived from
    // `findings.length` alone (which skips the sealed region and would report a
    // sealed in-place tamper as clean).
    const verdict = foldAuditChainVerdict(findings.length, sealedRegion);
    const head = await auditLog.getChainHead();
    const exportManifest = await buildExportManifest(guardedStorage);

    const state = classifyPlanState({
      verdict,
      findings,
      daemonAccess: exportManifest.daemon_chain_access,
    });
    const fortressId = fortressIdFromStoragePath(fortressPath);

    const plan: AuditChainRepairPlan = {
      schema_version: REPAIR_PLAN_SCHEMA_VERSION,
      generated_at: new Date().toISOString(),
      fortress_id: fortressId,
      sanctuary_version: getSanctuaryVersion(),
      chain_state: {
        verdict: verdict.status,
        routine_finding_count: findings.length,
        sealed_region: sealedRegion,
        tip_sequence: head.sequence,
        tip_entry_hash: head.entry_hash,
        findings: findings
          .slice(0, REPAIR_PLAN_MAX_VERBATIM_FINDINGS)
          .map((finding) => toReportFinding(finding)),
        findings_truncated: findings.length > REPAIR_PLAN_MAX_VERBATIM_FINDINGS,
      },
      export_manifest: exportManifest,
      plan: {
        state,
        observation: observationFor(state),
        next_actions: nextActionsFor(state, findings),
      },
      evidence_commitment: computeRepairPlanEvidenceCommitment({
        fortressId,
        verdict: verdict.status,
        sealedRegion,
        tipSequence: head.sequence,
        tipEntryHash: head.entry_hash,
        findings,
        exportManifest,
      }),
      evidence_commitment_scope: REPAIR_PLAN_EVIDENCE_SCOPE,
      bounds: [...REPAIR_PLAN_BOUNDS],
    };

    out.write(JSON.stringify(plan, null, 2) + "\n");
    err.write(`${state}: ${plan.plan.observation}\n`);
    return repairPlanExitCode(state);
  } catch (error) {
    // MUST-NEVER #5: a failure to read is reported as a failure to read and
    // exits non-zero. It is never rendered as a clean chain, and never as a
    // damaged one either — neither claim was earned.
    if (error instanceof ReadOnlyStorageViolationError) {
      err.write(
        `Error: audit-chain repair-plan attempted to modify fortress state and ` +
          `was refused. This is a defect in the command, not in the fortress; ` +
          `nothing was changed. ${error.message}\n`
      );
      return REPAIR_PLAN_EXIT_STATE_UNREADABLE;
    }
    err.write(
      `Error: could not read the fortress audit state, so no verdict was ` +
        `produced (this is NOT a report that the chain is clean): ` +
        `${error instanceof Error ? error.message : String(error)}\n`
    );
    return REPAIR_PLAN_EXIT_STATE_UNREADABLE;
  } finally {
    masterKey?.fill(0);
  }
}
