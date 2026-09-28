/**
 * Manual memory-file ingest, emit, transcode, and archive-restore CLI wrappers.
 *
 * These are manual transcode commands. They use the same SDW memory backend as
 * the MCP tools and deliberately do not watch, sync, or modify harness-owned
 * source files.
 */

import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";
import type { Writable } from "node:stream";

import { loadConfig } from "../config.js";
import { unlockLocalFortress } from "./local-fortress-unlock.js";
import {
  createLocalHumanApprovalInteraction,
  type MemoryArchiveDialogRunner,
} from "./memory-archive.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import { AuditLog } from "../operational/audit-log.js";
import { BaselineTracker } from "../principal-policy/baseline.js";
import type { ApprovalChannel } from "../principal-policy/approval-channel.js";
import { ApprovalGate } from "../principal-policy/gate.js";
import { loadPrincipalPolicy } from "../principal-policy/loader.js";
import {
  CLAUDE_CODE_MEMORY_HARNESS,
  emitClaudeCodeMemoryDirectory,
} from "../sdw/adapters/claude-code-file-adapter.js";
import {
  CODEX_MEMORY_HARNESS,
  emitCodexMemoryDirectory,
} from "../sdw/adapters/codex-memory-file-adapter.js";
import { SdwValidationError, sdwClassifierReasonText } from "../sdw/errors.js";
import { SdwMemoryBackendAdapter } from "../sdw/adapters/sdw-memory-backend.js";
import { ingestMemoryFiles } from "../sdw/memory-file-ingest-service.js";
import {
  checkOrEstablishSdwOwnerPin,
  precheckSdwOwnerPin,
  sdwLegacyOwnerPinNote,
  type IsolationRefusalReason,
  type SdwOwnerPinPrecheckResult,
} from "../sdw/memory-isolation.js";
import type { StorageBackend } from "../storage/interface.js";
import {
  MEMORY_TRANSCODE_MODE,
  restoreMemoryTranscodeArchive,
  transcodeMemoryDirectory,
} from "../sdw/memory-transcode.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import type { MasterWriteBarrierLease } from "../storage/cross-process-lock.js";
import { IdentityManager } from "../cognitive/tools.js";
import { createPrimaryMemoryProvenancePublicKeyResolver, createPrimaryMemoryProvenanceSigningHandleResolver } from "../sdw/memory-provenance-signing.js";
import { SdwMemoryProvenanceMigration } from "../sdw/memory-provenance-migration.js";
import {
  consumeFlagValue,
  consumeFlagValues,
  flagValue,
  fortressFlagRefusalText,
  hasFlag,
  shellQuoteSingleArg,
} from "./argv.js";

export interface MemoryFileCommandArgs {
  readonly argv: string[];
  readonly out?: Writable;
  readonly err?: Writable;
  readonly env?: NodeJS.ProcessEnv;
  /** Stdin source for `--passphrase-stdin` (tests inject a Readable). */
  readonly stdin?: NodeJS.ReadableStream;
  /**
   * Test seam: receives a REFERENCE to the unlocked master buffer at bootstrap,
   * so a test can assert the verb's `finally` zeroed it on every path — including
   * when the body errors and when the audit flush throws — without printing the
   * bytes. Production leaves it undefined.
   */
  readonly observeMasterKey?: (buf: Uint8Array) => void;
  readonly dialogRunner?: MemoryArchiveDialogRunner;
}

// Must match ownerRef: "fleet-self" in server/src/index.ts
// (sdwMemoryIsolationGuard construction) and OWNER_REF in
// server/src/cli/sdw-owner.ts: the only scope those know how to read, claim,
// or transfer. STEP1-F1/F2: a pin under any other owner_ref would be
// invisible to both, with no recovery verb, so runMemoryIngestCommand refuses
// a non-default `--owner-ref` outright (see the check below) rather than
// establishing a pin under a scope nothing else can ever reconcile.
const DEFAULT_OWNER_REF = "fleet-self";

/**
 * The wrap-time `SANCTUARY_AGENT_ID` the MCP guard's `wrappedAgentIdentityFromEnv`
 * would resolve for this SAME process (must match that function in
 * `../sdw/memory-isolation.js`), read from the CLI's OWN threaded `env`
 * (never `process.env` directly) so tests can exercise the identity-present
 * and identity-missing cases without mutating the real process environment.
 *
 * STEP1-F1 fix round 1 (Claude F3 / Grok finding 1): there is deliberately NO
 * fallback identity here. A prior version substituted a synthetic
 * `"cli-ingest"` principal when this was unset, which let an UNWRAPPED
 * ingest silently pin a fresh fortress to a principal no wrapped MCP server
 * can ever be — the exact lockout STEP1-F1 was meant to remove, just moved
 * one step over. `undefined`/empty is a hard refusal (see the caller).
 *
 * STEP1-F2: shared by every CLI verb that touches the SDW owner-pin rule
 * (`memory_ingest`, `memory_emit`, `memory_transcode`,
 * `memory_transcode_restore`), not just ingest — the wrap-time identity is
 * the same for all four verbs run inside the same wrapped harness process,
 * so there is exactly one resolver, never a per-verb copy.
 */
function resolveCliMemoryAgentId(env: NodeJS.ProcessEnv): string | undefined {
  const wrapped = env.SANCTUARY_AGENT_ID;
  return wrapped !== undefined && wrapped.length > 0 ? wrapped : undefined;
}

// fix round 2 (Claude N5): every printed remediation command shell-quotes its
// interpolated values, so an agent id or fortress path containing a space or
// shell metacharacter still pastes as the one command it names, not a
// silently different one (same discipline as shellQuoteSingleArg's own doc
// comment in argv.ts).
function sdwOwnerStatusCommand(fortress: string | undefined): string {
  return fortress !== undefined
    ? `sanctuary sdw-owner status --fortress ${shellQuoteSingleArg(fortress)}`
    : "sanctuary sdw-owner status";
}

function sdwOwnerClaimCommand(agentId: string, fortress: string | undefined): string {
  const fortressFlag = fortress !== undefined ? ` --fortress ${shellQuoteSingleArg(fortress)}` : "";
  return `sanctuary sdw-owner claim --agent-id ${shellQuoteSingleArg(agentId)}${fortressFlag}`;
}

// fix round 2 (Claude N1): also names `sdw-owner status`, the only way to
// learn the id an already-pinned store requires; `sdw-owner claim` alone only
// helps a store nothing has pinned yet.
// STEP1-F2: `command` is the exact CLI verb name printed as the message
// prefix (e.g. "memory_ingest", "memory_emit") so the four callers below
// share one function instead of four near-identical copies drifting apart.
function noWrappedAgentIdMessage(fortress: string | undefined, command: string): string {
  return (
    `${command}: refused (owner_identity_missing) - set SANCTUARY_AGENT_ID to the wrapped harness id.\n` +
    `${command}: run '${sdwOwnerStatusCommand(fortress)}' to see the required id if this store is already pinned, ` +
    `or '${sdwOwnerClaimCommand("<your wrapped harness id>", fortress)}' to claim a fresh one.\n`
  );
}

/**
 * Operator-facing text for an owner-pin refusal, printed to stderr before the
 * verb returns 1. Never invents a new reason string: the refusal `reason`
 * itself is the guard's own (STEP1-F1 constraint: reuse the MCP guard's
 * reasons verbatim). This only adds the remediation command. `command` is the
 * printed message prefix (STEP1-F2: shared by all four CLI verbs, never a
 * copy per verb).
 *
 * `owner_identity_missing` is UNREACHABLE through this function: every caller
 * refuses that case itself, before ever calling `precheckSdwOwnerPin` or
 * `checkOrEstablishSdwOwnerPin` (see `noWrappedAgentIdMessage` above and its
 * call sites), so neither of those ever returns it to here. The arm is kept
 * only so this switch stays exhaustive over `IsolationRefusalReason` (the MCP
 * guard's own inline identity check still produces it there).
 */
function describeOwnerPinRefusal(
  reason: IsolationRefusalReason,
  agentId: string,
  fortress: string | undefined,
  command: string,
): string {
  switch (reason) {
    case "owner_pin_missing_after_establishment":
      return (
        `${command}: refused (${reason}) - this SDW store already has passages but no owner pin.\n` +
        `${command}: run '${sdwOwnerClaimCommand(agentId, fortress)}' to claim it, then re-run.\n`
      );
    case "owner_scope_conflict":
      // fix round 2 (Claude N1): name `sdw-owner status`, the only way to
      // learn the pinned id — this is the message an operator who set the
      // WRONG SANCTUARY_AGENT_ID sees, so it must say how to find the right one.
      return (
        `${command}: refused (${reason}) - this SDW store is pinned to a different agent id than ${agentId}.\n` +
        `${command}: run '${sdwOwnerStatusCommand(fortress)}' to see the required id.\n`
      );
    case "owner_pin_invalid":
    case "owner_pin_backend_unsupported":
    case "owner_pin_io_error":
      return `${command}: refused (${reason}) - the SDW owner pin could not be read or established.\n`;
    case "owner_identity_missing":
      return noWrappedAgentIdMessage(fortress, command);
    case "owner_identity_malformed":
      // The shape rule lives in memory-isolation.ts (isWrappedAgentId) and is
      // reached only when this id would ESTABLISH a new pin (an already-pinned
      // store compares ids and never refuses for shape); this only names the
      // form so the operator can see what `wrap` would write.
      return (
        `${command}: refused (${reason}) - SANCTUARY_AGENT_ID ${shellQuoteSingleArg(agentId)} is not a wrapped harness id ` +
        `(<harness-kind>:fortress-<16 hex>, the value 'sanctuary wrap' writes into the harness's sanctuary MCP entry), ` +
        `and a new SDW owner pin may only bind a wrapped id.\n` +
        `${command}: re-run from the wrapped harness, or run '${sdwOwnerStatusCommand(fortress)}' to see whether the store is pinned.\n`
      );
  }
}

/**
 * STEP1-F2 fix round 1 (Grok/Claude adversarial code gate on commit
 * 0f0db45d, both UNSOUND / SOUND-WITH-FIXES on the same finding): the ONE
 * pre-bootstrap gate shared by all FOUR memory-file CLI verbs, called before
 * `bootstrap()` ever unlocks the fortress. Two checks, in this order:
 *
 *   1. A non-default `--owner-ref`. The fortress's SDW owner pin is a SINGLE
 *      fortress-wide record (`SDW_OWNER_PIN_KEY` in write-gate.ts — never
 *      keyed by `owner_ref`), and `precheckSdwOwnerPin` compares scope only
 *      once a pin ALREADY exists (memory-isolation.ts's `sameScope`), so on a
 *      genuinely fresh store it reports "fresh" for ANY `--owner-ref`. If a
 *      verb were allowed to establish that one slot under a scope other than
 *      "fleet-self" (must match `DEFAULT_OWNER_REF` above), the pin would be
 *      UNRECOVERABLE: the MCP guard and `sanctuary sdw-owner` both hard-code
 *      "fleet-self" and have no verb that reads, claims, or transfers any
 *      other `owner_ref` — the real fleet-self principal would be locked out
 *      of its own fortress with no recovery path. This is the exact lockout
 *      STEP1-F1 refused for `memory_ingest`; the gate here closes the same
 *      hole reopened through the three sibling verbs in STEP1-F2.
 *   2. A missing wrap-time `SANCTUARY_AGENT_ID` (STEP1-F1's no-synthetic-
 *      fallback-principal rule), checked at this SAME pre-bootstrap point for
 *      every verb, so a credential-less/unwrapped invocation refuses
 *      identically everywhere and never even opens the fortress.
 *
 * Neither check can write an audit entry (no fortress is open yet to hold
 * one) — same as the owner-ref check already did before this round. Returns
 * `true` (refused; the caller returns 1) or `false` (proceed to bootstrap).
 */
function refuseOwnerRefOrIdentityBeforeBootstrap(
  ownerRef: string,
  env: NodeJS.ProcessEnv,
  fortress: string | undefined,
  command: string,
  err: Writable,
): boolean {
  if (ownerRef !== DEFAULT_OWNER_REF) {
    write(
      err,
      `${command}: refused - only --owner-ref ${DEFAULT_OWNER_REF} is supported; ` +
        `the MCP guard and 'sanctuary sdw-owner' hard-code this scope and cannot read back or reconcile any other owner_ref.\n`,
    );
    return true;
  }
  if (resolveCliMemoryAgentId(env) === undefined) {
    write(err, noWrappedAgentIdMessage(fortress, command));
    return true;
  }
  return false;
}

/**
 * Bound on the `--passphrase-stdin` read so a pipe that is opened and never
 * written does not hang the command forever. An empty read falls through to the
 * normal "no credential supplied" refusal.
 */
const STDIN_READ_DEADLINE_MS = 30_000;
export const PASSPHRASE_ARGV_WARNING =
  "Warning: --passphrase puts the fortress passphrase in this process's argv, " +
  "where any local user can read it from the process list. Use " +
  "SANCTUARY_PASSPHRASE or --passphrase-stdin instead.\n";

function write(stream: Writable, text: string): void {
  stream.write(text);
}

export async function runMemoryIngestCommand(
  args: MemoryFileCommandArgs,
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;
  if (hasFlag(args.argv, "--help") || hasFlag(args.argv, "-h")) {
    printIngestHelp(out);
    return 0;
  }

  const parsed = parseCommonArgs(args.argv, "memory_ingest", err);
  if (!parsed) return 2;
  // STEP1-F1/F2 fix round 1: shared pre-bootstrap gate (owner-ref scope +
  // wrap-time identity), same function every memory-file CLI verb calls — see
  // its doc comment above for why both checks must happen before any
  // bootstrap or fortress unlock, never establish under a different scope.
  if (refuseOwnerRefOrIdentityBeforeBootstrap(parsed.ownerRef, env, parsed.fortress, "memory_ingest", err)) {
    return 1;
  }
  // Rung-1 point 3: an explicit, named, per-file escape hatch, never a global
  // force flag. Each path is exact-match only (no globs, no directories) and
  // is checked against the actual source directory listing below; an unknown
  // path is an error (see assertAllowFilesKnown in memory-file-allow-list.ts),
  // not a silently ignored one. consumeFlagValues (not the bare flagValues
  // scan) so a trailing bare --allow-file, or --allow-file followed by
  // another flag, is a loud parse error instead of a silently dropped or
  // silently wrong waiver: a requested waiver must never vanish quietly.
  const allowFileFlags = consumeFlagValues(args.argv, "--allow-file");
  if (allowFileFlags.error !== undefined) {
    write(err, `memory_ingest: ${allowFileFlags.error}
`);
    return 2;
  }
  const allowFiles: ReadonlySet<string> = new Set(allowFileFlags.values);

  // The generated policy makes memory_ingest Tier 1. An operator may relax
  // plain ingest to Tier 3; a classifier waiver stays forced Tier 1. On hosts
  // without a reviewed OS dialog, Tier 3 can still proceed while every human
  // approval request is denied.
  const humanChannel = process.platform === "darwin" || args.dialogRunner !== undefined
    ? createLocalHumanApprovalInteraction(args.dialogRunner, err)
    : null;
  const approvalChannel: ApprovalChannel = humanChannel ?? {
    async requestApproval() {
      return { decision: "deny", decided_at: new Date().toISOString(), decided_by: "channel_failure" };
    },
  };

  const boot = await bootstrap(parsed, env, err, args.stdin ?? process.stdin, args.observeMasterKey);
  if (!boot) return 1;

  try {
    // STEP1-F2 fix round 1: `refuseOwnerRefOrIdentityBeforeBootstrap` above
    // already refused and returned before `bootstrap()` ran if `env` carried
    // no wrap-time identity, so this branch is unreachable in practice. It
    // stays only because `resolveCliMemoryAgentId` is typed `string |
    // undefined` and TypeScript cannot narrow that across the two functions;
    // this is the runtime proof for the compiler, not a second policy.
    const cliIngestAgentId = resolveCliMemoryAgentId(env);
    if (cliIngestAgentId === undefined) {
      write(err, noWrappedAgentIdMessage(parsed.fortress, "memory_ingest"));
      await appendFailure(boot.auditLog, "memory_ingest", {
        harness: parsed.harness,
        owner_ref: parsed.ownerRef,
        denial_class: "owner_identity_missing",
      });
      return 1;
    }

    // READ-ONLY precheck, run BEFORE the Tier-1 approval dialog (fix round 1,
    // Claude F1 / Grok finding 2). An already-decidable refusal (pinned to a
    // different agent, or a used-but-unpinned legacy store) returns here
    // without ever bothering the operator or writing anything. It NEVER
    // creates the pin — a genuinely fresh, untouched store reports "fresh"
    // and establishment is deferred to the `authorize` success branch below,
    // so a denied dialog leaves the store exactly as it found it.
    const ownerPinPrecheck = await precheckSdwOwnerPin({
      storage: boot.storage,
      masterKey: boot.masterKey,
      fortressId: boot.fortressId,
      ownerRef: parsed.ownerRef,
      agentId: cliIngestAgentId,
    });
    if (ownerPinPrecheck.status === "refuse") {
      write(err, describeOwnerPinRefusal(ownerPinPrecheck.reason, cliIngestAgentId, parsed.fortress, "memory_ingest"));
      await appendFailure(boot.auditLog, "memory_ingest", {
        harness: parsed.harness,
        owner_ref: parsed.ownerRef,
        denial_class: ownerPinPrecheck.reason,
      });
      return 1;
    }
    if (ownerPinPrecheck.status === "pinned" && ownerPinPrecheck.legacyPin === true) {
      await noteLegacyOwnerPin(boot.auditLog, "memory_ingest", cliIngestAgentId, parsed.ownerRef, err);
    }

    // Set only by the race branch inside `authorize` below (fix round 2,
    // Grok finding / Claude N4): a `null` from `ingestMemoryFiles` otherwise
    // always means "the policy gate denied this," so the generic message
    // after the call must not fire when the REAL reason was a lost owner-pin
    // race, and that race must leave its own audit row, not silently ride
    // along as an approved-but-undone gate decision.
    let ownerPinRaceRefusal: IsolationRefusalReason | null = null;

    const result = await ingestMemoryFiles({
      adapter: boot.adapter,
      auditLog: boot.auditLog,
      harness: parsed.harness,
      sourceDir: parsed.dir,
      ownerRef: parsed.ownerRef,
      allowFiles,
      // The CLI's human/policy approval is a one-shot decision for this call.
      // A delegated grant caller must recheck its grant before commit.
      beforeCommit: async () => {},
      authorize: async () => {
        // Tier-1 gate FIRST: the service reads no source and writes no vault
        // content or ingest-intent audit, and the SDW owner pin (below) is
        // established, until this exact request is allowed. STEP1-F1 fix
        // round 1: a denied request must never leave a pin behind, so nothing
        // here writes the pin before this decision, and a "deny" returns null
        // without ever reaching the establishment step.
        const decision = await new ApprovalGate(
          await loadPrincipalPolicy(boot.fortressPath),
          boot.baseline,
          approvalChannel,
          boot.auditLog,
        ).evaluate("memory_ingest", {
          agent_id: null,
          harness: parsed.harness,
          source_dir: parsed.dir,
          owner_ref: parsed.ownerRef,
          allow_files: [...allowFiles],
        });
        const unattended = decision.allowed && decision.tier === 3 && allowFiles.size === 0;
        const humanApproved = decision.allowed &&
          (decision.tier === 1 || (allowFiles.size === 0 && decision.tier === 2)) &&
          Boolean(decision.approval_audit_id);
        const authorization = unattended
          ? {
              approvalBasis: "operator_policy_tier3" as const,
              policyTier: 3 as const,
              ...(decision.approval_audit_id ? { approvalAuditId: decision.approval_audit_id } : {}),
            }
          : humanApproved
            ? {
                approvalBasis: "human" as const,
                policyTier: decision.tier as 1 | 2,
                approvalAuditId: decision.approval_audit_id!,
              }
            : null;
        if (authorization === null) return null;

        // Establish ONLY now: the request is approved, and the precheck above
        // found nothing pinned yet ("fresh"). A "pinned" precheck means this
        // exact agent id already owns the scope — nothing to write.
        if (ownerPinPrecheck.status === "fresh") {
          const established = await checkOrEstablishSdwOwnerPin({
            storage: boot.storage,
            masterKey: boot.masterKey,
            fortressId: boot.fortressId,
            ownerRef: parsed.ownerRef,
            agentId: cliIngestAgentId,
          });
          if (!established.allowed) {
            // Lost a race with a concurrent first writer between the precheck
            // and here; deny rather than proceed under a scope we do not own.
            // This is NOT a policy denial — the gate already approved the
            // request — so it gets its own message and its own audit row
            // (fix round 2), never the generic "not permitted by the local
            // policy" line below, which would misreport an owner-pin failure
            // as a policy failure.
            ownerPinRaceRefusal = established.reason;
            write(err, describeOwnerPinRefusal(established.reason, cliIngestAgentId, parsed.fortress, "memory_ingest"));
            await appendFailure(boot.auditLog, "memory_ingest", {
              harness: parsed.harness,
              owner_ref: parsed.ownerRef,
              denial_class: established.reason,
            });
            return null;
          }
        }
        return authorization;
      },
    });
    if (result === null) {
      if (ownerPinRaceRefusal === null) {
        write(err, "Denied: memory ingest was not permitted by the local policy.\n");
      }
      return 1;
    }
    write(
      out,
      `memory_ingest: ingested ${String(result.ingested.length)} of ${String(result.source_file_count)} ${harnessLabel(parsed.harness)} memory files into owner_ref ${parsed.ownerRef}\n`,
    );
    if (result.overridden.length > 0) {
      write(
        out,
        `memory_ingest: ${String(result.overridden.length)} file(s) were overridden (classifier refusal waived by --allow-file):\n`,
      );
      for (const override of result.overridden) {
        write(out, `  overridden ${override.source_path}: ${describeMemorySkipReason(override)}\n`);
      }
    }
    if (result.unused_allow_files.length > 0) {
      write(
        err,
        `memory_ingest: WARNING - --allow-file named ${String(result.unused_allow_files.length)} path(s) the classifier never refused (nothing was waived): ${result.unused_allow_files.join(", ")}\n`,
      );
    }
    if (!result.complete) {
      // Loud, on stderr, and named per file: a partial mirror that reports only
      // a count reads exactly like a complete one.
      write(
        err,
        `memory_ingest: WARNING - the mirror is INCOMPLETE. ${String(result.skipped.length)} file(s) were refused by the secret classifier and are NOT in the vault:\n`,
      );
      for (const skip of result.skipped) {
        write(err, `  refused ${skip.source_path}: ${describeMemorySkipReason(skip)}\n`);
      }
      write(
        err,
        "memory_ingest: remove the sensitive material from those files or keep them outside the mirrored directory, then re-run.\n",
      );
    }
    return 0;
  } catch (error) {
    await appendFailure(boot.auditLog, "memory_ingest", {
      harness: parsed.harness,
      owner_ref: parsed.ownerRef,
      error_class: errorName(error),
      ...errorCategoryDetail(error),
    });
    write(err, `memory_ingest failed: ${errorMessage(error)}\n`);
    return 1;
  } finally {
    // F4: zero the owned master even if the audit flush THROWS. The flush is the
    // last consumer that needs the key, but a flush/write error must not skip the
    // fill — so it runs in an inner `finally`, never a bare sequential statement.
    // S1: the shared rotation barrier is released LAST, in its own `finally`, so
    // a flush/zeroing throw can never strand the lease and block rotate-master.
    // The flush above is this verb's final master-derived write, so releasing
    // here is releasing after the last write (AGENTS rule 12).
    try {
      try {
        await boot.auditLog.flush();
      } finally {
        boot.masterKey.fill(0);
      }
    } finally {
      await boot.barrier?.release().catch(() => undefined);
    }
  }
}

/** The three plaintext-materializing CLI verbs the owner-pin gate below
 * applies to, besides `memory_ingest` (which inlines its own copy of this
 * same two-step shape because its establishment sits inside a service
 * `authorize` callback, not a flat sequence — see `runMemoryIngestCommand`). */
type OwnerPinGatedCommand = "memory_emit" | "memory_transcode" | "memory_transcode_restore";

interface OwnerPinGateResult {
  readonly agentId: string;
  readonly precheck: SdwOwnerPinPrecheckResult;
}

/**
 * STEP1-F2: shared pre-approval half of the SAME owner-pin rule
 * `memory_ingest` applies (STEP1-F1) — the MCP persistent guard and all four
 * CLI verbs must reach one custody decision for the shared `fleet-self`
 * scope, never a per-verb copy (module doc above: "Read paths and bulk
 * plaintext export paths are the same custody question"). Resolves the
 * wrap-time identity, then runs the READ-ONLY precheck before the Tier-1
 * approval dialog, so an already-decidable refusal (pinned to a different
 * agent, or a used-but-unpinned legacy store) never bothers the operator or
 * writes anything. On refusal this writes the message and the audit denial
 * itself and returns null; the caller just propagates a `return 1`.
 */
async function precheckOwnerPinOrRefuse(
  boot: BootstrappedMemoryFileCommand,
  env: NodeJS.ProcessEnv,
  parsed: ParsedVaultArgs,
  command: OwnerPinGatedCommand,
  err: Writable,
): Promise<OwnerPinGateResult | null> {
  const agentId = resolveCliMemoryAgentId(env);
  if (agentId === undefined) {
    write(err, noWrappedAgentIdMessage(parsed.fortress, command));
    await appendFailure(boot.auditLog, command, {
      owner_ref: parsed.ownerRef,
      denial_class: "owner_identity_missing",
    });
    return null;
  }
  const precheck = await precheckSdwOwnerPin({
    storage: boot.storage,
    masterKey: boot.masterKey,
    fortressId: boot.fortressId,
    ownerRef: parsed.ownerRef,
    agentId,
  });
  if (precheck.status === "refuse") {
    write(err, describeOwnerPinRefusal(precheck.reason, agentId, parsed.fortress, command));
    await appendFailure(boot.auditLog, command, {
      owner_ref: parsed.ownerRef,
      denial_class: precheck.reason,
    });
    return null;
  }
  if (precheck.status === "pinned" && precheck.legacyPin === true) {
    await noteLegacyOwnerPin(boot.auditLog, command, agentId, parsed.ownerRef, err);
  }
  return { agentId, precheck };
}

/**
 * Post-approval half of the same gate: establishes the pin ONLY if the
 * precheck above found nothing pinned yet ("fresh"), and only from inside the
 * caller's OWN approved branch — a denied dialog must leave the store exactly
 * as it found it, same as `memory_ingest`'s `authorize` establishment step
 * (STEP1-F1 fix round 1). Must run before any plaintext is read from or
 * written into the vault by the caller. Returns true on success; on a lost
 * race with a concurrent first writer it writes the refusal and its own audit
 * denial row (never the generic policy-denied message) and returns false.
 */
async function establishOwnerPinAfterApproval(
  boot: BootstrappedMemoryFileCommand,
  gate: OwnerPinGateResult,
  parsed: ParsedVaultArgs,
  command: OwnerPinGatedCommand,
  err: Writable,
): Promise<boolean> {
  if (gate.precheck.status !== "fresh") return true;
  const established = await checkOrEstablishSdwOwnerPin({
    storage: boot.storage,
    masterKey: boot.masterKey,
    fortressId: boot.fortressId,
    ownerRef: parsed.ownerRef,
    agentId: gate.agentId,
  });
  if (established.allowed) return true;
  write(err, describeOwnerPinRefusal(established.reason, gate.agentId, parsed.fortress, command));
  await appendFailure(boot.auditLog, command, {
    owner_ref: parsed.ownerRef,
    denial_class: established.reason,
  });
  return false;
}

export async function runMemoryEmitCommand(
  args: MemoryFileCommandArgs,
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;
  if (hasFlag(args.argv, "--help") || hasFlag(args.argv, "-h")) {
    printEmitHelp(out);
    return 0;
  }

  const parsed = parseCommonArgs(args.argv, "memory_emit", err);
  if (!parsed) return 2;
  // STEP1-F2 fix round 1: same pre-bootstrap gate memory_ingest applies (see
  // its doc comment above), so a non-default --owner-ref or a missing
  // wrap-time identity refuses before any fortress unlock, dialog, or read.
  if (refuseOwnerRefOrIdentityBeforeBootstrap(parsed.ownerRef, env, parsed.fortress, "memory_emit", err)) {
    return 1;
  }

  const approvalChannel = createLocalHumanApprovalInteraction(args.dialogRunner, err);
  if (!approvalChannel) return 1;

  const boot = await bootstrap(parsed, env, err, args.stdin ?? process.stdin, args.observeMasterKey);
  if (!boot) return 1;

  try {
    // STEP1-F2: same owner-pin custody question memory_ingest answers before
    // its approval dialog (STEP1-F1) — memory_emit materializes vault content
    // as plaintext on disk, so it is one of the "bulk plaintext export paths"
    // the module doc on memory-isolation.ts names as sharing this rule.
    const ownerPinGate = await precheckOwnerPinOrRefuse(boot, env, parsed, "memory_emit", err);
    if (ownerPinGate === null) return 1;

    const decision = await new ApprovalGate(
      await loadPrincipalPolicy(boot.fortressPath),
      boot.baseline,
      approvalChannel,
      boot.auditLog,
    ).evaluate("memory_emit", {
      agent_id: null,
      harness: parsed.harness,
      output_dir: parsed.dir,
      owner_ref: parsed.ownerRef,
    });
    if (!decision.allowed || !decision.approval_audit_id) {
      write(err, "Denied: plaintext memory emission was not approved by the local operator.\n");
      return 1;
    }
    // Establish the pin only now that this exact request is approved (never
    // before, same as memory_ingest: a denied dialog leaves the store exactly
    // as it found it), and before any plaintext is read from the vault below.
    if (!(await establishOwnerPinAfterApproval(boot, ownerPinGate, parsed, "memory_emit", err))) {
      return 1;
    }
    // Write-ahead INTENT, durable before any plaintext file is materialized
    // from the vault. If appendCritical throws, emit aborts without writes.
    // Labelled `_started`: at this point no file exists on disk yet.
    await boot.auditLog.appendCritical({
      layer: "l1",
      operation: "memory_emit_started",
      identity_id: "principal",
      result: "success",
      details: {
        harness: parsed.harness,
        output_dir: parsed.dir,
        owner_ref: parsed.ownerRef,
        approval_audit_id: decision.approval_audit_id,
      },
    });
    const result = parsed.harness === CLAUDE_CODE_MEMORY_HARNESS
      ? await emitClaudeCodeMemoryDirectory(boot.adapter, parsed.dir)
      : await emitCodexMemoryDirectory(boot.adapter, parsed.dir);
    await boot.auditLog.appendCritical({
      layer: "l1",
      operation: "memory_emit",
      identity_id: "principal",
      result: "success",
      details: {
        harness: parsed.harness,
        output_dir: parsed.dir,
        owner_ref: parsed.ownerRef,
        emitted_file_count: result.emitted.length,
        index_present: result.index_present,
        approval_audit_id: decision.approval_audit_id,
      },
    });
    write(
      out,
      `memory_emit: emitted ${String(result.emitted.length)} ${harnessLabel(parsed.harness)} memory files to ${parsed.dir} (index_present: ${result.index_present ? "yes" : "no"})\n`,
    );
    if (!result.index_present) {
      write(
        err,
        `memory_emit: WARNING - emitted tree is missing MEMORY.md and cannot be re-ingested as a ${harnessLabel(parsed.harness)} memory directory.\n`,
      );
    }
    return 0;
  } catch (error) {
    await appendFailure(boot.auditLog, "memory_emit", {
      harness: parsed.harness,
      owner_ref: parsed.ownerRef,
      error_class: errorName(error),
      ...errorCategoryDetail(error),
    });
    write(err, `memory_emit failed: ${errorMessage(error)}\n`);
    return 1;
  } finally {
    // F4: zero the owned master even if the audit flush THROWS. The flush is the
    // last consumer that needs the key, but a flush/write error must not skip the
    // fill — so it runs in an inner `finally`, never a bare sequential statement.
    // S1: the shared rotation barrier is released LAST, in its own `finally`, so
    // a flush/zeroing throw can never strand the lease and block rotate-master.
    // The flush above is this verb's final master-derived write, so releasing
    // here is releasing after the last write (AGENTS rule 12).
    try {
      try {
        await boot.auditLog.flush();
      } finally {
        boot.masterKey.fill(0);
      }
    } finally {
      await boot.barrier?.release().catch(() => undefined);
    }
  }
}

export async function runMemoryTranscodeCommand(
  args: MemoryFileCommandArgs,
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;
  if (hasFlag(args.argv, "--help") || hasFlag(args.argv, "-h")) {
    printTranscodeHelp(out);
    return 0;
  }
  const parsed = parseTranscodeArgs(args.argv, err);
  if (!parsed) return 2;
  // STEP1-F2 fix round 1: same pre-bootstrap gate memory_ingest applies (see
  // its doc comment above), so a non-default --owner-ref or a missing
  // wrap-time identity refuses before any fortress unlock, dialog, or read.
  if (refuseOwnerRefOrIdentityBeforeBootstrap(parsed.ownerRef, env, parsed.fortress, "memory_transcode", err)) {
    return 1;
  }
  const approvalChannel = createLocalHumanApprovalInteraction(args.dialogRunner, err);
  if (!approvalChannel) return 1;
  const boot = await bootstrap(parsed, env, err, args.stdin ?? process.stdin, args.observeMasterKey);
  if (!boot) return 1;

  try {
    // STEP1-F2: same owner-pin custody question memory_ingest answers before
    // its approval dialog (STEP1-F1) — memory_transcode reads the SDW vault
    // and materializes a plaintext projection on disk.
    const ownerPinGate = await precheckOwnerPinOrRefuse(boot, env, parsed, "memory_transcode", err);
    if (ownerPinGate === null) return 1;

    const decision = await new ApprovalGate(
      await loadPrincipalPolicy(boot.fortressPath),
      boot.baseline,
      approvalChannel,
      boot.auditLog,
    ).evaluate("memory_transcode", {
      agent_id: null,
      from_harness: parsed.fromHarness,
      to_harness: parsed.toHarness,
      output_dir: parsed.dir,
      owner_ref: parsed.ownerRef,
    });
    if (!decision.allowed || !decision.approval_audit_id) {
      write(err, "Denied: plaintext memory transcode was not approved by the local operator.\n");
      return 1;
    }
    // Establish the pin only now that this exact request is approved, and
    // before any vault content is read below (same discipline as memory_emit
    // and memory_ingest).
    if (!(await establishOwnerPinAfterApproval(boot, ownerPinGate, parsed, "memory_transcode", err))) {
      return 1;
    }
    await boot.auditLog.appendCritical({
      layer: "l1",
      operation: "memory_transcode_started",
      identity_id: "principal",
      result: "success",
      details: {
        from_harness: parsed.fromHarness,
        to_harness: parsed.toHarness,
        mode: MEMORY_TRANSCODE_MODE,
        output_dir: parsed.dir,
        owner_ref: parsed.ownerRef,
        approval_audit_id: decision.approval_audit_id,
      },
    });
    const result = await transcodeMemoryDirectory(
      boot.adapter,
      parsed.fromHarness,
      parsed.toHarness,
      parsed.dir,
    );
    try {
      await boot.auditLog.appendCritical({
        layer: "l1",
        operation: "memory_transcode",
        identity_id: "principal",
        result: "success",
        details: {
          archive_id: result.archive_id,
          from_harness: result.from_harness,
          to_harness: result.to_harness,
          mode: result.mode,
          output_dir: parsed.dir,
          owner_ref: parsed.ownerRef,
          source_file_count: result.source_file_count,
          projection_file_count: result.projection_file_count,
          source_set_sha256: result.source_set_sha256,
          projection_set_sha256: result.projection_set_sha256,
          approval_audit_id: decision.approval_audit_id,
        },
      });
    } catch (auditError) {
      write(
        err,
        `memory_transcode completed, but its outcome audit record failed (${errorName(auditError)}). Preserve archive_id ${result.archive_id} and inspect the output before retrying.\n`,
      );
      return 1;
    }
    write(
      out,
      `memory_transcode: projected ${String(result.source_file_count)} ${harnessLabel(parsed.fromHarness)} source files into ${String(result.projection_file_count)} ${harnessLabel(parsed.toHarness)} plaintext files at ${parsed.dir}\n` +
      `memory_transcode: exact source recovery archive_id ${result.archive_id}\n`,
    );
    return 0;
  } catch (error) {
    await appendFailure(boot.auditLog, "memory_transcode", {
      from_harness: parsed.fromHarness,
      to_harness: parsed.toHarness,
      mode: MEMORY_TRANSCODE_MODE,
      owner_ref: parsed.ownerRef,
      error_class: errorName(error),
      ...errorCategoryDetail(error),
    });
    write(err, `memory_transcode failed: ${errorMessage(error)}\n`);
    return 1;
  } finally {
    // F4: zero the owned master even if the audit flush THROWS. The flush is the
    // last consumer that needs the key, but a flush/write error must not skip the
    // fill — so it runs in an inner `finally`, never a bare sequential statement.
    // S1: the shared rotation barrier is released LAST, in its own `finally`, so
    // a flush/zeroing throw can never strand the lease and block rotate-master.
    // The flush above is this verb's final master-derived write, so releasing
    // here is releasing after the last write (AGENTS rule 12).
    try {
      try {
        await boot.auditLog.flush();
      } finally {
        boot.masterKey.fill(0);
      }
    } finally {
      await boot.barrier?.release().catch(() => undefined);
    }
  }
}

export async function runMemoryTranscodeRestoreCommand(
  args: MemoryFileCommandArgs,
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;
  if (hasFlag(args.argv, "--help") || hasFlag(args.argv, "-h")) {
    printTranscodeRestoreHelp(out);
    return 0;
  }
  const parsed = parseRestoreArgs(args.argv, err);
  if (!parsed) return 2;
  // STEP1-F2 fix round 1: same pre-bootstrap gate memory_ingest applies (see
  // its doc comment above), so a non-default --owner-ref or a missing
  // wrap-time identity refuses before any fortress unlock, dialog, or read.
  if (refuseOwnerRefOrIdentityBeforeBootstrap(parsed.ownerRef, env, parsed.fortress, "memory_transcode_restore", err)) {
    return 1;
  }
  const approvalChannel = createLocalHumanApprovalInteraction(args.dialogRunner, err);
  if (!approvalChannel) return 1;
  const boot = await bootstrap(parsed, env, err, args.stdin ?? process.stdin, args.observeMasterKey);
  if (!boot) return 1;

  try {
    // STEP1-F2: same owner-pin custody question memory_ingest answers before
    // its approval dialog (STEP1-F1) — memory_transcode_restore materializes
    // exact plaintext source files from an encrypted archive onto disk.
    const ownerPinGate = await precheckOwnerPinOrRefuse(boot, env, parsed, "memory_transcode_restore", err);
    if (ownerPinGate === null) return 1;

    const decision = await new ApprovalGate(
      await loadPrincipalPolicy(boot.fortressPath),
      boot.baseline,
      approvalChannel,
      boot.auditLog,
    ).evaluate("memory_transcode_restore", {
      agent_id: null,
      archive_id: parsed.archiveId,
      output_dir: parsed.dir,
      owner_ref: parsed.ownerRef,
    });
    if (!decision.allowed || !decision.approval_audit_id) {
      write(err, "Denied: plaintext memory transcode restore was not approved by the local operator.\n");
      return 1;
    }
    // Establish the pin only now that this exact request is approved, and
    // before the archive is read below.
    if (!(await establishOwnerPinAfterApproval(boot, ownerPinGate, parsed, "memory_transcode_restore", err))) {
      return 1;
    }
    await boot.auditLog.appendCritical({
      layer: "l1",
      operation: "memory_transcode_restore_started",
      identity_id: "principal",
      result: "success",
      details: {
        archive_id: parsed.archiveId,
        output_dir: parsed.dir,
        owner_ref: parsed.ownerRef,
        approval_audit_id: decision.approval_audit_id,
      },
    });
    const result = await restoreMemoryTranscodeArchive(
      boot.adapter,
      parsed.archiveId,
      parsed.dir,
    );
    try {
      await boot.auditLog.appendCritical({
        layer: "l1",
        operation: "memory_transcode_restore",
        identity_id: "principal",
        result: "success",
        details: {
          archive_id: parsed.archiveId,
          source_harness: result.source_harness,
          output_dir: parsed.dir,
          owner_ref: parsed.ownerRef,
          restored_file_count: result.source_file_count,
          source_set_sha256: result.source_set_sha256,
          approval_audit_id: decision.approval_audit_id,
        },
      });
    } catch (auditError) {
      write(
        err,
        `memory_transcode_restore completed, but its outcome audit record failed (${errorName(auditError)}). Inspect ${parsed.dir} before retrying.\n`,
      );
      return 1;
    }
    write(
      out,
      `memory_transcode_restore: restored ${String(result.source_file_count)} exact ${harnessLabel(result.source_harness)} source files to ${parsed.dir}\n`,
    );
    return 0;
  } catch (error) {
    await appendFailure(boot.auditLog, "memory_transcode_restore", {
      archive_id: parsed.archiveId,
      owner_ref: parsed.ownerRef,
      error_class: errorName(error),
      ...errorCategoryDetail(error),
    });
    write(err, `memory_transcode_restore failed: ${errorMessage(error)}\n`);
    return 1;
  } finally {
    // F4: zero the owned master even if the audit flush THROWS. The flush is the
    // last consumer that needs the key, but a flush/write error must not skip the
    // fill — so it runs in an inner `finally`, never a bare sequential statement.
    // S1: the shared rotation barrier is released LAST, in its own `finally`, so
    // a flush/zeroing throw can never strand the lease and block rotate-master.
    // The flush above is this verb's final master-derived write, so releasing
    // here is releasing after the last write (AGENTS rule 12).
    try {
      try {
        await boot.auditLog.flush();
      } finally {
        boot.masterKey.fill(0);
      }
    } finally {
      await boot.barrier?.release().catch(() => undefined);
    }
  }
}

interface ParsedVaultArgs {
  readonly dir: string;
  readonly ownerRef: string;
  readonly fortress?: string;
  readonly passphrase?: string;
  readonly passphraseFromStdin: boolean;
}

interface ParsedCommonArgs extends ParsedVaultArgs {
  readonly harness:
    | typeof CLAUDE_CODE_MEMORY_HARNESS
    | typeof CODEX_MEMORY_HARNESS;
}

interface ParsedTranscodeArgs extends ParsedVaultArgs {
  readonly fromHarness: ParsedCommonArgs["harness"];
  readonly toHarness: ParsedCommonArgs["harness"];
}

interface ParsedRestoreArgs extends ParsedVaultArgs {
  readonly archiveId: string;
}

function parseCommonArgs(
  argv: readonly string[],
  command: "memory_ingest" | "memory_emit",
  err: Writable,
): ParsedCommonArgs | null {
  const harness = flagValue([...argv], "--harness");
  const dir = flagValue([...argv], "--dir");
  if (harness !== CLAUDE_CODE_MEMORY_HARNESS && harness !== CODEX_MEMORY_HARNESS) {
    write(err, `${command}: --harness must be "claude-code" or "codex"\n`);
    return null;
  }
  if (dir === undefined || dir.trim().length === 0) {
    write(err, `${command}: --dir is required\n`);
    return null;
  }
  const passphrase = flagValue([...argv], "--passphrase");
  if (passphrase !== undefined) {
    // The secret is already in argv by the time this runs; the warning exists so
    // the operator learns to stop, not to pretend the leak was prevented.
    write(err, PASSPHRASE_ARGV_WARNING);
  }
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress value must
  // refuse, never silently resolve the default fortress; wrong-fortress
  // memory ingest/emit operations are a constraint-5 violation.
  const consumedFortress = consumeFlagValue([...argv], "--fortress");
  if (consumedFortress.error !== undefined) {
    write(err, `${fortressFlagRefusalText(consumedFortress.error)}\n`);
    return null;
  }
  return {
    harness,
    dir,
    ownerRef: flagValue([...argv], "--owner-ref") ?? DEFAULT_OWNER_REF,
    fortress: consumedFortress.value,
    passphrase,
    passphraseFromStdin: hasFlag([...argv], "--passphrase-stdin"),
  };
}

function parseTranscodeArgs(argv: readonly string[], err: Writable): ParsedTranscodeArgs | null {
  const fromHarness = flagValue([...argv], "--from-harness");
  const toHarness = flagValue([...argv], "--to-harness");
  if (
    (fromHarness !== CLAUDE_CODE_MEMORY_HARNESS && fromHarness !== CODEX_MEMORY_HARNESS) ||
    (toHarness !== CLAUDE_CODE_MEMORY_HARNESS && toHarness !== CODEX_MEMORY_HARNESS) ||
    fromHarness === toHarness
  ) {
    write(
      err,
      "memory_transcode: --from-harness and --to-harness must name different values from claude-code or codex\n",
    );
    return null;
  }
  if (flagValue([...argv], "--mode") !== MEMORY_TRANSCODE_MODE) {
    write(err, `memory_transcode: --mode must be "${MEMORY_TRANSCODE_MODE}"\n`);
    return null;
  }
  const common = parseVaultArgs(argv, "memory_transcode", err);
  return common === null ? null : { ...common, fromHarness, toHarness };
}

function parseRestoreArgs(argv: readonly string[], err: Writable): ParsedRestoreArgs | null {
  const archiveId = flagValue([...argv], "--archive-id");
  if (archiveId === undefined || !/^[a-f0-9]{32}$/.test(archiveId)) {
    write(err, "memory_transcode_restore: --archive-id must be the 32-hex id returned by memory_transcode\n");
    return null;
  }
  const common = parseVaultArgs(argv, "memory_transcode_restore", err);
  return common === null ? null : { ...common, archiveId };
}

function parseVaultArgs(
  argv: readonly string[],
  command: string,
  err: Writable,
): ParsedVaultArgs | null {
  const dir = flagValue([...argv], "--dir");
  if (dir === undefined || dir.trim().length === 0) {
    write(err, `${command}: --dir is required\n`);
    return null;
  }
  const passphrase = flagValue([...argv], "--passphrase");
  if (passphrase !== undefined) write(err, PASSPHRASE_ARGV_WARNING);
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress value must
  // refuse, never silently resolve the default fortress; wrong-fortress
  // vault operations are a constraint-5 violation.
  const consumedFortress = consumeFlagValue([...argv], "--fortress");
  if (consumedFortress.error !== undefined) {
    write(err, `${fortressFlagRefusalText(consumedFortress.error)}\n`);
    return null;
  }
  return {
    dir,
    ownerRef: flagValue([...argv], "--owner-ref") ?? DEFAULT_OWNER_REF,
    fortress: consumedFortress.value,
    passphrase,
    passphraseFromStdin: hasFlag([...argv], "--passphrase-stdin"),
  };
}

/**
 * Read one line from stdin as the fortress passphrase.
 *
 * Failure mode to watch for: a caller that passes `--passphrase-stdin` and then
 * never writes to the pipe. That looks like a stuck command rather than a
 * credential problem, so the read is deadline-bounded and an empty result falls
 * through to the normal refusal.
 */
async function readPassphraseFromStdin(stdin: NodeJS.ReadableStream): Promise<string> {
  return new Promise((resolvePassphrase) => {
    const rl = createInterface({ input: stdin });
    let settled = false;
    const finish = (value: string): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      try {
        rl.close();
      } catch {
        // Already closed; the value is what matters.
      }
      resolvePassphrase(value);
    };
    const deadline = setTimeout(() => finish(""), STDIN_READ_DEADLINE_MS);
    rl.once("line", (line) => finish(line));
    rl.once("close", () => finish(""));
    rl.once("error", () => finish(""));
  });
}

interface BootstrappedMemoryFileCommand {
  readonly adapter: SdwMemoryBackendAdapter;
  readonly auditLog: AuditLog;
  readonly baseline: BaselineTracker;
  readonly fortressPath: string;
  /** Same backend the adapter above writes through; exposed so a caller can
   * run `checkOrEstablishSdwOwnerPin` (STEP1-F1) against the real store
   * before any ingest write, not a copy. */
  readonly storage: StorageBackend;
  /** Must match the value `adapter`/`migration` were constructed with below
   * (`fortressIdFromStoragePath(config.storage_path)`) — the owner-pin check
   * scopes to this same id. */
  readonly fortressId: string;
  /**
   * The 32-byte fortress master key, OWNED by the caller: every verb must
   * `masterKey.fill(0)` in its `finally` AFTER the audit flush (the flush is the
   * last consumer that needs the key to encrypt/sign entries). The adapter,
   * audit log, identity manager, and migration all hold this same buffer, so a
   * single zeroing scrubs every reference.
   */
  readonly masterKey: Uint8Array;
  /**
   * The shared master-rotation barrier held for this write session (S1). Every
   * memory verb here appends audit entries under the master, which are
   * master-derived fortress WRITES, so the barrier is held from unlock and each
   * verb MUST `await barrier.release()` in its `finally` AFTER the final audit
   * flush. Releasing it lets a queued `rotate-master` proceed; holding it makes
   * a concurrent rotation serialize behind this verb rather than commit
   * old-master ciphertext (AGENTS rule 12).
   */
  readonly barrier?: MasterWriteBarrierLease;
}

async function bootstrap(
  args: ParsedVaultArgs,
  env: NodeJS.ProcessEnv,
  err: Writable,
  stdin: NodeJS.ReadableStream,
  observeMasterKey?: (buf: Uint8Array) => void,
): Promise<BootstrappedMemoryFileCommand | null> {
  if (args.fortress !== undefined) {
    process.env.SANCTUARY_STORAGE_PATH = args.fortress;
  }

  const stdinPassphrase = args.passphraseFromStdin
    ? await readPassphraseFromStdin(stdin)
    : "";

  const config = await loadConfig();
  await mkdir(config.storage_path, { recursive: true, mode: 0o700 });
  const storage = new FilesystemStorage(join(config.storage_path, "state"));

  // Unlock via the shared local-fortress chokepoint: argv/stdin/env credentials
  // first (the pre-existing compatibility path), then the EXACT-fortress OS
  // keyring so a fresh host whose passphrase is already stored by `protect` can
  // run the first memory verb without re-typing a secret. `config.storage_path`
  // is exact here: `--fortress` was promoted onto SANCTUARY_STORAGE_PATH above,
  // so the keyring lookup is namespaced to THIS fortress. Never generates.
  const unlocked = await unlockLocalFortress({
    storage,
    storagePath: config.storage_path,
    ...(stdinPassphrase.length > 0
      ? { passphraseFromStdin: stdinPassphrase }
      : {}),
    ...(args.passphrase !== undefined
      ? { passphraseFromArgv: args.passphrase }
      : {}),
    env,
    // Every memory verb here appends master-derived audit entries; hold the
    // shared rotation barrier across the whole verb so a concurrent
    // rotate-master serializes or the write fails closed (S1).
    writeIntent: true,
  });
  if (!unlocked.ok) {
    // Fail closed AND diagnosable, with a secret-free remediation. The message
    // never carries credential bytes (CLAUDE.md #6).
    write(err, `Error: could not unlock the fortress: ${unlocked.message}\n`);
    return null;
  }
  const masterKey = unlocked.masterKey;
  observeMasterKey?.(masterKey);
  // Any failure between here and the successful return must zero the owned
  // master before propagating, or a construction throw would leak the live key.
  try {
    const auditLog = new AuditLog(storage, masterKey);
    const baseline = new BaselineTracker(storage, masterKey);
    await baseline.load();
    const identityManager = new IdentityManager(storage, masterKey);
    const loaded = await identityManager.load();
    if (loaded.loaded === 0 || identityManager.getDefault() === undefined) {
      masterKey.fill(0);
      // Release the writeIntent barrier on this early return too: it was acquired
      // before the unlock and is transferred to the caller ONLY on the successful
      // return below, so any bail-out here must release it itself or a stranded
      // shared lease blocks a later rotate-master for the process lifetime (S1).
      // An outer finally cannot own this — the success path must NOT release.
      await unlocked.barrier?.release().catch(() => undefined);
      write(err, "Error: fortress primary identity is unavailable.\n");
      return null;
    }
    const fortressId = fortressIdFromStoragePath(config.storage_path);
    const signingHandle = createPrimaryMemoryProvenanceSigningHandleResolver(identityManager, masterKey);
    const signerPublicKey = createPrimaryMemoryProvenancePublicKeyResolver(identityManager);
    const migration = new SdwMemoryProvenanceMigration({
      storage,
      masterKey,
      fortressId,
      ownerRef: args.ownerRef,
      resolvePrimarySigningHandle: signingHandle,
      resolveSignerPublicKey: signerPublicKey,
    });
    const adapter = new SdwMemoryBackendAdapter({
      storage,
      masterKey,
      fortressId,
      ownerRef: args.ownerRef,
      resolvePrimarySigningHandle: signingHandle,
      resolveSignerPublicKey: signerPublicKey,
      resolveMemoryIntegrityState: () => migration.getState(),
    });
    return {
      adapter,
      auditLog,
      baseline,
      fortressPath: config.storage_path,
      storage,
      fortressId,
      masterKey,
      ...(unlocked.barrier !== undefined ? { barrier: unlocked.barrier } : {}),
    };
  } catch (e) {
    masterKey.fill(0);
    // The construction failed AFTER the write barrier was acquired; release it
    // so a stranded lease does not block a later rotate-master (S1).
    await unlocked.barrier?.release().catch(() => undefined);
    throw e;
  }
}

/**
 * An already-pinned store whose owner id predates the wrapped form keeps
 * working (the shape rule binds only a NEW pin; see LEGACY PINS on
 * WRAPPED_AGENT_ID_PATTERN in sdw/memory-isolation.ts). The operator learns of
 * it through one stderr line and one audit row whose `reason` is the shared
 * note text; neither changes the verb's outcome.
 */
async function noteLegacyOwnerPin(
  auditLog: AuditLog,
  operation:
    | "memory_ingest"
    | "memory_emit"
    | "memory_transcode"
    | "memory_transcode_restore",
  storedAgentId: string,
  ownerRef: string,
  err: Writable,
): Promise<void> {
  const note = sdwLegacyOwnerPinNote(storedAgentId);
  write(err, `${operation}: note - ${note}.\n`);
  try {
    await auditLog.appendCritical({
      layer: "l1",
      operation: `${operation}_owner_pin_legacy`,
      identity_id: "system",
      result: "success",
      details: { owner_ref: ownerRef, reason: note },
    });
  } catch {
    // Advisory only: a failed note append must not refuse an allowed verb.
  }
}

async function appendFailure(
  auditLog: AuditLog,
  operation:
    | "memory_ingest"
    | "memory_emit"
    | "memory_transcode"
    | "memory_transcode_restore",
  details: Record<string, unknown>,
): Promise<void> {
  try {
    await auditLog.appendCritical({
      layer: "l1",
      operation: `${operation}_denied`,
      identity_id: "system",
      result: "failure",
      details,
    });
  } catch {
    // Preserve the original operator-visible error. The command still returns
    // non-zero and flushes whatever audit state is available in finally.
  }
}

function harnessLabel(
  harness: typeof CLAUDE_CODE_MEMORY_HARNESS | typeof CODEX_MEMORY_HARNESS,
): string {
  return harness === CLAUDE_CODE_MEMORY_HARNESS ? "Claude Code" : "Codex";
}

/**
 * Rung-1 F2: name which detector refused a file and where, in plain English,
 * instead of the constant "classifier_reject" category alone. Class and
 * location only, never the matched content. The reason-text lookup itself is
 * sdwClassifierReasonText (sdw/errors.ts), shared with the memory_ingest MCP
 * tool result so the two surfaces cannot drift on what a detector id means.
 */
function describeMemorySkipReason(skip: {
  readonly reason: string;
  readonly detector?: string;
  readonly line?: number;
}): string {
  const reasonText = sdwClassifierReasonText(skip.reason, skip.detector);
  return skip.line === undefined ? reasonText : `${reasonText} (line ${String(skip.line)})`;
}

function printIngestHelp(out: Writable): void {
  write(
    out,
    `Usage: sanctuary memory_ingest --harness=<claude-code|codex> --dir <path> [options]

Manually mirror Claude Code or Codex memory files into the encrypted SDW vault.
Source files remain plaintext and untouched; this command does not sync or watch.

Options:
  --harness <name>       Required: claude-code or codex.
  --dir <path>           Harness memory directory to read. Codex also accepts
                         the parent Codex home containing memories/.
  --allow-file <path>    Repeatable. Ingest this ONE file as-is even if the
                         secret classifier would refuse it: the source
                         filename exactly as this command names it in its
                         WARNING/refused output (e.g. Codex raw_memories.md,
                         not memories/raw_memories.md), never a glob or a
                         directory. Records an audited override naming the
                         path and the detector that would have fired. A path
                         the classifier never refused is reported as unused,
                         and an unknown path is an error. There is no flag
                         that waives the classifier for every file.
  --owner-ref <id>       Only "fleet-self" is accepted; the MCP guard and
                         'sanctuary sdw-owner' both hard-code this scope, so
                         any other value refuses before touching the vault.
  --fortress <path>      Override the fortress path.
  --passphrase-stdin     Read the fortress passphrase from stdin (preferred).
  --passphrase <value>   Fortress passphrase. Visible in the process list to
                         any local user; prefer SANCTUARY_PASSPHRASE or
                         --passphrase-stdin.
  --help, -h             Show this help.

Credential precedence: --passphrase-stdin, then --passphrase, then
SANCTUARY_PASSPHRASE, then SANCTUARY_RECOVERY_KEY, then this fortress's stored
passphrase in the OS keyring (the exact-fortress unwrap, so a host where
'sanctuary protect' already stored the passphrase opens the fortress with no
secret supplied). A locked keyring is reported; a passphrase is never generated.
`,
  );
}

function printEmitHelp(out: Writable): void {
  write(
    out,
    `Usage: sanctuary memory_emit --harness=<claude-code|codex> --dir <path> [options]

Manually emit Claude Code or Codex memory files from the encrypted SDW vault
into an operator-named output directory. Existing files are never overwritten.

Options:
  --harness <name>       Required: claude-code or codex.
  --dir <path>           Output directory for emitted plaintext files.
  --owner-ref <id>       Only "fleet-self" is accepted; the MCP guard and
                         'sanctuary sdw-owner' both hard-code this scope, so
                         any other value refuses before touching the vault.
  --fortress <path>      Override the fortress path.
  --passphrase-stdin     Read the fortress passphrase from stdin (preferred).
  --passphrase <value>   Fortress passphrase. Visible in the process list to
                         any local user; prefer SANCTUARY_PASSPHRASE or
                         --passphrase-stdin.
  --help, -h             Show this help.

Requires SANCTUARY_AGENT_ID set to the wrapped harness id, same as
memory_ingest; refuses before opening the fortress if it is unset.
`,
  );
}

function printTranscodeHelp(out: Writable): void {
  write(
    out,
    `Usage: sanctuary memory_transcode --from-harness=<claude-code|codex> --to-harness=<claude-code|codex> --mode=reversible --dir <path> [options]

Manually create a plaintext native projection in the other harness format and
a versioned encrypted archive for exact source recovery. This is not sync.

Options:
  --from-harness <name> Source harness already mirrored into the SDW vault.
  --to-harness <name>   Different destination harness format.
  --mode reversible     Required frozen transcode contract.
  --dir <path>           Empty output directory; existing files are refused.
  --owner-ref <id>       Only "fleet-self" is accepted; the MCP guard and
                         'sanctuary sdw-owner' both hard-code this scope, so
                         any other value refuses before touching the vault.
  --fortress <path>      Override the fortress path.
  --passphrase-stdin     Read the fortress passphrase from stdin (preferred).
  --passphrase <value>   Visible in the process list; prefer the environment or stdin.
  --help, -h             Show this help.

Requires SANCTUARY_AGENT_ID set to the wrapped harness id, same as
memory_ingest; refuses before opening the fortress if it is unset.
`,
  );
}

function printTranscodeRestoreHelp(out: Writable): void {
  write(
    out,
    `Usage: sanctuary memory_transcode_restore --archive-id <id> --dir <path> [options]

Restore exact plaintext source files from a completed encrypted transcode
archive into an empty output directory. This is not sync.

Options:
  --archive-id <id>      Opaque id returned by memory_transcode.
  --dir <path>           Empty output directory; existing files are refused.
  --owner-ref <id>       Only "fleet-self" is accepted; the MCP guard and
                         'sanctuary sdw-owner' both hard-code this scope, so
                         any other value refuses before touching the vault.
  --fortress <path>      Override the fortress path.
  --passphrase-stdin     Read the fortress passphrase from stdin (preferred).
  --passphrase <value>   Visible in the process list; prefer the environment or stdin.
  --help, -h             Show this help.

Requires SANCTUARY_AGENT_ID set to the wrapped harness id, same as
memory_ingest; refuses before opening the fortress if it is unset.
`,
  );
}

function errorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const cause = errorCauseMessage(errorCause(error));
  return cause === undefined ? message : `${message}; cause: ${cause}`;
}

function errorName(error: unknown): string {
  return error instanceof Error ? error.name : "Error";
}

function errorCategoryDetail(error: unknown): Record<string, string> {
  if (!(error instanceof SdwValidationError)) return {};
  const cause = errorCauseMessage(errorCause(error));
  return {
    error_category: error.category,
    ...(cause === undefined ? {} : { error_cause: cause }),
  };
}

function errorCause(error: unknown): unknown {
  return error instanceof Error ? error.cause : undefined;
}

function errorCauseMessage(cause: unknown): string | undefined {
  if (cause === undefined) return undefined;
  if (cause instanceof AggregateError) {
    return cause.errors.map((item) => errorCauseMessage(item) ?? String(item)).join("; ");
  }
  if (cause instanceof Error) return cause.message;
  return String(cause);
}
