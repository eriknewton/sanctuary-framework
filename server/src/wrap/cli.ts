#!/usr/bin/env node
/**
 * Sanctuary wrap - CLI Entry Point
 *
 * One command to wrap any MCP-compatible agent in Sanctuary's enforcement
 * chain, auto-generate a passphrase, start the Sovereignty Dashboard
 * in-process, and open it in the user's browser.
 *
 * Usage:
 *   npx @sanctuary-framework/mcp-server wrap --openclaw
 *   npx @sanctuary-framework/mcp-server wrap --hermes
 *   npx @sanctuary-framework/mcp-server wrap --claude-code
 *   npx @sanctuary-framework/mcp-server wrap --cursor
 *   npx @sanctuary-framework/mcp-server wrap --cline
 *   npx @sanctuary-framework/mcp-server wrap --mastra
 *   npx @sanctuary-framework/mcp-server wrap --wrap /path/to/config.json
 *   npx @sanctuary-framework/mcp-server wrap --unwrap
 *
 * Layer 1 vs Layer 2 (Cline, and any other harness that has both):
 *   `sanctuary wrap --cline` is the Layer 1 install-time flag handled here.
 *   It detects the operator's existing Cline VS Code extension MCP config,
 *   backs it up, and rewrites it so Sanctuary becomes the upstream gateway.
 *   The operator keeps running Cline; Sanctuary slips in front of Cline's
 *   MCP client.
 *
 *   `sanctuary wrap --tier-b cline` is the Layer 2 managed-child SDK
 *   adapter selector (see server/src/agent-contract/adapters/cline.ts).
 *   It spawns Cline as a child process and brokers MCP over stdio. This is
 *   the advanced path; most operators want Layer 1.
 */

import { writeFile, readFile, mkdir, access, lstat } from "node:fs/promises";
import { dirname, join, resolve as resolvePath } from "node:path";
import { Writable } from "node:stream";
import { platform, homedir } from "node:os";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { get as httpsGet } from "node:https";
import { get as httpGet } from "node:http";
import { outboundUpdateChecksEnabled } from "../update-check.js";
import {
  detectAgentConfigWithDiagnostics,
  backupConfig,
  saveWrapMeta,
  hasExistingWrapMeta,
  findLatestBackup,
  findNewerBackup,
  listWrapMetaPointerSummaries,
  removeWrapMeta,
  restoreConfig,
  rewriteConfigForWrap,
  getPlatformPaths,
  validateWrapMetaAuxiliary,
  writeFileSafeUnderRoot,
  unlinkSafeUnderRoot,
  WrapMetaValidationError,
  WrapMetaUnreadableError,
  type WrapMetaRemovalFailure,
  type AgentPlatform,
  type MCPServerEntry,
  type WrapMetaAuxiliaryFile,
  type ValidatedWrapMetaAuxiliaryFile,
} from "./config-reader.js";
import {
  hermesConfigYamlPath,
  planHermesYamlInjection,
  yamlContainsSanctuaryEntry,
  HermesYamlUnsupportedError,
  type HermesYamlPlan,
} from "./hermes-yaml.js";
import {
  assertHermesYamlParseParity,
  HermesYamlParityRefusedError,
} from "./hermes-yaml-parse-parity.js";
import {
  getOrCreatePassphrase,
  persistUserProvidedPassphrase,
  isOsKeyringLocation,
  PassphraseUnreadableError,
  PassphraseKeyringUnreachableError,
} from "./passphrase.js";
import { startDashboard, type DashboardHandle } from "../dashboard/index.js";
import { buildWrapFleetRosterProvider } from "./fleet-roster-provider.js";
import {
  runAutoProvisionForWrap,
  type AutoProvisionSummary,
} from "./auto-provision.js";
import type {
  DisarmNePreferenceOutcome,
  ProvisionFlowOutcome,
} from "../castle-wall/provision/index.js";
import { ProvisionLockHeldError } from "../castle-wall/provision/index.js";
import { harnessDispositionSentence } from "../egress-gate/parked-claim.js";
import {
  EGRESS_GATE_REPAIR_WITH_STAND_DOWN_ADVICE,
  EGRESS_GATE_REPAIR_WITH_STAND_DOWN_COMMAND,
  EGRESS_GATE_STAND_DOWN_EFFECT,
} from "../egress-gate/operator-advice.js";
import {
  buildV11Bindings,
  fortressIdFromStoragePath,
} from "../dashboard/v1_1/wiring.js";
import { upsertPersistedLocalAgent } from "../hub/agent-registry-persistence.js";
import type {
  LocalAgentRecord,
  LocalHarnessKind,
} from "../contracts/v1.1/local-agent-records.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { CustodyUnlockError } from "../core/master-custody.js";
import {
  establishWrapCustody,
  type WrapCustodyResult,
} from "./custody-flow.js";
import {
  AuditLog,
  type AuditEntry,
  type AuditIntegrityFinding,
} from "../operational/audit-log.js";
import {
  createDaemonAuditLog,
  resolveDaemonStorePresence,
  verifyFortressAuditFullPicture,
} from "../operational/audit-store-split.js";
import type { FeatureHealthAuditReader } from "../principal-policy/feature-health.js";
import {
  DEFAULT_ENFORCEMENT_FRESHNESS_MS,
  type ExclusiveEgressStatus,
} from "../principal-policy/posture.js";
import {
  protectionObservationFromFeatureHealth,
  protectionStateAdvice,
  protectionStateClaimFromObservation,
  type ProtectionFeatureBasis,
  type ProtectionFeatureStatus,
  type ProtectionClaimState,
  type ProtectionStateClaim,
  type ProtectionStateObservation,
} from "../egress-gate/protection-claim.js";
import {
  CASTLE_WALL_AUDIT_LAYER,
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
  CASTLE_WALL_HEARTBEAT_OPERATION,
} from "../castle-wall/constants.js";
import {
  castleWallEvidenceMatchesProtectionSubject,
  protectionSubjectForUid,
  resolveProtectionSubjectFromFortressPath,
} from "../castle-wall/subject-binding.js";
import { SubstrateSelector } from "../intelligence/selector.js";
import { installConsentGatedRedactor } from "../intelligence/privacy-tier2-redactor.js";
import { SANCTUARY_VERSION } from "../config.js";
import { recordWrappedHarnessRegistration } from "../workload-lifecycle/index.js";
import {
  formatFortressPathWritableError,
  preflightFortressPathWritable,
  resolveStoragePath,
  resolveDashboardPort,
} from "../paths.js";
import { writeTenantRuntime, clearTenantRuntime } from "../cli/agents/runtime.js";
import {
  registerHostTenant,
  TENANTS_REGISTRY_FILE_NAME,
} from "../cli/agents/tenant-registry.js";
import {
  disclosePassphrase,
  PassphraseConfirmationDeclinedError,
  PassphraseConfirmationNonInteractiveError,
} from "./recovery-key-disclosure.js";
import type { UpstreamServer, SovereigntyProfile } from "../sovereignty-profile.js";
import { runProvisionPin } from "../cli/castle-wall.js";

type ProcessShutdownCleanup = () => void | Promise<void>;

const processShutdownCleanups = new Set<ProcessShutdownCleanup>();
let processShutdownListenersInstalled = false;
let autoProvisionMutationInFlight = false;
let autoProvisionSignalRefusedOnce = false;
let autoProvisionPendingShutdownSignal: NodeJS.Signals | undefined;
let pendingAutoProvisionWasExclusiveEgress = false;
let processShutdownRequestedSignal: NodeJS.Signals | undefined;

const AUTO_PROVISION_SIGNAL_RECOVERY_COMMAND =
  "sudo sanctuary protect --hermes --provision-agent-account";

function autoProvisionSignalRecoveryGuidance(input?: { exclusiveEgress?: boolean }): string {
  const staleLockGuidance =
    "The provision lock is released on forced exit; only an abrupt process death outside the exit path should leave it stranded, and recovery will report that separately.";
  return input?.exclusiveEgress === true
    ? `after checking the machine state, use the matching recovery command: ${AUTO_PROVISION_SIGNAL_RECOVERY_COMMAND} from an interactive terminal if account creation or re-home did not reach exclusive-egress gate generation; ${EGRESS_GATE_REPAIR_WITH_STAND_DOWN_COMMAND} if an exclusive-egress gate generation exists. ${staleLockGuidance}`
    : `recover from an interactive terminal with: ${AUTO_PROVISION_SIGNAL_RECOVERY_COMMAND}. ${staleLockGuidance}`;
}

export function renderAutoProvisionSignalRefusal(
  signal: NodeJS.Signals,
  input?: { exclusiveEgress?: boolean },
): string {
  return (
    `  WARNING: received ${signal} while account provisioning is mid-flight. ` +
    "Exiting now could leave this machine half-provisioned, so this shutdown request will be honored after provisioning closes. " +
    "Press Ctrl-C again (or send the signal again) to exit immediately anyway. " +
    `If manual recovery is needed, ${autoProvisionSignalRecoveryGuidance(input)} ` +
    "Before changing state, check whether Castle Wall is armed; only run 'sudo sanctuary castle-wall disable' if it is enforcing over a half-provisioned agent."
  );
}

export function renderAutoProvisionForcedExitWarning(
  signal: NodeJS.Signals,
  input?: { exclusiveEgress?: boolean; firstSignal?: NodeJS.Signals },
): string {
  const repeatDescription =
    input?.firstSignal !== undefined && input.firstSignal !== signal
      ? `received ${signal} while account provisioning is still mid-flight after an earlier ${input.firstSignal}`
      : `received ${signal} again while account provisioning is still mid-flight`;
  return (
    `  WARNING: ${repeatDescription}; exiting now. ` +
    "Provisioning was interrupted mid-flight, no rollback was attempted, and the machine may be in a partial state. " +
    "Some shutdown records may be missing, Castle Wall teardown did not run, and a provision lock can remain only after an abrupt process death outside the exit path. " +
    `${autoProvisionSignalRecoveryGuidance(input)} ` +
    "Before changing state, check whether Castle Wall is armed; only run 'sudo sanctuary castle-wall disable' if it is enforcing over a half-provisioned agent."
  );
}

export function __setAutoProvisionMutationInFlightForTest(input: {
  inFlight: boolean;
  refusedOnce?: boolean;
  pendingShutdownSignal?: NodeJS.Signals;
}): void {
  assertWrapCliTestHookAllowed("__setAutoProvisionMutationInFlightForTest");
  autoProvisionMutationInFlight = input.inFlight;
  autoProvisionSignalRefusedOnce = input.refusedOnce ?? false;
  autoProvisionPendingShutdownSignal = input.pendingShutdownSignal;
  pendingAutoProvisionWasExclusiveEgress = false;
}

export function __resetProcessShutdownStateForTest(): void {
  assertWrapCliTestHookAllowed("__resetProcessShutdownStateForTest");
  autoProvisionMutationInFlight = false;
  autoProvisionSignalRefusedOnce = false;
  autoProvisionPendingShutdownSignal = undefined;
  pendingAutoProvisionWasExclusiveEgress = false;
  processShutdownInFlight = undefined;
  processShutdownRequestedSignal = undefined;
  processShutdownRepeatSignalCount = 0;
  processShutdownExitIssued = false;
  processShutdownCleanups.clear();
  process.removeListener("SIGINT", handleProcessShutdownSignal);
  process.removeListener("SIGTERM", handleProcessShutdownSignal);
  process.removeListener("exit", runProcessShutdownCleanups);
  processShutdownListenersInstalled = false;
}

export function __processShutdownCleanupCountForTest(): number {
  assertWrapCliTestHookAllowed("__processShutdownCleanupCountForTest");
  return processShutdownCleanups.size;
}

function assertWrapCliTestHookAllowed(name: string): void {
  if (process.env.NODE_ENV === "test" || process.env.VITEST !== undefined) return;
  throw new Error(`${name} is test-only and is disabled outside the test runner.`);
}

// FIX (N1-1 corrected, 2026-07-27): every registered cleanup starts an async
// operation (Castle Wall daemon teardown, tenant-runtime unlink, audit-log
// flush) rather than awaiting it -- `process.exit()` right after firing them
// synchronously abandons every promise past its first `await`, so a `kill
// <pid>` still lost the graceful-shutdown audit checkpoint, the
// `filter_stopped` close record, and the tenant-runtime unlink even though
// the process itself now exits. Await every cleanup to completion (via
// `Promise.allSettled` so one failing cleanup cannot block the others)
// before returning.
//
// FIX (harden-loop, late-registration drop): a single snapshot-clear-drain
// pass silently abandoned any cleanup registered by `registerProcessShutdown
// Cleanup` DURING the drain -- nothing here stops `runWrap`'s main flow
// (there is no "shutting down" flag it checks), so it keeps running in the
// same await window as this function's `Promise.allSettled`, and can
// register a brand-new cleanup (e.g. the tenant-runtime unlink registered
// right after `writeTenantRuntime` resolves) into the Set this function
// already cleared. That cleanup then sits unawaited: `process.exit()` runs
// once THIS call returns, and the only other place that would ever run it,
// `process.on("exit", runProcessShutdownCleanups)`, cannot do async work
// (Node tears down synchronously once `exit` listeners return), so it is
// abandoned at its first `await`. Loop until the set is observed empty so
// any cleanup registered while a previous batch was draining gets picked up
// by the next iteration instead of orphaned.
async function runProcessShutdownCleanups(): Promise<void> {
  while (processShutdownCleanups.size > 0) {
    const cleanups = [...processShutdownCleanups];
    processShutdownCleanups.clear();
    await Promise.allSettled(
      cleanups.map(async (cleanup) => {
        await cleanup();
      }),
    );
  }
}

// FIX (N1-1, 2026-07-26): SIGINT/SIGTERM handlers that only run cleanups
// disable Node's default termination behavior for that signal -- installing
// ANY listener suppresses the runtime's built-in "exit on signal" action, so
// `sanctuary protect` survived a plain `kill` and drills needed `kill -9`
// (drill record 2026-07-26). Exit explicitly with the conventional
// 128+signal code after cleanups complete. The `exit` listener is a
// different event (fired during an already-in-progress shutdown) and must
// keep running cleanups only -- calling `process.exit()` from inside an
// `exit` handler has no effect and would be misleading to leave in.
const SIGNAL_EXIT_CODE: Partial<Record<NodeJS.Signals, number>> = {
  SIGINT: 128 + 2,
  SIGTERM: 128 + 15,
};

// FIX (N1-1 second-signal, 2026-07-27): `process.on` (not `once`) means a
// repeat SIGINT/SIGTERM re-enters this handler while the first call is
// mid-await. Outside the provisioning mutation window, repeat signals join the
// same cleanup promise so audit flush / Castle Wall teardown are not abandoned.
let processShutdownInFlight: Promise<void> | undefined;
let processShutdownRepeatSignalCount = 0;
let processShutdownExitIssued = false;
export const PROCESS_SHUTDOWN_REPEAT_SIGNAL_GRACE_MS = 1_000;

function waitForProcessShutdownGrace(
  promise: Promise<void>,
  ms: number,
): Promise<"settled" | "timeout"> {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve("timeout"), ms);
    void promise.finally(() => {
      clearTimeout(timeout);
      resolve("settled");
    });
  });
}

export function installProcessShutdownListeners(): void {
  if (processShutdownListenersInstalled) return;
  processShutdownListenersInstalled = true;
  process.on("SIGINT", handleProcessShutdownSignal);
  process.on("SIGTERM", handleProcessShutdownSignal);
  process.on("exit", runProcessShutdownCleanups);
}

async function runProcessShutdownForSignal(signal: NodeJS.Signals): Promise<void> {
  if (processShutdownExitIssued) return;
  processShutdownRequestedSignal ??= signal;
  if (processShutdownInFlight) {
    processShutdownRepeatSignalCount += 1;
    const exitCode = SIGNAL_EXIT_CODE[processShutdownRequestedSignal] ?? 128;
    if (processShutdownRepeatSignalCount >= 2) {
      processShutdownExitIssued = true;
      processShutdownRequestedSignal = undefined;
      process.exit(exitCode);
      return;
    }
    const result = await waitForProcessShutdownGrace(
      processShutdownInFlight,
      PROCESS_SHUTDOWN_REPEAT_SIGNAL_GRACE_MS,
    );
    if (result === "timeout" && !processShutdownExitIssued) {
      processShutdownExitIssued = true;
      processShutdownRequestedSignal = undefined;
      process.exit(exitCode);
    }
    return;
  }
  processShutdownInFlight = runProcessShutdownCleanups();
  try {
    await processShutdownInFlight;
  } finally {
    processShutdownInFlight = undefined;
    processShutdownRepeatSignalCount = 0;
  }
  if (processShutdownExitIssued) return;
  processShutdownExitIssued = true;
  process.exit(SIGNAL_EXIT_CODE[signal] ?? 128);
}

function closeAutoProvisionMutationWindow(): NodeJS.Signals | undefined {
  autoProvisionMutationInFlight = false;
  autoProvisionSignalRefusedOnce = false;
  pendingAutoProvisionWasExclusiveEgress = false;
  const deferredSignal = autoProvisionPendingShutdownSignal;
  autoProvisionPendingShutdownSignal = undefined;
  return deferredSignal;
}

function tryOpenAutoProvisionMutationWindow(options: WrapOptions): boolean {
  if (processShutdownRequestedSignal !== undefined || processShutdownInFlight !== undefined) {
    // SAFETY: stderr is the operator-facing CLI channel; this fixed text names
    // only the lifecycle state and says no privileged provisioning mutation ran.
    console.error(
      `  Note: automatic account provisioning did not start because shutdown is already in flight ` +
        `(${processShutdownRequestedSignal ?? "cleanup-drain"}). No account, re-home, or Castle Wall changes were made by provisioning.`,
    );
    return false;
  }
  autoProvisionMutationInFlight = true;
  autoProvisionSignalRefusedOnce = false;
  autoProvisionPendingShutdownSignal = undefined;
  pendingAutoProvisionWasExclusiveEgress = options.exclusiveEgress === true;
  return true;
}

/** Exported for the seam: unit-test the exit code without sending real signals. */
export async function handleProcessShutdownSignal(
  signal: NodeJS.Signals,
): Promise<void> {
  if (autoProvisionMutationInFlight) {
    if (!autoProvisionSignalRefusedOnce) {
      autoProvisionSignalRefusedOnce = true;
      autoProvisionPendingShutdownSignal = signal;
      // SAFETY: stderr is the operator-facing signal channel; this fixed text
      // names only the signal and recovery command, never secrets.
      console.error(renderAutoProvisionSignalRefusal(signal, {
        exclusiveEgress: pendingAutoProvisionWasExclusiveEgress,
      }));
      return;
    }
    // SAFETY: stderr is the operator-facing signal channel; this fixed text
    // names only the signal and recovery command, never secrets.
    console.error(renderAutoProvisionForcedExitWarning(signal, {
      exclusiveEgress: pendingAutoProvisionWasExclusiveEgress,
      firstSignal: autoProvisionPendingShutdownSignal,
    }));
    const exitSignal = autoProvisionPendingShutdownSignal ?? signal;
    autoProvisionPendingShutdownSignal = undefined;
    processShutdownExitIssued = true;
    process.exit(SIGNAL_EXIT_CODE[exitSignal] ?? 128);
    return;
  }
  autoProvisionSignalRefusedOnce = false;
  await runProcessShutdownForSignal(signal);
}

/** Exported for the seam: unit-test that a registered cleanup is awaited. */
export function registerProcessShutdownCleanup(
  cleanup: ProcessShutdownCleanup,
): () => void {
  processShutdownCleanups.add(cleanup);
  return () => {
    processShutdownCleanups.delete(cleanup);
  };
}

// ── Types ───────────────────────────────────────────────────────────

export interface WrapOptions {
  /** Wrap a specific config file. */
  wrap?: string;
  /** Auto-detect OpenClaw config. */
  openclaw?: boolean;
  /** Auto-detect Hermes Agent config (NousResearch). */
  hermes?: boolean;
  /** Auto-detect Claude Code config. */
  claudeCode?: boolean;
  /** Auto-detect Cursor config. */
  cursor?: boolean;
  /** Auto-detect Cline config. */
  cline?: boolean;
  /** Auto-detect Mastra MCP config. */
  mastra?: boolean;
  /** Unwrap - restore the original config. */
  unwrap?: boolean;
  /** Explicit passphrase override. If unset, one is generated and stored. */
  passphrase?: string;
  /**
   * Operator-supplied fortress path. Overrides SANCTUARY_FORTRESS_PATH and
   * SANCTUARY_STORAGE_PATH env vars. v1.1.0 silently ignored this flag
   * (Finding T); v1.1.1 honors it end-to-end. The fortress directory is
   * created if it does not exist.
   */
  fortress?: string;
  /**
   * Dashboard port (default 3501). If bound, the loop retries
   * `preferredPort` through `preferredPort + PORT_FALLBACK_ATTEMPTS - 1`
   * regardless of the absolute port number. v0.10.0 shipped a hardcoded
   * absolute upper bound of 3510, which silently rejected multi-tenant
   * setups starting above 3510.
   */
  port?: number;
  /**
   * Persist the plaintext-remote dashboard opt-in into the wrapped harness
   * environment. The approval channel still refuses by default unless this
   * reaches the later MCP boot path.
   */
  allowPlaintextRemote?: boolean;
  /** Preview changes without writing. */
  dryRun?: boolean;
  /** Suppress auto-open of the browser. */
  noOpen?: boolean;
  /**
   * Suppress dashboard server spawn (v1.1.5, Finding AA). When set, wrap
   * persists the agent record and updates the harness config but does not
   * start a per-call dashboard server, bind a port, or print a dashboard
   * URL. Operators that want a single persistent dashboard run
   * `sanctuary dashboard &` once, then `sanctuary wrap --<harness>
   * --no-dashboard` per harness; the persistent dashboard rehydrates the
   * agent registry from the same fortress file each wrap writes.
   */
  noDashboard?: boolean;
  /**
   * Dogfood path (`--dev-dist <path>`): point the harness MCP
   * config entry at a local Sanctuary build instead of the
   * version-pinned npx registry entry. Without this, an unpublished
   * branch (e.g. an in-flight PR) gets shadowed by the npm-resolved
   * version because npx pulls from the registry, not from the local
   * checkout.
   *
   * Pass the absolute path to the build's `dist/cli.js`. The wrap CLI
   * registers `node <path>` as the `sanctuary` command. `--dev-dist`
   * is intended for local development and CI dogfood; published-version
   * wraps omit it and use the npx default unchanged.
   */
  devDist?: string;
  /**
   * Opt-in plaintext passphrase backup file path. When set, writes the
   * generated passphrase to this file at mode 0600. Default behavior
   * (unset): Keychain-only, no plaintext file on disk. v1.2.1 change:
   * previously wrap wrote passphrase-backup.txt by default.
   */
  writePassphraseBackup?: string;
  /**
   * Opt-in transparency anchoring at setup (PR-2). OFF by default. When
   * set, wrap records consent and enables publishing a salted hash
   * commitment of each enforcement checkpoint to the public Sigstore
   * Rekor transparency log. Only the salted hash, a signature from a
   * dedicated derived key, and that key's public half are ever
   * published; never checkpoint contents, counts, policy data, or
   * fortress identifiers. Passing the flag IS the explicit consent
   * action; the consent statement is printed and its hash recorded.
   * If the flag is passed and enabling fails, wrap fails LOUDLY
   * (exit 2) rather than silently continuing without anchoring.
   */
  anchorTransparency?: boolean;
  /**
   * Auto-provision Step 2 (Build 1): pre-answers the CHOICE of whether to
   * provision a dedicated agent OS account, when `protect` detects the
   * agent is running on a shared (operator) account. Fix L2: this pre-
   * answers the choice ONLY -- the privileged mutation (create account,
   * re-home, install daemon, arm) still prints its plan and, on a TTY,
   * still asks its own single confirm. `--provision-agent-account` sets
   * this true; `--no-provision-agent-account` sets it false (an explicit
   * decline, skipping straight to "cooperative wrap only"). Unset (neither
   * flag passed) leaves the interactive prompt as the sole decision point.
   */
  provisionAgentAccount?: boolean;
  /**
   * Unified Protect Slice 5 S5-6: provision in FINE-GRAINED (exclusive-
   * egress) mode -- the agent's only sanctioned egress path becomes the
   * loopback policy gate; the harness is PARK-installed and released only
   * after the gate generation commits (the S5-5 release barrier). Requires
   * `--hermes` + darwin. Off by default (the coarse drill-proven path).
   */
  exclusiveEgress?: boolean;
  /**
   * S5-6 repair verb: re-run the exclusive-egress bring-up + release barrier
   * for an already-provisioned fine-grained agent (after a flush, gate
   * crash, or degrade). Runs the MED-7 transient-pf-rule drift guard first
   * and REFUSES when foreign (VPN/firewall) rules are present in the running
   * ruleset, unless `--override-transient-pf-rules` is also passed on an
   * interactive TTY. Does not wrap anything.
   */
  repairEgressGate?: boolean;
  /**
   * Required operator acknowledgement for the S5-6/S5-7 repair and unprotect
   * verbs: the sequence stops/disables the agent harness and verifies launchd
   * settled it stopped before continuing.
   */
  standDownAgent?: boolean;
  /**
   * Explicit, interactive-only override for the repair drift guard (design
   * MED-7). TTY-only: refused on a non-interactive stdin. Audited
   * (`egress_gate_repair_override`) before any pf mutation.
   */
  overrideTransientPfRules?: boolean;
  /**
   * S5-7 unprotect verb: per-agent exclusive-egress teardown via the locked
   * registry (verified park -> generation recovery -> gate daemon down ->
   * credential/oracle teardown -> policy surfaces off -> provisioned-rule
   * scrub -> registry remove; every REMAINING confined uid's rules re-verified
   * live; the anchor is flushed only when the LAST agent leaves). Fail-closed:
   * any failure leaves remaining protection intact; idempotent re-run
   * converges. Does not delete accounts, disarm the coarse wall, or wrap
   * anything.
   */
  unprotectEgressGate?: boolean;
}

// ── Helpers ─────────────────────────────────────────────────────────

/**
 * v1.1.1 hotfix (Finding T): promote --fortress and SANCTUARY_FORTRESS_PATH
 * onto SANCTUARY_STORAGE_PATH so downstream code that reads
 * SANCTUARY_STORAGE_PATH (resolveStoragePath, etc.) sees the operator's
 * intended fortress location.
 *
 * Precedence (highest wins):
 *   1. options.fortress (--fortress CLI flag)
 *   2. SANCTUARY_FORTRESS_PATH env var
 *   3. SANCTUARY_STORAGE_PATH env var (left untouched)
 *
 * Exported for unit tests that pin precedence without standing up the
 * whole wrap flow.
 */
export function promoteFortressToStoragePath(options: {
  fortress?: string;
}): void {
  if (options.fortress) {
    process.env.SANCTUARY_STORAGE_PATH = options.fortress;
    return;
  }
  if (process.env.SANCTUARY_FORTRESS_PATH) {
    process.env.SANCTUARY_STORAGE_PATH = process.env.SANCTUARY_FORTRESS_PATH;
  }
}

/**
 * v1.1.1 hotfix (Finding B): the wrap "MCP servers found" reporting line
 * pre-fix read "MCP servers found: 0" when a re-wrap found Sanctuary
 * already present, because the filtered `agentConfig.servers` excludes
 * the canonical Sanctuary entry to avoid double-wrapping. Operators saw
 * a "0 servers" message and concluded wrap had nothing to do, even
 * though Sanctuary was clearly there.
 *
 * This helper formats counts honestly: it splits the Sanctuary entry
 * (already-wrapped) count from the other-server count and pluralizes
 * properly.
 */
export function formatMcpServerCount(
  otherCount: number,
  hasSanctuaryEntry: boolean,
): string {
  if (!hasSanctuaryEntry) {
    return `MCP servers found: ${otherCount}`;
  }
  const otherWord = otherCount === 1 ? "server" : "servers";
  return `MCP servers found: 1 Sanctuary entry (existing), ${otherCount} other ${otherWord}`;
}

/**
 * Build the env block for the sanctuary entry. These vars are required for
 * the dashboard and passphrase resolution to work after the config rewrite.
 * Pulled from process.env so they survive the rewrite.
 *
 * v1.1.2 hotfix (Finding W): persist the operator-supplied --fortress
 * path so harness restarts (Claude Code re-spawning the MCP server)
 * keep the same fortress directory. Pre-fix, --fortress was honored at
 * wrap time (via promoteFortressToStoragePath) but never written
 * into ~/.claude.json - every harness restart fell back to the default
 * fortress location, silently drifting fortress isolation across reboots.
 *
 * The args list stays constant: persistence travels through env vars
 * exclusively, matching the SANCTUARY_PASSPHRASE pattern. The runtime
 * promotion at promoteFortressToStoragePath() honors SANCTUARY_FORTRESS_PATH
 * identically, so the spawned MCP server resolves the right storage
 * path on its boot path. Resolved to absolute so subsequent CWD
 * changes do not break the persisted reference.
 */
function buildSanctuaryEnv(options: WrapOptions): Record<string, string> {
  const sanctuaryEnv: Record<string, string> = {};
  if (process.env.SANCTUARY_PASSPHRASE) {
    sanctuaryEnv.SANCTUARY_PASSPHRASE = process.env.SANCTUARY_PASSPHRASE;
  }
  if (process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN) {
    sanctuaryEnv.SANCTUARY_DASHBOARD_AUTH_TOKEN = process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
  }
  if (process.env.SANCTUARY_DASHBOARD_ENABLED) {
    sanctuaryEnv.SANCTUARY_DASHBOARD_ENABLED = process.env.SANCTUARY_DASHBOARD_ENABLED;
  }
  if (options.allowPlaintextRemote) {
    sanctuaryEnv.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE = "true";
  } else if (process.env.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE) {
    sanctuaryEnv.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE =
      process.env.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE;
  }
  if (options.fortress) {
    sanctuaryEnv.SANCTUARY_FORTRESS_PATH = resolvePath(options.fortress);
  } else if (process.env.SANCTUARY_FORTRESS_PATH) {
    sanctuaryEnv.SANCTUARY_FORTRESS_PATH = resolvePath(
      process.env.SANCTUARY_FORTRESS_PATH,
    );
  }
  return sanctuaryEnv;
}

/**
 * Resolve the command + args registered for the `sanctuary` MCP entry.
 *
 * Dogfood path (`--dev-dist <path>`): when set, point the main
 * `sanctuary` entry at a local Sanctuary build instead of the
 * npm-published version. Without this flag, an unpublished branch
 * (e.g. an in-flight PR) gets shadowed by the npm-resolved version
 * because npx pulls from the registry. Published-version wraps omit
 * the flag and use the npx default unchanged.
 *
 * Published-version form (v1.6.1 install-path hardening, F2): the entry
 * is PINNED to the version of the server that performed the wrap and
 * names the `sanctuary` bin explicitly via `-p <pkg>@<version> sanctuary`.
 * Two failure modes of the previous bare
 * `npx @sanctuary-framework/mcp-server` form drove this:
 * 1. npm's multi-bin resolution could not pick an executable for the
 *    bare package name (dead at spawn on npm >= 7 for v1.4.0..v1.6.0).
 * 2. An unpinned entry re-resolves to `latest` at every cold npx run,
 *    so what the operator approved at wrap time is silently swapped
 *    for whatever the registry serves later (no version custody).
 * `-y` keeps the non-interactive MCP spawn from wedging on the npx
 * install prompt. Upgrades re-run `sanctuary protect`, which rewrites
 * the pin to the new version.
 */
function resolveSanctuaryCommand(options: WrapOptions): {
  command: string;
  args: string[];
} {
  const useDevDist = options.devDist !== undefined;
  return {
    command: useDevDist ? "node" : "npx",
    args: useDevDist
      ? [options.devDist!]
      : [
          "-y",
          "-p",
          `@sanctuary-framework/mcp-server@${SANCTUARY_VERSION}`,
          "sanctuary",
        ],
  };
}

function resolveAutoProvisionCliBinary(options: WrapOptions): string | undefined {
  const candidate = options.devDist ?? process.argv[1];
  return candidate === undefined || candidate.length === 0
    ? undefined
    : resolvePath(candidate);
}

/**
 * Validate a `--dev-dist <path>` before it is written into the harness config
 * (Finding 4, 2026-06-25). The dogfood path registers `node <path>` as the
 * `sanctuary` MCP command; a typo'd or non-existent path produces a wrap that
 * "verifies" (the JSON check only requires a non-empty command string) but
 * whose harness entry silently fails at MCP spawn time, with no wrap-time
 * signal. Fail loudly at wrap time instead: the file must exist and end in
 * `.js`. Throws {@link DevDistInvalidError} with an actionable message.
 */
export class DevDistInvalidError extends Error {
  readonly devDist: string;
  constructor(devDist: string, reason: string) {
    super(
      `--dev-dist path is invalid: ${reason}\n` +
        `  path: ${devDist}\n` +
        `  --dev-dist must point at a built Sanctuary entrypoint .js file ` +
        `(e.g. dist/index.js). It is registered as 'node <path>' for the ` +
        `sanctuary MCP entry; a missing path would fail silently at spawn time.`
    );
    this.name = "DevDistInvalidError";
    this.devDist = devDist;
  }
}

export async function validateDevDist(devDist: string): Promise<void> {
  const resolved = resolvePath(devDist);
  if (!resolved.endsWith(".js")) {
    throw new DevDistInvalidError(devDist, "path does not end in '.js'");
  }
  try {
    await access(resolved);
  } catch {
    throw new DevDistInvalidError(devDist, "no such file");
  }
  // Reject a directory masquerading as the entrypoint.
  try {
    const st = await lstat(resolved);
    if (!st.isFile()) {
      throw new DevDistInvalidError(devDist, "path is not a regular file");
    }
  } catch (err) {
    if (err instanceof DevDistInvalidError) throw err;
    throw new DevDistInvalidError(devDist, "could not stat the path");
  }
}

/**
 * Outcome of the wrap-time pinned-version resolvability probe (2026-07-02
 * install-path hardening).
 *
 *   - "resolvable":  the registry affirmatively serves the pinned version.
 *   - "unpublished": the registry (as resolved at wrap time) is reachable
 *                    and affirmatively does NOT have the pinned version -
 *                    the MCP entry this wrap writes would be dead at spawn
 *                    time, unless the harness's own spawn directory routes
 *                    the scope to a different registry this probe cannot
 *                    see. Advisory, never a hard block.
 *   - "unreachable": the registry could not be consulted (offline, DNS,
 *                    timeout), or resolution is indirected through config
 *                    the probe cannot faithfully reproduce (a non-default
 *                    registry that may hide packages from unauthenticated
 *                    requests, or proxy-only egress) and the answer was
 *                    not an affirmative 200. Honest-unknown, never treated
 *                    as either of the affirmative outcomes.
 *   - "skipped":     the probe is OFF. ZERO-OUTBOUND-BY-DEFAULT (2026-07-05):
 *                    with neither env var set, this is the default outcome -
 *                    this probe is the same registry-metadata class of egress
 *                    as the update check, so it is gated by the same helper
 *                    (`outboundUpdateChecksEnabled`). Opt in with
 *                    SANCTUARY_UPDATE_CHECK=1. SANCTUARY_NO_UPDATE_CHECK=1 is
 *                    a back-compat alias that also keeps this off.
 */
export type PinnedVersionResolvability =
  | "resolvable"
  | "unpublished"
  | "unreachable"
  | "skipped";

/** The registry `npx` consults when nothing overrides it. */
const DEFAULT_NPM_REGISTRY = "https://registry.npmjs.org";

interface NormalizedRegistryUrl {
  /** Registry base URL with trailing slashes and userinfo removed. */
  base: string;
  /** True when the source URL carried username/password userinfo. */
  strippedCredentials: boolean;
}

/** Trim + validate an npm registry URL; strip trailing slashes and userinfo. */
function normalizeRegistryUrl(
  value: string | undefined,
): NormalizedRegistryUrl | null {
  const trimmed = value?.trim();
  if (!trimmed) return null;
  if (!trimmed.startsWith("https://") && !trimmed.startsWith("http://")) {
    return null;
  }
  try {
    const parsed = new URL(trimmed);
    const strippedCredentials =
      parsed.username !== "" || parsed.password !== "";
    parsed.username = "";
    parsed.password = "";
    return {
      base: parsed.toString().replace(/\/+$/, ""),
      strippedCredentials,
    };
  } catch {
    return null;
  }
}

/** Lenient `.npmrc` scan for the two registry keys the probe cares about. */
async function readNpmrcRegistryKeys(
  npmrcPath: string,
): Promise<{ scoped: string | null; registry: string | null }> {
  let raw: string;
  try {
    raw = await readFile(npmrcPath, "utf-8");
  } catch {
    return { scoped: null, registry: null };
  }
  let scoped: string | null = null;
  let registry: string | null = null;
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith(";")) {
      continue;
    }
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    // Last occurrence wins, matching npm's ini semantics: a first-wins scan
    // here read the OLD value of a key that tooling later re-appended
    // (`registry=` twice in one file), probed the wrong registry, and could
    // re-create the false-affirmative "unpublished" dead-pin warning.
    if (key === "@sanctuary-framework:registry") {
      scoped = value;
    } else if (key === "registry") {
      registry = value;
    }
  }
  return { scoped, registry };
}

/**
 * Walk up from `cwd` to npm's PROJECT ROOT: the nearest directory (cwd
 * included) containing `package.json` or `node_modules`, mirroring npm's
 * localPrefix resolution. npm reads the project `.npmrc` at that root,
 * not at the literal cwd, so a probe that read only `<cwd>/.npmrc` missed
 * a repo-root registry override whenever the wrap ran from a subdirectory
 * (a corporate mirror-only package then 404ed on the DEFAULT registry,
 * resolved direct, and rendered the false-affirmative "unpublished"
 * dead-pin warning npx disproves at spawn time - the same class the
 * wrong-registry and duplicate-key fixes closed). Falls back to `cwd`
 * itself when no marker exists on the walk, matching npm's default
 * localPrefix. Never throws; an unreadable candidate just keeps the walk
 * going.
 */
async function findNpmProjectRoot(cwd: string): Promise<string> {
  let dir = resolvePath(cwd);
  for (;;) {
    for (const marker of ["package.json", "node_modules"]) {
      try {
        await access(join(dir, marker));
        return dir;
      } catch {
        // Marker absent (or unreadable): keep walking up.
      }
    }
    const parent = dirname(dir);
    if (parent === dir) return resolvePath(cwd);
    dir = parent;
  }
}

/**
 * Best-effort path of npm's GLOBAL config file (`$PREFIX/etc/npmrc`, the
 * file `npm config set --location=global registry=...` writes). Mirrors
 * npm's own derivation approximately: an explicit globalconfig override in
 * the npm config env wins, then a prefix override, then node's install
 * prefix (the executable's grandparent directory on POSIX, its directory
 * on Windows). Never throws; the caller treats an absent/unreadable file
 * as "no keys", so an imprecise path only degrades to the pre-fix
 * behavior.
 */
function defaultGlobalNpmrcPath(env: NodeJS.ProcessEnv): string {
  const explicit = env.npm_config_globalconfig ?? env.NPM_CONFIG_GLOBALCONFIG;
  if (typeof explicit === "string" && explicit.trim() !== "") {
    return explicit.trim();
  }
  const prefixOverride =
    env.npm_config_prefix ?? env.NPM_CONFIG_PREFIX ?? env.PREFIX;
  const prefix =
    typeof prefixOverride === "string" && prefixOverride.trim() !== ""
      ? prefixOverride.trim()
      : platform() === "win32"
        ? dirname(process.execPath)
        : resolvePath(process.execPath, "..", "..");
  return join(prefix, "etc", "npmrc");
}

/**
 * Best-effort, WRAP-TIME approximation of the npm registry the
 * wrap-written `npx` entry will consult at spawn time (2026-07-02 fix
 * round). The probe previously hard-coded the public registry, so in a
 * private-mirror / corporate environment (registry override in `.npmrc`
 * or the npm config env) it asked the WRONG registry and rendered a false
 * dead-pin warning for an entry npx would start fine.
 *
 * Honesty limit: this resolves from the wrap process's OWN env and cwd.
 * The harness spawns the MCP entry later, possibly from a different
 * working directory whose project `.npmrc` this probe cannot see (e.g. a
 * scope override pointing at a private mirror). A direct-default result
 * here therefore does NOT guarantee spawn-time resolution also hits the
 * default registry; callers must keep the resulting "unpublished" verdict
 * advisory, never a hard block.
 *
 * Mirrors npm's per-key precedence approximately: the package-scope key
 * (`@sanctuary-framework:registry`) beats the plain `registry` key, and
 * within each key the env override beats the project `.npmrc` beats the
 * user `~/.npmrc` beats npm's GLOBAL npmrc (`$PREFIX/etc/npmrc`, resolved
 * by defaultGlobalNpmrcPath - a mirror configured only via `npm config
 * set --location=global` previously resolved default+direct and rendered
 * the same false-affirmative "unpublished" warning the other levels'
 * fixes closed); duplicate keys within one file are last-wins, matching
 * npm's ini semantics. The project `.npmrc` is read at the PROJECT ROOT
 * (findNpmProjectRoot's upward walk from cwd), matching where npm reads
 * it - the literal cwd alone missed a repo-root override when the wrap
 * ran from a subdirectory. Never throws; a winning override this probe cannot
 * interpret (npm env-var expansion like `registry=${NPM_MIRROR}`, or a
 * non-http(s) value) falls back to the public default marked `indirect`,
 * so a 404 stays honest-unknown instead of the affirmative "unpublished".
 *
 * `indirect` is true when resolution goes through machinery this bare
 * node:http(s) probe cannot faithfully reproduce - a non-default registry
 * (which may require auth npx has and the probe deliberately never sends)
 * or proxy egress (npx honors HTTPS_PROXY/HTTP_PROXY; node:https does not).
 * The caller then treats a 404 as honest-unknown instead of affirmative.
 *
 * `seams` (env/cwd/home/globalNpmrcPath) exist for tests; production
 * callers pass nothing. `globalNpmrcPath: null` means "no global npmrc"
 * (keeps hermetic tests off the host's real `$PREFIX/etc/npmrc`).
 */
export async function resolveNpmRegistryForProbe(
  seams: {
    env?: NodeJS.ProcessEnv;
    cwd?: string;
    home?: string;
    globalNpmrcPath?: string | null;
  } = {},
): Promise<{ base: string; indirect: boolean }> {
  const env = seams.env ?? process.env;
  // Guard the cwd lookup: process.cwd() THROWS (uv_cwd ENOENT) when the
  // wrap runs from a deleted directory (removed worktree, cleaned tmp
  // dir). This probe's contract is never-throws / never-blocks-the-wrap,
  // so an unresolvable cwd degrades to user-level config only (same
  // semantics as an absent project .npmrc) instead of crashing the wrap.
  let cwd: string | undefined = seams.cwd;
  if (cwd === undefined) {
    try {
      cwd = process.cwd();
    } catch {
      cwd = undefined;
    }
  }
  const globalNpmrcPath =
    seams.globalNpmrcPath !== undefined
      ? seams.globalNpmrcPath
      : defaultGlobalNpmrcPath(env);
  const files = [
    cwd !== undefined
      ? await readNpmrcRegistryKeys(
          join(await findNpmProjectRoot(cwd), ".npmrc"),
        )
      : { scoped: null as string | null, registry: null as string | null },
    await readNpmrcRegistryKeys(join(seams.home ?? homedir(), ".npmrc")),
    globalNpmrcPath !== null
      ? await readNpmrcRegistryKeys(globalNpmrcPath)
      : { scoped: null as string | null, registry: null as string | null },
  ];
  // Per-key precedence: first PRESENT raw value wins (env beats project
  // .npmrc beats user ~/.npmrc), and only then is the winner normalized.
  // Normalizing each candidate and taking the first that PARSED silently
  // skipped a higher-precedence override this probe cannot faithfully
  // reproduce (npm env-var expansion like `registry=${NPM_MIRROR}`) and
  // fell back to default+direct, where a 404 reads as the affirmative
  // "unpublished". A present-but-unnormalizable winner now resolves to the
  // default registry marked `indirect`, so a 404 stays honest-unknown.
  const firstPresent = (
    ...candidates: Array<string | null | undefined>
  ): string | null => {
    for (const candidate of candidates) {
      if (typeof candidate === "string" && candidate.trim() !== "") {
        return candidate;
      }
    }
    return null;
  };
  const scopedRaw = firstPresent(
    env["npm_config_@sanctuary-framework:registry"],
    files[0].scoped,
    files[1].scoped,
    files[2].scoped,
  );
  const plainRaw = firstPresent(
    env.npm_config_registry,
    env.NPM_CONFIG_REGISTRY,
    files[0].registry,
    files[1].registry,
    files[2].registry,
  );
  const winningRaw = scopedRaw ?? plainRaw;
  const normalized = normalizeRegistryUrl(winningRaw ?? undefined);
  const unresolvableOverride = winningRaw !== null && normalized === null;
  const base = normalized?.base ?? DEFAULT_NPM_REGISTRY;
  const credentialedOverride = normalized?.strippedCredentials === true;
  const proxied = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
  ].some((key) => {
    const value = env[key];
    return typeof value === "string" && value.trim() !== "";
  });
  return {
    base,
    indirect:
      proxied ||
      unresolvableOverride ||
      credentialedOverride ||
      base !== DEFAULT_NPM_REGISTRY,
  };
}

/**
 * Wrap-time check that the version-pinned MCP entry
 * (`-p @sanctuary-framework/mcp-server@<version> sanctuary`) actually
 * resolves on the npm registry (2026-07-02 hardening): an unpublished pin
 * - e.g. a wrap run from a not-yet-published release build without
 * `--dev-dist` - writes a dead MCP entry behind a success banner, and the
 * harness only discovers it at spawn time.
 *
 * Fail HONEST, not fail-open and not fail-closed: the caller never blocks
 * the wrap on this probe (an unreachable registry must not take wrap
 * availability down), but it downgrades the success claim with an explicit
 * warning on "unpublished" and an honest could-not-verify note on
 * "unreachable". Never throws.
 *
 * 2026-07-02 fix round (registry-config honesty): the probe consults the
 * registry npx will most likely use, resolved at WRAP time
 * (resolveNpmRegistryForProbe: npm config env, project/user/global npmrc;
 * the harness's spawn-time cwd can differ, so even an affirmative
 * "unpublished" stays advisory), and when resolution is `indirect` (non-default
 * registry, which may hide packages from this deliberately unauthenticated
 * probe, or proxy-only egress the bare GET does not traverse) a 404 is NOT
 * affirmative: it maps to "unreachable" (honest could-not-verify) instead
 * of the loud "unpublished" dead-pin warning. Only the public default
 * registry, consulted directly, can affirm "unpublished". No credential is
 * ever attached to the probe request.
 *
 * `registryBaseUrl` / `timeoutMs` are test seams; production callers use
 * the defaults. An explicit `registryBaseUrl` is treated as authoritative
 * (404 stays affirmative), preserving the seam's stub-registry semantics.
 */
export async function checkPinnedVersionResolvable(
  version: string,
  opts: { registryBaseUrl?: string; timeoutMs?: number } = {},
): Promise<PinnedVersionResolvability> {
  if (!outboundUpdateChecksEnabled()) return "skipped";
  let base: string;
  let notFoundIsAffirmative: boolean;
  if (opts.registryBaseUrl !== undefined) {
    base = opts.registryBaseUrl;
    notFoundIsAffirmative = true;
  } else {
    const resolved = await resolveNpmRegistryForProbe();
    base = resolved.base;
    notFoundIsAffirmative = !resolved.indirect;
  }
  const timeoutMs = opts.timeoutMs ?? 3000;
  const url = `${base}/@sanctuary-framework/mcp-server/${encodeURIComponent(version)}`;
  const getFn = base.startsWith("http://") ? httpGet : httpsGet;
  return new Promise((resolve) => {
    // 2026-07-02 hardening (round 14): `timeout` on the request options
    // below is a socket INACTIVITY timer (Node resets it on every byte
    // received), not a wall-clock deadline. A responder that dribbles the
    // HTTP status line slowly enough to keep beating that timer - a
    // tarpit, a misbehaving proxy, an attacker on the network path - would
    // otherwise stall this probe indefinitely, contradicting the "never
    // blocks the wrap" contract this function documents. `deadline` is the
    // hard wall-clock cap: it fires exactly once, destroys the in-flight
    // request, and resolves "unreachable" regardless of subsequent socket
    // activity. `settled` guards against a double-resolve if the deadline
    // and a request event race.
    let settled = false;
    const settle = (result: PinnedVersionResolvability) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      resolve(result);
    };
    const deadline = setTimeout(() => {
      req?.destroy();
      settle("unreachable");
    }, timeoutMs);
    let req: ReturnType<typeof httpGet> | undefined;
    try {
      req = getFn(
        url,
        { headers: { Accept: "application/json" }, timeout: timeoutMs },
        (res) => {
          // Only the response STATUS is consulted. Destroy the request
          // (not just res.resume()-drain) before settling: a drained-but-
          // open socket still has Node's per-byte inactivity timer backing
          // it, so a tarpit that dribbles the body one byte at a time
          // forever keeps that socket - and the event loop - alive even
          // after this promise has resolved. req.destroy() releases the
          // handle outright so a slow/hostile body can't outlive the
          // decision that already stopped needing it.
          req?.destroy();
          if (res.statusCode === 200) settle("resolvable");
          else if (res.statusCode === 404)
            settle(notFoundIsAffirmative ? "unpublished" : "unreachable");
          else settle("unreachable");
        },
      );
      req.on("error", () => settle("unreachable"));
      req.on("timeout", () => {
        req?.destroy();
        settle("unreachable");
      });
    } catch {
      settle("unreachable");
    }
  });
}

/** Operator-facing one-liner for what the YAML injection did / would do. */
function formatHermesYamlAction(plan: HermesYamlPlan, yamlPath: string): string {
  const preserved =
    plan.preservedEntryNames.length > 0
      ? ` (${plan.preservedEntryNames.length} existing ${
          plan.preservedEntryNames.length === 1 ? "entry" : "entries"
        } preserved)`
      : "";
  switch (plan.action) {
    case "create-file":
      return `create ${yamlPath} with the sanctuary entry under mcp_servers`;
    case "add-key":
      return `add mcp_servers with the sanctuary entry to ${yamlPath}${preserved}`;
    case "append-entry":
      return `add the sanctuary entry to mcp_servers in ${yamlPath}${preserved}`;
    case "replace-entry":
      return `update the existing sanctuary entry in ${yamlPath}${preserved}`;
  }
}

/**
 * Read-only existence probe. Returns true if `path` is reachable, false on
 * any error (absent, permission, etc.). Used to decide first-run messaging;
 * never mutates the filesystem.
 */
async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

/**
 * D4 staging, Bugs 1+2: dry-run preview of the Hermes config.yaml
 * injection. Read-only by construction (planHermesYamlInjection is pure;
 * the only filesystem touch is the readFile probe), and previews the
 * exact entry the real run would write because it shares
 * buildSanctuaryEnv / resolveSanctuaryCommand with the write path.
 */
async function reportHermesYamlDryRun(options: WrapOptions): Promise<void> {
  const yamlPath = hermesConfigYamlPath();
  let existingYaml: string | null = null;
  try {
    existingYaml = await readFile(yamlPath, "utf-8");
  } catch {
    // File absent - the plan would create it.
  }
  const sanctuaryEnv = buildSanctuaryEnv(options);
  const { command, args } = resolveSanctuaryCommand(options);
  try {
    // Preview the parse-parity guard too: a dry run should report that the
    // real run would refuse (disagreement or PyYAML-unavailable) rather than
    // previewing an edit that would not actually happen. Production uses the
    // real sidecar, resolving the python interpreter by PyYAML importability
    // across a CODE-CONTROLLED candidate list (no caller or env input); the
    // __hermesParityTestHook DI seam is test-only and stays non-injectable.
    await assertHermesYamlParseParity(existingYaml, __hermesParityTestHook.parity);
    const plan = planHermesYamlInjection(existingYaml, {
      command,
      args,
      ...(Object.keys(sanctuaryEnv).length > 0 ? { env: sanctuaryEnv } : {}),
    });
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  Hermes MCP routing: would ${formatHermesYamlAction(plan, yamlPath)}`
    );
  } catch (err) {
    if (
      err instanceof HermesYamlUnsupportedError ||
      err instanceof HermesYamlParityRefusedError
    ) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `  Hermes MCP routing: wrap would FAIL before modifying anything: ${err.message}`
      );
      return;
    }
    throw err;
  }
}

/**
 * D4 P2-3: refuse to write through a symlinked config target. writeFile
 * and copyFile follow symlinks, so a symlinked ~/.hermes/config.yaml (or a
 * symlinked restore target on unwrap) would redirect the write to an
 * arbitrary path outside the agent's config directory. lstat sees the link
 * itself; an absent path is fine (the write creates it).
 */
async function refuseSymlinkTarget(path: string, surface: string): Promise<void> {
  let isLink: boolean;
  try {
    isLink = (await lstat(path)).isSymbolicLink();
  } catch {
    return; // Absent - nothing to refuse.
  }
  if (isLink) {
    throw new Error(
      `${surface} at ${path} is a symlink; refusing to write through it. ` +
        `Replace the symlink with a regular file and re-run.`
    );
  }
}

// ── Constants ───────────────────────────────────────────────────────

/** Default CallGovernor limits for wrapped agents. */
export const WRAP_GOVERNOR_DEFAULTS = {
  volume_limit: 200,
  rate_limit_per_tool: 20,
  lifetime_limit: 1000,
} as const;

/**
 * How many consecutive ports the dashboard fallback tries, starting at
 * `preferredPort`. v0.10.0 hardcoded an absolute `MAX_PORT = 3510` cap -
 * starting above it (the documented tenant ports 3511/3512) produced an
 * empty range and the error "No free dashboard port in range 3511-3510".
 * Making the window relative to `preferredPort` fixes both the multi-tenant
 * case and the nonsensical error message.
 *
 * Exported for tests; not public API.
 */
export const PORT_FALLBACK_ATTEMPTS = 20;

// ── Dashboard integration ───────────────────────────────────────────

/** Minimal starter signature - matches `startDashboard` from ../dashboard. */
export type DashboardStarter = (opts: {
  port: number;
  host?: string;
  mode: "co-located" | "standalone";
  authToken: string;
  serverVersion: string;
}) => Promise<DashboardHandle>;

// ── Main: wrap ──────────────────────────────────────────────────────

/**
 * Wrap protection-state observation. The coarse evidence helper reads the
 * dashboard's adjudicated-flow standard for the exclusive-egress producer.
 * The banner-facing path then requires the producer's capped verdict and
 * returns a branded ProtectionStateClaim; a missing or throwing provider
 * fails closed to unknown, never green.
 *
 * Known bounded staleness: the feature-health panel treats fresh
 * Castle-Wall-originated adjudicated-flow evidence as current for its bounded
 * freshness window (10 minutes today). A later `wall_disarmed` /
 * `filter_stopped` / `arm_lease_revoked` entry now demotes that evidence, and
 * the banner requires an observed current-wrap daemon heartbeat before it lets
 * a probe render green. Residual bound: adjudicated-flow evidence and daemon
 * liveness are still bounded-window observations, not proof of the exact
 * packet-filter state at the print instant.
 */
type CastleWallFeatureProbeInput =
  | { purpose: "coarse-wall" }
  | {
      purpose: "protection-claim";
      exclusiveEgress: ExclusiveEgressStatus | null;
      protectionClaimSubject: string | null;
    };

type CastleWallFeatureProbeResult = {
  status: ProtectionFeatureStatus | undefined;
  basis: ProtectionFeatureBasis | undefined;
};

type AuditQueryResult = Awaited<ReturnType<FeatureHealthAuditReader["query"]>>;

interface WrapAuditEvidenceReader extends FeatureHealthAuditReader {
  runEagerReads<T>(fn: () => Promise<T>): Promise<T>;
  incompleteEvidenceReasons?: readonly string[];
}

function protectionSubjectFromAutoProvisionSummary(
  summary: AutoProvisionSummary,
  fortressId: string,
): string | null {
  const outcome = summary.outcome;
  if (outcome === undefined || !("uid" in outcome)) return null;
  return protectionSubjectForUid(fortressId, outcome.uid);
}

async function resolveWrapProtectionClaimSubject(input: {
  storagePath: string;
  autoProvisionSummary: AutoProvisionSummary;
}): Promise<string | null> {
  const fortressId = fortressIdFromStoragePath(input.storagePath);
  return (
    protectionSubjectFromAutoProvisionSummary(
      input.autoProvisionSummary,
      fortressId,
    ) ??
    (await resolveProtectionSubjectFromFortressPath(
      input.storagePath,
      fortressId,
    )).subject
  );
}

function compareAuditEntriesByTimestamp(a: AuditEntry, b: AuditEntry): number {
  const aMs = Date.parse(a.timestamp);
  const bMs = Date.parse(b.timestamp);
  if (Number.isFinite(aMs) && Number.isFinite(bMs) && aMs !== bMs) {
    return aMs - bMs;
  }
  return a.timestamp.localeCompare(b.timestamp);
}

function daemonChainUnavailableFinding(message: string): AuditIntegrityFinding {
  return {
    kind: "storage_unavailable",
    message,
  };
}

function mergedAuditQueryTruncatedFinding(input: {
  total: number;
  returned: number;
  limit: number;
}): AuditIntegrityFinding {
  return daemonChainUnavailableFinding(
    `dual-chain audit query returned ${input.returned} of ${input.total} matching entries (limit ${input.limit}); read is incomplete`,
  );
}

function mergeAuditQueryResults(
  operator: AuditQueryResult,
  daemon: AuditQueryResult,
  limit: number,
): AuditQueryResult {
  const safeLimit = Number.isInteger(limit) && limit > 0 ? limit : 50;
  const entries = [...operator.entries, ...daemon.entries]
    .sort(compareAuditEntriesByTimestamp)
    .slice(-safeLimit);
  const total = operator.total + daemon.total;
  const integrityFindings = [
    ...operator.integrity_findings,
    ...daemon.integrity_findings,
  ];
  if (total > entries.length) {
    integrityFindings.push(
      mergedAuditQueryTruncatedFinding({
        total,
        returned: entries.length,
        limit: safeLimit,
      }),
    );
  }
  return {
    entries,
    total,
    integrity_findings: integrityFindings,
  };
}

type WrapDualAuditEvidence =
  | { kind: "operator_only" }
  | {
      kind: "dual_chain";
      auditStorage: FilesystemStorage;
      masterKey: Uint8Array;
    }
  | { kind: "invalid"; reason: string };

function dualAuditEvidenceFromInput(input: {
  auditStorage?: FilesystemStorage;
  masterKey?: Uint8Array;
}): WrapDualAuditEvidence {
  if (input.auditStorage === undefined && input.masterKey === undefined) {
    return { kind: "operator_only" };
  }
  if (input.auditStorage !== undefined && input.masterKey !== undefined) {
    return {
      kind: "dual_chain",
      auditStorage: input.auditStorage,
      masterKey: input.masterKey,
    };
  }
  return {
    kind: "invalid",
    reason:
      "dual-chain audit evidence requires both audit storage and master key",
  };
}

async function createWrapAuditEvidenceReader(input: {
  auditLog: AuditLog;
  dualAuditEvidence: WrapDualAuditEvidence;
}): Promise<WrapAuditEvidenceReader> {
  const { auditLog, dualAuditEvidence } = input;
  if (dualAuditEvidence.kind === "operator_only") {
    return auditLog;
  }
  if (dualAuditEvidence.kind === "invalid") {
    const finding = daemonChainUnavailableFinding(dualAuditEvidence.reason);
    return {
      query: async (options) => {
        const operator = await auditLog.queryEager(options);
        return {
          ...operator,
          integrity_findings: [...operator.integrity_findings, finding],
        };
      },
      runEagerReads: (fn) => auditLog.runEagerReads(fn),
      verifySealedRegion: () => auditLog.verifySealedRegion(),
    };
  }
  const { auditStorage, masterKey } = dualAuditEvidence;

  try {
    const fullPicture = await verifyFortressAuditFullPicture({
      storage: auditStorage,
      masterKey,
    });
    if (fullPicture.daemon.status === "absent") {
      return auditLog;
    }
    if (fullPicture.daemon.status === "present_unreadable") {
      const presence = await resolveDaemonStorePresence(auditStorage, masterKey);
      const unreadableReason =
        presence.kind === "present_unreadable" ? presence.reason : "io";
      if (unreadableReason !== "privilege") {
        const finding = daemonChainUnavailableFinding(
          `daemon audit chain is present_unreadable/${unreadableReason}: ${fullPicture.daemon.note}`,
        );
        return {
          query: async (options) => {
            const operator = await auditLog.queryEager(options);
            return {
              ...operator,
              integrity_findings: [...operator.integrity_findings, finding],
            };
          },
          runEagerReads: (fn) => auditLog.runEagerReads(fn),
          verifySealedRegion: () => auditLog.verifySealedRegion(),
        };
      }
      return {
        query: (options) => auditLog.queryEager(options),
        runEagerReads: (fn) => auditLog.runEagerReads(fn),
        verifySealedRegion: () => auditLog.verifySealedRegion(),
        incompleteEvidenceReasons: [fullPicture.daemon.note],
      };
    }
    if (fullPicture.daemon.status !== "verified") {
      const findings =
        fullPicture.daemon.status === "findings" &&
        fullPicture.daemon.findings !== undefined
          ? fullPicture.daemon.findings
          : [
              daemonChainUnavailableFinding(
                `daemon audit chain is ${fullPicture.daemon.status}: ${fullPicture.daemon.note}`,
              ),
            ];
      return {
        query: async (options) => {
          const operator = await auditLog.queryEager(options);
          return {
            ...operator,
            integrity_findings: [...operator.integrity_findings, ...findings],
          };
        },
        runEagerReads: (fn) => auditLog.runEagerReads(fn),
        verifySealedRegion: () => auditLog.verifySealedRegion(),
      };
    }

    const daemonLog = createDaemonAuditLog(auditStorage, masterKey, {
      integrityMode: "lenient",
    });
    return {
      query: async (options) => {
        const limit = options.limit ?? 50;
        const [operator, daemon] = await Promise.all([
          auditLog.queryEager(options),
          daemonLog.queryEager(options),
        ]);
        return mergeAuditQueryResults(operator, daemon, limit);
      },
      runEagerReads: (fn) => auditLog.runEagerReads(fn),
      verifySealedRegion: () => auditLog.verifySealedRegion(),
    };
  } catch (err) {
    const finding = daemonChainUnavailableFinding(
      `dual-chain audit evidence could not be verified: ${(err as Error).message}`,
    );
    return {
      query: async (options) => {
        const operator = await auditLog.queryEager(options);
        return {
          ...operator,
          integrity_findings: [...operator.integrity_findings, finding],
        };
      },
      runEagerReads: (fn) => auditLog.runEagerReads(fn),
      verifySealedRegion: () => auditLog.verifySealedRegion(),
    };
  }
}

function appendProtectionObservationReasons(
  observation: ProtectionStateObservation,
  reasons: readonly string[] | undefined,
): ProtectionStateObservation {
  if (reasons === undefined || reasons.length === 0) return observation;
  const merged = [...(observation.reasons ?? []), ...reasons];
  switch (observation.state) {
    case "exclusive":
      return { ...observation, reasons: merged };
    case "coarse-only":
      return { ...observation, reasons: merged };
    case "unprotected":
      return { ...observation, reasons: merged };
    case "unknown":
      return { ...observation, reasons: merged };
  }
}

async function readCastleWallEgressFeatureStatus(
  auditLog: WrapAuditEvidenceReader,
  storagePath: string,
  input: CastleWallFeatureProbeInput,
): Promise<CastleWallFeatureProbeResult> {
  const { buildFeatureHealthPanel } = await import(
    "../principal-policy/feature-health.js"
  );
  const { loadFortressProducerKey } = await import(
    "../castle-wall/runtime/producer-signature.js"
  );
  const { readEnforcementAvailabilityStatus } = await import(
    "../castle-wall/runtime/enforcement-availability-status.js"
  );
  const keyLoad = await loadFortressProducerKey(storagePath);
  const enforcementAvailabilityStatus =
    await readEnforcementAvailabilityStatus(storagePath);
  // Eager-read scope: same one-verified-view discipline as the dashboard
  // callers of buildFeatureHealthPanel (H4 chokepoint).
  const panel = await auditLog.runEagerReads(() =>
    buildFeatureHealthPanel({
      auditLog,
      originMachine: fortressIdFromStoragePath(storagePath),
      pinnedProducerKeyB64url:
        keyLoad.status === "present" ? keyLoad.keyB64url : null,
      ...(keyLoad.status === "unreadable"
        ? { producerKeyExpectedButUnavailable: true }
        : {}),
      ...(input.purpose === "protection-claim" &&
      input.exclusiveEgress !== null
        ? { exclusiveEgress: input.exclusiveEgress }
        : {}),
      protectionClaimSubject:
        input.purpose === "protection-claim"
          ? input.protectionClaimSubject ?? null
          : fortressIdFromStoragePath(storagePath),
      ...(enforcementAvailabilityStatus !== null
        ? { enforcementAvailabilityStatus }
        : {}),
      ...(input.purpose === "coarse-wall"
        ? {
            protectionSubjectMatchMode: {
              mode: "fortress_scoped" as const,
              fortressId: fortressIdFromStoragePath(storagePath),
            },
          }
        : {}),
    }),
  );
  const row = panel.rows.find((r) => r.feature_id === "castle_wall_egress");
  return { status: row?.status, basis: row?.basis };
}

/**
 * Coarse-wall evidence probe for callers that are building the exclusive-
 * egress provider itself. It deliberately does NOT render protection prose:
 * protection rendering goes through `probeCastleWallProtectionClaim`, which
 * requires the capped exclusive-egress verdict.
 */
export async function probeCoarseCastleWallEnforcementObserved(
  auditLog: WrapAuditEvidenceReader,
  storagePath: string,
): Promise<boolean> {
  try {
    return (
      (await readCastleWallEgressFeatureStatus(auditLog, storagePath, {
        purpose: "coarse-wall",
      })).status === "active"
    );
  } catch {
    return false;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasCastleWallAuditProvenance(details: unknown): boolean {
  return (
    isRecord(details) &&
    details[CASTLE_WALL_AUDIT_PROVENANCE_KEY] ===
      CASTLE_WALL_AUDIT_PROVENANCE_VALUE
  );
}

const CASTLE_WALL_DAEMON_START_OPERATION = "filter_started" as const;

function stringDetail(
  details: Record<string, unknown>,
  key: string,
): string | undefined {
  const value = details[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function daemonAttributionKey(details: unknown): string | undefined {
  if (!isRecord(details)) return undefined;
  const socketPath = stringDetail(details, "socket_path");
  const source = stringDetail(details, "source");
  if (socketPath === undefined || source === undefined) return undefined;
  return `${source}\u0000${socketPath}`;
}

function currentWrapHeartbeatAttribution(details: unknown): string | undefined {
  if (!isRecord(details) || !hasCastleWallAuditProvenance(details)) {
    return undefined;
  }
  const daemonMode = details.daemon_mode;
  if (daemonMode !== "full" && daemonMode !== "safe") return undefined;
  return daemonAttributionKey(details);
}

/**
 * Current-wrap daemon liveness gate for the banner resolver. This observes a
 * daemon-shaped, provenance-marked heartbeat after the daemon-start attempt and
 * inside the existing freshness window, paired to this wrap's daemon start entry.
 * The subject match is fortress-scoped because a heartbeat proves the daemon is
 * alive for this fortress, not that any one confined agent has subject-bound
 * enforcement evidence. It never earns green by itself; exact-subject
 * enforcement evidence remains required downstream.
 */
export async function observeCurrentWrapCastleWallDaemonLiveness(
  auditLog: WrapAuditEvidenceReader,
  storagePath: string,
  daemonLivenessSince: Date | undefined,
  nowMs: number = Date.now(),
): Promise<boolean> {
  const sinceMs = daemonLivenessSince?.getTime();
  if (sinceMs === undefined || !Number.isFinite(sinceMs)) {
    return false;
  }
  const freshnessFloorMs = nowMs - DEFAULT_ENFORCEMENT_FRESHNESS_MS;
  try {
    const limit = 10_000;
    const fortressId = fortressIdFromStoragePath(storagePath);
    const livenessMatchMode = {
      mode: "fortress_scoped" as const,
      fortressId,
    };
    const result = await auditLog.runEagerReads(() =>
      auditLog.query({
        layer: CASTLE_WALL_AUDIT_LAYER,
        since: new Date(sinceMs).toISOString(),
        limit,
      }),
    );
    // audit-chokepoint-exempt: fail-closed liveness gate; raw integrity
    // findings only block the banner from rendering green.
    if (
      result.integrity_findings.length > 0 ||
      result.total > result.entries.length
    ) {
      return false;
    }
    const currentWrapDaemonStarts = new Map<string, number>();
    for (const entry of result.entries) {
      if (entry.operation !== CASTLE_WALL_DAEMON_START_OPERATION) continue;
      if (entry.result !== "success") continue;
      if (
        !castleWallEvidenceMatchesProtectionSubject(
          null,
          entry,
          livenessMatchMode,
        ).matches
      ) {
        continue;
      }
      const ts = Date.parse(entry.timestamp);
      if (!Number.isFinite(ts) || ts < sinceMs) continue;
      const key = daemonAttributionKey(entry.details);
      if (key === undefined) continue;
      const previous = currentWrapDaemonStarts.get(key);
      if (previous === undefined || ts > previous) {
        currentWrapDaemonStarts.set(key, ts);
      }
    }
    return result.entries.some((entry) => {
      if (entry.operation !== CASTLE_WALL_HEARTBEAT_OPERATION) return false;
      if (entry.result !== "success") return false;
      if (
        !castleWallEvidenceMatchesProtectionSubject(
          null,
          entry,
          livenessMatchMode,
        ).matches
      ) {
        return false;
      }
      const ts = Date.parse(entry.timestamp);
      const key = currentWrapHeartbeatAttribution(entry.details);
      const startTs = key === undefined ? undefined : currentWrapDaemonStarts.get(key);
      return (
        Number.isFinite(ts) &&
        ts >= sinceMs &&
        ts >= freshnessFloorMs &&
        startTs !== undefined &&
        ts >= startTs
      );
    });
  } catch {
    return false;
  }
}

export const WRAP_PROTECTION_PROVIDER_TIMEOUT_MS = 1_500;

async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  label: string,
): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<never>((_resolve, reject) => {
    timeout = setTimeout(() => {
      reject(new Error(`${label} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
  });
  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

export async function probeCastleWallProtectionClaim(
  auditLog: WrapAuditEvidenceReader,
  storagePath: string,
  resolveExclusiveEgress: () => Promise<ExclusiveEgressStatus | null>,
  options: {
    providerTimeoutMs?: number;
    protectionClaimSubject?: string | null;
  } = {},
): Promise<ProtectionStateClaim> {
  let exclusiveEgress: ExclusiveEgressStatus | null;
  try {
    exclusiveEgress = await withTimeout(
      resolveExclusiveEgress(),
      options.providerTimeoutMs ?? WRAP_PROTECTION_PROVIDER_TIMEOUT_MS,
      "exclusive-egress posture provider",
    );
  } catch (err) {
    return protectionStateClaimFromObservation({
      state: "unknown",
      basis: "provider_unavailable",
      reasons: [
        `exclusive-egress posture provider could not be resolved: ${(err as Error).message}`,
      ],
    });
  }
  try {
    const castleWallEgress = await readCastleWallEgressFeatureStatus(
      auditLog,
      storagePath,
      {
        purpose: "protection-claim",
        exclusiveEgress,
        protectionClaimSubject: options.protectionClaimSubject ?? null,
      },
    );
    return protectionStateClaimFromObservation(
      appendProtectionObservationReasons(
        protectionObservationFromFeatureHealth({
          castleWallEgressStatus: castleWallEgress.status,
          castleWallEgressBasis: castleWallEgress.basis,
          exclusiveEgress,
        }),
        auditLog.incompleteEvidenceReasons,
      ),
    );
  } catch (err) {
    return protectionStateClaimFromObservation({
      state: "unknown",
      basis: "read_failed",
      reasons: [
        `Castle Wall enforcement evidence could not be read: ${(err as Error).message}`,
      ],
    });
  }
}

/**
 * Build the production exclusive-egress resolver required before a protection
 * claim can be rendered from feature-health evidence. Absent resolver means
 * unknown, never green.
 */
async function createWrapProtectionResolver(
  auditLog: WrapAuditEvidenceReader,
  storagePath: string,
): Promise<(() => Promise<ExclusiveEgressStatus | null>) | undefined> {
  if (process.platform !== "darwin") return undefined;
  const { createExclusiveEgressPostureProducer } = await import(
    "../egress-gate/arming-wiring.js"
  );
  return createExclusiveEgressPostureProducer({
    fortressPath: storagePath,
    coarseWallArmed: () =>
      probeCoarseCastleWallEnforcementObserved(auditLog, storagePath),
  });
}

function protectionObservationFromAutoProvisionSummary(
  summary: AutoProvisionSummary,
): ProtectionStateObservation | undefined {
  if (!summary.ran || summary.outcome === undefined) return undefined;
  const outcome = summary.outcome;
  switch (outcome.kind) {
    case "armed-exclusive":
    case "armed":
      return undefined;
    case "armed-exclusive-repark-failed":
      return {
        state: "unknown",
        basis: "exclusive_egress_repark_failed",
        reasons: [outcome.reparkError],
      };
    case "exclusive-egress-unarmed-coarse-active":
      return {
        state: "unknown",
        basis: "provision_outcome_not_observation",
        reasons: [outcome.reason, ...outcome.cleanupErrors],
      };
    case "armed-rollback-failed":
      return {
        state: "unknown",
        basis: "insufficient_evidence",
        reasons: [outcome.reason, outcome.disarmError],
      };
    case "aborted":
      if (outcome.disarmObservedOff === true) {
        return {
          state: "unprotected",
          basis: "disarm_observed_off",
          reasons: [outcome.reason],
        };
      }
      return {
        state: "unknown",
        basis: "provision_outcome_not_observation",
        reasons: [outcome.reason],
      };
    case "armed-then-rolled-back":
    case "egress-unprovisioned-rolled-back":
      if (outcome.disarmObservedOff === true) {
        return {
          state: "unprotected",
          basis: "disarm_observed_off",
          reasons: [outcome.reason],
        };
      }
      return {
        state: "unknown",
        basis: "provision_outcome_not_observation",
        reasons: [outcome.reason],
      };
    case "skipped-already-dedicated":
    case "skipped-non-tty-cooperative-only":
    case "declined-by-operator":
      return undefined;
    default:
      return assertNeverProvisionFlowOutcome(outcome);
  }
}

export function protectionClaimFromAutoProvisionSummary(
  summary: AutoProvisionSummary,
): ProtectionStateClaim | undefined {
  const observation = protectionObservationFromAutoProvisionSummary(summary);
  return observation === undefined
    ? undefined
    : protectionStateClaimFromObservation(observation);
}

function disarmOutcomeProtectionCeiling(
  outcome: DisarmNePreferenceOutcome,
  reason: string,
): ProtectionStateClaim | undefined {
  switch (outcome) {
    case "corroborated_off":
      return protectionStateClaimFromObservation({
        state: "unprotected",
        basis: "disarm_observed_off",
        reasons: [reason],
      });
    case "save_accepted_inconclusive":
    case "fail_open_deadman":
      return protectionStateClaimFromObservation({
        state: "unknown",
        basis: "provision_outcome_not_observation",
        reasons: [reason],
      });
    default:
      return assertNeverDisarmNePreferenceOutcome(outcome);
  }
}

export function autoProvisionCeilingFromSummary(
  summary: AutoProvisionSummary,
): ProtectionStateClaim | undefined {
  if (!summary.ran || summary.outcome === undefined) return undefined;
  const outcome = summary.outcome;
  switch (outcome.kind) {
    case "armed-exclusive-repark-failed":
      return protectionStateClaimFromObservation({
        state: "unknown",
        basis: "exclusive_egress_repark_failed",
        reasons: [outcome.reparkError],
      });
    case "exclusive-egress-unarmed-coarse-active":
      if (
        outcome.coarseCompositionRestored === true &&
        outcome.harness.disposition === "started-coarse"
      ) {
        return protectionStateClaimFromObservation({
          state: "coarse-only",
          basis: "exclusive_egress_unarmed_coarse_active",
          reasons: [outcome.reason, ...outcome.cleanupErrors],
        });
      }
      return protectionStateClaimFromObservation({
        state: "unknown",
        basis: "provision_outcome_not_observation",
        reasons: [outcome.reason, ...outcome.cleanupErrors],
      });
    case "aborted":
    case "armed-then-rolled-back":
    case "egress-unprovisioned-rolled-back":
      if ("wallMayBeArmed" in outcome && outcome.wallMayBeArmed === true) {
        return protectionStateClaimFromObservation({
          state: "unknown",
          basis: "provision_outcome_not_observation",
          reasons: [outcome.reason],
        });
      }
      if (outcome.disarmObservedOff === true) {
        return disarmOutcomeProtectionCeiling("corroborated_off", outcome.reason);
      }
      return "disarmOutcome" in outcome && outcome.disarmOutcome !== undefined
        ? disarmOutcomeProtectionCeiling(outcome.disarmOutcome, outcome.reason)
        : undefined;
    case "armed":
    case "armed-exclusive":
    case "armed-rollback-failed":
    case "skipped-already-dedicated":
    case "skipped-non-tty-cooperative-only":
    case "declined-by-operator":
      return undefined;
    default:
      return assertNeverProvisionFlowOutcome(outcome);
  }
}

function assertNeverProvisionFlowOutcome(outcome: never): never {
  const kind = (outcome as { kind?: unknown }).kind;
  throw new Error(
    `Unhandled ProvisionFlowOutcome kind in wrap protection claim path: ${String(kind)}`,
  );
}

function assertNeverDisarmNePreferenceOutcome(outcome: never): never {
  throw new Error(
    `Unhandled DisarmNePreferenceOutcome in wrap protection claim ceiling: ${String(outcome)}`,
  );
}

const protectionClaimStateOrder: Readonly<Record<ProtectionClaimState, number>> =
  Object.freeze({
    unprotected: 0,
    unknown: 1,
    "coarse-only": 2,
    exclusive: 3,
  });

function applyAutoProvisionCeiling(
  probedClaim: ProtectionStateClaim,
  autoProvisionCeiling: ProtectionStateClaim | undefined,
): ProtectionStateClaim {
  if (autoProvisionCeiling === undefined) return probedClaim;
  return protectionClaimStateOrder[autoProvisionCeiling.state] <=
    protectionClaimStateOrder[probedClaim.state]
    ? autoProvisionCeiling
    : probedClaim;
}

function unknownClaimWithAutoProvisionReasons(
  observation: ProtectionStateObservation,
  autoProvisionSummaryClaim: ProtectionStateClaim | undefined,
): ProtectionStateClaim {
  if (autoProvisionSummaryClaim?.basis === "disarm_observed_off") {
    return autoProvisionSummaryClaim;
  }
  return protectionStateClaimFromObservation({
    ...observation,
    reasons: [
      ...(observation.reasons ?? []),
      ...(autoProvisionSummaryClaim?.reasons ?? []),
    ],
  });
}

export async function resolveWrapProtectionClaim(input: {
  auditLog: AuditLog | undefined;
  auditStorage?: FilesystemStorage;
  masterKey?: Uint8Array;
  autoProvisionSummary: AutoProvisionSummary;
  castleWallDaemonLivenessSince?: Date;
  storagePath: string;
  providerTimeoutMs?: number;
  resolveExclusiveEgress?: () => Promise<ExclusiveEgressStatus | null>;
}): Promise<ProtectionStateClaim> {
  const autoProvisionClaim = protectionClaimFromAutoProvisionSummary(
    input.autoProvisionSummary,
  );
  const autoProvisionCeiling = autoProvisionCeilingFromSummary(
    input.autoProvisionSummary,
  );
  if (input.auditLog === undefined) {
    return unknownClaimWithAutoProvisionReasons(
      {
        state: "unknown",
        basis: "provider_unavailable",
        reasons: ["no audit log was available to observe enforcement"],
      },
      autoProvisionClaim,
    );
  }
  const auditEvidence = await createWrapAuditEvidenceReader({
    auditLog: input.auditLog,
    dualAuditEvidence: dualAuditEvidenceFromInput({
      auditStorage: input.auditStorage,
      masterKey: input.masterKey,
    }),
  });
  const protectionClaimSubject = await resolveWrapProtectionClaimSubject({
    storagePath: input.storagePath,
    autoProvisionSummary: input.autoProvisionSummary,
  });
  const daemonLivenessObserved =
    await observeCurrentWrapCastleWallDaemonLiveness(
      auditEvidence,
      input.storagePath,
      input.castleWallDaemonLivenessSince,
    );
  if (!daemonLivenessObserved) {
    return unknownClaimWithAutoProvisionReasons(
      {
        state: "unknown",
        basis: "provider_unavailable",
        reasons: [
          "Castle Wall current-wrap daemon heartbeat could not be confirmed",
        ],
      },
      autoProvisionClaim,
    );
  }
  let resolver: (() => Promise<ExclusiveEgressStatus | null>) | undefined;
  try {
    resolver =
      input.resolveExclusiveEgress ??
      (await createWrapProtectionResolver(
        auditEvidence,
        input.storagePath,
      ));
  } catch (err) {
    return unknownClaimWithAutoProvisionReasons(
      {
        state: "unknown",
        basis: "provider_unavailable",
        reasons: [
          `exclusive-egress posture provider could not be loaded: ${(err as Error).message}`,
        ],
      },
      autoProvisionClaim,
    );
  }
  if (resolver === undefined) {
    return unknownClaimWithAutoProvisionReasons(
      {
        state: "unknown",
        basis: "provider_unavailable",
        reasons: ["exclusive-egress posture provider was not available"],
      },
      autoProvisionClaim,
    );
  }
  const probedClaim = await probeCastleWallProtectionClaim(
    auditEvidence,
    input.storagePath,
    resolver,
    {
      providerTimeoutMs: input.providerTimeoutMs,
      protectionClaimSubject,
    },
  );
  return applyAutoProvisionCeiling(probedClaim, autoProvisionCeiling);
}

/**
 * Auto-provision Step 2 (Build 1): gate + invoke the one-flow orchestration
 * (castle-wall/provision) from `runWrap`. v1 scope (D1/D2 resolved): Hermes
 * on darwin only; a dry run never provisions (fix: dry-run must remain
 * write-free, matching the existing `options.dryRun` early-return above).
 * `--unwrap` never reaches this call (the unwrap branch returns at the top
 * of `runWrap`).
 *
 * Fix H4: when provisioning is skipped because this run is non-interactive
 * (no TTY), the cooperative wrap this function is called from has ALREADY
 * completed its own writes by the time this runs -- this call only adds a
 * status line, it never blocks or reverts the wrap that already happened.
 * Any error thrown by the auto-provision flow is caught here and reported
 * as a note, never allowed to turn an otherwise-successful cooperative wrap
 * into a hard CLI failure. The terminal banner later resolves a protection
 * claim from the observed final state, not from this control-flow boundary.
 */
async function maybeRunAutoProvisionForWrap(
  agentConfig: { platform: AgentPlatform },
  options: WrapOptions,
  deps: RunWrapDeps,
  stopTransientCastleWallDaemon?: () => Promise<void>,
): Promise<{ summary: AutoProvisionSummary; deferredSignal?: NodeJS.Signals }> {
  if (agentConfig.platform !== "hermes" || options.dryRun) {
    return { summary: { ran: false } };
  }
  const runner = deps.runAutoProvisionForWrap ?? runAutoProvisionForWrap;
  let mutationWindowOpened = false;
  let deferredSignal: NodeJS.Signals | undefined;
  let summary: AutoProvisionSummary;
  try {
    try {
      summary = await runner({
        isTty: process.stdin.isTTY === true,
        preAnsweredProvision: options.provisionAgentAccount,
        cliBinary: resolveAutoProvisionCliBinary(options),
        stopTransientCastleWallDaemon,
        beforeFirstMutation: () => {
          mutationWindowOpened = tryOpenAutoProvisionMutationWindow(options);
          return mutationWindowOpened;
        },
        // S5-6: fine-grained (exclusive-egress) provisioning mode.
        exclusiveEgress: options.exclusiveEgress,
        // SAFETY: stderr is the operator-facing CLI channel for this
        // subcommand; this prints the plan-and-print + progress lines from
        // the auto-provision flow (account plan, re-home summary, arm
        // result), never secrets or key material.
        print: (line) => console.error(`  ${line}`),
      });
    } catch (err) {
      // FIX (round 5 / R8-2): a held provision lock means the flow body NEVER
      // ran (another `sanctuary protect` is mid-provision), so this run mutated
      // NOTHING. Classify it honestly -- the generic "may have PARTIALLY applied"
      // warning below would falsely tell the operator to consider disarming a
      // wall this run never touched.
      if (err instanceof ProvisionLockHeldError) {
        // SAFETY: stderr is the operator-facing CLI channel; a fixed, safe
        // string plus the lock error message (a lock-path only, no secrets).
        console.error(
          `  Note: another 'sanctuary protect' provisioning run is already in progress (${(err as Error).message}); ` +
            `this run made NO account, re-home, or Castle Wall changes. If a protect process is actually running, wait for it to finish; ` +
            `if not, remove the stale lock file named above and re-run if needed.`,
        );
        summary = { ran: true };
      } else {
        // FIX (round 5, item N5): a throw reaching here can surface AFTER
        // privileged side effects already landed -- e.g. `withProvisionLock`'s
        // finally re-throws a non-ENOENT lock-release error even when
        // `runProvisionFlow` already created the account, re-homed the secrets, or
        // ARMED the wall. The pre-fix copy asserted provisioning "did not
        // complete" and told the operator to blindly re-run, which is wrong (and
        // unsafe) if the wall is in fact armed over a half-provisioned agent. The
        // catch cannot know how far the flow got, so it must not claim a
        // completion state: warn that it may have PARTIALLY applied and that the
        // armed state must be checked before re-running.
        //
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this
        // subcommand; never surface secrets or key material here.
        console.error(
          `  WARNING: automatic account provisioning raised an error (${(err as Error).message}). ` +
            `It may have PARTIALLY applied -- the dedicated account, the re-home, or an armed Castle Wall could ` +
            `already be in place. The cooperative wrap above still applies. Do NOT assume nothing happened: check ` +
            `whether Castle Wall is armed before re-running, and run 'sudo sanctuary castle-wall disable' if it is ` +
            `enforcing over a half-provisioned agent.`,
        );
        summary = { ran: true };
      }
    }
  } finally {
    deferredSignal = mutationWindowOpened ? closeAutoProvisionMutationWindow() : undefined;
  }
  return { summary, deferredSignal };
}

async function exitAfterDeferredAutoProvisionSignal(
  deferredSignal: NodeJS.Signals | undefined,
): Promise<void> {
  if (deferredSignal !== undefined) {
    await runProcessShutdownForSignal(deferredSignal);
  }
}

/**
 * FIX F5 (HIGH, 2026-07-07 fix-round, absorbs the earlier F4 messaging nit):
 * render EVERY `ProvisionFlowOutcome` at the CLI, not just the ones that
 * happen to reach a catch block. Before this fix both wrap call sites
 * ignored the returned outcome entirely: on a real abort (e.g. `launchctl
 * bootstrap` failing after re-home) the wrap printed its normal success
 * banner and the structured abort -- stage, reason, backup path, whether
 * anything was actually restored -- was silently dropped. Every branch here
 * is a distinct, accurate line:
 *   - declined / non-tty: informational only, never "retry provisioning"
 *     phrasing (the operator did not fail at anything).
 *   - aborted with rolledBack === true: clean recovery, still surfaced so
 *     the operator knows provisioning did not complete this run.
 *   - aborted with rolledBack === false / "partial": LOUD manual-recovery
 *     guidance with the backup path(s), since the operator's secrets may be
 *     stranded under the new account's home.
 *   - armed-then-rolled-back: the wall came down after a failed post-arm
 *     check; the agent stays re-homed and the operator is told plainly.
 *   - armed-rollback-failed (fix R5, 2026-07-07 fix-round 2): the wall
 *     stayed ARMED after a failed post-arm check AND the fast-disarm rollback
 *     itself failed. LOUDEST manual-recovery guidance of any branch: the
 *     operator must disarm by hand, since the automatic rollback did not
 *     complete.
 *   - armed / skipped-already-dedicated: quiet single-line confirmation.
 */
/**
 * Pure (exported for the seam, fix round-5 R2-2/R2-3): the operator-facing
 * lines for a `ProvisionFlowOutcome`. Split out from the printer so every
 * branch -- the silent-vs-loud framing, the non-TTY reason surfacing (R2-3),
 * and the daemon-still-live loud override (R2-2) -- is unit-testable without
 * spying on `console`. Returns `[]` when there is nothing to print. The
 * render being untested is exactly how R2-2/R2-3 survived; this closes that.
 */
export function renderAutoProvisionOutcomeLines(summary: AutoProvisionSummary): string[] {
  if (!summary.ran || summary.outcome === undefined) return [];
  const outcome = summary.outcome;
  switch (outcome.kind) {
    case "armed":
      return [`  Dedicated agent account provisioned and Castle Wall armed (uid ${outcome.uid}).`];
    case "skipped-already-dedicated":
      // The orchestrator already printed the "already a verified dedicated
      // account ..." line via `print` at plan-and-print time; nothing to add.
      return [];
    case "skipped-non-tty-cooperative-only":
      // FIX (round 5 / R2-3): the orchestrator printed only the forward-looking
      // Plan line, NOT this outcome's reason, so the "re-run interactively to
      // provision the account and arm the wall" guidance was silently dropped.
      // Surface the reason here.
      return [`  ${outcome.reason}`];
    case "declined-by-operator":
      return ["  Account provisioning declined; the cooperative wrap above still applies."];
    case "armed-then-rolled-back":
      return [
        `  Note: Castle Wall armed then was fast-disarmed (${outcome.reason}). ` +
          `The agent still runs under its dedicated, re-homed account; only enforcement came down. ` +
          // FIX (round 5, item N5): honest -- the post-arm re-check proves
          // DNS-resolvability + credential readability, not allow-list
          // correctness, so do not tell the operator to "fix the allow-list".
          `Re-run 'sanctuary protect --hermes' once the connectivity re-check passes (see the reason above).`,
      ];
    case "armed-rollback-failed":
      return [
        `  WARNING: Castle Wall is ARMED (uid ${outcome.uid}) and the automatic rollback FAILED (${outcome.reason}). ` +
          `The disarm attempt itself also failed: ${outcome.disarmError}. ` +
          `The agent may be unreachable behind the wall. Run 'sudo sanctuary castle-wall disable' manually now, ` +
          `then investigate before re-running 'sanctuary protect --hermes'.`,
      ];
    case "egress-unprovisioned-rolled-back":
      // Confined-agent egress (design section 5): the wall armed but the
      // post-arm AS-UID egress verification failed (an endpoint unreachable
      // as the agent uid, or the negative control reachable), so the flow
      // fast-disarmed and put the provisioned rules back to their pre-run state
      // rather than leave a confined-into-silence agent or an unverified grant.
      // Honest framing: the per-endpoint PASS/FAIL table was already printed by
      // the flow. FIX F-REVOKE: the claim is "restored to their pre-run state",
      // which on a first run means removed and on a re-run means a previous
      // run's grants survived -- the old "were scrubbed" wording asserted
      // removal on both, and on a re-run that was the agent-strangling case.
      return [
        `  Note: Castle Wall armed, then was fast-disarmed because the as-agent-uid egress verification failed ` +
          `(${outcome.reason}). The agent still runs under its dedicated, re-homed account; only enforcement came down` +
          `${outcome.egressRestoredToPreRunState ? " and the provisioned egress rules were restored to their pre-run state" : ""}. ` +
          `Re-run 'sanctuary protect --hermes' once the per-endpoint failures above are resolved.`,
      ];
    case "armed-exclusive":
      // S5-6: the full fine-grained outcome. Honest wording: wired + live,
      // drill-owed (no "audited per-rule per-flow"-class overclaim).
      return [
        `  Dedicated agent account provisioned, Castle Wall armed, and the exclusive-egress gate is LIVE ` +
          `(uid ${outcome.uid}, generation ${outcome.generationId}). The agent's only sanctioned egress path is the gate.`,
      ];
    case "armed-exclusive-repark-failed":
      // FIX-ROUND 5. This used to say "the agent is running confined" -- a
      // positive run-state assertion composed at the RENDER layer, which is
      // the thing the round-4 guard exists to forbid; it evaded the guard only
      // by letter case. Its basis was also stale: the barrier's last
      // stable-running probe ran BEFORE the re-park mutation that then threw.
      // What IS observed here is the gate: a committed generation, live, with
      // the agent's egress scoped to it. Say that, and leave run state to the
      // one surface that reads it.
      return [
        `  WARNING: the exclusive-egress gate is LIVE (uid ${outcome.uid}, generation ${outcome.generationId}) and the ` +
          `agent's only sanctioned egress path is the gate, but the persistent boot state could NOT be re-parked ` +
          `(${outcome.reparkError}). ` +
          `The NEXT boot could start the agent before the gate re-arms. Run '${EGRESS_GATE_REPAIR_WITH_STAND_DOWN_COMMAND}' (${EGRESS_GATE_STAND_DOWN_EFFECT}) now.`,
      ];
    case "exclusive-egress-unarmed-coarse-active": {
      // S5-6 degrade-loud: DISTINCT non-green state; every posture surface
      // renders coarse-only amber (S5-P). Never softened into a success line.
      // FIX-ROUND 4 (the round-4 HIGH landed exactly here). This branch used
      // to compose its own run-state sentence from `harnessStartedCoarse`,
      // whose false branch means "this run did not start it" and was printed
      // as "The agent is PARKED (not running)" -- captured over a live pid
      // 9001, in the same output whose reason string said the job still
      // reported that pid. The render layer no longer decides run state at
      // all: the sentence comes from the parked-claim chokepoint, which
      // produced it from a settled observation or explicitly weakened it.
      const agentState = harnessDispositionSentence(outcome.harness);
      const manifestState = outcome.coarseCompositionRestored
        ? "The manifest is back in coarse scope."
        : "The manifest could NOT be restored to coarse scope.";
      const cleanupNote =
        outcome.cleanupErrors.length > 0 ? ` Cleanup problems: ${outcome.cleanupErrors.join("; ")}.` : "";
      return [
        `  WARNING: fine-grained exclusive egress could NOT come live at "${outcome.stage}" (${outcome.reason}). ` +
          `The coarse Castle Wall remains armed over the agent -- this is a DISTINCT NON-GREEN (coarse-only) state ` +
          `on every posture surface, not full protection. ${manifestState} ${agentState}${cleanupNote} ` +
          `Fix with: ${EGRESS_GATE_REPAIR_WITH_STAND_DOWN_ADVICE}`,
      ];
    }
    case "aborted":
      return abortedProvisionLines(outcome);
    default:
      return assertNeverProvisionFlowOutcome(outcome);
  }
}

function abortedProvisionLines(outcome: Extract<ProvisionFlowOutcome, { kind: "aborted" }>): string[] {
  const backupNote =
    outcome.backupPaths !== undefined && outcome.backupPaths.length > 0
      ? ` Backup copies remain at: ${outcome.backupPaths.join(", ")}.`
      : "";
  // FIX (round 5 / R5-2): an R6 restore CONFLICT means the operator recreated
  // a re-homed file during provisioning; their recreated file was left intact
  // and the previously re-homed copy is preserved at conflictPaths. This is
  // NOT a failed restore and the operator must NOT be told to overwrite from
  // the stale backup (that would destroy their newer file).
  const conflictNote =
    outcome.conflictPaths !== undefined && outcome.conflictPaths.length > 0
      ? ` Your file(s) recreated during provisioning were left intact; the previously re-homed copy is preserved at: ${outcome.conflictPaths.join(", ")} -- reconcile these by hand, and do NOT overwrite them from the backup.`
      : "";
  // Bug B P0 (disarm-first): an ARM-stage abort where disarm could NOT confirm
  // the content filter is off. The freshly-installed policy daemon was left
  // RUNNING (filter-on + daemon-up is enforcing and recoverable, never the
  // deny-all lockout), and the wall MAY STILL BE ARMED. This is the most severe
  // state, so it is checked FIRST and NEVER softened into a clean "rolled back;
  // re-run" line (the honesty gap the P0 flagged). `outcome.reason` already
  // carries the full WALL-STATE WARNING with the `castle-wall disable` command.
  if (outcome.wallMayBeArmed) {
    return [
      `  WARNING: automatic account provisioning stopped at "${outcome.stage}" (${outcome.reason})${backupNote}${conflictNote}` +
        ` The Castle Wall content filter MAY STILL BE ARMED; the policy daemon was left running to avoid a lockout.` +
        ` Run 'sudo sanctuary castle-wall disable' to confirm the filter is off, then investigate before re-running.`,
    ];
  }
  // FIX (round 5 / R2-2): a failed daemon teardown means a root LaunchDaemon
  // may STILL BE LIVE regardless of whether the re-home restore succeeded, so
  // it gets the LOUD frame -- never the soft "Note: ... re-run to retry" line
  // the rolledBack===true branch below would otherwise emit (which would
  // directly contradict the manual-recovery note already folded into
  // `outcome.reason`).
  if (outcome.daemonTeardownFailed) {
    return [
      `  WARNING: automatic account provisioning stopped at "${outcome.stage}" (${outcome.reason}).` +
        ` A root harness LaunchDaemon may still be running under the dedicated account.${backupNote}${conflictNote}` +
        ` Do not re-run until you have torn it down (see the note above) and recovered any files.`,
    ];
  }
  // FIX (round 5 / R5-2): surface a restore conflict as its own honest frame
  // (data is safe at conflictPaths) BEFORE the rolledBack branches, which would
  // otherwise render a pure conflict (restoredCount 0 -> rolledBack false) as
  // "restore FAILED / recover from backup" -- a false alarm that also
  // misdirects the operator to clobber their newer recreated file.
  //
  // FIX (round 5 / R6-2): ONLY when there is no GENUINE failure. If a real
  // restore failure co-occurs with a conflict, fall through to the LOUD
  // rolledBack frames below (which now also carry `conflictNote`), so a
  // conflict never masks a failure that needs backup recovery.
  const hasGenuineFailure = outcome.failedPaths !== undefined && outcome.failedPaths.length > 0;
  if (outcome.conflictPaths !== undefined && outcome.conflictPaths.length > 0 && !hasGenuineFailure) {
    return [
      `  Note: automatic account provisioning stopped at "${outcome.stage}" (${outcome.reason}).` +
        conflictNote +
        ` The cooperative wrap above still applies. Reconcile the file(s) above, then re-run 'sanctuary protect --hermes'.`,
    ];
  }
  // FIX (round 5 / R3-2): a pre-re-home abort (root-check, operator-identity,
  // detect, create-account, or a rehome that moved nothing) has NOTHING to
  // restore. Render a neutral "nothing was changed; safe to re-run" line --
  // never the "restore of your re-homed files FAILED / do not re-run" alarm
  // the `rolledBack === false` branch below would otherwise print. This is the
  // common no-sudo first attempt (stage "root-check"). Account existence is
  // deliberately NOT inferred here; create-account failures carry their own
  // observed rollback/repair text in `reason`.
  if (outcome.rehomeAttempted === false) {
    // FIX (round 5 / R4-2): key the account clause on `accountCreated`, not on
    // `rehomeAttempted` (which only tracks whether a MOVE happened). At the
    // rehome stage create-account has already succeeded, so an orphaned hidden
    // account exists even though nothing moved.
    const accountClause = outcome.accountCreated
      ? `The dedicated account was created but no files were moved (it will be reused on the next run).`
      : `No files were moved before this stop.`;
    return [
      `  Note: automatic account provisioning stopped at "${outcome.stage}" (${outcome.reason}). ` +
        `${accountClause} The cooperative wrap above still applies. ` +
        `Re-run 'sanctuary protect --hermes' once the cause above is resolved.`,
    ];
  }
  if (outcome.rolledBack === true) {
    return [
      `  Note: automatic account provisioning stopped at "${outcome.stage}" (${outcome.reason}). ` +
        `Re-homed paths were restored to your account. Re-run 'sanctuary protect --hermes' to retry.`,
    ];
  }
  if (outcome.rolledBack === "partial") {
    return [
      `  WARNING: automatic account provisioning stopped at "${outcome.stage}" (${outcome.reason}). ` +
        `Only SOME of your re-homed files were restored; the rest need manual recovery.${backupNote}${conflictNote} ` +
        `Do not re-run until you have recovered the remaining files.`,
    ];
  }
  return [
    `  WARNING: automatic account provisioning stopped at "${outcome.stage}" (${outcome.reason}). ` +
      `The restore of your re-homed files FAILED; manual recovery is required.${backupNote}${conflictNote} ` +
      `Do not re-run until you have recovered your files.`,
  ];
}

function printAutoProvisionOutcomeLineToStderr(line: string): void {
  // SAFETY: stderr is the operator-facing CLI channel for this subcommand; the
  // caller supplies rendered outcome metadata only, never secrets.
  console.error(line);
}

export function renderAutoProvisionOutcome(
  summary: AutoProvisionSummary,
  print: (line: string) => void = printAutoProvisionOutcomeLineToStderr,
): void {
  try {
    for (const line of renderAutoProvisionOutcomeLines(summary)) {
      // SAFETY: stderr is the operator-facing CLI channel for this subcommand;
      // every line comes from renderAutoProvisionOutcomeLines, which interpolates
      // only outcome metadata (stage / reason / uid / backup paths this process
      // itself wrote) -- never secrets or key material.
      print(line);
    }
  } catch (err) {
    print(
      `  WARNING: automatic account provisioning completed with an outcome the CLI renderer could not display ` +
        `(${err instanceof Error ? err.message : String(err)}). Re-run 'sudo sanctuary protect --hermes' or inspect ` +
        `the Castle Wall status before assuming protection state.`,
    );
  }
}

export interface RunWrapDeps {
  /**
   * Override the auto-provision entry point (for tests). Production
   * callers leave this undefined and get the real
   * `wrap/auto-provision.ts:runAutoProvisionForWrap`, which is the ONLY
   * caller of the privileged (drill-only) account-creation / re-home /
   * daemon-install / arm side effects.
   */
  runAutoProvisionForWrap?: typeof runAutoProvisionForWrap;
  /**
   * Override the resolved OS platform used by the `--exclusive-egress` /
   * `--provision-agent-account` darwin-only refusal (for tests). Production
   * callers leave this undefined and get the real `node:os` `platform()`.
   * Auto-provision itself (`wrap/auto-provision.ts:runAutoProvisionForWrap`)
   * is gated the same way but is NOT test-overridable here -- this seam
   * exists so a test can deterministically exercise the CLI-level refusal
   * independent of the CI runner's actual OS, without needing to fake the
   * full auto-provision darwin gate too.
   */
  osPlatform?: () => NodeJS.Platform;
  /** Override dashboard starter (for tests). */
  startDashboard?: DashboardStarter;
  /** Override browser opener (for tests). */
  openBrowser?: (url: string) => Promise<void>;
  /** Override passphrase resolver (for tests). */
  resolvePassphrase?: () => Promise<{ value: string; location: string; source: string }>;
  /**
   * Override the persistence helper for a user-supplied `--passphrase` flag
   * (for tests). Production callers leave this undefined.
   */
  persistPassphrase?: (
    value: string
  ) => Promise<{ location: string; source: "keychain" | "fallback-file" }>;
  /**
   * Override the config rewrite (for tests). Production callers leave this
   * undefined.
   */
  rewriteConfig?: typeof rewriteConfigForWrap;
  /**
   * Override the Claude Code permissions.allow installer (WP-V1.2 reshape).
   * Production uses the bundled `installClaudeCodeAllowlist`; tests
   * inject a stub to assert the call shape without touching the
   * developer's real ~/.claude/settings.json.
   */
  installClaudeCodeAllowlist?: (
    opts: import("./claude-code-allowlist.js").InstallClaudeCodeAllowlistOptions,
  ) => Promise<
    import("./claude-code-allowlist.js").InstallClaudeCodeAllowlistResult
  >;
  /**
   * Override the wrap-meta persistence (for tests). Production callers
   * leave this undefined. Tests inject a throwing stub to pin the
   * meta-write failure paths: full rollback of every wrapped surface, and
   * the orphan-wrap guard's fallback meta write when a rollback restore
   * itself fails.
   */
  saveWrapMeta?: typeof saveWrapMeta;
  /**
   * Override the wrap-time pinned-version resolvability probe (for tests).
   * Production callers leave this undefined and get
   * `checkPinnedVersionResolvable` (a real registry-metadata HEAD-class
   * probe with a short timeout).
   */
  checkPinResolvability?: (
    version: string,
  ) => Promise<PinnedVersionResolvability>;
}

/**
 * Test-only injection seam for the Hermes config.yaml parse-parity guard's
 * PyYAML sidecar. This is DELIBERATELY not a field on RunWrapDeps: a public
 * dep would let a programmatic production caller pass an agreeing / no-op
 * parity and edit config.yaml WITHOUT the real PyYAML validator, defeating
 * the fail-closed guarantee (HIGH: DI-bypass on the mutating path, closed
 * 2026-07-03). The production runWrap paths always call the guard with the
 * real default sidecar; only test code reaches in here to override it.
 *
 * Named `__`-prefixed and NOT re-exported from wrap/index.ts, matching the
 * `__wrapMetaLockTestHooks` convention (config-reader.ts): a test sets
 * `__hermesParityTestHook.parity` before driving runWrap and clears it after.
 * When unset (every production path), `parity` is undefined and the guard
 * spawns the real one-shot `python3` PyYAML parse.
 */
export const __hermesParityTestHook: {
  parity?: import("./hermes-yaml-parse-parity.js").ParseParityOptions;
} = {};

export async function runWrap(
  options: WrapOptions,
  deps: RunWrapDeps = {}
): Promise<void> {
  installProcessShutdownListeners();

  // D4 P2-2: --unwrap honors --dry-run too - pre-fix, the unwrap dispatch
  // sat above the dry-run gate, so `--unwrap --dry-run` restored backups
  // for real. The gate travels into unwrap() so it can report what WOULD
  // be restored/removed while writing nothing.
  if (options.unwrap) {
    await unwrap(options.dryRun === true);
    return;
  }

  // Finding 4 (2026-06-25): validate --dev-dist BEFORE anything is previewed or
  // written. The dry-run reporter previews the exact 'node <path>' harness
  // entry this would write, so a typo'd path must fail the dry run too, not
  // just the real wrap. Fail loudly here rather than at deferred MCP spawn time.
  if (options.devDist !== undefined) {
    try {
      await validateDevDist(options.devDist);
    } catch (err) {
      if (err instanceof DevDistInvalidError) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`\n  Sanctuary wrap: ${err.message}\n`);
        process.exit(2);
      }
      throw err;
    }
  }

  // v1.1.1 hotfix (Finding T): honor --fortress and SANCTUARY_FORTRESS_PATH
  // by promoting them onto SANCTUARY_STORAGE_PATH BEFORE any code calls
  // resolveStoragePath(). Extracted so tests can pin the precedence
  // without standing up the whole wrap flow.
  promoteFortressToStoragePath(options);

  // S5-6: the exclusive-egress repair verb. Does NOT wrap anything -- it
  // re-runs the gate generation bring-up + release barrier for an
  // already-provisioned fine-grained agent, behind the MED-7 transient-
  // pf-rule drift guard (foreign VPN/firewall rules refuse without the
  // interactive `--override-transient-pf-rules`).
  if (options.repairEgressGate === true) {
    const { runEgressGateRepairForCli } = await import("./auto-provision.js");
    let mutationWindowOpened = false;
    let deferredSignal: NodeJS.Signals | undefined;
    let code = 2;
    let thrown: unknown;
    try {
      code = await runEgressGateRepairForCli({
        isTty: process.stdin.isTTY === true,
        overrideTransientPfRules: options.overrideTransientPfRules === true,
        standDownAgent: options.standDownAgent === true,
        cliBinary: resolveAutoProvisionCliBinary(options),
        beforeFirstMutation: () => {
          mutationWindowOpened = tryOpenAutoProvisionMutationWindow(options);
          return mutationWindowOpened;
        },
      });
    } catch (err) {
      thrown = err;
    } finally {
      deferredSignal = mutationWindowOpened ? closeAutoProvisionMutationWindow() : undefined;
    }
    await exitAfterDeferredAutoProvisionSignal(deferredSignal);
    if (thrown !== undefined) throw thrown;
    process.exit(code);
  }

  // S5-7: the exclusive-egress unprotect verb. Does NOT wrap anything -- it
  // tears down the per-agent exclusive-egress stack (verified park first;
  // registry remove LAST so every remaining confined uid's rules re-verify
  // live and the anchor flushes only when the last agent leaves).
  if (options.unprotectEgressGate === true) {
    const { runEgressGateUnprotectForCli } = await import("./auto-provision.js");
    let mutationWindowOpened = false;
    let deferredSignal: NodeJS.Signals | undefined;
    let code = 2;
    let thrown: unknown;
    try {
      code = await runEgressGateUnprotectForCli({
        standDownAgent: options.standDownAgent === true,
        cliBinary: resolveAutoProvisionCliBinary(options),
        beforeFirstMutation: () => {
          mutationWindowOpened = tryOpenAutoProvisionMutationWindow(options);
          return mutationWindowOpened;
        },
      });
    } catch (err) {
      thrown = err;
    } finally {
      deferredSignal = mutationWindowOpened ? closeAutoProvisionMutationWindow() : undefined;
    }
    await exitAfterDeferredAutoProvisionSignal(deferredSignal);
    if (thrown !== undefined) throw thrown;
    process.exit(code);
  }

  let platformHint: AgentPlatform | undefined;
  if (options.openclaw) platformHint = "openclaw";
  else if (options.hermes) platformHint = "hermes";
  else if (options.claudeCode) platformHint = "claude-code";
  else if (options.cursor) platformHint = "cursor";
  else if (options.cline) platformHint = "cline";
  else if (options.mastra) platformHint = "mastra";

  let detection = await detectAgentConfigWithDiagnostics(
    platformHint,
    options.wrap
  );
  let agentConfig = detection.config;

  // FIX (harden-loop, side-effect-before-refusal): shared by both the
  // dry-run branch below and the real (write) branch. Pre-fix, this check
  // only ran inside the `options.dryRun` early-return, so on a REAL run the
  // fresh-config bootstrap's `writeFileSafeUnderRoot` (further down) landed
  // on disk -- and its "Bootstrapped a fresh config at ..." line printed --
  // BEFORE this refusal could fire, on the exact darwin-only / wrong-
  // platform-selector cases it's meant to block. That left a stub
  // `~/.hermes/cli-config.json` (or platform equivalent) an operator never
  // asked for sitting at the canonical path after a refused, exit-2 command,
  // which then makes the NEXT run see a "configured" platform and skip the
  // bootstrap branch entirely. Calling this BEFORE the write makes the
  // refusal side-effect-free on both paths, matching the PR's own claim
  // that it fires "before any wrap work (config detection, file writes,
  // dashboard start)". Uses `platformHint`, not `agentConfig?.platform`:
  // neither branch has a resolved `agentConfig` yet at this point (that's
  // the whole reason the bootstrap block exists), and a real run would
  // bootstrap a config FOR the hinted platform, so `platformHint` is what
  // `agentConfig?.platform` would become.
  function refuseUnsupportedExclusiveArmForHint(): boolean {
    if (options.exclusiveEgress !== true && options.provisionAgentAccount !== true) {
      return false;
    }
    const requestedFlags = [
      options.exclusiveEgress === true ? "--exclusive-egress" : undefined,
      options.provisionAgentAccount === true ? "--provision-agent-account" : undefined,
    ]
      .filter((flag): flag is string => flag !== undefined)
      .join(" / ");
    if (platformHint !== "hermes") {
      // SAFETY: stderr is the operator-facing CLI channel for this subcommand.
      console.error(
        `\n  Sanctuary: ${requestedFlags} requires a provisionable agent selector, ` +
          `but the detected/configured platform is "${platformHint}". Only Hermes is provisionable today -- re-run with ` +
          `--hermes against a Hermes config. Without it, wrap would proceed as a ` +
          `plain cooperative wrap and arm nothing.\n`
      );
      process.exit(2);
      return true;
    }
    const resolvedOsPlatform = (deps.osPlatform ?? platform)();
    if (resolvedOsPlatform !== "darwin") {
      // SAFETY: stderr is the operator-facing CLI channel for this subcommand.
      console.error(
        `\n  Sanctuary: ${requestedFlags} requires automatic account provisioning ` +
          `and Castle Wall arming, which are darwin-only today (this host reports ` +
          `"${resolvedOsPlatform}"). Without it, wrap would proceed as a plain cooperative ` +
          `wrap and arm nothing.\n`
      );
      process.exit(2);
      return true;
    }
    return false;
  }

  // If no config file exists for an explicitly-hinted platform, bootstrap an
  // empty one at the canonical (first-listed) path. Wrap then proceeds to
  // inject Sanctuary as the sole entry. First-time operators on a fresh
  // Claude Code install (no prior `claude mcp add`) hit this path; pre-v1.0
  // wrap exited here and forced them to seed an unrelated placeholder.
  if (!agentConfig && platformHint && !options.wrap) {
    const candidatePaths = getPlatformPaths()[platformHint];
    const canonicalPath = candidatePaths[0];
    // Honesty fix: for Hermes, the JSON surface detected above
    // (cli-config.json / config.json) is NOT where Hermes routes MCP
    // traffic. v0.16.0 reads ~/.hermes/config.yaml (see hermes-yaml.ts
    // header). A host that already has a populated config.yaml (e.g. a
    // `venice` entry) has a REAL Hermes MCP config, so claiming "No
    // existing hermes config found" is false and confusing on the exact
    // install target. When config.yaml exists we say so, name the
    // authoritative file, and note existing entries are preserved; the
    // per-entry preserved count is reported by the config.yaml routing
    // line (reportHermesYamlDryRun / the real injection below).
    const hermesYamlExists =
      platformHint === "hermes" && (await pathExists(hermesConfigYamlPath()));
    // D4 staging, Bug 1: --dry-run must guarantee ZERO filesystem writes.
    // This bootstrap ran BEFORE the dry-run gate below, so `protect
    // --hermes --dry-run` on a host with no config still created the file.
    // Report what would be bootstrapped and stop before any write path.
    if (canonicalPath && options.dryRun) {
      // FIX (N1-3 dry-run gap, harden-loop): this early return happens
      // BEFORE the `--exclusive-egress` / `--provision-agent-account`
      // refusal further below, which only runs on the resolved
      // `agentConfig?.platform` -- but a dry run never actually writes the
      // bootstrap file or re-detects, so `agentConfig` stays undefined and
      // that refusal is unreachable here. Without this, a dry run against a
      // fresh (or non-hermes) host prints a clean "Would bootstrap.../Dry
      // run. No changes made." plan for a command that refuses when run for
      // real -- exactly the false belief the refusal exists to prevent.
      if (refuseUnsupportedExclusiveArmForHint()) return;
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      if (hermesYamlExists) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `\n  Found your Hermes MCP config at ${hermesConfigYamlPath()}.` +
            `\n  Existing MCP servers there are preserved; Sanctuary routing will be added.`
        );
      } else {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`\n  No existing ${platformHint} config found.`);
      }
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`  Would bootstrap a fresh config at ${canonicalPath}.`);
      if (platformHint === "hermes") {
        await reportHermesYamlDryRun(options);
      }
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Dry run. No changes made.\n`);
      return;
    }
    if (canonicalPath) {
      // FIX (harden-loop, side-effect-before-refusal): mirror the dry-run
      // check above BEFORE the write below. Without this, `sanctuary
      // protect --hermes --exclusive-egress` on a non-darwin host (or
      // `--cursor --exclusive-egress` with no cursor config) bootstrapped
      // and printed "Bootstrapped a fresh config at ..." for real, THEN hit
      // the resolved-platform refusal further down and exited 2 -- leaving
      // a stub config on disk the operator never had, for a command that
      // never armed anything.
      if (refuseUnsupportedExclusiveArmForHint()) return;
      try {
        // Round-3 P1-A: the fresh-config bootstrap used mkdir(recursive) +
        // plain writeFile, both of which follow a symlinked parent (e.g.
        // ~/.hermes -> /tmp/victim). Route it through the same safe-path
        // discipline as every other wrap sink.
        // DEBT (hermes cli-config.json): this JSON file is a legacy compat
        // artifact. Hermes v0.16.0 does NOT consult it for MCP routing
        // (hermes-yaml.ts:4-10). It is kept because the generic wrap flow
        // keys off `agentConfig`, which detectAgentConfigWithDiagnostics
        // derives from the JSON surface, and unwrap unlinks it
        // (config-reader.ts). The authoritative surface is config.yaml.
        await writeFileSafeUnderRoot(canonicalPath, "{}", { mode: 0o600 });
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        if (hermesYamlExists) {
          // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
          console.error(
            `\n  Found your Hermes MCP config at ${hermesConfigYamlPath()}.` +
              `\n  Existing MCP servers there are preserved; Sanctuary routing will be added.`
          );
        } else {
          // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
          console.error(`\n  No existing ${platformHint} config found.`);
        }
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Bootstrapped a fresh config at ${canonicalPath}.\n`
        );
        detection = await detectAgentConfigWithDiagnostics(
          platformHint,
          options.wrap
        );
        agentConfig = detection.config;
      } catch (err) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `\n  Sanctuary: could not bootstrap ${platformHint} config at ${canonicalPath}`
        );
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`  Error: ${(err as Error).message}\n`);
        process.exit(1);
      }
    }
  }

  // FIX (N1-3 corrected, 2026-07-27): `sanctuary protect --exclusive-egress`
  // (or `--provision-agent-account`) without a provisionable agent selected
  // silently armed NOTHING -- maybeRunAutoProvisionForWrap's early return
  // (`agentConfig.platform !== "hermes"`) prints nothing, and there was zero
  // cross-flag validation on these flags. Only Hermes is provisionable
  // today; refuse loudly rather than quietly performing a plain cooperative
  // wrap while the operator believes exclusive egress (or account
  // provisioning) was armed. Fires the same regardless of --dry-run -- a
  // dry run must not silently omit the same refusal.
  //
  // This checks the RESOLVED platform (`agentConfig?.platform`), not the
  // explicit `--hermes` flag: `platformHint` is only set when the operator
  // passed a platform selector, but `maybeRunAutoProvisionForWrap` (and the
  // arming it gates) key on the platform `detectAgentConfigWithDiagnostics`
  // actually resolves, which auto-detects Hermes with no flag at all (and
  // resolves Hermes from an explicit `--wrap ~/.hermes/cli-config.json`
  // too).
  //
  // FIX (N1-3 placement, 2026-07-27 harden-loop): this check must run AFTER
  // the fresh-config bootstrap directly above, not before it. Hermes
  // detection only probes the legacy JSON compat surface
  // (`~/.hermes/cli-config.json` / `config.json`) -- never the authoritative
  // `~/.hermes/config.yaml` that v0.16.0 actually routes MCP traffic
  // through (see the DEBT note above). A first-install/yaml-only Hermes
  // host therefore has `agentConfig === undefined` on the FIRST detection
  // call, and only resolves to a Hermes config once the bootstrap block
  // above has written the compat JSON file and re-detected. Checking before
  // the bootstrap falsely refused that exact host with "re-run with
  // --hermes" advice the operator had already followed. Placed here --
  // after the bootstrap, before the generic "Configuration Not Found"
  // handler -- `agentConfig` reflects the FINAL resolution, and a genuinely
  // unresolvable config (no platform hint, or a hint the bootstrap can't
  // help) still falls through to that handler's better diagnostics
  // (paths checked, per-path errors) unchanged.
  if (options.exclusiveEgress === true || options.provisionAgentAccount === true) {
    const requestedFlags = [
      options.exclusiveEgress === true ? "--exclusive-egress" : undefined,
      options.provisionAgentAccount === true ? "--provision-agent-account" : undefined,
    ]
      .filter((flag): flag is string => flag !== undefined)
      .join(" / ");
    if (agentConfig?.platform !== "hermes") {
      if (!agentConfig) {
        // FIX (N1-3 diagnostics-swallow, harden-loop): this refusal exits
        // BEFORE the "Configuration Not Found" handler below ever runs, so
        // that handler's better diagnostics (`detection.pathsChecked`, the
        // per-path `detection.errors`) and the underlying read error were
        // silently dropped -- and the fixed "re-run with --hermes" advice
        // is actively wrong when the operator already gave an explicit
        // `--wrap <path>` (a typo'd path just gets told to try a flag that
        // wouldn't change anything) or already passed `--hermes` itself
        // (whose config the bootstrap above could not resolve). Surface
        // the diagnostics this check would otherwise swallow, and only
        // suggest `--hermes` when the operator has not already tried an
        // explicit selector.
        const alreadyTriedSelector = options.wrap !== undefined || platformHint === "hermes";
        let diagnosticsClause = "";
        if (detection.pathsChecked.length > 0) {
          diagnosticsClause += `\n\n  Paths checked:\n${detection.pathsChecked
            .map((p) => `    ${p}`)
            .join("\n")}`;
        }
        if (detection.errors.length > 0) {
          diagnosticsClause += `\n\n  Errors encountered:\n${detection.errors
            .map((e) => `    ${e.path}: ${e.error}`)
            .join("\n")}`;
        }
        const notFoundClause = "no agent configuration could be found";
        if (alreadyTriedSelector) {
          // SAFETY: stderr is the operator-facing CLI channel for this subcommand.
          console.error(
            `\n  Sanctuary: ${requestedFlags} requires a provisionable agent selector, ` +
              `but ${notFoundClause}. Only Hermes is provisionable today. Without it, ` +
              `wrap would proceed as a plain cooperative wrap and arm nothing.${diagnosticsClause}\n`
          );
        } else {
          // SAFETY: stderr is the operator-facing CLI channel for this subcommand.
          console.error(
            `\n  Sanctuary: ${requestedFlags} requires a provisionable agent selector, ` +
              `but ${notFoundClause}. Only Hermes is provisionable today -- re-run with ` +
              `--hermes against a Hermes config. Without it, wrap would proceed as a ` +
              `plain cooperative wrap and arm nothing.${diagnosticsClause}\n`
          );
        }
        process.exit(2);
        return;
      }
      // SAFETY: stderr is the operator-facing CLI channel for this subcommand.
      console.error(
        `\n  Sanctuary: ${requestedFlags} requires a provisionable agent selector, ` +
          `but the detected/configured platform is "${agentConfig.platform}". Only Hermes is provisionable today -- re-run with ` +
          `--hermes against a Hermes config. Without it, wrap would proceed as a ` +
          `plain cooperative wrap and arm nothing.\n`
      );
      process.exit(2);
      return;
    }
    // FIX (N1-3 non-darwin gap, 2026-07-27 harden-loop): the check above
    // only guards the platform-selector dimension. `runAutoProvisionForWrap`
    // (auto-provision.ts) ALSO no-ops silently -- `{ ran: false }`, nothing
    // printed -- on any non-darwin host, D1's v1 scope being darwin-only.
    // Without this, a non-darwin Hermes host reached the real wrap flow,
    // auto-provision silently armed nothing, and `printWrapSuccess` still
    // rendered a success banner with no statement that exclusive egress (or
    // account provisioning) armed nothing. Refuse loudly here too, before
    // any wrap work, exactly like the platform-selector case above.
    // `deps.osPlatform` is a test-only seam (defaults to the real `node:os`
    // `platform()`) so this deterministically exercises both branches
    // regardless of the CI runner's actual OS.
    const resolvedOsPlatform = (deps.osPlatform ?? platform)();
    if (resolvedOsPlatform !== "darwin") {
      // SAFETY: stderr is the operator-facing CLI channel for this subcommand.
      console.error(
        `\n  Sanctuary: ${requestedFlags} requires automatic account provisioning ` +
          `and Castle Wall arming, which are darwin-only today (this host reports ` +
          `"${resolvedOsPlatform}"). Without it, wrap would proceed as a plain cooperative ` +
          `wrap and arm nothing.\n`
      );
      process.exit(2);
      return;
    }
  }

  if (!agentConfig) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`\n  Sanctuary: Configuration Not Found\n`);
    if (platformHint) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`  Could not find ${platformHint} configuration.`);
    } else if (options.wrap) {
      console.error(`  Could not read config file: ${options.wrap}`);
    } else {
      console.error("  Could not auto-detect any agent configuration.");
      console.error(
        "  Use --openclaw, --hermes, --claude-code, --cursor, --cline, --mastra, or --wrap /path/to/config.json"
      );
    }
    if (detection.pathsChecked.length > 0) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Paths checked:`);
      for (const p of detection.pathsChecked) console.error(`    ${p}`);
    }
    if (detection.errors.length > 0) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Errors encountered:`);
      for (const e of detection.errors) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`    ${e.path}: ${e.error}`);
      }
    }
    console.error("");
    process.exit(1);
  }

  // An empty server list is no longer a hard error: wrap proceeds to inject
  // Sanctuary as the sole entry. This unblocks (a) first-install configs
  // that have no `mcpServers` key yet and (b) re-wrap of a config whose
  // only entry was Sanctuary (which extractServers filters out).
  const hasSanctuaryInRaw = rawConfigContainsSanctuary(
    agentConfig.rawConfig,
    agentConfig.platform
  );
  if (hasSanctuaryInRaw) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `\n  Sanctuary already wrapped: updating the existing Sanctuary entry.\n`
    );
  } else if (agentConfig.servers.length === 0) {
    if (agentConfig.platform === "hermes") {
      // F7 (v1.6.1 first-run honesty): the empty surface here is the legacy
      // cli-config.json artifact Hermes does NOT consult for MCP routing
      // (see the DEBT note in the bootstrap path above). Printing "installed
      // as the only MCP server" contradicted the config.yaml message printed
      // moments earlier ("existing MCP servers there are preserved"), so
      // point at the authoritative YAML surface instead.
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  Hermes routes MCP traffic through ${hermesConfigYamlPath()}.` +
          `\n  Sanctuary will be added there; existing MCP entries are preserved.\n`
      );
    } else {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  Found ${agentConfig.platform} config at ${agentConfig.configPath} with no MCP servers yet.`
      );
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `  Sanctuary will be installed as the only MCP server.\n`
      );
    }
  }

  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(`\n  Sanctuary wrap`);
  console.error(`  Platform: ${agentConfig.platform}`);
  console.error(`  Config: ${agentConfig.configPath}`);

  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(
    `  ${formatMcpServerCount(agentConfig.servers.length, hasSanctuaryInRaw)}`
  );

  const upstreamServers = convertToUpstreamServers(agentConfig.servers);
  for (const server of upstreamServers) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `    → ${server.name} (${server.transport.type}, tier ${server.default_tier})`
    );
  }

  if (options.dryRun) {
    // D4 staging, Bug 2: report what WOULD be written to Hermes's
    // config.yaml so the dry run previews the full wrap, while Bug 1
    // keeps this path guaranteed write-free (the gate sits above every
    // write: config bootstrap, fortress state, agent-record persistence).
    if (agentConfig.platform === "hermes") {
      await reportHermesYamlDryRun(options);
    }
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`\n  Dry run. No changes made.\n`);
    return;
  }

  // Resolve the storage path once up front so the passphrase, sovereignty
  // profile, backup dir, and every other on-disk artifact land in the same
  // per-tenant location when SANCTUARY_STORAGE_PATH is set.
  const storagePath = resolveStoragePath();
  const fortressWritable = await preflightFortressPathWritable(storagePath);
  if (!fortressWritable.ok) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `\n  Sanctuary wrap: ${formatFortressPathWritableError(
        storagePath,
        fortressWritable,
      )}\n`,
    );
    process.exit(2);
  }

  // Resolve or generate passphrase.
  //
  // Invariant: the resolved passphrase never reaches argv or the rewritten
  // agent config. User-supplied `--passphrase` is treated as a one-time
  // setter - we persist it into Keychain/fallback and the launcher
  // re-resolves it at runtime via the same path everyone else uses.
  // See SEC-061 in Archive/DELTA_REVIEW_V0.9.0_RC1.md.
  let passphraseLocation: string;
  let passphraseSource: string;
  // v1.1.2 hotfix (Finding V): capture the passphrase value so the
  // wrap-auto dashboard can derive the master key + initialize an
  // AuditLog for the v1.1 hub bindings. Held in this function's scope
  // only; never persisted to disk beyond the existing keychain write
  // and never injected into the rewritten harness env.
  let passphraseValue: string | undefined;
  if (options.passphrase) {
    try {
      const persist =
        deps.persistPassphrase ??
        ((value: string) => persistUserProvidedPassphrase(value, { storagePath }));
      const persisted = await persist(options.passphrase);
      passphraseLocation = persisted.location;
      passphraseSource = persisted.source;
      passphraseValue = options.passphrase;
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  \u{1F510} Persisted user-supplied passphrase (${persisted.location}).`
      );
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `  Back up with: sanctuary export-passphrase`
      );
    } catch (err) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Sanctuary: Passphrase Persistence Failed`);
      console.error(`  ${(err as Error).message}`);
      console.error("");
      process.exit(2);
    }
  } else if (process.env.SANCTUARY_PASSPHRASE) {
    passphraseLocation = "SANCTUARY_PASSPHRASE";
    passphraseSource = "env";
    passphraseValue = process.env.SANCTUARY_PASSPHRASE;
  } else {
    try {
      const resolve =
        deps.resolvePassphrase ??
        (() => getOrCreatePassphrase({ storagePath }));
      const resolved = await resolve();
      passphraseLocation = resolved.location;
      passphraseSource = resolved.source;
      passphraseValue = resolved.value;
      if (resolved.source === "generated") {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `\n  \u{1F510} Generated and stored passphrase (${resolved.location}).`
        );
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Back up with: sanctuary export-passphrase`
        );
      }
    } catch (err) {
      if (err instanceof PassphraseKeyringUnreachableError) {
        // Locked / unreachable OS keyring (error 36 / no D-Bus): fail closed
        // with the actionable unlock message. Sanctuary did NOT regenerate or
        // overwrite the stored passphrase, so retrying after unlocking the
        // keyring recovers cleanly.
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`\n  Sanctuary: Keyring Locked`);
        console.error(`  ${err.message}\n`);
        process.exit(2);
      }
      if (err instanceof PassphraseUnreadableError) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`\n  Sanctuary: Passphrase Unreadable`);
        console.error(`  ${err.message}\n`);
        process.exit(2);
      }
      throw err;
    }
  }

  // Emit fallback-storage warning (SEC-063) when not using an OS keyring.
  // One-time: only on first wrap (source === "generated") when the location
  // is the fallback file, not when reading back a pre-existing fallback.
  // Treats macOS Keychain and Linux Secret Service as equivalent OS-keyring
  // destinations; the warning is about falling back to the machine-local
  // encrypted file, which is weaker than either keyring.
  const usingFallback = !isOsKeyringLocation(passphraseLocation);
  const isFallbackGenerated = passphraseSource === "generated" && usingFallback;
  const isFallbackUserProvided =
    passphraseSource === "fallback-file" && usingFallback;
  if (isFallbackGenerated || (options.passphrase && isFallbackUserProvided)) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `\n  \u26A0  Passphrase stored in encrypted fallback file (machine-local key).` +
      `\n     This is protected only against off-machine access. On macOS, Sanctuary` +
      `\n     uses Keychain; on Linux, Sanctuary uses Secret Service (D-Bus, via` +
      `\n     libsecret) when available. To migrate: run \`sanctuary export-passphrase\`` +
      `\n     on the current machine, then import into the OS keyring or pass via the` +
      `\n     SANCTUARY_PASSPHRASE env var on the new machine.`
    );
  }

  // Write sovereignty profile into the per-tenant storage path resolved
  // above (honours SANCTUARY_STORAGE_PATH for multi-agent hosts).
  await mkdir(storagePath, { recursive: true, mode: 0o700 });

  // Establish the fortress's unified custody (core/master-custody.ts) BEFORE
  // anything trust-bearing is written: one master, wrapped under the
  // resolved passphrase AND a minted recovery key (a wrap of that same
  // master - never a parallel one). Legacy fortresses migrate in place on
  // this unlock. Interactive runs force recovery-key capture + re-entry
  // verification; non-interactive runs are recorded as an audited headless
  // install. Fail closed on a credential that does not unlock (#5).
  let wrapCustody: WrapCustodyResult | undefined;
  if (passphraseValue !== undefined) {
    try {
      wrapCustody = await establishWrapCustody({
        storagePath,
        passphrase: passphraseValue,
        interactive: !options.noOpen && process.stdin.isTTY === true,
      });
    } catch (err) {
      if (err instanceof CustodyUnlockError) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`\n  Sanctuary wrap: Custody Establishment Failed`);
        console.error(`  ${err.message}\n`);
        process.exit(2);
      }
      throw err;
    }
  }

  if (passphraseValue !== undefined) {
    // Auto-bootstrap pinned-key state for the IPC handshake. Failures here
    // warn but do not abort wrap: a missing pin surfaces cleanly at handshake
    // time (sysext refuses connection) rather than as a wrap-startup abort.
    // First-integration discipline: do no harm to the wrap critical path.
    try {
      const pinResult = await runProvisionPin([], {
        out: new Writable({ write(_chunk, _encoding, callback) { callback(); } }),
        err: new Writable({ write(_chunk, _encoding, callback) { callback(); } }),
        env: {
          ...process.env,
          SANCTUARY_STORAGE_PATH: storagePath,
          SANCTUARY_PASSPHRASE: passphraseValue,
        },
      });
      if (pinResult !== 0) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `\n  Sanctuary wrap: Castle Wall provision-pin auto-bootstrap exited ${pinResult}.` +
          `\n  Wrap continues; run 'sanctuary castle-wall provision-pin' manually if IPC handshake fails.`
        );
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  Sanctuary wrap: Castle Wall provision-pin auto-bootstrap threw (${msg}).` +
        `\n  Wrap continues; run 'sanctuary castle-wall provision-pin' manually if IPC handshake fails.`
      );
    }
  }

  // The active Castle Wall bring-up: the macOS daemon (channel basis, default) OR
  // the opt-in Linux producer-signed activation (FIX 3). Both expose `stop()`; we
  // keep only the common shape so the cleanup is uniform.
  let castleWallDaemon: { stop(): Promise<void> } | undefined;
  let castleWallDaemonLivenessSince: Date | undefined;
  let unregisterCastleWallCleanup: (() => void) | undefined;
  const registerCastleWallCleanup = () => {
    if (!castleWallDaemon) return;
    unregisterCastleWallCleanup?.();
    const stop = async () => {
      try {
        await castleWallDaemon?.stop();
      } catch {
        /* best-effort: a shutdown cleanup must not throw out of the signal handler */
      }
    };
    unregisterCastleWallCleanup = registerProcessShutdownCleanup(stop);
  };
  const startCastleWallForWrap = async (auditLog: AuditLog, masterKey: Uint8Array) => {
    if (castleWallDaemon) return;
    castleWallDaemonLivenessSince = new Date();
    const fortressId = fortressIdFromStoragePath(storagePath);
    const runtime = await import("../castle-wall/runtime/index.js");

    // FIX 3 (codex HIGH - wire the opt-in producer-signed close into production).
    // On Linux WITH the explicit opt-in flag, route through the producer-signed
    // activation gate (fail-closed, drill-pending, off by default). macOS - and
    // Linux WITHOUT the flag - keep the existing macOS daemon / channel basis.
    // The gate itself re-checks platform + opt-in, so this is belt-and-suspenders.
    if (
      process.platform === "linux" &&
      runtime.isLinuxProducerSignedActivationRequested()
    ) {
      const key = await runtime.buildLinuxIpcClientKeyMaterial({
        fortressPath: storagePath,
        fortressId,
        masterKey,
      });
      const outcome = await runtime.maybeActivateLinuxProducerSignedCastleWall({
        fortressId,
        fortressStoragePath: storagePath,
        key,
        auditSink: auditLog,
      });
      // The gate returns activated:false only when NOT opted in / not Linux -
      // neither is possible here (we just checked both), so an inactive outcome
      // means a logic drift; treat it as a no-op rather than a fake-arm.
      if (outcome.activated) {
        castleWallDaemon = outcome.activation;
        registerCastleWallCleanup();
      }
      return;
    }

    castleWallDaemon = await runtime.startMacOSCastleWallDaemon({
      fortressPath: storagePath,
      fortressId,
      masterKey,
      auditLog,
    });
    registerCastleWallCleanup();
  };
  const stopTransientCastleWallDaemonForAutoProvision = async () => {
    const daemon = castleWallDaemon;
    castleWallDaemon = undefined;
    unregisterCastleWallCleanup?.();
    unregisterCastleWallCleanup = undefined;
    await daemon?.stop();
  };

  // v1.2.1 (Finding GGG): plaintext passphrase backup file is now opt-in.
  // Default: Keychain-only on macOS. The plaintext file is written ONLY when
  // --write-passphrase-backup <path> is supplied. The stderr banner still
  // prints so the operator sees the passphrase once.
  if (passphraseSource === "generated" && passphraseValue !== undefined) {
    if (options.writePassphraseBackup) {
      try {
        await disclosePassphrase({
          passphrase: passphraseValue,
          storagePath: dirname(options.writePassphraseBackup),
          fortressId: fortressIdFromStoragePath(storagePath),
          mode:
            options.noOpen || process.stdin.isTTY !== true
              ? "no-confirm"
              : "interactive",
        });
      } catch (err) {
        if (
          err instanceof PassphraseConfirmationDeclinedError ||
          err instanceof PassphraseConfirmationNonInteractiveError
        ) {
          // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
          console.error(`\n  Sanctuary wrap: ${err.message}\n`);
          process.exit(2);
        }
        throw err;
      }
    } else {
      // Keychain-only: print the passphrase banner to stderr but do NOT
      // write a plaintext file to disk.
      process.stderr.write(
        `\n  Passphrase stored in macOS Keychain.` +
        `\n  Run 'sanctuary export-passphrase' to retrieve it.` +
        `\n  To write a plaintext backup: sanctuary wrap ... --write-passphrase-backup <path>\n`,
      );
    }
  }

  const profile = createWrapProfile(upstreamServers);
  // Read-both, write-new: new wraps write this canonical name; tenant
  // discovery (cli/agents/discovery.ts) also recognizes the legacy
  // pre-vocabulary-sweep filename so existing installs keep working.
  const profilePath = join(storagePath, "wrap-profile.json");
  await writeFile(profilePath, JSON.stringify(profile, null, 2), {
    mode: 0o600,
  });

  // The args list is a constant - never inject `--passphrase`. The launcher
  // re-resolves the stored passphrase at runtime from Keychain / fallback
  // file / SANCTUARY_PASSPHRASE env var. See SEC-061. Env-block and
  // command/args construction live in buildSanctuaryEnv /
  // resolveSanctuaryCommand so the dry-run reporter previews the exact
  // entry the real run writes.
  const sanctuaryEnv = buildSanctuaryEnv(options);
  const { command: sanctuaryCommand, args: sanctuaryArgs } =
    resolveSanctuaryCommand(options);

  // 2026-07-02 hardening: the MCP entry written below is PINNED to
  // SANCTUARY_VERSION with no prior guarantee that version is actually
  // published - an unpublished pin yields a dead entry behind a success
  // banner. Probe the registry (short timeout) and downgrade the claim
  // honestly. NEVER blocks the wrap: "unpublished" and "unreachable" both
  // warn and continue (availability); `--dev-dist` entries point at a local
  // build validated above and involve no registry, so they skip the probe.
  // The outcome is ALSO threaded into the terminal-final success banner
  // (WrapSuccessInfo.pinnedVersionResolvability): the early warning here
  // scrolls above dozens of lines of subsequent flow output, and a success
  // surface that ends byte-identical to the resolvable case would re-create
  // the exact dead-entry-behind-a-success-banner defect the probe exists to
  // close.
  let pinResolvability: PinnedVersionResolvability | undefined;
  if (options.devDist === undefined) {
    const checkPin = deps.checkPinResolvability ?? checkPinnedVersionResolvable;
    pinResolvability = await checkPin(SANCTUARY_VERSION);
    if (pinResolvability === "unpublished") {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  WARNING: the harness MCP entry this wrap writes is pinned to` +
          `\n  @sanctuary-framework/mcp-server@${SANCTUARY_VERSION}, but the npm registry` +
          `\n  (as resolved from this directory) does not have that version. Unless your` +
          `\n  agent's own project config routes the package scope to another registry,` +
          `\n  the MCP entry will fail to start until it is published. If you are running` +
          `\n  an unpublished build, re-run with --dev-dist <path-to-dist/cli.js> to point` +
          `\n  the entry at your local build instead.`
      );
    } else if (pinResolvability === "unreachable") {
      // "unreachable" also covers a REACHED custom registry whose
      // unauthenticated 404 the probe declines to treat as authoritative
      // (see checkPinnedVersionResolvable), so the stated cause must not
      // claim the registry could not be reached.
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  Note: could not confirm with the npm registry that the pinned version` +
          `\n  ${SANCTUARY_VERSION} resolves: the registry was unreachable (offline or` +
          `\n  blocked), or a custom registry gave an answer this unauthenticated probe` +
          `\n  cannot treat as authoritative. This wrap cannot verify the MCP entry it` +
          `\n  writes will start; if the agent fails to start, re-run 'sanctuary protect'` +
          `\n  once the registry confirms the version.`
      );
    }
  }

  // D4 staging, Bug 2: Hermes v0.16.0 loads MCP servers from
  // ~/.hermes/config.yaml (`mcp_servers:` key, upstream
  // hermes_cli/mcp_config.py and mcp_startup.py), not from the JSON
  // cli-config.json wrap rewrites below. Without the YAML injection the
  // wrap records the agent but Hermes MCP traffic silently bypasses the
  // Sanctuary proxy. The plan is computed BEFORE any harness config is
  // touched so an unsupported YAML shape aborts with both surfaces
  // untouched; the JSON write is kept for forward-compat with the
  // documented cli-config.json surface.
  let hermesYaml:
    | { yamlPath: string; existedBefore: boolean; plan: HermesYamlPlan }
    | undefined;
  if (agentConfig.platform === "hermes") {
    const yamlPath = hermesConfigYamlPath();
    // D4 P2-3: a symlinked config.yaml would redirect the writeFile below
    // outside ~/.hermes. Checked here, before ANY surface is backed up or
    // rewritten, so the refusal leaves everything untouched.
    try {
      await refuseSymlinkTarget(yamlPath, "Hermes config.yaml");
    } catch (err) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Sanctuary: Hermes config.yaml Not Editable`);
      console.error(`  ${(err as Error).message}`);
      console.error(`  Nothing was modified.\n`);
      process.exit(1);
    }
    let existingYaml: string | null = null;
    try {
      existingYaml = await readFile(yamlPath, "utf-8");
    } catch {
      // File absent - the plan creates it.
    }
    try {
      // Parse-parity guard (Erik-ratified 2026-07-03, Option A): before the
      // line-scanner's plan is allowed to drive a mutation, validate the
      // scanner's view against a REAL PyYAML parse of the same bytes. Refuse
      // on any disagreement, and refuse (fail-closed) if the PyYAML validator
      // cannot run at all. This supersedes trusting the scanner's fidelity;
      // it does not claim the scanner is correct, only that a real parser and
      // the scanner agree on the facts this edit depends on. Runs BEFORE any
      // surface is backed up or rewritten, so a refusal leaves everything
      // untouched.
      //
      // The sidecar DI seam is NON-injectable on this production mutating
      // path: the __hermesParityTestHook override is test-only (not a public
      // dep), so a programmatic caller cannot pass an agreeing no-op parity and
      // edit config.yaml without the real validator (DI-bypass closed
      // 2026-07-03). The production path always runs a REAL PyYAML parse; it
      // resolves WHICH python3 to run by probing a CODE-CONTROLLED candidate
      // list (see hermesParityPythonCandidates) for PyYAML importability. No
      // caller argument and no environment variable can steer that selection,
      // so the parse cannot be pointed at an attacker-chosen interpreter.
      await assertHermesYamlParseParity(
        existingYaml,
        __hermesParityTestHook.parity
      );
      const plan = planHermesYamlInjection(existingYaml, {
        command: sanctuaryCommand,
        args: sanctuaryArgs,
        ...(Object.keys(sanctuaryEnv).length > 0 ? { env: sanctuaryEnv } : {}),
      });
      hermesYaml = { yamlPath, existedBefore: existingYaml !== null, plan };
    } catch (err) {
      if (err instanceof HermesYamlUnsupportedError) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`\n  Sanctuary: Hermes config.yaml Not Editable`);
        console.error(`  ${err.message}`);
        console.error(
          `  Nothing was modified. Hermes routes MCP traffic through ${yamlPath};` +
            `\n  wrap will not proceed without updating it (a JSON-only wrap would` +
            `\n  silently leave Hermes traffic outside the Sanctuary proxy).\n`
        );
        process.exit(1);
      }
      if (err instanceof HermesYamlParityRefusedError) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`\n  Sanctuary: Hermes config.yaml Not Editable`);
        console.error(`  ${err.message}`);
        console.error(
          `  Nothing was modified. The line-scanner that edits config.yaml is ` +
            `checked\n  against the real PyYAML parser Hermes uses; wrap refuses to ` +
            `edit when\n  they disagree or when that parser cannot run.\n`
        );
        process.exit(1);
      }
      throw err;
    }
  }

  // `configStillWrapped` carries the PRE-wrap detection result (did ANY
  // wrapped surface genuinely still carry the sanctuary entry? for Hermes
  // that includes the authoritative config.yaml, whose plan action
  // `replace-entry` means it did). Computed BEFORE the backup below so the
  // crash-window warning next to it can fire before the already-wrapped
  // content is captured as "the" backup; consumed by the deferred wrap-meta
  // write at the end of the wrap.
  const configStillWrapped =
    hasSanctuaryInRaw || hermesYaml?.plan.action === "replace-entry";

  // MED-2 (crash-window honesty): a config that already carries the
  // sanctuary entry while NO wrap-meta exists on disk is exactly what an
  // interrupted earlier wrap leaves behind (surfaces committed, then a
  // crash before the deferred meta write). In that state the pristine
  // pre-wrap config CANNOT be identified: the condition is
  // indistinguishable from an operator who authored the sanctuary entry by
  // hand, so no automatic recovery is attempted. The backup this wrap is
  // about to take captures the CURRENT (already-wrapped) contents, and a
  // later --unwrap restores THAT. Say so loudly, and point at the backup
  // directory where an older pristine snapshot from the interrupted wrap
  // may still exist (findNewerBackup's inverse breadcrumb: backup
  // filenames embed timestamps, so older snapshots sort below the fresh
  // one).
  //
  // 2026-07-02 hardening (MED-2 residual): the meta check is scoped to THIS
  // surface (resolve()d configPath). The previous tenant-global check let a
  // wrap-meta belonging to a DIFFERENT surface suppress the warning while
  // this surface was in exactly the crash-window state.
  //
  // Copy honesty (fifth round): hasExistingWrapMeta deliberately reads an
  // UNREADABLE pointer as false (failing toward this warning), so the text
  // says "no READABLE wrap metadata" - in the unreadable-pointer state the
  // meta likely IS on disk and the deferred meta write later in this same
  // run will refuse with "wrap metadata exists but could not be read";
  // the unhedged wording flatly contradicted that message.
  if (
    configStillWrapped &&
    !(await hasExistingWrapMeta(agentConfig.configPath))
  ) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `\n  WARNING: this config already contains a Sanctuary entry, but no` +
        `\n  readable wrap metadata exists for it, so the pristine pre-wrap` +
        `\n  config could not be identified. The backup taken by THIS wrap` +
        `\n  captures the current (already-wrapped) contents, and --unwrap` +
        `\n  will restore that state. If this follows an interrupted wrap, check` +
        `\n  ${join(storagePath, "backup")}` +
        `\n  for an older pristine backup (timestamped config-backup-* files)` +
        `\n  before relying on --unwrap.`
    );
  }

  // Back up and rewrite agent config. For Hermes, config.yaml is backed up
  // alongside cli-config.json and recorded in the wrap meta so unwrap
  // restores both surfaces.
  const backupPath = await backupConfig(agentConfig.configPath);
  let hermesYamlBackupPath: string | null = null;
  if (hermesYaml?.existedBefore) {
    hermesYamlBackupPath = await backupConfig(hermesYaml.yamlPath);
  }

  // Harden round: the wrap-meta write is DEFERRED until every wrapped
  // surface below is verified-committed. Writing it here (as earlier
  // revisions did) violated the F6 invariant ("a wrap-meta exists" means
  // "currently wrapped"): every rollback path after the write left the
  // meta behind, and the next SUCCESSFUL wrap then preserved that stale
  // pristine pointer, so a later --unwrap restored pre-failed-wrap content
  // and silently discarded operator edits made between the failed wrap and
  // the retry (worse for the created-fresh Hermes config.yaml, where a
  // stale `backupPath: null` made unwrap DELETE an operator-authored file).

  // Rollback for every post-rewrite failure: restore the primary config
  // and, for Hermes, the config.yaml surface (or remove it when this wrap
  // created it fresh). Defined here so the deferred wrap-meta write below
  // shares the exact rollback the YAML block uses. Returns false when ANY
  // surface could not be restored (MED-1: the wrap-meta failure path must
  // know, because a still-wrapped surface with no meta on disk is an
  // orphan --unwrap cannot find).
  const rollbackWrapSurfaces = async (): Promise<boolean> => {
    let allRestored = true;
    if (hermesYaml) {
      if (hermesYamlBackupPath) {
        if (
          !(await restoreFromBackup(hermesYaml.yamlPath, hermesYamlBackupPath))
        ) {
          allRestored = false;
        }
      } else {
        try {
          // Round-3 P1-A: parent-walk-safe even on the rollback path.
          await unlinkSafeUnderRoot(hermesYaml.yamlPath);
        } catch (err) {
          // Best-effort removal of the file this wrap created. ENOENT means
          // the write itself never landed (the end-state "absent" already
          // holds); any OTHER failure (a symlink raced into its parent, an
          // unwritable directory) leaves the created file in place, which
          // counts as a failed restore for the orphan-wrap guard below.
          const code =
            err && typeof err === "object" && "code" in err
              ? (err as NodeJS.ErrnoException).code
              : undefined;
          if (code !== "ENOENT") allRestored = false;
        }
      }
    }
    if (!(await restoreFromBackup(agentConfig.configPath, backupPath))) {
      allRestored = false;
    }
    return allRestored;
  };

  // The unwrap pointer this wrap will persist once every surface verifies
  // (see the deferred-write rationale at the persist site below). Built
  // here, right after the backups, so the orphan-wrap guard can fall back
  // to writing it from EVERY rollback path, not just the meta-write-failure
  // one.
  const wrapMetaPayload = {
    backupPath,
    originalPath: agentConfig.configPath,
    platform: agentConfig.platform,
    wrappedAt: new Date().toISOString(),
    ...(hermesYaml
      ? {
          auxiliary: [
            {
              originalPath: hermesYaml.yamlPath,
              backupPath: hermesYamlBackupPath,
            },
          ] satisfies WrapMetaAuxiliaryFile[],
        }
      : {}),
  };
  const persistWrapMeta = deps.saveWrapMeta ?? saveWrapMeta;

  // MED-1 orphan-wrap guard, extended to ALL rollback paths (2026-07-02
  // hardening; the #843 fix covered only the meta-write-failure rollback,
  // leaving the three earlier rollback call sites able to end
  // wrapped-with-no-meta). When ANY surface restore fails, the live config
  // may STILL route traffic through Sanctuary while nothing on disk points
  // at the pre-wrap backup; `--unwrap` would report "No Sanctuary wrap
  // found". A meta pointing at the pre-wrap backup is strictly better than
  // that orphan state (unwrap restores are idempotent, so re-restoring an
  // already-restored surface is harmless - including a null-backup aux file
  // this failed wrap never created or already removed, which unwrap's
  // removal branch tolerates as already-absent ENOENT), so write it; if
  // even that fails
  // (e.g. disk full), never end silently: spell out exactly what --unwrap
  // will (not) do and the manual restore for every surface.
  const guardOrphanWrapAfterRollback = async (
    fullyRolledBack: boolean,
  ): Promise<void> => {
    if (fullyRolledBack) return;
    try {
      await persistWrapMeta(wrapMetaPayload, { configStillWrapped });
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `  Wrap metadata was written after the failed restore: run the` +
          `\n  unwrap command (--unwrap) to retry restoring the pre-wrap config.`
      );
    } catch (retryErr) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  CRITICAL: the config is STILL WRAPPED and no wrap metadata` +
          `\n  could be written: ${(retryErr as Error).message}` +
          `\n  --unwrap will NOT find this wrap; traffic keeps routing` +
          `\n  through Sanctuary until you restore manually:`
      );
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `    cp "${backupPath}" "${agentConfig.configPath}"`
      );
      if (hermesYaml) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          hermesYamlBackupPath
            ? `    cp "${hermesYamlBackupPath}" "${hermesYaml.yamlPath}"`
            : `    rm "${hermesYaml.yamlPath}" (this wrap created it fresh)`
        );
      }
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error("");
    }
  };

  const rewrite = deps.rewriteConfig ?? rewriteConfigForWrap;
  // Harden round: the primary rewrite writes the live config IN PLACE
  // (O_TRUNC via writeFileNoFollow, not temp+rename), so a throw mid-write
  // (disk full, EIO) can leave the config truncated. With the wrap-meta
  // write deferred until after verification, an uncaught throw here would
  // propagate out of runWrap with no rollback AND no meta, so
  // `--unwrap` would report nothing to restore. Catch, restore the
  // pre-wrap surfaces, and exit non-zero, matching the YAML-write path.
  try {
    await rewrite(
      agentConfig,
      sanctuaryCommand,
      sanctuaryArgs,
      Object.keys(sanctuaryEnv).length > 0 ? sanctuaryEnv : undefined,
    );
  } catch (err) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `\n  Config rewrite FAILED: ${(err as Error).message}`
    );
    await guardOrphanWrapAfterRollback(await rollbackWrapSurfaces());
    process.exit(1);
  }

  const verifyResult = await verifyRewrittenConfig(
    agentConfig.configPath,
    backupPath
  );
  if (!verifyResult.verified) {
    // 2026-07-02 hardening: verification failure rolls back internally; if
    // THAT restore failed, the live config is in an unknown (possibly still
    // wrapped) state with no meta - run the orphan-wrap guard here too.
    await guardOrphanWrapAfterRollback(verifyResult.restoredOnFailure);
    process.exit(1);
  }

  // D4 staging, Bug 2: apply the precomputed config.yaml injection now that
  // the JSON surface verified. D4 P1-1: the ENTIRE write+verify is inside
  // one rollback scope - a thrown writeFile (unwritable file, bad symlink)
  // previously escaped the verify-only rollback and left the wrap partially
  // applied (JSON wrapped, YAML not: the exact silent-bypass state this fix
  // exists to prevent). Any failure now rolls BOTH surfaces back and exits
  // non-zero, so the wrap is atomic: fully applied or fully rolled back.
  if (hermesYaml) {
    const yamlSurface = hermesYaml;
    let yamlVerified = false;
    try {
      // D4 P2-3 courtesy re-check at write time. Round-2 P1-A: lstat-then-
      // write is TOCTOU-raceable, so the no-follow open is the leaf
      // enforcement. Round-3 P1-A: the leaf-only O_NOFOLLOW could STILL be
      // redirected by a symlinked PARENT (`~/.hermes -> /tmp/victim`), so
      // writeFileSafeUnderRoot walks every parent component from HOME and
      // refuses a symlinked ancestor, recreates missing parents segment-by-
      // segment (no recursive mkdir following a link), then opens the leaf
      // O_NOFOLLOW.
      await refuseSymlinkTarget(yamlSurface.yamlPath, "Hermes config.yaml");
      await writeFileSafeUnderRoot(yamlSurface.yamlPath, yamlSurface.plan.content, {
        mode: 0o600,
      });
      yamlVerified = yamlContainsSanctuaryEntry(
        await readFile(yamlSurface.yamlPath, "utf-8")
      );
    } catch (err) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  Hermes config.yaml write FAILED: ${(err as Error).message}`
      );
      await guardOrphanWrapAfterRollback(await rollbackWrapSurfaces());
      process.exit(1);
    }
    if (!yamlVerified) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  Verification FAILED: No sanctuary entry in rewritten ${yamlSurface.yamlPath}.`
      );
      await guardOrphanWrapAfterRollback(await rollbackWrapSurfaces());
      process.exit(1);
    }
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  Hermes MCP routing: ${formatHermesYamlAction(yamlSurface.plan, yamlSurface.yamlPath)}`
    );
  }

  // F6 + harden round: persist the unwrap pointer ONLY now, after every
  // wrapped surface is verified-committed, so no failure path can leave a
  // meta behind for a wrap that did not stick. `configStillWrapped`
  // (computed pre-backup above) keeps a stale meta left by a pre-1.6.1
  // unwrap - which never removed metas - or by a by-hand unwrap from
  // pinning an ancient pristine pointer over a config the operator has
  // since edited, while a re-wrap over a partially-unwrapped Hermes install
  // (JSON restored, YAML restore failed and retained the meta) still
  // preserves the good pristine pointers. If the meta write itself fails,
  // roll both surfaces back: a wrapped config with no unwrap pointer would
  // strand --unwrap entirely.
  //
  // Honest crash window (MED-2): deferring the meta write opens the inverse
  // hazard. Between the surface commits above and this write, a crash or
  // power loss leaves the config WRAPPED with NO meta. A retry wrap then
  // sees configStillWrapped=true with no existing meta to preserve, so the
  // fresh pointer wins and the fresh backup captures the ALREADY-WRAPPED
  // content; the pristine pre-wrap state survives only in the older
  // timestamped backups nothing points at. Perfect detection is impossible
  // (that state is indistinguishable from a hand-authored sanctuary entry),
  // so the wrap prints the loud pre-backup warning above in exactly that
  // condition instead of guessing.
  try {
    await persistWrapMeta(wrapMetaPayload, { configStillWrapped });
  } catch (err) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `\n  Wrap metadata write FAILED: ${(err as Error).message}`
    );
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  Rolling back: a wrapped config without an unwrap pointer would strand --unwrap.`
    );
    // MED-1 (orphan-wrap guard): when a surface restore fails here, the
    // guard retries the meta write once before giving up (a meta pointing
    // at the pre-wrap backup beats the orphan state), then prints the
    // CRITICAL manual-restore message on a double failure.
    await guardOrphanWrapAfterRollback(await rollbackWrapSurfaces());
    process.exit(1);
  }

  // WP-V1.2 reshape: write the broker-tool identifiers to Claude Code's
  // permissions.allow list at wrap time so the wrapped agent's routine
  // broker calls (request_token, read_secret, list_grants, audit_query)
  // run without a per-turn permission prompt for the operator. The
  // broker's policy gate stops any write-side or destructive operation
  // regardless of the allowlist; the allowlist only suppresses the
  // Claude Code UI confirmation flow on routine reads. Best-effort:
  // failure logs to stderr but does not fail wrap (operator can still
  // grant permission interactively on first call).
  if (agentConfig.platform === "claude-code") {
    try {
      const allowFn =
        deps.installClaudeCodeAllowlist ??
        (async (o) => {
          const { installClaudeCodeAllowlist } = await import(
            "./claude-code-allowlist.js"
          );
          return installClaudeCodeAllowlist(o);
        });
      const allowResult = await allowFn({});
      if (allowResult.alreadyPresent) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Sanctuary broker tool allowlist already present at ${allowResult.installedAt}. No change.`,
        );
      } else {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Sanctuary broker tool allowlist updated at ${allowResult.installedAt} ` +
            `(${allowResult.added.length} ${allowResult.added.length === 1 ? "entry" : "entries"} added; ` +
            `routine broker calls run without per-turn prompts).`,
        );
      }
    } catch (err) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `  Note: broker tool allowlist write failed (${(err as Error).message}). ` +
          `Wrap is otherwise complete; Claude Code will prompt to approve ` +
          `broker/request_token, broker/read_secret, broker/list_grants, ` +
          `and broker/audit_query on first call. ` +
          `Click "Always allow" once per tool to suppress future prompts.`,
      );
    }
  }

  // v1.1.5 (Finding Z): persist a v1.1 hub `LocalAgentRecord` so the
  // dashboard's Agents view (`/api/hub/agents`, `/v1.1`) reflects the
  // wrap. Without this, v1.1.1 ships the API surface but never populates
  // it (registry construction at `dashboard/v1_1/wiring.ts` was empty by
  // design, deferring the data plane to v1.2). Persistence fires here,
  // after harness-config verification succeeds and before dashboard
  // spawn, so that:
  //   (a) the wrap-auto dashboard's `setV11Bindings` call below picks
  //       up the new record via the rehydrating `buildV11Bindings`;
  //   (b) `--no-dashboard` wraps still register, so a later `sanctuary
  //       dashboard` (or the next wrap) sees the cumulative set;
  //   (c) re-wrapping the same harness updates rather than duplicates
  //       (`upsertPersistedLocalAgent` keys on `agent_id`).
  // Best-effort: persistence errors do not fail wrap (the harness
  // config is already rewritten and operational; a missing dashboard
  // record is a UX degradation, not a security one). The error is
  // surfaced on stderr so operators can re-run later if needed.
  const localAgentRecord = buildLocalAgentRecord({
    storagePath,
    platform: agentConfig.platform,
  });
  try {
    // The host tenant registry must live under the *resolved* storage root,
    // not the hardcoded ~/.sanctuary default. When SANCTUARY_STORAGE_PATH is
    // set (an isolated/drill fortress), `storagePath` is that override and the
    // registry row lands in `<override>/tenants.json` - it must never pollute
    // the real operator fortress's `~/.sanctuary/tenants.json`. When the env
    // var is unset, `storagePath` already equals `~/.sanctuary`, so default
    // behavior (and the existing host-level cross-fortress index) is unchanged.
    // The read side (`sanctuary agents list`) resolves the same root from the
    // same env var, so read and write always agree.
    await registerHostTenant(storagePath, { root: storagePath });
  } catch (err) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  Note: host tenant registry not updated ` +
        `(${(err as Error).message}). ` +
        `Re-run \`sanctuary wrap\` to retry, or check permissions on ${storagePath}/${TENANTS_REGISTRY_FILE_NAME}.`,
    );
  }

  try {
    upsertPersistedLocalAgent(storagePath, localAgentRecord);
  } catch (err) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  Note: v1.1 hub agent record not persisted ` +
        `(${(err as Error).message}). ` +
        `Re-run \`sanctuary wrap\` to retry, or check storage permissions on ${storagePath}.`,
    );
  }

  // PR-2 transparency anchoring opt-in (default OFF). Set to true only
  // when consent is recorded and the MAC'd config is written; checked
  // LOUDLY before each success exit so a requested opt-in can never be
  // silently dropped by a best-effort failure above it.
  let anchorTransparencyEnabled = false;
  const enableAnchorTransparencyForWrap = async (
    storageForWrap: import("../storage/interface.js").StorageBackend,
    masterKeyForWrap: Uint8Array,
    auditLogForWrap: AuditLog,
  ): Promise<void> => {
    if (!options.anchorTransparency || anchorTransparencyEnabled) return;
    const { ANCHOR_CONSENT_TEXT, enableAnchoring } = await import(
      "../transparency/anchoring.js"
    );
    // Print the exact consent statement the flag agreed to; its hash is
    // recorded in the MAC'd config and the audit log.
    process.stderr.write(`\n  ${ANCHOR_CONSENT_TEXT}\n`);
    await enableAnchoring({
      storage: storageForWrap,
      masterKey: masterKeyForWrap,
      auditLog: auditLogForWrap,
      fortressId: fortressIdFromStoragePath(storagePath),
    });
    anchorTransparencyEnabled = true;
    process.stderr.write(
      `\n  Transparency anchoring ENABLED (consent recorded in the audit log).\n` +
        `  Manage it with: sanctuary transparency anchor status|disable|now\n`,
    );
  };
  const failIfAnchorOptInDropped = (): void => {
    if (options.anchorTransparency && !anchorTransparencyEnabled) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  ERROR: --anchor-transparency was requested but anchoring could not be enabled.` +
          `\n  Nothing was transmitted. Fix the error above, or enable it on the existing fortress with:` +
          `\n    sanctuary transparency anchor enable\n`,
      );
      process.exit(2);
    }
  };

  if (options.noDashboard) {
    // v1.1.5 (Finding AA): operator opted out of the per-call dashboard
    // spawn. The agent record is already persisted above; a later
    // `sanctuary dashboard` (or another wrap) will pick it up. Skip the
    // dashboard server, the v1.1 binding, the runtime advertisement,
    // and the auto-open browser path; print a concise success line that
    // points operators at the persistent dashboard.

    let ndAuditLog: AuditLog | undefined;
    let ndAuditStorage: FilesystemStorage | undefined;
    let ndAuditMasterKey: Uint8Array | undefined;
    let unregisterNoDashboardAuditFlush: (() => void) | undefined;
    // v1.3.0 (WWWWW, NNN regression): --no-dashboard wraps previously
    // skipped identity bootstrap because the creation lived after the
    // dashboard startup path. Derive the master key and create a default
    // identity so CLI surfaces (exit export, identity show) work
    // immediately after wrap without launching the dashboard first.
    if (passphraseValue !== undefined && wrapCustody !== undefined) {
      try {
        const ndStorage = new FilesystemStorage(`${storagePath}/state`);
        // Unified custody: the master was established (or migrated) above;
        // re-deriving from key-params here could produce a DIFFERENT master
        // than the envelope holds - exactly the divergence this build ends.
        const ndDerived = { key: wrapCustody.masterKey };
        ndAuditStorage = ndStorage;
        ndAuditMasterKey = ndDerived.key;
        ndAuditLog = new AuditLog(ndStorage, ndDerived.key);
        const flushNoDashboardAuditLogOnShutdown = ndAuditLog;
        unregisterNoDashboardAuditFlush = registerProcessShutdownCleanup(async () => {
          try {
            await flushNoDashboardAuditLogOnShutdown.flush();
          } catch {
            /* best-effort: a shutdown cleanup must not throw out of the signal handler */
          }
        });
        await bestEffortRecordWrapWorkloadRegistration({
          auditLog: ndAuditLog,
          storagePath,
          record: localAgentRecord,
        });
        // Best-effort: daemon failure does not block identity bootstrap.
        // See parallel block below (line ~939) for full rationale.
        try {
          await startCastleWallForWrap(ndAuditLog, ndDerived.key);
        } catch (err) {
          warnCastleWallDaemonNotStarted(err);
        }

        // PR-2: setup opt-in for transparency anchoring (default OFF).
        // NOT best-effort: a failure here is caught by the loud check
        // before the success exit below.
        await enableAnchorTransparencyForWrap(ndStorage, ndDerived.key, ndAuditLog);

        const { IdentityManager } = await import("../cognitive/tools.js");
        const { createIdentity } = await import("../core/identity.js");
        const { derivePurposeKey } = await import("../core/key-derivation.js");
        const identityMgr = new IdentityManager(ndStorage, ndDerived.key);
        const loadResult = await identityMgr.load();
        if (loadResult.loaded === 0) {
          const identityEncKey = derivePurposeKey(ndDerived.key, "identity-encryption");
          const { storedIdentity, publicIdentity } = createIdentity(
            "default",
            identityEncKey,
            "passphrase",
          );
          await identityMgr.save(storedIdentity);
          await ndAuditLog.append("l1", "identity_create", publicIdentity.identity_id, {
            label: "default",
            source: "wrap-auto",
          });
        }
        await ndAuditLog.flush();
        unregisterNoDashboardAuditFlush?.();
      } catch (err) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel.
        console.error(
          `  Note: default identity not created at wrap time ` +
            `(${(err as Error).message}).`,
        );
      }
    }

    failIfAnchorOptInDropped();
    // Auto-provision Step 2 (Build 1): after the cooperative wrap above has
    // fully completed (config rewritten, identity bootstrapped, agent
    // record persisted), offer to provision the dedicated agent account and
    // arm the wall. Runs AFTER, never blocking, the cooperative wrap: a
    // decline / non-TTY skip / mid-flow abort here never reverts anything
    // already done above (fix H4 -- the cooperative wrap always completes).
    const autoProvisionRun = await maybeRunAutoProvisionForWrap(
      agentConfig,
      options,
      deps,
      stopTransientCastleWallDaemonForAutoProvision,
    );
    const autoProvisionSummary = autoProvisionRun.summary;
    renderAutoProvisionOutcome(autoProvisionSummary);
    await exitAfterDeferredAutoProvisionSignal(autoProvisionRun.deferredSignal);
    bestEffortUpsertLocalAgentProtectionSubject({
      storagePath,
      record: localAgentRecord,
      autoProvisionSummary,
    });
    const castleWallProtectionClaim = await resolveWrapProtectionClaim({
      auditLog: ndAuditLog,
      auditStorage: ndAuditStorage,
      masterKey: ndAuditMasterKey,
      autoProvisionSummary,
      castleWallDaemonLivenessSince,
      storagePath,
    });
    const toolName = toolNameFor(agentConfig.platform, agentConfig.servers);
    printWrapSuccessNoDashboard({
      toolName,
      version: readPackageVersion(),
      toolCount: countUpstreamTools(upstreamServers),
      serverCount: upstreamServers.length,
      platform: agentConfig.platform,
      passphraseLocation,
      passphraseSource,
      castleWallProtectionClaim,
      // 2026-07-02 hardening: the dead-pin warning must survive to the
      // terminal-final success surface, not only the mid-flow warning.
      pinnedVersionResolvability: pinResolvability,
    });
    try {
      await stopTransientCastleWallDaemonForAutoProvision();
    } catch (err) {
      // SAFETY: a lingering transient daemon keeps the fortress socket held and blocks the sudo retry.
      console.error(
        `  WARNING: the transient Castle Wall daemon could not be stopped before --no-dashboard exit ` +
          `(${(err as Error).message}). Stop the holding process before retrying the sudo protect command.`,
      );
    }
    return;
  }

  // v1.2.1 (Finding III): track intelligence subsystem health for the
  // success banner. Updated below when the substrate selector loads.
  let intelligenceHealthy: boolean | undefined;
  let intelligenceError: string | undefined;
  // Rho-2.5: whether the consent-gated Tier B redactor was installed on the
  // wrap-auto selector. Threaded into buildV11Bindings so the wrap-emitted
  // dashboard's /api/query-anonymity/pii route reports the truthful state.
  let wrapTierBPiiRedactorInstalled = false;
  let wrapAuditLog: AuditLog | undefined;
  let wrapAuditStorage: FilesystemStorage | undefined;
  let wrapAuditMasterKey: Uint8Array | undefined;
  let unregisterWrapAuditFlush: (() => void) | undefined;

  // Start the dashboard in-process.
  const authToken = generateAuthToken();

  // Fleet Console: wire the wrap ("Protect") dashboard's fleet-roster panel to
  // the REAL, read-only, disk-backed federation projection. Without this the
  // panel's `GET /api/posture/fleet` (and `GET /api/fleet/roster`) always read
  // the honest-absent shape even when federation IS provisioned, so a real fleet
  // was invisible on the wrap dashboard. The provider reads the at-rest fortress
  // records (trust root + durable revocation projection) under the custody
  // master; it is strictly read-only (no sync loop, no mutation, no key
  // material) and resolved lazily per request so a post-start
  // `sanctuary federation provision` is observed without a wrap restart. Only
  // wired when custody is established (federation records are encrypted under the
  // master key); otherwise the panel stays honestly absent.
  const wrapFleetRoster =
    wrapCustody !== undefined
      ? buildWrapFleetRosterProvider({
          storage: new FilesystemStorage(`${storagePath}/state`),
          masterKey: wrapCustody.masterKey,
        })
      : undefined;

  const startFn: DashboardStarter =
    deps.startDashboard ??
    ((opts) =>
      startDashboard({
        port: opts.port,
        ...(opts.host !== undefined ? { host: opts.host } : {}),
        mode: opts.mode,
        authToken: opts.authToken,
        serverVersion: opts.serverVersion,
        resolveEnforcementAvailabilityStatus: async () => {
          const { readEnforcementAvailabilityStatus } = await import(
            "../castle-wall/runtime/enforcement-availability-status.js"
          );
          return readEnforcementAvailabilityStatus(storagePath);
        },
        ...(wrapFleetRoster ? { fleetRoster: wrapFleetRoster } : {}),
      }));
  // Multi-tenancy: honour SANCTUARY_DASHBOARD_PORT so two wraps can pick
  // distinct starting ports without both racing for 3501.
  const requestedPort = resolveDashboardPort(options.port);
  const dashboard = await startDashboardWithFallback(
    startFn,
    requestedPort,
    authToken,
    readPackageVersion()
  );

  // v1.1.2 hotfix (Finding V): bind v1.1 hub surfaces to the wrap-auto
  // dashboard so /v1.1, /api/hub/*, and /api/identities serve content
  // from the wrap-emitted URL. PR #82 wired these routes only into the
  // principal-policy dashboard (sanctuary dashboard standalone path) and
  // the MCP-server boot path; the wrap-auto dashboard at server/src/dashboard/
  // is a separate HTTP server and shipped without any v1.1 routing.
  //
  // Initialization mirrors the standalone path (dashboard-standalone.ts):
  // derive the master key over the persisted passphrase, construct
  // FilesystemStorage + AuditLog. The fortress-on-disk is shared between
  // this short-lived wrap process and any later MCP-server-boot process;
  // both derive the same master key from the same passphrase via Argon2id
  // (read existing key-params if present, else persist fresh ones), so
  // the activity feed projection reads the same audit log the MCP server
  // writes once it boots.
  //
  // v1.2.1 (Finding NNN): create a default identity at wrap time so
  // `sanctuary exit export` works immediately. IdentityManager.load()
  // is called to check if an identity already exists before creating.
  // Reset-history continuity (v1.0.2 item a) is also not consumed here;
  // the next caller (MCP-server-boot or sanctuary dashboard standalone)
  // handles it on first fortress-unlock as before.
  //
  // Best-effort: a derivation failure does not fail wrap (operators still
  // get a working v1.0 dashboard at /). The v1.1 surface is reachable
  // via `sanctuary dashboard` if this wiring path errors.
  if (passphraseValue !== undefined && wrapCustody !== undefined) {
    try {
      const v11Storage = new FilesystemStorage(`${storagePath}/state`);
      // Unified custody: reuse the master established above (envelope-backed)
      // instead of re-deriving from key-params - the spawned MCP server
      // unlocks the same envelope with the same passphrase.
      const derived = { key: wrapCustody.masterKey };
      wrapAuditStorage = v11Storage;
      wrapAuditMasterKey = derived.key;
      wrapAuditLog = new AuditLog(v11Storage, derived.key);
      // FIX (N1-1 corrected, 2026-07-27): `flush()` is the documented
      // contract for durability on short-lived-CLI exit (drains
      // `pendingWrites`/`appendQueue` and writes the graceful-shutdown
      // checkpoint -- see AuditLog.flush()'s doc comment), but it was never
      // registered as a shutdown cleanup. A SIGINT/SIGTERM during the
      // foreground dashboard serve (the normal way this long-lived process
      // ends) abandoned any in-flight append and skipped the checkpoint
      // entirely. `flush()` documents itself as safe to call more than
      // once, so this is harmless alongside the explicit `flush()` calls on
      // the normal-completion exit paths below.
      const flushAuditLogOnShutdown = wrapAuditLog;
      unregisterWrapAuditFlush = registerProcessShutdownCleanup(async () => {
        try {
          await flushAuditLogOnShutdown.flush();
        } catch {
          /* best-effort: a shutdown cleanup must not throw out of the signal handler */
        }
      });
      await bestEffortRecordWrapWorkloadRegistration({
        auditLog: wrapAuditLog,
        storagePath,
        record: localAgentRecord,
      });

      // HIGH never-overclaim fix (honesty/dashboard-rollup seam #2): resolve the
      // pinned producer key over the SAME canonical storage path the wrap-auto
      // Castle Wall daemon publishes it to (`<storagePath>/policy/egress/
      // audit-producer.pub`, via loadFortressProducerKey) and feed it into the
      // snapshot server's sources. Without this the wrap-auto dashboard read the
      // wall posture on the bare channel basis, so on a key-bearing host a forged
      // marker-only audit entry would arm the hero shield green. With the key
      // present the reader re-verifies the producer signature and a forgery fails
      // closed to amber, identical to the DashboardApprovalChannel path. `absent`
      // (macOS / pre-provision) → honest channel basis; `unreadable` (a key is
      // expected but malformed/locked) → fail honestly to amber via
      // producerKeyExpectedButUnavailable, never the weaker channel basis.
      try {
        const { loadFortressProducerKey } = await import(
          "../castle-wall/runtime/producer-signature.js"
        );
        const { loadBrokerProducerKey } = await import(
          "../broker-mcp/producer-signature.js"
        );
        const { readEnforcementAvailabilityStatus } = await import(
          "../castle-wall/runtime/enforcement-availability-status.js"
        );
        const producerKeyLoad = await loadFortressProducerKey(storagePath);
        const brokerProducerKeyLoad = await loadBrokerProducerKey(storagePath);
        dashboard.updateSources?.({
          resolvePinnedProducerKey: () =>
            producerKeyLoad.status === "present"
              ? producerKeyLoad.keyB64url
              : null,
          ...(producerKeyLoad.status === "unreadable"
            ? { producerKeyExpectedButUnavailable: true }
            : {}),
          resolveBrokerPinnedProducerKey: () =>
            brokerProducerKeyLoad.status === "present"
              ? brokerProducerKeyLoad.keyB64url
              : null,
          ...(brokerProducerKeyLoad.status === "unreadable"
            ? { brokerProducerKeyExpectedButUnavailable: true }
            : {}),
          resolveProtectionClaimSubject: () =>
            resolveProtectionSubjectFromFortressPath(
              storagePath,
              fortressIdFromStoragePath(storagePath),
            ).then((result) => result.subject),
          resolveEnforcementAvailabilityStatus: () =>
            readEnforcementAvailabilityStatus(storagePath),
        });
      } catch {
        // Never let the producer-key probe fail wrap. On any unexpected throw the
        // snapshot server keeps its honest default (no producer key → channel
        // basis); it never silently arms green on a forged entry because the
        // aggregator's wall reader treats absent-key as the channel floor.
      }
      // Best-effort: a Castle Wall daemon startup failure (e.g. EACCES on
      // Linux when the fortress-scoped socket dir requires root, or any
      // platform where the pinned key is unavailable) does not fail wrap.
      // The agent harness still gets wrapped; the IPC daemon will surface
      // its absence at handshake time. This mirrors the surrounding
      // best-effort discipline for v1.1 dashboard wiring.
      try {
        await startCastleWallForWrap(wrapAuditLog, derived.key);
      } catch (err) {
        warnCastleWallDaemonNotStarted(err);
      }

      // PR-2: setup opt-in for transparency anchoring (default OFF).
      // NOT best-effort: if this throws, the outer catch prints the
      // error and the loud check below exits 2 rather than letting a
      // requested opt-in be silently dropped.
      await enableAnchorTransparencyForWrap(v11Storage, derived.key, wrapAuditLog);

      // v1.2.1 (Finding NNN): auto-create default identity at wrap time.
      try {
        const { IdentityManager } = await import("../cognitive/tools.js");
        const { createIdentity } = await import("../core/identity.js");
        const { derivePurposeKey } = await import("../core/key-derivation.js");
        const identityMgr = new IdentityManager(v11Storage, derived.key);
        const loadResult = await identityMgr.load();
        if (loadResult.loaded === 0) {
          const identityEncKey = derivePurposeKey(derived.key, "identity-encryption");
          const { storedIdentity, publicIdentity } = createIdentity(
            "default",
            identityEncKey,
            "passphrase",
          );
          await identityMgr.save(storedIdentity);
          await wrapAuditLog.append("l1", "identity_create", publicIdentity.identity_id, {
            label: "default",
            source: "wrap-auto",
          });
        }
        dashboard.updateSources?.({
          auditLog: wrapAuditLog,
          identityManager: identityMgr,
        });
      } catch (err) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Note: default identity not created at wrap time ` +
            `(${(err as Error).message}).`,
        );
      }

      // WP-V1.2-5: construct + load the Intelligence Substrate Selector
      // against the wrap-auto fortress. The selector reads / writes its
      // config under the fortress storage namespace `_intelligence`,
      // encrypted with the same master key the wrap path just derived.
      let wrapIntelligenceSelector: SubstrateSelector | undefined;
      try {
        wrapIntelligenceSelector = new SubstrateSelector({
          storage: v11Storage,
          masterKey: derived.key,
          auditLog: wrapAuditLog,
          identityId: `fortress:${storagePath}`,
        });
        await wrapIntelligenceSelector.load();
        // Rho-2.5 (HIGH privacy-leak fix): the wrap-auto dashboard mounts
        // the /api/query-anonymity/pii route and serves concierge over the
        // frontier substrate. Without this install the selector kept the
        // passthrough IDENTITY_REDACTOR, so an operator who opted into
        // Tier B here egressed query + context UNSCRUBBED. Route through
        // THE shared chokepoint with the SAME hashed fortressId that the
        // buildV11Bindings call below uses, so the route's PATCH and the
        // live scrub read the same encrypted config.
        wrapTierBPiiRedactorInstalled = installConsentGatedRedactor({
          selector: wrapIntelligenceSelector,
          storage: v11Storage,
          masterKey: derived.key,
          fortressId: fortressIdFromStoragePath(storagePath),
        });
        intelligenceHealthy = true;
      } catch (err) {
        intelligenceHealthy = false;
        intelligenceError = (err as Error).message;
        // wrapTierBPiiRedactorInstalled stays false (its initialized value):
        // the install assignment above only completes when no throw occurred.
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Note: Intelligence panel unavailable on wrap URL ` +
            `(${(err as Error).message}).`,
        );
        wrapIntelligenceSelector = undefined;
      }
      dashboard.setV11Bindings(
        buildV11Bindings({
          identityId: `fortress:${storagePath}`,
          fortressId: fortressIdFromStoragePath(storagePath),
          auditLog: wrapAuditLog,
          // v1.1.5 (Finding Z): rehydrate from the file the upsert
          // above just wrote, so the registry the wrap-auto dashboard
          // serves contains this wrap plus any prior wraps against the
          // same fortress.
          storagePath,
          ...(wrapIntelligenceSelector
            ? { intelligenceSelector: wrapIntelligenceSelector }
            : {}),
          // WP-V1.2-4: forward the wrap-auto fortress's storage + master
          // key so buildV11Bindings constructs the operator chat service.
          // The wrap-emitted dashboard URL surfaces concierge + direct-
          // agent chat from first launch.
          storage: v11Storage,
          masterKey: derived.key,
          // Rho-2.5: the consent-gated redactor is installed on the
          // wrap-auto selector, so report the truthful effective state.
          tierBPiiRedactorInstalled: wrapTierBPiiRedactorInstalled,
        }),
      );
      // The wrap-auto dashboard always binds 127.0.0.1. The printed URL
      // carries only a short-lived session; loopback auto-auth keeps the
      // v1.1 client one-click without putting the bearer token in a URL.
      dashboard.setV11LoopbackAutoAuth(true);
    } catch (err) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `  Note: v1.1 dashboard surfaces unavailable on wrap URL ` +
          `(${(err as Error).message}). ` +
          `Run \`sanctuary dashboard\` to reach them.`,
      );
    }
  }

  failIfAnchorOptInDropped();

  // Auto-provision Step 2 (Build 1): see the matching call + comment in the
  // --no-dashboard branch above. Runs after the cooperative wrap (config +
  // identity + dashboard) has fully completed; never reverts it.
  const autoProvisionRun = await maybeRunAutoProvisionForWrap(
    agentConfig,
    options,
    deps,
    stopTransientCastleWallDaemonForAutoProvision,
  );
  const autoProvisionSummary = autoProvisionRun.summary;
  renderAutoProvisionOutcome(autoProvisionSummary);
  await exitAfterDeferredAutoProvisionSignal(autoProvisionRun.deferredSignal);
  bestEffortUpsertLocalAgentProtectionSubject({
    storagePath,
    record: localAgentRecord,
    autoProvisionSummary,
  });

  // FIX (N1-2, 2026-07-26; REVERTED 2026-07-27 harden-loop): a prior version
  // of this fix exited the process whenever `declined-by-operator` was the
  // outcome, on the premise that falling through to the foreground
  // dashboard serve "holds the event loop open forever". That premise does
  // not hold for this outcome kind: `declined-by-operator` is returned by
  // the provision orchestrator ONLY when `ctx.isTty === true` (a
  // non-interactive run returns the distinct `skipped-non-tty-cooperative-
  // only` kind instead, via an earlier check in that same function) --
  // i.e. this is always a real interactive operator at a terminal, for whom
  // holding the dashboard open until they stop it is the entire point of
  // `sanctuary protect`, identical to the accepted-arm path just below.
  // Exiting here regressed the default interactive case: a bare Enter at
  // the step-2 confirm (the DEFAULT-N prompt) or the explicit, common
  // `--no-provision-agent-account` flag both terminated the whole wrap
  // instead of continuing to serve the dashboard, and skipped
  // `resolveWrapProtectionClaim` / `printWrapSuccess` entirely -- dropping
  // the honest protection-state claim, the dashboard URL, and the
  // passphrase location precisely on the un-armed path where the operator
  // most needs them. The actual automation blocker this was meant to fix
  // (a `kill` not terminating the process) is the SIGINT/SIGTERM fix above
  // (`handleProcessShutdownSignal` now calls `process.exit` after cleanups,
  // and the Castle Wall daemon started above is already registered via
  // `registerProcessShutdownCleanup`, so it is torn down on that path
  // without any special-casing here). Decline is informational only
  // (`renderAutoProvisionOutcome` above already printed it) and the flow
  // continues exactly like every other non-arming outcome, matching the
  // `--no-dashboard` branch's sibling handling of the same outcome kind.

  const dashboardUrl = dashboard.createSessionUrl?.() ?? dashboard.url;

  // Publish runtime state so `sanctuary agents` + the multi-agent
  // dashboard aggregator can find this tenant's actual port. Best-effort:
  // write failures must not block wrap, and we clean up on shutdown.
  const webhookCallbackPortRaw = process.env.SANCTUARY_WEBHOOK_CALLBACK_PORT;
  const webhookCallbackPort = webhookCallbackPortRaw
    ? parseInt(webhookCallbackPortRaw, 10)
    : undefined;
  await writeTenantRuntime(storagePath, {
    version: readPackageVersion(),
    pid: process.pid,
    started_at: new Date().toISOString(),
    dashboard_host: dashboard.host,
    dashboard_port: dashboard.port,
    ...(webhookCallbackPort !== undefined &&
    !Number.isNaN(webhookCallbackPort)
      ? {
          webhook_callback_port: webhookCallbackPort,
          webhook_callback_host:
            process.env.SANCTUARY_WEBHOOK_CALLBACK_HOST ?? "127.0.0.1",
        }
      : {}),
    mode: "wrap",
  });
  const cleanupRuntime = async () => {
    try {
      await clearTenantRuntime(storagePath);
    } catch {
      /* best-effort: a shutdown cleanup must not throw out of the signal handler */
    }
  };
  registerProcessShutdownCleanup(cleanupRuntime);

  // Auto-open in browser.
  const toolName = toolNameFor(agentConfig.platform, agentConfig.servers);
  if (!options.noOpen) {
    try {
      const opener = deps.openBrowser ?? defaultOpenBrowser;
      await opener(dashboardUrl);
    } catch {
      /* best-effort - user can still copy the URL */
    }
  }

  if (wrapAuditLog) {
    await wrapAuditLog.flush();
    unregisterWrapAuditFlush?.();
  }

  const castleWallProtectionClaim = await resolveWrapProtectionClaim({
    auditLog: wrapAuditLog,
    auditStorage: wrapAuditStorage,
    masterKey: wrapAuditMasterKey,
    autoProvisionSummary,
    castleWallDaemonLivenessSince,
    storagePath,
  });

  printWrapSuccess({
    toolName,
    version: readPackageVersion(),
    toolCount: countUpstreamTools(upstreamServers),
    serverCount: upstreamServers.length,
    platform: agentConfig.platform,
    dashboardUrl,
    browserOpened: !options.noOpen,
    passphraseLocation,
    passphraseSource,
    intelligenceHealthy,
    intelligenceError,
    castleWallProtectionClaim,
    // 2026-07-02 hardening: the dead-pin warning must survive to the
    // terminal-final success surface, not only the mid-flow warning.
    pinnedVersionResolvability: pinResolvability,
  });
}

// ── Dashboard: port fallback ────────────────────────────────────────

export async function startDashboardWithFallback(
  startFn: DashboardStarter,
  preferredPort: number,
  authToken: string,
  serverVersion: string
): Promise<DashboardHandle> {
  let lastErr: unknown;
  for (let i = 0; i < PORT_FALLBACK_ATTEMPTS; i++) {
    const port = preferredPort + i;
    try {
      const handle = await startFn({
        port,
        mode: "co-located",
        authToken,
        serverVersion,
      });
      if (port !== preferredPort) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Port ${preferredPort} was unavailable. Dashboard bound to ${port}.`
        );
      }
      return handle;
    } catch (err) {
      lastErr = err;
      if (!isAddressInUse(err)) throw err;
    }
  }
  const lastPort = preferredPort + PORT_FALLBACK_ATTEMPTS - 1;
  throw new Error(
    `No free dashboard port in the range ${preferredPort}-${lastPort} (all ${PORT_FALLBACK_ATTEMPTS} tried): ${
      (lastErr as Error)?.message ?? "unknown"
    }. Stop the other Sanctuary instance, or choose a port with: sanctuary wrap <your-flags> --port <port>.`
  );
}

function isAddressInUse(err: unknown): boolean {
  if (!err || typeof err !== "object") return false;
  const code = (err as { code?: string }).code;
  return code === "EADDRINUSE";
}

// ── Browser auto-open ───────────────────────────────────────────────

async function defaultOpenBrowser(url: string): Promise<void> {
  const plat = platform();
  let cmd: string;
  let args: string[];
  if (plat === "darwin") {
    cmd = "open";
    args = [url];
  } else if (plat === "win32") {
    cmd = "cmd";
    args = ["/c", "start", "", url];
  } else {
    cmd = "xdg-open";
    args = [url];
  }
  await new Promise<void>((resolve) => {
    const child = spawn(cmd, args, { stdio: "ignore", detached: true });
    child.on("error", () => resolve());
    child.on("spawn", () => {
      child.unref();
      resolve();
    });
  });
}

// ── Success output ──────────────────────────────────────────────────

interface WrapSuccessInfo {
  toolName: string;
  version: string;
  toolCount: number;
  serverCount: number;
  /**
   * Wrap platform, used for platform-specific banner copy (F7: on Hermes with
   * an empty legacy JSON surface, the upstream-count line would read
   * "0 tools registered across 0 upstream servers" and appear to contradict
   * the authoritative config.yaml routing message).
   */
  platform?: AgentPlatform;
  dashboardUrl: string;
  browserOpened: boolean;
  passphraseLocation: string;
  passphraseSource: string;
  intelligenceHealthy?: boolean;
  intelligenceError?: string;
  castleWallProtectionClaim: ProtectionStateClaim;
  /**
   * Wrap-time registry probe outcome for the version-pinned MCP entry
   * (2026-07-02 hardening). "unpublished" renders a loud warning INSIDE the
   * final banner (the entry cannot start until the version is published);
   * "unreachable" renders an honest could-not-verify note. `undefined`
   * means the probe did not run (`--dev-dist` local-build entries involve
   * no registry) and, conservatively, "resolvable"/"skipped" add no noise.
   * The mid-flow warning alone is NOT enough: it scrolls far above the
   * banner, and the banner is the success claim the operator acts on.
   */
  pinnedVersionResolvability?: PinnedVersionResolvability;
}

export function formatWrapSuccess(info: WrapSuccessInfo): string {
  const g = (s: string) => `\x1b[32m${s}\x1b[0m`; // green
  const d = (s: string) => `\x1b[2m${s}\x1b[0m`;  // dim
  const b = (s: string) => `\x1b[1m${s}\x1b[0m`;  // bold
  const check = "\u2713";

  const lines: string[] = [];
  lines.push("");
  lines.push(
    `  ${g(check)} Wrapped ${b(info.toolName)} with Sanctuary v${info.version}`
  );
  lines.push(`  ${g(check)} ${renderUpstreamCountLine(info)}`);
  lines.push(
    `  ${g(check)} Sovereignty Dashboard running at ${b(info.dashboardUrl)}`
  );
  if (info.browserOpened) {
    lines.push(`  ${g(check)} Opened in your browser`);
  } else {
    lines.push(`  ${d("(browser auto-open suppressed)")}`);
  }
  lines.push("");
  // Named enforcement layers (L1-L4 numbering retired 2026-05-24). Mapping
  // matches the Castle Architecture surface in server/README.md and the
  // sovereignty manifesto: Castle Wall (OS-level egress), Sentinels (internal
  // observation / intelligence \u2014 the TEE/intelligence-dependent slot), Charter
  // (Cooperative MCP), Heralds (receipts + cross-castle reputation).
  const sentinelsStatus = info.intelligenceHealthy === false
    ? "Sentinels Degraded (intelligence disabled)"
    : "Sentinels Degraded (no TEE)";
  const protection = protectionStateAdvice(info.castleWallProtectionClaim);
  // Honesty (Finding 3, 2026-06-25): Charter and Heralds are "ready" after a
  // wrap, not "Full". "Full" is a superlative reserved for observed/verified
  // state (as Castle Wall and Sentinels already are); printing "Charter Full /
  // Heralds Full" unconditionally (even under --no-dashboard, even when nothing
  // was exercised) was the same overclaim the load-bearing-layer fix removed.
  lines.push(
    `  ${b(protection.operatorSentence)} ${protection.castleWallLabel} / ${sentinelsStatus} / Charter: ready / Heralds: ready.`,
  );
  if (protection.imperative !== null) {
    lines.push(`  ${protection.imperative}`);
  }
  if (info.intelligenceHealthy === false && info.intelligenceError) {
    const w = (s: string) => `\x1b[33m${s}\x1b[0m`; // yellow
    lines.push("");
    lines.push(`  ${w("\u26A0")} Sentinels intelligence disabled: ${info.intelligenceError}`);
    lines.push(`    Concierge chat and substrate-driven explanations will not work until this is resolved.`);
    lines.push(`    Run 'sanctuary intelligence diagnose' to inspect substrate config.`);
  }
  lines.push(...renderPinResolvabilityBannerLines(info));
  lines.push("");
  return lines.join("\n");
}

/**
 * Banner lines for the pinned-MCP-entry resolvability outcome, shared by
 * both success surfaces (2026-07-02 hardening). An "unpublished" pin means
 * the MCP entry this wrap just wrote CANNOT start \u2014 saying so only in a
 * mid-flow warning that scrolls above the banner left the terminal-final
 * success surface byte-identical to a working wrap (the dead-entry-behind-
 * a-success-banner defect the probe exists to close). "unreachable" gets
 * the honest could-not-verify note; "resolvable"/"skipped"/absent add
 * nothing.
 */
function renderPinResolvabilityBannerLines(info: {
  version: string;
  pinnedVersionResolvability?: PinnedVersionResolvability;
}): string[] {
  const w = (s: string) => `\x1b[33m${s}\x1b[0m`; // yellow
  const d = (s: string) => `\x1b[2m${s}\x1b[0m`; // dim
  if (info.pinnedVersionResolvability === "unpublished") {
    return [
      "",
      `  ${w("\u26A0")} The MCP entry this wrap wrote is pinned to ` +
        `@sanctuary-framework/mcp-server@${info.version},`,
      `    which is not on the npm registry (as resolved from this directory): unless`,
      `    your agent's project config routes the scope to another registry, it cannot`,
      `    start until that version is published. For an unpublished build, re-run`,
      `    with --dev-dist <path-to-dist/cli.js> to point the entry at your local build.`,
    ];
  }
  if (info.pinnedVersionResolvability === "unreachable") {
    // "unreachable" also covers a REACHED custom registry whose 404 the
    // unauthenticated probe declines to trust, so the cause line says
    // "could not confirm", never "could not be reached".
    return [
      "",
      `  ${d(
        `Note: the npm registry could not confirm the pinned MCP entry (v${info.version})`,
      )}`,
      `  ${d(
        "resolves (unreachable, or a custom registry this probe cannot verify against),",
      )}`,
      `  ${d(
        "so this wrap could not verify it. If the agent fails to start, re-run",
      )}`,
      `  ${d("'sanctuary protect' once the registry confirms the version.")}`,
    ];
  }
  return [];
}

/**
 * Render the upstream tools/servers count line. F7 (v1.6.1 first-run
 * honesty): on Hermes the counts derive from the legacy cli-config.json
 * surface Hermes does not consult for MCP routing, so a first run would
 * print "0 tools registered across 0 upstream servers" moments after the
 * (correct) message that config.yaml entries are preserved. When the
 * authoritative surface is the Hermes YAML and the legacy surface is empty,
 * say what actually happened instead.
 */
function renderUpstreamCountLine(info: {
  toolCount: number;
  serverCount: number;
  platform?: AgentPlatform;
}): string {
  if (info.platform === "hermes" && info.serverCount === 0) {
    return "Sanctuary MCP routing installed in Hermes config.yaml (existing entries preserved)";
  }
  return `${info.toolCount} tools registered across ${info.serverCount} upstream server${info.serverCount !== 1 ? "s" : ""}`;
}

function printWrapSuccess(info: WrapSuccessInfo): void {
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(formatWrapSuccess(info));
}

interface WrapSuccessNoDashboardInfo {
  toolName: string;
  version: string;
  toolCount: number;
  serverCount: number;
  /** See WrapSuccessInfo.platform; same platform-specific copy rules. */
  platform?: AgentPlatform;
  passphraseLocation: string;
  passphraseSource: string;
  intelligenceHealthy?: boolean;
  intelligenceError?: string;
  castleWallProtectionClaim: ProtectionStateClaim;
  /**
   * See WrapSuccessInfo.pinnedVersionResolvability; same banner-honesty
   * discipline (an unpublished pin must be visible on the terminal-final
   * success surface, not only in a mid-flow warning).
   */
  pinnedVersionResolvability?: PinnedVersionResolvability;
}

/**
 * Format the wrap-success output for the v1.1.5 `--no-dashboard` path
 * (Finding AA). Mirrors `formatWrapSuccess` but replaces the dashboard
 * URL line with a single-line note pointing operators at the persistent
 * dashboard pattern. Exposed for tests; production callers go through
 * `printWrapSuccessNoDashboard`.
 */
export function formatWrapSuccessNoDashboard(
  info: WrapSuccessNoDashboardInfo,
): string {
  const g = (s: string) => `\x1b[32m${s}\x1b[0m`;
  const d = (s: string) => `\x1b[2m${s}\x1b[0m`;
  const b = (s: string) => `\x1b[1m${s}\x1b[0m`;
  const check = "✓";

  const lines: string[] = [];
  lines.push("");
  lines.push(
    `  ${g(check)} Wrapped ${b(info.toolName)} with Sanctuary v${info.version}`,
  );
  lines.push(`  ${g(check)} ${renderUpstreamCountLine(info)}`);
  lines.push(
    `  ${d("Dashboard spawn skipped per --no-dashboard. Run `sanctuary dashboard` separately for a persistent dashboard.")}`,
  );
  lines.push("");
  // Named enforcement layers (L1-L4 numbering retired 2026-05-24). See the
  // mapping note in formatWrapSuccess above; both surfaces must agree.
  const sentinelsStatus = info.intelligenceHealthy === false
    ? "Sentinels Degraded (intelligence disabled)"
    : "Sentinels Degraded (no TEE)";
  const protection = protectionStateAdvice(info.castleWallProtectionClaim);
  lines.push(
    `  ${b(protection.operatorSentence)} ${protection.castleWallLabel} / ${sentinelsStatus} / Charter: ready / Heralds: ready.`,
  );
  if (protection.imperative !== null) {
    lines.push(`  ${protection.imperative}`);
  }
  if (info.intelligenceHealthy === false && info.intelligenceError) {
    const w = (s: string) => `\x1b[33m${s}\x1b[0m`;
    lines.push("");
    lines.push(`  ${w("\u26A0")} Sentinels intelligence disabled: ${info.intelligenceError}`);
    lines.push(`    Run 'sanctuary intelligence diagnose' to inspect substrate config.`);
  }
  lines.push(...renderPinResolvabilityBannerLines(info));
  lines.push("");
  return lines.join("\n");
}

function printWrapSuccessNoDashboard(
  info: WrapSuccessNoDashboardInfo,
): void {
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(formatWrapSuccessNoDashboard(info));
}

// ── Post-wrap verification ──────────────────────────────────────────

/**
 * Verify the rewritten primary config and roll it back on failure.
 * `restoredOnFailure` reports whether the internal rollback restore
 * succeeded (meaningful only when `verified` is false) so the caller's
 * orphan-wrap guard can detect a failed restore (2026-07-02 hardening;
 * previously the restore result was discarded here).
 */
async function verifyRewrittenConfig(
  configPath: string,
  backupPath: string
): Promise<{ verified: boolean; restoredOnFailure: boolean }> {
  try {
    const raw = await readFile(configPath, "utf-8");
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Verification FAILED: Rewritten config is not valid JSON.`);
      console.error(`  Error: ${(err as Error).message}`);
      return {
        verified: false,
        restoredOnFailure: await restoreFromBackup(configPath, backupPath),
      };
    }

    const servers =
      ((parsed.mcp as Record<string, unknown>)?.servers as Record<string, unknown>) ??
      (parsed.mcpServers as Record<string, unknown>) ??
      (parsed.mcp_servers as Record<string, unknown>) ??
      {};

    if (!servers.sanctuary) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Verification FAILED: No sanctuary entry in rewritten config.`);
      return {
        verified: false,
        restoredOnFailure: await restoreFromBackup(configPath, backupPath),
      };
    }

    const sanctuaryEntry = servers.sanctuary as Record<string, unknown>;
    if (!sanctuaryEntry.command || typeof sanctuaryEntry.command !== "string") {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Verification FAILED: Sanctuary entry has no command.`);
      return {
        verified: false,
        restoredOnFailure: await restoreFromBackup(configPath, backupPath),
      };
    }

    return { verified: true, restoredOnFailure: true };
  } catch (err) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`\n  Verification FAILED: ${(err as Error).message}`);
    return {
      verified: false,
      restoredOnFailure: await restoreFromBackup(configPath, backupPath),
    };
  }
}

/**
 * Restore `configPath` from `backupPath`, reporting failure to the operator
 * without throwing. Returns false when the restore FAILED (the live config
 * keeps its current, possibly-wrapped contents); callers that must not end
 * in a wrapped-with-no-meta orphan state (MED-1, the wrap-meta failure
 * rollback) branch on it. Other callers may ignore the result: the CRITICAL
 * manual-recovery message has already printed.
 */
async function restoreFromBackup(
  configPath: string,
  backupPath: string
): Promise<boolean> {
  try {
    await restoreConfig(backupPath, configPath);
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`  Original config restored from backup.`);
    console.error(`  Backup preserved at: ${backupPath}\n`);
    return true;
  } catch (restoreErr) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`  CRITICAL: Could not restore backup from ${backupPath}`);
    console.error(`  Error: ${(restoreErr as Error).message}`);
    console.error(`  Manual recovery: copy ${backupPath} to ${configPath}\n`);
    return false;
  }
}

// ── Unwrap ──────────────────────────────────────────────────────────

async function unwrap(dryRun: boolean): Promise<void> {
  // D4 P1-2: findLatestBackup validates wrap-meta `auxiliary` entries on
  // read and throws WrapMetaValidationError on a forged or corrupted list
  // (arbitrary backupPath/originalPath would turn the restore loop below
  // into an arbitrary-file write/delete primitive). Abort loudly with
  // nothing modified.
  let meta: Awaited<ReturnType<typeof findLatestBackup>>;
  try {
    meta = await findLatestBackup();
  } catch (err) {
    if (
      err instanceof WrapMetaValidationError ||
      err instanceof WrapMetaUnreadableError
    ) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Sanctuary: Unwrap REFUSED`);
      console.error(`  ${err.message}`);
      console.error(
        `  Nothing was modified. Inspect the wrap metadata in your fortress` +
          `\n  backup directory before retrying.\n`
      );
      process.exit(1);
    }
    throw err;
  }
  if (!meta) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error("No Sanctuary wrap found to restore.");
    console.error("Run `sanctuary wrap --openclaw` first.");
    process.exit(1);
  }

  try {
    await access(meta.backupPath);
  } catch {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`Backup file not found: ${meta.backupPath}`);
    // Multi-surface honesty on the REFUSAL path (matches the eighth-round
    // survivor note on the success path): findLatestBackup returns the
    // FIRST readable pointer, so a wedged first pointer (its backup file
    // pruned) blocks every later scoped slot - ending here silently would
    // hide any other surface that remains wrapped behind it. Enumerate the
    // other readable pointers and say what unblocks them. Advisory output
    // only; the refusal itself (exit 1, nothing modified) is unchanged.
    const resolvedWedged = resolvePath(meta.originalPath);
    const pointers = await listWrapMetaPointerSummaries();
    const wedgedPointer = pointers.find(
      (p) => resolvePath(p.originalPath) === resolvedWedged,
    );
    const survivors = Array.from(
      new Set(
        pointers
          .map((p) => resolvePath(p.originalPath))
          .filter((p) => p !== resolvedWedged),
      ),
    );
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  This wrap metadata pointer` +
        `${wedgedPointer ? ` (${wedgedPointer.metaPath})` : ""} names ` +
        `${meta.originalPath}\n  but its backup file is gone. Restore the ` +
        `backup file if you can; if it is gone\n  for good, remove the ` +
        `pointer file manually (the config it names stays wrapped\n  and ` +
        `must then be restored by hand).`
    );
    if (survivors.length > 0) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `  Note: ${
          survivors.length === 1
            ? "another wrapped surface remains"
            : "other wrapped surfaces remain"
        } behind this pointer:` +
          survivors.map((p) => `\n    ${p}`).join("") +
          `\n  Re-run 'sanctuary wrap --unwrap' after this pointer is ` +
          `repaired or removed\n  to restore ${
            survivors.length === 1 ? "it" : "them"
          }.`
      );
    }
    process.exit(1);
  }

  // D4 P1-2 (validate before use) + P2-3 (no symlinked restore targets):
  // re-validate every auxiliary entry and refuse symlinked targets BEFORE
  // any restore runs, so a forged or symlinked entry aborts the whole
  // unwrap with nothing modified - including the primary config. Round-2
  // P1-A: the lstat loop below is a courtesy early refusal; the atomic
  // enforcement is the O_NOFOLLOW open inside restoreConfig itself.
  let auxiliary: ValidatedWrapMetaAuxiliaryFile[] = [];
  try {
    auxiliary = await validateWrapMetaAuxiliary(meta.auxiliary);
    for (const aux of auxiliary) {
      await refuseSymlinkTarget(aux.originalPath, "Restore target");
    }
  } catch (err) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`\n  Sanctuary: Unwrap REFUSED`);
    console.error(`  ${(err as Error).message}`);
    console.error(`  Nothing was modified.\n`);
    process.exit(1);
  }

  // D4 P2-2: --unwrap --dry-run reports what WOULD be restored/removed
  // and writes nothing. All checks above are read-only, so the dry run
  // surfaces the same refusals the real unwrap would.
  if (dryRun) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`\n  Sanctuary: Unwrap (dry run)`);
    console.error(`  Would restore ${meta.originalPath} from ${meta.backupPath}`);
    for (const aux of auxiliary) {
      if (aux.backupPath) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`  Would restore ${aux.originalPath} from ${aux.backupPath}`);
      } else if (aux.alreadyAbsent) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Would skip ${aux.originalPath} (created by wrap; already absent)`
        );
      } else {
        // Fifth round (preview parity): the real unwrap snapshots this
        // file's final contents into a timestamped backup BEFORE removing
        // it (the recovery breadcrumb below); a dry run that omitted the
        // snapshot read scarier than reality for an operator judging
        // whether post-wrap edits would be lost.
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Would remove ${aux.originalPath} (created by wrap; no pre-wrap version existed;` +
            `\n  its final contents would first be preserved as a timestamped backup)`
        );
      }
    }
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`\n  Dry run. No changes made.\n`);
    return;
  }

  await restoreConfig(meta.backupPath, meta.originalPath);
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(`\n  Sanctuary: Unwrapped`);
  console.error(`  Original config restored to: ${meta.originalPath}`);
  console.error(`  Backup preserved at: ${meta.backupPath}`);
  // Harden round (operator breadcrumb): the restored snapshot is the FIRST
  // pre-wrap backup (F6 pristine-pointer preservation); config edits made
  // while wrapped survive only in the newer timestamped backups that
  // nothing points at. Say where they are so the discard is recoverable.
  const newerPrimaryBackup = await findNewerBackup(
    meta.backupPath,
    meta.originalPath,
  );
  if (newerPrimaryBackup) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  Note: this restored the pristine pre-wrap snapshot. Newer backups exist;` +
        `\n  config changes made while wrapped may be recoverable from: ${newerPrimaryBackup}`
    );
  }

  // D4 staging, Bug 2: restore auxiliary files the wrap touched (the
  // Hermes config.yaml surface). A null backupPath means wrap created the
  // file fresh; restoring the pre-wrap state removes it. Best-effort: the
  // primary config restore above already succeeded, so an auxiliary
  // failure reports loudly with the manual recovery path instead of
  // aborting the unwrap. Failures are counted: the wrap-meta retirement
  // below is gated on ALL restores having succeeded.
  let auxiliaryRestoreFailures = 0;
  for (const aux of auxiliary) {
    try {
      if (aux.backupPath) {
        // Round-2 P1-A/P2: restoreConfig writes the target O_NOFOLLOW
        // (atomic symlink refusal) and recreates a missing parent (0o700).
        await restoreConfig(aux.backupPath, aux.originalPath);
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`  Original config restored to: ${aux.originalPath}`);
        console.error(`  Backup preserved at: ${aux.backupPath}`);
        const newerAuxBackup = await findNewerBackup(
          aux.backupPath,
          aux.originalPath,
        );
        if (newerAuxBackup) {
          // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
          console.error(
            `  Note: newer backups of this file exist; changes made while wrapped` +
              `\n  may be recoverable from: ${newerAuxBackup}`
          );
        }
      } else if (aux.alreadyAbsent) {
        // Round-2 P2: created-by-wrap file whose parent directory is gone -
        // the "absent" end-state already holds; informational no-op.
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Skipped ${aux.originalPath} (created by wrap; already absent)`
        );
      } else {
        // 2026-07-02 hardening (recovery breadcrumb): a created-by-wrap file
        // (e.g. the Hermes config.yaml) is removed wholesale here, but the
        // operator may have added their own MCP entries to it AFTER the
        // wrap. Preserve the file's final contents as a timestamped backup
        // before removing it and say where it is. Best-effort: a failed
        // pre-removal snapshot warns but does not change the restore
        // semantics (the file is still removed, exactly as before).
        let preRemovalBackup: string | null = null;
        try {
          preRemovalBackup = await backupConfig(aux.originalPath);
        } catch (err) {
          // ENOENT is silent: the file is already gone (see the removal
          // carve-out below), so there is nothing to snapshot and a WARNING
          // would misread as a real failure.
          if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
            // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
            console.error(
              `  WARNING: could not snapshot ${aux.originalPath} before removal: ` +
                `${(err as Error).message}`
            );
          }
        }
        // Round-3 P1-A: refuse the unlink if a symlink was raced into the
        // parent dir after validate-time; unlink() does not follow a
        // symlinked leaf, so only the parent walk is needed.
        //
        // 2026-07-02 hardening (second round): ENOENT means the delete-on-
        // unwrap end-state ALREADY holds - mirror the rollbackWrapSurfaces
        // carve-out instead of counting it as an auxiliaryRestoreFailure.
        // The orphan-wrap guard can persist a null-backup entry for a file
        // the failed wrap never created (or that its rollback already
        // removed) while the parent dir still exists (so validate-time
        // `alreadyAbsent` does not fire); treating that phantom file as a
        // restore failure kept the wrap-meta alive forever and wedged every
        // --unwrap re-run on a cause that is a nonexistent file.
        let removed = true;
        try {
          await unlinkSafeUnderRoot(aux.originalPath);
        } catch (err) {
          const code =
            err && typeof err === "object" && "code" in err
              ? (err as NodeJS.ErrnoException).code
              : undefined;
          if (code !== "ENOENT") throw err;
          removed = false;
        }
        if (removed) {
          // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
          console.error(
            `  Removed ${aux.originalPath} (created by wrap; no pre-wrap version existed)`
          );
          if (preRemovalBackup) {
            // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
            console.error(
              `  Its final contents were preserved at: ${preRemovalBackup}` +
                `\n  (in case you added entries to it after the wrap).`
            );
          }
        } else {
          // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
          console.error(
            `  Skipped ${aux.originalPath} (created by wrap; already absent)`
          );
        }
      }
    } catch (err) {
      auxiliaryRestoreFailures += 1;
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `  WARNING: could not restore ${aux.originalPath}: ${(err as Error).message}`
      );
      if (aux.backupPath) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Manual recovery: copy ${aux.backupPath} to ${aux.originalPath}`
        );
      }
    }
  }

  // F6 (v1.6.1 wrap safety): a COMPLETED unwrap retires the wrap-meta
  // pointer files, so "a wrap-meta exists" means "currently wrapped" and a
  // FUTURE wrap records a fresh pristine backup instead of preserving a
  // stale pointer (see saveWrapMeta). The backup files themselves stay.
  //
  // Harden round: retirement is gated on every auxiliary restore having
  // succeeded. Removing the meta after a partial restore stranded the CLI
  // retry path: a re-run of --unwrap reported "No Sanctuary wrap found"
  // while e.g. the Hermes config.yaml still routed traffic through
  // Sanctuary, and a subsequent wrap recorded that still-wrapped file as
  // the new "pristine" backup. Keeping the meta keeps --unwrap re-runnable.
  // The retirement is also scoped to the originalPath just restored, so a
  // legacy meta naming a DIFFERENT wrapped surface keeps its pointer.
  if (auxiliaryRestoreFailures > 0) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  WARNING: ${auxiliaryRestoreFailures} auxiliary ` +
        `${auxiliaryRestoreFailures === 1 ? "restore" : "restores"} failed; ` +
        `keeping the wrap metadata so 'sanctuary wrap --unwrap' can be ` +
        `re-run after fixing the cause above.`
    );
  } else {
    // 2026-07-02 hardening (honest failure surface): removeWrapMeta can now
    // THROW - its wrap-meta lock acquisition is bounded + fail-closed (the
    // 15s timeout while another sanctuary wrap/unwrap holds the lock, and
    // the displaced-holder mutation guard). Uncaught, that throw fell
    // through runWrap to the CLI's top-level catch, which printed
    // "Sanctuary MCP Server failed to start:" plus a raw error AFTER the
    // "Sanctuary: Unwrapped" success lines - a server-boot banner for a
    // wrap subcommand whose restore had already succeeded. State is safe
    // either way (config restored, meta retained, a re-run recovers), so
    // report the failure in the retirement-warning voice with re-run
    // advice and exit non-zero without the misleading banner.
    let metaRemovalFailures: WrapMetaRemovalFailure[];
    try {
      metaRemovalFailures = await removeWrapMeta(meta.originalPath);
    } catch (err) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `  WARNING: could not retire the wrap metadata: ${(err as Error).message}`
      );
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `  The restore above succeeded; the wrap metadata was left in place` +
          `\n  so 'sanctuary wrap --unwrap' can be re-run to retire it once no` +
          `\n  other sanctuary wrap/unwrap is running.`
      );
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error("");
      process.exitCode = 1;
      return;
    }
    for (const failure of metaRemovalFailures) {
      // The advice must match the failure class: an UNREADABLE pointer may
      // be a DIFFERENT wrapped surface's only restore pointer (a successful
      // read would have skipped it), so telling the operator to delete it
      // could orphan that surface's pristine backup.
      if (failure.reason === "unreadable") {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  WARNING: could not read wrap metadata ${failure.path}; it was ` +
            `left in place because it may be another wrapped surface's only ` +
            `restore pointer. Do NOT delete it; fix the read failure (for ` +
            `example file permissions) and re-run 'sanctuary wrap --unwrap' ` +
            `if a surface remains wrapped.`
        );
      } else {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  WARNING: could not remove wrap metadata ${failure.path}; a ` +
            `future re-wrap may preserve a stale restore pointer. Remove it ` +
            `manually.`
        );
      }
    }
    // Eighth round (multi-surface honesty): surface-scoped meta slots mean
    // OTHER surfaces wrapped on this tenant keep their own live pointers,
    // and this run restored exactly ONE surface. Ending on an unqualified
    // "Unwrapped" while e.g. ~/.claude/settings.json still routes traffic
    // through Sanctuary is the same dead-entry-behind-a-success-banner
    // class the wrap banner fix closed, so enumerate the survivors and say
    // so. Scoped to the clean-retirement path: the failure branches above
    // already print their own re-run guidance, and a surviving pointer for
    // THIS surface (unreadable/unremovable) would otherwise misread here as
    // "another wrapped surface".
    if (metaRemovalFailures.length === 0) {
      try {
        const remaining = await findLatestBackup();
        if (remaining) {
          // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
          console.error(
            `  Note: another wrapped surface remains (${remaining.originalPath}).` +
              `\n  Re-run 'sanctuary wrap --unwrap' to restore it.`
          );
        }
      } catch {
        // A surviving pointer exists but failed validation on read; a
        // re-run surfaces the precise refusal with nothing modified.
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Note: wrap metadata for another surface remains but could not ` +
            `be validated. Re-run 'sanctuary wrap --unwrap' to inspect it.`
        );
      }
    }
  }
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error("");
}

// ── Helpers ─────────────────────────────────────────────────────────

/**
 * Operator-facing warning when the Castle Wall enforcement daemon fails to
 * start during `wrap`. Wrap is best-effort with respect to the daemon (a start
 * failure never blocks wrapping the agent), but a silent "Note:" let an
 * upgrade quietly leave a previously-armed host UNARMED. This makes the
 * not-armed state loud, and - on macOS, when the failure is the A2/B2
 * helper-signing default having no reachable signer - prints the exact
 * migration path (install the helper + point at the shim, or opt back into the
 * legacy local-signing key). See the A2/B2 re-drill verdict's migration caveat.
 */
function warnCastleWallDaemonNotStarted(err: unknown): void {
  const message = err instanceof Error ? err.message : String(err);
  const helperMigration =
    process.platform === "darwin" &&
    /helper signing is unavailable|signer helper is unreachable|without a signer/i.test(
      message,
    );
  const lines = [
    "",
    "  ====================================================================",
    "  WARNING: Castle Wall is NOT armed. Your agent is wrapped, but the",
    "  enforcement wall did not start, so outbound traffic is NOT filtered.",
    `  Reason: ${message}`,
  ];
  if (helperMigration) {
    lines.push(
      "",
      "  Castle Wall now signs through a root helper by default (A2/B2). To",
      "  start the userspace daemon, do ONE of:",
      '    1. Install the Castle Wall app (one-time "Allow background item"',
      "       approval), then set SANCTUARY_CASTLE_SIGNER_CLIENT to its shim:",
      "       /Applications/Sanctuary-CastleWall.app/Contents/MacOS/castle-wall-signer-client",
      "    2. To keep the legacy local-signing key, set SANCTUARY_CASTLE_LOCAL_SIGN=1",
      "  then re-run 'sanctuary wrap'.",
      "",
      "  NOTE: either option only starts the userspace daemon; that alone does",
      "  NOT mean traffic is being filtered. Enforcement also needs the approved",
      "  system extension, and is confirmed only by observed flow evidence on",
      "  the dashboard's Castle Wall panel.",
    );
  } else {
    lines.push(
      "  Wrap continues; the IPC daemon will surface its absence at handshake.",
    );
  }
  lines.push(
    "  ====================================================================",
    "",
  );
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(lines.join("\n"));
}

function convertToUpstreamServers(
  servers: MCPServerEntry[]
): UpstreamServer[] {
  return servers.map((server) => ({
    name: server.name,
    transport:
      server.transport === "sse"
        ? { type: "sse" as const, url: server.url! }
        : {
            type: "stdio" as const,
            command: server.command!,
            ...(server.args ? { args: server.args } : {}),
            ...(server.env ? { env: server.env } : {}),
          },
    enabled: true,
    default_tier: 2,
  }));
}

function createWrapProfile(upstream: UpstreamServer[]): SovereigntyProfile {
  return {
    version: 1,
    features: {
      audit_logging: { enabled: true },
      injection_detection: { enabled: true },
      context_gating: { enabled: false },
      approval_gate: { enabled: true },
      zk_proofs: { enabled: false },
    },
    upstream_servers: upstream,
    updated_at: new Date().toISOString(),
  };
}

function generateAuthToken(): string {
  // 24 bytes → 32-char base64url - plenty of entropy for a single-use URL.
  return randomBytes(24)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function toolNameFor(platform: AgentPlatform, _servers: MCPServerEntry[]): string {
  switch (platform) {
    case "openclaw": return "OpenClaw";
    case "hermes": return "Hermes Agent";
    case "claude-code": return "Claude Code";
    case "cursor": return "Cursor";
    case "cline": return "Cline";
    case "mastra": return "Mastra";
    default: return "your agent";
  }
}

/**
 * Map the wrap-side `AgentPlatform` (kebab-cased, harness detection
 * vocabulary) to the v1.1 hub registry's `LocalHarnessKind` (snake-cased,
 * dashboard-render vocabulary). The two enums describe the same set of
 * supported wrap targets but live in different layers; centralizing the
 * mapping here means the hub layer doesn't import the wrap layer's enum
 * and vice versa.
 */
export function harnessKindForPlatform(platform: AgentPlatform): LocalHarnessKind {
  switch (platform) {
    case "openclaw": return "openclaw";
    case "hermes": return "hermes";
    case "claude-code": return "claude_code";
    case "cursor": return "cursor";
    case "cline": return "cline";
    case "mastra": return "mastra";
    case "generic": return "generic_mcp";
    default: {
      // Defensive: unknown future platforms map to "other" rather than
      // crashing wrap. Adding a new platform should land its
      // `LocalHarnessKind` mapping in the same PR.
      const _exhaustive: never = platform;
      void _exhaustive;
      return "other";
    }
  }
}

/**
 * Build the v1.1 hub `LocalAgentRecord` for a freshly wrapped harness.
 *
 * v1.1.5 placeholders (Finding Z): wrap does not yet detect the model
 * provider or bind a policy at wrap time, so `model_provider.vendor`
 * stays "unknown" and `policy_id` stays "unbound" until the v1.2
 * data-plane work lands real detection / Phase 2 binding. The capability
 * flags reflect what the dashboard controller honestly supports today:
 * `can_unwrap` remains the only harness mutation exposed, and
 * `can_change_template` is registry-local through the Tier 1 binding flow.
 */
function buildLocalAgentRecord(input: {
  storagePath: string;
  platform: AgentPlatform;
}): LocalAgentRecord {
  const harness = harnessKindForPlatform(input.platform);
  const fortressId = fortressIdFromStoragePath(input.storagePath);
  const nowIso = new Date().toISOString();
  return {
    version: "1.1",
    agent_id: `agent:${harness}:${fortressId}`,
    identity_id: `fortress:${input.storagePath}`,
    harness,
    model_provider: {
      vendor: "unknown",
      model_id: "unknown",
      runs_locally: false,
    },
    policy_id: "unbound",
    status: "active",
    budget_summary: {
      last_refreshed_at: nowIso,
    },
    last_activity_at: nowIso,
    wrapped_at: nowIso,
    capabilities: {
      can_pause: false,
      can_resume: false,
      can_restart: false,
      can_unwrap: true,
      can_lockdown: false,
      can_chat: false,
      can_change_template: true,
    },
  };
}

function withProtectionSubjectAlias(
  record: LocalAgentRecord,
  protectionSubject: string | null,
): LocalAgentRecord {
  return protectionSubject === null
    ? record
    : { ...record, protection_subject: protectionSubject };
}

function bestEffortUpsertLocalAgentProtectionSubject(input: {
  storagePath: string;
  record: LocalAgentRecord;
  autoProvisionSummary: AutoProvisionSummary;
}): void {
  const fortressId = fortressIdFromStoragePath(input.storagePath);
  const protectionSubject = protectionSubjectFromAutoProvisionSummary(
    input.autoProvisionSummary,
    fortressId,
  );
  if (protectionSubject === null) return;
  try {
    upsertPersistedLocalAgent(
      input.storagePath,
      withProtectionSubjectAlias(input.record, protectionSubject),
    );
  } catch (err) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  Note: hub agent protection subject not persisted ` +
        `(${(err as Error).message}). ` +
        `Recent macOS Castle Wall activity may not correlate to this agent until wrap is rerun.`,
    );
  }
}

async function recordWrapWorkloadRegistration(input: {
  auditLog: AuditLog;
  storagePath: string;
  record: LocalAgentRecord;
}): Promise<void> {
  const fortressId = fortressIdFromStoragePath(input.storagePath);
  await recordWrappedHarnessRegistration({
    auditLog: input.auditLog,
    fortressId,
    agentId: input.record.agent_id,
  });
}

async function bestEffortRecordWrapWorkloadRegistration(input: {
  auditLog: AuditLog;
  storagePath: string;
  record: LocalAgentRecord;
}): Promise<void> {
  try {
    await recordWrapWorkloadRegistration(input);
  } catch (err) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  Note: workload-lifecycle registration not recorded ` +
        `(${(err as Error).message}). ` +
        `Wrap is otherwise complete; re-run \`sanctuary wrap\` to retry after fixing the audit log.`,
    );
  }
}

function countUpstreamTools(servers: UpstreamServer[]): number {
  // Conservative estimate - real count requires live tool discovery.
  // At wrap time we do not have an MCP client connection yet, so we show
  // a "0+ tools" placeholder until the dashboard fills in live data.
  return servers.length === 0 ? 0 : servers.length;
}

function readPackageVersion(): string {
  return SANCTUARY_VERSION;
}

/**
 * Detects whether a parsed agent config already has a Sanctuary entry under
 * its platform-specific MCP servers key. extractServers filters Sanctuary
 * out of the upstream list (so we don't stack entries on rewrite), so the
 * filtered `agentConfig.servers` array can't be used to detect re-wrap;
 * we have to look at the raw config instead.
 */
function rawConfigContainsSanctuary(
  raw: unknown,
  agentPlatform: AgentPlatform
): boolean {
  if (!raw || typeof raw !== "object") return false;
  const obj = raw as Record<string, unknown>;
  let serversBag: Record<string, unknown> | undefined;
  if (agentPlatform === "openclaw") {
    const mcp = obj.mcp as Record<string, unknown> | undefined;
    serversBag =
      (mcp?.servers as Record<string, unknown> | undefined) ??
      (obj.mcpServers as Record<string, unknown> | undefined);
  } else if (agentPlatform === "hermes") {
    serversBag = obj.mcp_servers as Record<string, unknown> | undefined;
  } else {
    serversBag = obj.mcpServers as Record<string, unknown> | undefined;
  }
  if (!serversBag || typeof serversBag !== "object") return false;
  return Object.keys(serversBag).some(
    (name) => name.toLowerCase() === "sanctuary"
  );
}

// ── CLI argument parser ─────────────────────────────────────────────

/** Known flags that take a value argument (the next argv element). */
const WRAP_VALUE_FLAGS = new Set([
  "--wrap",
  "--passphrase",
  "--port",
  "--dashboard-port",
  "--fortress",
  "--dev-dist",
  "--write-passphrase-backup",
]);

/** Known boolean flags. */
const WRAP_BOOLEAN_FLAGS = new Set([
  "--openclaw",
  "--hermes",
  "--claude-code",
  "--cursor",
  "--cline",
  "--mastra",
  "--unwrap",
  "--dry-run",
  "--no-open",
  "--no-dashboard",
  "--allow-plaintext-remote",
  "--anchor-transparency",
  "--provision-agent-account",
  "--no-provision-agent-account",
  "--exclusive-egress",
  "--repair-egress-gate",
  "--unprotect-egress-gate",
  "--stand-down-agent",
  "--override-transient-pf-rules",
  "--help",
  "-h",
]);

/** Known harness flags (for "did you mean" suggestions). */
const WRAP_HARNESS_FLAGS = [
  "--openclaw",
  "--hermes",
  "--claude-code",
  "--cursor",
  "--cline",
  "--mastra",
];

function parseDashboardPortFlag(flag: string, value: string | undefined): number {
  if (value === undefined || value.startsWith("-")) {
    throw new Error(`${flag} requires a port value (1024-65535).`);
  }
  if (!/^\d+$/.test(value)) {
    throw new Error(`${flag} must be a positive integer from 1024 to 65535.`);
  }

  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) {
    throw new Error(`${flag} must be a positive integer from 1024 to 65535.`);
  }
  return port;
}

export function parseWrapArgs(argv: string[]): WrapOptions {
  const options: WrapOptions = {};

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;

    // Reject unknown positional arguments
    if (!arg.startsWith("-")) {
      const suggestion = WRAP_HARNESS_FLAGS.find(
        (f) => f.replace(/^--/, "") === arg,
      );
      const hint = suggestion ? ` Did you mean ${suggestion}?` : "";
      throw new Error(
        `Unrecognized argument '${arg}'.${hint} Run 'sanctuary wrap --help' for valid flags.`,
      );
    }

    // Reject unknown flags
    if (!WRAP_BOOLEAN_FLAGS.has(arg) && !WRAP_VALUE_FLAGS.has(arg)) {
      throw new Error(
        `Unrecognized flag '${arg}'. Run 'sanctuary wrap --help' for valid flags.`,
      );
    }

    switch (arg) {
      case "--wrap":
        options.wrap = argv[++i];
        break;
      case "--openclaw":
        options.openclaw = true;
        break;
      case "--hermes":
        options.hermes = true;
        break;
      case "--claude-code":
        options.claudeCode = true;
        break;
      case "--cursor":
        options.cursor = true;
        break;
      case "--cline":
        options.cline = true;
        break;
      case "--mastra":
        options.mastra = true;
        break;
      case "--unwrap":
        options.unwrap = true;
        break;
      case "--passphrase":
        options.passphrase = argv[++i];
        break;
      case "--port":
      case "--dashboard-port":
        options.port = parseDashboardPortFlag(arg, argv[++i]);
        break;
      case "--dry-run":
        options.dryRun = true;
        break;
      case "--no-open":
        options.noOpen = true;
        break;
      case "--no-dashboard":
        options.noDashboard = true;
        break;
      case "--allow-plaintext-remote":
        options.allowPlaintextRemote = true;
        break;
      case "--anchor-transparency":
        options.anchorTransparency = true;
        break;
      case "--provision-agent-account":
        options.provisionAgentAccount = true;
        break;
      case "--no-provision-agent-account":
        options.provisionAgentAccount = false;
        break;
      case "--exclusive-egress":
        options.exclusiveEgress = true;
        break;
      case "--repair-egress-gate":
        options.repairEgressGate = true;
        break;
      case "--unprotect-egress-gate":
        options.unprotectEgressGate = true;
        break;
      case "--stand-down-agent":
        options.standDownAgent = true;
        break;
      case "--override-transient-pf-rules":
        options.overrideTransientPfRules = true;
        break;
      case "--fortress":
        options.fortress = argv[++i];
        break;
      case "--dev-dist":
        options.devDist = argv[++i];
        break;
      case "--write-passphrase-backup":
        options.writePassphraseBackup = argv[++i];
        break;
      case "--help":
      case "-h":
        printWrapHelp();
        process.exit(0);
    }
  }

  if (
    options.standDownAgent === true &&
    options.repairEgressGate !== true &&
    options.unprotectEgressGate !== true
  ) {
    throw new Error(
      "--stand-down-agent is only valid with --repair-egress-gate or --unprotect-egress-gate.",
    );
  }

  return options;
}

function printWrapHelp(): void {
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.log(`
  sanctuary wrap. Wrap any agent in Sanctuary protection.

  Usage:
    sanctuary wrap --openclaw          Wrap OpenClaw
    sanctuary wrap --hermes            Wrap Hermes Agent (NousResearch)
    sanctuary wrap --claude-code       Wrap Claude Code
    sanctuary wrap --cursor            Wrap Cursor
    sanctuary wrap --cline             Wrap Cline (VS Code extension)
    sanctuary wrap --mastra            Wrap Mastra
    sanctuary wrap --wrap <path>       Wrap a specific MCP config file
    sanctuary wrap --unwrap            Restore original config

  Options:
    --openclaw         Auto-detect and wrap OpenClaw
    --hermes           Auto-detect and wrap Hermes Agent
    --claude-code      Auto-detect and wrap Claude Code
    --cursor           Auto-detect and wrap Cursor
    --cline            Auto-detect and wrap Cline (VS Code extension)
    --mastra           Auto-detect and wrap Mastra
    --wrap <path>      Wrap a specific MCP config file
    --unwrap           Restore original config from backup
    --passphrase <p>   Override the stored passphrase (one-off)
    --fortress <path>  Fortress directory (default: ~/.sanctuary). Honors
                       SANCTUARY_FORTRESS_PATH env var when the flag is
                       absent. Use to keep multiple fortresses isolated
                       on one host.
    --port <port>      Preferred dashboard port (default: 3501)
    --dashboard-port <port>
                       Preferred dashboard port (1024-65535). Overrides
                       SANCTUARY_DASHBOARD_PORT when both are set.
    --dry-run          Show what would happen without making changes
    --no-open          Do not auto-open the dashboard in a browser
    --no-dashboard     Do not spawn a per-call dashboard server. Wrap still
                       persists the agent record so a separately-running
                       \`sanctuary dashboard\` (or a later wrap) sees the
                       harness. Use this for the clean operator setup
                       (one persistent dashboard + many wraps).
    --allow-plaintext-remote
                       Persist SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE=true
                       into the wrapped harness environment. Use only when a
                       separate network layer already encrypts transport.
    --anchor-transparency
                       Opt in to transparency anchoring at setup (OFF by
                       default). Publishes a salted hash commitment of each
                       enforcement checkpoint to the public Sigstore Rekor
                       transparency log so the enforcement history becomes
                       fork-evident. Only the salted hash, a signature from
                       a dedicated derived key, and that key's public half
                       ever leave the machine; never checkpoint contents,
                       counts, policy data, or fortress identifiers.
                       Equivalent to running
                       \`sanctuary transparency anchor enable\` later.
    --dev-dist <path>  Dogfood path. Point the harness MCP entries at a
                       local Sanctuary build (\`node <path>\` instead of the
                       version-pinned npx registry entry). Required
                       when testing an unpublished branch; the published
                       version doesn't have new subcommands yet, and
                       npx pulls from the registry, not your checkout.
                       Pass the absolute path to dist/cli.js.
    --stand-down-agent
                       With --repair-egress-gate or --unprotect-egress-gate,
                       acknowledge and permit the required agent-harness stop.
                       Those verbs stop and disable the harness before changing
                       exclusive-egress state and refuse without this flag.
    --help, -h         Show this help

  What happens:
    1. Reads your agent's MCP config
    2. Generates a passphrase (stored in Keychain on macOS, encrypted file elsewhere)
    3. Backs up and rewrites the config so calls route through Sanctuary
    4. Starts the Sovereignty Dashboard and opens it in your browser
    5. Every tool call is logged, scanned, and tier-gated
`);
}
