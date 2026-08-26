import {
  execFile as nodeExecFile,
  execSync as nodeExecSync,
  spawnSync as nodeSpawnSync,
} from "node:child_process";
import { createConnection } from "node:net";
import { createHash, randomBytes as nodeRandomBytes } from "node:crypto";
import { chmod, lstat, mkdir, readFile, readdir, stat, unlink, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { Writable } from "node:stream";
import { ed25519 } from "@noble/curves/ed25519";
import { establishMaster } from "../core/master-custody.js";
import { stringToBytes, toBase64url } from "../core/encoding.js";
import { encrypt, type EncryptedPayload } from "../core/encryption.js";
import { sign as identitySign, type RotationEvent } from "../core/identity.js";
import { randomBytes } from "../core/random.js";
import {
  HelperSignerClient,
  type ShimInvoker,
} from "../castle-wall/runtime/helper-signer.js";
import { resolveFortressCreateOwner } from "../castle-wall/runtime/fortress-create-owner.js";
import { resolveStoragePath } from "../paths.js";
import { getSanctuaryVersion } from "../version.js";
import { getOrCreatePassphrase } from "../wrap/passphrase.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { writeFileCustody } from "../storage/custody-fs.js";
import {
  AuditLog,
  AuditIntegrityError,
  type AuditEntry,
  type AuditIntegrityFinding,
} from "../operational/audit-log.js";
import {
  AuditStoreSplitMigrationError,
  createDaemonAuditLog,
  migrateFortressAuditStoreSplit,
  probeDaemonChainAccess,
  verifyFortressAuditFullPicture,
  verifySealedLegacyPrefix,
} from "../operational/audit-store-split.js";
import {
  DEFAULT_DENY_BUCKET,
  attributeFlows,
  filterFlowsByRule,
  groupFlowsByRule,
  type FlowAttribution,
  type PerRuleGroup,
} from "../castle-wall/audit/per-rule-report.js";
import { frame, parseFrame } from "../castle-wall/ipc/framing.js";
import { writeGlobalPinIfUnestablished } from "../castle-wall/global-pin/index.js";
import { resolveCastleWallSocketPath } from "../castle-wall/runtime/socket-path.js";
import {
  DEFAULT_ENFORCEMENT_AVAILABILITY_FRESHNESS_MS,
  queryMacOSEnforcementAvailability,
  type ResolvedEnforcementAvailability,
} from "../castle-wall/runtime/enforcement-availability.js";
import {
  BOOT_TOKEN_LENGTH,
  deriveSafeModeAuditKey,
  readBootToken,
  safeModeAuditStoragePath,
} from "../castle-wall/boot/boot-token.js";
import { validateAgentOrigin } from "../castle-wall/allowlist/agent-origin.js";
import { listAgentMatchableAllowRuleFiles } from "../castle-wall/allowlist/agent-matchable.js";
import {
  AGENT_EGRESS_NEGATIVE_CONTROL_HOST,
  EGRESS_PROVISION_REFUSED_AUDIT_OP,
  asUidProbeReachableDecision,
  asUidTlsProbeArgv,
} from "../castle-wall/provision/egress.js";
import {
  normalizeFortressCustody,
  resolveSudoIdentityDecision,
  type NormalizeFortressCustodyInput,
  type NormalizeFortressCustodyOutcome,
} from "../castle-wall/provision/fortress-custody.js";
import {
  loadFortressProducerKey,
  loadPinnedProducerKeyB64url,
} from "../castle-wall/runtime/producer-signature.js";
import {
  reverifyEntryProducerSignature,
  signedCanonicalOperation,
  producerSignedDedupKey,
  type EntryReverifyBasis,
} from "../principal-policy/producer-reverify.js";
import {
  CASTLE_WALL_BOOT_LABEL,
  CASTLE_WALL_BOOT_PLIST_PATH,
  bootServiceInstalled,
  bootServiceReady,
} from "./castle-wall-boot.js";
import { consumeFlagValue } from "./argv.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import {
  EGRESS_GATE_REPAIR_WITH_STAND_DOWN_ADVICE,
  GENERIC_UID_CONFINEMENT_REMEDY,
} from "../egress-gate/operator-advice.js";
import {
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
} from "../castle-wall/constants.js";
import type {
  CastleWallMessage,
  DecisionResponse,
} from "../castle-wall/ipc/messages.js";
import {
  requestPolicyReload,
  type PolicyReloadResult,
} from "../castle-wall/runtime/policy-reload-client.js";
import { observing, type Observed } from "../claim-witness.js";
import { ED25519_PUBLIC_KEY_BYTES } from "../core/crypto-suite-registry.js";

export { requestPolicyReload, type PolicyReloadResult };

const CASTLE_PINNED_PUBKEY = "castle-pinned-pubkey.bin";
const CASTLE_PINNED_PRIVKEY = "castle-pinned-privkey.enc";
const CASTLE_GLOBAL_PINNED_PUBKEY_DIR = "/Library/Application Support/Sanctuary";
const CASTLE_GLOBAL_PINNED_PUBKEY_PATH = `${CASTLE_GLOBAL_PINNED_PUBKEY_DIR}/${CASTLE_PINNED_PUBKEY}`;
const DENY_ALL_QUARANTINE_PROBE_TIMEOUT_MS = 12_000;

export interface CastleWallCommandContext {
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  execSyncFn?: (command: string) => string;
  getuid?: () => number;
  /** Path to the signer-client shim (re-pin). Defaults to env. */
  signerClientPath?: string;
  /** Override the shim runner (tests drive re-pin without a real helper). */
  signerClientInvoke?: ShimInvoker;
  /**
   * Override the auto-discovery candidate list for the signer-client shim
   * (tests drive bundle auto-discovery without a real /Applications install).
   * Mirrors the `hostAppCandidates` seam.
   */
  signerClientCandidates?: string[];
  /**
   * Override the candidate-trust probe used by signer-client auto-discovery
   * (tests). Defaults to the `isOwnerTrustedExecutable` owner-trust check (the
   * same check the host-app arming surface uses): a real `stat`-based predicate
   * that requires a regular file owned by root or the current uid.
   */
  fileExistsFn?: (path: string) => Promise<boolean>;
  /**
   * Override the global-pin reader used by `status` (tests inject a present /
   * absent / unreadable global pin without touching the root-owned path).
   */
  globalPinReader?: () => Promise<Uint8Array>;
  /** Override the host-app headless runner (tests drive enable/disable without the real app). */
  hostAppInvoke?: HostAppInvoker;
  /** Override the host-app binary probe list (tests). */
  hostAppCandidates?: string[];
  /** Override the daemon-socket reachability probe (tests). */
  daemonProbe?: (socketPath: string) => Promise<boolean>;
  /** Override the signed enforcement-availability socket query (tests). */
  enforcementAvailabilityQuery?: (
    socketPath: string,
  ) => Promise<ResolvedEnforcementAvailability>;
  /**
   * Override the persistent-boot-service readiness probe used by the `enable`
   * composition guard (#450 item 5; tests). Defaults to {@link bootServiceReady},
   * which validates the LaunchDaemon plist, stable loaded launchd job, enabled
   * state, and expected fortress binding. Returns true iff the boot-survival
   * service is ready for reboot.
   */
  bootServiceReadyProbe?: (expectedFortressPath?: string) => Promise<boolean>;
  /**
   * Override the installed-plist probe used only for diagnostic wording when
   * readiness fails. Defaults to {@link bootServiceInstalled}.
   */
  bootServiceInstalledProbe?: (expectedFortressPath?: string) => Promise<boolean>;
  /**
   * Override the `open` runner used by the DEFAULT LaunchServices invoker
   * (tests exercise the report-file round-trip without shelling out to real
   * `open`). Ignored when `hostAppInvoke` is supplied.
   */
  openRunner?: OpenRunner;
  /**
   * Override the report-file path factory used by the default LaunchServices
   * invoker (tests pin a known temp path). Ignored when `hostAppInvoke` is set.
   */
  reportPathFactory?: () => string;
  /** Override running-app handling for LaunchServices tests. */
  runningAppController?: RunningAppController;
  /**
   * Override the launchd session-manager probe used to pick the disarm-path
   * invoker (tests). Defaults to `launchctl managername`: "Aqua" in a console
   * GUI session, "Background" over SSH, "System" in root/daemon contexts.
   * Returns null when the probe itself failed (fail-safe: LaunchServices, the
   * shipped primary, is used). Ignored when `hostAppInvoke` is supplied.
   */
  sessionManagerNameProbe?: () => Promise<string | null>;
  /**
   * Override the direct-exec host-app invoker used by the disarm-path
   * no-GUI-session fallback (tests). Defaults to {@link makeHostAppInvoke}
   * with the same per-action timeout as the LaunchServices invoker. Ignored
   * when `hostAppInvoke` is supplied.
   */
  directHostAppInvoke?: HostAppInvoker;
  /**
   * Override the system-extension state probe used by the enable gate (tests).
   * Defaults to `systemextensionsctl list | grep castle-wall`.
   */
  sysextProbe?: () => Promise<SysextState>;
  /** Override the boot-token custody path (F1 safe-mode; tests). */
  bootTokenPath?: string;
  /**
   * Override the fortress-dir stat used by the safe-mode daemon to derive the
   * socket re-own uid + create-with-fchown owner (tests simulate a root-owned
   * fortress without root).
   */
  fortressStat?: (
    path: string,
  ) => Promise<{ uid: number; gid: number; isSymbolicLink?: () => boolean }>;
  /**
   * Override the fortress-owner probe behind the `enable` root-owned-fortress
   * refusal (fortress-ownership spec 2026-07-30 §4(a2)(2); tests). Resolves
   * the fortress dir's owner uid, or undefined when it cannot be statted.
   */
  fortressOwnerUidProbe?: (fortressPath: string) => Promise<number | undefined>;
  /**
   * Override the end-of-flow custody-normalize chokepoint (tests). Defaults
   * to {@link normalizeFortressCustody}.
   */
  normalizeFortressCustody?: (
    input: NormalizeFortressCustodyInput,
  ) => Promise<NormalizeFortressCustodyOutcome>;
  /**
   * Override the root-owned global pin path threaded into the safe-mode daemon
   * cross-check (F1 safe-mode; tests point it at a temp path).
   */
  globalPinnedPublicKeyPath?: string;
  /**
   * Inject the daemon start function (F1 safe-mode; tests pass a fake so no
   * real socket/helper is needed). Defaults to {@link startMacOSCastleWallDaemon}.
   */
  safeModeDaemonStart?: (
    input: import("../castle-wall/runtime/macos-daemon.js").MacOSCastleWallDaemonInput,
  ) => Promise<{ socketPath: string; stop: () => Promise<void> }>;
  /**
   * Override the agent-origin descriptor presence probe used by the `enable`
   * boot-cut WARNING (#877 follow-up; tests). Returns true iff a structurally
   * valid agent-origin descriptor is set for the fortress. Defaults to reading
   * and validating `<fortress>/policy/egress/agent-origin.json`.
   */
  agentOriginDescriptorProbe?: (fortressPath: string) => Promise<boolean>;
  /**
   * Bug B P1/B round-2: out-callback that surfaces the disable outcome
   * ALONGSIDE the numeric exit code. `runDisable` can return 0 in three
   * meanings: (B) status re-read observed disabled, (C) save-disabled returned
   * ok but corroboration was inconclusive, and (A) the save did not complete
   * but the dead-man lease revoke made the provider fail open. These must stay
   * distinguishable because only (B) is an OBSERVED-off fact suitable for a
   * protection claim; (C) is a recovery/control-flow success, not an
   * observation. Never fires on non-zero paths.
   */
  onDisableNePreferenceOutcome?: (outcome: DisableNePreferenceOutcome) => void;
  /**
   * Override the agent-matchable-allow-rule counter used by the `enable`
   * no-egress brick guard (confined-agent egress design, section 5 layer 2;
   * tests). Defaults to {@link countAgentMatchableAllowRules}, which reads
   * `<fortress>/policy/egress/rules/*.json` and counts allow-disposition
   * rules an agent-classified flow could match.
   */
  egressAllowRuleCountProbe?: (fortressPath: string) => Promise<number>;
  /**
   * Override the final deny-all quarantine smoke used only after an explicit
   * `enable --allow-no-egress`. Defaults to running the same direct as-uid
   * curl probe shape as the provisioned-egress verifier.
   */
  denyAllQuarantineProbe?: (
    input: DenyAllQuarantineProbeInput,
  ) => Promise<DenyAllQuarantineProbeResult>;
  /**
   * Override the pre-arm sudo credential probe used only for the explicit
   * `enable --allow-no-egress` uid-quarantine path. Defaults to running
   * `/usr/bin/sudo -n -u '#<uid>' /usr/bin/true` with the same timeout as the
   * deny-all quarantine smoke.
   */
  sudoPreflightProbe?: (uid: number) => Promise<SudoPreflightProbeResult>;
  /**
   * Inject the FULL operator-daemon start function (Slice M; tests pass a fake
   * that captures the resolved {@link MacOSCastleWallDaemonInput}, so the
   * key-resolution + producer-key threading can be exercised without a real
   * socket/helper). Defaults to {@link startMacOSCastleWallDaemon}.
   */
  fullDaemonStart?: (
    input: import("../castle-wall/runtime/macos-daemon.js").MacOSCastleWallDaemonInput,
  ) => Promise<{ socketPath: string; stop: () => Promise<void> }>;
  /**
   * Override the macOS audit-producer public-key path threaded into the daemon
   * and macOS reader verification (Slice M). Tests point it at a temp key; an
   * operator may set it via `SANCTUARY_CASTLE_AUDIT_PRODUCER_PUBKEY` for a
   * non-default helper layout. When unset the daemon/readers use their built-in
   * `/Library/Application Support/Sanctuary/castle-audit-producer.pub` default.
   */
  auditProducerPublicKeyPath?: string;
}

export interface CastleWallParsedArgs {
  fortress?: string;
  since?: string;
  parseError?: string;
  scope?: "once" | "session" | "always";
  requestId?: string;
  force?: boolean;
  acceptBrokenChain?: boolean;
  ttlSeconds?: number;
  noTtl?: boolean;
  /** audit-dump: roll flows up per deciding rule (counts + allow/deny split). */
  byRule?: boolean;
  /** audit-dump: restrict the per-flow read-out to a single matched rule id. */
  rule?: string;
  /**
   * Set when `--rule` was given with no following value (end of argv or
   * immediately followed by another flag). The caller turns this into a usage
   * error instead of silently falling back to the raw dump.
   */
  ruleMissingValue?: boolean;
  /**
   * `enable --agent-uid=<uid>` (Build 3, one-command arm): fold
   * `configure-origin uid` into `enable` so an operator can configure-then-arm
   * in one command. Raw string, parsed/validated downstream via
   * `validateAgentOrigin` - never trust this as a well-formed uid on its own.
   * Explicit-flag-only; never auto-derived.
   */
  agentUid?: string;
  /**
   * `enable --ceiling=<uid>` (Build 3): optional system-uid allow-ceiling
   * paired with `--agent-uid`. Defaults to 500 (matching `configure-origin`)
   * when `--agent-uid` is given but `--ceiling` is not.
   */
  ceiling?: string;
  /**
   * `enable --allow-no-egress` (confined-agent egress design, section 5
   * layer 2): explicit override for the standing no-egress brick guard.
   * Arming a uid-mode wall whose manifest source carries ZERO
   * agent-matchable allow rules confines the agent into total
   * non-functionality; a deliberate deny-all quarantine is legitimate but
   * must be ASKED FOR, never the accident. Deliberately NOT covered by
   * `--force` (whose meaning is "the daemon/boot service is supervised
   * out-of-band", a different assertion). The override is audited.
   */
  allowNoEgress?: boolean;
  /** audit-verify: emit machine-readable JSON instead of the human summary. */
  json?: boolean;
  /**
   * audit-verify: explicit override for the pinned audit-producer public-key
   * file. Tests point this at a temp key; production resolves it from the
   * fortress publish path. Never accepted from an untrusted source.
   */
  producerPubKey?: string;
  /**
   * reload (NF-08, additive): opt a scripted caller into a non-zero exit when
   * no daemon was reachable to reload. The bare exit-0 "nothing to reload"
   * default is unchanged and test-pinned: this flag only widens what a
   * caller can ask for, it never narrows the default.
   */
  requireDaemon?: boolean;
}

function writeCastleWallParseError(
  parsed: CastleWallParsedArgs,
  err: Writable,
): boolean {
  if (parsed.parseError === undefined) return false;
  write(err, `Error: ${parsed.parseError}\n`);
  return true;
}

/** Runs the host-app binary in headless mode; mirrors execFile semantics. */
export type HostAppInvoker = (
  binaryPath: string,
  args: string[],
) => Promise<{ stdout: string; stderr: string; exitCode: number }>;

export interface DenyAllQuarantineProbeInput {
  agentUid: number;
  host: string;
  port: number;
}

export interface DenyAllQuarantineProbeResult {
  /** True only when the direct as-uid probe positively reached the host. */
  reachable: boolean;
  /**
   * True when the probe itself ran far enough to distinguish reachable from
   * blocked. A sudo/spawn/timeout failure is not proof that quarantine works.
   */
  verified: boolean;
  exitCode: number | null;
  stderr?: string;
  command?: readonly string[];
}

export interface SudoPreflightProbeResult {
  /** True only when sudo ran the target command as the uid and exited 0. */
  ok: boolean;
  exitCode: number | null;
  stderr?: string;
  command?: readonly string[];
}

export type DisableNePreferenceOutcome =
  | "corroborated_off"
  | "save_accepted_inconclusive"
  | "fail_open_deadman";

/**
 * Runs `open` (or a test double). The default LaunchServices invoker launches
 * the host app through `open` so the child runs as a real LaunchServices
 * instance - the only way to reach NE preferences on macOS Tahoe, where a
 * directly-exec'd binary's `NEFilterManager.loadFromPreferences` hangs forever
 * (Mini1 Tahoe drill, 2026-06-10, finding 1).
 */
export type OpenRunner = (
  command: string,
  args: string[],
) => Promise<{ stdout: string; stderr: string; exitCode: number }>;

/** Parsed `systemextensionsctl list` state for the Castle Wall sysext. */
export type SysextState =
  | "[activated enabled]"
  | "[activated disabled]"
  | "[activated waiting for user]"
  | "not loaded";

type SysextArmClaimState = SysextState | "unreadable";

interface SysextArmClaimObservation {
  state: SysextArmClaimState;
  reason?: string;
}

interface ArmClaimObservationBasis {
  sysext: SysextArmClaimObservation;
  enforcementAvailability: ResolvedEnforcementAvailability;
}

type ObservedArmClaimObservationBasis =
  Omit<ArmClaimObservationBasis, "sysext" | "enforcementAvailability"> & {
    sysext: Observed<SysextArmClaimObservation>;
    enforcementAvailability: Observed<ResolvedEnforcementAvailability>;
  };

/** JSON line emitted by `CastleWallHostApp --headless <action>` (HeadlessFilterCLI.Report). */
interface HeadlessReport {
  ok: boolean;
  action: string;
  state:
    | "enabled"
    | "disabled"
    | "deactivated"
    | "will_complete_after_reboot"
    | "needs_user_approval"
    | "unknown";
  error?: string;
  build?: HeadlessBuildIdentity;
}

/**
 * The CLI's `armed` status shape. It sources from the live daemon lease/IPC
 * (`source: "castle-wall-cli"`), NOT from the audit-marker read path, so it does
 * not re-verify per-event producer signatures (Slice R) - and, importantly, it
 * makes NO per-producer-authenticity claim at all. `armed` here means "the
 * daemon holds a live, non-revoked enforcement lease"; it is liveness, not an
 * authenticity assertion. Because it asserts no authenticity basis, it cannot
 * diverge from the posture surface's `producer_authenticity` (the H3 second-
 * green-path hazard): there is no contradictory claim to make. Any future field
 * that DOES assert authenticity here must mirror `CastleWallPosture.
 * producer_authenticity`, never assert producer-signed independently.
 */
interface LeaseStatusFile {
  armed: boolean;
  revoked?: boolean;
  ttl_seconds: number | null;
  heartbeat_interval_seconds: number;
  updated_at: string;
  source: "castle-wall-cli";
}

type ContentFilterStatusForLease = "enabled" | "disabled" | "unknown" | null;

function formatDeadManLeaseStatus(
  lease: LeaseStatusFile,
  contentFilterState: ContentFilterStatusForLease,
): string {
  const ttl = lease.ttl_seconds === null ? "none (--no-ttl)" : `${lease.ttl_seconds}s`;
  const filter =
    contentFilterState === null ? "" : `; content-filter=${contentFilterState}`;
  // The lease line is a liveness signal for the dead-man BROADCAST, not an
  // enforcement verdict - enforcement is the live content-filter state above.
  // When the filter is disabled, the word "armed" can mislead a skimmer into
  // reading it as "protected". In that case make the advisory nature explicit
  // so the line cannot be mistaken for enforcement (audit-D F5).
  const enforcementActive = contentFilterState === "enabled";
  const label =
    lease.armed && !enforcementActive
      ? "Dead-man lease (advisory broadcast, not enforcement): armed"
      : `Dead-man lease broadcast: ${lease.armed ? "armed" : "disarmed"}`;
  return (
    `${label}` +
    `${filter}; ttl=${ttl}; heartbeat=${lease.heartbeat_interval_seconds}s; updated=${lease.updated_at}\n`
  );
}

/**
 * Matches an availability reason whose socket connect died at permissions
 * (EACCES/EPERM), i.e. THIS ACCOUNT could not reach the socket path at all.
 * That is querier blindness, not wall state; the render appends a
 * plain-English line so a human cannot misread it as an enforcement verdict
 * (fortress-ownership spec 2026-07-30 §4(a2)(3); the per-cause reason code is
 * kept verbatim, this only adds to it).
 */
const AVAILABILITY_CONNECT_PERMISSION_RE = /connect\s+E(?:ACCES|PERM)\b/;

export function formatEnforcementAvailabilityStatus(
  availability: ResolvedEnforcementAvailability,
): string {
  const observed = availability.observed_at ?? "none";
  let text =
    `Enforcement availability: ${availability.status} (${availability.reason}; ` +
    `observed=${observed}; active_connections=${availability.active_connection_count})\n`;
  if (AVAILABILITY_CONNECT_PERMISSION_RE.test(availability.reason)) {
    text +=
      "Note: this account cannot reach the fortress socket, so this surface is blind, not the wall. " +
      "If the fortress is root-owned, repair custody: sudo sanctuary castle-wall repair-custody\n";
  }
  return text;
}

async function readEnforcementAvailabilityForStatus(
  storagePath: string,
  platform: NodeJS.Platform,
  ctx: CastleWallCommandContext,
): Promise<ResolvedEnforcementAvailability> {
  if (platform !== "darwin") {
    return {
      status: "undetermined",
      reason: "not_macos",
      observed_at: null,
      freshness_window_ms: DEFAULT_ENFORCEMENT_AVAILABILITY_FRESHNESS_MS,
      active_connection_count: 0,
    };
  }
  const socketPath = resolveCastleWallSocketPath({ platform, fortressPath: storagePath }).path;
  const query = ctx.enforcementAvailabilityQuery ?? queryMacOSEnforcementAvailability;
  try {
    return await query(socketPath);
  } catch (error) {
    return {
      status: "undetermined",
      reason: `availability_query_failed:${
        error instanceof Error ? error.message : String(error)
      }`,
      observed_at: null,
      freshness_window_ms: DEFAULT_ENFORCEMENT_AVAILABILITY_FRESHNESS_MS,
      active_connection_count: 0,
    };
  }
}

/** Exit-code contract with HeadlessFilterCLI.ExitCode (Swift side). */
const HEADLESS_EXIT_NEEDS_APPROVAL = 3;
export const CASTLE_WALL_HEADLESS_CONTRACT_VERSION = "3";

interface HeadlessBuildIdentity {
  git_sha?: string;
  headless_contract_version?: string;
}

interface RunningAppController {
  isRunning(processName: string): Promise<boolean>;
  terminate(processName: string): Promise<boolean>;
}

/**
 * Distinct CLI exit code for "the system extension is installed but toggled
 * OFF" - the Tahoe-specific state that needs a one-time console toggle in
 * System Settings (drill finding 1). Kept separate from the generic failure (1)
 * and the consent-missing path (3) so an operator/runbook can branch on it.
 */
const EXIT_SYSEXT_DISABLED = 4;

function write(stream: Writable, text: string): void {
  stream.write(text);
}

/**
 * Default agent-origin descriptor presence probe for the `enable` boot-cut
 * WARNING (#877 follow-up). True iff `<fortress>/policy/egress/agent-origin.json`
 * exists, parses, and passes `validateAgentOrigin`. Fail-safe to false (missing,
 * unreadable, malformed, or invalid all count as "no descriptor set") so the
 * warning errs toward informing the operator rather than staying silent.
 */
async function defaultAgentOriginDescriptorPresent(fortressPath: string): Promise<boolean> {
  try {
    const raw = await readFile(agentOriginDescriptorPath(fortressPath), "utf8");
    return validateAgentOrigin(JSON.parse(raw)) !== null;
  } catch {
    return false;
  }
}

/**
 * Shared helper: on a helper-sign-mode daemon-start failure (in `runDaemon` or
 * `runSafeModeDaemon`), run the signer-helper boot-readiness preflight
 * (design pass 2026-06-26) and print the SPECIFIC diagnosis (approve the
 * Background Item, pin mismatch, or repair the custody directory) instead of
 * leaving the operator with only the generic "signer helper is unreachable"
 * message the caller already printed. Best-effort: a failure running the
 * preflight itself must never mask the original daemon-start error, so this
 * never throws.
 */
async function writeSignerHelperReadinessDiagnosis(
  err: Writable,
  opts: {
    platform: NodeJS.Platform;
    signerClientPath: string | undefined;
    signerClientInvoke: ShimInvoker | undefined;
    globalPinPath: string;
  },
): Promise<void> {
  try {
    const {
      assessSignerHelperReadiness,
      buildHelperPublicKeyQuery,
      SIGNER_HELPER_LAUNCHCTL_KILL_SIGNAL,
      SIGNER_HELPER_LAUNCHCTL_TIMEOUT_MS,
    } = await import("./castle-wall-signer-helper.js");
    const readiness = await assessSignerHelperReadiness({
      execFileFn: (cmd, cmdArgs) => {
        const result = nodeSpawnSync(cmd, cmdArgs, {
          encoding: "utf8",
          timeout: SIGNER_HELPER_LAUNCHCTL_TIMEOUT_MS,
          killSignal: SIGNER_HELPER_LAUNCHCTL_KILL_SIGNAL,
        });
        const errorText = result.error ? `${result.error.name}: ${result.error.message}` : "";
        return {
          code: result.status ?? 1,
          stdout: result.stdout ?? "",
          stderr: [result.stderr ?? "", errorText].filter(Boolean).join("\n"),
        };
      },
      queryHelperPublicKey: buildHelperPublicKeyQuery(opts.signerClientPath, opts.signerClientInvoke),
      readGlobalPin: () => readFile(opts.globalPinPath),
      statCustodyDir: async (dirPath) => {
        const info = await stat(dirPath);
        return { uid: info.uid, mode: info.mode & 0o777 };
      },
      platform: opts.platform,
    });
    if (!readiness.ready) {
      write(err, `${readiness.guidance}\n`);
    }
  } catch {
    // Preflight itself failed to run; the caller's generic message still stands.
  }
}

function fingerprintFromPublicKey(publicKey: Uint8Array): string {
  return createHash("sha256")
    .update(publicKey)
    .digest("hex")
    .slice(0, 16);
}

export function parseCastleWallState(raw: string): SysextState {
  if (raw.includes("[activated enabled]")) return "[activated enabled]";
  if (raw.includes("[activated waiting for user]")) {
    return "[activated waiting for user]";
  }
  // Tahoe ships the sysext toggled OFF ([activated disabled]); surface that
  // distinctly rather than mislabeling it "not loaded" (the false-assurance
  // trap from the 2026-06-10 drill, finding 2).
  if (raw.includes("[activated disabled]")) return "[activated disabled]";
  return "not loaded";
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

async function resolveMasterKey(
  storagePath: string,
  env: NodeJS.ProcessEnv
): Promise<Uint8Array> {
  const storage = new FilesystemStorage(join(storagePath, "state"));

  // Unified custody path (master-custody.ts): envelope-first, legacy markers
  // migrated in place, first runs recorded as a headless establishment. This
  // is the same path the MCP server boots through - the CLI can no longer
  // derive a *different* master for the same fortress (the 2026-06-12
  // incident class). SANCTUARY_RECOVERY_KEY keeps its historical precedence
  // over the passphrase for this CLI.
  if (env.SANCTUARY_RECOVERY_KEY) {
    const result = await establishMaster({
      storage,
      recoveryKey: env.SANCTUARY_RECOVERY_KEY,
      firstRun: { installMode: "headless", mintRecoveryKey: false },
      storagePathHint: storagePath,
    });
    return result.masterKey;
  }

  const passphrase =
    env.SANCTUARY_PASSPHRASE ??
    (await getOrCreatePassphrase({ storagePath })).value;

  const result = await establishMaster({
    storage,
    passphrase,
    firstRun: { installMode: "headless", mintRecoveryKey: false },
    storagePathHint: storagePath,
  });
  return result.masterKey;
}

/**
 * Operation name for the CLI's audited "operator accepted a broken audit chain"
 * consent entry. This flag lets specific privileged CLI verbs (daemon
 * bring-up on the legacy chain, re-pin) proceed with their OWN action past
 * existing audit integrity findings; it does not repair or clear those
 * findings, and it does not restore MCP write capability — a fortress that
 * has accumulated an audit-integrity finding has no path back to MCP write
 * access anywhere in this tree today. The MCP router's former
 * `mcp_accept_broken_chain_override` agent path was removed from
 * router.ts/tool-args.ts because it let an MCP-calling agent bypass the same
 * gate whose findings might be evidence of that agent's own tampering; this
 * CLI flag is separate, unrelated machinery, not a replacement for it. A
 * privileged CLI action past audit integrity findings records the
 * operator's consent BEFORE it proceeds, so the override is itself
 * auditable. The broken history is NEVER repaired or deleted; it stays on
 * disk, visible to `sanctuary castle-wall audit-findings`.
 */
const CASTLE_WALL_ACCEPT_BROKEN_CHAIN_OP = "castle_wall_accept_broken_chain_override";

/**
 * Build the `AuditLog` a privileged CLI verb (daemon / re-pin) should use,
 * applying this CLI's operator-override semantics (the MCP router has no
 * equivalent agent-facing path anymore; this flag is operator-CLI-only):
 *
 *  - No `--accept-broken-chain`: return a default (strict) `AuditLog`. If the
 *    chain has integrity findings, the verb's first append throws
 *    `AuditIntegrityError` exactly as today - fail-closed default, unchanged.
 *  - `--accept-broken-chain` + findings present: emit a loud stderr warning,
 *    write an audited critical override entry FIRST (so the consent lands in the
 *    log before the privileged action runs), then return a lenient `AuditLog`
 *    so the verb's own appends proceed past the findings. Nothing is repaired,
 *    rewritten, or deleted - anti-rollback stays intact.
 *  - `--accept-broken-chain` + no findings: return a default (strict)
 *    `AuditLog` and write NO override entry (no spurious consent record).
 *
 * Findings are probed via `getIntegrityFindings()`, which surfaces findings
 * without throwing - the override decision must be made on the actual finding
 * set, not on a thrown error.
 */
async function buildAuditLogForPrivilegedAction(opts: {
  storage: FilesystemStorage;
  masterKey: Uint8Array;
  fortressPath: string;
  verb: "daemon" | "re-pin";
  acceptBrokenChain: boolean;
  err: Writable;
}): Promise<AuditLog> {
  const { storage, masterKey, fortressPath, verb, acceptBrokenChain, err } = opts;
  if (!acceptBrokenChain) {
    return new AuditLog(storage, masterKey);
  }

  // Flag set: probe findings without throwing (lenient read).
  const lenient = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
  const findings = await lenient.getIntegrityFindings();
  if (findings.length === 0) {
    // Clean chain: the override is a no-op. Keep the default strict log and do
    // not write a spurious consent entry.
    return new AuditLog(storage, masterKey);
  }

  // Findings present + operator consented. Make it loud, then record consent
  // BEFORE the privileged action proceeds, mirroring the router ordering.
  write(
    err,
    `WARNING: --accept-broken-chain: proceeding past ${findings.length} audit ` +
      `integrity finding(s) for '${verb}'. Recording an audited override entry ` +
      `(${CASTLE_WALL_ACCEPT_BROKEN_CHAIN_OP}). The broken history is NOT ` +
      `repaired or deleted; inspect it with 'sanctuary castle-wall audit-findings'.\n`,
  );
  await lenient.appendCritical({
    layer: "l2",
    operation: CASTLE_WALL_ACCEPT_BROKEN_CHAIN_OP,
    identity_id: fortressIdFromStoragePath(fortressPath),
    result: "success",
    details: {
      verb,
      finding_count: findings.length,
      findings,
      source: "castle-wall-cli",
    },
  });
  await lenient.flush();
  return lenient;
}

/**
 * Print the current audit-chain integrity findings for a fortress (read-only).
 *
 * This is the "what is actually wrong" diagnostic that lets an operator decide
 * whether `--accept-broken-chain` is warranted. It loads the audit log in
 * lenient mode and reports findings via `getIntegrityFindings()`; it NEVER
 * appends to, repairs, rewrites, or deletes the audit chain. Each finding is
 * emitted as one JSON line (index, kind, message, affected entry key/sequence,
 * expected/actual where present).
 */
export async function runAuditFindings(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const parsed = parseCastleWallArgs(argv);
  if (writeCastleWallParseError(parsed, err)) return 2;
  const fortressPath = resolveFortressArg(parsed.fortress, env);

  try {
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const masterKey = await resolveMasterKey(fortressPath, env);
    const auditLog = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
    const findings = await auditLog.getIntegrityFindings();

    // BLOCKER-R1 (adversarial re-gate 2026-07-14): the routine load SKIPS the
    // sealed legacy region (that is the F2 fix), so `getIntegrityFindings()`
    // above verified only the post-split SUFFIX plus the cheap sealed-region
    // LISTING completeness check. It cannot, on its own, prove the sealed
    // region's CONTENT is intact. So this diagnostic must NOT print "the chain
    // verifies clean" unless the sealed region was actually crypto-walked and
    // returned `verified` / `empty` / `not_present` (never migrated). Run that
    // walk now and fold its verdict into the clean/unclean decision.
    const sealed = await verifySealedLegacyPrefix(storage, masterKey);
    masterKey.fill(0);

    const sealedClean =
      sealed.status === "verified" ||
      sealed.status === "empty" ||
      sealed.status === "not_present";

    if (findings.length === 0 && sealedClean) {
      write(
        out,
        sealed.status === "verified"
          ? "No audit integrity findings; the chain verifies clean (including a crypto re-walk of the sealed legacy region).\n"
          : "No audit integrity findings; the chain verifies clean.\n",
      );
      return 0;
    }

    // Not clean. Emit the routine findings AND an honest sealed-region verdict.
    const sealedNote =
      sealed.status === "unreadable"
        ? "the sealed legacy region is NOT readable at this privilege and was NOT re-verified (re-run as root); this is NOT a clean result"
        : sealed.status === "incomplete"
          ? `the sealed legacy region is INCOMPLETE (expected tip sequence ${sealed.expected_tip}, highest present ${sealed.highest_present}); a sealed entry was deleted`
          : sealed.status === "hash_mismatch"
            ? `the sealed legacy region FAILED crypto re-verification at sequence ${sealed.sequence} (content tampered)`
            : null;

    write(
      err,
      `${findings.length} audit integrity finding(s)` +
        (sealedNote ? ` plus a sealed-region issue` : "") +
        ` for fortress ${fortressIdFromStoragePath(fortressPath)}; the chain does NOT verify clean.\n`,
    );
    findings.forEach((finding, index) => {
      write(
        out,
        JSON.stringify({
          index,
          kind: finding.kind,
          message: finding.message,
          ...(finding.key !== undefined ? { key: finding.key } : {}),
          ...(finding.sequence !== undefined ? { sequence: finding.sequence } : {}),
          ...(finding.expected !== undefined ? { expected: finding.expected } : {}),
          ...(finding.actual !== undefined ? { actual: finding.actual } : {}),
        }) + "\n",
      );
    });
    if (sealedNote) {
      write(
        out,
        JSON.stringify({
          kind: "sealed_region",
          status: sealed.status,
          message: sealedNote,
        }) + "\n",
      );
      write(err, `sealed legacy region: ${sealedNote}.\n`);
    }
    return 0;
  } catch (error) {
    write(err, `Error: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

/**
 * F2 Option A: print the full-picture fortress audit-store-split status
 * (both chains' verdicts, reported honestly and separately). Read-only;
 * never migrates, repairs, or writes anything.
 *
 * Exit code is always 0 unless resolving the master key itself fails: a
 * `present_unreadable` or `findings` verdict is the whole POINT of this
 * command (it is meant to be run as the operator, where the daemon chain, if
 * armed, is EXPECTED to be unreadable) and is not itself a command failure.
 */
export async function runAuditStoreStatus(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const parsed = parseCastleWallArgs(argv);
  if (writeCastleWallParseError(parsed, err)) return 2;
  const fortressPath = resolveFortressArg(parsed.fortress, env);

  try {
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const masterKey = await resolveMasterKey(fortressPath, env);
    const report = await verifyFortressAuditFullPicture({ storage, masterKey });
    masterKey.fill(0);
    write(out, JSON.stringify(report, null, 2) + "\n");
    return 0;
  } catch (error) {
    write(err, `Error: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

export async function runProvisionPin(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {}
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  // Honor the subcommand-level `--fortress <path>` flag, exactly like every
  // other castle-wall custody verb (re-pin, daemon, audit-*) and like the
  // federation/identity/transparency verbs. Before this, provision-pin
  // silently DROPPED its `--fortress` arg and read SANCTUARY_STORAGE_PATH
  // only, so `castle-wall provision-pin --fortress <good>` loaded the custody
  // envelope from a DIFFERENT (default/stale) fortress than the one named -
  // surfacing as "custody envelope exists but has an unsupported shape or
  // version" while federation/identity verbs against the SAME --fortress path
  // worked (2026-06-24 stock-CLI drill). resolveFortressArg falls back to
  // resolveStoragePath(env) when no flag is given, preserving prior behavior.
  const parsed = parseCastleWallArgs(argv);
  if (writeCastleWallParseError(parsed, err)) return 2;
  const storagePath = resolveFortressArg(parsed.fortress, env);
  const pubPath = join(storagePath, CASTLE_PINNED_PUBKEY);
  const privPath = join(storagePath, CASTLE_PINNED_PRIVKEY);
  // Reuse the existing globalPinnedPublicKeyPath test seam (already threaded
  // through the F1 safe-mode daemon path above) instead of adding a new ctx
  // field: tests point this at a temp file so the fail-open regression test
  // below can drive the guard without a real root-owned path.
  const globalPinPath =
    ctx.globalPinnedPublicKeyPath ?? CASTLE_GLOBAL_PINNED_PUBKEY_PATH;

  try {
    await mkdir(storagePath, { recursive: true, mode: 0o700 });

    try {
      const existingPub = await readFile(pubPath);
      if (existingPub.length !== ED25519_PUBLIC_KEY_BYTES) {
        throw new Error(
          `Pinned public key at ${pubPath} must be 32 bytes (found ${existingPub.length}).`
        );
      }
      await writeGlobalPinnedPublicKey(existingPub, globalPinPath);
      const fingerprint = fingerprintFromPublicKey(existingPub);
      write(out, `${fingerprint}\n`);
      write(
        out,
        "Pinned key already provisioned; leaving existing key in place.\n"
      );
      return 0;
    } catch (readError) {
      if (
        !(readError instanceof Error) ||
        !("code" in readError) ||
        (readError as NodeJS.ErrnoException).code !== "ENOENT"
      ) {
        throw readError;
      }
    }

    const masterKey = await resolveMasterKey(storagePath, env);

    // Two-factor custody floor (I4/F6): the Castle pin is trust-bearing
    // material. Enforced in the core verb - not the wrapping CLI - so
    // scripted provisioning hits it too.
    const { enforceCustodyFloor } = await import("../core/master-custody.js");
    await enforceCustodyFloor(
      new FilesystemStorage(join(storagePath, "state")),
      "castle_pin_provision",
      masterKey
    );

    const privateSeed = randomBytes(32);
    const publicKey = ed25519.getPublicKey(privateSeed);
    const encryptedPrivateKey = encrypt(privateSeed, masterKey);
    const fingerprint = fingerprintFromPublicKey(publicKey);

    await writeFile(pubPath, publicKey, { mode: 0o600 });
    await chmod(pubPath, 0o600);
    await writeGlobalPinnedPublicKey(publicKey, globalPinPath);
    await writeFile(privPath, JSON.stringify(encryptedPrivateKey), {
      mode: 0o600,
    });
    await chmod(privPath, 0o600);

    privateSeed.fill(0);
    masterKey.fill(0);

    write(out, `${fingerprint}\n`);
    return 0;
  } catch (error) {
    write(
      err,
      `Error: ${
        error instanceof Error ? error.message : String(error)
      }\n`
    );
    return 1;
  }
}

async function writeGlobalPinnedPublicKey(
  publicKey: Uint8Array,
  globalPinPath: string = CASTLE_GLOBAL_PINNED_PUBKEY_PATH,
): Promise<void> {
  // Fail-open fix (2026-07-07, drill-confirmed on real hardware): the ORIGINAL
  // guard here treated an EACCES/EPERM on write as "the root signer helper owns
  // this file, skip." That holds for an operator-UID provision-pin, but fails
  // OPEN under root: `sanctuary protect --hermes --provision-agent-account`
  // runs the whole wrap (including provision-pin) under `sudo` because
  // OS-account creation needs root, so a root-euid write to the root:wheel 0644
  // global pin SUCCEEDS - silently clobbering the signer helper's pin with a
  // fortress-local key and breaking arm/enforcement until a manual re-pin.
  //
  // The global-pin immutability invariant ("only re-pin migrates the pin") is
  // now enforced in ONE shared chokepoint - `writeGlobalPinIfUnestablished` -
  // that reads-and-compares BEFORE any write, so a second writer (the local-sign
  // daemon) cannot reintroduce the fail-open on a different path. This function
  // supplies the CLI-specific fresh write (exclusive-create) + refusal guidance.
  const emitRePinGuidance = () =>
    console.warn(
      `[castle-wall] global pin ${globalPinPath} already exists and is owned by the root signer helper (A2); provision-pin does not overwrite it. Run 'sanctuary castle-wall re-pin' to migrate the trust anchor to the signer helper.`,
    );

  try {
    await writeGlobalPinIfUnestablished(publicKey, {
      path: globalPinPath,
      onRefuse: emitRePinGuidance,
      // A2/B2 (F-A2-1): do NOT `mkdir` the custody directory here. This runs as
      // the operator-UID (or, under auto-provision, root-euid) provision-pin
      // CLI; creating the directory operator-owned is exactly the gap the
      // helper-as-signer design closes (an operator-owned dir lets same-UID
      // malware swap the key + pin). The root signer helper creates + owns the
      // directory. The exclusive-create ("wx") flag closes the read-then-write
      // TOCTOU inside the chokepoint (EEXIST there is turned into a refusal).
      freshWrite: async (path, key) => {
        await writeFile(path, key, { mode: 0o644, flag: "wx" });
        await chmod(path, 0o644);
      },
    });
  } catch (error) {
    // Reached only when the fresh write threw a NON-EEXIST error (the chokepoint
    // handled EEXIST as a refusal). SAFETY: provision-pin diagnostics are
    // operator-facing CLI stderr output. These carry CLI-specific guidance:
    //   - ENOENT: the custody directory does not exist yet (only the root
    //     helper creates it) - fresh install, no shared pin to migrate. Emit a
    //     quiet, non-action-implying line so a first-time installer is not told
    //     to "migrate the trust anchor" that does not exist. (audit-C MED-1 /
    //     audit-D omit noise on fresh wrap.)
    //   - EACCES/EPERM: the parent directory is not writable (e.g. root-owned
    //     dir, no pin file yet) for an operator-UID caller - `re-pin` migrates
    //     the trust anchor to the signer helper.
    const code =
      error instanceof Error && "code" in error
        ? (error as NodeJS.ErrnoException).code
        : undefined;
    if (code === "ENOENT") {
      console.warn(
        `[castle-wall] shared pin not provisioned (root signer helper not installed); nothing to do for a cooperative-only install.`,
      );
      return;
    }
    if (code === "EACCES" || code === "EPERM") {
      console.warn(
        `[castle-wall] global pin ${globalPinPath} is owned by the root signer helper (A2); provision-pin does not write it. Run 'sanctuary castle-wall re-pin' to migrate the trust anchor to the signer helper.`,
      );
      return;
    }
    console.warn(
      `[castle-wall] warning: unable to write shared pinned key at ${globalPinPath}: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

/**
 * Build the audit-continuity rotation proof binding the OLD pin key to the new
 * helper key (§4.5 step 4). The OLD key signs the binding, proving the holder of
 * the retiring key authorized the migration. Reuses the `RotationEvent` shape
 * from core/identity.ts (already "signature over the event by the OLD key").
 */
export function buildPinRotationProof(opts: {
  oldPublicKey: Uint8Array;
  oldEncryptedPrivateKey: EncryptedPayload;
  encryptionKey: Uint8Array;
  newPublicKey: Uint8Array;
  rotatedAt: string;
}): RotationEvent {
  const oldB64 = toBase64url(opts.oldPublicKey);
  const newB64 = toBase64url(opts.newPublicKey);
  const identityId = `castle-wall:${oldB64}`;
  const reason = "castle-wall-pin-rotation-a2-b2";
  // Match identity.ts rotateKeys: sign the JSON of the 5 fields (no signature).
  const eventData = JSON.stringify({
    old_public_key: oldB64,
    new_public_key: newB64,
    identity_id: identityId,
    reason,
    rotated_at: opts.rotatedAt,
  });
  const signature = identitySign(
    stringToBytes(eventData),
    opts.oldEncryptedPrivateKey,
    opts.encryptionKey,
  );
  return {
    old_public_key: oldB64,
    new_public_key: newB64,
    identity_id: identityId,
    reason,
    rotated_at: opts.rotatedAt,
    signature: toBase64url(signature),
  };
}

/** Bundled path of the signer-client shim inside the installed host app. */
const SIGNER_CLIENT_RELATIVE_BINARY =
  "Sanctuary-CastleWall.app/Contents/MacOS/castle-wall-signer-client";

/**
 * Known on-disk locations of the bundled signer-client shim, in probe order.
 * The shim ships inside the installed host app, so a normally-installed box
 * always has it even when SANCTUARY_CASTLE_SIGNER_CLIENT is unset (the
 * operability gap from the 2026-06-13 Mini1 arming-path drill).
 */
function defaultSignerClientCandidates(env: NodeJS.ProcessEnv): string[] {
  const home = env.HOME ?? homedir();
  return [
    `/Applications/${SIGNER_CLIENT_RELATIVE_BINARY}`,
    `${home}/Applications/${SIGNER_CLIENT_RELATIVE_BINARY}`,
  ];
}

/**
 * Resolve the signer-client shim path used by `re-pin` and the daemon path.
 * Precedence: explicit `ctx.signerClientPath` → `SANCTUARY_CASTLE_SIGNER_CLIENT`
 * env → (darwin only) auto-discovered bundled shim → `undefined`. Auto-discovery
 * is test-injectable via `ctx.signerClientCandidates` / `ctx.fileExistsFn`,
 * mirroring the host-app `hostAppCandidates` seam, so tests never depend on a
 * real `/Applications` install.
 *
 * The DEFAULT discovery predicate is `isOwnerTrustedExecutable` (the same
 * owner-trust check `resolveHostAppBinary` uses to guard the arming surface):
 * a probed candidate must be a regular file owned by root, the current uid, or
 * (for a root process launched via sudo) SUDO_UID. The sudo case is required
 * for `sudo sanctuary protect --hermes`: privileged account/launchd steps run
 * as root, while the installed and user-consented Castle Wall app can be owned
 * by the operator who invoked sudo.
 * This brings the signer-client surface to PARITY with the host-app surface.
 * NOTE: stronger same-UID hardening (designated-requirement / codesign
 * validation) is a broader follow-up that, if pursued, must apply UNIFORMLY to
 * BOTH the host-app and signer-client surfaces - deliberately out of scope here
 * to stay consistent with the established owner-trust model.
 */
async function resolveSignerClientPath(
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform,
  ctx: CastleWallCommandContext,
): Promise<string | undefined> {
  if (ctx.signerClientPath) return ctx.signerClientPath;
  if (env.SANCTUARY_CASTLE_SIGNER_CLIENT) {
    return env.SANCTUARY_CASTLE_SIGNER_CLIENT;
  }
  if (platform !== "darwin") return undefined;
  const getuid = ctx.getuid ?? process.getuid?.bind(process);
  const exists =
    ctx.fileExistsFn ?? ((path: string) => isOwnerTrustedExecutable(path, getuid, env));
  const candidates = ctx.signerClientCandidates ?? defaultSignerClientCandidates(env);
  for (const candidate of candidates) {
    if (await exists(candidate)) return candidate;
  }
  return undefined;
}

/**
 * One-time, operator-approved trust-anchor migration (A2/B2 re-pin). Tells the
 * root signer helper to (re)write the global pin with ITS key (K_helper), then
 * records a rotation proof signed by the retiring passphrase-derived key
 * (K_old). Idempotent: when the global pin already holds K_helper, this
 * re-asserts state rather than rotating again.
 *
 * This is a Tier-1-class irreversible op (hard constraint #3): it runs only when
 * the operator is present and has just approved the helper - never silently,
 * never agent-triggerable.
 */
export async function runRePin(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;
  const parsed = parseCastleWallArgs(argv);
  if (writeCastleWallParseError(parsed, err)) return 2;
  const acceptBrokenChain = parsed.acceptBrokenChain ?? false;

  if (platform !== "darwin") {
    write(err, "castle-wall re-pin is macOS-only.\n");
    return 1;
  }

  const storagePath = resolveStoragePath(env);

  // F2a - loud target-fortress announcement (visibility, NOT a gating change).
  // `resolveStoragePath` silently defaults to ~/.sanctuary when
  // SANCTUARY_STORAGE_PATH is unset; the 2026-06-13 drill pain was an UNSCOPED
  // invocation touching the real default fortress's audit lock with no signal.
  // Print the resolved target before any state-touching work, and call out the
  // default-fortress case. NOTE: a stricter opt-in confirm/refuse gate on the
  // DEFAULT fortress was considered and deliberately DEFERRED to Erik - re-pinning
  // the real default fortress is the legitimate operator path, so this stays a
  // pure-visibility change with no gating effect.
  const usingDefaultFortress = !env.SANCTUARY_STORAGE_PATH;
  write(
    err,
    `Re-pinning trust anchor for fortress: ${storagePath}` +
      (usingDefaultFortress
        ? " (default fortress; set SANCTUARY_STORAGE_PATH to target another)"
        : "") +
      "\n",
  );

  const clientBinaryPath =
    (await resolveSignerClientPath(env, platform, ctx)) ??
    ctx.signerClientPath ??
    env.SANCTUARY_CASTLE_SIGNER_CLIENT;
  if (!clientBinaryPath && !ctx.signerClientInvoke) {
    write(
      err,
      "Cannot re-pin: signer-client shim path unknown. Set SANCTUARY_CASTLE_SIGNER_CLIENT or install the Castle Wall app (which bundles it).\n",
    );
    return 1;
  }

  const client = new HelperSignerClient({
    clientBinaryPath: clientBinaryPath ?? "castle-wall-signer-client",
    ...(ctx.signerClientInvoke ? { invoke: ctx.signerClientInvoke } : {}),
  });

  // PRE-MIGRATION phase: any failure here (shim unreachable, bad key length,
  // etc.) means the trust anchor did NOT move - report failure and return 1.
  let helperPub: Uint8Array;
  try {
    // Ask the helper to (re)write the root-owned pin with K_helper and return it.
    helperPub = await client.installPin();
  } catch (error) {
    write(err, `Error: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
  if (helperPub.length !== ED25519_PUBLIC_KEY_BYTES) {
    write(err, `Helper returned a ${helperPub.length}-byte key (expected 32).\n`);
    return 1;
  }
  const helperFingerprint = fingerprintFromPublicKey(helperPub);

  // POST-MIGRATION phase: `installPin()` succeeded, so the trust anchor IS
  // migrated to the helper key. Everything below is audit bookkeeping (reading
  // the retiring key, deriving the master key, recording the rotation proof).
  // F2b - a failure HERE (e.g. `aes/gcm: invalid ghash tag` when the fortress
  // material can't be decrypted) must NOT be reported as a re-pin failure:
  // telling the operator the migration failed when the anchor actually moved is
  // the more dangerous lie. Degrade to a loud warning and still return 0,
  // printing the migrated fingerprint.
  //
  // FIX 3 - `masterKey` (decrypted fortress secret) is hoisted so a `finally`
  // zeroes it on EVERY exit from this block: success returns, the
  // AuditIntegrityError exit-1 path, and the F2b degraded-warning exit-0 path.
  // A throw between resolveMasterKey() and a return must never leave the
  // plaintext key resident in memory.
  let masterKey: Uint8Array | null = null;
  try {
    // Read the retiring K_old (the passphrase-derived key provision-pin minted).
    // Its presence lets us emit the old-signs-new rotation proof for audit
    // continuity. If it is already gone (a prior re-pin retired it), treat this
    // as an idempotent re-assert.
    const pubPath = join(storagePath, CASTLE_PINNED_PUBKEY);
    const privPath = join(storagePath, CASTLE_PINNED_PRIVKEY);
    let oldPub: Uint8Array | null = null;
    let oldEnc: EncryptedPayload | null = null;
    try {
      oldPub = await readFile(pubPath);
      oldEnc = JSON.parse(await readFile(privPath, "utf8")) as EncryptedPayload;
    } catch {
      oldPub = null;
      oldEnc = null;
    }

    const storage = new FilesystemStorage(join(storagePath, "state"));
    masterKey = await resolveMasterKey(storagePath, env);
    const auditLog = await buildAuditLogForPrivilegedAction({
      storage,
      masterKey,
      fortressPath: storagePath,
      verb: "re-pin",
      acceptBrokenChain,
      err,
    });

    if (oldPub && oldPub.length === ED25519_PUBLIC_KEY_BYTES && oldEnc) {
      const oldFingerprint = fingerprintFromPublicKey(oldPub);
      if (oldFingerprint === helperFingerprint) {
        // Already migrated (K_old already equals K_helper would be unusual, but
        // re-running after a prior re-pin where the helper key is now the pin is
        // the idempotent case handled below). Treat equal fingerprints as a
        // no-op re-assert.
        write(out, `${helperFingerprint}\n`);
        write(out, "Pin already holds the helper key; re-asserted (no rotation).\n");
        return 0;
      }
      const proof = buildPinRotationProof({
        oldPublicKey: oldPub,
        oldEncryptedPrivateKey: oldEnc,
        encryptionKey: masterKey,
        newPublicKey: helperPub,
        rotatedAt: new Date().toISOString(),
      });
      await auditLog.append(
        "l1",
        "policy_loaded",
        fortressIdFromStoragePath(storagePath),
        {
          source: "castle-wall-re-pin",
          rotation_proof: proof,
          old_pin_fingerprint: oldFingerprint,
          new_pin_fingerprint: helperFingerprint,
        },
        "success",
      );
      await auditLog.flush();
      write(out, `${helperFingerprint}\n`);
      write(
        out,
        `Trust anchor migrated to the signer helper (was ${oldFingerprint}). Rotation proof recorded in the audit log.\n`,
      );
      return 0;
    }

    // No retiring key on disk: idempotent re-assert (already migrated earlier).
    await auditLog.append(
      "l1",
      "policy_loaded",
      fortressIdFromStoragePath(storagePath),
      {
        source: "castle-wall-re-pin",
        new_pin_fingerprint: helperFingerprint,
        note: "re-assert (no retiring key present)",
      },
      "success",
    );
    await auditLog.flush();
    write(out, `${helperFingerprint}\n`);
    write(out, "Pin re-asserted to the helper key (no retiring key to rotate).\n");
    return 0;
  } catch (error) {
    // The broken-audit-chain refusal (no --accept-broken-chain) is a DELIBERATE
    // fail-closed gate, not an incidental bookkeeping error. Preserve it exactly
    // as before: surface it and return 1. F2b must not weaken this gating.
    if (error instanceof AuditIntegrityError) {
      write(err, `Error: ${error.message}\n`);
      return 1;
    }
    // F2b - the pin migrated, but recording the rotation proof failed for an
    // incidental reason (e.g. `aes/gcm: invalid ghash tag` when fortress
    // material can't be decrypted). Do NOT report re-pin failure: emit a
    // warning, print the migrated fingerprint, and return 0. The anchor IS
    // migrated; claiming failure would be the more dangerous lie.
    const reason = error instanceof Error ? error.message : String(error);
    write(out, `${helperFingerprint}\n`);
    write(
      err,
      `Trust anchor migrated to ${helperFingerprint}, but recording the rotation ` +
        `proof in the audit log failed: ${reason}. The pin migration itself succeeded.\n`,
    );
    return 0;
  } finally {
    // FIX 3 - zero the decrypted fortress key on every exit (success,
    // AuditIntegrityError exit-1, F2b degraded exit-0, or any throw between
    // resolveMasterKey() and a return). No-op when resolveMasterKey() never ran.
    masterKey?.fill(0);
  }
}

/**
 * Read the global enforcement pin without ever throwing out of `status`.
 * Returns the 32-byte key on success, `"none"` when no global pin is
 * provisioned (ENOENT), or `"unreadable"` when it exists but is root-owned and
 * not readable without elevation (EACCES/EPERM). Any other error also degrades
 * to `"unreadable"` rather than throwing - status is a diagnostic, not a gate.
 * Test-injectable via `ctx.globalPinReader`.
 */
async function readGlobalPinForStatus(
  ctx: CastleWallCommandContext,
): Promise<Uint8Array | "none" | "unreadable"> {
  const reader =
    ctx.globalPinReader ?? (() => readFile(CASTLE_GLOBAL_PINNED_PUBKEY_PATH));
  try {
    const key = await reader();
    if (key.length !== ED25519_PUBLIC_KEY_BYTES) return "unreadable";
    return key;
  } catch (error) {
    const code =
      error instanceof Error && "code" in error
        ? (error as NodeJS.ErrnoException).code
        : undefined;
    if (code === "ENOENT") return "none";
    if (code === "EACCES" || code === "EPERM") return "unreadable";
    return "unreadable";
  }
}

/**
 * F3 - print the global enforcement pin and a trust-anchor consistency verdict.
 * AUTHORITATIVE approach: the signer helper exposes a non-mutating `get-pubkey`
 * query (`HelperSignerClient.getPublicKey`), so when a signer-client shim is
 * resolvable we compare the global pin against the live helper key and print
 * CONSISTENT / BROKEN. If no helper query is reachable (no shim resolvable, or
 * the query fails), we fall back to comparing the global pin against the local
 * fortress key and note that the authoritative pin==helper check needs the
 * running daemon/helper. Never throws out of status.
 */
async function reportGlobalPinAndVerdict(
  out: Writable,
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform,
  ctx: CastleWallCommandContext,
  localFingerprint: string | null,
): Promise<void> {
  const global = await readGlobalPinForStatus(ctx);
  if (global === "none") {
    write(out, "Global pin (enforcement anchor): none (no global pin provisioned)\n");
    write(
      out,
      "Trust anchor: no global pin provisioned (run 'sanctuary castle-wall re-pin' to install it)\n",
    );
    return;
  }
  if (global === "unreadable") {
    write(
      out,
      "Global pin (enforcement anchor): unreadable (root-owned; re-run with elevation to inspect)\n",
    );
    return;
  }

  const globalFingerprint = fingerprintFromPublicKey(global);
  write(out, `Global pin (enforcement anchor): ${globalFingerprint}\n`);

  // Try the AUTHORITATIVE read-only helper query first.
  const shimPath = await resolveSignerClientPath(env, platform, ctx);
  if (shimPath || ctx.signerClientInvoke) {
    try {
      const client = new HelperSignerClient({
        clientBinaryPath: shimPath ?? "castle-wall-signer-client",
        ...(ctx.signerClientInvoke ? { invoke: ctx.signerClientInvoke } : {}),
      });
      const helperPub = await client.getPublicKey();
      const helperFingerprint = fingerprintFromPublicKey(helperPub);
      if (helperFingerprint === globalFingerprint) {
        write(out, "Trust anchor: CONSISTENT (global pin == signer-helper key)\n");
      } else {
        write(
          out,
          "Trust anchor: BROKEN (global pin != signer-helper key; box cannot arm until re-pinned)\n",
        );
      }
      return;
    } catch {
      // Helper query unreachable - fall through to the softer local comparison.
    }
  }

  // Fallback: compare global pin vs local fortress key (softer, non-authoritative).
  if (localFingerprint === null) {
    write(
      out,
      "Trust anchor: cannot verify (no local fortress key on disk; the authoritative pin==signer-helper check needs the running daemon/signer helper)\n",
    );
    return;
  }
  if (localFingerprint === globalFingerprint) {
    write(out, "Trust anchor: global pin matches local fortress key\n");
  } else {
    write(
      out,
      "Trust anchor: global pin DIFFERS from local fortress key (run re-pin or check the signer helper)\n",
    );
  }
  write(
    out,
    "Note: the authoritative pin==signer-helper check needs the running daemon/signer helper.\n",
  );
}

export async function runStatus(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {}
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;
  const execSyncFn =
    ctx.execSyncFn ??
    ((command: string) =>
      nodeExecSync(`sh -lc '${command.replace(/'/g, "'\\''")}'`, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim());
  // O-07 (register): honor the subcommand-level `--fortress <path>` flag,
  // exactly like every other castle-wall custody verb (re-pin, daemon,
  // audit-store-status; see runProvisionPin's doc for the identical prior
  // bug). Before this fix `runStatus` took no argv at all and always read
  // `resolveStoragePath(env)` (SANCTUARY_STORAGE_PATH or the default
  // ~/.sanctuary fortress), so `castle-wall status --fortress <path>`
  // silently reported the local pinned key AND probed the enforcement-
  // availability socket for the DEFAULT fortress, never the one named --
  // whatever order the flag was passed in, since it was never parsed.
  // resolveFortressArg falls back to resolveStoragePath(env) when no flag is
  // given, preserving prior (env-or-default) behavior exactly.
  const parsed = parseCastleWallArgs(argv);
  if (writeCastleWallParseError(parsed, err)) return 2;
  const storagePath = resolveFortressArg(parsed.fortress, env);
  const pubPath = join(storagePath, CASTLE_PINNED_PUBKEY);

  let localFingerprint: string | null = null;
  try {
    const publicKey = await readFile(pubPath);
    if (publicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
      throw new Error(
        `Pinned public key at ${pubPath} must be 32 bytes (found ${publicKey.length}).`
      );
    }
    localFingerprint = fingerprintFromPublicKey(publicKey);
    write(out, `Pinned key fingerprint: ${localFingerprint}\n`);
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error as NodeJS.ErrnoException).code === "ENOENT"
    ) {
      write(
        out,
        "No pinned key provisioned. Run: sanctuary castle-wall provision-pin\n"
      );
    } else {
      // DEGRADE, never throw: `status` is the diagnostic an operator runs WHEN
      // the anchor is broken (e.g. a malformed-length local pin). Throwing out
      // here would defeat the F3 global-pin verdict below - the very thing
      // needed to diagnose the break. Warn, leave localFingerprint = null, and
      // fall through to global-pin reporting. (ENOENT keeps its message above.)
      const reason = error instanceof Error ? error.message : String(error);
      write(out, `Local fortress key: unreadable (${reason})\n`);
    }
  }

  if (platform !== "darwin") {
    write(out, "Castle Wall sysext: not applicable (non-macOS)\n");
    return 0;
  }

  // F3 - surface the GLOBAL pin (the actual enforcement anchor) and a
  // trust-anchor consistency verdict. A box can sit un-armable for days with no
  // signal when the global pin diverges from the signer-helper key (the
  // 06-11b→06-13 situation). Reading the global pin NEVER throws out of status:
  // ENOENT = no global pin provisioned; EACCES/EPERM = root-owned and
  // unreadable without elevation. The consistency check is AUTHORITATIVE: the
  // signer helper exposes a non-mutating `get-pubkey` query (HelperSignerClient
  // .getPublicKey - NOT installPin(), which would MUTATE the pin), so we compare
  // the global pin against the live helper key directly.
  await reportGlobalPinAndVerdict(out, env, platform, ctx, localFingerprint);

  let sysextState: SysextState;
  try {
    const raw = execSyncFn(
      "systemextensionsctl list 2>/dev/null | grep castle-wall"
    );
    sysextState = parseCastleWallState(raw);
  } catch {
    sysextState = "not loaded";
  }

  write(out, `Castle Wall sysext: ${sysextState}\n`);
  let contentFilterState: ContentFilterStatusForLease = null;

  // Sysext "[activated enabled]" only means installed, not filtering. When the
  // host-app binary is present, corroborate the live NE filter state through
  // its --headless status probe. Binary absent → stay silent so output is
  // unchanged on machines without the app (and on non-Mac CI).
  const resolved = await resolveHostAppBinary(env, ctx);
  if (!("error" in resolved)) {
    const invoke = ctx.hostAppInvoke ?? makeHostAppInvoke(STATUS_PROBE_TIMEOUT_MS);
    try {
      const result = await invoke(resolved.path, ["--headless", "status"]);
      const report = parseHeadlessReport(result.stdout);
      if (
        result.exitCode === 0 &&
        report?.ok &&
        (report.state === "enabled" || report.state === "disabled")
      ) {
        contentFilterState = report.state;
        write(out, `Content filter: ${report.state}\n`);
        if (report.build?.git_sha && report.build?.headless_contract_version) {
          write(
            out,
            `Castle Wall app build: ${report.build.git_sha} (headless contract ${report.build.headless_contract_version})\n`,
          );
        } else {
          write(
            out,
            "Castle Wall app build: unknown (host app does not report headless contract identity)\n",
          );
        }
      } else {
        const reason =
          report?.error ??
          (report && report.state !== "enabled" && report.state !== "disabled"
            ? `host app reported state '${report.state}'`
            : undefined) ??
          (result.stderr.trim() ||
            `host app exited with code ${result.exitCode}`);
        contentFilterState = "unknown";
        write(out, `Content filter: unknown (${reason})\n`);
      }
    } catch (error) {
      contentFilterState = "unknown";
      write(
        out,
        `Content filter: unknown (${
          error instanceof Error ? error.message : String(error)
        })\n`,
      );
    }
  }
  const enforcementAvailability = await readEnforcementAvailabilityForStatus(
    storagePath,
    platform,
    ctx,
  );
  write(out, formatEnforcementAvailabilityStatus(enforcementAvailability));
  const lease = await readLeaseStatus(storagePath);
  if (lease) {
    write(out, formatDeadManLeaseStatus(lease, contentFilterState));
  }
  return 0;
}

/**
 * Start the Castle Wall enforcement daemon standalone, using the EXISTING
 * fortress signing key, without wrapping a live agent. This is the
 * acceptance-drill bring-up path (A1/B2): `sanctuary wrap` couples the daemon
 * to a wrapped agent's MCP-server lifetime, which is unsuitable for a
 * multi-step, multi-reboot armed-wall drill.
 *
 * B2: by default the daemon signs via the root signer helper, so signing no
 * longer needs the passphrase at all. The derived master key is still required
 * to open the encrypted audit log (residual R2 - a boot-time daemon still needs
 * it; that is F1's problem, not closed here). The legacy local-sign path
 * (`SANCTUARY_CASTLE_LOCAL_SIGN=1`) still decrypts `castle-pinned-privkey.enc`
 * and proves the passphrase matches the pin by construction.
 *
 * This verb refuses to mint a fresh passphrase (which could never open the
 * existing audit log) and requires an existing fortress (key-params present).
 *
 * Runs in the foreground until SIGINT/SIGTERM, then tears the daemon down.
 *
 * F1: `--launchd` marks a launchd boot-service invocation (install-boot's
 * LaunchDaemon passes it). Behavior is identical except audit provenance:
 * filter/policy lifecycle events carry source "launchd-boot" so boot-time
 * policy delivery is distinguishable from an interactive bring-up in the
 * audit log.
 */
export async function runDaemon(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;
  const parsed = parseCastleWallArgs(argv);
  if (writeCastleWallParseError(parsed, err)) return 2;
  const acceptBrokenChain = parsed.acceptBrokenChain ?? false;

  // FIX 3 (codex HIGH - wire the opt-in producer-signed close into production).
  // The daemon verb is macOS by default. On Linux it stays unsupported UNLESS the
  // operator explicitly opts in to the producer-signed close, in which case it
  // routes to the Linux activation gate (fail-closed, off-by-default,
  // drill-pending). The gate re-checks platform + opt-in internally.
  const { isLinuxProducerSignedActivationRequested } = await import(
    "../castle-wall/runtime/index.js"
  );
  const linuxProducerSigned =
    platform === "linux" &&
    isLinuxProducerSignedActivationRequested({ env });

  if (platform !== "darwin" && !linuxProducerSigned) {
    write(
      err,
      platform === "linux"
        ? "castle-wall daemon is macOS-only by default. To run the opt-in Linux producer-signed close, set SANCTUARY_CASTLE_LINUX_PRODUCER_SIGNED=1 (drill-pending, off by default).\n"
        : "castle-wall daemon is macOS-only.\n",
    );
    return 1;
  }

  // F1 Option C: the launchd boot service comes up in SAFE MODE - it holds
  // only the software-protected boot token, never the fortress master key.
  // (macOS-only path; Linux never reaches here with --safe-mode.)
  if (argv.includes("--safe-mode")) {
    return runSafeModeDaemon(argv, ctx);
  }

  // Honor the subcommand-level `--fortress <path>` flag, exactly like the
  // sibling custody verbs (provision-pin, re-pin, audit-*). Before this the
  // daemon resolved with `resolveStoragePath(env)`, which reads
  // SANCTUARY_STORAGE_PATH only, so it silently DROPPED a trailing
  // `--fortress` (the top-level extractor stops at the subcommand boundary
  // and never sees it) and armed against the DEFAULT/home fortress instead of
  // the operator-named one - a "never silently degrade" footgun (wrong-fortress
  // unlock failures, or arming the wrong fortress). resolveFortressArg falls
  // back to resolveStoragePath(env) when no flag is given, preserving prior
  // env-var behavior (SANCTUARY_FORTRESS_PATH is promoted to
  // SANCTUARY_STORAGE_PATH upstream in cli.ts).
  const storagePath = resolveFortressArg(parsed.fortress, env);
  const localSign = env.SANCTUARY_CASTLE_LOCAL_SIGN === "1";
  const launchdBoot = argv.includes("--launchd");

  // Report the active pin fingerprint. In helper mode the trust anchor is the
  // root-owned global pin (K_helper); in local mode it is the per-fortress key.
  const pubPath = join(storagePath, CASTLE_PINNED_PUBKEY);
  let pinFingerprint: string;
  try {
    let publicKey: Uint8Array;
    if (!localSign) {
      try {
        publicKey = await readFile(CASTLE_GLOBAL_PINNED_PUBKEY_PATH);
      } catch {
        publicKey = await readFile(pubPath);
      }
    } else {
      publicKey = await readFile(pubPath);
    }
    if (publicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
      write(err, `Pinned public key must be 32 bytes (found ${publicKey.length}).\n`);
      return 1;
    }
    pinFingerprint = fingerprintFromPublicKey(publicKey);
  } catch {
    write(
      err,
      `No pinned key found. Run 'sanctuary castle-wall provision-pin' (local) or 'sanctuary castle-wall re-pin' (helper) first.\n`,
    );
    return 1;
  }
  write(out, `Pinned key fingerprint: ${pinFingerprint}\n`);

  // Resolve the EXISTING fortress passphrase. Refuse to generate a fresh one:
  // a new key could never match the pin, and arming with it would fail-closed
  // the whole machine to deny-all.
  let passphrase: string;
  if (env.SANCTUARY_PASSPHRASE) {
    passphrase = env.SANCTUARY_PASSPHRASE;
  } else {
    const resolved = await getOrCreatePassphrase({ storagePath });
    if (resolved.source === "generated") {
      write(err, "Refusing to start: no existing fortress passphrase found (would mint a new key that cannot match the pin). Run where the fortress Keychain entry is unlocked, or set SANCTUARY_PASSPHRASE.\n");
      return 1;
    }
    passphrase = resolved.value;
  }

  // Require an already-provisioned fortress (custody envelope or legacy
  // key-params); never establish a fresh master from the daemon verb - a
  // fresh key could not match the pin and arming with it would fail-closed
  // the whole machine.
  const getuid = ctx.getuid ?? process.getuid?.bind(process);
  const processUid = getuid?.();
  const isRootDaemon = processUid === 0;
  const fortressCreateOwner =
    platform === "darwin"
      ? resolveFortressCreateOwner({ fortressPath: storagePath })
      : undefined;
  const storage = new FilesystemStorage(
    join(storagePath, "state"),
    fortressCreateOwner !== undefined ? { owner: fortressCreateOwner } : {},
  );
  let derived: { key: Uint8Array };
  try {
    const custodyResult = await establishMaster({
      storage,
      passphrase,
      storagePathHint: storagePath,
    });
    derived = { key: custodyResult.masterKey };
  } catch (error) {
    write(
      err,
      `Refusing to start: ${error instanceof Error ? error.message : String(error)}\n` +
        "(nothing provisioned to bring up, or the credential does not unlock this fortress).\n",
    );
    return 1;
  }
  // F2 Option A (2026-07-14): on an armed box the `daemon` verb is launched as
  // ROOT (launchd/system context, needed for the NEFilter/pf enforcement
  // primitives), while every OTHER caller of this same binary runs as the
  // fortress operator. When both write into the shared `_audit` chain, the
  // daemon's root-owned entries become permanently unreadable to the
  // operator uid, so the operator's own `ensureLoaded()` throws
  // `AuditIntegrityError` on every subsequent read/mint (drill-verified
  // finding F2, `Review/Sanctuary/FileGrant_F2_Audit_Contamination_Decision_2026-07-14.md`).
  // The fix is store separation: a root daemon gets its OWN root-owned
  // `_audit-daemon` chain (never `_audit`), reached via
  // `createDaemonAuditLog`. On startup it MUST also run the one-time,
  // idempotent, crash-safe migration that seals any PRE-EXISTING `_audit`
  // history (which may already have contamination) as a legacy segment; see
  // `operational/audit-store-split.ts`'s module doc comment for the full
  // design.
  //
  // A NON-root daemon run (dev/test/manual, or a deployment that does not
  // need root for enforcement) is unaffected: it keeps writing straight into
  // the shared `_audit` chain exactly as before this PR, byte-for-byte, and
  // never provisions a daemon namespace or a split-boundary record. This
  // keeps every existing test/CI/dev flow (which never runs as uid 0)
  // completely unchanged.
  let auditLog: AuditLog;
  if (isRootDaemon) {
    try {
      const migration = await migrateFortressAuditStoreSplit({
        storage,
        masterKey: derived.key,
        identityId: fortressIdFromStoragePath(storagePath),
        ...(fortressCreateOwner !== undefined ? { createOwner: fortressCreateOwner } : {}),
      });
      write(
        out,
        migration.status === "already-migrated"
          ? `Fortress audit store split already active (sealed at legacy sequence ${migration.boundary.sealed_tip_sequence}).\n`
          : `Fortress audit store split engaged: sealed the pre-split "_audit" chain at sequence ${migration.boundary.sealed_tip_sequence}; this daemon now writes its own root-owned "${migration.boundary.daemon_namespace}" chain.\n`,
      );
    } catch (error) {
      write(
        err,
        `Refusing to start: the fortress audit store writer-split migration failed ` +
          `(${error instanceof AuditStoreSplitMigrationError ? error.message : String(error)}).\n` +
          "This runs as root and can read every existing audit entry regardless of " +
          "owner, so a failure here means a genuine chain problem, not routine " +
          "cross-uid unreadability. Investigate before retrying (see " +
          "'sanctuary castle-wall audit-findings').\n",
      );
      return 1;
    }
    // The daemon's own chain is fresh from this migration onward (nothing but
    // this migration and this daemon ever write to it), so there is no
    // analogous "accept a pre-existing broken chain" override to apply here;
    // `--accept-broken-chain` still governs ONLY the legacy `_audit` read
    // path other privileged verbs (e.g. `re-pin`) use.
    auditLog = createDaemonAuditLog(
      storage,
      derived.key,
      fortressCreateOwner !== undefined ? { createOwner: fortressCreateOwner } : undefined,
    );
  } else {
    auditLog = await buildAuditLogForPrivilegedAction({
      storage,
      masterKey: derived.key,
      fortressPath: storagePath,
      verb: "daemon",
      acceptBrokenChain,
      err,
    });
  }

  let daemon: { socketPath: string; stop: () => Promise<void> };

  if (linuxProducerSigned) {
    // FIX 3: opt-in Linux producer-signed close. Route through the fail-closed
    // activation gate using the fortress's existing pinned key as the IPC
    // handshake identity. No macOS helper signer is involved (the systemd daemon
    // holds its own root-owned producer key). Off-by-default + drill-pending.
    const {
      maybeActivateLinuxProducerSignedCastleWall,
      buildLinuxIpcClientKeyMaterial,
    } = await import("../castle-wall/runtime/index.js");
    const fortressId = fortressIdFromStoragePath(storagePath);
    try {
      const key = await buildLinuxIpcClientKeyMaterial({
        fortressPath: storagePath,
        fortressId,
        masterKey: derived.key,
      });
      const outcome = await maybeActivateLinuxProducerSignedCastleWall({
        fortressId,
        fortressStoragePath: storagePath,
        key,
        auditSink: auditLog,
        env,
      });
      if (!outcome.activated) {
        // Not possible here (we already gated on platform + opt-in), but never
        // fake-arm: surface not-armed rather than pretend.
        write(
          err,
          `Refusing to report armed: Linux producer-signed activation did not engage (${outcome.reason}).\n`,
        );
        return 1;
      }
      const socketPath = resolveCastleWallSocketPath({
        platform,
        fortressId,
        fortressPath: storagePath,
      }).path;
      daemon = { socketPath, stop: () => outcome.activation.stop() };
    } catch (error) {
      write(err, `Daemon failed to start (Linux producer-signed, fail-closed): ${(error as Error).message}\n`);
      write(err, "The producer-signed close is fail-closed: a daemon-start, key, handshake, or drain failure surfaces NOT-ARMED rather than degrading to the channel basis.\n");
      return 1;
    }
  } else {
    // F1 - resolve the signer-client shim the same way `re-pin` does: explicit
    // ctx → env → auto-discovered bundled shim. Lets a normally-installed box arm
    // without the operator having to set SANCTUARY_CASTLE_SIGNER_CLIENT by hand
    // (the 2026-06-13 drill operability gap). Only used in helper-sign mode.
    const resolvedSignerClient = localSign
      ? undefined
      : await resolveSignerClientPath(env, platform, ctx);

    // Slice M: resolve the macOS audit-producer public-key path the daemon
    // pins flow verdicts against. ctx (tests) → env override → daemon default
    // (`/Library/Application Support/Sanctuary/castle-audit-producer.pub`). When
    // a key IS published there, the daemon loads it and engages per-producer
    // re-verification; when it is absent, the daemon stays on the honest
    // channel-authenticated floor (never overclaims).
    const auditProducerKeyPath =
      ctx.auditProducerPublicKeyPath ??
      env.SANCTUARY_CASTLE_AUDIT_PRODUCER_PUBKEY;

    const startFullDaemon =
      ctx.fullDaemonStart ??
      (async (input) => {
        const { startMacOSCastleWallDaemon } = await import(
          "../castle-wall/runtime/index.js"
        );
        return startMacOSCastleWallDaemon(input);
      });
    try {
      daemon = await startFullDaemon({
        fortressPath: storagePath,
        fortressId: fortressIdFromStoragePath(storagePath),
        masterKey: derived.key,
        auditLog,
        // FULL operator daemon: come up in FULL mode (NOT safe-mode-from-boot-
        // token). This is the console-login enforcement path that holds the
        // fortress key + reaches the audit-producer signing service.
        daemonMode: "full",
        ...(launchdBoot ? { auditSource: "launchd-boot" } : {}),
        ...(localSign ? { localSign: true } : {}),
        ...(resolvedSignerClient
          ? { signerClientPath: resolvedSignerClient }
          : {}),
        ...(auditProducerKeyPath
          ? { auditProducerPublicKeyPath: auditProducerKeyPath }
          : {}),
      });
    } catch (error) {
      write(err, `Daemon failed to start: ${(error as Error).message}\n`);
      if (localSign) {
        write(err, "Local-sign mode: a decrypt error means the passphrase does not match the pinned key. Refusing to arm with a mismatched key.\n");
      } else {
        write(err, "Helper-sign mode: the signer helper is unreachable. Refusing to arm without a signer (fail-closed).\n");
        await writeSignerHelperReadinessDiagnosis(err, {
          platform,
          signerClientPath: resolvedSignerClient,
          signerClientInvoke: ctx.signerClientInvoke,
          globalPinPath: CASTLE_GLOBAL_PINNED_PUBKEY_PATH,
        });
      }
      return 1;
    }
  }

  write(out, `Castle Wall daemon listening on ${daemon.socketPath}\n`);
  if (linuxProducerSigned) {
    write(
      out,
      `Linux producer-signed close ACTIVE (opt-in): the systemd daemon signs every ` +
        `enforcement event with its root-owned producer key; the in-process server ` +
        `re-verifies against pin ${pinFingerprint}. Drill-acceptance pending.\n`,
    );
  } else {
    if (launchdBoot) {
      write(out, "Started under launchd (boot service); audit source = launchd-boot.\n");
    }
    if (localSign) {
      write(out, `Signing via the local key; matches pin ${pinFingerprint} (decryption succeeded).\n`);
    } else {
      write(out, `Signing via the root signer helper (no passphrase used for signing); pin ${pinFingerprint}.\n`);
    }
  }
  write(out, "Daemon running in the foreground. Ctrl-C (SIGINT) or SIGTERM to stop.\n");

  // Periodic verifiable-transparency checkpoints. Default cadence 6h;
  // SANCTUARY_TRANSPARENCY_INTERVAL accepts "off", ms, or <n>s|m|h|d. A
  // misconfigured cadence refuses to start the daemon (no silent fallback);
  // a failed emission tick is loud on stderr but never crashes enforcement
  // and never persists a partial checkpoint (the emitter is fail-closed).
  let transparencyScheduler: { stop(): void } | undefined;
  {
    const {
      parseTransparencyInterval,
      startTransparencyScheduler,
      TRANSPARENCY_INTERVAL_ENV,
    } = await import("../transparency/scheduler.js");
    let intervalMs: number | null;
    try {
      intervalMs = parseTransparencyInterval(env[TRANSPARENCY_INTERVAL_ENV]);
    } catch (error) {
      write(err, `${(error as Error).message}\n`);
      await daemon.stop().catch(() => undefined);
      return 1;
    }
    if (intervalMs !== null) {
      const { emitEnforcementCheckpoint } = await import(
        "../transparency/emitter.js"
      );
      const { resolveTransparencySigner } = await import(
        "../transparency/signer.js"
      );
      const { realpathSync } = await import("node:fs");
      // Canonical version source. A bare require("../../package.json") resolves
      // to the repo-root package.json (no `version`) once bundled to
      // server/dist/, which corrupts the persisted checkpoint chain; the helper
      // reads server/package.json from both src/ and dist/.
      const pkgVersion = getSanctuaryVersion();
      transparencyScheduler = startTransparencyScheduler({
        intervalMs,
        emit: async () => {
          const signer = await resolveTransparencySigner({
            fortressPath: storagePath,
            masterKey: derived.key,
            env,
            ...(localSign ? { mode: "local" as const } : {}),
          });
          const record = await emitEnforcementCheckpoint({
            storage,
            auditLog,
            fortressId: fortressIdFromStoragePath(storagePath),
            fortressPath: storagePath,
            masterKey: derived.key,
            signer,
            binaryPath: realpathSync(process.argv[1] ?? ""),
            version: pkgVersion,
          });
          await auditLog.appendCritical({
            layer: "l2",
            operation: "transparency_checkpoint_emitted",
            identity_id: record.fortress_id,
            result: "success",
            details: {
              counter: record.counter,
              merkle_root: record.audit.merkle_root,
              highest_sequence: record.audit.highest_sequence,
              signer_kid: record.signer_kid,
            },
          });
          write(
            out,
            `[transparency] enforcement checkpoint ${record.counter} emitted (audit head seq ${record.audit.highest_sequence}).\n`,
          );
          // Opt-in external anchoring (PR-2). OFF by default: with no
          // consent record nothing is transmitted. FAIL LOUD, never
          // blocking: an anchor failure (or a tampered anchoring config)
          // is reported on the console and in the audit log, but the
          // emitted checkpoint above stands and enforcement continues.
          try {
            const { anchorCheckpoint, readAnchorConfig } = await import(
              "../transparency/anchoring.js"
            );
            const anchorState = await readAnchorConfig({
              storage,
              masterKey: derived.key,
            });
            if (anchorState.status === "enabled") {
              const outcome = await anchorCheckpoint({
                storage,
                masterKey: derived.key,
                auditLog,
                record,
              });
              if (outcome.status === "anchored") {
                write(
                  out,
                  `[transparency] checkpoint ${record.counter} anchored to ${anchorState.config.rekor_url} (Rekor index ${outcome.receipt.rekor.log_index}).\n`,
                );
              } else if (outcome.status === "failed") {
                write(
                  err,
                  `[transparency] checkpoint ${record.counter} ANCHORING FAILED (emission stands; recorded in the audit log): ${outcome.error}. Retry with: sanctuary transparency anchor now\n`,
                );
              }
            }
          } catch (anchorError) {
            write(
              err,
              `[transparency] checkpoint ${record.counter} ANCHORING REFUSED (emission stands): ${anchorError instanceof Error ? anchorError.message : String(anchorError)}\n`,
            );
          }
        },
        onError: (error) => {
          write(
            err,
            `[transparency] checkpoint emission FAILED (nothing was persisted): ${error instanceof Error ? error.message : String(error)}\n`,
          );
        },
      });
      write(
        out,
        `[transparency] periodic enforcement checkpoints every ${Math.round(intervalMs / 60_000)}m (set ${TRANSPARENCY_INTERVAL_ENV}=off to disable).\n`,
      );
    }
  }

  await new Promise<void>((resolveWait) => {
    let stopping = false;
    const stop = () => {
      if (stopping) return;
      stopping = true;
      write(err, "\nStopping Castle Wall daemon...\n");
      transparencyScheduler?.stop();
      void daemon
        .stop()
        .catch(() => undefined)
        .finally(() => resolveWait());
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
  return 0;
}

/**
 * F1 Option C - the SAFE-MODE boot daemon (the anti-brick half).
 *
 * This is what `install-boot`'s LaunchDaemon runs (`castle-wall daemon
 * --safe-mode --launchd`) at boot, before any user login. It comes up holding
 * ONLY the software-protected boot token - never the fortress passphrase or
 * master key, which are not present pre-login. Concretely it differs from the
 * full `runDaemon` in three ways:
 *
 *   1. No passphrase / master key. It reads the boot token (root-only 0600,
 *      fail-closed on any custody violation) and derives a safe-mode audit key
 *      from it, so boot-time lifecycle is recorded in a dedicated audit segment
 *      without the master key. The fortress passphrase is never touched.
 *   2. Helper signing only. Manifest delivery routes through the root signer
 *      helper (no private key in this process). Local-sign is REFUSED here: it
 *      would require the master key to decrypt the on-disk private key, which
 *      defeats the entire point of the split credential.
 *   3. Audit provenance `launchd-boot-safe-mode`, so safe-mode bring-up is
 *      distinguishable from a full interactive/login bring-up in the audit
 *      stream.
 *
 * The wall still enforces: the system extension recovers + verifies the
 * persisted last-valid signed manifest against the pinned PUBLIC key (no secret
 * needed), and absent a manifest classifies every flow `.agent` and denies.
 * Full operation (approvals that touch fortress state, the master-key audit
 * log) resumes when the operator logs in and starts the full daemon.
 *
 * HANDOFF (#450 item 4 - de-scoped, no automatic supersede): this boot daemon
 * is a ROOT launchd KeepAlive unit. The full operator daemon runs unprivileged
 * and CANNOT stop it, so it does not silently "supersede" this one (an earlier
 * doc comment claimed it did; that coordination was never implemented). Until
 * the boot daemon is explicitly stood down - `sudo launchctl bootout
 * system/<boot-label>`, after which it returns on the next reboot - a starting
 * full daemon detects the live boot daemon (via the active-config `mode` marker)
 * and refuses with handoff guidance rather than orphaning it. The box stays
 * safely in safe mode meanwhile. SSH / operator endpoints stay reachable
 * throughout, so an unattended reboot can no longer brick the box.
 */
export async function runSafeModeDaemon(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;
  const parsed = parseCastleWallArgs(argv);
  if (writeCastleWallParseError(parsed, err)) return 2;

  if (platform !== "darwin") {
    write(err, "castle-wall daemon --safe-mode is macOS-only.\n");
    return 1;
  }

  // Local-sign is incompatible with safe mode: it needs the master key to
  // decrypt the on-disk private key, which the boot context must never hold.
  if (env.SANCTUARY_CASTLE_LOCAL_SIGN === "1") {
    write(
      err,
      "Refusing to start safe mode with SANCTUARY_CASTLE_LOCAL_SIGN=1: local signing needs the fortress master key, which is never present in the pre-login boot context. Safe mode signs via the root helper only.\n",
    );
    return 1;
  }

  // Honor the subcommand-level `--fortress <path>` flag, matching runDaemon and
  // the other custody verbs. `castle-wall daemon --safe-mode --fortress <path>`
  // routes here with the full argv, so without this the safe-mode boot path
  // silently dropped `--fortress` and armed against the default/home fortress -
  // the same footgun runDaemon had. resolveFortressArg falls back to
  // resolveStoragePath(env) when no flag is given, so the launchd boot path
  // (SANCTUARY_STORAGE_PATH set in the plist, no flag) is unchanged.
  const storagePath = resolveFortressArg(parsed.fortress, env);
  const fortressId = fortressIdFromStoragePath(storagePath);

  // 1. Boot token (the only secret safe mode holds). Fail-closed on absence or
  //    any custody violation, never mint a fresh one.
  const tokenRead = await readBootToken(
    ctx.bootTokenPath ? { path: ctx.bootTokenPath } : {},
  );
  if (tokenRead.status !== "ok") {
    const detail =
      tokenRead.status === "not-found"
        ? "no boot token found. Run 'sudo sanctuary castle-wall provision-boot-token' first"
        : tokenRead.status === "bad-mode"
          ? `boot token has insecure permissions (mode ${tokenRead.mode.toString(8)}); it must be 0600. Re-run 'sudo sanctuary castle-wall provision-boot-token'`
          : `boot token is the wrong length (${tokenRead.length} bytes; expected ${BOOT_TOKEN_LENGTH}); re-run 'sudo sanctuary castle-wall provision-boot-token'`;
    write(err, `Refusing to start safe mode: ${detail}.\n`);
    return 1;
  }

  // #450 item 3: safe mode runs as root, so the socket it binds is root-owned
  // and the operator CLI dead-man lever (`disable`) cannot reach it. Re-own the
  // socket to the FORTRESS OWNER (= operator). Derive the uid from the fortress
  // dir owner rather than trust SUDO_USER/env, so it tracks whoever actually
  // owns the fortress. Fail-soft: if the fortress is unreadable we skip the
  // re-own (the daemon still comes up + enforces; only the programmatic lever is
  // degraded, with the GUI toggle as backstop) rather than refuse to start.
  // Resolved BEFORE the audit storage opens so the same owner drives
  // create-with-fchown for the fortress-internal audit segments this ROOT
  // daemon writes (fortress-ownership spec 2026-07-30, open question 5).
  let socketOwnerUid: number | undefined;
  let fortressOwnerGid: number | undefined;
  try {
    // lstat, NOT stat (2026-07-31 gate round 3): a SYMLINKED fortress would
    // otherwise report its target's owner, and the create-with-fchown writes
    // below would hand files outside the fortress to that uid.
    const fortressStat = await (ctx.fortressStat ?? lstat)(storagePath);
    if (
      typeof (fortressStat as { isSymbolicLink?: () => boolean }).isSymbolicLink === "function" &&
      (fortressStat as { isSymbolicLink: () => boolean }).isSymbolicLink()
    ) {
      throw new Error(`fortress ${storagePath} is a symlink`);
    }
    socketOwnerUid = fortressStat.uid;
    fortressOwnerGid = fortressStat.gid;
  } catch (error) {
    write(
      err,
      `Warning: could not resolve the fortress owner for ${storagePath} (${error instanceof Error ? error.message : String(error)}); the operator may be unable to reach the safe-mode socket. Disarm via System Settings VPN & Filters if needed.\n`,
    );
  }
  if (socketOwnerUid === 0 && (ctx.getuid ?? process.getuid?.bind(process))?.() === 0) {
    // Fortress-ownership spec 2026-07-30 §4(a2)(3): a root-owned fortress makes
    // the socket re-own a no-op BY CONSTRUCTION (we would "re-own" the socket to
    // root). That state is exactly as blind as a failed stat, so it gets the
    // same loud operator-facing warning instead of silence.
    write(
      err,
      `Warning: the fortress at ${storagePath} is owned by root (uid 0), so the safe-mode socket stays root-owned and the operator may be unable to reach it (including the 'disable' dead-man lever). Run 'sudo sanctuary castle-wall repair-custody' to hand the fortress back to the operator. Disarm via System Settings VPN & Filters if needed.\n`,
    );
  }
  // 2026-07-31 re-gate MED: gid 0 is refused alongside uid 0, so a `501:0`
  // fortress never has root-created files chowned to group wheel.
  const fortressCreateOwner =
    socketOwnerUid !== undefined &&
    socketOwnerUid !== 0 &&
    fortressOwnerGid !== undefined &&
    fortressOwnerGid !== 0 &&
    process.getuid?.() === 0
      ? { uid: socketOwnerUid, gid: fortressOwnerGid }
      : undefined;

  // 2. Derive the safe-mode audit key and open the boot-token-keyed audit
  //    segment (separate from the master-key audit log, which is unreadable
  //    pre-login by design). Create-with-fchown: audit segments this ROOT
  //    daemon creates inside the operator-owned fortress are handed to the
  //    fortress owner at creation, so operator readability never erodes.
  const safeModeAuditKey = deriveSafeModeAuditKey(tokenRead.token);
  const auditStorage = new FilesystemStorage(
    safeModeAuditStoragePath(storagePath, tokenRead.token),
    fortressCreateOwner !== undefined ? { owner: fortressCreateOwner } : {},
  );
  const auditLog = new AuditLog(
    auditStorage,
    safeModeAuditKey,
    fortressCreateOwner !== undefined ? { createOwner: fortressCreateOwner } : undefined,
  );

  // 3. Helper signer is mandatory in safe mode.
  const signerClientPath =
    ctx.signerClientPath ?? env.SANCTUARY_CASTLE_SIGNER_CLIENT;
  if (!signerClientPath && !ctx.signerClientInvoke) {
    write(
      err,
      "Refusing to start safe mode without a signer helper: set SANCTUARY_CASTLE_SIGNER_CLIENT to the signer-client shim path. Safe mode never local-signs.\n",
    );
    return 1;
  }

  const startDaemon =
    ctx.safeModeDaemonStart ??
    (async (input) => {
      const { startMacOSCastleWallDaemon } = await import(
        "../castle-wall/runtime/index.js"
      );
      return startMacOSCastleWallDaemon(input);
    });

  let daemon: { socketPath: string; stop: () => Promise<void> };
  try {
    daemon = await startDaemon({
      fortressPath: storagePath,
      fortressId,
      // Inert in helper mode (only local signing reads masterKey); we pass the
      // safe-mode audit key so no fortress key material is constructed here.
      masterKey: safeModeAuditKey,
      auditLog,
      ...(socketOwnerUid !== undefined ? { socketOwnerUid } : {}),
      // #450 item 4: mark the active-config so a colliding full daemon gives the
      // operator precise stand-down/handoff guidance (no automatic supersede).
      daemonMode: "safe",
      auditSource: "launchd-boot-safe-mode",
      ...(signerClientPath ? { signerClientPath } : {}),
      ...(ctx.signerClientInvoke ? { signerClientInvoke: ctx.signerClientInvoke } : {}),
      ...(ctx.globalPinnedPublicKeyPath
        ? { globalPinnedPublicKeyPath: ctx.globalPinnedPublicKeyPath }
        : {}),
      // Slice M: a safe-mode boot daemon also loads the helper-published
      // audit-producer key (the helper provisions it at boot independent of
      // login), so producer-signed verdicts are re-verified even before login.
      ...(ctx.auditProducerPublicKeyPath ?? env.SANCTUARY_CASTLE_AUDIT_PRODUCER_PUBKEY
        ? {
            auditProducerPublicKeyPath:
              ctx.auditProducerPublicKeyPath ??
              env.SANCTUARY_CASTLE_AUDIT_PRODUCER_PUBKEY,
          }
        : {}),
    });
  } catch (error) {
    write(err, `Safe-mode daemon failed to start: ${(error as Error).message}\n`);
    write(
      err,
      "The signer helper is unreachable. The system extension keeps enforcing the persisted last-valid manifest (deny baseline) meanwhile; KeepAlive will retry. Refusing to arm without a signer (fail-closed).\n",
    );
    // Boot-readiness preflight (design pass 2026-06-26): this is the boot-daemon
    // path itself, so the diagnosis matters most here.
    await writeSignerHelperReadinessDiagnosis(err, {
      platform,
      signerClientPath,
      signerClientInvoke: ctx.signerClientInvoke,
      globalPinPath: ctx.globalPinnedPublicKeyPath ?? CASTLE_GLOBAL_PINNED_PUBKEY_PATH,
    });
    return 1;
  }

  write(out, `Castle Wall SAFE-MODE daemon listening on ${daemon.socketPath}\n`);
  write(
    out,
    "Safe mode: boot token only, no fortress master key; signing via the root helper; audit source = launchd-boot-safe-mode.\n",
  );
  write(
    out,
    "Agents denied by default; persisted signed manifest enforced if present. Full operation resumes at first login.\n",
  );

  // Unified Protect Slice 5 S5-6: the exclusive-egress BOOT release sequence
  // (design "Boot ordering via the root supervisor"). For every confined
  // agent in the S5-1 registry: re-arm the pf anchor union from the registry
  // -> verify gate + generation -> recommit + hold file -> enable+bootstrap
  // the parked harness, per the S5-5 persistent-park contract -- then keep
  // the oracle freshness-token loop running (the gate's per-CONNECT liveness
  // is TTL-fresh). PER-AGENT FAIL-CLOSED and NEVER daemon-fatal: a failure
  // leaves that agent PARKED (loud, amber, repairable via
  // 'sudo sanctuary protect --repair-egress-gate --stand-down-agent'), and the policy daemon
  // keeps serving regardless.
  let exclusiveEgressSupervisor: { stopOracleLoop(): void } | undefined;
  try {
    const { startExclusiveEgressBootSupervisor, NON_HERMES_BOOT_PARK_REASON } = await import(
      "../egress-gate/arming-wiring.js"
    );
    const { deriveGateAccountName } = await import("../egress-gate/index.js");
    const { loadExclusiveRoutingMarker } = await import("../castle-wall/allowlist/routing-marker.js");
    const { deriveAgentAccountName, resolveHermesGatewayArgv, realHarnessArgvOps } = await import(
      "../castle-wall/provision/index.js"
    );
    exclusiveEgressSupervisor = await startExclusiveEgressBootSupervisor({
      // Discriminated resolution (fix-round H1): an unresolvable agent gets a
      // REAL reassert-parked (bootout + hold-file removal + disable) inside
      // the supervisor, never a synthetic unverified "parked" report.
      resolveAgent: async (entry) => {
        const marker = await loadExclusiveRoutingMarker(entry.fortress_path).catch(() => null);
        if (marker === null || marker.agent_uid !== entry.agent_uid) {
          return {
            kind: "unresolvable" as const,
            reason: `no exclusive-routing marker names uid ${entry.agent_uid} in ${entry.fortress_path} (marker missing, malformed, or for another uid)`,
          };
        }
        if (marker.agent_id !== "hermes") {
          // Fix-round M6: a deliberate v1 scope bound, not a fault.
          return { kind: "unresolvable" as const, reason: NON_HERMES_BOOT_PARK_REASON };
        }
        const accountName = deriveAgentAccountName(marker.agent_id);
        const agentHome = `/var/sanctuary-agents/${accountName}`;
        const gateAccount = deriveGateAccountName(marker.agent_id);
        const gateHomeDirectory = `/var/sanctuary-agents/${gateAccount}`;
        // FIX F-INTERP: one shared production probe set (never a hand-rolled
        // `pathExists` here), and the argv is resolved for the AGENT uid the
        // boot release will actually run the harness as.
        const resolved = await resolveHermesGatewayArgv(realHarnessArgvOps(), {
          agentHome,
          agentUid: marker.agent_uid,
        });
        return {
          kind: "ok" as const,
          agentAccount: accountName,
          // FIX F-HARNESSENV: the boot release re-renders the harness plist, so
          // it carries the WHOLE launch (argv + environment), never a bare argv.
          harnessLaunch: resolved.launch,
          harnessLogDir: `${agentHome}/logs`,
          gateAccount,
          gateHomeDirectory,
          gateUid: marker.gate_uid,
        };
      },
      audit: async () => undefined, // safe-mode: unified log is the boot evidence channel.
      print: (line) => write(out, `${line}\n`),
    });
  } catch (bootErr) {
    // HONESTY (fix-round-2 BLOCKER-1): a supervisor throw means NO re-park op
    // verifiably ran here -- never claim the agents "stay PARKED"; their
    // persisted parked posture (hold files + disable overrides) was not
    // re-verified this boot.
    write(
      err,
      `[castle-wall] exclusive-egress boot supervisor failed (${bootErr instanceof Error ? bootErr.message : String(bootErr)}); NO boot release or re-park ran and the confined agents' parked state was NOT verified -- treat them as possibly startable and intervene. Repair: ${EGRESS_GATE_REPAIR_WITH_STAND_DOWN_ADVICE}\n`,
    );
  }

  await new Promise<void>((resolveWait) => {
    let stopping = false;
    const stop = () => {
      if (stopping) return;
      stopping = true;
      write(err, "\nStopping Castle Wall safe-mode daemon...\n");
      exclusiveEgressSupervisor?.stopOracleLoop();
      void daemon
        .stop()
        .catch(() => undefined)
        .finally(() => resolveWait());
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
  return 0;
}

export async function runSetupSharedDir(
  ctx: CastleWallCommandContext = {}
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;
  const getuid = ctx.getuid ?? process.getuid?.bind(process);
  const execSyncFn =
    ctx.execSyncFn ??
    ((command: string) =>
      nodeExecSync(`sh -lc '${command.replace(/'/g, "'\\''")}'`, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim());

  if (platform !== "darwin") {
    write(out, "Castle Wall shared dir: not applicable (non-macOS)\n");
    return 0;
  }

  if (getuid?.() !== 0) {
    write(
      err,
      "setup-shared-dir must run as root. Re-run: sudo sanctuary castle-wall setup-shared-dir\n",
    );
    return 1;
  }

  const sudoUser = env.SUDO_USER;
  if (!sudoUser) {
    write(
      err,
      "Cannot determine the operator account (SUDO_USER unset). Run via sudo, not as a raw root shell.\n",
    );
    return 1;
  }

  if (!/^[a-zA-Z0-9._-]+$/.test(sudoUser)) {
    write(
      err,
      "Invalid SUDO_USER value; refusing to build a shell command from it.\n",
    );
    return 1;
  }

  try {
    const dir = shellQuote(CASTLE_GLOBAL_PINNED_PUBKEY_DIR);
    execSyncFn(`mkdir -p ${dir}`);
    // A2/B2 (F-A2-1): the custody directory holds the root-owned signing key +
    // trust-anchor pin. It MUST be owned by root and not group/other-writable,
    // or an operator-UID process could unlink + substitute those files (POSIX
    // governs unlink/rename by DIRECTORY write permission). Chown to root:wheel,
    // NOT to the operator. SUDO_USER above is validated only to confirm a real
    // sudo invocation; it is no longer interpolated into a privileged command.
    execSyncFn(`chown root:wheel ${dir}`);
    execSyncFn(`chmod 0755 ${dir}`);
  } catch (error) {
    write(err, `${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }

  write(out, `${CASTLE_GLOBAL_PINNED_PUBKEY_DIR}\n`);
  write(
    out,
    "Shared dir ready (root:wheel 0755). The signer helper owns the key + pin inside it; run 'sanctuary castle-wall re-pin' to install the trust anchor.\n",
  );
  return 0;
}

export async function runReload(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {}
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const parsed = parseCastleWallArgs(argv);
  if (writeCastleWallParseError(parsed, err)) return 2;
  const fortressPath = resolveFortressArg(parsed.fortress, env);

  const result = await requestPolicyReload(fortressPath, ctx.platform ?? process.platform);
  if (result.ok) {
    write(out, `Castle Wall policy reloaded (${result.loadedRuleCount} rules).\n`);
    return 0;
  }
  if (result.socketUnavailable) {
    write(
      out,
      `No Castle Wall daemon running for fortress ${fortressIdLabel(fortressPath)}. Run 'sanctuary wrap' to start one.\n`,
    );
    // NF-08: "nothing to reload" is not a failure by default: a fresh
    // fortress with no daemon yet is a normal state, and this exit code is
    // test-pinned. A scripted caller that needs to tell "reloaded" apart from
    // "nothing was there" opts in with --require-daemon rather than the
    // default silently becoming unscriptable for everyone else.
    if (parsed.requireDaemon) {
      write(
        err,
        `Error: --require-daemon set and no Castle Wall daemon is reachable for fortress ${fortressIdLabel(fortressPath)}.\n`,
      );
      return 1;
    }
    return 0;
  }
  write(err, `Error: ${result.error ?? "policy reload failed"}\n`);
  return 1;
}

export async function runApprove(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {}
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const parsed = parseCastleWallArgs(argv);
  if (writeCastleWallParseError(parsed, err)) return 2;
  const requestId = parsed.requestId;
  if (!requestId) {
    write(err, "Error: castle-wall approve requires <request_id>\n");
    return 2;
  }
  const fortressPath = resolveFortressArg(parsed.fortress, env);
  const socketPath = resolveCastleWallSocketPath({
    platform: ctx.platform ?? process.platform,
    fortressPath,
  }).path;
  const scope = parsed.scope ?? "once";
  const message: DecisionResponse = {
    type: "decision_response",
    request_id: requestId,
    decision:
      scope === "always"
        ? "allow_always"
        : "allow_once",
    ...(scope === "session"
      ? { learn: { granularity: "per_template_domain" as const } }
      : {}),
  };

  try {
    const reply = await sendCastleWallMessage<CastleWallMessage>(
      socketPath,
      message,
      "decision_response_ack",
    );
    if ("ok" in reply && reply.ok === true) {
      write(out, `Castle Wall request ${requestId} approved (${scope}).\n`);
      return 0;
    }
    write(err, `Error: no pending request matches ${requestId}\n`);
    return 1;
  } catch (error) {
    write(err, `Error: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

/**
 * F2 HIGH-1 (adversarial gate 2026-07-14): after the writer-split, the root
 * daemon's Castle Wall enforcement events (egress_allowed / egress_blocked /
 * filter_started) live in `_audit-daemon`, NOT `_audit`. A reader that reads
 * only `_audit` would print a false-green over an incomplete chain. This helper
 * returns the daemon chain's entries when readable, or an honest status so the
 * caller can mark its output INCOMPLETE (and never treat a zero-count as a
 * clean success).
 */
type DaemonAuditView = {
  // HIGH-R4 (adversarial re-gate 2026-07-14): `tampered` means the daemon chain
  // is readable but FAILED integrity verification. Its entries must NOT be
  // counted as verified coverage, and the caller must mark the run incomplete.
  status: "absent" | "included" | "unreadable" | "tampered";
  entries: AuditEntry[];
  findings: AuditIntegrityFinding[];
};

async function collectDaemonCastleWallEntries(
  storage: FilesystemStorage,
  masterKey: Uint8Array,
  queryOpts: { since?: string; layer: "l1"; limit: number },
): Promise<DaemonAuditView> {
  const access = await probeDaemonChainAccess(storage);
  if (access === "absent") return { status: "absent", entries: [], findings: [] };
  if (access === "present_unreadable") {
    return { status: "unreadable", entries: [], findings: [] };
  }
  try {
    const daemonLog = createDaemonAuditLog(storage, masterKey, {
      integrityMode: "lenient",
    });
    const q = await daemonLog.query(queryOpts);
    // HIGH-R4: `query()` returns the daemon chain's integrity findings; a prior
    // version DISCARDED them, so a readable-but-tampered daemon chain read as
    // `complete: true` with no warning. Surface them: a chain with findings is
    // `tampered`, and its entries are NOT counted as verified coverage.
    //
    // F2 BLOCKER-1 (round 3): the cleanliness decision routes through the shared
    // chokepoint `getAuditChainVerdict` (the daemon chain has no sealed region of
    // its own, so its sealed verdict is `not_present` and the fold reduces to the
    // routine findings, exactly as before) rather than reading findings.length
    // directly. This keeps every audit-cleanliness claim on one code path.
    const verdict = await daemonLog.getAuditChainVerdict();
    if (verdict.status === "findings") {
      return {
        status: "tampered",
        entries: q.entries,
        findings: q.integrity_findings,
      };
    }
    return { status: "included", entries: q.entries, findings: [] };
  } catch {
    // A read error mid-query (e.g. the dir became unreadable in a race) is
    // reported as unreadable, never silently dropped to "complete".
    return { status: "unreadable", entries: [], findings: [] };
  }
}

export async function runAuditDump(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {}
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const parsed = parseCastleWallArgs(argv);
  if (writeCastleWallParseError(parsed, err)) return 2;
  if (parsed.ruleMissingValue) {
    write(err, "Error: --rule requires a rule id (e.g. --rule allow-anthropic, or --rule default-deny).\n");
    return 2;
  }
  const fortressPath = resolveFortressArg(parsed.fortress, env);
  const sinceIso = parsed.since
    ? new Date(Date.now() - parseDurationMs(parsed.since)).toISOString()
    : undefined;

  try {
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const masterKey = await resolveMasterKey(fortressPath, env);
    const queryOpts = {
      ...(sinceIso ? { since: sinceIso } : {}),
      layer: "l1" as const,
      limit: 100_000,
    };
    const auditLog = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
    const query = await auditLog.query(queryOpts);
    const operatorEntries = query.entries.filter(isCastleWallAuditEntry);

    // F2 HIGH-1: include the root daemon's own Castle Wall chain when present +
    // readable; warn INCOMPLETE (never a false green) when it exists but is
    // unreadable at this privilege.
    const daemonView = await collectDaemonCastleWallEntries(
      storage,
      masterKey,
      queryOpts,
    );
    const daemonEntries = daemonView.entries.filter(isCastleWallAuditEntry);
    const daemonPresent = daemonView.status !== "absent";
    if (daemonView.status === "unreadable") {
      write(
        err,
        "WARNING: a root daemon audit store (_audit-daemon) exists but is NOT " +
          "readable at this privilege; this dump is INCOMPLETE (daemon " +
          "enforcement events are omitted). Re-run as root for the full picture.\n",
      );
    } else if (daemonView.status === "tampered") {
      // HIGH-R4: the daemon chain is readable but FAILED integrity verification.
      // Its records are still emitted (for forensic inspection) but MUST be
      // flagged loudly so they are not trusted as verified evidence.
      write(
        err,
        `WARNING: the root daemon audit store (_audit-daemon) has ` +
          `${daemonView.findings.length} integrity finding(s); its records below ` +
          `are TAMPERED / not trustworthy. Do NOT treat them as verified ` +
          `enforcement evidence.\n`,
      );
      for (const f of daemonView.findings.slice(0, 20)) {
        write(err, `  daemon finding: ${f.kind} - ${f.message}\n`);
      }
    }
    // Merge for per-rule attribution (both chains' recorded flows).
    const mergedEntries = [...operatorEntries, ...daemonEntries];

    // Per-rule-per-flow read-out modes (#c4). These attribute each RECORDED flow
    // to the rule that decided it; they do NOT change emission, schema, or
    // enforcement, and they do NOT make the trail tamper-evident (that is the
    // separate, currently-inert producer-signed-audit capability). The rule id
    // shown here is operator-only - this CLI runs in operator context.
    if (parsed.byRule || parsed.rule !== undefined) {
      const flows = attributeFlows(mergedEntries);
      if (parsed.rule !== undefined) {
        const ruleId = normalizeRuleFilter(parsed.rule);
        for (const flow of filterFlowsByRule(flows, ruleId)) {
          write(out, JSON.stringify(flowReportRecord(flow)) + "\n");
        }
        return 0;
      }
      for (const group of groupFlowsByRule(flows)) {
        write(out, JSON.stringify(perRuleGroupRecord(group)) + "\n");
      }
      return 0;
    }

    // Plain dump. When a daemon chain is present at all, tag each record with
    // its source chain (`_chain`) so the two are distinguishable; on the
    // overwhelming (non-migrated) majority the output is byte-identical to
    // before this change (no `_chain` field, operator entries only).
    for (const entry of operatorEntries) {
      write(
        out,
        JSON.stringify(daemonPresent ? { ...entry, _chain: "operator" } : entry) + "\n",
      );
    }
    for (const entry of daemonEntries) {
      write(out, JSON.stringify({ ...entry, _chain: "daemon" }) + "\n");
    }
    return 0;
  } catch (error) {
    write(err, `Error: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

/** The per-basis tally `audit-verify` reports. */
interface AuditVerifyTally {
  verified: number;
  rejected: number;
  channel: number;
  /**
   * Verified-but-duplicate entries: a genuine signed tuple (same seq|signature)
   * re-appended N times. The first copy is counted as `verified`; each extra
   * copy lands here and does NOT inflate `verified`, so N copies of one real
   * enforcement event never read as N distinct verified events.
   */
  duplicates: number;
}

/** Map a re-verification basis into the tally bucket it contributes to. */
function tallyBucketForBasis(basis: EntryReverifyBasis): keyof AuditVerifyTally {
  switch (basis) {
    case "producer_signed_verified":
      return "verified";
    case "producer_signed_rejected":
      return "rejected";
    case "channel_authenticated":
      return "channel";
  }
}

/**
 * Map from the daemon's SIGNED WAL `operation` vocabulary to the read-side
 * `entry.operation` `audit-verify` scopes to. Mirrors `SIGNED_WAL_OP_TO_ENTRY_OP`
 * in `posture.ts` and `SIGNED_WAL_OP_TO_FEATURE_OP` in `feature-health.ts`. Only
 * the two flow-verdict operations matter here (the verb already filters to
 * `egress_allowed` / `egress_blocked`); a signed `egress_pending` body can never
 * match either, so a paused-decision tuple cannot be relabeled into a verdict.
 */
const AUDIT_VERIFY_SIGNED_WAL_OP_TO_ENTRY_OP: Readonly<Record<string, string>> =
  Object.freeze({
    egress_approved: "egress_allowed",
    egress_blocked: "egress_blocked",
  });

/**
 * True iff a re-verified producer-signed entry's SIGNED canonical body attests
 * to the same read-side operation the entry is filed under (parity with the
 * posture / feature-health green-light surfaces). Fail closed on any parse
 * failure / unknown signed op / mismatch: a verified signature over one
 * operation must NOT count toward a DIFFERENT operation's verified tally, so a
 * genuine signed tuple cannot be relabeled under a different top-level operation
 * to inflate or mis-slice the verified count.
 */
function auditVerifySignedOperationMatchesEntry(
  details: Record<string, unknown>,
  entryOperation: string,
): boolean {
  const signedOp = signedCanonicalOperation(details);
  if (signedOp === null) return false;
  return AUDIT_VERIFY_SIGNED_WAL_OP_TO_ENTRY_OP[signedOp] === entryOperation;
}

/**
 * Resolve the pinned audit-producer public key for `audit-verify`, in
 * base64url-no-pad, or `null` when no key is published.
 *
 * Path resolution (single source of truth - never invents a weaker basis):
 *   1. an explicit `--producer-pub-key <path>` override (tests / non-default
 *      layouts), else
 *   2. on macOS, the root-helper-published host-wide key at
 *      `/Library/Application Support/Sanctuary/castle-audit-producer.pub`,
 *      falling back to the fortress path only when the host-wide key is absent,
 *      else
 *   3. the fortress publish path `resolveProducerPubKeyPath(fortressPath)` =
 *      `<fortress>/policy/egress/audit-producer.pub`, which is exactly where the
 *      Linux daemon publishes the key the audit CONSUMER pinned, so the reader
 *      can never diverge onto a different key than the one writes were gated
 *      against.
 *
 * A MISSING key file (ENOENT) is the honest no-key floor: the reader returns
 * `null` and reports every entry on the channel basis - it never fabricates a
 * verified result it cannot check. A PRESENT-but-bad key (wrong length, EACCES)
 * is a fault, not "absent": it throws so the verb fails honestly rather than
 * silently dropping to the channel basis (the Slice P fail-closed contract).
 */
async function resolveAuditVerifyProducerKey(
  fortressPath: string,
  explicitPath: string | undefined,
  opts: {
    platform?: NodeJS.Platform;
    macosProducerPubKeyPath?: string;
  } = {},
): Promise<string | null> {
  if (explicitPath === undefined) {
    const load = await loadFortressProducerKey(fortressPath, {
      platform: opts.platform,
      macosProducerPubKeyPath: opts.macosProducerPubKeyPath,
    });
    if (load.status === "present") return load.keyB64url;
    if (load.status === "absent") return null;
    throw new Error(load.reason);
  }
  const pubKeyPath = explicitPath;
  try {
    return await loadPinnedProducerKeyB64url(pubKeyPath);
  } catch (error) {
    const code =
      error && typeof error === "object" && "code" in error
        ? (error as NodeJS.ErrnoException).code
        : undefined;
    if (code === "ENOENT") {
      // No producer key published: the honest channel-authenticated floor.
      // Not a failure - macOS pre-Slice-M / pre-provision Linux lives here.
      return null;
    }
    // A key file exists but is unreadable / malformed. A key is EXPECTED here,
    // so do NOT pretend it is absent and drop to the channel basis.
    throw error;
  }
}

/**
 * `audit-verify` - the read-side tamper-evidence reader for Castle Wall
 * enforcement evidence (Slice R / Slice M reader leg).
 *
 * Unlike `audit-dump` (which surfaces the RECORDED attribution, including a
 * forgeable `cw_source` marker, and makes NO authenticity claim), this verb
 * CRYPTOGRAPHICALLY RE-VERIFIES each entry's persisted producer signature
 * against the daemon's pinned producer public key. A forger that stamped the
 * `producer_signed` basis + marker but could not mint a signature over the
 * pinned key is REJECTED here; only a signature that re-verifies counts as
 * per-producer-authenticated.
 *
 * It reuses `reverifyEntryProducerSignature()` - the exact same fail-closed
 * gate the posture/feature-health readers run - so the CLI cannot diverge from
 * the live posture surface. Beyond the signature check it applies the SAME two
 * guards those green-light surfaces apply, so a re-verifiable signature alone
 * does not inflate the count: (1) OPERATION BINDING - the signed canonical
 * body's operation must map to the entry's top-level operation, so a genuine
 * signed tuple relabeled under a different operation is REJECTED, not verified;
 * and (2) DEDUP on `seq|signature` - a genuine tuple copied N times counts once
 * (the extras are surfaced as `duplicates`, never as distinct verified events).
 * Without these, an in-process actor holding the AuditLog handle could replay a
 * genuine signed tuple - relabeled and/or duplicated - to mis-slice the count.
 *
 * Honest no-key floor: when no producer key is published (macOS pre-Slice-M,
 * pre-provision Linux), the verb reports every enforcement entry on the
 * `channel_authenticated` basis and explicitly states it could NOT re-verify
 * per-producer signatures. It never fakes a verified count.
 *
 * Exit codes:
 *   0 - read + classification succeeded (this is a DIAGNOSTIC; a present
 *       `rejected` count does NOT change the exit code, so a tamper finding is
 *       reported, not swallowed by a non-zero exit a script might ignore).
 *   1 - could not read the audit log / load an expected-but-broken key.
 */
export async function runAuditVerify(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const parsed = parseCastleWallArgs(argv);
  if (writeCastleWallParseError(parsed, err)) return 2;
  const fortressPath = resolveFortressArg(parsed.fortress, env);
  const sinceIso = parsed.since
    ? new Date(Date.now() - parseDurationMs(parsed.since)).toISOString()
    : undefined;

  try {
    const pinnedProducerKeyB64url = await resolveAuditVerifyProducerKey(
      fortressPath,
      parsed.producerPubKey,
      {
        platform: ctx.platform ?? process.platform,
        macosProducerPubKeyPath: ctx.auditProducerPublicKeyPath,
      },
    );

    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const masterKey = await resolveMasterKey(fortressPath, env);
    const queryOpts = {
      ...(sinceIso ? { since: sinceIso } : {}),
      layer: "l1" as const,
      limit: 100_000,
    };
    const auditLog = new AuditLog(storage, masterKey, {
      integrityMode: "lenient",
    });
    const query = await auditLog.query(queryOpts);
    // Only enforcement-evidence operations carry producer signatures; an
    // operator_decision / policy_loaded / heartbeat entry is never expected to
    // be producer-signed, so re-verifying them would inflate the channel count
    // with entries that were never enforcement evidence. Scope to the two flow
    // verdict operations the consumer signs.
    const isEvidence = (entry: { operation: string }): boolean =>
      entry.operation === "egress_allowed" ||
      entry.operation === "egress_blocked";
    const operatorEvidence = query.entries.filter(isEvidence);

    // F2 HIGH-1: after the writer-split, the LIVE daemon enforcement evidence
    // lives in `_audit-daemon`. Include it when readable; mark the run
    // INCOMPLETE (and refuse to present a zero-count as a clean success) when
    // the daemon chain exists but is unreadable at this privilege.
    const daemonView = await collectDaemonCastleWallEntries(
      storage,
      masterKey,
      queryOpts,
    );
    // HIGH-R4: a `tampered` daemon chain (readable but with integrity findings)
    // is INCOMPLETE coverage too (its evidence is NOT trustworthy), so it is NOT
    // merged into the verified tally and the run is marked incomplete.
    const daemonTampered = daemonView.status === "tampered";
    const daemonEvidence = daemonTampered
      ? []
      : daemonView.entries.filter(isEvidence);
    const daemonIncomplete =
      daemonView.status === "unreadable" || daemonTampered;
    const evidenceEntries = [...operatorEvidence, ...daemonEvidence];

    const tally: AuditVerifyTally = {
      verified: 0,
      rejected: 0,
      channel: 0,
      duplicates: 0,
    };
    const rejectedSamples: Array<{
      timestamp: string;
      operation: string;
      reason: string;
    }> = [];
    // Dedup verified producer-signed entries on `seq|signature` so a genuine
    // tuple copied N times counts once. Mirrors the posture / feature-health
    // green-light surfaces, which already dedup the same way.
    const seenSignedKeys = new Set<string>();
    for (const entry of evidenceEntries) {
      const details = entry.details ?? {};
      const result = reverifyEntryProducerSignature(
        details,
        pinnedProducerKeyB64url,
      );
      // A signature that re-verifies is necessary but not sufficient to count as
      // a distinct verified enforcement event: apply the same operation-binding
      // and dedup guards the sibling green-light surfaces apply, so an in-process
      // actor cannot replay a genuine signed tuple relabeled under a different
      // top-level operation, nor duplicated N times, to inflate the verified
      // tally.
      if (result.basis === "producer_signed_verified") {
        // (1) Operation binding: the signed canonical body's operation is
        // authoritative, not the forgeable top-level `entry.operation`. A
        // mismatch is a relabel attack: count it as REJECTED, not verified.
        if (!auditVerifySignedOperationMatchesEntry(details, entry.operation)) {
          tally.rejected += 1;
          if (rejectedSamples.length < 20) {
            rejectedSamples.push({
              timestamp: entry.timestamp,
              operation: entry.operation,
              reason: "operation mismatch (signed body attests a different operation)",
            });
          }
          continue;
        }
        // (2) Dedup: a genuine tuple copied N times re-verifies identically.
        // Count the first copy as verified; surface the extras as duplicates so
        // they do not read as distinct verified enforcement events. A
        // null/absent dedup key cannot be trusted to be unique, so treat it as a
        // duplicate beyond the first un-keyed entry would be unsound. Instead it
        // simply cannot dedup, so it counts as verified (the inputs that make it
        // verified already required seq+sig present in re-verification).
        const dedupKey = producerSignedDedupKey(details);
        if (dedupKey !== null && seenSignedKeys.has(dedupKey)) {
          tally.duplicates += 1;
          continue;
        }
        if (dedupKey !== null) seenSignedKeys.add(dedupKey);
        tally.verified += 1;
        continue;
      }
      tally[tallyBucketForBasis(result.basis)] += 1;
      if (result.basis === "producer_signed_rejected" && rejectedSamples.length < 20) {
        rejectedSamples.push({
          timestamp: entry.timestamp,
          operation: entry.operation,
          reason: "signature failed re-verification against the pinned key",
        });
      }
    }

    if (parsed.json) {
      write(
        out,
        JSON.stringify({
          fortress: fortressPath,
          producer_key_present: pinnedProducerKeyB64url !== null,
          // The honest basis label for this run: with no pinned key we could
          // only channel-authenticate; with a key we re-verified per-producer.
          reader_basis:
            pinnedProducerKeyB64url !== null
              ? "per_producer_reverified"
              : "channel_authenticated_only",
          // F2 HIGH-1/HIGH-R4: honesty about chain coverage. `complete: false`
          // means a daemon chain exists but was unreadable OR tampered, so this
          // tally OMITS the live daemon enforcement evidence and a green here is
          // NOT a full success claim. `daemon_chain: "tampered"` additionally
          // surfaces the daemon chain's integrity findings.
          daemon_chain: daemonView.status,
          complete: !daemonIncomplete,
          ...(daemonView.status === "tampered"
            ? { daemon_integrity_findings: daemonView.findings }
            : {}),
          enforcement_entries: evidenceEntries.length,
          verified: tally.verified,
          rejected: tally.rejected,
          channel_authenticated: tally.channel,
          // Verified-but-duplicate copies of a genuine signed tuple. Surfaced
          // separately so N copies of one real event never inflate `verified`.
          duplicates: tally.duplicates,
          rejected_samples: rejectedSamples,
        }) + "\n",
      );
      return 0;
    }

    write(out, `Castle Wall audit-verify (fortress ${fortressPath})\n`);
    if (pinnedProducerKeyB64url === null) {
      write(
        out,
        "Producer key: NONE published. Cannot re-verify per-producer signatures.\n" +
          "  Reporting on the channel-authenticated basis only (the honest macOS\n" +
          "  pre-Slice-M / pre-provision Linux floor). A green here is NOT a\n" +
          "  per-producer-authenticated claim.\n",
      );
    } else {
      write(
        out,
        "Producer key: published. Re-verifying each enforcement entry's producer\n" +
          "  signature against the pinned key (the forgeable cw_source marker is NOT\n" +
          "  trusted; the cryptographic signature is the authority).\n",
      );
    }
    if (daemonView.status === "included") {
      write(
        out,
        "Chain coverage: operator + root daemon (_audit-daemon) chains both included.\n",
      );
    } else if (daemonView.status === "tampered") {
      // HIGH-R4: readable but failed integrity verification.
      write(
        err,
        `WARNING: the root daemon audit store (_audit-daemon) has ` +
          `${daemonView.findings.length} integrity finding(s); its enforcement ` +
          `evidence is NOT trustworthy and is EXCLUDED from this tally. This verify ` +
          `is INCOMPLETE: a green here is NOT a full success claim.\n`,
      );
      for (const f of daemonView.findings.slice(0, 20)) {
        write(err, `  daemon finding: ${f.kind} - ${f.message}\n`);
      }
    } else if (daemonIncomplete) {
      write(
        err,
        "WARNING: a root daemon audit store (_audit-daemon) exists but is NOT " +
          "readable at this privilege. This verify is INCOMPLETE: it OMITS the " +
          "daemon's live enforcement evidence. A green / zero-count here is NOT a " +
          "full success claim. Re-run as root to include the daemon chain.\n",
      );
    }
    write(out, `Enforcement entries examined: ${evidenceEntries.length}\n`);
    write(out, `  producer_signed_verified : ${tally.verified}\n`);
    write(out, `  producer_signed_rejected : ${tally.rejected}\n`);
    write(out, `  channel_authenticated    : ${tally.channel}\n`);
    if (tally.duplicates > 0) {
      write(
        out,
        `  duplicates (not counted)  : ${tally.duplicates}\n` +
          "    (genuine signed tuples re-appended; the first copy counts as\n" +
          "     verified, the rest are NOT distinct enforcement events.)\n",
      );
    }
    if (tally.rejected > 0) {
      write(
        err,
        `WARNING: ${tally.rejected} enforcement entr${
          tally.rejected === 1 ? "y" : "ies"
        } CLAIMED producer_signed but did NOT count as verified.\n` +
          "  This is a forgery / tamper signal: either the signature failed to\n" +
          "  re-verify against the pinned producer key, or it re-verified but the\n" +
          "  signed body attests a DIFFERENT operation than the entry was filed\n" +
          "  under (a relabel / staple attack). Neither counts as a verified event.\n",
      );
      for (const sample of rejectedSamples) {
        write(
          err,
          `    rejected: ${sample.timestamp} ${sample.operation} (${sample.reason})\n`,
        );
      }
    }
    return 0;
  } catch (error) {
    write(
      err,
      `Error: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    return 1;
  }
}

/**
 * Resolve a `--rule` filter value to a per-rule-report selector. The default-deny
 * (null-rule) bucket is verbose to type, so the convenience alias
 * `--rule default-deny` selects it, returned here as `null` (the unambiguous
 * null-rule selector `filterFlowsByRule` expects). The raw bucket DISPLAY label
 * (`DEFAULT_DENY_BUCKET`, e.g. "(default-deny: no matching rule)") is NOT an
 * alias: it is returned as a literal rule id, so a real allow/deny rule that
 * happens to be named exactly that can still be selected (the alias must not
 * shadow a literal rule).
 */
function normalizeRuleFilter(value: string): string | null {
  if (value === "default-deny") {
    return null;
  }
  return value;
}

/** Operator-facing JSON shape for a single attributed flow row. */
function flowReportRecord(flow: FlowAttribution): Record<string, unknown> {
  return {
    timestamp: flow.timestamp,
    operation: flow.operation,
    decision: flow.decision,
    // `null` rule_id is rendered honestly as the default-deny bucket label; a
    // real rule is never fabricated for a flow that matched none.
    rule_id: flow.ruleId,
    rule: flow.ruleId ?? DEFAULT_DENY_BUCKET,
    ...(flow.destinationHost !== null
      ? { destination_host: flow.destinationHost }
      : {}),
  };
}

/** Operator-facing JSON shape for a per-rule rollup row. */
function perRuleGroupRecord(group: PerRuleGroup): Record<string, unknown> {
  return {
    rule: group.ruleId,
    default_deny: group.isDefaultDeny,
    total: group.total,
    allow: group.allow,
    deny: group.deny,
    prompt: group.prompt,
    samples: group.samples.map((flow) => ({
      timestamp: flow.timestamp,
      operation: flow.operation,
      decision: flow.decision,
      ...(flow.destinationHost !== null
        ? { destination_host: flow.destinationHost }
        : {}),
    })),
  };
}

/** Filesystem path of the agent-origin descriptor within a fortress. */
function agentOriginDescriptorPath(fortressPath: string): string {
  return join(fortressPath, "policy", "egress", "agent-origin.json");
}

/**
 * Best-effort read of the fortress's agent-origin MODE ("uid" | "nat"), or
 * null when the descriptor is absent, unreadable, or invalid. Used by the
 * no-egress brick guard, which is uid-mode-only: descriptor ABSENCE is
 * already handled (refused or --force-acknowledged) by the origin-descriptor
 * boot-cut guard just above it, so null here means "guard does not apply",
 * never a silent fail-open of a state some other guard owns.
 */
async function readAgentOriginModeBestEffort(
  fortressPath: string,
): Promise<"uid" | "nat" | null> {
  try {
    const validated = await readAgentOriginDescriptorBestEffort(fortressPath);
    if (validated === null) return null;
    return validated.mode === "uid" ? "uid" : "nat";
  } catch {
    return null;
  }
}

async function readAgentOriginDescriptorBestEffort(
  fortressPath: string,
): Promise<ReturnType<typeof validateAgentOrigin>> {
  try {
    const raw = await readFile(agentOriginDescriptorPath(fortressPath), "utf8");
    return validateAgentOrigin(JSON.parse(raw));
  } catch {
    return null;
  }
}

async function readAgentOriginUidBestEffort(fortressPath: string): Promise<number | null> {
  const descriptor = await readAgentOriginDescriptorBestEffort(fortressPath);
  if (descriptor?.mode !== "uid" || descriptor.agent_uid === undefined) return null;
  return descriptor.agent_uid;
}

function asUidSudoPreflightArgv(uid: number): { file: string; args: string[] } {
  if (!Number.isSafeInteger(uid) || uid <= 0) {
    throw new Error(`sudo preflight requires a positive integer uid, got ${String(uid)}`);
  }
  return {
    file: "/usr/bin/sudo",
    args: ["-n", "-u", `#${uid}`, "/usr/bin/true"],
  };
}

function defaultSudoPreflightProbe(uid: number): Promise<SudoPreflightProbeResult> {
  const probe = asUidSudoPreflightArgv(uid);
  return new Promise((resolvePromise) => {
    nodeExecFile(
      probe.file,
      probe.args,
      {
        encoding: "utf8",
        timeout: DENY_ALL_QUARANTINE_PROBE_TIMEOUT_MS,
      },
      (error, _stdout, stderr) => {
        const exitCode = error
          ? typeof error.code === "number"
            ? error.code
            : null
          : 0;
        const stderrText = stderr ?? "";
        const errorText =
          error && exitCode === null ? `${error.name}: ${error.message}` : "";
        const combinedStderr = [stderrText, errorText].filter(Boolean).join("\n");
        resolvePromise({
          ok: exitCode === 0,
          exitCode,
          ...(combinedStderr ? { stderr: combinedStderr } : {}),
          command: [probe.file, ...probe.args],
        });
      },
    );
  });
}

function defaultDenyAllQuarantineProbe(
  input: DenyAllQuarantineProbeInput,
): Promise<DenyAllQuarantineProbeResult> {
  const probe = asUidTlsProbeArgv(input.agentUid, input.host, input.port);
  return new Promise((resolvePromise) => {
    nodeExecFile(
      probe.file,
      probe.args,
      {
        encoding: "utf8",
        timeout: DENY_ALL_QUARANTINE_PROBE_TIMEOUT_MS,
      },
      (error, _stdout, stderr) => {
        const exitCode = error
          ? typeof error.code === "number"
            ? error.code
            : null
          : 0;
        const stderrText = stderr ?? "";
        const errorText =
          error && exitCode === null ? `${error.name}: ${error.message}` : "";
        const combinedStderr = [stderrText, errorText].filter(Boolean).join("\n");
        resolvePromise({
          reachable: asUidProbeReachableDecision(exitCode),
          // Exit 0 or a curl-originated nonzero exit proves sudo reached curl
          // as the target uid. A sudo/spawn/timeout failure is unverified.
          verified:
            exitCode === 0 ||
            (exitCode !== null && /\bcurl: \(\d+\)/.test(combinedStderr)),
          exitCode,
          ...(combinedStderr ? { stderr: combinedStderr } : {}),
          command: [probe.file, ...probe.args],
        });
      },
    );
  });
}

function formatProbeCommand(command: readonly string[] | undefined): string {
  if (command === undefined || command.length === 0) return "(probe command unavailable)";
  return command
    .map((part) => (/^[A-Za-z0-9_./:=@%+#-]+$/.test(part) ? part : JSON.stringify(part)))
    .join(" ");
}

function renderSudoPreflightRefusal(
  uid: number,
  result: SudoPreflightProbeResult,
): string {
  const details = [
    `probe: ${formatProbeCommand(result.command)}`,
    `exit_code: ${result.exitCode === null ? "none" : result.exitCode}`,
    ...(result.stderr?.trim() ? [`stderr: ${result.stderr.trim()}`] : []),
  ].join("\n");
  return (
    `Refusing to arm: a non-interactive sudo credential for the arm probe is unavailable for uid ${uid}.\n` +
    "Run 'sudo -v' to cache your credential (or configure a sudoers rule for the probe), then retry. The wall was not armed.\n" +
    `${details}\n`
  );
}

function renderDenyAllQuarantineProbeRefusal(
  input: DenyAllQuarantineProbeInput,
  result: DenyAllQuarantineProbeResult,
): string {
  const details = [
    `probe: ${formatProbeCommand(result.command)}`,
    `exit_code: ${result.exitCode === null ? "none" : result.exitCode}`,
    ...(result.stderr?.trim() ? [`stderr: ${result.stderr.trim()}`] : []),
  ].join("\n");
  if (!result.verified) {
    return (
      "Castle Wall arm saved by the host app, but the deny-all quarantine smoke could not verify the direct as-uid path.\n" +
      `Expected uid ${input.agentUid} to be unable to reach ${input.host}:${input.port} with --noproxy '*', but the probe itself was inconclusive.\n` +
      `${details}\n` +
      "Treat the quarantine as unverified; run 'sanctuary castle-wall disable' before continuing.\n"
    );
  }
  return (
    "Castle Wall arm saved by the host app, but the deny-all quarantine smoke FAILED.\n" +
    `uid ${input.agentUid} reached ${input.host}:${input.port} on the direct --noproxy path despite ZERO agent-matchable allow rules.\n` +
    `${details}\n` +
    "Treat this as fail-open for the confined uid; run 'sanctuary castle-wall disable' before continuing.\n"
  );
}

/**
 * Count the allow-disposition rules in the fortress's persisted manifest
 * source (`policy/egress/rules/*.json`) that an AGENT-classified flow could
 * ever match (the no-egress brick guard's input; confined-agent egress
 * design section 5 layer 2).
 *
 * Honest scope of "agent-matchable": every on-disk allow rule counts except
 * rules claiming the reserved habeas distress ids (those are scoped to a
 * synthetic agent id no wrapped agent is ever assigned, so they grant the
 * agent nothing). Rules scoped to specific agent_ids/template_ids still
 * count -- this generic guard cannot know the harness's ids (the
 * endpoint-specific static check in the provision flow can, and does).
 * Fail-closed reads: an unreadable directory or an unparseable/invalid rule
 * file contributes ZERO (the enforcing daemon would refuse such a ruleset,
 * so it cannot be the agent's egress path).
 */
export async function countAgentMatchableAllowRules(fortressPath: string): Promise<number> {
  const rulesDir = join(fortressPath, "policy", "egress", "rules");
  let filenames: string[];
  try {
    filenames = (await readdir(rulesDir)).filter((name) => name.endsWith(".json"));
  } catch {
    return 0;
  }
  return (await listAgentMatchableAllowRuleFiles(rulesDir, filenames)).length;
}

/**
 * Strict uid/ceiling flag parse (shared chokepoint for `--agent-uid` /
 * `--ceiling` in BOTH `configure-origin` and the `enable` fold-in). Returns a
 * number ONLY when the ENTIRE string is decimal digits; anything else returns
 * null so the caller fails closed. `parseInt` is NOT usable here: it silently
 * truncates, so `parseInt("501abc",10)===501`, `parseInt("502.9",10)===502`,
 * `parseInt("1e10",10)===1` - each a WRONG-but-plausible uid that could fail
 * OPEN (leave the agent unconfined) or cut a system daemon. Rejecting the whole
 * token is the only safe read of an operator-supplied uid.
 */
function parseUidFlag(value: string): number | null {
  if (!/^\d+$/.test(value)) {
    return null;
  }
  const n = Number(value);
  return Number.isSafeInteger(n) ? n : null;
}

/**
 * Shared build+validate+write path for the agent-origin descriptor (DRY
 * chokepoint used by BOTH `configure-origin` and `enable --agent-uid`; do not
 * copy-paste this logic into a second call site). Validates the candidate via
 * {@link validateAgentOrigin} BEFORE writing anything - a structurally invalid
 * candidate (e.g. uid mode missing `agent_uid`) is rejected and nothing is
 * written or overwritten on disk, preserving the fail-closed invariant that a
 * half-built descriptor must never reach the filesystem (see the file-level
 * doc comment in `agent-origin.ts`).
 */
async function writeAgentOriginDescriptor(
  fortressPath: string,
  candidate: Record<string, unknown>,
  owner?: { uid: number; gid: number },
): Promise<
  | { ok: true; validated: ReturnType<typeof validateAgentOrigin> & object; path: string }
  | { ok: false; error: string }
> {
  const validated = validateAgentOrigin(candidate);
  if (validated === null) {
    return {
      ok: false,
      error:
        "agent-origin descriptor is invalid (uid mode requires agent_uid a positive integer >= the ceiling; root/0 and sub-ceiling uids are rejected).",
    };
  }

  const originPath = agentOriginDescriptorPath(fortressPath);
  try {
    await writeFileCustody(originPath, JSON.stringify(validated, null, 2) + "\n", {
      mode: 0o600,
      parentMode: 0o700,
      ...(owner !== undefined ? { owner, ownerBase: fortressPath } : {}),
    });
    return { ok: true, validated, path: originPath };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export async function runConfigureOrigin(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {}
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const parsed = parseCastleWallArgs(argv);
  if (writeCastleWallParseError(parsed, err)) return 2;
  const fortressPath = resolveFortressArg(parsed.fortress, env);

  // Parse remaining positional args: configure-origin <mode> [options]
  // Usage:
  //   castle-wall configure-origin uid --agent-uid=502 [--ceiling=500]
  //   castle-wall configure-origin nat --signing-id=ai.sanctuaryprotocol.egress-helper [--team-id=YFQSWQ9BJN] [--ceiling=500]
  const modeArg = argv.find((a) => a === "uid" || a === "nat");
  if (!modeArg) {
    write(err, "Usage: castle-wall configure-origin <uid|nat> [options]\n");
    write(err, "  uid mode: --agent-uid=<uid> [--ceiling=<uid>]\n");
    write(err, "  nat mode: --signing-id=<id> [--team-id=<id>] [--ceiling=<uid>]\n");
    return 2;
  }

  const getFlag = (name: string): string | undefined => {
    const prefix = `--${name}=`;
    const match = argv.find((a) => a.startsWith(prefix));
    return match ? match.slice(prefix.length) : undefined;
  };

  // Strict parse (no truncation) of --ceiling; applies to both modes.
  const ceilingStr = getFlag("ceiling") ?? "500";
  const ceiling = parseUidFlag(ceilingStr);
  if (ceiling === null) {
    write(err, `Error: --ceiling must be a plain non-negative integer, got '${ceilingStr}'.\n`);
    return 1;
  }

  const candidate: Record<string, unknown> = {
    mode: modeArg,
    system_uid_allow_ceiling: ceiling,
  };

  if (modeArg === "uid") {
    const uidStr = getFlag("agent-uid");
    if (!uidStr) {
      write(err, "Error: uid mode requires --agent-uid=<uid>\n");
      return 2;
    }
    // Strict parse (no truncation): a wrong-but-plausible uid can fail open or
    // cut a system daemon. The semantic floor (>= 1 and >= ceiling) is enforced
    // in validateAgentOrigin (the shared chokepoint) via writeAgentOriginDescriptor.
    const agentUid = parseUidFlag(uidStr);
    if (agentUid === null) {
      write(err, `Error: --agent-uid must be a plain positive integer, got '${uidStr}'.\n`);
      return 1;
    }
    candidate.agent_uid = agentUid;
  } else {
    const signingId = getFlag("signing-id");
    const teamId = getFlag("team-id");
    if (!signingId && !teamId) {
      write(err, "Error: nat mode requires --signing-id=<id> and/or --team-id=<id>\n");
      return 2;
    }
    if (signingId) candidate.egress_helper_signing_id = signingId;
    if (teamId) candidate.egress_helper_team_id = teamId;
    const portRange = getFlag("port-range");
    if (portRange) {
      const parts = portRange.split("-").map(Number);
      if (parts.length === 2) candidate.agent_runtime_port_range = parts;
    }
  }

  const result = await writeAgentOriginDescriptor(fortressPath, candidate);
  if (!result.ok) {
    write(err, `Error: ${result.error}\n`);
    return 1;
  }

  write(out, `Agent origin configured: mode=${result.validated.mode}\n`);
  write(out, `Written to: ${result.path}\n`);
  write(out, "Run 'sanctuary castle-wall reload' to apply.\n");
  return 0;
}

const HOST_APP_RELATIVE_BINARY =
  "Sanctuary-CastleWall.app/Contents/MacOS/CastleWallHostApp";

function defaultHostAppCandidates(env: NodeJS.ProcessEnv): string[] {
  const home = env.HOME ?? homedir();
  return [
    `/Applications/${HOST_APP_RELATIVE_BINARY}`,
    `${home}/Applications/${HOST_APP_RELATIVE_BINARY}`,
  ];
}

/**
 * True iff `path` is an existing regular file owned by root or the current
 * user (mirrors SanctuaryServerBridge.isOwnerTrustedExecutable on the Swift
 * side): prevents invoking a binary an attacker dropped at a probed path.
 */
async function isOwnerTrustedExecutable(
  path: string,
  getuid: (() => number) | undefined,
  env: NodeJS.ProcessEnv = process.env,
): Promise<boolean> {
  try {
    const info = await stat(path);
    if (!info.isFile()) return false;
    const uid = getuid?.();
    const trusted = new Set<number>([0]);
    if (uid !== undefined) {
      trusted.add(uid);
      if (uid === 0 && env.SUDO_UID !== undefined && /^\d+$/.test(env.SUDO_UID)) {
        const sudoUid = Number(env.SUDO_UID);
        if (Number.isSafeInteger(sudoUid) && sudoUid > 0) {
          trusted.add(sudoUid);
        }
      }
    }
    return trusted.has(info.uid);
  } catch {
    return false;
  }
}

/**
 * Resolve the Castle Wall host-app binary that owns the NE filter
 * configuration. Only that signed binary can toggle the filter without
 * re-triggering the one-time consent, so this is the single arming surface.
 * SANCTUARY_CASTLE_HOSTAPP overrides; an invalid override fails loud rather
 * than silently falling through to a different binary.
 */
async function resolveHostAppBinary(
  env: NodeJS.ProcessEnv,
  ctx: CastleWallCommandContext,
): Promise<{ path: string } | { error: string }> {
  const getuid = ctx.getuid ?? process.getuid?.bind(process);
  const override = env.SANCTUARY_CASTLE_HOSTAPP;
  if (override) {
    if (await isOwnerTrustedExecutable(override, getuid, env)) {
      return { path: override };
    }
    return {
      error: `SANCTUARY_CASTLE_HOSTAPP is set but does not point at a trusted executable: ${override}`,
    };
  }
  const candidates = ctx.hostAppCandidates ?? defaultHostAppCandidates(env);
  for (const candidate of candidates) {
    if (await isOwnerTrustedExecutable(candidate, getuid, env)) {
      return { path: candidate };
    }
  }
  return {
    error:
      "Castle Wall app not found (looked in /Applications and ~/Applications). " +
      "Install Sanctuary-CastleWall.app or set SANCTUARY_CASTLE_HOSTAPP to its " +
      `Contents/MacOS/CastleWallHostApp binary.`,
  };
}

function makeHostAppInvoke(timeoutMs: number): HostAppInvoker {
  return (binaryPath, args) =>
    new Promise((resolvePromise) => {
      nodeExecFile(
        binaryPath,
        args,
        { encoding: "utf8", timeout: timeoutMs },
        (error, stdout, stderr) => {
          let exitCode = 0;
          let stderrOut = stderr ?? "";
          if (error) {
            exitCode =
              typeof error.code === "number"
                ? error.code
                : // Spawn failure (ENOENT/EACCES/timeout kill): no exit code exists.
                  -1;
            if (error.killed && !stderrOut.trim()) {
              stderrOut = `host app did not respond within ${timeoutMs}ms`;
            }
          }
          resolvePromise({ stdout: stdout ?? "", stderr: stderrOut, exitCode });
        },
      );
    });
}

/**
 * Resolve the `.app` bundle directory from a path to the binary inside it
 * (`…/Sanctuary-CastleWall.app/Contents/MacOS/CastleWallHostApp` →
 * `…/Sanctuary-CastleWall.app`). `open` launches bundles, not the inner
 * executable. Falls back to the input when no `.app` component is present
 * (e.g. an SANCTUARY_CASTLE_HOSTAPP override pointing at a bare binary).
 */
function resolveAppBundlePath(binaryPath: string): string {
  const marker = ".app/";
  // cli-argv-indexof-allowed: scans a filesystem path string, not CLI argv tokens.
  const idx = binaryPath.indexOf(marker);
  if (idx >= 0) return binaryPath.slice(0, idx + ".app".length);
  return binaryPath;
}

function defaultReportPath(): string {
  return join(tmpdir(), `sanctuary-cw-report-${nodeRandomBytes(16).toString("hex")}.json`);
}

export interface LaunchServicesInvokerOptions {
  timeoutMs: number;
  /** Test seam: run `open` (or a double). Defaults to a real `execFile`. */
  openRunner?: OpenRunner;
  /** Test seam: where the host app writes its report. Defaults to a random temp path. */
  reportPathFactory?: () => string;
  /** Test seam: detect/terminate an already-running GUI app before `open -W`. */
  runningAppController?: RunningAppController;
}

/**
 * Host-app invoker that routes through LaunchServices (`open -n -W`) instead of
 * directly exec'ing the binary. On macOS Tahoe a directly-exec'd binary cannot
 * reach NE preferences (`loadFromPreferences` hangs indefinitely); only a
 * LaunchServices-launched app instance can. Because `open` does not relay the
 * child's stdout, the host app also writes its single JSON report line to a
 * caller-supplied `--report-file`; this invoker reads it back, derives an exit
 * code from the report, and returns it in the same shape as the direct invoker.
 *
 * Fail-closed: a missing, empty, or unparseable report file yields a generic
 * failure (exit 1) - never a silent success.
 */
export function makeLaunchServicesHostAppInvoke(
  opts: LaunchServicesInvokerOptions,
): HostAppInvoker {
  const openRunner = opts.openRunner ?? makeDefaultOpenRunner(opts.timeoutMs);
  const reportPathFactory = opts.reportPathFactory ?? defaultReportPath;
  const runningAppController =
    opts.runningAppController ?? makeDefaultRunningAppController();
  return async (binaryPath, args) => {
    const appBundle = resolveAppBundlePath(binaryPath);
    const reportPath = reportPathFactory();
    const processName = binaryPath.split("/").pop() || "CastleWallHostApp";
    let preflight = "";
    if (await runningAppController.isRunning(processName)) {
      const terminated = await runningAppController.terminate(processName);
      if (!terminated) {
        return {
          stdout: "",
          stderr:
            `Castle Wall host app is already running (${processName}) and could not be terminated for headless LaunchServices mode. ` +
            "Quit Sanctuary-CastleWall.app at the console or retry after it exits.",
          exitCode: 1,
        };
      }
      preflight =
        `Castle Wall host app is already running (${processName}); terminating it and relaunching headlessly with the same signed app consent.\n`;
    }
    const openArgs = [
      "-n",
      "-W",
      appBundle,
      "--args",
      ...args,
      `--report-file=${reportPath}`,
    ];

    let openResult: { stdout: string; stderr: string; exitCode: number };
    try {
      openResult = await openRunner("open", openArgs);
    } catch (error) {
      openResult = {
        stdout: "",
        stderr: error instanceof Error ? error.message : String(error),
        exitCode: -1,
      };
    }

    let raw: string;
    try {
      raw = await readFile(reportPath, "utf8");
    } catch {
      raw = "";
    } finally {
      await unlink(reportPath).catch(() => undefined);
    }

    if (!raw.trim()) {
      const reason = openResult.stderr.trim()
        ? `: ${openResult.stderr.trim()}`
        : "";
      return {
        stdout: "",
        stderr:
          `Castle Wall host app produced no report (open exit ${openResult.exitCode}${reason}). ` +
          "On macOS Tahoe, confirm the Castle Wall system extension is toggled on in " +
          "System Settings > General > Login Items & Extensions > Network Extensions.",
        exitCode: 1,
      };
    }

    const report = parseHeadlessReport(raw);
    if (!report) {
      return {
        stdout: raw,
        stderr: "Castle Wall host app report was unparseable.",
        exitCode: 1,
      };
    }

    const exitCode =
      report.state === "needs_user_approval"
        ? HEADLESS_EXIT_NEEDS_APPROVAL
        : report.ok
          ? 0
          : 1;
    return { stdout: raw, stderr: preflight, exitCode };
  };
}

function makeDefaultRunningAppController(): RunningAppController {
  const execFile = (command: string, args: string[], timeoutMs: number) =>
    new Promise<{ exitCode: number }>((resolvePromise) => {
      nodeExecFile(command, args, { timeout: timeoutMs }, (error) => {
        if (!error) {
          resolvePromise({ exitCode: 0 });
          return;
        }
        resolvePromise({
          exitCode: typeof error.code === "number" ? error.code : -1,
        });
      });
    });

  return {
    async isRunning(processName) {
      const result = await execFile("pgrep", ["-x", processName], 2_000);
      return result.exitCode === 0;
    },
    async terminate(processName) {
      await execFile("pkill", ["-TERM", "-x", processName], 2_000);
      const deadline = Date.now() + 5_000;
      while (Date.now() < deadline) {
        if (!(await this.isRunning(processName))) return true;
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
      }
      return !(await this.isRunning(processName));
    },
  };
}

function makeDefaultOpenRunner(timeoutMs: number): OpenRunner {
  return (command, args) =>
    new Promise((resolvePromise) => {
      nodeExecFile(
        command,
        args,
        { encoding: "utf8", timeout: timeoutMs },
        (error, stdout, stderr) => {
          let exitCode = 0;
          let stderrOut = stderr ?? "";
          if (error) {
            exitCode = typeof error.code === "number" ? error.code : -1;
            if (error.killed && !stderrOut.trim()) {
              stderrOut = `open did not return within ${timeoutMs}ms`;
            }
          }
          resolvePromise({ stdout: stdout ?? "", stderr: stderrOut, exitCode });
        },
      );
    });
}

/**
 * Default arm/disarm invoker. LaunchServices-routed so it survives macOS Tahoe
 * (see makeLaunchServicesHostAppInvoke). The direct-exec makeHostAppInvoke is
 * retained for the read-only status probe and pre-Tahoe paths.
 */
const ARM_INVOKE_TIMEOUT_MS = 90_000;
const DISARM_INVOKE_TIMEOUT_MS = 7_000;
const DEACTIVATE_SYSTEM_EXTENSION_TIMEOUT_MS = 90_000;

/**
 * `launchctl managername` output naming the console GUI (Aqua) session.
 * Must match the value the probe in defaultSessionManagerNameProbe compares
 * against; any other manager ("Background" over SSH, "System" in root/daemon
 * contexts) means there is no Aqua domain for LaunchServices to launch into.
 */
const LAUNCHD_GUI_SESSION_MANAGER = "Aqua";
/**
 * `launchctl managername` is a local, non-network read of the calling
 * session's launchd manager; 2s matches the pgrep/pkill probe budget in
 * makeDefaultRunningAppController (same class of local process query).
 */
const SESSION_MANAGER_PROBE_TIMEOUT_MS = 2_000;

function defaultSessionManagerNameProbe(): Promise<string | null> {
  return new Promise((resolvePromise) => {
    nodeExecFile(
      "/bin/launchctl",
      ["managername"],
      { encoding: "utf8", timeout: SESSION_MANAGER_PROBE_TIMEOUT_MS },
      (error, stdout) => {
        if (error) {
          resolvePromise(null);
          return;
        }
        const name = (stdout ?? "").trim();
        resolvePromise(name.length > 0 ? name : null);
      },
    );
  });
}

/**
 * Session-aware invoker for the protection-DECREASING host-app verbs (disable
 * and deactivate-system-extension) only; the enable/arm path stays purely
 * LaunchServices-routed and is deliberately untouched.
 *
 * LaunchServices stays primary in a console GUI (Aqua) session: on macOS Tahoe
 * a directly-exec'd binary's `NEFilterManager.loadFromPreferences` hangs there
 * (Mini1 Tahoe drill 2026-06-10, finding 1; see OpenRunner). With NO GUI
 * session there is no Aqua domain at all, so `open -n -W` fails before the
 * host app ever runs (observed on hardware: RBSRequestErrorDomain 5 /
 * OSLaunchdErrorDomain 125, D5 drill 2026-08-25) and the shipped disarm and
 * uninstall could never complete from an SSH/agent session. In that case this
 * falls back to direct exec of the SAME resolved signed binary with the SAME
 * argv, whose output flows through the same parseHeadlessReport +
 * validateHeadlessBuildIdentity checks as the LaunchServices round-trip, so
 * the trust chain is unchanged - only the launch transport differs. Direct
 * exec was proven to reach NE preferences headlessly on hardware in the same
 * D5 drill. Fail-safe: a failed or empty probe keeps LaunchServices (the
 * shipped primary), whose failure output the callers surface verbatim.
 */
function makeSessionAwareDisarmInvoke(
  ctx: CastleWallCommandContext,
  timeoutMs: number,
): HostAppInvoker {
  const launchServicesInvoke = makeLaunchServicesHostAppInvoke({
    timeoutMs,
    ...(ctx.openRunner ? { openRunner: ctx.openRunner } : {}),
    ...(ctx.reportPathFactory ? { reportPathFactory: ctx.reportPathFactory } : {}),
    ...(ctx.runningAppController
      ? { runningAppController: ctx.runningAppController }
      : {}),
  });
  const directInvoke = ctx.directHostAppInvoke ?? makeHostAppInvoke(timeoutMs);
  const probe = ctx.sessionManagerNameProbe ?? defaultSessionManagerNameProbe;
  return async (binaryPath, args) => {
    const managerName = await probe();
    // The fallback engages only on a POSITIVE non-Aqua determination; an
    // indeterminate probe must not reroute the shipped primary transport.
    if (managerName !== null && managerName.trim() !== LAUNCHD_GUI_SESSION_MANAGER) {
      return directInvoke(binaryPath, args);
    }
    return launchServicesInvoke(binaryPath, args);
  };
}

function defaultArmInvoke(ctx: CastleWallCommandContext, action: "enable" | "disable"): HostAppInvoker {
  if (action === "disable") {
    // Disarm is the dead-man recovery lever and must work from a headless
    // (SSH/agent) session, where LaunchServices cannot launch anything.
    return makeSessionAwareDisarmInvoke(ctx, DISARM_INVOKE_TIMEOUT_MS);
  }
  return makeLaunchServicesHostAppInvoke({
    timeoutMs: ARM_INVOKE_TIMEOUT_MS,
    ...(ctx.openRunner ? { openRunner: ctx.openRunner } : {}),
    ...(ctx.reportPathFactory ? { reportPathFactory: ctx.reportPathFactory } : {}),
    ...(ctx.runningAppController
      ? { runningAppController: ctx.runningAppController }
      : {}),
  });
}

export type SystemExtensionDeactivationRequestOutcome =
  | { kind: "request-completed" }
  | { kind: "reboot-required" }
  | { kind: "needs-user-approval"; detail: string }
  | { kind: "failed"; detail: string };

/**
 * Ask the deployed signed host app to deactivate its bundled system
 * extension. This function deliberately proves only the REQUEST outcome;
 * callers must independently observe system-extension absence before they
 * claim removal, because macOS may defer completion until reboot.
 */
export async function requestSystemExtensionDeactivation(
  ctx: CastleWallCommandContext = {},
): Promise<SystemExtensionDeactivationRequestOutcome> {
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;
  if (platform !== "darwin") {
    return { kind: "failed", detail: "system-extension deactivation is macOS-only" };
  }

  const resolved = await resolveHostAppBinary(env, ctx);
  if ("error" in resolved) {
    return { kind: "failed", detail: resolved.error };
  }

  // Session-aware for the same reason as disarm: headlessly there is no Aqua
  // domain, so a LaunchServices launch fails before the deactivation request
  // is even submitted, and the host app's real answer (including
  // needs_user_approval) never reaches the operator. Direct exec of the same
  // signed binary surfaces it (D5 drill 2026-08-25).
  const invoke =
    ctx.hostAppInvoke ??
    makeSessionAwareDisarmInvoke(ctx, DEACTIVATE_SYSTEM_EXTENSION_TIMEOUT_MS);
  const cliGitSha = resolveCliBuildSha(env, ctx);

  // The signed host refuses deactivation while the filter is enabled too,
  // but the CLI checks first so no destructive request is even submitted
  // when the disarm postcondition is not positively observed.
  const statusResult = await invoke(resolved.path, ["--headless", "status"]);
  const statusReport = parseHeadlessReport(statusResult.stdout);
  if (!statusReport) {
    return {
      kind: "failed",
      detail:
        statusResult.stderr.trim() ||
        `host app status exited with code ${statusResult.exitCode}`,
    };
  }
  const statusBuildMismatch = validateHeadlessBuildIdentity(statusReport, cliGitSha);
  if (statusBuildMismatch) {
    return { kind: "failed", detail: statusBuildMismatch };
  }
  if (statusReport.state !== "disabled") {
    return {
      kind: "failed",
      detail: `content filter state is '${statusReport.state}', not positively observed disabled`,
    };
  }

  const result = await invoke(resolved.path, [
    "--headless",
    "deactivate-system-extension",
    "--timeout=60",
  ]);
  const report = parseHeadlessReport(result.stdout);
  if (!report) {
    return {
      kind: "failed",
      detail:
        result.stderr.trim() ||
        `host app deactivation exited with code ${result.exitCode}`,
    };
  }
  const buildMismatch = validateHeadlessBuildIdentity(report, cliGitSha);
  if (buildMismatch) {
    return { kind: "failed", detail: buildMismatch };
  }
  if (report.state === "needs_user_approval") {
    return {
      kind: "needs-user-approval",
      detail: report.error ?? "macOS requires operator approval",
    };
  }
  if (!report.ok || result.exitCode !== 0) {
    return {
      kind: "failed",
      detail:
        report.error ??
        (result.stderr.trim() ||
          `host app deactivation exited with code ${result.exitCode}`),
    };
  }
  if (report.state === "will_complete_after_reboot") {
    return { kind: "reboot-required" };
  }
  if (report.state === "deactivated") {
    return { kind: "request-completed" };
  }
  return {
    kind: "failed",
    detail: `host app returned unexpected deactivation state '${report.state}'`,
  };
}

/**
 * `status` is a read-only quick check; never let it hang behind a wedged
 * NE-preferences read (observed: --headless status can stall minutes on a
 * host where the filter configuration is in a bad state). 10s is orders of
 * magnitude above the healthy-path latency (~0.1s).
 */
const STATUS_PROBE_TIMEOUT_MS = 10_000;

function parseHeadlessReport(stdout: string): HeadlessReport | null {
  const lines = stdout
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  const last = lines[lines.length - 1];
  if (!last) return null;
  try {
    const parsed = JSON.parse(last) as Partial<HeadlessReport>;
    if (typeof parsed.ok !== "boolean" || typeof parsed.state !== "string") {
      return null;
    }
    return parsed as HeadlessReport;
  } catch {
    return null;
  }
}

function resolveCliBuildSha(
  env: NodeJS.ProcessEnv,
  ctx: CastleWallCommandContext,
): string {
  const envSha =
    env.SANCTUARY_CASTLE_BUILD_SHA ?? env.SANCTUARY_CASTLE_CLI_BUILD_SHA;
  if (envSha?.trim()) return envSha.trim();

  const execSyncFn =
    ctx.execSyncFn ??
    ((command: string) =>
      nodeExecSync(`sh -lc '${command.replace(/'/g, "'\\''")}'`, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim());
  try {
    const sha = execSyncFn("git rev-parse --short=12 HEAD").trim();
    return sha || "unknown";
  } catch {
    return "unknown";
  }
}

function validateHeadlessBuildIdentity(
  report: HeadlessReport,
  cliGitSha: string,
): string | null {
  const appBuild = report.build;
  if (
    !appBuild ||
    typeof appBuild.git_sha !== "string" ||
    typeof appBuild.headless_contract_version !== "string"
  ) {
    return (
      "deployed Castle Wall app did not report a headless build identity; " +
      "rebuild + redeploy the signed app before using headless enable/disable."
    );
  }
  if (
    appBuild.headless_contract_version !== CASTLE_WALL_HEADLESS_CONTRACT_VERSION
  ) {
    return (
      `deployed app headless contract ${appBuild.headless_contract_version} ` +
      `!= CLI ${CASTLE_WALL_HEADLESS_CONTRACT_VERSION}; rebuild + redeploy the signed app.`
    );
  }
  if (appBuild.git_sha !== cliGitSha) {
    return (
      `deployed app ${appBuild.git_sha} != CLI ${cliGitSha} - rebuild + redeploy the signed app. ` +
      `(The CLI SHA comes from SANCTUARY_CASTLE_BUILD_SHA or, if unset, 'git rev-parse HEAD' in the ` +
      `current working directory - NOT the binary. If you are running from a git worktree whose HEAD ` +
      `differs from the deployed app, run outside a repo or 'export SANCTUARY_CASTLE_BUILD_SHA=${appBuild.git_sha}'.)`
    );
  }
  return null;
}

export function defaultDaemonProbe(socketPath: string): Promise<boolean> {
  return new Promise((resolvePromise) => {
    let settled = false;
    const socket = createConnection(socketPath);
    const finish = (reachable: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolvePromise(reachable);
    };
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
    setTimeout(() => finish(false), 1_500).unref();
  });
}

/**
 * Best-effort audit record for a CLI arm/disarm. Never blocks the operation:
 * disarm especially is the dead-man recovery lever and must not depend on a
 * decryptable audit log (the authoritative filter_started/filter_stopped
 * events come from the daemon path). A failed write degrades to a warning.
 */
/**
 * Best-effort CLI-side Castle Wall audit append (shared chokepoint): opens
 * the fortress audit log with the resolved master key, writes ONE entry with
 * the given operation string, and warns (never throws) when the write cannot
 * complete. Used by the arm/disarm audit below and by the confined-agent
 * egress flow's `egress_provisioned` / `egress_provision_refused` records
 * (distinct LOCAL operation values, never a widened shared enum).
 */
export async function appendCastleWallCliAuditBestEffort(
  operation: string,
  details: Record<string, unknown>,
  fortressPath: string,
  env: NodeJS.ProcessEnv,
  err: Writable,
): Promise<void> {
  try {
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const masterKey = await resolveMasterKey(fortressPath, env);
    const auditLog = new AuditLog(storage, masterKey);
    await auditLog.append(
      "l1",
      operation,
      fortressIdFromStoragePath(fortressPath),
      details,
      "success",
    );
    await auditLog.flush();
    masterKey.fill(0);
  } catch (error) {
    write(
      err,
      `Warning: the '${operation}' audit entry could not be written (${
        error instanceof Error ? error.message : String(error)
      }). Corroborate via 'sanctuary castle-wall audit-dump' once the fortress key is available.\n`,
    );
  }
}

async function appendArmAuditBestEffort(
  action: "enable" | "disable",
  verifiedState: string,
  forced: boolean,
  fortressPath: string,
  env: NodeJS.ProcessEnv,
  err: Writable,
  extraDetails: Record<string, unknown> = {},
): Promise<void> {
  await appendCastleWallCliAuditBestEffort(
    action === "enable" ? "wall_armed" : "wall_disarmed",
    {
      source: "castle-wall-cli",
      action,
      verified_state: verifiedState,
      forced,
      ...extraDetails,
      [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    },
    fortressPath,
    env,
    err,
  );
}

function leaseStatusPath(fortressPath: string): string {
  return join(fortressPath, "castle-wall-lease.json");
}

async function writeLeaseStatusBestEffort(
  fortressPath: string,
  lease: LeaseStatusFile,
): Promise<void> {
  try {
    // SECURITY (2026-07-31 gate round 3): this used a plain `writeFile` +
    // PATHNAME `chmod`. Under `sudo enable|disable` that runs AS ROOT, so a
    // same-uid actor who pre-created `castle-wall-lease.json` as a symlink
    // made root write through it and chmod the outside target. `writeFileCustody`
    // creates an O_EXCL|O_NOFOLLOW temp file, chmods the DESCRIPTOR, and
    // atomically renames, so no pathname write or chmod ever follows a link.
    await writeFileCustody(
      leaseStatusPath(fortressPath),
      JSON.stringify(lease, null, 2) + "\n",
      { mode: 0o600, createParent: false },
    );
  } catch {
    // Advisory-only status surface; enforcement rides authenticated IPC.
  }
}

async function readLeaseStatus(fortressPath: string): Promise<LeaseStatusFile | null> {
  try {
    const parsed = JSON.parse(await readFile(leaseStatusPath(fortressPath), "utf8")) as LeaseStatusFile;
    if (
      typeof parsed.armed !== "boolean" ||
      typeof parsed.heartbeat_interval_seconds !== "number" ||
      typeof parsed.updated_at !== "string"
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function buildArmLeaseMessage(input: {
  armed: boolean;
  revoked?: boolean;
  ttlSeconds: number | null;
  heartbeatIntervalSeconds?: number;
}): LeaseStatusFile & { type: "arm_lease" } {
  return {
    type: "arm_lease",
    armed: input.armed,
    ...(input.revoked === true ? { revoked: true } : {}),
    ttl_seconds: input.ttlSeconds,
    heartbeat_interval_seconds: input.heartbeatIntervalSeconds ?? 5,
    updated_at: new Date().toISOString(),
    source: "castle-wall-cli",
  };
}

async function sendArmLeaseBestEffort(
  socketPath: string,
  message: ReturnType<typeof buildArmLeaseMessage>,
): Promise<boolean> {
  return await new Promise<boolean>((resolvePromise) => {
    const socket = createConnection(socketPath);
    let settled = false;
    const finish = (ok: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolvePromise(ok);
    };
    const timer = setTimeout(() => finish(false), 1_500);
    timer.unref();
    socket.once("connect", () => {
      socket.write(frame(JSON.stringify({
        jsonrpc: "2.0",
        method: "castle-wall.arm_lease",
        params: message,
      })), () => finish(true));
    });
    socket.once("error", () => finish(false));
  });
}

const NEEDS_APPROVAL_GUIDANCE =
  "The one-time macOS content-filter consent has not been granted on this machine.\n" +
  "That single step is GUI-only (macOS requirement): at the console, launch\n" +
  "Sanctuary-CastleWall.app once and click Allow on the content-filter prompt.\n" +
  "After that, every arm/disarm works headlessly.\n";

const SYSEXT_DISABLED_GUIDANCE =
  "The Castle Wall system extension is installed but toggled OFF.\n" +
  "On macOS Tahoe the extension ships disabled and needs a one-time console\n" +
  "toggle (GUI-only, macOS requirement): at the console, open\n" +
  "System Settings > General > Login Items & Extensions > Network Extensions\n" +
  "and switch Castle Wall on. After that, every arm/disarm works headlessly.\n";

/**
 * Probe the Castle Wall system-extension state via `systemextensionsctl`.
 * Failure (binary missing, e.g. non-macOS CI) degrades to "not loaded" so the
 * caller proceeds rather than blocking on an undetectable state.
 */
async function defaultSysextProbe(
  ctx: CastleWallCommandContext,
): Promise<SysextState> {
  const execSyncFn =
    ctx.execSyncFn ??
    ((command: string) =>
      nodeExecSync(`sh -lc '${command.replace(/'/g, "'\\''")}'`, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim());
  try {
    const raw = execSyncFn(
      "systemextensionsctl list 2>/dev/null | grep castle-wall",
    );
    return parseCastleWallState(raw);
  } catch {
    return "not loaded";
  }
}

function describeUnknownError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function readSysextStateForArmClaim(
  sysextProbe: () => Promise<SysextState>,
): Promise<SysextArmClaimObservation> {
  try {
    return { state: await sysextProbe() };
  } catch (error) {
    return { state: "unreadable", reason: describeUnknownError(error) };
  }
}

async function observeArmClaimBasis(
  storagePath: string,
  platform: NodeJS.Platform,
  ctx: CastleWallCommandContext,
  sysextProbe: () => Promise<SysextState>,
): Promise<ObservedArmClaimObservationBasis> {
  return observing(
    "castle-wall-cli.content-filter-enabled",
    async () => ({
      sysext: await readSysextStateForArmClaim(sysextProbe),
      enforcementAvailability: await readEnforcementAvailabilityForStatus(
        storagePath,
        platform,
        ctx,
      ),
    }),
    ["sysext", "enforcementAvailability"],
  );
}

function renderVerifiedArmClaimLine(
  basis: ObservedArmClaimObservationBasis,
): string | undefined {
  if (
    basis.sysext.state !== "[activated enabled]" ||
    basis.enforcementAvailability.status !== "live"
  ) {
    return undefined;
  }
  return "Castle Wall armed: content filter enabled (verified via host-app status, system extension state, and enforcement availability).\n";
}

function renderArmAvailabilityRemedyLine(
  availability: ResolvedEnforcementAvailability,
): string {
  if (
    availability.reason === "lease:heartbeat_stopped" ||
    availability.reason === "lease:arm_lease_missing"
  ) {
    return (
      "Remedy: restart the root Castle Wall boot daemon, then re-run enable: " +
      `sudo launchctl kickstart -k system/${CASTLE_WALL_BOOT_LABEL}\n`
    );
  }
  if (AVAILABILITY_CONNECT_PERMISSION_RE.test(availability.reason)) {
    return "Remedy: repair fortress custody, then re-run enable: sudo sanctuary castle-wall repair-custody\n";
  }
  if (
    availability.reason === "no_extension_connection" ||
    availability.reason === "no_report" ||
    availability.reason === "stale_report"
  ) {
    return "Remedy: start or repair the Castle Wall daemon, then re-run enable: sanctuary castle-wall daemon\n";
  }
  return "Remedy: run sanctuary castle-wall status, fix the named availability reason above, then re-run enable.\n";
}

function renderArmAvailabilityNotLiveRefusal(
  availability: Observed<ResolvedEnforcementAvailability>,
): string {
  return (
    "Castle Wall arm saved by the host app, but enforcement availability is not live. " +
    "Treat the wall as not enforcing until the availability surface is live.\n" +
    formatEnforcementAvailabilityStatus(availability) +
    renderArmAvailabilityRemedyLine(availability)
  );
}

function renderArmSysextNotEnabledLine(
  observation: SysextArmClaimObservation,
): string {
  switch (observation.state) {
    case "[activated waiting for user]":
      return (
        "Castle Wall arm pending: system extension is activated but waiting for user approval. " +
        "Open System Settings > Privacy & Security and approve the Castle Wall system extension before relying on enforcement.\n"
      );
    case "[activated disabled]":
      return (
        "Castle Wall arm saved by the host app, but the system extension is toggled off. " +
        "Open System Settings > General > Login Items & Extensions > Network Extensions and switch Castle Wall on before relying on enforcement.\n"
      );
    case "not loaded":
      return (
        "Castle Wall arm saved by the host app, but the system extension is not loaded. " +
        "Install and approve the Castle Wall system extension in System Settings before relying on enforcement.\n"
      );
    case "unreadable":
      return (
        "Castle Wall arm saved by the host app, but system extension state could not be read" +
        `${observation.reason !== undefined ? ` (${observation.reason})` : ""}. ` +
        "Open System Settings > Privacy & Security and approve the Castle Wall system extension before relying on enforcement.\n"
      );
    case "[activated enabled]":
      return (
        "Castle Wall arm saved by the host app, but enforcement availability was not evaluated. " +
        "Treat the wall as not enforcing until the availability surface is live.\n"
      );
  }
  return (
    "Castle Wall arm saved by the host app, but system extension state could not be read. " +
    "Open System Settings > Privacy & Security and approve the Castle Wall system extension before relying on enforcement.\n"
  );
}

/**
 * Default probe behind the `enable` root-owned-fortress refusal: the fortress
 * dir's owner uid, or undefined when the dir cannot be statted (an absent /
 * unreadable fortress is handled by the sibling guards, never refused here).
 */
async function defaultFortressOwnerUidProbe(
  fortressPath: string,
): Promise<number | undefined> {
  try {
    return (await stat(fortressPath)).uid;
  } catch {
    return undefined;
  }
}

/**
 * Custody-normalize chokepoint for privileged CLI verbs (fortress-ownership
 * spec 2026-07-30 §4(a2)(1)): when a verb ran with euid 0 (sudo) and touched
 * the fortress (lease status writes, arm audit entries), hand any root-owned
 * entries back to the resolved operator before returning. No-op for non-root
 * runs. Loud (never silent) when root ran without a resolvable operator.
 */
async function normalizeFortressCustodyAfterPrivilegedVerb(
  fortressPath: string,
  env: NodeJS.ProcessEnv,
  getuid: (() => number) | undefined,
  err: Writable,
  override?: (
    input: NormalizeFortressCustodyInput,
  ) => Promise<NormalizeFortressCustodyOutcome>,
): Promise<void> {
  if (getuid?.() !== 0) return;
  const identity = resolveSudoIdentityDecision(env);
  if (identity === undefined) {
    write(
      err,
      "Warning: this privileged run could not resolve the operator identity (SUDO_UID/SUDO_GID), so fortress custody was not normalized. If operator surfaces report EACCES, run: sudo sanctuary castle-wall repair-custody\n",
    );
    return;
  }
  const normalize = override ?? normalizeFortressCustody;
  await normalize({
    fortressPath,
    operator: { uid: identity.uid, gid: identity.gid },
    log: (line) => write(err, `${line}\n`),
  });
}

/**
 * Arm/disarm with the custody-normalize chokepoint on EVERY root exit path
 * (2026-07-31 gate HIGH). The inner flow writes into the fortress well before
 * several refusal returns -- `--agent-uid` writes the agent-origin descriptor
 * before the no-egress guard can refuse, and `disable` writes the lease-status
 * file before the host-app failure branches -- so hanging the normalize off
 * the two success returns left root-owned residue on those exits. Wrapping
 * makes reachability structural: no future return statement inside can skip it.
 */
async function runArmDisarm(
  action: "enable" | "disable",
  argv: string[],
  ctx: CastleWallCommandContext,
): Promise<number> {
  const wrapperEnv = ctx.env ?? process.env;
  const wrapperErr = ctx.err ?? process.stderr;
  const wrapperGetuid = ctx.getuid ?? process.getuid?.bind(process);
  if (wrapperGetuid?.() === 0 && resolveSudoIdentityDecision(wrapperEnv) === undefined) {
    write(
      wrapperErr,
      `Cannot resolve the non-root operator identity (SUDO_UID/SUDO_GID). Refusing to run castle-wall ${action} as root because fortress custody could not be normalized afterward. Re-run from a normal sudo invocation, not a raw root shell.\n`,
    );
    return 1;
  }
  try {
    return await runArmDisarmInner(action, argv, ctx);
  } finally {
    if (wrapperGetuid?.() === 0) {
      // Resolve LAZILY and only as root: a non-darwin or unresolvable-fortress
      // run touched nothing, and fortress resolution itself can refuse (the
      // hermetic-path guard), which must never turn into a thrown wrapper.
      let wrapperFortress: string | undefined;
      try {
        wrapperFortress = resolveFortressArg(
          parseCastleWallArgs(argv).fortress,
          wrapperEnv,
        );
      } catch {
        wrapperFortress = undefined;
      }
      if (wrapperFortress !== undefined) {
        await normalizeFortressCustodyAfterPrivilegedVerb(
          wrapperFortress,
          wrapperEnv,
          wrapperGetuid,
          wrapperErr,
          ctx.normalizeFortressCustody,
        );
      }
    }
  }
}

async function runArmDisarmInner(
  action: "enable" | "disable",
  argv: string[],
  ctx: CastleWallCommandContext,
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;
  const getuid = ctx.getuid ?? process.getuid?.bind(process);

  if (platform !== "darwin") {
    write(err, `castle-wall ${action} is macOS-only.\n`);
    return 1;
  }

  const parsed = parseCastleWallArgs(argv);
  if (writeCastleWallParseError(parsed, err)) return 2;
  const fortressPath = resolveFortressArg(parsed.fortress, env);
  const socketPath = resolveCastleWallSocketPath({
    platform,
    fortressPath,
  }).path;

  if (action === "enable") {
    // Root-owned-fortress refusal (fortress-ownership spec 2026-07-30
    // §4(a2)(2)): a root-owned fortress means the operator CLI cannot reach
    // castle.sock, so the `disable` dead-man lever PROVABLY cannot work.
    // Arming into that state is arming without an exit; "if the approval
    // channel is unreachable, deny" is the house rule. This is a hard refuse
    // (not a warning) and deliberately NOT overridable by --force: there is
    // no out-of-band story in which a root-owned fortress is intended, and
    // the remedy is one command. Disable never gates here: it stays the
    // unconditional dead-man lever.
    const ownerProbe = ctx.fortressOwnerUidProbe ?? defaultFortressOwnerUidProbe;
    if ((await ownerProbe(fortressPath)) === 0) {
      write(
        err,
        `Refusing to arm: the fortress at ${fortressPath} is owned by root (uid 0).\n` +
          "The operator account cannot traverse a root-owned fortress, so the\n" +
          "'sanctuary castle-wall disable' dead-man lever cannot reach castle.sock:\n" +
          "arming now would leave you no operator exit.\n" +
          "Repair custody first:  sudo sanctuary castle-wall repair-custody\n" +
          "Then re-run enable. (--force does not override this guard.)\n",
      );
      return 1;
    }
  }

  if (action === "enable" && !parsed.force) {
    // Brick-condition gate: filter on + no policy daemon = deny-all with no
    // recovery channel (the 2026-06-09 Hermes drill lockout). Refuse to arm
    // unless the daemon socket answers, or the operator explicitly overrides.
    const probe = ctx.daemonProbe ?? defaultDaemonProbe;
    if (!(await probe(socketPath))) {
      write(
        err,
        `Refusing to arm: no Castle Wall daemon is reachable for this fortress (${socketPath}).\n` +
          "Arming without a policy daemon fail-closes this machine to deny-all\n" +
          "(filter on + daemon down = locked out, including SSH).\n" +
          "Start the daemon first:  sanctuary castle-wall daemon\n" +
          "Or pass --force if the daemon is supervised out-of-band.\n",
      );
      return 1;
    }
  }

  if (action === "enable" && !parsed.force) {
    // Composition guard (#450 item 5): "arming implies a READY persistent BOOT
    // service." The daemon-reachability gate above only proves a daemon is up
    // NOW - a manually-started daemon passes it, and even a matching plist can be
    // disabled/unloaded. Require the persistent boot service to be strictly
    // installed, loaded for this fortress, enabled, and stable so you cannot arm
    // into the reboot-brick state. --force overrides (a boot-survival service
    // supervised out-of-band).
    const bootReadyProbe =
      ctx.bootServiceReadyProbe ??
      ((expectedFortressPath?: string) =>
        bootServiceReady(CASTLE_WALL_BOOT_PLIST_PATH, expectedFortressPath));
    const bootInstalledProbe =
      ctx.bootServiceInstalledProbe ??
      ((expectedFortressPath?: string) =>
        bootServiceInstalled(CASTLE_WALL_BOOT_PLIST_PATH, expectedFortressPath));
    if (!(await bootReadyProbe(fortressPath))) {
      if (await bootInstalledProbe(fortressPath)) {
        write(
          err,
          `Refusing to arm: the Castle Wall boot service for this fortress is installed but not ready/enabled/loaded (${fortressPath}).\n` +
            "A disabled or unloaded boot service does not survive reboot; arming would make\n" +
            "the NEXT REBOOT come up deny-all with no daemon for this fortress.\n" +
            "Repair it first:  sudo sanctuary castle-wall install-boot --fortress <path>\n" +
            "Or pass --force if a boot-survival service is supervised out-of-band.\n",
        );
        return 1;
      }
      if (await bootInstalledProbe()) {
        write(
          err,
          `Refusing to arm: the installed Castle Wall boot service targets a different fortress than this command (${fortressPath}).\n` +
            "A boot service for another fortress does not survive reboot for this one; arming\n" +
            "would make the NEXT REBOOT come up deny-all with no daemon for this fortress.\n" +
            "Install the matching service first:  sudo sanctuary castle-wall install-boot --fortress <path>\n" +
            "Or pass --force if a boot-survival service is supervised out-of-band.\n",
        );
        return 1;
      }
      write(
        err,
        "Refusing to arm: no persistent Castle Wall boot service is installed, loaded, enabled, and ready for this fortress.\n" +
          "Reachability of a daemon NOW does not survive a reboot - arming without the\n" +
          "boot service means the NEXT REBOOT comes up deny-all with no daemon (SSH\n" +
          "locked out, the F1 boot-cut).\n" +
          "Install it first:  sudo sanctuary castle-wall install-boot\n" +
          "Or pass --force if a boot-survival service is supervised out-of-band.\n",
      );
      return 1;
    }
  }

  if (action === "enable" && !parsed.noTtl && parsed.ttlSeconds === undefined) {
    write(
      err,
      "Usage: sanctuary castle-wall enable requires either --ttl <duration> for drills or --no-ttl for durable arming.\n",
    );
    return 2;
  }
  if (action === "enable" && parsed.noTtl && parsed.ttlSeconds !== undefined) {
    write(err, "Usage: choose only one dead-man TTL mode: --ttl <duration> or --no-ttl.\n");
    return 2;
  }

  const sysextProbe = ctx.sysextProbe ?? (() => defaultSysextProbe(ctx));
  if (action === "enable") {
    // Tahoe ships the sysext toggled OFF; arming over it would save an NE config
    // that never enforces (the false-assurance trap). Detect that distinct state
    // and route the operator to the one-time console toggle. Disable never gates
    // here - it stays the unconditional dead-man lever.
    if ((await readSysextStateForArmClaim(sysextProbe)).state === "[activated disabled]") {
      write(err, SYSEXT_DISABLED_GUIDANCE);
      return EXIT_SYSEXT_DISABLED;
    }
  }

  if (action === "enable" && parsed.agentUid !== undefined) {
    // One-command arm (Build 3, 2026-07-06): fold `configure-origin uid` into
    // `enable` so an operator can configure-then-arm in a single command.
    // Explicit `--agent-uid` ONLY - never auto-derived (a wrong-uid inference
    // could cut the operator; that inference is the deliberately-deferred
    // Build 3b). Validate + write BEFORE the origin-descriptor guard below so
    // a freshly-written descriptor satisfies that guard in the same run. Uses
    // the SAME build/validate/write chokepoint as `configure-origin` -
    // `writeAgentOriginDescriptor` - so the two entry points cannot drift.
    // Fail-closed: an invalid/malformed uid or ceiling is rejected here and
    // `enable` returns non-zero WITHOUT arming, matching the #884 hard-refuse
    // floor (it never falls through to "no descriptor, proceed anyway").
    // Strict parse (no truncation) - a wrong-but-plausible uid can fail OPEN
    // (agent unconfined) or cut a system daemon. The semantic floor (>= 1 and
    // >= ceiling) is enforced in validateAgentOrigin (the shared chokepoint).
    const agentUid = parseUidFlag(parsed.agentUid);
    if (agentUid === null) {
      write(
        err,
        `Refusing to arm: --agent-uid must be a plain positive integer, got '${parsed.agentUid}'. Not arming.\n`,
      );
      return 1;
    }
    const ceilingStr = parsed.ceiling ?? "500";
    const ceiling = parseUidFlag(ceilingStr);
    if (ceiling === null) {
      write(
        err,
        `Refusing to arm: --ceiling must be a plain non-negative integer, got '${ceilingStr}'. Not arming.\n`,
      );
      return 1;
    }
    const candidate: Record<string, unknown> = {
      mode: "uid",
      agent_uid: agentUid,
      system_uid_allow_ceiling: ceiling,
    };
    const sudoIdentity = resolveSudoIdentityDecision(env);
    const result = await writeAgentOriginDescriptor(
      fortressPath,
      candidate,
      getuid?.() === 0 && sudoIdentity !== undefined
        ? { uid: sudoIdentity.uid, gid: sudoIdentity.gid }
        : undefined,
    );
    if (!result.ok) {
      write(
        err,
        `Refusing to arm: --agent-uid=${parsed.agentUid} --ceiling=${ceiling} produced an invalid agent-origin descriptor (${result.error}). ` +
          `agent_uid must be a positive integer >= the ceiling (root/0 and sub-ceiling uids are rejected). Not arming.\n`,
      );
      return 1;
    }
    write(
      out,
      `Agent origin configured: mode=uid agent_uid=${result.validated.agent_uid} ceiling=${result.validated.system_uid_allow_ceiling}\n`,
    );
  }

  if (action === "enable") {
    // Origin-descriptor boot-cut guard (#877 follow-up; refuse upgrade of the
    // #883 warning). With NO valid agent-origin descriptor set, the macOS
    // OriginClassifier classifies EVERY flow `.agent`, so arming default-denies
    // the operator's OWN SSH / Tailscale / operator shell (the boot-cut). Like
    // the sibling no-daemon / no-boot-service brick guards above, this REFUSES
    // without `--force` so the lockout is PREVENTED, not merely narrated. When
    // `--agent-uid` was passed above, the descriptor we just wrote satisfies
    // this guard directly (no `--force` needed for the one-command path).
    // `--force` still arms agent-only (an intentional no-operator lockdown) but
    // warns loudly that operator access will be cut.
    const originProbe =
      ctx.agentOriginDescriptorProbe ?? defaultAgentOriginDescriptorPresent;
    if (!(await originProbe(fortressPath))) {
      if (!parsed.force) {
        write(
          err,
          "Refusing to arm: no agent-origin descriptor is set for this fortress.\n" +
            "Arming would classify EVERY flow as `.agent`, so default-deny would cut\n" +
            "your OWN SSH / Tailscale / operator shell (the boot-cut).\n" +
            `Set one first: ${GENERIC_UID_CONFINEMENT_REMEDY} Then re-run enable.\n` +
            "Or pass --force to arm agent-only anyway (you WILL lose operator access\n" +
            "unless another carve-out already exists).\n",
        );
        return 1;
      }
      write(
        err,
        "WARNING: --force arming with no agent-origin descriptor.\n" +
          "Every flow classifies `.agent`; your OWN SSH / Tailscale / operator shell\n" +
          "will be cut unless another carve-out already exists. Proceeding.\n",
      );
    }
  }

  // Standing no-egress brick guard (confined-agent egress design 2026-07-10,
  // section 5 layer 2). When arming in uid mode over a manifest source with
  // ZERO agent-matchable allow rules, the confined agent is walled off from
  // EVERYTHING it needs (the 2026-07-09 drill finding: the CoS armed
  // "successfully" and could not reach even its own endpoints). A deliberate
  // deny-all quarantine is a legitimate posture, but it must be ASKED FOR via
  // the explicit `--allow-no-egress` override (audited), never the accident.
  // Deliberately NOT covered by --force (that flag asserts out-of-band
  // daemon/boot supervision, a different statement). This guard is GENERIC
  // (the CLI does not know harness endpoints); the endpoint-specific static +
  // as-uid verification lives in the auto-provision flow.
  let allowNoEgressOverrideUsed = false;
  let allowNoEgressQuarantineUid: number | null = null;
  if (action === "enable") {
    const originMode = await readAgentOriginModeBestEffort(fortressPath);
    if (originMode === "uid") {
      const countProbe = ctx.egressAllowRuleCountProbe ?? countAgentMatchableAllowRules;
      const agentAllowRules = await countProbe(fortressPath);
      if (agentAllowRules === 0) {
        if (!parsed.allowNoEgress) {
          write(
            err,
            "Refusing to arm: this fortress has ZERO agent-matchable allow rules, so the\n" +
              "confined agent would be default-denied for EVERYTHING (including its own\n" +
              "endpoints) -- confined into non-functionality, silently.\n" +
              `${GENERIC_UID_CONFINEMENT_REMEDY} Also add agent-matchable allow rules to\n` +
              `${join(fortressPath, "policy", "egress", "rules")} and reload.\n` +
              "Or pass --allow-no-egress to arm a deliberate deny-all quarantine (audited).\n",
          );
          await appendCastleWallCliAuditBestEffort(
            EGRESS_PROVISION_REFUSED_AUDIT_OP,
            {
              source: "castle-wall-cli",
              guard: "no-egress-brick",
              agent_origin_mode: "uid",
              agent_matchable_allow_rules: 0,
              disarm_outcome: "not-armed",
            },
            fortressPath,
            env,
            err,
          );
          return 1;
        }
        allowNoEgressOverrideUsed = true;
        allowNoEgressQuarantineUid = await readAgentOriginUidBestEffort(fortressPath);
        write(
          err,
          "WARNING: --allow-no-egress: arming a uid-mode wall with ZERO agent-matchable\n" +
            "allow rules. The confined agent will be default-denied for everything (a\n" +
            "deliberate quarantine posture). This override is audited.\n",
        );
      }
    }
  }

  const resolved = await resolveHostAppBinary(env, ctx);
  if ("error" in resolved) {
    write(err, `${resolved.error}\n`);
    return 1;
  }

  if (allowNoEgressOverrideUsed) {
    if (allowNoEgressQuarantineUid === null) {
      write(
        err,
        "Refusing to arm: --allow-no-egress was requested, but the uid-mode agent-origin descriptor could not be resolved.\n" +
          `${GENERIC_UID_CONFINEMENT_REMEDY} Then retry. The wall was not armed.\n`,
      );
      await appendCastleWallCliAuditBestEffort(
        EGRESS_PROVISION_REFUSED_AUDIT_OP,
        {
          source: "castle-wall-cli",
          guard: "deny-all-quarantine-uid-resolution",
          agent_origin_mode: "uid",
          negative_control_host: AGENT_EGRESS_NEGATIVE_CONTROL_HOST,
          negative_control_port: 443,
          observed: "unverified",
          disarm_outcome: "not-armed",
        },
        fortressPath,
        env,
        err,
      );
      return 1;
    }
    const preflightProbe = ctx.sudoPreflightProbe ?? defaultSudoPreflightProbe;
    const preflightResult = await preflightProbe(allowNoEgressQuarantineUid);
    // A missing sudo credential must refuse before the wall is armed, so an inconclusive probe is never mistaken
    // for a wall failure and the operator is never left with an armed wall they were told to disarm.
    if (!preflightResult.ok) {
      write(
        err,
        renderSudoPreflightRefusal(allowNoEgressQuarantineUid, preflightResult),
      );
      await appendCastleWallCliAuditBestEffort(
        EGRESS_PROVISION_REFUSED_AUDIT_OP,
        {
          source: "castle-wall-cli",
          guard: "sudo-preflight",
          agent_origin_mode: "uid",
          agent_uid: allowNoEgressQuarantineUid,
          exit_code: preflightResult.exitCode,
          ...(preflightResult.stderr?.trim()
            ? { stderr: preflightResult.stderr.trim() }
            : {}),
          disarm_outcome: "not-armed",
        },
        fortressPath,
        env,
        err,
      );
      return 1;
    }
  }

  const invoke = ctx.hostAppInvoke ?? defaultArmInvoke(ctx, action);
  const cliGitSha = resolveCliBuildSha(env, ctx);
  if (action === "enable") {
    // Identity is a PRECONDITION to mutation, not a postcondition. The old
    // ordering invoked `--headless enable` first and only then rejected a
    // stale deployed app, which could leave the NE preference enabled while
    // returning failure before the authenticated arm lease was sent. Read the
    // deployed app's identity through the non-mutating status action first;
    // any missing/mismatched identity refuses without calling enable.
    const identityProbe = await invoke(resolved.path, ["--headless", "status"]);
    if (identityProbe.stderr.trim()) {
      write(err, identityProbe.stderr.trimEnd() + "\n");
    }
    const identityReport = parseHeadlessReport(identityProbe.stdout);
    if (!identityReport) {
      const detail =
        identityProbe.stderr.trim() ||
        `host app status exited with code ${identityProbe.exitCode}`;
      write(
        err,
        `castle-wall enable failed before arming: deployed app identity could not be verified (${detail}).\n`,
      );
      return 1;
    }
    const buildMismatch = validateHeadlessBuildIdentity(
      identityReport,
      cliGitSha,
    );
    if (buildMismatch) {
      write(err, `castle-wall enable failed before arming: ${buildMismatch}\n`);
      return 1;
    }
  }
  const headlessArgs = ["--headless", action];
  if (action === "enable") {
    if (parsed.noTtl) headlessArgs.push("--no-ttl");
    else headlessArgs.push(`--ttl=${parsed.ttlSeconds}`);
  } else {
    headlessArgs.push("--timeout=3");
  }
  let leaseRevoked = false;
  if (action === "disable") {
    const leaseMessage = buildArmLeaseMessage({ armed: false, revoked: true, ttlSeconds: null });
    leaseRevoked = await sendArmLeaseBestEffort(socketPath, leaseMessage);
    await writeLeaseStatusBestEffort(fortressPath, leaseMessage);
  }
  const result = await invoke(resolved.path, headlessArgs);
  if (result.stderr.trim()) {
    write(err, result.stderr.trimEnd() + "\n");
  }
  const report = parseHeadlessReport(result.stdout);
  if (report) {
    const buildMismatch = validateHeadlessBuildIdentity(report, cliGitSha);
    if (buildMismatch) {
      write(err, `castle-wall ${action} failed: ${buildMismatch}\n`);
      return 1;
    }
  }

  if (result.exitCode === HEADLESS_EXIT_NEEDS_APPROVAL) {
    write(err, NEEDS_APPROVAL_GUIDANCE);
    return 3;
  }
  if (result.exitCode !== 0 || !report || !report.ok) {
    const detail =
      report?.error ||
      result.stderr.trim() ||
      `host app exited with code ${result.exitCode}`;
    if (action === "disable" && leaseRevoked) {
      // This warning is the ONLY place the lease-ratchet disclosure and the
      // underlying invoke failure detail are rendered; realUninstallOps.disarm
      // in cli/uninstall.ts surfaces both by capturing this stream (must match
      // the capture there). The label alone ("fail_open_deadman") masked the
      // real cause on hardware (D5 drill 2026-08-25: a LaunchServices launch
      // failure read as a filter-observation problem), and the revoked lease
      // was observed there as FULL DENY for the protected uid, not fail-open.
      write(
        err,
        `Warning: NE preference disable did not complete (${detail}); the authenticated dead-man lease was already revoked, so the protected uid is fully denied until a later successful disable or re-enable.\n`,
      );
      await appendArmAuditBestEffort(
        action,
        "fail_open_deadman",
        parsed.force ?? false,
        fortressPath,
        env,
        err,
      );
      write(out, "Castle Wall disarmed: provider dead-man lease revoked (NE preference disable best-effort did not complete).\n");
      // Bug B P1 (case A): the lease is revoked but the NE preference disable
      // did NOT complete -- the filter may STILL be enabled. This is NOT a
      // confirmed filter-off; a caller must not treat it as safe to remove the
      // policy daemon (reboot could come up enabled + no daemon = deny-all).
      // The revoked-lease state was DESIGNED as the provider's fail-open path,
      // but on hardware it was observed as full deny for the protected uid (D5
      // drill 2026-08-25, allow-under-revoked-lease evidence); the operator
      // warning above discloses the observed behavior, not the design intent.
      ctx.onDisableNePreferenceOutcome?.("fail_open_deadman");
      return 0;
    }
    write(err, `castle-wall ${action} failed: ${detail}\n`);
    return 1;
  }

  // Post-change corroboration: re-read the live NE configuration through the
  // host app rather than trusting the mutation call's own report.
  const verify = await invoke(resolved.path, ["--headless", "status"]);
  if (verify.stderr.trim()) {
    write(err, verify.stderr.trimEnd() + "\n");
  }
  const verifyReport = parseHeadlessReport(verify.stdout);
  if (verify.exitCode === 0 && verifyReport) {
    const verifyBuildMismatch = validateHeadlessBuildIdentity(
      verifyReport,
      cliGitSha,
    );
    if (verifyBuildMismatch) {
      write(err, `castle-wall ${action} failed: ${verifyBuildMismatch}\n`);
      return 1;
    }
  }
  const expectedState = action === "enable" ? "enabled" : "disabled";
  const confirmed =
    verify.exitCode === 0 && verifyReport?.state === expectedState;
  const observedState = verifyReport?.state ?? "unparseable";

  if (!confirmed) {
    if (action === "enable") {
      // Arm is the protection-increasing direction: never claim "armed"
      // without a positive corroboration. Fail closed.
      write(
        err,
        `castle-wall enable: state change reported but post-change verification ` +
          `returned '${observedState}' (expected 'enabled').\n`,
      );
      return 1;
    }

    // Disarm is the dead-man recovery lever. Its authoritative signal is the
    // mutation itself (saveToPreferences returned ok, above); the status
    // re-read is only corroboration. On macOS Tahoe that re-read spawns a
    // SECOND LaunchServices app instance, which can time out or yield no report
    // even though the wall is already down - so an INCONCLUSIVE corroboration
    // must not flip a genuine recovery into a reported failure, or the lever
    // stops being trustworthy (the whole point of the SSH-only drill is that
    // `disable` reliably means "wall down"). A corroboration that
    // AFFIRMATIVELY still shows the wall 'enabled' is a real contradiction (the
    // disarm did not stick): fail loud rather than hand back a false recovery
    // assurance (CLAUDE.md invariant 5).
    if (verify.exitCode === 0 && verifyReport?.state === "enabled") {
      write(
        err,
        `castle-wall disable: disarm reported success but post-change ` +
          `verification still shows the wall ENABLED. The wall may still be ` +
          `up - re-run 'sanctuary castle-wall disable' and confirm with ` +
          `'sanctuary castle-wall status'.\n`,
      );
      return 1;
    }
    write(
      err,
      `Warning: castle-wall disable succeeded (the host app confirmed the NE ` +
        `configuration was saved disabled) but post-change corroboration was ` +
        `inconclusive (status returned '${observedState}'). Disarm is the ` +
        `authoritative dead-man lever and is treated as effective; confirm ` +
        `with 'sanctuary castle-wall status' once the host is responsive.\n`,
    );
  }

  await appendArmAuditBestEffort(
    action,
    confirmed ? expectedState : observedState,
    parsed.force ?? false,
    fortressPath,
    env,
    err,
    // The --allow-no-egress override is audited (design section 5 layer 2):
    // the wall_armed record carries the explicit quarantine consent.
    allowNoEgressOverrideUsed ? { allow_no_egress_override: true } : {},
  );

  if (action === "enable") {
    const leaseMessage = buildArmLeaseMessage({
      armed: true,
      ttlSeconds: parsed.noTtl ? null : parsed.ttlSeconds ?? null,
    });
    const leaseSent = await sendArmLeaseBestEffort(socketPath, leaseMessage);
    await writeLeaseStatusBestEffort(fortressPath, leaseMessage);
    if (!leaseSent) {
      write(
        err,
        "Warning: the host app saved the Castle Wall arm preference, but the daemon did not accept the dead-man lease update. Existing daemon heartbeat state remains authoritative.\n",
      );
    }
    const armClaimBasis = await observeArmClaimBasis(
      fortressPath,
      platform,
      ctx,
      sysextProbe,
    );
    if (armClaimBasis.enforcementAvailability.status !== "live") {
      write(
        err,
        renderArmAvailabilityNotLiveRefusal(
          armClaimBasis.enforcementAvailability,
        ),
      );
      return 1;
    }
    if (allowNoEgressOverrideUsed) {
      const smokeInput: DenyAllQuarantineProbeInput = {
        // The pre-arm block above returns unless `--allow-no-egress` has a resolved, sudo-preflighted uid.
        agentUid: allowNoEgressQuarantineUid!,
        host: AGENT_EGRESS_NEGATIVE_CONTROL_HOST,
        port: 443,
      };
      const smokeProbe = ctx.denyAllQuarantineProbe ?? defaultDenyAllQuarantineProbe;
      const smokeResult = await smokeProbe(smokeInput);
      // The sudo preflight above proves this probe could run as the uid before arming; an unverified smoke here is
      // an enforcement uncertainty, not a cold sudo credential miss.
      if (!smokeResult.verified || smokeResult.reachable) {
        write(err, renderDenyAllQuarantineProbeRefusal(smokeInput, smokeResult));
        await appendCastleWallCliAuditBestEffort(
          EGRESS_PROVISION_REFUSED_AUDIT_OP,
          {
            source: "castle-wall-cli",
            guard: "deny-all-quarantine-smoke",
            agent_origin_mode: "uid",
            agent_uid: smokeInput.agentUid,
            negative_control_host: smokeInput.host,
            negative_control_port: smokeInput.port,
            observed: smokeResult.reachable
              ? "reachable"
              : smokeResult.verified
                ? "blocked"
                : "unverified",
            exit_code: smokeResult.exitCode,
            disarm_outcome: "operator-action-needed",
          },
          fortressPath,
          env,
          err,
        );
        return 1;
      }
      write(
        out,
        `Deny-all quarantine smoke passed: uid ${smokeInput.agentUid} could not reach ${smokeInput.host}:${smokeInput.port} on the direct --noproxy path.\n`,
      );
    }
    const verifiedArmClaim = renderVerifiedArmClaimLine(armClaimBasis);
    write(
      out,
      verifiedArmClaim ?? renderArmSysextNotEnabledLine(armClaimBasis.sysext),
    );
  } else if (confirmed) {
    write(out, "Castle Wall disarmed: content filter disabled (verified via host-app status).\n");
  } else {
    write(
      out,
      "Castle Wall disarmed: content filter disabled (host app confirmed the save; status corroboration pending).\n",
    );
  }
  if (action === "disable") {
    ctx.onDisableNePreferenceOutcome?.(
      confirmed ? "corroborated_off" : "save_accepted_inconclusive",
    );
  }
  // The custody-normalize chokepoint runs in the runArmDisarm wrapper, so it
  // covers this success path AND every refusal return above it.
  return 0;
}

/**
 * Headlessly arm the Castle Wall content filter (`sanctuary castle-wall
 * enable`). Drives the signed host-app binary's --headless mode, so it works
 * over SSH once the one-time GUI consent exists. Gated on daemon
 * reachability to avoid the deny-all brick condition; --force overrides.
 */
export async function runEnable(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {},
): Promise<number> {
  return runArmDisarm("enable", argv, ctx);
}

/**
 * Headlessly disarm the Castle Wall content filter (`sanctuary castle-wall
 * disable`). Unconditional by design: this is the remote dead-man lever that
 * makes SSH-only drills recoverable, so it has no preconditions beyond the
 * binary existing.
 */
export async function runDisable(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {},
): Promise<number> {
  return runArmDisarm("disable", argv, ctx);
}

export function parseCastleWallArgs(argv: string[]): CastleWallParsedArgs {
  const parsed: CastleWallParsedArgs = {};
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress/--since value must refuse, never silently resolve the default fortress; wrong-fortress custody/daemon operations are a constraint-5 violation.
  const fortress = consumeFlagValue(argv, "--fortress");
  if (fortress.error !== undefined) return { parseError: fortress.error };
  if (fortress.value !== undefined) parsed.fortress = fortress.value;
  const since = consumeFlagValue(fortress.argv, "--since");
  if (since.error !== undefined) return { ...parsed, parseError: since.error };
  if (since.value !== undefined) parsed.since = since.value;

  for (let i = 0; i < since.argv.length; i++) {
    const arg = since.argv[i]!;
    if (arg === "--ttl") {
      // Route through parseError rather than letting the parser throw: this loop
      // runs inside parseCastleWallArgs, the single chokepoint every castle-wall
      // verb calls before its own try block starts, so an uncaught throw here
      // would skip writeCastleWallParseError and land in the top-level
      // `main().catch` handler instead (wrong exit code, "failed to start"
      // instead of a usage error).
      const ttl = parseLeaseTtlSeconds(since.argv[++i]);
      if ("error" in ttl) return { ...parsed, parseError: ttl.error };
      parsed.ttlSeconds = ttl.value;
    } else if (arg.startsWith("--ttl=")) {
      const ttl = parseLeaseTtlSeconds(arg.slice("--ttl=".length));
      if ("error" in ttl) return { ...parsed, parseError: ttl.error };
      parsed.ttlSeconds = ttl.value;
    } else if (arg === "--no-ttl") {
      parsed.noTtl = true;
    } else if (arg.startsWith("--scope=")) {
      const scope = parseScope(arg.slice("--scope=".length));
      if ("error" in scope) return { ...parsed, parseError: scope.error };
      parsed.scope = scope.value;
    } else if (arg === "--scope") {
      const scope = parseScope(since.argv[++i]);
      if ("error" in scope) return { ...parsed, parseError: scope.error };
      parsed.scope = scope.value;
    } else if (arg === "--force") {
      parsed.force = true;
    } else if (arg === "--require-daemon") {
      parsed.requireDaemon = true;
    } else if (arg === "--allow-no-egress") {
      parsed.allowNoEgress = true;
    } else if (arg.startsWith("--agent-uid=")) {
      parsed.agentUid = arg.slice("--agent-uid=".length);
    } else if (arg.startsWith("--ceiling=")) {
      parsed.ceiling = arg.slice("--ceiling=".length);
    } else if (arg === "--accept-broken-chain") {
      parsed.acceptBrokenChain = true;
    } else if (arg === "--by-rule") {
      parsed.byRule = true;
    } else if (arg === "--json") {
      parsed.json = true;
    } else if (arg.startsWith("--producer-pub-key=")) {
      parsed.producerPubKey = arg.slice("--producer-pub-key=".length);
    } else if (arg === "--producer-pub-key") {
      parsed.producerPubKey = since.argv[++i];
    } else if (arg.startsWith("--rule=")) {
      parsed.rule = arg.slice("--rule=".length);
    } else if (arg === "--rule") {
      // `--rule` requires a value. If the next token is missing or is itself a
      // flag, do NOT consume it - flag the omission so the caller emits a usage
      // error rather than silently falling back to the raw audit dump.
      const next = since.argv[i + 1];
      if (next === undefined || next.startsWith("-")) {
        parsed.ruleMissingValue = true;
      } else {
        parsed.rule = next;
        i++;
      }
    } else if (!arg.startsWith("-") && !parsed.requestId) {
      parsed.requestId = arg;
    }
  }
  return parsed;
}

// Returns a result object instead of throwing (must match the equivalent
// choice in parseLeaseTtlSeconds below): both are called from inside
// parseCastleWallArgs's arg loop, before any verb's own try block, so a thrown
// Error would bypass writeCastleWallParseError and surface as an unhandled
// top-level failure rather than the structured parse-error path every other
// flag uses.
function parseScope(
  value: string | undefined,
): { value: "once" | "session" | "always" } | { error: string } {
  if (value === "session" || value === "always" || value === "once") return { value };
  return { error: "--scope must be once, session, or always" };
}

function resolveFortressArg(
  fortress: string | undefined,
  env: NodeJS.ProcessEnv,
): string {
  if (!fortress) return resolveStoragePath(env);
  return isAbsolute(fortress) ? fortress : resolve(process.cwd(), fortress);
}

function fortressIdLabel(fortressPath: string): string {
  return fortressPath;
}

function parseDurationMs(value: string): number {
  const match = /^(\d+)([mhd])$/.exec(value);
  if (!match) throw new Error("--since must use forms like 5m, 1h, or 2d");
  const amount = Number(match[1]);
  const unit = match[2];
  const multiplier = unit === "m" ? 60_000 : unit === "h" ? 3_600_000 : 86_400_000;
  return amount * multiplier;
}

// See parseScope's comment above: same reasoning applies here.
function parseLeaseTtlSeconds(
  value: string | undefined,
): { value: number } | { error: string } {
  if (!value) return { error: "--ttl requires a duration like 30s, 5m, or 1h" };
  const match = /^(\d+)([smh])$/.exec(value);
  if (!match) return { error: "--ttl must use forms like 30s, 5m, or 1h" };
  const amount = Number(match[1]);
  const unit = match[2];
  const multiplier = unit === "s" ? 1 : unit === "m" ? 60 : 3600;
  return { value: amount * multiplier };
}

function isCastleWallAuditEntry(entry: AuditEntry): boolean {
  return CASTLE_WALL_AUDIT_OPERATIONS.has(entry.operation);
}

const CASTLE_WALL_AUDIT_OPERATIONS = new Set([
  "egress_allowed",
  "egress_blocked",
  "operator_decision",
  "policy_loaded",
  "policy_validation_failed",
  "filter_started",
  "filter_stopped",
  "filter_crashed",
  "wall_armed",
  "wall_disarmed",
  "queue_saturated",
  "no_wall_engaged",
  "no_wall_expired",
  "wal_overflow",
  "external_firewall_clobber",
  "flow_decision_rejected",
  "flow_pending_approval_rejected",
  "boot_token_provisioned",
]);

async function sendCastleWallMessage<T extends CastleWallMessage>(
  socketPath: string,
  message: CastleWallMessage,
  expectedType: T["type"],
  timeoutMs = 5_000,
): Promise<T> {
  return await new Promise<T>((resolvePromise, reject) => {
    const socket = createConnection(socketPath);
    let inbound = new Uint8Array(0);
    let settled = false;
    const timer = setTimeout(() => {
      finish(new Error("Castle Wall IPC request timed out"));
    }, timeoutMs);
    const finish = (result: T | Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (result instanceof Error) reject(result);
      else resolvePromise(result);
    };
    socket.on("connect", () => {
      socket.write(frame(JSON.stringify({
        jsonrpc: "2.0",
        method: `castle-wall.${message.type}`,
        params: message,
      })));
    });
    socket.on("data", (chunk: Buffer) => {
      const merged = new Uint8Array(inbound.length + chunk.length);
      merged.set(inbound, 0);
      merged.set(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.length), inbound.length);
      inbound = merged;
      while (inbound.length > 0) {
        const parsed = parseFrame(inbound);
        if (parsed.kind === "need_more") break;
        if (parsed.kind === "error") {
          finish(new Error(`Castle Wall IPC framing error: ${parsed.reason}`));
          return;
        }
        inbound = inbound.slice(parsed.consumedBytes);
        try {
          const envelope = JSON.parse(parsed.body) as { params?: CastleWallMessage };
          if (envelope.params?.type === expectedType) {
            finish(envelope.params as T);
            return;
          }
        } catch {
          // Ignore malformed frames from non-admin peers until timeout.
        }
      }
    });
    socket.on("error", finish);
  });
}
