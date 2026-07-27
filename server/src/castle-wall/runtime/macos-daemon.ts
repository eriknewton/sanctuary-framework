import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { statSync } from "node:fs";
import { mkdir, readdir, stat, unlink } from "node:fs/promises";
import { createConnection } from "node:net";
import { dirname, join } from "node:path";
import { promisify } from "node:util";

import { bytesToString, toBase64url } from "../../core/encoding.js";
import { decrypt, encrypt, type EncryptedPayload } from "../../core/encryption.js";
import type { AuditLog } from "../../operational/audit-log.js";
import type { AllowlistRule } from "../allowlist/schema.js";
import { validateRule } from "../allowlist/schema.js";
import {
  composeEffectiveRules,
  HABEAS_RULE_ID_PREFIX,
  isGenuineDerivedHabeasRule,
} from "../allowlist/habeas-port.js";
import { composeExclusiveRoutingRules } from "../allowlist/exclusive-routing.js";
import { loadExclusiveRoutingMarker } from "../allowlist/routing-marker.js";
import { collectSystemResolvers } from "./system-resolvers.js";
import { readDistressConfig } from "../../distress/config.js";
import { validateAgentOrigin } from "../allowlist/agent-origin.js";
import {
  EXCLUSIVE_EGRESS_GATE_FILENAME,
  validateExclusiveEgressGatePolicy,
  type ExclusiveEgressGatePolicy,
} from "../allowlist/gate-derivation.js";
import { validateOperatorBaseline } from "../allowlist/operator-baseline.js";
import {
  EMISSION_STALL_AUDIT_OP,
  EMISSION_STALL_LOG_PREFIX,
  EMISSION_STALL_RECOVERED_AUDIT_OP,
  EmissionLivenessWatchdog,
  type EmissionRecoveryFinding,
  type EmissionStallFinding,
} from "../audit/emission-liveness.js";
import { verifyManifestSignature } from "../allowlist/parse.js";
import type { SignedManifest } from "../allowlist/manifest.js";
import type {
  ArmLeaseNotification,
  DecisionResponse,
  PolicyReloadRequest,
  PolicyReloadResponse,
} from "../ipc/messages.js";
import {
  buildSignedManifest,
  localManifestSigner,
} from "./manifest-publisher.js";
import { HelperSignerClient, type ShimInvoker } from "./helper-signer.js";
import { writeGlobalPinIfUnestablished } from "../global-pin/index.js";
import {
  CASTLE_WALL_MACOS_AUDIT_PRODUCER_PUBKEY_PATH,
  CASTLE_WALL_MACOS_GLOBAL_PINNED_PUBKEY_DIR,
  resolveProducerPubKeyPath,
} from "./producer-signature.js";
import {
  isCustodyFsError,
  readFileCustody,
  readFileCustodyWithStats,
  writeFileCustody,
} from "../../storage/custody-fs.js";
import { MacOSFlowEventConsumer } from "./macos-flow-events.js";
import { MacOSFlowIpcListener } from "./macos-ipc-listener.js";
import { protectionSubjectFromAgentOrigin } from "../subject-binding.js";
import {
  CASTLE_WALL_ACTIVE_CONFIG_PATH,
  CASTLE_WALL_ACTIVE_CONFIG_LEGACY_PATH,
  resolveCastleWallSocketPath,
} from "./socket-path.js";
import {
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
  CASTLE_WALL_HEARTBEAT_OPERATION,
  CASTLE_WALL_ARM_LEASE_REVOKED_OPERATION,
  CASTLE_WALL_RELOAD_SIGN_DEADLINE_MS,
  CASTLE_WALL_RELOAD_BROADCAST_DEADLINE_MS,
  CASTLE_WALL_RELOAD_AUDIT_DEADLINE_MS,
} from "../constants.js";
import {
  EGRESS_PROBE_FAILED_AUDIT_OP,
  asUidTlsProbeArgv,
} from "../provision/egress.js";

const execFileAsync = promisify(execFile);

const CASTLE_PINNED_PUBKEY = "castle-pinned-pubkey.bin";
const CASTLE_PINNED_PRIVKEY = "castle-pinned-privkey.enc";
const CASTLE_GLOBAL_PINNED_PUBKEY_DIR = CASTLE_WALL_MACOS_GLOBAL_PINNED_PUBKEY_DIR;
const CASTLE_GLOBAL_PINNED_PUBKEY_PATH = `${CASTLE_GLOBAL_PINNED_PUBKEY_DIR}/${CASTLE_PINNED_PUBKEY}`;
const CASTLE_GLOBAL_AUDIT_PRODUCER_PUBKEY_PATH =
  CASTLE_WALL_MACOS_AUDIT_PRODUCER_PUBKEY_PATH;

/**
 * Signing handle used by the daemon. B2: the production default routes both
 * manifest and handshake-nonce signing through the root helper (`mode: "helper"`),
 * so no private key reaches this process. The local path (`mode: "local"`) is a
 * dev/test fallback gated behind an explicit flag; it must be OFF for the P1
 * key-non-extraction drill.
 */
export interface DaemonSigner {
  mode: "helper" | "local";
  signingKeyId: string;
  publicKey: Uint8Array;
  signManifest(canonicalBytes: Uint8Array): Promise<Uint8Array>;
  signNonce(nonce: Uint8Array): Promise<Uint8Array>;
}

export function formatCastleWallAlreadyRunningMessage(pid?: number | null): string {
  const pidText =
    typeof pid === "number" && Number.isSafeInteger(pid) && pid > 0
      ? `PID ${pid}`
      : "pid unavailable";
  return `Castle Wall daemon already running for this fortress (${pidText}). Multi-wrap-per-fortress is Phase 3.`;
}

/**
 * Default cadence (seconds) of the periodic AUDIT liveness heartbeat
 * (observability Slice 2). Deliberately an AUDIT cadence (45s), an order of
 * magnitude slower than the 5s IPC arm-lease heartbeat, so a continuously-armed
 * wall writes a bounded number of heartbeat entries per hour and does not bloat
 * the audit chain. The reader's enforcement freshness window
 * (`DEFAULT_ENFORCEMENT_FRESHNESS_MS`, 10 min) is far wider than this, so a live
 * daemon always lands at least one heartbeat inside the window.
 */
export const CASTLE_WALL_DEFAULT_AUDIT_HEARTBEAT_INTERVAL_SECONDS = 45 as const;

/**
 * Default cadence (seconds) of the periodic as-agent-uid egress liveness
 * probe (confined-agent egress design MED-3, secondary signal): 6 hours.
 * Deliberately order-of-hours -- the probe spawns real as-uid processes and
 * makes real TLS connects; the PRIMARY runtime signal (the deny-spike
 * sentinel over already-recorded audit denials) carries the minutes-scale
 * latency, this probe only backstops endpoints the harness is not currently
 * calling at all.
 */
export const CASTLE_WALL_DEFAULT_AGENT_EGRESS_PROBE_INTERVAL_SECONDS = 21_600 as const;

/**
 * Default cadence (seconds) of the Slice M emission-liveness watchdog tick
 * (the decided-vs-emitted divergence evaluation). The tick is a pure counter
 * comparison (no I/O unless a stall fires), so a seconds-scale cadence is
 * cheap; it just needs to be comfortably shorter than the watchdog's grace
 * window (default 60s) so a stall fires within roughly one grace window of
 * onset.
 */
export const CASTLE_WALL_DEFAULT_EMISSION_LIVENESS_TICK_SECONDS = 15 as const;

/**
 * Resolve the as-agent-uid egress probe: the injected one (tests), else the
 * real `sudo -n -u '#<uid>' curl` probe IFF this daemon runs as root on
 * darwin (only root can genuinely change the real uid the wall keys on),
 * else undefined (timer stays off; a probe that cannot change uid would
 * report THIS process's reachability and alarm falsely).
 */
function resolveAgentEgressProbe(
  input: MacOSCastleWallDaemonInput,
): ((uid: number, host: string, port: number) => Promise<boolean>) | undefined {
  if (input.agentEgressProbe !== undefined) return input.agentEgressProbe;
  if ((input.platform ?? process.platform) !== "darwin") return undefined;
  if (typeof process.getuid !== "function" || process.getuid() !== 0) return undefined;
  return async (uid, host, port) => {
    const { file, args } = asUidTlsProbeArgv(uid, host, port);
    try {
      await execFileAsync(file, args);
      return true;
    } catch {
      return false;
    }
  };
}

/**
 * launchd label of the safe-mode boot daemon. Mirror of `CASTLE_WALL_BOOT_LABEL`
 * in `cli/castle-wall-boot.ts` — duplicated (not imported) to keep this runtime
 * module free of a dependency on the CLI layer. Used only to build the handoff
 * guidance when a full daemon collides with a live safe-mode boot daemon.
 */
const CASTLE_WALL_BOOT_LABEL_MIRROR = "ai.sanctuaryprotocol.castle-wall.daemon";

/**
 * #450 item 4: actionable, non-bricking handoff message for when a FULL operator
 * daemon tries to start while the root SAFE-MODE boot daemon is still live.
 * There is no automatic supersede (the operator daemon cannot stop a root
 * KeepAlive unit), so guide the operator to stand the boot daemon down. The box
 * stays protected in safe mode until they do.
 */
export function safeModeHandoffMessage(pid: number): string {
  return (
    `A Castle Wall SAFE-MODE boot daemon (PID ${pid}) is currently enforcing this fortress.\n` +
    "The full operator daemon does not automatically supersede the root boot daemon\n" +
    "(it is a launchd KeepAlive unit that an unprivileged daemon cannot stop). Stand it\n" +
    "down for this session, then start the full daemon again:\n" +
    `  sudo launchctl bootout system/${CASTLE_WALL_BOOT_LABEL_MIRROR}\n` +
    "The boot daemon returns automatically on the next reboot; the box stays protected\n" +
    "in safe mode until you hand off."
  );
}

export interface MacOSCastleWallDaemonInput {
  fortressPath: string;
  fortressId: string;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  platform?: NodeJS.Platform;
  socketPath?: string;
  /**
   * Re-own the bound IPC socket to this uid (F1 #450 item 3). Set explicitly by
   * the SAFE-MODE boot daemon (which runs as root) to the operator/fortress-owner
   * uid so the operator CLI dead-man lever can reach the otherwise root-owned
   * socket.
   *
   * Slice M Layer-2 (2026-06-29): this is now OPTIONAL even for a root daemon. When
   * omitted and the daemon runs as root, the operator uid is AUTO-DERIVED from the
   * fortress dir owner (the uid the content-filter extension runs as) so the engage
   * path (`wrap`, which never passed this) re-owns the socket too and
   * audit-producer signing can engage. An explicit value is still honored verbatim.
   * See {@link resolveSocketReownUid} and
   * {@link MacOSFlowIpcListenerOptions.socketOwnerUid}.
   */
  socketOwnerUid?: number;
  /**
   * Which daemon role is starting (#450 item 4). Recorded in the active-config
   * `mode` marker so a colliding starter can give precise handoff guidance:
   * "safe" = the root safe-mode boot daemon; "full" (default) = the operator
   * login daemon. Purely advisory for messaging — it is not a trust signal.
   */
  daemonMode?: "safe" | "full";
  activeConfigPath?: string;
  listenerFactory?: (options: MacOSCastleWallListenerOptions) => MacOSCastleWallListenerHandle;
  /**
   * Optional agent-origin descriptor (config / test fixture). When absent,
   * the daemon loads `policy/egress/agent-origin.json` from the fortress
   * directory. When BOTH are absent, the manifest omits the field and the
   * sysext classifies every flow as `.agent` (machine-wide default-deny).
   */
  agentOrigin?: unknown;
  /**
   * Optional operator-baseline descriptor (config / test fixture). When absent,
   * the daemon loads `policy/egress/operator-baseline.json` from the fortress.
   */
  operatorBaseline?: unknown;
  /**
   * Optional exclusive-egress gate policy (config / test fixture; Unified
   * Protect Slice 1). When absent, the daemon loads
   * `policy/egress/exclusive-egress-gate.json` from the fortress. When BOTH
   * are absent (or the candidate is malformed), the manifest carries no gate
   * allow rule (fail closed: no derived grant).
   */
  exclusiveEgressGate?: unknown;
  /**
   * Explicit signing handle. When provided it is used verbatim (tests inject a
   * fake). When absent the daemon builds one via the helper path (default) or
   * the local path (`localSign`).
   */
  signer?: DaemonSigner;
  /**
   * Force the LOCAL (dev/test) signing path: decrypt the on-disk private key
   * with the master key and sign in-process. Default is the helper path. The
   * P1 key-non-extraction drill REQUIRES this to be OFF (the proof is void if a
   * local key can sign). Also honored via env `SANCTUARY_CASTLE_LOCAL_SIGN=1`.
   */
  localSign?: boolean;
  /** Absolute path to the `castle-wall-signer-client` shim (helper path). */
  signerClientPath?: string;
  /** Override the shim runner (tests). */
  signerClientInvoke?: ShimInvoker;
  /**
   * Audit provenance label for filter lifecycle events (`filter_started` /
   * `filter_stopped`). Defaults to "sanctuary-wrap" (the wrap-coupled
   * bring-up). The launchd boot service passes "launchd-boot" so boot-time
   * policy delivery is distinguishable in the audit log (F1).
   */
  auditSource?: string;
  /**
   * Override the root-owned global pin path used for the F-A2-1 #4
   * defense-in-depth cross-check (helper mode). Defaults to the production
   * custody path; tests point it at a nonexistent temp path to isolate from any
   * pin installed on the build host.
   */
  globalPinnedPublicKeyPath?: string;
  /**
   * Root-helper-published macOS audit-producer public key. When present, the
   * daemon pins the macOS flow-event consumer to it and copies it to the
   * existing fortress producer-key reader path. Missing means the honest macOS
   * channel-authenticated floor remains in effect.
   */
  auditProducerPublicKeyPath?: string;
  /**
   * Provider-side dead-man lease. Undefined/null means durable arming
   * (--no-ttl); a positive number means the extension fails open after that
   * many seconds unless renewed by the authenticated daemon channel.
   */
  armLeaseTtlSeconds?: number | null;
  armLeaseHeartbeatIntervalSeconds?: number;
  /**
   * Injectable wall clock (epoch ms) for the dead-man TTL deadline. Defaults to
   * `Date.now`. Tests inject a controllable clock so the periodic heartbeat's
   * TTL-expiry fail-open can be asserted deterministically without a real sleep.
   */
  now?: () => number;
  /**
   * Interval (seconds) of the periodic AUDIT liveness heartbeat (observability
   * Slice 2). This is a SEPARATE, slower cadence than the ~5s IPC arm-lease
   * heartbeat above: the IPC lease is an in-memory broadcast (no audit write),
   * whereas this writes ONE `castle_wall_heartbeat` audit entry so a reader can
   * tell an alive-but-idle wall from one that silently died in a quiet window.
   * Audit cadence (default 45s), never the 5s IPC cadence, so the heartbeat does
   * not bloat the audit chain. Tests inject a small value for determinism.
   */
  auditHeartbeatIntervalSeconds?: number;
  /**
   * Interval (seconds) of the periodic AS-AGENT-UID egress liveness probe
   * (confined-agent egress design 2026-07-10, MED-3 secondary signal).
   * Order-of-hours by default (21600s = 6h): for each `provisioned-*` allow
   * rule in the loaded manifest (uid mode only), a probe process running as
   * the agent uid attempts a TLS connect; a failure appends an
   * `egress_probe_failed` audit entry that the agent-egress sentinel
   * surfaces as an operator alert. Tests inject a small value.
   */
  agentEgressProbeIntervalSeconds?: number;
  /**
   * Injected as-uid egress probe (tests; also the ONLY way the probe runs on
   * a non-root / non-darwin daemon). Resolve true iff a process running as
   * `uid` completes a TLS connect to `host:port`. When absent, a real
   * `sudo -n -u '#<uid>' curl` probe is used IFF this daemon runs as root on
   * darwin; otherwise the timer stays OFF (no false alarms from a probe that
   * cannot actually change uid).
   */
  agentEgressProbe?: (uid: number, host: string, port: number) => Promise<boolean>;
  /**
   * Grace window (ms) of the Slice M emission-liveness watchdog: how long
   * decisions may keep arriving with ZERO persisted enforcement emission
   * before the daemon fails loud (`audit_emission_stall` audit entry + a
   * greppable stderr line). Defaults to
   * {@link DEFAULT_EMISSION_STALL_GRACE_MS}. Tests inject a small value.
   */
  emissionStallGraceMs?: number;
  /**
   * Cadence (seconds) of the watchdog's divergence evaluation tick. Defaults
   * to {@link CASTLE_WALL_DEFAULT_EMISSION_LIVENESS_TICK_SECONDS}. Tests
   * inject a small value.
   */
  emissionLivenessTickSeconds?: number;
  /**
   * Backstop deadline (ms) for the compose+sign phase of a `policy_reload`
   * (drill-found hang guard, 2026-07-12). Bounds custody reads + compose + the
   * helper re-sign so the reload can NEVER exceed the client's request deadline
   * silently; on breach the reload returns a specific `ok:false` rather than
   * hanging. Defaults to {@link CASTLE_WALL_RELOAD_SIGN_DEADLINE_MS}. Tests
   * inject a small value to assert the bounded refusal deterministically.
   */
  reloadSignDeadlineMs?: number;
  /**
   * Backstop deadline (ms) for the broadcast phase of a `policy_reload`. Bounds
   * the manifest fan-out to sysext subscribers so a wedged subscriber write
   * cannot hang the reload. Defaults to
   * {@link CASTLE_WALL_RELOAD_BROADCAST_DEADLINE_MS}. Tests inject a small value.
   */
  reloadBroadcastDeadlineMs?: number;
  /**
   * Deadline (ms) for the fire-and-forget audit write that records a reload
   * outcome. The reload response never awaits this write. Defaults to
   * {@link CASTLE_WALL_RELOAD_AUDIT_DEADLINE_MS}. Tests inject a small value.
   */
  reloadAuditDeadlineMs?: number;
  /**
   * Test-only fault-injection seam (mirrors the existing `signerClientInvoke` /
   * `agentEgressProbe` / `now` injection seams). When present it is awaited at
   * the very TOP of the reload compose phase, BEFORE any fortress read or the
   * re-sign, so a test can prove the whole-body reload deadline bounds a stall
   * that occurs before the signer is ever reached (not only a signer hang).
   * Undefined in production.
   */
  reloadComposeHook?: () => Promise<void>;
}

export type MacOSCastleWallListenerOptions = ConstructorParameters<
  typeof MacOSFlowIpcListener
>[0];

export interface MacOSCastleWallListenerHandle {
  start(): Promise<void>;
  stop(): Promise<void>;
  broadcastManifestUpdate(): Promise<number>;
  broadcastDecisionResponse(response: DecisionResponse): Promise<number>;
  broadcastArmLease(lease: ArmLeaseNotification): Promise<number>;
}

export interface MacOSCastleWallDaemonHandle {
  socketPath: string;
  reloadPolicy(): Promise<PolicyReloadResponse>;
  stop(): Promise<void>;
}

/** The composed + signed manifest state `loadManifestState` produces. */
export interface ManifestState {
  signed: SignedManifest;
  rules: AllowlistRule[];
}

interface ActiveCastleWallConfig {
  socket_path: string;
  fortress_id: string;
  fortress_path?: string;
  pid: number;
  started_at: string;
  pinned_pubkey_sha256?: string;
  /** Daemon role marker (#450 item 4): "safe" boot daemon vs "full" login daemon. */
  mode?: "safe" | "full";
}

/**
 * Resolve the uid the bound IPC socket must be (re-)owned by so the macOS
 * content-filter extension (which runs as the LOGGED-IN OPERATOR uid, not root)
 * can connect to it.
 *
 * WHY this exists (Slice M Layer-2, drilled 2026-06-29, Erik-present): macOS
 * audit-producer signing never engaged because the extension's IPC dispatcher
 * could not CONNECT to the daemon's UDS control socket. When the daemon runs as
 * ROOT (the engage drill ran it as root), `net.Server.listen()` binds the socket
 * owned by `root` at mode 0600, and a non-root operator-uid extension gets EPERM
 * connecting to it (the host app, which shares the extension's IPCClient
 * connect+handshake code, handshook fine over an OPERATOR-owned socket; only the
 * root-owned 0600 socket blocked it). The fix is to re-own the socket to the
 * operator uid (the same user the extension runs as), which is the uid that
 * OWNS THE FORTRESS DIRECTORY (an operator-owned 0o700 dir). Mode stays 0600, so
 * root (the daemon + a root-running extension) still reaches it via superuser
 * bypass and no other local user can; we NEVER widen the socket.
 *
 * Resolution order:
 *   - An explicit `socketOwnerUid` (the safe-mode boot daemon already derives
 *     and passes it) wins verbatim, preserving that path's behavior.
 *   - Otherwise, only when the daemon is running as ROOT (`getuid() === 0`, i.e.
 *     the socket would otherwise be root-owned) AND the fortress-dir owner is a
 *     DIFFERENT uid than the daemon process, return that owner uid so the socket
 *     is re-owned to the operator. When owners already match (a same-uid operator
 *     daemon), or we are not root, return `undefined` (no re-own is needed).
 *   - On a stat failure, warn and return `undefined` (fail-soft: the daemon still
 *     comes up + enforces; the re-own is best-effort and the listener's own
 *     chown is likewise loud-but-non-fatal).
 *
 * Pure except for the optional `warn` sink, so the LOGIC (target uid / skip
 * conditions) is unit-testable without a root-owned socket on disk.
 */
export function resolveSocketReownUid(input: {
  socketOwnerUid?: number;
  fortressPath: string;
  /** Current process uid; defaults to `process.getuid?.()`. Injected by tests. */
  processUid?: number | undefined;
  /** Stat the fortress dir for its owner uid; defaults to `fs.statSync`. */
  statFortressUid?: (fortressPath: string) => number;
  /** Operator-facing warning sink (stderr by default). */
  warn?: (message: string) => void;
}): number | undefined {
  if (input.socketOwnerUid !== undefined) {
    return input.socketOwnerUid;
  }
  const processUid =
    input.processUid !== undefined ? input.processUid : process.getuid?.();
  // Only a root daemon binds a root-owned socket the operator-uid extension
  // cannot reach. A non-root (operator) daemon already binds an operator-owned
  // socket; leave ownership untouched.
  if (processUid !== 0) {
    return undefined;
  }
  let ownerUid: number;
  try {
    ownerUid = input.statFortressUid
      ? input.statFortressUid(input.fortressPath)
      : statSync(input.fortressPath).uid;
  } catch (err) {
    // SAFETY: daemon startup diagnostics are operator-facing stderr output.
    (input.warn ?? defaultDaemonWarn)(
      `[castle-wall] warning: could not resolve the fortress owner for ${input.fortressPath} ` +
        `(${err instanceof Error ? err.message : String(err)}); the content-filter extension may be ` +
        `unable to connect to the root-owned control socket and audit-producer signing may not engage.`,
    );
    return undefined;
  }
  // Owners already match (a same-uid daemon, e.g. an operator daemon that somehow
  // reached here as root over its own fortress): no re-own needed.
  if (ownerUid === processUid) {
    return undefined;
  }
  return ownerUid;
}

function defaultDaemonWarn(message: string): void {
  // SAFETY: daemon startup diagnostics are operator-facing stderr output.
  console.error(message);
}

export async function startMacOSCastleWallDaemon(
  input: MacOSCastleWallDaemonInput,
): Promise<MacOSCastleWallDaemonHandle> {
  const socketPath =
    input.socketPath ??
    resolveCastleWallSocketPath({
      platform: input.platform ?? process.platform,
      fortressId: input.fortressId,
      fortressPath: input.fortressPath,
    }).path;
  const activeConfigPath = input.activeConfigPath ?? CASTLE_WALL_ACTIVE_CONFIG_PATH;
  // Legacy /tmp read-fallback only applies to the production default path, so a
  // test passing an explicit (hermetic) activeConfigPath is never perturbed by a
  // stray /tmp file from a real daemon.
  const legacyActiveConfigPath = input.activeConfigPath
    ? undefined
    : CASTLE_WALL_ACTIVE_CONFIG_LEGACY_PATH;

  const auditSource = input.auditSource ?? "sanctuary-wrap";
  const daemonMode: "safe" | "full" = input.daemonMode ?? "full";
  const reloadSignDeadlineMs =
    input.reloadSignDeadlineMs ?? CASTLE_WALL_RELOAD_SIGN_DEADLINE_MS;
  const reloadBroadcastDeadlineMs =
    input.reloadBroadcastDeadlineMs ?? CASTLE_WALL_RELOAD_BROADCAST_DEADLINE_MS;
  const reloadAuditDeadlineMs =
    input.reloadAuditDeadlineMs ?? CASTLE_WALL_RELOAD_AUDIT_DEADLINE_MS;

  // Slice M Layer-2: when the daemon runs as root the socket binds root-owned and
  // the operator-uid content-filter extension cannot connect (EPERM on a 0600 root
  // socket), so audit-producer signing never engages. Re-own to the fortress owner
  // (= the operator the extension runs as). An explicit `socketOwnerUid` (the
  // safe-mode boot daemon already supplies one) is honored verbatim; otherwise this
  // auto-derives it from the fortress dir so EVERY caller (notably `wrap`, which did
  // not pass one) is correct without per-caller patching. Mode stays 0600 and is
  // never widened. See {@link resolveSocketReownUid}.
  const socketOwnerUid = resolveSocketReownUid({
    ...(input.socketOwnerUid !== undefined
      ? { socketOwnerUid: input.socketOwnerUid }
      : {}),
    fortressPath: input.fortressPath,
  });

  await assertActiveConfigNotOwnedByLiveProcess(activeConfigPath, legacyActiveConfigPath);
  await assertSocketNotOwnedByLiveProcess(socketPath);
  await mkdir(join(input.fortressPath, "policy", "egress", "rules"), {
    recursive: true,
    mode: 0o700,
  });

  const signer = input.signer ?? (await loadSigningKey(input));
  await writeSystemPinnedPublicKey(signer, input.globalPinnedPublicKeyPath);
  const auditProducerKey = await loadMacOSAuditProducerPublicKey(
    input.auditProducerPublicKeyPath ?? CASTLE_GLOBAL_AUDIT_PRODUCER_PUBKEY_PATH,
  );
  if (auditProducerKey !== null) {
    await publishFortressAuditProducerPublicKey(
      input.fortressPath,
      auditProducerKey.bytes,
    );
  }
  const pinnedPublicKeySha256 = sha256Hex(signer.publicKey);
  const agentOrigin = await resolveAgentOrigin(input.fortressPath, input.agentOrigin);
  const protectionClaimSubject =
    protectionSubjectFromAgentOrigin(input.fortressId, agentOrigin) ??
    input.fortressId;
  const operatorBaseline = await resolveOperatorBaseline(
    input.fortressPath,
    input.operatorBaseline,
  );
  const exclusiveEgressGate = await resolveExclusiveEgressGate(
    input.fortressPath,
    input.exclusiveEgressGate,
  );
  let manifestState = await loadManifestState({
    fortressPath: input.fortressPath,
    fortressId: input.fortressId,
    signer,
    agentOrigin,
    operatorBaseline,
    exclusiveEgressGate,
    ...(input.globalPinnedPublicKeyPath
      ? { globalPinnedPublicKeyPath: input.globalPinnedPublicKeyPath }
      : {}),
  });
  const pendingRequests = new Set<string>();
  const heartbeatIntervalSeconds = input.armLeaseHeartbeatIntervalSeconds ?? 5;
  let leaseHeartbeat: NodeJS.Timeout | undefined;
  const stopLeaseHeartbeat = (): void => {
    if (!leaseHeartbeat) return;
    clearInterval(leaseHeartbeat);
    leaseHeartbeat = undefined;
  };
  // Absolute epoch-ms deadline of the operator's active dead-man TTL, or null
  // for durable (--no-ttl) arming. The daemon ADOPTS this when an operator
  // arm-lease with a positive `ttl_seconds` arrives (onArmLease), and its
  // periodic heartbeat re-broadcasts the REMAINING seconds toward this fixed
  // deadline. Without it, each heartbeat rebuilt the lease from the static
  // `input.armLeaseTtlSeconds` (never set by any caller -> always null), which
  // erased the operator's TTL in the extension every heartbeat interval, so the
  // dead-man `ttl_expired` fail-open never fired (2026-07-05 Mini1 TTL-expiry
  // drill: armed `--ttl 90s`, still enforcing at t+160s). `nowMs` is injectable
  // so the fail-open deadline is testable without a wall-clock sleep.
  const nowMs = input.now ?? (() => Date.now());
  let operatorLeaseDeadlineMs: number | null =
    typeof input.armLeaseTtlSeconds === "number" && input.armLeaseTtlSeconds > 0
      ? nowMs() + input.armLeaseTtlSeconds * 1000
      : null;
  // Latched once the lease heartbeat has broadcast a fully-expired (0s) lease,
  // so the interval self-cancels even in the first-emit-already-expired edge.
  // A fresh operator arm (onArmLease) clears it to resume renewals.
  let leaseExpired = false;
  /**
   * Remaining whole seconds until the operator's dead-man deadline, or null for
   * durable arming. Returns 0 once the deadline has passed so the next heartbeat
   * broadcasts `ttl_seconds: 0`, which the Swift extension turns into an
   * immediate `ttl_expired` fail-open. Never negative. Rounds UP so a still-live
   * lease is never reported as already-expired by a sub-second rounding error
   * (the anti-spurious-disarm direction: a dead-man must never fire early on a
   * live/renewed lease).
   */
  const remainingLeaseSeconds = (): number | null => {
    if (operatorLeaseDeadlineMs === null) return null;
    const remainingMs = operatorLeaseDeadlineMs - nowMs();
    if (remainingMs <= 0) return 0;
    return Math.ceil(remainingMs / 1000);
  };
  // Restart the periodic lease heartbeat if it is not currently running. Used
  // when a fresh operator arm arrives AFTER a prior TTL expiry stopped the beat
  // (re-arm resumes renewals). Assigned once the emit loop is wired up below;
  // an operator arm can only arrive after `listener.start()`, by which point
  // this is set. A no-op before then.
  let restartLeaseHeartbeat: (() => void) | undefined;
  const auditHeartbeatIntervalSeconds =
    input.auditHeartbeatIntervalSeconds ??
    CASTLE_WALL_DEFAULT_AUDIT_HEARTBEAT_INTERVAL_SECONDS;
  let auditHeartbeat: NodeJS.Timeout | undefined;
  const stopAuditHeartbeat = (): void => {
    if (!auditHeartbeat) return;
    clearInterval(auditHeartbeat);
    auditHeartbeat = undefined;
  };
  // Restart the periodic audit liveness heartbeat if it is not currently
  // running. Used when a fresh operator arm arrives AFTER a prior revoke
  // stopped the beat (final fix-round MED: onArmLeaseRevoke calls
  // stopAuditHeartbeat, and without a restart the re-engaged watchdog's
  // snapshot would never publish again for the rest of the process life).
  // Assigned in the startup try-block below (it closes over
  // emitAuditHeartbeat); an operator arm can only arrive after
  // `listener.start()`, by which point this is set. A no-op before then.
  let restartAuditHeartbeat: (() => void) | undefined;
  /**
   * #912 MED-1 fix (drill-found, 2026-07-12): a dropped best-effort reload
   * audit write (`recordReloadOutcome`'s detached persist missing its
   * deadline, or the underlying write itself failing) used to surface ONLY on
   * daemon stderr; the reload still reported `ok:true`, and the drop was
   * never chain-visible. Each drop is now counted here and stamped as an
   * `audit_write_degraded_count` detail field onto the next successfully
   * appended `castle_wall_heartbeat` (or the shutdown `filter_stopped`), so
   * the loss becomes a tamper-evident chain entry within one heartbeat
   * interval. A LOCAL detail field on existing operations, not a new
   * operation or a widened enum. Reservation semantics (fix-round HIGH):
   * see {@link createAuditWriteDegradedCarry} for why carries reserve units
   * up front instead of subtracting after the append lands.
   *
   * HONEST BOUND (fix-round MED): the pending count is PROCESS-LOCAL. Once a
   * carry is appended the marker is durable in the chain, but a count that
   * has not yet been carried survives only until process exit: the residual
   * loss window is one heartbeat interval, or a crash/SIGKILL before the
   * next carry. This is availability-of-evidence in a crash window, not a
   * forgery path; the full-chain verification is unchanged.
   * DEBT: if a drill ever shows that window matters, persist the pending
   * count alongside the existing daemon state (the active-config /
   * fortress-path files) instead of building a retry queue.
   *
   * MEANING (fix-round LOW-3, deliberate): the counter records reload
   * outcome audit writes NOT CONFIRMED within the deadline, not writes
   * proven lost. A detached append that misses the deadline but lands late
   * still increments (fail-safe over-report; the operator investigates a
   * marker and finds the entry present, rather than a real loss going
   * unmarked).
   */
  const degradedCarry = createAuditWriteDegradedCarry();
  const agentEgressProbeIntervalSeconds =
    input.agentEgressProbeIntervalSeconds ??
    CASTLE_WALL_DEFAULT_AGENT_EGRESS_PROBE_INTERVAL_SECONDS;
  let agentEgressProbeTimer: NodeJS.Timeout | undefined;
  const stopAgentEgressProbeTimer = (): void => {
    if (!agentEgressProbeTimer) return;
    clearInterval(agentEgressProbeTimer);
    agentEgressProbeTimer = undefined;
  };

  // Slice M emission-liveness watchdog (decided-vs-emitted divergence; the
  // honest #946 follow-up, root cause in
  // Review/Sanctuary/SliceM_Emission_Stall_RootCause_2026-07-17.md). The flow
  // consumer feeds it (receipts / emissions / rejections), the as-uid egress
  // probe feeds it (a daemon-initiated flow an armed wall must adjudicate),
  // and the tick timer below evaluates it. A stall fails LOUD: one greppable
  // stderr line plus one `audit_emission_stall` chain entry; recovery writes
  // the paired recovered entry. The callbacks must NEVER crash the daemon or
  // touch enforcement, and a failed stall-audit append must not mask the
  // alarm: the stderr line fires FIRST, unconditionally.
  const emissionLivenessTickSeconds =
    input.emissionLivenessTickSeconds ??
    CASTLE_WALL_DEFAULT_EMISSION_LIVENESS_TICK_SECONDS;
  // Fail-closed boundary validation (fix-round LOW): a 0/negative/NaN cadence
  // would either throw inside setInterval, silently clamp to a ~1ms busy
  // tick, or never tick; none of those is an acceptable failure mode for the
  // component whose job is detecting silent failure. Mirrors the watchdog's
  // own graceMs/minDecisions constructor validation.
  if (
    !Number.isFinite(emissionLivenessTickSeconds) ||
    emissionLivenessTickSeconds <= 0
  ) {
    throw new Error(
      `startMacOSCastleWallDaemon: emissionLivenessTickSeconds must be a positive finite number (got ${String(
        input.emissionLivenessTickSeconds,
      )})`,
    );
  }
  let emissionLivenessTimer: NodeJS.Timeout | undefined;
  const stopEmissionLivenessTimer = (): void => {
    if (!emissionLivenessTimer) return;
    clearInterval(emissionLivenessTimer);
    emissionLivenessTimer = undefined;
  };
  // Whether the operator has REVOKED the arm lease (deliberate stand-down).
  // Gates exactly ONE decision feed, the as-uid egress probe below (the
  // receipt feed in the flow consumer is deliberately ungated, so receipts
  // landing in a revoked window still count into the watchdog's state; the
  // fresh-arm stand-down in onArmLease clears them before the tick resumes).
  // The revoke handler also stops the tick timer: a stood-down wall makes no
  // emission promise, so nothing observed after a revoke may mature into a
  // stall alarm (fix-round MED). A fresh operator arm clears it.
  let armLeaseRevoked = false;
  // Idempotent starter so the tick timer can be resumed after a revoke
  // stopped it (mirror of restartLeaseHeartbeat). Defined here, first started
  // in the startup try-block below.
  const startEmissionLivenessTimer = (): void => {
    if (emissionLivenessTimer) return;
    // Slice M emission-liveness tick: evaluate the decided-vs-emitted
    // divergence on a fixed cadence. Pure counter comparison; the loud
    // outputs live in the watchdog callbacks below. A throwing evaluation
    // must never take down enforcement, so the tick catches and reports.
    emissionLivenessTimer = setInterval(() => {
      try {
        emissionLivenessWatchdog.evaluate();
      } catch (err) {
        // SAFETY: a throwing evaluate (e.g. a throwing onStall callback) must
        // never take down enforcement; surface it on the operator channel and
        // continue ticking.
        console.error(
          `${EMISSION_STALL_LOG_PREFIX} watchdog evaluation failed (non-fatal): ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }
    }, emissionLivenessTickSeconds * 1000);
    emissionLivenessTimer.unref();
  };
  const recordEmissionLivenessTransition = (
    operation:
      | typeof EMISSION_STALL_AUDIT_OP
      | typeof EMISSION_STALL_RECOVERED_AUDIT_OP,
    details: Record<string, unknown>,
    result: "success" | "failure",
  ): void => {
    void (async () => {
      await input.auditLog.append(
        "l1",
        operation,
        input.fortressId,
        {
          ...details,
          source: auditSource,
          // Provenance marker LAST, from constructed fields only (no
          // untrusted spread), mirroring the heartbeat / filter_stopped
          // pattern so the honest readers recognize daemon origin.
          [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
        },
        result,
      );
      await input.auditLog.flush();
    })().catch((err: unknown) => {
      // SAFETY: never crash the daemon, never mask the alarm; the stderr line
      // has already fired before this append was attempted, so this is a
      // best-effort diagnostic for a failed audit write, not the alarm itself.
      console.error(
        `${EMISSION_STALL_LOG_PREFIX} ${operation} audit write failed (non-fatal; stderr line above is the alarm): ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    });
  };
  const emissionLivenessWatchdog = new EmissionLivenessWatchdog({
    now: nowMs,
    ...(input.emissionStallGraceMs !== undefined
      ? { graceMs: input.emissionStallGraceMs }
      : {}),
    onStall: (finding: EmissionStallFinding) => {
      // SAFETY: this stderr line IS the loud alarm the divergence detector
      // exists to raise; it fires unconditionally, before any audit write, so
      // a wedged/failing audit store can never suppress the operator signal.
      console.error(
        `${EMISSION_STALL_LOG_PREFIX} enforcement decisions continue but audit emission has STOPPED: decided_since_last_emission=${finding.decidedSinceLastEmission} decided_total=${finding.decidedTotal} emitted_total=${finding.emittedTotal} rejected_total=${finding.rejectedTotal} ms_since_last_emission=${finding.msSinceLastEmissionMs ?? "never"} sources=${JSON.stringify(finding.decidedBySource)}`,
      );
      recordEmissionLivenessTransition(
        EMISSION_STALL_AUDIT_OP,
        {
          decided_total: finding.decidedTotal,
          emitted_total: finding.emittedTotal,
          rejected_total: finding.rejectedTotal,
          decided_since_last_emission: finding.decidedSinceLastEmission,
          decided_by_source: finding.decidedBySource,
          ms_since_last_emission: finding.msSinceLastEmissionMs,
          ms_since_first_unemitted_decision:
            finding.msSinceFirstUnemittedDecisionMs,
        },
        "failure",
      );
    },
    onRecovery: (finding: EmissionRecoveryFinding) => {
      // SAFETY: recovery is operator-relevant state (the stall cleared), so it
      // uses the same stderr operator channel as the stall alarm above; it
      // fires before the paired recovered audit write.
      console.error(
        `${EMISSION_STALL_LOG_PREFIX} audit emission RECOVERED after ${finding.stallDurationMs}ms (decided_during_stall=${finding.decidedDuringStall})`,
      );
      recordEmissionLivenessTransition(
        EMISSION_STALL_RECOVERED_AUDIT_OP,
        {
          decided_total: finding.decidedTotal,
          emitted_total: finding.emittedTotal,
          rejected_total: finding.rejectedTotal,
          decided_during_stall: finding.decidedDuringStall,
          stall_duration_ms: finding.stallDurationMs,
        },
        "success",
      );
    },
  });

  const consumer = new MacOSFlowEventConsumer({
    manifestProvider: {
      currentSnapshot() {
        return {
          signed_manifest: manifestState.signed,
          rules: manifestState.rules,
        };
      },
    },
    approvalQueue: {
      async enqueue(input) {
        pendingRequests.add(input.requestId);
      },
    },
    auditSink: input.auditLog,
    defaultApprovalTimeoutSeconds: 30,
    pinnedProducerKeyB64url: auditProducerKey?.keyB64url ?? null,
    fortressId: input.fortressId,
    emissionLiveness: emissionLivenessWatchdog,
  });

  const listenerOptions: MacOSCastleWallListenerOptions = {
    socketPath,
    ...(socketOwnerUid !== undefined ? { socketOwnerUid } : {}),
    consumer,
    handshakeSigner: {
      fortressId: input.fortressId,
      signingKeyId: signer.signingKeyId,
      // B2: delegate nonce signing to the helper (or local dev path), symmetric
      // with manifest signing. Async — the listener awaits it.
      signNonce(nonce) {
        return signer.signNonce(nonce);
      },
    },
    adminHandler: {
      async reloadPolicy(request) {
        return reloadPolicy(request);
      },
      async handleDecision(response) {
        if (!pendingRequests.has(response.request_id)) {
          return { ok: false, error: `no pending request matches ${response.request_id}` };
        }
        pendingRequests.delete(response.request_id);
        await listener.broadcastDecisionResponse(response);
        await input.auditLog.append(
          "l1",
          "operator_decision",
          input.fortressId,
          {
            request_id: response.request_id,
            decision: response.decision,
            learn: response.learn,
            source: "castle-wall-cli",
            // NB: deliberately NOT stamped with the Castle Wall provenance
            // marker. An operator CLI decision is broadcast to the extension but
            // delivery/application is not confirmed here (broadcastDecisionResponse
            // can reach zero subscribers if the extension disconnected), so it is
            // not proof of live enforcement. The honest posture arms only from
            // real adjudicated flows (egress_allowed/egress_blocked via
            // flow_decision_recorded), never from an unacknowledged operator
            // decision. Marking this would be a false-green over-claim.
          },
          "success",
        );
        await input.auditLog.flush();
        return { ok: true };
      },
    },
    onArmLease(lease) {
      // ADOPT the operator's dead-man TTL so the periodic heartbeat below
      // re-broadcasts the SAME deadline (decrementing remaining seconds) rather
      // than erasing it with a no-TTL renewal. A positive `ttl_seconds` anchors
      // a fresh deadline; null/absent (an explicit --no-ttl arm) clears any
      // prior deadline back to durable. Never EXTENDS an unrelated deadline: the
      // most recent operator arm is authoritative.
      operatorLeaseDeadlineMs =
        typeof lease.ttl_seconds === "number" && lease.ttl_seconds > 0
          ? nowMs() + lease.ttl_seconds * 1000
          : null;
      // A fresh arm clears any prior expiry latch and resumes renewals if a
      // previous TTL expiry had stopped the beat (re-arm after fail-open).
      leaseExpired = false;
      restartLeaseHeartbeat?.();
      // A fresh arm also re-engages the emission-liveness watchdog that a
      // prior revoke stood down (fix-round MED). Stand it down FIRST (final
      // fix-round HIGH): the receipt feed is deliberately not gated by the
      // revoke, so receipts landing DURING the revoked window (an in-flight
      // or draining sysext, validation-rejected or persist-failing
      // decisions) accumulate as an unemitted run whose grace anchor keeps
      // aging while the wall is intentionally stood down. Restarting the
      // tick with that stale run intact would mature it into a false
      // `audit_emission_stall` on the first post-re-arm tick; clearing it
      // here means only FRESH post-re-arm divergence can fire. Then clear
      // the revoke gate so the probe feed counts again, and resume the
      // divergence tick.
      emissionLivenessWatchdog.standDown();
      armLeaseRevoked = false;
      startEmissionLivenessTimer();
      // The revoke also stopped the audit liveness heartbeat; restart it so
      // the re-armed wall's liveness (and the re-engaged watchdog's snapshot
      // riding each beat) publishes again (final fix-round MED). Mirrors the
      // initial start: one immediate best-effort beat, then the interval.
      restartAuditHeartbeat?.();
    },
    async onArmLeaseRevoke() {
      stopLeaseHeartbeat();
      // A revoke ends the operator's dead-man window; drop the adopted deadline
      // so a later re-arm cannot inherit a stale expiry.
      operatorLeaseDeadlineMs = null;
      // A revoked arm-lease means the wall is no longer enforcing for this
      // operator; stop claiming liveness too so the reader does not see a fresh
      // heartbeat from a daemon that has been told to stand down.
      stopAuditHeartbeat();
      // Stand the emission-liveness watchdog down with the wall (fix-round
      // MED): a deliberately revoked wall makes no emission promise, so
      // decisions observed BEFORE the revoke must not mature into a stall
      // alarm after it (false-fire on an intentionally stood-down wall), and
      // the probe feed is gated off via `armLeaseRevoked` so probe attempts
      // on an unarmed wall are never counted as decisions. Timer stopped +
      // run cleared; a fresh operator arm (onArmLease) re-engages both.
      armLeaseRevoked = true;
      stopEmissionLivenessTimer();
      emissionLivenessWatchdog.standDown();
      // Observability Slice 2 (false-RED fix): RECORD the intentional stand-down.
      // Stopping the heartbeat without a recorded reason is indistinguishable
      // from a daemon that was KILLED mid-flight, so the silent-death reader
      // would raise a false `dead_no_heartbeat`/red alarm for the whole digest
      // window on a deliberately-revoked wall. A clean `stop()` already files
      // `filter_stopped`; a lease revoke must leave the same recognizable
      // "stood down on purpose" signal. Stamped with the SAME `cw_source` marker
      // the heartbeat carries (constructed fields only, marker LAST, no untrusted
      // spread), so the reader recognizes it on the heartbeat's trust basis. A
      // write failure must never crash the stand-down path; the reader fails
      // toward the alarm (a missing stand-down reads as silent death), so a
      // dropped marker is surfaced honestly rather than masked.
      try {
        await input.auditLog.append(
          "l1",
          CASTLE_WALL_ARM_LEASE_REVOKED_OPERATION,
          protectionClaimSubject,
          {
            socket_path: socketPath,
            source: auditSource,
            daemon_mode: daemonMode,
            fortress_id: input.fortressId,
            // Provenance marker LAST, from constructed fields only.
            [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
          },
          "success",
        );
        await input.auditLog.flush();
      } catch {
        // Intentional no-op: see comment above (fail toward the alarm).
      }
    },
  };
  const listener = input.listenerFactory
    ? input.listenerFactory(listenerOptions)
    : new MacOSFlowIpcListener(listenerOptions);

  let activeConfigWritten = false;
  // The path active-config was actually written to (the protected path, or the
  // operator-writable fallback when the custody dir is root-owned). Cleanup must
  // target the SAME file, so we thread the resolved path rather than assume it.
  let writtenActiveConfigPath = activeConfigPath;
  try {
    await listener.start();
    writtenActiveConfigPath = await writeActiveConfig(
      activeConfigPath,
      {
        socket_path: socketPath,
        fortress_id: input.fortressId,
        fortress_path: input.fortressPath,
        pid: process.pid,
        started_at: new Date().toISOString(),
        pinned_pubkey_sha256: pinnedPublicKeySha256,
        mode: daemonMode,
      },
      legacyActiveConfigPath,
    );
    activeConfigWritten = true;
    await input.auditLog.append(
      "l1",
      "filter_started",
      protectionClaimSubject,
      { socket_path: socketPath, source: auditSource, fortress_id: input.fortressId },
      "success",
    );
    await input.auditLog.flush();
    const emitLease = async (): Promise<void> => {
      // Broadcast the REMAINING seconds of the operator's active dead-man TTL,
      // not the static `input.armLeaseTtlSeconds`. This is the fix for the
      // 2026-07-05 TTL-expiry gap: previously every heartbeat re-broadcast a
      // no-TTL lease (input.armLeaseTtlSeconds was never set by any caller), so
      // the extension's `leaseExpiresAt` was cleared every interval and the
      // dead-man never fired. Now the deadline stays fixed (heartbeat refreshes
      // liveness; remaining seconds count down toward the operator's arm+ttl
      // instant) and the Swift `ttl_expired` fail-open fires on schedule.
      const remaining = remainingLeaseSeconds();
      await listener.broadcastArmLease(buildArmLease({
        armed: true,
        ttlSeconds: remaining,
        heartbeatIntervalSeconds,
      })).catch(() => undefined);
      // Once the deadline has passed, we have broadcast `ttl_seconds: 0` (an
      // immediate fail-open in the extension). Stop the lease heartbeat so we do
      // not keep spamming a 0-TTL renewal; the wall has intentionally degraded
      // to the operator-armed fail-open. The audit liveness heartbeat is left
      // running (the daemon process itself is still alive and honest about it).
      // `leaseExpired` also covers the (test-only) case where the FIRST emit is
      // already expired: the interval is created just below, so a plain
      // stopLeaseHeartbeat() here would no-op against a not-yet-assigned handle;
      // the flag makes the next tick self-cancel.
      if (remaining === 0) {
        leaseExpired = true;
        stopLeaseHeartbeat();
      }
    };
    restartLeaseHeartbeat = (): void => {
      if (leaseHeartbeat) return;
      leaseHeartbeat = setInterval(() => {
        if (leaseExpired) {
          stopLeaseHeartbeat();
          return;
        }
        void emitLease();
      }, heartbeatIntervalSeconds * 1000);
      leaseHeartbeat.unref();
    };
    await emitLease();
    restartLeaseHeartbeat();

    // Observability Slice 2: periodic AUDIT liveness heartbeat. SEPARATE from the
    // IPC arm-lease heartbeat above (that is an in-memory broadcast; this writes
    // ONE audit entry). A reader turns a MISSING heartbeat in a quiet window into
    // an honest "the wall silently died" alarm instead of `unknown`.
    //
    // Provenance: stamped with the SAME `cw_source` marker the audit consumer
    // stamps on enforcement evidence (`egress_blocked`), built from constructed
    // fields only (no untrusted spread) and stamped LAST, so a forger cannot mint
    // a fake "I am alive" beat that out-ranks the marker.
    //
    // BASIS HONESTY: this is a DIRECT audit append, NOT routed through the signing
    // audit consumer, so a genuine beat is CHANNEL-basis (marker only, no producer
    // signature) on EVERY host, Linux included. The reader gates the heartbeat
    // with `livenessEntryCounts` (a genuine channel beat counts on a key-bearing
    // host; only a forged `producer_signed`-claiming beat with a bad signature is
    // dropped), so the silent-death alarm stays functional on Linux. It does NOT
    // require the stricter enforcement-evidence signature gate `egress_blocked`
    // uses (see `principal-policy/feature-health.ts`).
    //
    // HONESTY: a heartbeat proves the daemon is ALIVE, NOT that it adjudicated a
    // real flow, so the reader keeps it OUT of the green/armed determination.
    const emitAuditHeartbeat = async (): Promise<void> => {
      // RESERVATION carry (fix-round HIGH): take ownership of the pending
      // units synchronously BEFORE the append, so an overlapping beat (slow
      // append + short interval) reserves 0 and can never double-subtract
      // the same units. A drop recorded WHILE this write is in flight stays
      // pending for the next beat.
      const degradedCountThisBeat = degradedCarry.reserve();
      // Slice M fix-round HIGH: the emission-liveness watchdog is a detector
      // FOR silent failure, so its own liveness must be observable, not
      // assumed. Each heartbeat carries a compact watchdog snapshot on the
      // same provenance basis as `audit_write_degraded_count` (a LOCAL detail
      // field on the existing heartbeat operation, constructed fields only).
      // `last_evaluate_at_ms` is the tick timer's own pulse: a cleared /
      // never-started tick shows up as a null or stale value against the
      // advancing heartbeat timestamps instead of being invisible.
      const emissionLivenessSnapshot = emissionLivenessWatchdog.snapshot();
      try {
        await input.auditLog.append(
          "l1",
          CASTLE_WALL_HEARTBEAT_OPERATION,
          protectionClaimSubject,
          {
            socket_path: socketPath,
            source: auditSource,
            daemon_mode: daemonMode,
            fortress_id: input.fortressId,
            // #912 MED-1: a non-zero count means a reload outcome audit write
            // was not confirmed within its deadline (deadline or persist
            // failure) since the last successfully carried marker. See the
            // `degradedCarry` declaration above for the exact semantics.
            ...(degradedCountThisBeat > 0
              ? { audit_write_degraded_count: degradedCountThisBeat }
              : {}),
            emission_liveness: {
              decided_total: emissionLivenessSnapshot.decidedTotal,
              emitted_total: emissionLivenessSnapshot.emittedTotal,
              decided_since_last_emission:
                emissionLivenessSnapshot.decidedSinceLastEmission,
              stalled: emissionLivenessSnapshot.stalled,
              last_evaluate_at_ms: emissionLivenessSnapshot.lastEvaluateAtMs,
            },
            // Provenance marker LAST, from constructed fields only (no untrusted
            // spread), mirroring the audit consumer's enforcement-evidence path.
            [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
          },
          "success",
        );
        await input.auditLog.flush();
      } catch {
        // A heartbeat write failure must never crash the daemon or take down
        // enforcement. The reader's silent-death detection fails toward an
        // alarm (a MISSING heartbeat reads as fault), so a dropped beat is
        // surfaced honestly rather than masked. The reserved units go back
        // so the next beat retries carrying the same count.
        degradedCarry.restore(degradedCountThisBeat);
      }
    };
    const startAuditHeartbeatInterval = (): void => {
      auditHeartbeat = setInterval(() => {
        void emitAuditHeartbeat();
      }, auditHeartbeatIntervalSeconds * 1000);
      auditHeartbeat.unref();
    };
    restartAuditHeartbeat = (): void => {
      if (auditHeartbeat) return;
      // One immediate best-effort beat so the re-armed wall's liveness (and
      // the watchdog snapshot it carries) is visible without waiting a full
      // audit-cadence interval, mirroring the awaited first beat of the
      // initial start below. emitAuditHeartbeat handles its own write
      // failures, so nothing here can throw into the arm path.
      void emitAuditHeartbeat();
      startAuditHeartbeatInterval();
    };
    await emitAuditHeartbeat();
    startAuditHeartbeatInterval();

    // Slice M emission-liveness tick (definition next to
    // stopEmissionLivenessTimer above; restarted by a fresh operator arm
    // after a revoke stopped it).
    startEmissionLivenessTimer();

    // Confined-agent egress MED-3 (secondary signal): periodic AS-AGENT-UID
    // egress liveness probe over the provisioned-* allow rules in the loaded
    // manifest. Refuse-to-arm protects the ARM moment; this timer bounds
    // RUNTIME silent degradation (a rotated host, a harness update, a broken
    // path) to the probe interval: a failed probe appends one
    // `egress_probe_failed` audit entry (result: failure) that the
    // agent-egress sentinel raises as an operator alert. Observation only --
    // it never mutates policy or enforcement. The timer only runs when a
    // probe is available (injected, or root-on-darwin for the real
    // `sudo -u '#<uid>'` probe): a probe that cannot actually change uid
    // would report the DAEMON's reachability and alarm falsely.
    const agentEgressProbe = resolveAgentEgressProbe(input);
    if (agentEgressProbe !== undefined) {
      const emitAgentEgressProbe = async (): Promise<void> => {
        try {
          const origin = manifestState.signed.manifest.agent_origin;
          if (!origin || origin.mode !== "uid" || typeof origin.agent_uid !== "number") {
            return;
          }
          const provisioned = manifestState.rules.filter(
            (rule) => rule.disposition === "allow" && rule.id.startsWith("provisioned-"),
          );
          for (const rule of provisioned) {
            const hostAxis = rule.match.host;
            const host = Array.isArray(hostAxis) ? hostAxis[0] : hostAxis;
            if (typeof host !== "string" || host.length === 0) continue;
            const portAxis = rule.match.port;
            const port = Array.isArray(portAxis) ? portAxis[0] : portAxis;
            const destPort = typeof port === "number" ? port : 443;
            let reachable = false;
            try {
              reachable = await agentEgressProbe(origin.agent_uid, host, destPort);
            } catch {
              reachable = false;
            }
            // Slice M emission-liveness: an INFERRED decision signal, and an
            // honest accounting of what it proves. What the daemon observes
            // here is ONLY its own probe attempt and its connect outcome. It
            // does NOT observe a sysext verdict for this flow: no receipt is
            // matched to it, and a successful (allowed) probe is not
            // correlated with any paired audit entry here. Counting it as a
            // decision rests on an inference: while an operator arm is live
            // and a sysext subscriber is connected, a real as-agent-uid flow
            // SHOULD be adjudicated by the wall, so a sustained run of probe
            // attempts with ZERO emissions is divergence-shaped evidence.
            // That inference can be wrong exactly when the wall is not
            // actually filtering this flow, which is why this feed is gated
            // on the arm-lease state (below) and why it is NOT the owed
            // instrument from the root-cause doc section 6(b): that design
            // correlates each probe with the appearance of its OWN audit
            // entry and only it fires under every surviving hypothesis.
            // Gates: never counted after an operator revoke (a stood-down
            // wall adjudicates nothing on this operator's behalf; fix-round
            // MED), and never without a sysext subscriber (nothing on the
            // channel could emit, and the silent-death / provider_unbound
            // alarms own that state).
            if (!armLeaseRevoked && consumer.getStats().subscribers > 0) {
              emissionLivenessWatchdog.noteDecision("agent_egress_probe");
            }
            if (!reachable) {
              await input.auditLog.append(
                "l1",
                EGRESS_PROBE_FAILED_AUDIT_OP,
                input.fortressId,
                {
                  host,
                  port: destPort,
                  agent_uid: origin.agent_uid,
                  rule_id: rule.id,
                  source: auditSource,
                },
                "failure",
              );
              await input.auditLog.flush();
            }
          }
        } catch {
          // The probe must never crash the daemon or take down enforcement;
          // a missed probe cycle is bounded by the next interval tick.
        }
      };
      agentEgressProbeTimer = setInterval(() => {
        void emitAgentEgressProbe();
      }, agentEgressProbeIntervalSeconds * 1000);
      agentEgressProbeTimer.unref();
    }
  } catch (err) {
    stopLeaseHeartbeat();
    stopAuditHeartbeat();
    stopAgentEgressProbeTimer();
    stopEmissionLivenessTimer();
    if (activeConfigWritten) {
      await removeActiveConfigIfCurrent(writtenActiveConfigPath, socketPath, input.fortressId);
    }
    await listener.stop().catch(() => undefined);
    throw err;
  }

  /**
   * Record a reload outcome to the audit log BEST-EFFORT and FIRE-AND-FORGET.
   *
   * Drill-found root cause (Mini1 2026-07-12, second miss): the reload COMPLETED
   * the compose + sign + broadcast, but the response was gated behind
   * `auditLog.append` + `flush`. A slow / wedged / lock-contended audit write
   * therefore turned a successful reload into a client-visible generic timeout
   * AND swallowed the bounded refusal (the failure-audit in the old catch block
   * hung the same way, so no response was ever written). The audit write is
   * observability, not correctness: the manifest is already signed and
   * broadcast to the enforcing sysext. So the response path MUST NOT await it.
   * This runs it detached, under its own deadline so it can never leak a pending
   * operation, and never rejects into the caller.
   */
  function recordReloadOutcome(
    operation: "policy_loaded" | "policy_validation_failed",
    details: Record<string, unknown>,
    result: "success" | "failure",
  ): void {
    void withReloadDeadline(
      (async () => {
        await input.auditLog.append(
          "l1",
          operation,
          input.fortressId,
          { ...details, source: "castle-wall-reload" },
          result,
        );
        await input.auditLog.flush();
      })(),
      reloadAuditDeadlineMs,
      `reload audit write (${operation}) did not complete within ${reloadAuditDeadlineMs}ms`,
    ).catch((err: unknown) => {
      // A dropped audit write must not be silent: count it so it becomes
      // chain-visible on the next successful carry (#912 MED-1; see the
      // `degradedCarry` declaration / `emitAuditHeartbeat` above).
      degradedCarry.record();
      // SAFETY: the reload itself never fails on this (the wall is already
      // armed with the new manifest); the immediate operator signal is
      // daemon stderr, and the chain marker above is the durable record.
      console.error(
        `[castle-wall] reload audit write (${operation}) failed (non-fatal): ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    });
  }

  async function reloadPolicy(
    request?: PolicyReloadRequest,
  ): Promise<PolicyReloadResponse> {
    const requestId = request?.request_id ?? randomBytes(16).toString("hex");
    // Preserve the last-known-good signature for the failure response BEFORE any
    // await, so a bounded refusal can be returned without touching (possibly
    // wedged) shared state.
    const lastKnownSignature = manifestState.signed.signature.signature_b64url;
    try {
      // Drill-found hang guard (Mini1 egress drill 2026-07-12): a policy reload
      // RE-COMPOSES and RE-SIGNS the ruleset through the root signer helper. The
      // ENTIRE compose+sign phase (the fortress reads AND the re-sign) runs under
      // one internal deadline strictly shorter than the client's request
      // deadline, so a stall ANYWHERE before the sign completes (a hung fortress
      // read, a stalled signer helper) surfaces as a FAST, SPECIFIC `ok:false`
      // from the daemon rather than a generic client-side "IPC request timed
      // out". The response is NEVER gated on the audit write (see
      // recordReloadOutcome). A bounded specific refusal preserves fail-closed
      // refuse-to-arm.
      manifestState = await withReloadDeadline(
        (async () => {
          // Test-only fault-injection point (before any real work), so the
          // whole-body bound can be proven for a stall that is NOT the signer.
          if (input.reloadComposeHook) {
            await input.reloadComposeHook();
          }
          const reloadedOrigin = await resolveAgentOrigin(
            input.fortressPath,
            input.agentOrigin,
          );
          const reloadedBaseline = await resolveOperatorBaseline(
            input.fortressPath,
            input.operatorBaseline,
          );
          const reloadedGate = await resolveExclusiveEgressGate(
            input.fortressPath,
            input.exclusiveEgressGate,
          );
          return await loadManifestState({
            fortressPath: input.fortressPath,
            fortressId: input.fortressId,
            signer,
            agentOrigin: reloadedOrigin,
            operatorBaseline: reloadedBaseline,
            exclusiveEgressGate: reloadedGate,
            ...(input.globalPinnedPublicKeyPath
              ? { globalPinnedPublicKeyPath: input.globalPinnedPublicKeyPath }
              : {}),
          });
        })(),
        reloadSignDeadlineMs,
        `policy reload did not compose and sign within ${reloadSignDeadlineMs}ms (signer helper or fortress read stalled)`,
      );
      const emitted = await withReloadDeadline(
        listener.broadcastManifestUpdate(),
        reloadBroadcastDeadlineMs,
        `manifest broadcast did not complete within ${reloadBroadcastDeadlineMs}ms during policy reload`,
      );
      // Fire-and-forget: the response is returned WITHOUT awaiting the audit.
      recordReloadOutcome(
        "policy_loaded",
        {
          loaded_rule_count: manifestState.rules.length,
          // Surface auto-derived rules (#380) so a derived grant is never
          // silently invisible in policy introspection.
          derived_rule_ids: manifestState.rules
            .filter((rule) => rule.derived === true)
            .map((rule) => rule.id),
          emitted_subscribers: emitted,
        },
        "success",
      );
      return {
        type: "policy_reload_response",
        request_id: requestId,
        ok: true,
        loaded_manifest_signature_b64url: manifestState.signed.signature.signature_b64url,
        loaded_rule_count: manifestState.rules.length,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      // Fire-and-forget: a bounded refusal must reach the client even if the
      // audit log is the thing that is wedged.
      recordReloadOutcome("policy_validation_failed", { error: message }, "failure");
      return {
        type: "policy_reload_response",
        request_id: requestId,
        ok: false,
        loaded_manifest_signature_b64url: lastKnownSignature,
        loaded_rule_count: manifestState.rules.length,
        error: message,
      };
    }
  }

  return {
    socketPath,
    reloadPolicy,
    async stop() {
      try {
        stopLeaseHeartbeat();
        // Stop the audit liveness heartbeat in the SAME teardown that stops the
        // IPC lease heartbeat, so a stopped daemon stops claiming liveness.
        stopAuditHeartbeat();
        stopAgentEgressProbeTimer();
        stopEmissionLivenessTimer();
        await listener.broadcastArmLease(buildArmLease({
          armed: false,
          ttlSeconds: null,
          heartbeatIntervalSeconds,
        })).catch(() => undefined);
        await listener.stop();
        // #912 MED-1: carry any still-pending degraded-write count into the
        // shutdown audit write too, not only the next heartbeat -- a reload
        // that drops its audit write shortly before `stop()` must not lose the
        // marker to a heartbeat that never fires again. Same RESERVATION
        // semantics as the heartbeat carry (fix-round HIGH; the same
        // double-subtract race exists against an in-flight beat at teardown):
        // reserve before the append, restore on append failure.
        const degradedCountAtStop = degradedCarry.reserve();
        try {
          await input.auditLog.append(
            "l1",
            "filter_stopped",
            protectionClaimSubject,
            {
              socket_path: socketPath,
              source: auditSource,
              fortress_id: input.fortressId,
              ...(degradedCountAtStop > 0
                ? { audit_write_degraded_count: degradedCountAtStop }
                : {}),
              // Observability Slice 2 (false-RED fix): stamp the SAME `cw_source`
              // marker the heartbeat carries so the silent-death reader recognizes
              // this clean operator stop as an INTENTIONAL stand-down (off on
              // purpose) and does NOT raise a false `dead_no_heartbeat`/red alarm.
              // Constructed fields only, marker LAST (no untrusted spread). Gated
              // read-side on the heartbeat's trust basis; it can only relabel red
              // to a non-green `unknown`, never manufacture green.
              [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
            },
            "success",
          );
          await input.auditLog.flush();
        } catch (err) {
          degradedCarry.restore(degradedCountAtStop);
          throw err;
        }
      } finally {
        await removeActiveConfigIfCurrent(writtenActiveConfigPath, socketPath, input.fortressId);
      }
    },
  };
}

function buildArmLease(input: {
  armed: boolean;
  ttlSeconds: number | null;
  heartbeatIntervalSeconds: number;
  revoked?: boolean;
}): ArmLeaseNotification {
  return {
    type: "arm_lease",
    armed: input.armed,
    ...(input.revoked === true ? { revoked: true } : {}),
    ttl_seconds: input.ttlSeconds,
    heartbeat_interval_seconds: input.heartbeatIntervalSeconds,
    updated_at: new Date().toISOString(),
  };
}

/**
 * Race `op` against a deadline. Resolves with `op`'s value when it settles
 * first; rejects with a specific-reason Error on timeout. The underlying `op`
 * is NOT cancelled (the helper-sign shim already self-terminates at its own
 * timeout, and a late-settling `op` is simply dropped): the point is that the
 * caller returns PROMPTLY with a specific reason rather than blocking until a
 * downstream client's own generic deadline fires. Fail-closed: a timeout is an
 * error, so a `reloadPolicy` that times out here returns `ok:false`, never a
 * silent partial success.
 */
/**
 * Pending degraded-audit-write counter with RESERVATION carry semantics
 * (#912 MED-1 follow-up, fix-round HIGH).
 *
 * `record()` counts one dropped (deadline-missed or persist-failed) audit
 * write. A carrier calls `reserve()` to take ownership of the units it will
 * stamp into a chain entry, BEFORE starting its append; on append failure it
 * calls `restore(units)` so the next carrier retries them. Because a reserve
 * synchronously zeroes the pending units, two overlapping carries can never
 * both snapshot and then both subtract the same units (the double-subtract
 * bug: two concurrent heartbeat carries of the same 1-unit snapshot drove the
 * counter to -1, and a LATER real drop incremented -1 to 0, so its marker
 * never emitted and the loss became chain-invisible again).
 *
 * The count is clamped at >= 0: with reservation semantics a negative value
 * is unreachable, so reaching one means the carry protocol was violated and
 * is reported loudly instead of silently corrupting later markers.
 *
 * Exported for direct unit-testing of the reservation and clamp invariants;
 * production code uses the single instance inside
 * {@link startMacOSCastleWallDaemon}.
 */
export interface AuditWriteDegradedCarry {
  /** Count one dropped audit write. */
  record(): void;
  /** Take ownership of all pending units (may be 0). Call BEFORE the append. */
  reserve(): number;
  /** Return reserved units after a FAILED carry so the next carrier retries them. */
  restore(units: number): void;
}

export function createAuditWriteDegradedCarry(): AuditWriteDegradedCarry {
  let pending = 0;
  const clamp = (): void => {
    if (pending >= 0) return;
    // SAFETY: an impossible negative counter is an invariant violation in the
    // carry protocol; report it loudly on daemon stderr rather than letting it
    // silently swallow the next real drop's marker.
    console.error(
      `[castle-wall] degraded-audit-write counter went negative (${pending}); clamping to 0 (carry-protocol invariant violation)`,
    );
    pending = 0;
  };
  return {
    record() {
      pending += 1;
    },
    reserve() {
      const units = pending;
      pending -= units;
      clamp();
      return units;
    },
    restore(units) {
      pending += units;
      clamp();
    },
  };
}

function withReloadDeadline<T>(
  op: Promise<T>,
  deadlineMs: number,
  timeoutReason: string,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error(timeoutReason));
    }, deadlineMs);
    timer.unref?.();
    op.then(
      (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(value);
      },
      (err: unknown) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(err instanceof Error ? err : new Error(String(err)));
      },
    );
  });
}

const AGENT_ORIGIN_FILENAME = "agent-origin.json";
const OPERATOR_BASELINE_FILENAME = "operator-baseline.json";

/**
 * Resolve the exclusive-egress gate policy (Unified Protect Slice 1): prefer
 * the explicit input, fall back to `policy/egress/exclusive-egress-gate.json`
 * in the fortress. BOTH branches run through
 * `validateExclusiveEgressGatePolicy`; a malformed candidate resolves to
 * `undefined` (fail closed: the manifest carries no gate allow rule, so no
 * derived grant is ever signed from bad bytes).
 */
async function resolveExclusiveEgressGate(
  fortressPath: string,
  explicitInput: unknown,
): Promise<ExclusiveEgressGatePolicy | undefined> {
  if (explicitInput !== undefined) {
    const validated = validateExclusiveEgressGatePolicy(explicitInput);
    if (validated === null) {
      // SAFETY: daemon startup diagnostics are operator-facing stderr output.
      console.warn(
        "[castle-wall] warning: explicit exclusive-egress gate policy is structurally invalid; ignoring (no gate rule derived)",
      );
      return undefined;
    }
    return validated;
  }
  const filePath = join(fortressPath, "policy", "egress", EXCLUSIVE_EGRESS_GATE_FILENAME);
  try {
    const raw = await readFileCustody(filePath, {
      encoding: "utf8",
      verifyPathIdentity: true,
    });
    const parsed = JSON.parse(raw) as unknown;
    const validated = validateExclusiveEgressGatePolicy(parsed);
    if (validated === null) {
      // SAFETY: daemon startup diagnostics are operator-facing stderr output.
      console.warn(
        `[castle-wall] warning: ${EXCLUSIVE_EGRESS_GATE_FILENAME} is structurally invalid; ignoring (no gate rule derived)`,
      );
      return undefined;
    }
    return validated;
  } catch (err) {
    const code = err instanceof Error && "code" in err
      ? (err as NodeJS.ErrnoException).code
      : undefined;
    if (code === "ENOENT") return undefined;
    throw err;
  }
}

/**
 * Resolve the agent-origin descriptor from config: prefer the explicit input,
 * fall back to `policy/egress/agent-origin.json` in the fortress. Returns
 * `undefined` when no descriptor is available (manifest omits the field =>
 * sysext classifies everything `.agent`).
 */
async function resolveAgentOrigin(
  fortressPath: string,
  explicitInput: unknown,
): Promise<unknown> {
  if (explicitInput !== undefined) {
    return explicitInput;
  }
  const filePath = join(fortressPath, "policy", "egress", AGENT_ORIGIN_FILENAME);
  try {
    const raw = await readFileCustody(filePath, {
      encoding: "utf8",
      verifyPathIdentity: true,
    });
    const parsed = JSON.parse(raw) as unknown;
    const validated = validateAgentOrigin(parsed);
    if (validated === null) {
      // SAFETY: daemon startup diagnostics are operator-facing stderr output.
      console.warn(
        `[castle-wall] warning: ${AGENT_ORIGIN_FILENAME} is structurally invalid; ignoring (classify-all-agent fallback)`,
      );
      return undefined;
    }
    return validated;
  } catch (err) {
    const code = err instanceof Error && "code" in err
      ? (err as NodeJS.ErrnoException).code
      : undefined;
    if (code === "ENOENT") return undefined;
    throw err;
  }
}

async function resolveOperatorBaseline(
  fortressPath: string,
  explicitInput: unknown,
): Promise<unknown> {
  if (explicitInput !== undefined) {
    return explicitInput;
  }
  const filePath = join(fortressPath, "policy", "egress", OPERATOR_BASELINE_FILENAME);
  try {
    const raw = await readFileCustody(filePath, {
      encoding: "utf8",
      mode: { rejectGroupOrOther: true },
      verifyPathIdentity: true,
    });
    const parsed = JSON.parse(raw) as unknown;
    const validated = validateOperatorBaseline(parsed);
    if (validated === null) {
      // SAFETY: daemon startup diagnostics are operator-facing stderr output.
      console.warn(
        `[castle-wall] warning: ${OPERATOR_BASELINE_FILENAME} is structurally invalid; ignoring`,
      );
      return undefined;
    }
    return validated;
  } catch (err) {
    const code = err instanceof Error && "code" in err
      ? (err as NodeJS.ErrnoException).code
      : undefined;
    if (code === "ENOENT") return undefined;
    if (isCustodyFsError(err) && err.code === "mode_rejected") {
      // SAFETY: daemon startup diagnostics are operator-facing stderr output.
      console.warn(
        `[castle-wall] warning: ${OPERATOR_BASELINE_FILENAME} must be mode 0600/0700-equivalent for non-owner bits; ignoring`,
      );
      return undefined;
    }
    throw err;
  }
}

/**
 * Build the daemon's signing handle. B2 default = helper path: the public key is
 * fetched from the root helper over the shim and signing is delegated to it, so
 * NO private key is read or decrypted in this process (P1, P3 — no passphrase
 * needed to sign). The local path (dev/test, explicit opt-in) preserves the old
 * decrypt-in-process behavior.
 */
async function loadSigningKey(input: MacOSCastleWallDaemonInput): Promise<DaemonSigner> {
  const localSign =
    input.localSign === true ||
    (input.localSign === undefined &&
      process.env.SANCTUARY_CASTLE_LOCAL_SIGN === "1");

  if (localSign) {
    return loadLocalSigningKey(input.fortressPath, input.masterKey);
  }

  const clientBinaryPath =
    input.signerClientPath ?? process.env.SANCTUARY_CASTLE_SIGNER_CLIENT;
  if (!clientBinaryPath && !input.signerClientInvoke) {
    // Fail-closed: helper signing is the default and we have no way to reach the
    // helper. Refuse rather than silently degrading to a local key.
    throw new Error(
      "Castle Wall helper signing is unavailable: set SANCTUARY_CASTLE_SIGNER_CLIENT to the signer-client shim path (or SANCTUARY_CASTLE_LOCAL_SIGN=1 for the dev local-sign path).",
    );
  }
  const client = new HelperSignerClient({
    clientBinaryPath: clientBinaryPath ?? "castle-wall-signer-client",
    ...(input.signerClientInvoke ? { invoke: input.signerClientInvoke } : {}),
  });
  const publicKey = await client.getPublicKey();
  if (publicKey.length !== 32) {
    throw new Error(`Helper public key must be 32 bytes (found ${publicKey.length}).`);
  }
  return {
    mode: "helper",
    signingKeyId: `castle-wall:${toBase64url(publicKey)}`,
    publicKey,
    signManifest: (bytes) => client.signManifest(bytes),
    signNonce: (nonce) => client.signNonce(nonce),
  };
}

/** Dev/test local-sign path: decrypt the on-disk private key with the master key. */
async function loadLocalSigningKey(
  fortressPath: string,
  masterKey: Uint8Array,
): Promise<DaemonSigner> {
  const publicKey = await readFileCustody(join(fortressPath, CASTLE_PINNED_PUBKEY), {
    verifyPathIdentity: true,
  });
  if (publicKey.length !== 32) {
    throw new Error(`Pinned public key must be 32 bytes (found ${publicKey.length}).`);
  }
  let encryptedPrivateKey = JSON.parse(
    await readFileCustody(join(fortressPath, CASTLE_PINNED_PRIVKEY), {
      encoding: "utf8",
      verifyPathIdentity: true,
    }),
  ) as EncryptedPayload;
  const privateKey = decrypt(encryptedPrivateKey, masterKey);
  try {
    if (privateKey.length === 64) {
      encryptedPrivateKey = encrypt(privateKey.slice(0, 32), masterKey);
    } else if (privateKey.length !== 32) {
      throw new Error(`Pinned private key must decrypt to 32 bytes (found ${privateKey.length}).`);
    }
  } finally {
    privateKey.fill(0);
  }
  const signer = localManifestSigner({
    signingKeyId: `castle-wall:${toBase64url(publicKey)}`,
    encryptedPrivateKey,
    encryptionKey: masterKey,
  });
  return {
    mode: "local",
    signingKeyId: signer.signingKeyId,
    publicKey: new Uint8Array(publicKey),
    signManifest: async (bytes) => signer.sign(bytes),
    signNonce: async (nonce) => signer.sign(nonce),
  };
}

/**
 * Write the global trust-anchor pin. Under A2 the helper owns the pin file
 * (root:wheel 0644) and writes it during re-pin — so in helper mode the daemon
 * must NOT write it (it lacks root and would only EACCES). It is explicit, not a
 * silent warn. In the local dev/test path the daemon still best-effort writes it
 * so a developer box without the helper still has a readable pin.
 *
 * Fail-open fix (2026-07-07): the local-sign path previously rename-over-wrote
 * the pin unconditionally, so a root local-sign daemon would silently CLOBBER
 * an existing DIFFERING signer-owned pin (the same fail-open the provision-pin
 * path had, on a different path). It now routes through the shared
 * `writeGlobalPinIfUnestablished` chokepoint (read-and-compare before any
 * write), so an existing, differing pin is left intact at ANY euid. Only re-pin
 * (`helper-signer.ts installPin()`, NOT routed here) migrates an established
 * pin. `globalPinPath` mirrors the existing helper-mode cross-check seam so the
 * guard is testable without the real `/Library` path.
 */
export async function writeSystemPinnedPublicKey(
  signer: DaemonSigner,
  globalPinPath: string = CASTLE_GLOBAL_PINNED_PUBKEY_PATH,
): Promise<void> {
  if (signer.mode === "helper") {
    // SAFETY: daemon startup diagnostics are operator-facing stderr output.
    console.error(
      "[castle-wall] pin is owned by the root signer helper (A2); daemon does not write it.",
    );
    return;
  }
  try {
    await writeGlobalPinIfUnestablished(signer.publicKey, {
      path: globalPinPath,
      onRefuse: () =>
        // SAFETY: daemon startup diagnostics are operator-facing stderr output.
        console.warn(
          `[castle-wall] global pin ${globalPinPath} already exists with a different key owned by the root signer helper (A2); the local-sign daemon does not overwrite it. Run 'sanctuary castle-wall re-pin' to migrate the trust anchor to the signer helper.`,
        ),
      freshWrite: async (path, key) => {
        await mkdir(dirname(path), { recursive: true, mode: 0o755 });
        await writeFileCustody(path, key, {
          mode: 0o644,
          createParent: false,
        });
      },
    });
  } catch (error) {
    // SAFETY: daemon startup diagnostics are operator-facing stderr output.
    console.warn(
      `[castle-wall] warning: unable to write shared pinned public key at ${globalPinPath}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

async function loadMacOSAuditProducerPublicKey(
  path: string,
): Promise<{ bytes: Uint8Array; keyB64url: string } | null> {
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(
      await readFileCustody(path, { verifyPathIdentity: true }),
    );
  } catch (error) {
    const code =
      error && typeof error === "object" && "code" in error
        ? (error as NodeJS.ErrnoException).code
        : undefined;
    if (code === "ENOENT") {
      return null;
    }
    throw new Error(
      `Castle Wall macOS audit-producer key at ${path} is unreadable: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  if (bytes.length !== 32) {
    throw new Error(
      `Castle Wall macOS audit-producer key at ${path} is ${bytes.length} bytes (expected 32).`,
    );
  }
  return { bytes, keyB64url: toBase64url(bytes) };
}

async function publishFortressAuditProducerPublicKey(
  fortressPath: string,
  publicKey: Uint8Array,
): Promise<void> {
  await writeFileCustody(resolveProducerPubKeyPath(fortressPath), publicKey, {
    mode: 0o644,
    createParent: true,
  });
}

/**
 * F-A2-1 #4 defense-in-depth: in helper mode the ROOT-OWNED global pin on disk
 * MUST equal the live helper key. The daemon already verifies every manifest
 * against the helper's live `getPublicKey()`; this adds an independent
 * cross-check against the persisted trust anchor so a coordinated key+pin swap
 * — one that might fool either check alone — is still caught (fail closed).
 *
 * Only a root-owned pin is authoritative: a non-root-owned pin is ignored here
 * (the sysext's own owner-gate rejects it, F-A2-2), so this never false-positives
 * on a dev box where the global pin is operator-owned. A missing or unreadable
 * pin is also skipped — it is purely additive defense over the live-key check.
 */
/**
 * Pure trust decision for the F-A2-1 #4 cross-check. Extracted so the policy is
 * unit-testable without a root-owned file on disk:
 *   - no pin on disk            -> "skip"  (additive over the live-key check)
 *   - pin not root-owned        -> "skip"  (untrusted; the sysext gate rejects it)
 *   - root-owned, bytes equal   -> "match"
 *   - root-owned, bytes differ  -> "mismatch" (coordinated swap / stale pin)
 */
export function evaluateGlobalPinTrust(
  pin: { uid: number; bytes: Uint8Array } | null,
  liveKey: Uint8Array,
): "skip" | "match" | "mismatch" {
  if (!pin) return "skip";
  if (pin.uid !== 0) return "skip";
  const onDisk = Buffer.from(pin.bytes);
  const live = Buffer.from(liveKey);
  return onDisk.length === live.length && Buffer.compare(onDisk, live) === 0
    ? "match"
    : "mismatch";
}

async function assertGlobalPinMatchesLiveKey(
  livePublicKey: Uint8Array,
  pinPath: string,
): Promise<void> {
  let pin: { uid: number; bytes: Uint8Array } | null;
  try {
    const { data, stats } = await readFileCustodyWithStats(pinPath, {
      verifyPathIdentity: true,
    });
    pin = { uid: stats.uid, bytes: data };
  } catch {
    // absent / unreadable — additive check, skip
    return;
  }
  if (evaluateGlobalPinTrust(pin, livePublicKey) === "mismatch") {
    throw new Error(
      "Castle Wall trust-anchor mismatch: the root-owned global pin does not match the live signer helper key. Refusing to start; run 'sanctuary castle-wall re-pin' to re-establish the trust anchor.",
    );
  }
}

/**
 * THE manifest composer: read every rule file from the fortress's
 * `policy/egress/rules/` directory (the one true rule source -- promotion,
 * provisioning, and operator-authored rules all publish there), compose the
 * effective ruleset (habeas lanes, derived DNS, gate rule, and the
 * exclusive-routing assertion when the routing marker is present), and sign
 * the result. This is the daemon's ONLY manifest production path, for both
 * the initial load and every reload.
 *
 * Exported (2026-07-27) so the observe/promote enforcement-reach end-to-end
 * test can assert against the REAL composer the daemon runs, not a
 * test-local reimplementation of its read half -- the original defect
 * shipped precisely because the only round-trip test paired the promote
 * writer with the promote module's own reader while no enforcement path read
 * that location. Production callers remain inside this module.
 */
export async function loadManifestState(input: {
  fortressPath: string;
  fortressId: string;
  signer: DaemonSigner;
  agentOrigin?: unknown;
  operatorBaseline?: unknown;
  exclusiveEgressGate?: ExclusiveEgressGatePolicy | undefined;
  globalPinnedPublicKeyPath?: string;
}): Promise<ManifestState> {
  // Defense-in-depth: cross-check the persisted root-owned pin against the live
  // helper key before trusting this signer to sign a manifest (F-A2-1 #4).
  if (input.signer.mode === "helper") {
    await assertGlobalPinMatchesLiveKey(
      input.signer.publicKey,
      input.globalPinnedPublicKeyPath ?? CASTLE_GLOBAL_PINNED_PUBKEY_PATH,
    );
  }
  const rulesDir = join(input.fortressPath, "policy", "egress", "rules");
  const rules: AllowlistRule[] = [];
  let filenames: string[] = [];
  try {
    filenames = (await readdir(rulesDir)).filter((name) => name.endsWith(".json"));
  } catch (err) {
    const code = err instanceof Error && "code" in err
      ? (err as NodeJS.ErrnoException).code
      : undefined;
    if (code !== "ENOENT") throw err;
  }
  filenames.sort();
  for (const filename of filenames) {
    const raw = await readFileCustody(join(rulesDir, filename), {
      verifyPathIdentity: true,
    });
    const parsed = JSON.parse(bytesToString(raw)) as AllowlistRule;
    const issues = validateRule(parsed);
    if (issues.length > 0) {
      throw new Error(`rule ${filename} invalid: ${issues.join("; ")}`);
    }
    // Round-4 C2: the observe promote publishes the genuine derived habeas
    // lane INTO its signed manifest (the Linux daemon's composed-manifest
    // gate requires exactly one), which necessarily places the lane's rule
    // FILE in this directory (a manifest entry must resolve at
    // rules/<file> for the Rust loader). This composer derives its OWN
    // lanes and treats everything here as operator input, so a byte-GENUINE
    // lane file (the shipped exact-shape recognizer, never id-trust or the
    // `derived` flag) is skipped as the known cross-platform artifact --
    // semantically a dedup, never a widening: the injected lane is
    // identical. A file that merely CLAIMS a habeas id still flows through
    // and is rejected by the reserved-namespace firewall
    // (`findHabeasConflicts`), fail-closed, unchanged.
    if (parsed.id.startsWith(HABEAS_RULE_ID_PREFIX) && isGenuineDerivedHabeasRule(parsed)) {
      continue;
    }
    rules.push(parsed);
  }
  // Compose the effective ruleset: HABEAS PORT reserved distress rules are
  // ALWAYS injected (a conflicting operator ruleset throws — fail closed,
  // never a wall that can silence distress), then the scoped DNS allow
  // (#380) is derived when hostname allow-rules exist. The rule scopes to
  // the host's ACTIVE resolver set ONLY (collectSystemResolvers: on macOS a
  // fresh scutil --dns read, EMPTY on failure -- fail closed, never a grant
  // signed from this long-lived process's stale dns.getServers() snapshot;
  // the 2026-07-12 drill bug); absent when no hostname rules exist.
  const distressConfig = await readDistressConfig(input.fortressPath);
  const resolvers = await collectSystemResolvers();
  // Unified Protect Slice 5 S5-6: the exclusive-routing MODE MARKER decides
  // which composition this manifest gets. Marker ABSENT = coarse (today's
  // path, byte-unchanged). Marker PRESENT = the S5-4 exclusive composition:
  // provisioned endpoint rules must be gate-scoped and the compose-time
  // assertion refuses ANY agent-reachable direct off-box allow -- a violation
  // THROWS here, so NO manifest is produced (fail-closed: no manifest, no
  // arm; never a silently-widened one). A present-but-malformed marker also
  // throws (loadExclusiveRoutingMarker's contract) rather than guessing a
  // mode. This makes the daemon -- the only real manifest producer -- the
  // chokepoint for the BLOCKER-1 routing property on every load AND reload.
  const routingMarker = await loadExclusiveRoutingMarker(input.fortressPath);
  let effectiveRules: AllowlistRule[];
  if (routingMarker !== null) {
    const composition = await composeExclusiveRoutingRules({
      base: {
        operatorRules: rules,
        resolvers,
        distressWebhook: distressConfig.webhook_target,
        exclusiveEgressGate: input.exclusiveEgressGate,
        createdAt: new Date().toISOString(),
      },
      routing: {
        mode: "exclusive",
        principals: {
          agent_uid: routingMarker.agent_uid,
          gate_uid: routingMarker.gate_uid,
          agent: {
            agent_id: routingMarker.agent_id,
            agent_template: routingMarker.agent_template,
          },
        },
      },
    });
    effectiveRules = composition.rules;
  } else {
    effectiveRules = composeEffectiveRules({
      operatorRules: rules,
      resolvers,
      distressWebhook: distressConfig.webhook_target,
      exclusiveEgressGate: input.exclusiveEgressGate,
      createdAt: new Date().toISOString(),
    });
  }
  const { signed } = await buildSignedManifest({
    fortressId: input.fortressId,
    issuedAt: new Date().toISOString(),
    rules: effectiveRules,
    signer: {
      signingKeyId: input.signer.signingKeyId,
      sign: (bytes) => input.signer.signManifest(bytes),
    },
    agentOrigin: input.agentOrigin,
    operatorBaseline: input.operatorBaseline,
  });
  const verifyResult = verifyManifestSignature(signed, input.signer.publicKey);
  if (!verifyResult.ok) {
    throw new Error(`manifest signature verification failed: ${verifyResult.error}`);
  }
  return { signed, rules: effectiveRules };
}

async function assertSocketNotOwnedByLiveProcess(socketPath: string): Promise<void> {
  // A socket FILE existing is not proof of a live daemon. A non-graceful exit
  // (crash, `kill -9`, or a reboot — the SIGTERM cleanup that unlinks the
  // socket never runs) leaves a stale `castle.sock` behind, which would
  // otherwise wedge every subsequent start (notably the launchd auto-start
  // after a reboot). Decide on LIVENESS, not file-existence: a genuine daemon
  // accepts a connection; a stale socket refuses it. If no live process
  // answers, unlink the stale socket so the listener can rebind cleanly. The
  // companion active-config guard (`assertActiveConfigNotOwnedByLiveProcess`)
  // is already PID-liveness-aware; this brings the socket check in line.
  try {
    await stat(socketPath);
  } catch (err) {
    const code = err instanceof Error && "code" in err
      ? (err as NodeJS.ErrnoException).code
      : undefined;
    if (code === "ENOENT") return;
    throw err;
  }

  if (await socketHasLiveListener(socketPath)) {
    throw new Error(formatCastleWallAlreadyRunningMessage());
  }

  await unlink(socketPath).catch((err: unknown) => {
    const code = err instanceof Error && "code" in err
      ? (err as NodeJS.ErrnoException).code
      : undefined;
    if (code !== "ENOENT") throw err;
  });
}

/**
 * Resolve true iff a live process is currently accepting connections on the
 * unix socket at `socketPath`. A successful connect proves a live listener; a
 * connection error (ECONNREFUSED on a stale socket, ENOTSOCK on a leftover
 * plain file, ENOENT on a vanished path) proves there is not one. The probe
 * is bounded by a short timeout so a wedged peer cannot hang startup.
 */
function socketHasLiveListener(socketPath: string): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const socket = createConnection({ path: socketPath });
    const finish = (alive: boolean): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(alive);
    };
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
    socket.setTimeout(1000, () => finish(false));
  });
}

async function assertActiveConfigNotOwnedByLiveProcess(
  configPath: string,
  legacyConfigPath?: string,
): Promise<void> {
  const config = await readActiveConfig(configPath, legacyConfigPath);
  if (!config) return;
  // Liveness must be AUTHORITATIVE, not pid-only. A bare pid is unreliable across
  // a reboot: low pids are frequently REUSED by unrelated processes early in boot,
  // so `isPidAlive` alone yields a FALSE collision that refuses the freshly-booted
  // daemon (2026-06-14 A1 rep-2: the recorded pid 541 was reassigned to a
  // DriverKit dext while NO daemon was actually running, so the safe-mode daemon
  // refused to start). Require BOTH the pid alive AND a live listener answering the
  // recorded socket — the same authoritative liveness signal
  // `assertSocketNotOwnedByLiveProcess` uses. With no live listener the config is
  // stale: ignore it and let this daemon take over (the socket guard below then
  // unlinks the stale socket). This also stops the item-4 handoff message from
  // firing on a stale-config false positive — it now fires only on a genuinely
  // live peer.
  if (isPidAlive(config.pid) && (await socketHasLiveListener(config.socket_path))) {
    // #450 item 4: distinguish "a root safe-mode boot daemon is holding this
    // fortress" (the login-handoff case) from a generic full-vs-full collision,
    // so the operator gets actionable stand-down guidance instead of the
    // misleading "Multi-wrap is Phase 3" message. Either way we REFUSE (never
    // orphan the live daemon) — the box stays protected meanwhile.
    if (config.mode === "safe") {
      throw new Error(safeModeHandoffMessage(config.pid));
    }
    throw new Error(formatCastleWallAlreadyRunningMessage(config.pid));
  }
}

/**
 * Write the active-config discovery file, returning the path actually written.
 *
 * A2/B2: under helper-as-signer the custody directory is root-owned, so the
 * operator-UID daemon CANNOT write its discovery file there (and must never
 * CREATE that directory operator-owned — F-A2-1). When the protected path is
 * unwritable (root-owned: EACCES/EPERM) or its directory does not exist yet
 * (ENOENT — only the helper creates it), fall back to the operator-writable
 * legacy discovery path. This is socket DISCOVERY only: the IPC handshake binds
 * the pinned key, and the sysext's fingerprint gate ignores any non-root-owned
 * active-config (F-A2-4), so a discovery file is not a trust gate.
 */
export async function writeActiveConfig(
  configPath: string,
  config: ActiveCastleWallConfig,
  fallbackPath?: string,
): Promise<string> {
  // Never create the root-owned custody directory operator-owned (F-A2-1): only
  // the helper owns it. For test/dev paths outside that directory, create it.
  const createDir = dirname(configPath) !== CASTLE_GLOBAL_PINNED_PUBKEY_DIR;
  try {
    return await writeActiveConfigAt(configPath, config, createDir);
  } catch (error) {
    const code =
      error instanceof Error && "code" in error
        ? (error as NodeJS.ErrnoException).code
        : undefined;
    if (
      fallbackPath &&
      (code === "EACCES" || code === "EPERM" || code === "EROFS" || code === "ENOENT")
    ) {
      // SAFETY: daemon startup diagnostics are operator-facing stderr output.
      console.error(
        `[castle-wall] custody dir is root-owned (A2); writing discovery active-config to ${fallbackPath} (${code}). Socket discovery only — the handshake binds the pinned key.`,
      );
      return await writeActiveConfigAt(fallbackPath, config, true);
    }
    throw error;
  }
}

async function writeActiveConfigAt(
  configPath: string,
  config: ActiveCastleWallConfig,
  createDir: boolean,
): Promise<string> {
  if (createDir) {
    await mkdir(dirname(configPath), { recursive: true, mode: 0o755 });
  }
  await writeFileCustody(configPath, `${JSON.stringify(config)}\n`, {
    mode: 0o644,
    createParent: false,
  });
  return configPath;
}

async function removeActiveConfigIfCurrent(
  configPath: string,
  socketPath: string,
  fortressId: string,
): Promise<void> {
  const config = await readActiveConfig(configPath);
  if (
    config &&
    config.pid === process.pid &&
    config.socket_path === socketPath &&
    config.fortress_id === fortressId
  ) {
    await unlink(configPath).catch((err: unknown) => {
      const code = err instanceof Error && "code" in err
        ? (err as NodeJS.ErrnoException).code
        : undefined;
      if (code !== "ENOENT") throw err;
    });
  }
}

async function readActiveConfig(
  configPath: string,
  legacyConfigPath?: string,
): Promise<ActiveCastleWallConfig | null> {
  let raw: string;
  try {
    raw = await readFileCustody(configPath, {
      encoding: "utf8",
      verifyPathIdentity: true,
    });
  } catch (err) {
    const code = err instanceof Error && "code" in err
      ? (err as NodeJS.ErrnoException).code
      : undefined;
    if (code === "ENOENT") {
      // Migration: a daemon from before the active-config relocation may still
      // have its discovery file under the legacy /tmp path. Read it so a
      // half-migrated box still resolves liveness; writes only ever go to the
      // protected path.
      if (legacyConfigPath) return readActiveConfig(legacyConfigPath);
      return null;
    }
    throw err;
  }

  try {
    const parsed = JSON.parse(raw) as Partial<ActiveCastleWallConfig>;
    if (
      typeof parsed.socket_path !== "string" ||
      typeof parsed.fortress_id !== "string" ||
      typeof parsed.pid !== "number" ||
      !Number.isInteger(parsed.pid) ||
      typeof parsed.started_at !== "string"
    ) {
      return null;
    }
    if (
      parsed.pinned_pubkey_sha256 !== undefined &&
      typeof parsed.pinned_pubkey_sha256 !== "string"
    ) {
      return null;
    }
    // `mode` is advisory (#450 item 4): tolerate its absence (older daemons) and
    // ignore any value other than the two known roles.
    const mode = parsed.mode === "safe" || parsed.mode === "full" ? parsed.mode : undefined;
    return {
      socket_path: parsed.socket_path,
      fortress_id: parsed.fortress_id,
      ...(typeof parsed.fortress_path === "string"
        ? { fortress_path: parsed.fortress_path }
        : {}),
      pid: parsed.pid,
      started_at: parsed.started_at,
      ...(parsed.pinned_pubkey_sha256 !== undefined
        ? { pinned_pubkey_sha256: parsed.pinned_pubkey_sha256 }
        : {}),
      ...(mode !== undefined ? { mode } : {}),
    };
  } catch {
    return null;
  }
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function isPidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    const code = err instanceof Error && "code" in err
      ? (err as NodeJS.ErrnoException).code
      : undefined;
    return code === "EPERM";
  }
}
