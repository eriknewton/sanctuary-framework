import { createHash, randomBytes } from "node:crypto";
import { getServers } from "node:dns";
import { mkdir, readdir, stat, unlink } from "node:fs/promises";
import { createConnection } from "node:net";
import { dirname, join } from "node:path";

import { bytesToString, toBase64url } from "../../core/encoding.js";
import { decrypt, encrypt, type EncryptedPayload } from "../../core/encryption.js";
import type { AuditLog } from "../../operational/audit-log.js";
import type { AllowlistRule } from "../allowlist/schema.js";
import { validateRule } from "../allowlist/schema.js";
import { composeEffectiveRules } from "../allowlist/habeas-port.js";
import { readDistressConfig } from "../../distress/config.js";
import { validateAgentOrigin } from "../allowlist/agent-origin.js";
import { validateOperatorBaseline } from "../allowlist/operator-baseline.js";
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
import {
  isCustodyFsError,
  readFileCustody,
  readFileCustodyWithStats,
  writeFileCustody,
} from "../../storage/custody-fs.js";
import { MacOSFlowEventConsumer } from "./macos-flow-events.js";
import { MacOSFlowIpcListener } from "./macos-ipc-listener.js";
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
} from "../constants.js";

const CASTLE_PINNED_PUBKEY = "castle-pinned-pubkey.bin";
const CASTLE_PINNED_PRIVKEY = "castle-pinned-privkey.enc";
const CASTLE_GLOBAL_PINNED_PUBKEY_DIR = "/Library/Application Support/Sanctuary";
const CASTLE_GLOBAL_PINNED_PUBKEY_PATH = `${CASTLE_GLOBAL_PINNED_PUBKEY_DIR}/${CASTLE_PINNED_PUBKEY}`;

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

export const CASTLE_WALL_ALREADY_RUNNING_MESSAGE =
  "Castle Wall daemon already running for this fortress (PID <pid>). Multi-wrap-per-fortress is Phase 3.";

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
   * Re-own the bound IPC socket to this uid (F1 #450 item 3). Set by the
   * SAFE-MODE boot daemon (which runs as root) to the operator/fortress-owner
   * uid so the operator CLI dead-man lever can reach the otherwise root-owned
   * socket. Undefined for the full operator daemon (socket is already
   * operator-owned). See {@link MacOSFlowIpcListenerOptions.socketOwnerUid}.
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
   * Provider-side dead-man lease. Undefined/null means durable arming
   * (--no-ttl); a positive number means the extension fails open after that
   * many seconds unless renewed by the authenticated daemon channel.
   */
  armLeaseTtlSeconds?: number | null;
  armLeaseHeartbeatIntervalSeconds?: number;
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

interface ManifestState {
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

  await assertActiveConfigNotOwnedByLiveProcess(activeConfigPath, legacyActiveConfigPath);
  await assertSocketNotOwnedByLiveProcess(socketPath);
  await mkdir(join(input.fortressPath, "policy", "egress", "rules"), {
    recursive: true,
    mode: 0o700,
  });

  const signer = input.signer ?? (await loadSigningKey(input));
  await writeSystemPinnedPublicKey(signer);
  const pinnedPublicKeySha256 = sha256Hex(signer.publicKey);
  const agentOrigin = await resolveAgentOrigin(input.fortressPath, input.agentOrigin);
  const operatorBaseline = await resolveOperatorBaseline(
    input.fortressPath,
    input.operatorBaseline,
  );
  let manifestState = await loadManifestState({
    fortressPath: input.fortressPath,
    fortressId: input.fortressId,
    signer,
    agentOrigin,
    operatorBaseline,
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
  const auditHeartbeatIntervalSeconds =
    input.auditHeartbeatIntervalSeconds ??
    CASTLE_WALL_DEFAULT_AUDIT_HEARTBEAT_INTERVAL_SECONDS;
  let auditHeartbeat: NodeJS.Timeout | undefined;
  const stopAuditHeartbeat = (): void => {
    if (!auditHeartbeat) return;
    clearInterval(auditHeartbeat);
    auditHeartbeat = undefined;
  };

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
  });

  const listenerOptions: MacOSCastleWallListenerOptions = {
    socketPath,
    ...(input.socketOwnerUid !== undefined
      ? { socketOwnerUid: input.socketOwnerUid }
      : {}),
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
    async onArmLeaseRevoke() {
      stopLeaseHeartbeat();
      // A revoked arm-lease means the wall is no longer enforcing for this
      // operator; stop claiming liveness too so the reader does not see a fresh
      // heartbeat from a daemon that has been told to stand down.
      stopAuditHeartbeat();
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
          input.fortressId,
          {
            socket_path: socketPath,
            source: auditSource,
            daemon_mode: daemonMode,
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
      input.fortressId,
      { socket_path: socketPath, source: auditSource },
      "success",
    );
    await input.auditLog.flush();
    const emitLease = async (): Promise<void> => {
      await listener.broadcastArmLease(buildArmLease({
        armed: true,
        ttlSeconds: input.armLeaseTtlSeconds ?? null,
        heartbeatIntervalSeconds,
      })).catch(() => undefined);
    };
    await emitLease();
    leaseHeartbeat = setInterval(() => {
      void emitLease();
    }, heartbeatIntervalSeconds * 1000);
    leaseHeartbeat.unref();

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
      try {
        await input.auditLog.append(
          "l1",
          CASTLE_WALL_HEARTBEAT_OPERATION,
          input.fortressId,
          {
            socket_path: socketPath,
            source: auditSource,
            daemon_mode: daemonMode,
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
        // surfaced honestly rather than masked.
      }
    };
    await emitAuditHeartbeat();
    auditHeartbeat = setInterval(() => {
      void emitAuditHeartbeat();
    }, auditHeartbeatIntervalSeconds * 1000);
    auditHeartbeat.unref();
  } catch (err) {
    stopLeaseHeartbeat();
    stopAuditHeartbeat();
    if (activeConfigWritten) {
      await removeActiveConfigIfCurrent(writtenActiveConfigPath, socketPath, input.fortressId);
    }
    await listener.stop().catch(() => undefined);
    throw err;
  }

  async function reloadPolicy(
    request?: PolicyReloadRequest,
  ): Promise<PolicyReloadResponse> {
    try {
      const reloadedOrigin = await resolveAgentOrigin(input.fortressPath, input.agentOrigin);
      const reloadedBaseline = await resolveOperatorBaseline(
        input.fortressPath,
        input.operatorBaseline,
      );
      manifestState = await loadManifestState({
        fortressPath: input.fortressPath,
        fortressId: input.fortressId,
        signer,
        agentOrigin: reloadedOrigin,
        operatorBaseline: reloadedBaseline,
        ...(input.globalPinnedPublicKeyPath
          ? { globalPinnedPublicKeyPath: input.globalPinnedPublicKeyPath }
          : {}),
      });
      const emitted = await listener.broadcastManifestUpdate();
      await input.auditLog.append(
        "l1",
        "policy_loaded",
        input.fortressId,
        {
          loaded_rule_count: manifestState.rules.length,
          // Surface auto-derived rules (#380) so a derived grant is never
          // silently invisible in policy introspection.
          derived_rule_ids: manifestState.rules
            .filter((rule) => rule.derived === true)
            .map((rule) => rule.id),
          emitted_subscribers: emitted,
          source: "castle-wall-reload",
        },
        "success",
      );
      await input.auditLog.flush();
      return {
        type: "policy_reload_response",
        request_id: request?.request_id ?? randomBytes(16).toString("hex"),
        ok: true,
        loaded_manifest_signature_b64url: manifestState.signed.signature.signature_b64url,
        loaded_rule_count: manifestState.rules.length,
      };
    } catch (err) {
      await input.auditLog.append(
        "l1",
        "policy_validation_failed",
        input.fortressId,
        { error: err instanceof Error ? err.message : String(err) },
        "failure",
      );
      await input.auditLog.flush();
      return {
        type: "policy_reload_response",
        request_id: request?.request_id ?? randomBytes(16).toString("hex"),
        ok: false,
        loaded_manifest_signature_b64url: manifestState.signed.signature.signature_b64url,
        loaded_rule_count: manifestState.rules.length,
        error: err instanceof Error ? err.message : String(err),
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
        await listener.broadcastArmLease(buildArmLease({
          armed: false,
          ttlSeconds: null,
          heartbeatIntervalSeconds,
        })).catch(() => undefined);
        await listener.stop();
        await input.auditLog.append(
          "l1",
          "filter_stopped",
          input.fortressId,
          {
            socket_path: socketPath,
            source: auditSource,
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

const AGENT_ORIGIN_FILENAME = "agent-origin.json";
const OPERATOR_BASELINE_FILENAME = "operator-baseline.json";

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
 */
async function writeSystemPinnedPublicKey(signer: DaemonSigner): Promise<void> {
  if (signer.mode === "helper") {
    // SAFETY: daemon startup diagnostics are operator-facing stderr output.
    console.error(
      "[castle-wall] pin is owned by the root signer helper (A2); daemon does not write it.",
    );
    return;
  }
  try {
    await mkdir(CASTLE_GLOBAL_PINNED_PUBKEY_DIR, {
      recursive: true,
      mode: 0o755,
    });
    await writeFileCustody(CASTLE_GLOBAL_PINNED_PUBKEY_PATH, signer.publicKey, {
      mode: 0o644,
      createParent: false,
    });
  } catch (error) {
    // SAFETY: daemon startup diagnostics are operator-facing stderr output.
    console.warn(
      `[castle-wall] warning: unable to write shared pinned public key at ${CASTLE_GLOBAL_PINNED_PUBKEY_PATH}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
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

async function loadManifestState(input: {
  fortressPath: string;
  fortressId: string;
  signer: DaemonSigner;
  agentOrigin?: unknown;
  operatorBaseline?: unknown;
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
    rules.push(parsed);
  }
  // Compose the effective ruleset: HABEAS PORT reserved distress rules are
  // ALWAYS injected (a conflicting operator ruleset throws — fail closed,
  // never a wall that can silence distress), then the scoped DNS allow
  // (#380) is derived when hostname allow-rules exist. The rule scopes to
  // the system resolvers ONLY (dns.getServers(), verified to match
  // `scutil --dns`); absent when no hostname rules exist.
  const distressConfig = await readDistressConfig(input.fortressPath);
  const effectiveRules = composeEffectiveRules({
    operatorRules: rules,
    resolvers: getServers(),
    distressWebhook: distressConfig.webhook_target,
    createdAt: new Date().toISOString(),
  });
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
    throw new Error(CASTLE_WALL_ALREADY_RUNNING_MESSAGE);
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
    throw new Error(CASTLE_WALL_ALREADY_RUNNING_MESSAGE);
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
