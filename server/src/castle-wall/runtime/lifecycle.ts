/**
 * Lifecycle wrapper: spawns + supervises the Castle Wall daemon, runs the
 * IPC handshake, wires the audit consumer + approval stub onto incoming
 * IPC messages, and exposes a small public API to Sanctuary main.
 *
 * PR 2a ships the lifecycle shell; the full supervisor (restart-on-failure,
 * crash-detection, journalctl integration) is part of PR 2b. The shell
 * accepts a pre-constructed transport so tests can swap in an in-process
 * mock without spawning anything.
 */

import { CASTLE_WALL_DEFAULT_PROMPT_TIMEOUT_SECONDS } from "../constants.js";
import { ApprovalStub } from "./approval-stub.js";
import {
  AuditConsumer,
  type AuditSink,
  type ChainAnchorSource,
} from "./audit-consumer.js";
import { IpcClient, type IpcTransport, type ClientKeyMaterial } from "./ipc-client.js";
import {
  castleWallRuntimeReadiness,
  type CastleWallRuntimeReadiness,
  type StatusResponse,
} from "../ipc/messages.js";
import { RuntimeIpcError } from "./errors.js";
import {
  loadFortressProducerKey,
  type ProducerKeyLoadOptions,
} from "./producer-signature.js";

/** Public lifecycle state surface. */
export type CastleWallLifecycleState =
  | "idle"
  | "handshaking"
  | "running"
  | "draining"
  | "stopped"
  | "error";

/** Inputs to start the lifecycle. */
export interface StartCastleWallInput {
  transport: IpcTransport;
  key: ClientKeyMaterial;
  auditSink: AuditSink;
  /**
   * The TOFU-pinned audit-producer public key (base64url-no-pad, 32 raw
   * verifying-key bytes) published by the Linux daemon at
   * `<policy_dir>/audit-producer.pub`. When provided, the audit consumer
   * REQUIRES enforcement-evidence events to carry a producer signature that
   * verifies against this key (Slice L1 fail-closed). Load it with
   * `loadPinnedProducerKeyB64url`. Omit on platforms/paths without a signing
   * producer (macOS, legacy) to accept on the documented channel-authenticity
   * basis. Threading this through is what makes L1 enforcement default-on for
   * the runtime once the drain pull-loop (next slice) feeds the consumer.
   */
  pinnedProducerKeyB64url?: string | null;
  /**
   * Slice P consumer provisioning: the fortress storage path. When provided (and
   * `pinnedProducerKeyB64url` is not explicitly set), the lifecycle resolves the
   * pinned producer key through the SAME single-source loader the readers use
   * (`loadFortressProducerKey` → `<storagePath>/policy/egress/audit-producer.pub`),
   * so the consumer and the readers can never diverge onto different keys/paths.
   *
   * Activation + fail direction:
   *   - key `present`    → the consumer REQUIRES a valid producer signature on
   *                        enforcement evidence (the L1 close activates).
   *   - key `absent`     → channel basis (honest macOS / pre-provision floor).
   *   - key `unreadable` → a key is EXPECTED but cannot be loaded; `startCastleWall`
   *                        THROWS (fail closed). The consumer must never write
   *                        enforcement evidence on the channel basis while the
   *                        daemon is signing — a key-null consumer would persist
   *                        forgeable entries the reader could later trust.
   *
   * When `fortressStoragePath` is set it is AUTHORITATIVE (divergence-proof): an
   * explicit NON-null `pinnedProducerKeyB64url` passed alongside it is REJECTED
   * (two sources of truth for one key), and an explicit `null` does NOT downgrade
   * a present on-disk key. Pass an explicit `pinnedProducerKeyB64url` only WITHOUT
   * a storage path (tests / callers that resolve the key themselves).
   */
  fortressStoragePath?: string;
  /**
   * Optional producer-key loader overrides. Production callers normally omit
   * this; tests use it to pin Linux vs macOS behavior deterministically.
   */
  producerKeyLoadOptions?: ProducerKeyLoadOptions;
  /**
   * Reader for the consumer's own last persisted chain position (wire it with
   * `buildChainAnchorSourceFromAuditLog` over the same audit log `auditSink`
   * appends to). With a pinned producer key, the consumer restores its chain
   * anchor from LOCAL persisted history before the first incoming event —
   * including the one-time old-basis migration. Omitting it keeps the legacy
   * null-anchor bootstrap (tests / callers without a queryable log).
   */
  chainAnchorSource?: ChainAnchorSource;
  promptTimeoutMs?: number;
  strictMode?: boolean;
  /** Optional override for handshake timeout; defaults to 5s. */
  handshakeTimeoutMs?: number;
  /** Optional clock injection for the approval stub; tests use this. */
  setTimer?: (cb: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
}

/** Handle returned to Sanctuary main; close it on shutdown. */
export interface CastleWallLifecycleHandle {
  state(): CastleWallLifecycleState;
  client(): IpcClient;
  audit(): AuditConsumer;
  approval(): ApprovalStub;
  /** Close the daemon connection and reject in-flight requests. */
  stop(): Promise<void>;
}

/**
 * Start the lifecycle: build the IPC client, run handshake, instantiate
 * the audit consumer and approval stub. Returns a handle the caller stores.
 */
export async function startCastleWall(
  input: StartCastleWallInput
): Promise<CastleWallLifecycleHandle> {
  const promptTimeoutMs =
    input.promptTimeoutMs ?? CASTLE_WALL_DEFAULT_PROMPT_TIMEOUT_SECONDS * 1000;
  const approval = new ApprovalStub({
    promptTimeoutMs,
    strictMode: input.strictMode ?? true,
    setTimer: input.setTimer,
    clearTimer: input.clearTimer,
  });

  // Slice P: resolve the consumer's pinned producer key from the single source.
  //
  // Precedence (divergence-proof, codex MEDIUM #3): when a `fortressStoragePath`
  // is given, storage resolution is AUTHORITATIVE — the consumer reads the same
  // path the readers do, so it can never be pinned to a weaker basis than the
  // reader by a caller passing an explicit `null`. An explicit NON-null
  // `pinnedProducerKeyB64url` is honored only as a path-less convenience (tests /
  // callers that resolve the key themselves); it is rejected ALONGSIDE a
  // storage path to keep one source of truth. `unreadable` is a refuse-to-start
  // condition (fail closed): a key is expected but cannot be loaded, so the
  // consumer must not silently fall back to the channel basis while the daemon
  // signs.
  let consumerPinnedKey: string | null;
  if (typeof input.fortressStoragePath === "string") {
    if (
      input.pinnedProducerKeyB64url !== undefined &&
      input.pinnedProducerKeyB64url !== null
    ) {
      throw new RuntimeIpcError(
        "Castle Wall consumer: pass either fortressStoragePath OR an explicit pinnedProducerKeyB64url, not both — they are two sources of truth for one key."
      );
    }
    const load = await loadFortressProducerKey(
      input.fortressStoragePath,
      input.producerKeyLoadOptions,
    );
    if (load.status === "present") {
      consumerPinnedKey = load.keyB64url;
    } else if (load.status === "absent") {
      consumerPinnedKey = null;
    } else {
      throw new RuntimeIpcError(
        `Castle Wall consumer: audit-producer key is expected but unreadable; refusing to start on the channel basis (${load.reason}).`
      );
    }
  } else if (input.pinnedProducerKeyB64url !== undefined) {
    // No storage path: honor the explicit key (incl. an explicit null = channel
    // basis for path-less callers/tests).
    consumerPinnedKey = input.pinnedProducerKeyB64url;
  } else {
    consumerPinnedKey = null;
  }

  const audit = new AuditConsumer(input.auditSink, undefined, {
    pinnedProducerKeyB64url: consumerPinnedKey,
    ...(input.chainAnchorSource !== undefined
      ? { chainAnchorSource: input.chainAnchorSource }
      : {}),
  });
  let state: CastleWallLifecycleState = "handshaking";

  const client = IpcClient.create(input.transport, input.key, {
    handshakeTimeoutMs: input.handshakeTimeoutMs ?? 5_000,
  });

  try {
    await client.start();
    state = "running";
  } catch (err) {
    state = "error";
    throw err;
  }

  const stop = async () => {
    if (state === "stopped") return;
    state = "draining";
    approval.shutdown();
    try {
      await input.auditSink.flush();
    } catch {
      // flush failures during shutdown are non-fatal.
    }
    await client.close();
    state = "stopped";
  };

  return {
    state: () => state,
    client: () => client,
    audit: () => audit,
    approval: () => approval,
    stop,
  };
}

/** What a health check learned about the daemon's kernel runtime. */
export interface CastleWallHealth {
  /**
   * Sanctuary may report this runtime as healthy.
   *
   * TWO independent conditions, both required (owner ruling, 2026-09-02):
   *
   * 1. the kernel runtime is live: either a wrapped agent is being gated
   *    (`enforcing`) or the runtime is up with none wrapped
   *    (`kernel_runtime_ready`), which is this slice's ceiling; AND
   * 2. the peer confirms audit ACKs ({@link auditAckConfirmed}), so reclaimed
   *    WAL evidence was positively acknowledged rather than assumed.
   *
   * Deliberately NOT "enforcement is complete". The predicate this replaced
   * required `runtime_state === "enforcing"`, a state the daemon documents as
   * never produced in this slice, so `ok` was unsatisfiable by construction: a
   * fully healthy privileged host reported unhealthy forever. Requiring a claim
   * the system cannot make is not strictness, it is a broken gate. Condition 2
   * is different in kind: it IS satisfiable, and a peer that fails it is
   * operating on a weaker basis that must be visible, not fatal.
   *
   * Read `readiness` and `auditAckConfirmed` when you need the two facts apart;
   * `ok` is the composite a caller uses to decide whether to CLAIM health.
   */
  ok: boolean;
  /** The truthful state, for a caller that must distinguish the four cases. */
  readiness: CastleWallRuntimeReadiness;
  /**
   * The connected daemon negotiated `audit_drain_ack_response`, so a refused WAL
   * truncation is distinguishable from an applied one.
   *
   * `false` against a pre-v2 daemon. That peer keeps operating (the ACK is still
   * sent, the daemon still truncates), but reclamation is UNPROVEN, so it can
   * never support a health or complete-enforcement claim.
   */
  auditAckConfirmed: boolean;
  /**
   * True only for a gated wrapped agent on a CONFIRMED evidence channel. This is
   * the strong claim; keep it separate from `ok` so no caller can present a
   * ready-but-idle runtime, or an unconfirmed channel, as an enforced agent.
   */
  enforcementComplete: boolean;
  /**
   * The daemon did not give enough information to decide (a pre-v2 daemon that
   * does not report the runtime block, or a health probe with no current
   * answer). Not health and not failure: report it as unknown.
   */
  indeterminate: boolean;
  /**
   * The EXACT `status_response` every field above was derived from.
   *
   * Returned rather than left to the caller to re-fetch: a second
   * `statusRequest()` is a second OBSERVATION, and pairing a readiness computed
   * from one with the raw fields of another lets a snapshot straddle two daemon
   * states that never coexisted. One round-trip, one observation.
   */
  status: StatusResponse;
  uptime_seconds: number;
  loaded_rule_count: number;
}

const HEALTH_CHECK_CACHE_MS = 1_000;
const healthChecks = new WeakMap<
  IpcClient,
  { expiresAt: number; value?: CastleWallHealth; inFlight?: Promise<CastleWallHealth> }
>();

/**
 * Health check: send a status request and map it onto the truthful readiness
 * model. Sanctuary main's health evidence consumes this through
 * `castleWallSnapshotFromStatus`, so the gate has a real production call path
 * (AGENTS rule 4: a capability with no production consumer is not shipped).
 */
export async function healthCheck(client: IpcClient): Promise<CastleWallHealth> {
  if (!client.isHandshakeComplete()) {
    throw new RuntimeIpcError("handshake not complete; cannot health-check");
  }
  const cached = healthChecks.get(client);
  if (cached?.value && cached.expiresAt > Date.now()) return cached.value;
  if (cached?.inFlight) return await cached.inFlight;
  const inFlight = healthCheckUncached(client);
  healthChecks.set(client, { expiresAt: 0, inFlight });
  try {
    const value = await inFlight;
    healthChecks.set(client, { expiresAt: Date.now() + HEALTH_CHECK_CACHE_MS, value });
    return value;
  } catch (err) {
    healthChecks.delete(client);
    throw err;
  }
}

async function healthCheckUncached(client: IpcClient): Promise<CastleWallHealth> {
  const status = await client.statusRequest();
  const readiness = castleWallRuntimeReadiness(status);
  // Read from the NEGOTIATED handshake, not from an assumption about the peer's
  // version: only the advertised capability token proves the daemon will confirm
  // an ACK (see `IpcClient.drainAcksAreConfirmed`).
  const auditAckConfirmed = client.drainAcksAreConfirmed();
  const runtimeLive = readiness === "enforcing" || readiness === "kernel_runtime_ready";
  return {
    ok: runtimeLive && auditAckConfirmed,
    readiness,
    auditAckConfirmed,
    enforcementComplete: readiness === "enforcing" && auditAckConfirmed,
    indeterminate: readiness === "unavailable",
    status,
    uptime_seconds: status.uptime_seconds,
    loaded_rule_count: status.loaded_rule_count,
  };
}
