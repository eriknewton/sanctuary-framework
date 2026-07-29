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
import { AuditConsumer, type AuditSink } from "./audit-consumer.js";
import { IpcClient, type IpcTransport, type ClientKeyMaterial } from "./ipc-client.js";
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

/** Health check: send a status request and verify the response shape. */
export async function healthCheck(
  client: IpcClient
): Promise<{ ok: boolean; uptime_seconds: number; loaded_rule_count: number }> {
  if (!client.isHandshakeComplete()) {
    throw new RuntimeIpcError("handshake not complete; cannot health-check");
  }
  const status = await client.statusRequest();
  return {
    ok: status.no_wall_engaged === false,
    uptime_seconds: status.uptime_seconds,
    loaded_rule_count: status.loaded_rule_count,
  };
}
