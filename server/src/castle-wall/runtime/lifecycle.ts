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
  const audit = new AuditConsumer(input.auditSink);
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
