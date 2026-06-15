/**
 * Linux producer-signed Castle Wall activation gate (C4 tamper-proof half, P-3).
 *
 * This is the ONE place that turns the producer-signed audit close ON in
 * production. It is, by deliberate construction:
 *
 *   - OPT-IN / OFF-BY-DEFAULT. `isLinuxProducerSignedActivationRequested`
 *     returns false unless the operator explicitly sets the capability flag.
 *     There is no surprise default-on. The macOS leg is untouched: macOS keeps
 *     `startMacOSCastleWallDaemon` (the channel basis); only Linux activates the
 *     producer-signed close.
 *
 *   - LINUX-GATED. On any non-Linux platform the activation refuses (the macOS
 *     channel basis is the correct path there; this gate must never run the
 *     systemd launcher off-Linux).
 *
 *   - FAIL-CLOSED. If the daemon will not start, the unit is not active, the
 *     handshake fails, or the pinned producer key is expected-but-unreadable,
 *     the activation THROWS `RuntimeLinuxActivationError`. The caller surfaces
 *     NOT-ARMED. There is NO branch that swallows a failure and falls back to
 *     the channel basis when a key is expected — `startCastleWall` itself throws
 *     on `unreadable`, and we let that propagate.
 *
 * # Drill-acceptance caveat (never overclaim)
 *
 * Activating this gate wires the close end-to-end IN CODE on Linux. The external
 * capability claim ("the fake-arm hole is closed in prod on Linux") still
 * requires a CAPTURED DRILL on real Linux hardware. Until then the honest status
 * is "test/smoke-passed, drill-acceptance pending."
 */

import { startCastleWall, type CastleWallLifecycleHandle } from "./lifecycle.js";
import type { AuditSink } from "./audit-consumer.js";
import type { ClientKeyMaterial } from "./ipc-client.js";
import {
  launchLinuxCastleWallDaemon,
  connectLinuxUdsTransport,
  realSystemctlRunner,
  resolveCastleWallSocketPath,
  type SystemctlRunner,
  type LauncherFs,
} from "./linux-daemon.js";
import {
  startLinuxAuditDrainLoop,
  type LinuxAuditDrainHandle,
  type LinuxAuditDrainOptions,
} from "./linux-audit-drain.js";
import { RuntimeLinuxActivationError } from "./errors.js";

/**
 * The capability flag that OPTS IN to the Linux producer-signed close.
 * Off-by-default: absent or anything other than "1" leaves the close inactive
 * (channel basis), exactly as today. Named under the existing `SANCTUARY_CASTLE_`
 * prefix for consistency with `SANCTUARY_CASTLE_LOCAL_SIGN`.
 */
export const LINUX_PRODUCER_SIGNED_ACTIVATION_ENV =
  "SANCTUARY_CASTLE_LINUX_PRODUCER_SIGNED";

/**
 * True iff the operator has explicitly opted in to the Linux producer-signed
 * close. Default (no flag) is false — the close stays inactive. An optional
 * explicit boolean overrides the env (for callers that thread config).
 */
export function isLinuxProducerSignedActivationRequested(opts?: {
  explicit?: boolean;
  env?: NodeJS.ProcessEnv;
}): boolean {
  if (typeof opts?.explicit === "boolean") return opts.explicit;
  const env = opts?.env ?? process.env;
  return env[LINUX_PRODUCER_SIGNED_ACTIVATION_ENV] === "1";
}

/** Inputs to the Linux producer-signed activation. */
export interface ActivateLinuxProducerSignedInput {
  fortressId: string;
  /**
   * The fortress storage path. AUTHORITATIVE single source for the pinned
   * producer key: the daemon publishes its pub key here and `startCastleWall`
   * loads it from here, so the consumer can never diverge onto a weaker basis.
   */
  fortressStoragePath: string;
  /** Identity key material the IPC client signs the daemon handshake with. */
  key: ClientKeyMaterial;
  /** The audit sink (typically the fortress `AuditLog`). */
  auditSink: AuditSink;
  /** Platform override (tests). Defaults to `process.platform`. */
  platform?: NodeJS.Platform;
  /** Explicit opt-in override; when omitted the env flag governs. */
  explicitOptIn?: boolean;
  /** Env override (tests). */
  env?: NodeJS.ProcessEnv;
  /** Socket path override (tests / non-default fortress layout). */
  socketPath?: string;
  /** systemctl runner — injected in tests; defaults to the real one. */
  systemctl?: SystemctlRunner;
  /** Filesystem ops — injected in tests; defaults to node:fs/promises. */
  fs?: LauncherFs;
  /** Daemon binary path override. */
  daemonBinary?: string;
  /** Drop-in dir override (tests). */
  dropInDir?: string;
  /**
   * Transport factory override (tests inject an in-process mock daemon). When
   * omitted, a real UDS transport is connected to the daemon socket. Letting
   * tests inject the transport is what makes the full end-to-end path
   * (launch → connect → handshake → drain → re-verify) exercisable hermetically.
   */
  connectTransport?: (socketPath: string) => Promise<
    import("./ipc-client.js").IpcTransport
  >;
  /** Drain-loop options (poll interval, timers) — tests inject deterministic timers. */
  drainOptions?: LinuxAuditDrainOptions;
  /** Skip starting the continuous drain loop (tests that drive drain manually). */
  startDrainLoop?: boolean;
}

/** A live producer-signed activation; close it on shutdown. */
export interface LinuxProducerSignedActivation {
  lifecycle: CastleWallLifecycleHandle;
  drain: LinuxAuditDrainHandle | null;
  /** The drop-in path written, for diagnostics. */
  dropInPath: string;
  /** Tear down the drain loop + lifecycle (does NOT stop the systemd daemon). */
  stop(): Promise<void>;
}

/**
 * The outcome of consulting the gate: either an active producer-signed
 * activation, or an explicit "not activated" with a reason (NOT an error — the
 * caller keeps the macOS/channel basis path). A FAILURE during a REQUESTED
 * activation is thrown, not returned, so it cannot be mistaken for "inactive".
 */
export type LinuxActivationOutcome =
  | { activated: true; activation: LinuxProducerSignedActivation }
  | { activated: false; reason: "not_opted_in" | "not_linux" };

/**
 * Consult the gate and, when opted in on Linux, ACTIVATE the producer-signed
 * close end-to-end. Returns `{ activated: false, reason }` when the gate is not
 * engaged (no opt-in, or not Linux) — the caller then keeps its existing path
 * (macOS daemon / channel basis). When the gate IS engaged, any failure to
 * reach an armed, key-loaded state THROWS (fail-closed → caller surfaces
 * not-armed).
 */
export async function maybeActivateLinuxProducerSignedCastleWall(
  input: ActivateLinuxProducerSignedInput
): Promise<LinuxActivationOutcome> {
  const platform = input.platform ?? process.platform;
  if (
    !isLinuxProducerSignedActivationRequested({
      explicit: input.explicitOptIn,
      env: input.env,
    })
  ) {
    return { activated: false, reason: "not_opted_in" };
  }
  if (platform !== "linux") {
    // The producer-signed close is Linux-only. Off-Linux we must NOT run the
    // systemd launcher; the caller keeps the platform-appropriate path
    // (macOS = channel basis). This is the platform gate, not a failure.
    return { activated: false, reason: "not_linux" };
  }
  const activation = await activateLinuxProducerSignedCastleWall(input);
  return { activated: true, activation };
}

/**
 * Activate the producer-signed close on Linux (assumes the gate already decided
 * to engage). Orchestrates P-1 (launch the daemon with producer-key flags), P-2
 * (connect the UDS transport + run the drain pull-loop), and `startCastleWall`
 * (load the pinned key via the single source). FAIL-CLOSED throughout.
 *
 * Exposed directly for callers/tests that have already gated; most callers use
 * {@link maybeActivateLinuxProducerSignedCastleWall}.
 */
export async function activateLinuxProducerSignedCastleWall(
  input: ActivateLinuxProducerSignedInput
): Promise<LinuxProducerSignedActivation> {
  const platform = input.platform ?? process.platform;
  const systemctl = input.systemctl ?? realSystemctlRunner();

  // P-1: render + install the drop-in, reload, (re)start, VERIFY active.
  // Throws RuntimeLinuxActivationError fail-closed on any failure.
  const launch = await launchLinuxCastleWallDaemon({
    fortressId: input.fortressId,
    fortressStoragePath: input.fortressStoragePath,
    daemonBinary: input.daemonBinary,
    dropInDir: input.dropInDir,
    systemctl,
    fs: input.fs,
  });

  // P-2 (transport): resolve the daemon socket + connect a real UDS transport
  // (or the injected mock). A connect failure fails closed.
  const socketPath =
    input.socketPath ??
    resolveCastleWallSocketPath({ platform, fortressId: input.fortressId }).path;
  const transport = input.connectTransport
    ? await input.connectTransport(socketPath)
    : await connectLinuxUdsTransport({ socketPath });

  // startCastleWall loads the pinned key from `fortressStoragePath` via the
  // SINGLE source. key `present` → consumer ENFORCES; key `absent` → channel
  // basis (pre-provision); key `unreadable` → THROWS (a key is expected). We do
  // NOT swallow that throw: a thrown lifecycle = not-armed. We also wrap a
  // handshake failure as fail-closed.
  let lifecycle: CastleWallLifecycleHandle;
  try {
    lifecycle = await startCastleWall({
      transport,
      key: input.key,
      auditSink: input.auditSink,
      fortressStoragePath: input.fortressStoragePath,
    });
  } catch (err) {
    // Best-effort close the transport we opened before failing closed.
    await transport.close().catch(() => {});
    if (err instanceof RuntimeLinuxActivationError) throw err;
    const message = err instanceof Error ? err.message : String(err);
    // `startCastleWall` throws a RuntimeIpcError for `unreadable` and for
    // handshake failures. Either way the honest surface is NOT-ARMED.
    const reason: RuntimeLinuxActivationError["reason"] = /unreadable/.test(
      message
    )
      ? "producer_key_unreadable"
      : "handshake_failed";
    throw new RuntimeLinuxActivationError(
      `Castle Wall Linux activation failed (fail-closed, not armed): ${message}`,
      reason
    );
  }

  // P-2 (drain loop): pull signed events from the daemon into the consumer's
  // fail-closed re-verification gate.
  const drain =
    input.startDrainLoop === false
      ? null
      : startLinuxAuditDrainLoop(
          lifecycle.client(),
          lifecycle.audit(),
          input.drainOptions
        );

  return {
    lifecycle,
    drain,
    dropInPath: launch.dropInPath,
    stop: async () => {
      if (drain) await drain.stop();
      await lifecycle.stop();
    },
  };
}
