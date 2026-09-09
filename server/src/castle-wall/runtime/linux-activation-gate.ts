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
 *     handshake fails, the pinned producer key is expected-but-unreadable, the
 *     key is ABSENT after an opted-in launch (a key is required on this path -
 *     see FIX 1), or the audit drain transport wedges (armed-but-not-draining -
 *     see FIX 4), the activation THROWS / trips NOT-ARMED. The caller surfaces
 *     NOT-ARMED. There is NO branch that swallows a failure and falls back to
 *     the channel basis when a key is expected. The channel-basis floor applies
 *     ONLY on the non-opt-in path; here, opting in means enforcement is required.
 *
 * # Drill-acceptance caveat (never overclaim)
 *
 * Activating this gate wires the producer-signed evidence channel and the
 * authenticated, byte-only policy-publication broker. That is code-complete,
 * not deployment proof: no Linux capability claim is available until a
 * CAPTURED DRILL on real Linux hardware passes.
 */

import {
  healthCheck,
  startCastleWall,
  type CastleWallHealth,
  type CastleWallLifecycleHandle,
} from "./lifecycle.js";
import {
  castleWallSnapshotFromHealth,
} from "../../health/castle-wall-snapshot.js";
import {
  evaluateCastleWall,
  type CastleWallEvidence,
} from "../../health/evidence.js";
import type { AuditSink, ChainAnchorSource } from "./audit-consumer.js";
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
  drainOnce,
  DEFAULT_AUDIT_DRAIN_MAX_EVENTS,
  type CastleWallDrainState,
  type LinuxAuditDrainHandle,
  type LinuxAuditDrainOptions,
} from "./linux-audit-drain.js";
import {
  loadFortressProducerKey,
  resolveProducerPubKeyPath,
  resolveLinuxSystemProducerPubKeyPath,
} from "./producer-signature.js";
import { CASTLE_WALL_EVIDENCE_BASIS_DRAIN_FAULT_UNSIGNED } from "../constants.js";
import { RuntimeLinuxActivationError } from "./errors.js";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { decrypt, encrypt, type EncryptedPayload } from "../../core/encryption.js";
import {
  ED25519_LEGACY_SEED_AND_PUBKEY_BYTES,
  ED25519_PRIVATE_KEY_BYTES,
  ED25519_PUBLIC_KEY_BYTES,
} from "../../core/crypto-suite-registry.js";
import {
  BrokerManifestStorage,
  type BuildSignedManifestInput,
} from "./manifest-publisher.js";
import { publishLinuxCompatiblePolicy } from "./linux-policy-compatibility.js";
import { castleWallSigningKeyId } from "../allowlist/parse.js";

export type LinuxPolicyPublication = Awaited<ReturnType<typeof publishLinuxCompatiblePolicy>>;

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
 * close. Default (no flag) is false - the close stays inactive. An optional
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
   * User-space fortress storage. Linux producer-key authority does NOT come
   * from this caller-writable tree: the consumer resolves the daemon key from
   * `/run/sanctuary/<fortress-id>/audit-producer.pub`. The corresponding private
   * seed remains under root-only durable state.
   */
  fortressStoragePath: string;
  /** Identity key material the IPC client signs the daemon handshake with. */
  key: ClientKeyMaterial;
  /** The audit sink (typically the fortress `AuditLog`). */
  auditSink: AuditSink;
  /**
   * Reader for the consumer's own last persisted chain position (wire it with
   * `buildChainAnchorSourceFromAuditLog` over the same audit log `auditSink`
   * appends to). Enables the startup LOCAL anchor restore + one-time basis
   * migration; omitted → legacy null-anchor bootstrap.
   */
  chainAnchorSource?: ChainAnchorSource;
  /** Platform override (tests). Defaults to `process.platform`. */
  platform?: NodeJS.Platform;
  /** Explicit opt-in override; when omitted the env flag governs. */
  explicitOptIn?: boolean;
  /** Env override (tests). */
  env?: NodeJS.ProcessEnv;
  /** Socket path override (tests / non-default fortress layout). */
  socketPath?: string;
  /** systemctl runner - injected in tests; defaults to the real one. */
  systemctl?: SystemctlRunner;
  /** @deprecated Legacy test input; runtime activation is attach-only and ignores it. */
  fs?: LauncherFs;
  /** @deprecated Legacy test input; the root installer fixes the daemon path. */
  daemonBinary?: string;
  /** @deprecated Legacy test input; runtime activation never writes a drop-in. */
  dropInDir?: string;
  /** TEST-ONLY root-service producer public-key path override. */
  testSystemProducerPubKeyPath?: string;
  /**
   * Transport factory override (tests inject an in-process mock daemon). When
   * omitted, a real UDS transport is connected to the daemon socket. Letting
   * tests inject the transport is what makes the full end-to-end path
   * (launch → connect → handshake → drain → re-verify) exercisable hermetically.
   */
  connectTransport?: (socketPath: string) => Promise<
    import("./ipc-client.js").IpcTransport
  >;
  /** Drain-loop options (poll interval, timers) - tests inject deterministic timers. */
  drainOptions?: LinuxAuditDrainOptions;
  /** Skip starting the continuous drain loop (tests that drive drain manually). */
  startDrainLoop?: boolean;
  /**
   * Whether to PROVE the audit channel is live (one successful drain round-trip)
   * BEFORE reporting armed (codex round-4 HIGH - fail-open at the arming
   * boundary). Default true: a handshake-only "armed" is not enough - the signed
   * enforcement evidence must demonstrably flow, or the activation fails closed
   * (NOT-ARMED) rather than reporting armed for the request-timeout window on an
   * unconfirmed channel. Only honored when the continuous loop runs
   * (`startDrainLoop !== false`). A harness that deliberately injects a
   * non-responsive transport sets this false to skip the probe.
   */
  confirmInitialDrain?: boolean;
  /**
   * Hook for a durable NOT-ARMED / audit-failure signal when the drain loop hits
   * an UNSETTLED transport/persistence FAULT (FIX 4 - drain health is
   * load-bearing in opt-in mode). The activation routes only `onDrainFault`
   * (NOT settled producer-signature refusals) here: the FIRST drain fault trips
   * `markDrainUnhealthy`, which DURABLY records the failure and tears the
   * activation down (so the wall is never silently armed-but-not-draining).
   * `recordDurable` reports whether the not-armed record was persisted before
   * this hook fired (false ⇒ the audit sink was itself unavailable; see
   * `onAuditUnavailable`). Tests inject this to assert the unhealthy transition
   * + teardown fire.
   */
  onDrainUnhealthy?: (err: Error, info: { recordDurable: boolean }) => void;
  /**
   * Explicit FATAL hook for the "audit unavailable" path: a drain fault was
   * observed (wall reads NOT-ARMED) but the durable not-armed record could NOT
   * be persisted (the audit sink threw). Fail-closed + loud - there is no silent
   * fall-back to a less-secure state. When omitted the fatal is still raised
   * internally (the wall stays not-armed + the loop stops); this hook just lets
   * the operator entrypoint surface it (e.g. crash the supervised process so a
   * human notices the box is enforcing-blind).
   */
  onAuditUnavailable?: (fatal: RuntimeLinuxActivationError) => void;
  /**
   * Consecutive RETRYABLE (or unclassified) drain/ACK faults tolerated before
   * the wall is treated as genuinely faulted. Defaults to
   * {@link DEFAULT_RETRYABLE_DRAIN_FAULT_BUDGET}.
   */
  retryableDrainFaultBudget?: number;
  /**
   * Attempts for the fail-closed initial-drain probe when the daemon answers
   * with a RETRYABLE condition. Defaults to
   * {@link DEFAULT_INITIAL_DRAIN_ATTEMPTS}. A TERMINAL answer never retries.
   */
  initialDrainAttempts?: number;
  /** Injected delay for the initial-drain retry backoff; tests pass a no-op. */
  sleep?: (ms: number) => Promise<void>;
}

/**
 * Consecutive retryable drain/ACK faults tolerated before the wall is declared
 * faulted.
 *
 * Derived from what the loop does between faults, not picked: the loop backs off
 * `pollIntervalMs * 2^(n-1)` capped at `maxFaultBackoffMs`, so with the defaults
 * (1s, 30s cap) ten consecutive faults span 1+2+4+8+16+30+30+30+30 = 151
 * seconds. That is long enough that no `systemctl restart` or contention burst
 * reaches it, and short enough that a daemon which has been refusing for two and
 * a half minutes is correctly called broken.
 *
 * A budget is REQUIRED, not optional: without one, a daemon that answers
 * `retryable` forever would leave the wall retrying and claiming health
 * indefinitely, which is the opposite failure from the one being fixed.
 */
export const DEFAULT_RETRYABLE_DRAIN_FAULT_BUDGET = 10;

/**
 * Attempts for the fail-closed initial-drain probe against a RETRYABLE answer.
 *
 * Three, spaced by `INITIAL_DRAIN_RETRY_BASE_MS` doubling (0.5s, 1s), so a
 * daemon that is merely busy at the exact moment of arming gets ~1.5s to answer
 * rather than failing the activation outright, while a daemon that is actually
 * stopping still fails closed quickly. A TERMINAL answer consumes no attempts.
 */
export const DEFAULT_INITIAL_DRAIN_ATTEMPTS = 3;

/** First backoff between initial-drain probe attempts; doubles per attempt. */
const INITIAL_DRAIN_RETRY_BASE_MS = 500;

/**
 * Re-exported from the module that OWNS the drain loop, not declared here.
 *
 * `health/castle-wall-snapshot.ts` consumes this type and this file consumes
 * that module's builder, so declaring it here made the two import each other.
 * The re-export keeps `CastleWallDrainState` importable from the gate for
 * callers that already think of it as an activation concept.
 */
export type { CastleWallDrainState } from "./linux-audit-drain.js";

/** A live producer-signed activation; close it on shutdown. */
/**
 * How complete this activation is.
 *
 * - `full`                   the evidence channel is confirmed; Sanctuary may
 *                            report drain health and (given a wrapped agent) a
 *                            complete-enforcement claim.
 * - `unconfirmed_audit_ack`  the peer is pre-v2 and does not confirm ACKs.
 *                            OPERATION CONTINUES, but every health, arming, and
 *                            enforcement-completeness surface reads
 *                            degraded/incomplete (owner ruling, 2026-09-02).
 */
export type CastleWallActivationCompleteness = "full" | "unconfirmed_audit_ack";

export interface LinuxProducerSignedActivation {
  lifecycle: CastleWallLifecycleHandle;
  drain: LinuxAuditDrainHandle | null;
  /** Fixed pre-provisioned systemd unit verified by attach-only activation. */
  unit: string;
  /**
   * Whether the drain loop is still healthy. Returns false the instant a drain
   * transport/persistence FAULT is observed (FIX 4): in opt-in mode a wedged
   * drain means the wall is armed-but-not-draining, which must never read as
   * healthy. Flips synchronously when the fault is seen; the durable not-armed
   * record + teardown then settle asynchronously (await `whenDrainSettled`).
   */
  drainHealthy(): boolean;
  /**
   * The drain loop tripped a transport/persistence FAULT. Narrower than
   * `!drainHealthy()`: the legacy unconfirmed-ACK basis also fails
   * `drainHealthy()` while the link itself is fine.
   */
  drainFaulted(): boolean;
  /**
   * The three-valued evidence-channel condition. `retrying` means the daemon has
   * answered with a RETRYABLE condition (busy, or stopping) and the loop is
   * backing off: evidence flow is stalled, nothing is torn down, no durable
   * failure record exists, and a successful cycle returns it to `healthy`.
   * After {@link DEFAULT_RETRYABLE_DRAIN_FAULT_BUDGET} consecutive retryable
   * faults it escalates to `faulted`, which is terminal.
   */
  drainState(): CastleWallDrainState;
  /**
   * Whether this activation is FULL or is operating on the weaker pre-v2 basis.
   * Never silently healthy: an `unconfirmed_audit_ack` activation also reads
   * `drainHealthy() === false`, `runtimeHealth().ok === false`, and
   * `runtimeEvidence().status === "degraded"`.
   */
  activationCompleteness(): CastleWallActivationCompleteness;
  /**
   * Resolves once the in-flight unhealthy-transition teardown has fully settled
   * - i.e. the durable NOT-ARMED record was persisted (or the explicit
   * audit-unavailable fatal path was taken) AND the drain loop was stopped.
   * Resolves immediately when no transition is in flight. Round-3 HIGH: lets a
   * caller/test prove the NOT-ARMED record is DURABLE before treating the
   * transition as complete (the record append+flush is awaited, not
   * fire-and-forget).
   */
  whenDrainSettled(): Promise<void>;
  /**
   * The daemon's kernel-runtime health as observed at ARMING time, mapped onto
   * the truthful readiness model (`enforcing` / `kernel_runtime_ready` /
   * `control_plane_only` / `degraded` / `unavailable`).
   *
   * The daemon observation is captured at activation; consumer-side drain and
   * ACK state are recomputed on every call, so a later drain fault immediately
   * withdraws `ok`/`enforcementComplete`. The daemon-side supervisor owns
   * continuous kernel-runtime detection and exits the unit on a real loss.
   */
  runtimeHealth(): CastleWallHealth;
  /**
   * The health-evidence verdict `buildHealthEvidenceReport` would produce for
   * this runtime. This is the PRODUCTION consumer of `evaluateCastleWall`'s
   * lifecycle/runtime branch: without it the branch had no call path outside
   * tests (AGENTS rule 4).
   */
  runtimeEvidence(): CastleWallEvidence;
  /**
   * Sign and publish a complete policy through the authenticated broker. The
   * fortress id is bound to this activation and cannot be supplied by the
   * caller. A strictly increasing generation is mandatory on this server
   * profile; the root daemon also enforces its durable high-water mark.
   */
  publishPolicy(
    input: Omit<BuildSignedManifestInput, "fortressId" | "generation"> & {
      generation: number;
    }
  ): Promise<LinuxPolicyPublication>;
  /**
   * Tear down the drain loop + lifecycle (does NOT stop the systemd daemon).
   * Awaits any in-flight unhealthy-transition teardown first, so a durable
   * not-armed record is never lost to a teardown race.
   */
  stop(): Promise<void>;
}

/**
 * The outcome of consulting the gate: either a live producer-signed activation,
 * or an explicit "not activated" with a reason (NOT an error - the caller keeps
 * the macOS/channel basis path). A FAILURE during a REQUESTED activation is
 * thrown, not returned, so it cannot be mistaken for "inactive".
 *
 * `activated: true` means the activation is LIVE, not that it is HEALTHY. Read
 * `activation.activationCompleteness()` / `drainHealthy()` / `runtimeHealth()`
 * before making any health, arming, or enforcement claim: an activation against
 * a pre-v2 daemon is deliberately live-but-incomplete (owner ruling, 2026-09-02).
 */
export type LinuxActivationOutcome =
  | { activated: true; activation: LinuxProducerSignedActivation }
  | { activated: false; reason: "not_opted_in" | "not_linux" };

/**
 * Consult the gate and, when opted in on Linux, ACTIVATE the producer-signed
 * close end-to-end. Returns `{ activated: false, reason }` when the gate is not
 * engaged (no opt-in, or not Linux) - the caller then keeps its existing path
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

  // P-1: attach to and verify an already-provisioned root service. Runtime
  // activation has no authority to write `/etc` or restart systemd.
  const launch = await launchLinuxCastleWallDaemon({
    fortressId: input.fortressId,
    fortressStoragePath: input.fortressStoragePath,
    systemctl,
  });

  // FIX 1 (codex CRITICAL - fail-open on absent key in the opt-in path).
  //
  // We only reach here when the operator OPTED IN on Linux and the daemon was
  // launched. On the opt-in path a published producer key is EXPECTED: the
  // daemon was launched with `--producer-pub-key` pointed at exactly the path the
  // consumer reads, so by the time it is active it must have published its key.
  //
  // Without this check, an ABSENT key would let `startCastleWall` start on the
  // CHANNEL BASIS (lifecycle.ts: `absent` → consumer key-null) and the gate would
  // still return `activated: true` - reporting armed-but-NOT-enforcing (fake
  // green). The channel-basis floor is legitimate ONLY without opt-in; here a key
  // is required, so an absent key after an opted-in launch is fail-closed
  // not-armed. (`unreadable` already throws below via `startCastleWall`; this adds
  // the missing `absent` case so all three loads are handled honestly:
  // present→enforce, unreadable→throw, absent→throw - none silently channel.)
  if (input.testSystemProducerPubKeyPath && !input.connectTransport) {
    throw new RuntimeLinuxActivationError(
      "test producer-key path override requires an injected transport",
      "producer_key_unreadable"
    );
  }
  let systemProducerPubKeyPath: string;
  try {
    systemProducerPubKeyPath =
      input.testSystemProducerPubKeyPath ??
      (input.connectTransport
        ? resolveProducerPubKeyPath(input.fortressStoragePath)
        : resolveLinuxSystemProducerPubKeyPath(input.fortressId));
  } catch (error) {
    throw new RuntimeLinuxActivationError(
      `Castle Wall Linux activation failed (fail-closed, not armed): ${(error as Error).message}`,
      "producer_key_unreadable"
    );
  }
  const keyLoad = await loadFortressProducerKey(input.fortressStoragePath, {
    platform: "linux",
    linuxProducerPubKeyPath: systemProducerPubKeyPath,
  });
  if (keyLoad.status !== "present") {
    const reason: RuntimeLinuxActivationError["reason"] =
      keyLoad.status === "absent"
        ? "producer_key_absent"
        : "producer_key_unreadable";
    const detail =
      keyLoad.status === "absent"
        ? "no audit-producer key was published after the opted-in daemon launch"
        : keyLoad.reason;
    throw new RuntimeLinuxActivationError(
      `Castle Wall Linux activation failed (fail-closed, not armed): ${detail}. ` +
        `On the opt-in producer-signed path a published key is REQUIRED - refusing ` +
        `to report armed on the (weaker) channel basis.`,
      reason
    );
  }

  // P-2 (transport): resolve the daemon socket + connect a real UDS transport
  // (or the injected mock). A connect failure fails closed.
  const socketPath =
    input.socketPath ??
    resolveCastleWallSocketPath({ platform, fortressId: input.fortressId }).path;
  const transport = input.connectTransport
    ? await input.connectTransport(socketPath)
    : await connectLinuxUdsTransport({ socketPath });

  // startCastleWall loads the same root-published PUBLIC key selected above via
  // `producerKeyLoadOptions`. key `present` → consumer verifies producer
  // evidence; key `absent` / `unreadable` → THROWS on this opted-in server path.
  // We do NOT swallow that throw: a thrown lifecycle = not-armed. We also wrap
  // a handshake failure as fail-closed.
  let lifecycle: CastleWallLifecycleHandle;
  try {
    lifecycle = await startCastleWall({
      transport,
      key: input.key,
      auditSink: input.auditSink,
      fortressStoragePath: input.fortressStoragePath,
      producerKeyLoadOptions: {
        platform: "linux",
        linuxProducerPubKeyPath: systemProducerPubKeyPath,
      },
      ...(input.chainAnchorSource !== undefined
        ? { chainAnchorSource: input.chainAnchorSource }
        : {}),
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
  //
  // FIX 4 (codex HIGH - swallowed drain failure → armed-but-not-draining) +
  // round-3 HIGHs: (1) the NOT-ARMED record must be DURABLE before the
  // health-transition/teardown completes; (2) a SETTLED producer-signature
  // refusal must NOT stop the loop like a transport failure.
  //
  // In opt-in producer-signed mode the drain loop is LOAD-BEARING: if the
  // transport to the daemon wedges, the daemon's signed enforcement evidence
  // never reaches the consumer, so a "running" lifecycle would be silently
  // armed-but-not-draining. We trip a durable NOT-ARMED signal + tear the
  // activation down ONLY on an UNSETTLED drain FAULT (`onDrainFault`): a
  // transport/persistence failure or a malformed entry - never on a settled
  // refusal. A producer-signature REJECTION is the gate working as designed (it
  // is durably recorded + acked by the consumer); routing it here would let a
  // forged event DoS the wall into a false NOT-ARMED. Settled refusals flow
  // through `onError` (diagnostics only) and the loop continues.
  let drain: LinuxAuditDrainHandle | null = null;
  let drainUnhealthy = false;
  // The async teardown chain (durable record → caller hook → loop stop). The
  // health transition is not COMPLETE until this settles, so callers/tests can
  // await it. `drainHealthy()` flips to false synchronously at the START of the
  // transition (the wall must read not-armed the instant a fault is seen), but
  // the teardown completion is observable via `whenDrainSettled`.
  let drainTeardown: Promise<void> = Promise.resolve();
  // Consecutive RETRYABLE/UNCLASSIFIED faults. Reset by any clean cycle, so this
  // counts a persistent refusal, not a lifetime tally.
  let consecutiveRetryableFaults = 0;
  let lastRetryableFault: Error | null = null;
  /** The fault that latched `drainUnhealthy`, for the evidence string. */
  let terminalDrainFault: Error | null = null;
  const retryableBudget = positiveInteger(
    input.retryableDrainFaultBudget,
    DEFAULT_RETRYABLE_DRAIN_FAULT_BUDGET
  );
  const callerOnError = input.drainOptions?.onError;
  const callerOnDrainFault = input.drainOptions?.onDrainFault;
  const callerOnRetryableFault = input.drainOptions?.onRetryableFault;
  const markDrainUnhealthy = (err: Error): void => {
    if (drainUnhealthy) return;
    // Flip health to false SYNCHRONOUSLY: the instant a fault is observed the
    // wall is not draining, so `drainHealthy()` must already read false even
    // before the durable record lands. NOTE this latch is only ONE of the two
    // reasons `drainHealthy()` can be false; the other is the legacy
    // unconfirmed-ACK basis, which is not a fault and tears nothing down. Use
    // `drainFaulted()` when you mean this latch specifically.
    drainUnhealthy = true;
    terminalDrainFault = err;
    drainTeardown = (async () => {
      // Record the audit-failure / not-armed signal DURABLY *before* we treat the
      // transition as complete. The audit sink IS the tamper-evident record;
      // emitting here means an operator/reader sees the wall stopped draining
      // rather than a silent green. Round-3 HIGH: the append+flush were
      // previously fire-and-forget (unawaited, errors swallowed), so a process
      // exit / sink failure could leave `drainHealthy()=false` with NO durable
      // record. We now AWAIT both and, if the record cannot be persisted, take an
      // EXPLICIT fatal "audit unavailable" path (fail-closed) rather than a silent
      // drop. `append` may be sync (void) or async; `await` handles both.
      let recordDurable = false;
      try {
        await input.auditSink.append(
          "l1",
          "castle_wall_drain_failed",
          input.fortressId,
          {
            reason: err.message,
            // HONESTY: this is a consumer-emitted NOT-ARMED fault signal, NOT
            // accepted enforcement evidence, and it carries NO producer
            // signature - so it must never claim the `producer_signed` basis.
            // Read-side attributors already fail-closed-reject a record without
            // a verified producer signature; the honest label matches that.
            evidence_basis: CASTLE_WALL_EVIDENCE_BASIS_DRAIN_FAULT_UNSIGNED,
            armed: false,
            note: "drain transport/persistence fault - wall is NOT armed (signed enforcement evidence is not reaching the consumer)",
          },
          "failure"
        );
        await input.auditSink.flush();
        recordDurable = true;
      } catch (recordErr) {
        // Fail CLOSED + LOUD: the not-armed signal could not be made durable. We
        // never silently lose the record. Surface an explicit "audit unavailable"
        // fatal to the operator hook; the wall already reads not-armed
        // (`drainUnhealthy = true` above) and the loop is still stopped below, so
        // there is no fall-back to a less-secure (silent-green) state.
        const fatal = new RuntimeLinuxActivationError(
          `Castle Wall Linux activation: drain fault could NOT be durably recorded ` +
            `(audit unavailable). Original fault: ${err.message}. ` +
            `Record error: ${recordErr instanceof Error ? recordErr.message : String(recordErr)}.`,
          "drain_failed"
        );
        input.onAuditUnavailable?.(fatal);
      }
      // Surface the original fault to the caller's health hook (tests assert
      // this fires). Pass whether the record was made durable so an operator can
      // distinguish "recorded not-armed" from "not-armed AND audit unavailable".
      input.onDrainUnhealthy?.(err, { recordDurable });
      // Stop the loop so it cannot keep silently retrying a wedged link while the
      // lifecycle still reports "running". Await it so the transition is fully
      // settled (loop quiesced) before this promise resolves.
      await drain?.stop().catch(() => {});
    })();
  };

  /**
   * A RETRYABLE (or unclassified) drain/ACK fault: the daemon answered and said
   * it was busy or stopping.
   *
   * The consumer's data is unaffected in both cases - on the drain path nothing
   * was delivered, and on the ACK path the events are already durable
   * consumer-side - so this writes NO durable failure record and tears NOTHING
   * down. It is still not health: `drainState()` reads `retrying` until a clean
   * cycle clears it. The budget is what stops "retryable" from becoming a
   * permanent excuse: a daemon refusing for `retryableBudget` consecutive cycles
   * is broken whatever it calls itself, and escalates to the terminal path.
   */
  /** The three-valued evidence-channel condition, derived in one place. */
  const drainStateNow = (): CastleWallDrainState => {
    if (drainUnhealthy) return "faulted";
    return consecutiveRetryableFaults > 0 ? "retrying" : "healthy";
  };

  /**
   * The operator-facing reason behind a non-healthy `drainState`, or `undefined`
   * when healthy. Carries the daemon's own words so a reader is not left to
   * guess which condition stalled the channel.
   */
  const drainStateReasonNow = (): string | undefined => {
    if (drainUnhealthy) return terminalDrainFault?.message;
    if (consecutiveRetryableFaults > 0 && lastRetryableFault !== null) {
      return `${lastRetryableFault.message} (${consecutiveRetryableFaults} of ${retryableBudget} consecutive)`;
    }
    return undefined;
  };

  const noteRetryableDrainFault = (err: Error): void => {
    if (drainUnhealthy) return;
    consecutiveRetryableFaults += 1;
    lastRetryableFault = err;
    if (consecutiveRetryableFaults >= retryableBudget) {
      markDrainUnhealthy(
        new Error(
          `audit drain reported a retryable condition ${consecutiveRetryableFaults} ` +
            `consecutive times without a single clean cycle, exhausting the ` +
            `retry budget; the evidence channel is treated as faulted. ` +
            `Last condition: ${err.message}`
        )
      );
    }
  };

  if (input.startDrainLoop !== false) {
    const drainOptions: LinuxAuditDrainOptions = {
      ...input.drainOptions,
      // Settled diagnostics (e.g. a durably-recorded producer-signature refusal):
      // pass through to the caller; the loop CONTINUES; health is untouched.
      onError: (err: Error) => {
        callerOnError?.(err);
      },
      // TERMINAL fault (consumer persistence/integrity failure, malformed entry,
      // a poisoned or unwritable daemon WAL, a dropped link): the load-bearing
      // NOT-ARMED case. Pass through to the caller, then trip the durable
      // not-armed signal + teardown.
      onDrainFault: (err: Error) => {
        callerOnDrainFault?.(err);
        markDrainUnhealthy(err);
      },
      // RETRYABLE fault: bounded, non-durable, no teardown. See above.
      onRetryableFault: (err: Error) => {
        callerOnRetryableFault?.(err);
        noteRetryableDrainFault(err);
      },
      // A clean cycle clears the retry budget. Without this the budget would
      // count every retryable fault the process ever saw and would eventually
      // fault a wall that had been working for days.
      onCycleHealthy: () => {
        input.drainOptions?.onCycleHealthy?.();
        consecutiveRetryableFaults = 0;
        lastRetryableFault = null;
      },
    };

    // CODEX HIGH (round-4 - fail-OPEN at the arming boundary): the continuous
    // loop's first cycle is started fire-and-forget by `startLinuxAuditDrainLoop`,
    // so without this step the activation would return `activated: true` (and
    // `drainHealthy()` would read true) the instant the loop is *scheduled* -
    // BEFORE a single drain round-trip has succeeded. A daemon that completes the
    // handshake but then wedges the very first `audit_drain_request` would report
    // ARMED for the whole request-timeout window (`IpcClient.requestTimeoutMs`,
    // default 10s) with zero signed evidence having flowed. That is exactly the
    // "armed-but-not-draining" fake-green this file's contract forbids.
    //
    // Fix-CLOSED: PROVE the audit channel is live before reporting armed. Await
    // ONE drain round-trip (an empty batch counts - it proves the link delivers;
    // a SETTLED producer-signature refusal in the batch also counts - the channel
    // works and a refused forgery is the gate working, not a transport failure).
    // A transport failure/timeout makes `drainRequest` REJECT, which `drainOnce`
    // propagates → we fail closed. A transient persistence fault during the probe
    // trips `markDrainUnhealthy` (via the wired `onDrainFault`) → `drainUnhealthy`
    // becomes true → we also fail closed. The continuous loop then resumes from
    // the cursor the probe reached, so no event is drained twice or skipped.
    //
    // BOUNDED RETRY on a RETRYABLE answer. The probe is fail-closed, not
    // fail-fast: a daemon that is merely busy at the instant of arming (a WAL
    // control-lock held by an in-flight append) used to fail the whole
    // activation, and starting Sanctuary during a policy write was enough to
    // trigger it. A RETRYABLE answer gets `initialDrainAttempts` tries with a
    // doubling backoff; a TERMINAL answer consumes no attempts and fails closed
    // at once; exhausting the attempts also fails closed. Never a silent pass.
    //
    // `confirmInitialDrain: false` opts a caller out (e.g. a harness that injects
    // a non-responsive transport on purpose); the default is the fail-closed probe.
    const maxEvents =
      input.drainOptions?.maxEvents ?? DEFAULT_AUDIT_DRAIN_MAX_EVENTS;
    const sleep =
      input.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
    const attempts = positiveInteger(
      input.initialDrainAttempts,
      DEFAULT_INITIAL_DRAIN_ATTEMPTS
    );
    let initialCursor: number | null = null;
    let initialPendingAckSeq: number | null = null;
    if (input.confirmInitialDrain !== false) {
      let lastProbeFailure: string | null = null;
      for (let attempt = 1; attempt <= attempts; attempt += 1) {
        let result;
        try {
          result = await drainOnce(
            lifecycle.client(),
            lifecycle.audit(),
            null,
            maxEvents,
            drainOptions.onError,
            drainOptions.onDrainFault,
            {
              pendingAckSeq: initialPendingAckSeq,
              // The probe's retryable faults are NOT counted against the running
              // loop's budget: the probe has its own, smaller attempt bound, and
              // double-counting would let a slow start consume the budget the
              // loop needs for its whole lifetime.
              onRetryableFault: (err) => {
                callerOnRetryableFault?.(err);
                lastProbeFailure = err.message;
              },
            }
          );
        } catch (err) {
          // An UNEXPECTED throw (link dropped / request timed out before any
          // batch arrived). Tear down what we opened and surface NOT-ARMED -
          // never report armed on an unconfirmed audit channel.
          await lifecycle.stop().catch(() => {});
          const message = err instanceof Error ? err.message : String(err);
          throw new RuntimeLinuxActivationError(
            `Castle Wall Linux activation failed (fail-closed, not armed): the initial ` +
              `audit drain did not complete a round-trip, so the signed enforcement ` +
              `evidence channel is unproven (armed-but-not-draining). Cause: ${message}`,
            "drain_failed"
          );
        }
        // Carry any reclamation debt the probe incurred into the loop, or those
        // daemon WAL entries are never re-acked (the loop resumes ABOVE them).
        initialPendingAckSeq = result.pendingAckSeq;
        if (result.faultClass === null) break; // clean round-trip: channel proven
        if (result.faultClass === "terminal") break; // `drainUnhealthy` handles it
        if (attempt < attempts) {
          await sleep(INITIAL_DRAIN_RETRY_BASE_MS * 2 ** (attempt - 1));
          continue;
        }
        // Attempts exhausted on a retryable condition. Still fail CLOSED: the
        // channel was never proven, and "the daemon said it was busy" is not
        // evidence that evidence flows.
        await lifecycle.stop().catch(() => {});
        throw new RuntimeLinuxActivationError(
          `Castle Wall Linux activation failed (fail-closed, not armed): the initial ` +
            `audit drain reported a retryable condition on all ${attempts} attempts, ` +
            `so the signed enforcement evidence channel is unproven ` +
            `(armed-but-not-draining). Last condition: ${lastProbeFailure ?? "unknown"}`,
          "drain_failed"
        );
      }
      // RESUME from the CONSUMER's durable settled floor, NOT the probe's local
      // `nextAfterSeq` (codex round-5 - initialCursor must never outrun
      // settlement). `lastAckedSeq` is the authoritative high-water mark: the
      // consumer advances it ONLY on durable persistence, so it can never point
      // past an unsettled event even if the probe stopped mid-batch at a fault.
      // (The `drainUnhealthy` guard below already fails closed on a probe fault
      // so the loop never starts in that case; sourcing the cursor from the
      // consumer's durable state makes the no-skip property hold by
      // construction rather than by the probe's break-vs-advance bookkeeping.
      // Re-pulling is additionally idempotent: the consumer's chain validator
      // duplicate-drops an already-settled seq and refuses any skip-ahead.)
      initialCursor = lifecycle.audit().getWalChainState().lastAckedSeq;
      if (drainUnhealthy) {
        // A TERMINAL fault tripped during the probe: either the transport failed
        // outright, or the channel delivered and the consumer could not durably
        // settle. Both leave the evidence channel UNPROVEN, which is the fact the
        // operator needs; the cause below says which. The not-armed record +
        // teardown are already in flight; await them, then surface NOT-ARMED.
        await drainTeardown.catch(() => {});
        await lifecycle.stop().catch(() => {});
        throw new RuntimeLinuxActivationError(
          `Castle Wall Linux activation failed (fail-closed, not armed): the initial ` +
            `audit drain hit a terminal fault, so the signed enforcement evidence ` +
            // Through the shared derivation, not the field: one place decides
            // what the operator-facing reason for a non-healthy channel is.
            `channel is unproven (armed-but-not-draining). Cause: ` +
            `${drainStateReasonNow() ?? "unknown"}`,
          "drain_failed"
        );
      }
    }

    drain = startLinuxAuditDrainLoop(
      lifecycle.client(),
      lifecycle.audit(),
      // Resume the continuous loop from the consumer's DURABLE settled floor
      // (`initialCursor`, set above from `getWalChainState().lastAckedSeq`) so a
      // settled event is not needlessly re-pulled and an unsettled one is never
      // skipped. Even if this hint were stale, the consumer's chain validator is
      // the real guard (duplicate-drop / refuse-skip-ahead).
      { ...drainOptions, initialCursor, initialPendingAckSeq }
    );
  }

  // RUNTIME HONESTY GATE (wired, not ornamental).
  //
  // The daemon has completed the handshake and proven the evidence channel; ask
  // it what its KERNEL RUNTIME is doing before reporting armed. Three outcomes,
  // and the difference between them is the whole point:
  //
  //  * PROVEN-LOST (`degraded`)  -> fail closed. A daemon that reports a lost
  //    required component is not enforcing, and arming over it would be exactly
  //    the fake-green this file's contract forbids.
  //  * INDETERMINATE (`unavailable`) -> DO NOT fail. This is what a pre-v2
  //    daemon (which does not report the runtime block at all) and a momentary
  //    health-probe miss both look like, and treating "the daemon did not say"
  //    as "the daemon said no" would turn a partial upgrade into an outage.
  //    It is recorded and surfaced through `runtimeEvidence()` instead.
  //  * `kernel_runtime_ready` / `enforcing` -> proceed. NOTE the honesty bound:
  //    `kernel_runtime_ready` proves the base nft/NFQUEUE runtime, not that any
  //    particular agent has been wrapped. Per-agent enforcement remains a
  //    separate live-state claim; requiring it at channel attachment would make
  //    a correctly idle, default-deny daemon impossible to attach to.
  // ONE round-trip. `healthCheck` returns the exact observation it decided from,
  // so the snapshot below cannot pair a readiness from one status with the raw
  // fields of a later, different one.
  const health = await healthCheck(lifecycle.client());
  const auditAckConfirmed = health.auditAckConfirmed;
  const liveRuntimeHealth = (): CastleWallHealth => {
    const drainState = drainStateNow();
    const channelHealthy = drainState === "healthy" && auditAckConfirmed;
    if (channelHealthy) return health;
    return {
      ...health,
      ok: false,
      enforcementComplete: false,
    };
  };
  const liveRuntimeEvidence = (): CastleWallEvidence =>
    evaluateCastleWall(
      castleWallSnapshotFromHealth(liveRuntimeHealth(), {
        platform,
        drainState: drainStateNow(),
        drainStateReason: drainStateReasonNow(),
      })
    );
  const runtimeEvidenceAtActivation = liveRuntimeEvidence();

  // OWNER RULING (2026-09-02), the AUDIT-ACK gate.
  //
  // A pre-v2 daemon that does not negotiate `audit_drain_ack_response` MAY keep
  // operating: the ACK is still sent one-way, the daemon still truncates, and
  // failing here would turn a partial upgrade into an outage. But operating is
  // not the same as being healthy. Without confirmation the consumer cannot tell
  // a REFUSED truncation from an applied one, so this activation is INCOMPLETE:
  // `drainHealthy()` reads false, `activationCompleteness()` names the reason,
  // `runtimeHealth().ok` and `.enforcementComplete` are false, and
  // `runtimeEvidence()` is `degraded`. The one thing that must never happen is
  // the state passing silently, so it also gets a DURABLE record below.
  const activationCompleteness: CastleWallActivationCompleteness = auditAckConfirmed
    ? "full"
    : "unconfirmed_audit_ack";
  if (!auditAckConfirmed) {
    // Durable, before the activation is handed back. Best-effort on the sink:
    // unlike the drain-fault path this is not a transition INTO a fault, so a
    // sink failure must not tear down a wall that is otherwise operating. The
    // in-memory state is already degraded either way, so a lost record cannot
    // upgrade the claim.
    try {
      await input.auditSink.append(
        "l1",
        "castle_wall_audit_ack_unconfirmed",
        input.fortressId,
        {
          reason:
            "the connected daemon did not advertise audit_drain_ack_response; " +
            "WAL evidence is reclaimed without a confirmed ACK",
          // HONESTY: this is a consumer-emitted posture record, NOT accepted
          // enforcement evidence, and it carries no producer signature.
          evidence_basis: CASTLE_WALL_EVIDENCE_BASIS_DRAIN_FAULT_UNSIGNED,
          armed: true,
          complete: false,
          activation_completeness: activationCompleteness,
          peer_protocol_version: lifecycle.client().daemonProtocol(),
          note:
            "operation continues on the pre-v2 basis; Sanctuary must not report " +
            "drain health, full activation, or complete enforcement from it",
        },
        "failure"
      );
      await input.auditSink.flush();
    } catch {
      // Swallowed deliberately: see above. The degraded state is carried by the
      // returned handle, which the caller reads regardless of the sink.
    }
  }

  if (health.readiness === "degraded" || health.readiness === "control_plane_only") {
    if (drain) await drain.stop().catch(() => {});
    await lifecycle.stop().catch(() => {});
    throw new RuntimeLinuxActivationError(
      `Castle Wall Linux activation failed (fail-closed, not armed): the daemon ` +
        `reports its kernel runtime as ${health.readiness}. ` +
        `${runtimeEvidenceAtActivation.detector_evidence}`,
      "runtime_degraded"
    );
  }

  return {
    lifecycle,
    drain,
    unit: launch.unit,
    /**
     * Whether Sanctuary may report the signed-evidence channel as HEALTHY.
     *
     * BOTH conditions, per the owner ruling: the drain loop has not tripped its
     * fault signal, AND the peer confirms audit ACKs. The second is not a fault
     * (nothing is broken and nothing is torn down), but an unconfirmed channel
     * cannot prove reclamation, so it must never read as drain health. Use
     * `drainFaulted()` when you need the fault dimension by itself.
     */
    drainHealthy: () => drainStateNow() === "healthy" && auditAckConfirmed,
    /**
     * The drain loop tripped a TERMINAL fault. Distinct from `!drainHealthy()`,
     * which is also false on the legacy unconfirmed-ACK basis (link fine,
     * nothing torn down) and while `retrying`.
     */
    drainFaulted: () => drainUnhealthy,
    drainState: drainStateNow,
    activationCompleteness: () => activationCompleteness,
    runtimeHealth: liveRuntimeHealth,
    runtimeEvidence: liveRuntimeEvidence,
    publishPolicy: async (publication) =>
      publishLinuxCompatiblePolicy(
        {
          ...publication,
          fortressId: input.fortressId,
        },
        new BrokerManifestStorage(lifecycle.client())
      ),
    /** Resolves once an in-flight unhealthy-transition teardown has settled. */
    whenDrainSettled: () => drainTeardown,
    stop: async () => {
      // Await any in-flight unhealthy-transition teardown first so we never lose
      // the durable not-armed record to a teardown race.
      await drainTeardown.catch(() => {});
      if (drain) await drain.stop();
      await lifecycle.stop();
    },
  };
}

/** Relative location of the fortress's pinned Castle Wall public key. */
const CASTLE_PINNED_PUBKEY_RELPATH = "castle-pinned-pubkey.bin";
/** Relative location of the fortress's pinned Castle Wall (encrypted) private key. */
const CASTLE_PINNED_PRIVKEY_RELPATH = "castle-pinned-privkey.enc";

/**
 * Build the IPC-handshake {@link ClientKeyMaterial} for the Linux activation from
 * the fortress's on-disk pinned Castle Wall key pair + the fortress master key.
 *
 * This mirrors the macOS daemon's local-sign key load
 * (`macos-daemon.ts:loadLocalSigningKey`): read the 32-byte pinned public key,
 * decrypt the pinned private key with the master key, re-encrypt the 32-byte seed
 * (the IPC client decrypts it transiently per signature). It is the glue the
 * production entrypoints use to thread the existing fortress identity into the
 * opt-in Linux activation WITHOUT a second key source. FAIL-CLOSED: a missing /
 * wrong-length / undecryptable key throws (the caller surfaces not-armed).
 *
 * The private key bytes are zeroed after re-encryption; only the encrypted form
 * is retained on the returned material.
 */
export async function buildLinuxIpcClientKeyMaterial(input: {
  fortressPath: string;
  fortressId: string;
  masterKey: Uint8Array;
}): Promise<ClientKeyMaterial> {
  const publicKey = new Uint8Array(
    await readFile(join(input.fortressPath, CASTLE_PINNED_PUBKEY_RELPATH))
  );
  if (publicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new RuntimeLinuxActivationError(
      `Castle Wall Linux activation: pinned public key must be 32 bytes (found ${publicKey.length}).`,
      "handshake_failed"
    );
  }
  const storedPriv = JSON.parse(
    await readFile(join(input.fortressPath, CASTLE_PINNED_PRIVKEY_RELPATH), "utf8")
  ) as EncryptedPayload;
  const privateKey = decrypt(storedPriv, input.masterKey);
  let encryptedPrivateKey: EncryptedPayload;
  try {
    const seed =
      privateKey.length === ED25519_LEGACY_SEED_AND_PUBKEY_BYTES
        ? privateKey.slice(0, ED25519_PRIVATE_KEY_BYTES)
        : privateKey.length === ED25519_PRIVATE_KEY_BYTES
          ? privateKey
          : null;
    if (seed === null) {
      throw new RuntimeLinuxActivationError(
        `Castle Wall Linux activation: pinned private key must decrypt to 32 bytes (found ${privateKey.length}).`,
        "handshake_failed"
      );
    }
    encryptedPrivateKey = encrypt(seed, input.masterKey);
  } finally {
    privateKey.fill(0);
  }
  return {
    fortressId: input.fortressId,
    signingKeyId: castleWallSigningKeyId(publicKey),
    encryptedPrivateKey,
    encryptionKey: input.masterKey,
  };
}

/**
 * Coerce an optional caller-supplied bound to a usable positive integer.
 *
 * Shared by the retryable-fault budget and the initial-drain attempt count so
 * both reject the same nonsense the same way. A zero or negative budget would
 * mean "escalate on the first retryable condition", which is precisely the
 * behavior these bounds exist to remove, so it falls back to the default rather
 * than being honored.
 */
function positiveInteger(value: number | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  if (!Number.isFinite(value) || value < 1) return fallback;
  return Math.floor(value);
}
