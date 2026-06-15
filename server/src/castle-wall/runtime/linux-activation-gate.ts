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
 *     key is ABSENT after an opted-in launch (a key is required on this path —
 *     see FIX 1), or the audit drain transport wedges (armed-but-not-draining —
 *     see FIX 4), the activation THROWS / trips NOT-ARMED. The caller surfaces
 *     NOT-ARMED. There is NO branch that swallows a failure and falls back to
 *     the channel basis when a key is expected. The channel-basis floor applies
 *     ONLY on the non-opt-in path; here, opting in means enforcement is required.
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
  drainOnce,
  DEFAULT_AUDIT_DRAIN_MAX_EVENTS,
  type LinuxAuditDrainHandle,
  type LinuxAuditDrainOptions,
} from "./linux-audit-drain.js";
import { loadFortressProducerKey } from "./producer-signature.js";
import { RuntimeLinuxActivationError } from "./errors.js";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { decrypt, encrypt, type EncryptedPayload } from "../../core/encryption.js";
import { toBase64url } from "../../core/encoding.js";

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
  /**
   * Whether to PROVE the audit channel is live (one successful drain round-trip)
   * BEFORE reporting armed (codex round-4 HIGH — fail-open at the arming
   * boundary). Default true: a handshake-only "armed" is not enough — the signed
   * enforcement evidence must demonstrably flow, or the activation fails closed
   * (NOT-ARMED) rather than reporting armed for the request-timeout window on an
   * unconfirmed channel. Only honored when the continuous loop runs
   * (`startDrainLoop !== false`). A harness that deliberately injects a
   * non-responsive transport sets this false to skip the probe.
   */
  confirmInitialDrain?: boolean;
  /**
   * Hook for a durable NOT-ARMED / audit-failure signal when the drain loop hits
   * an UNSETTLED transport/persistence FAULT (FIX 4 — drain health is
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
   * be persisted (the audit sink threw). Fail-closed + loud — there is no silent
   * fall-back to a less-secure state. When omitted the fatal is still raised
   * internally (the wall stays not-armed + the loop stops); this hook just lets
   * the operator entrypoint surface it (e.g. crash the supervised process so a
   * human notices the box is enforcing-blind).
   */
  onAuditUnavailable?: (fatal: RuntimeLinuxActivationError) => void;
}

/** A live producer-signed activation; close it on shutdown. */
export interface LinuxProducerSignedActivation {
  lifecycle: CastleWallLifecycleHandle;
  drain: LinuxAuditDrainHandle | null;
  /** The drop-in path written, for diagnostics. */
  dropInPath: string;
  /**
   * Whether the drain loop is still healthy. Returns false the instant a drain
   * transport/persistence FAULT is observed (FIX 4): in opt-in mode a wedged
   * drain means the wall is armed-but-not-draining, which must never read as
   * healthy. Flips synchronously when the fault is seen; the durable not-armed
   * record + teardown then settle asynchronously (await `whenDrainSettled`).
   */
  drainHealthy(): boolean;
  /**
   * Resolves once the in-flight unhealthy-transition teardown has fully settled
   * — i.e. the durable NOT-ARMED record was persisted (or the explicit
   * audit-unavailable fatal path was taken) AND the drain loop was stopped.
   * Resolves immediately when no transition is in flight. Round-3 HIGH: lets a
   * caller/test prove the NOT-ARMED record is DURABLE before treating the
   * transition as complete (the record append+flush is awaited, not
   * fire-and-forget).
   */
  whenDrainSettled(): Promise<void>;
  /**
   * Tear down the drain loop + lifecycle (does NOT stop the systemd daemon).
   * Awaits any in-flight unhealthy-transition teardown first, so a durable
   * not-armed record is never lost to a teardown race.
   */
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

  // FIX 1 (codex CRITICAL — fail-open on absent key in the opt-in path).
  //
  // We only reach here when the operator OPTED IN on Linux and the daemon was
  // launched. On the opt-in path a published producer key is EXPECTED: the
  // daemon was launched with `--producer-pub-key` pointed at exactly the path the
  // consumer reads, so by the time it is active it must have published its key.
  //
  // Without this check, an ABSENT key would let `startCastleWall` start on the
  // CHANNEL BASIS (lifecycle.ts: `absent` → consumer key-null) and the gate would
  // still return `activated: true` — reporting armed-but-NOT-enforcing (fake
  // green). The channel-basis floor is legitimate ONLY without opt-in; here a key
  // is required, so an absent key after an opted-in launch is fail-closed
  // not-armed. (`unreadable` already throws below via `startCastleWall`; this adds
  // the missing `absent` case so all three loads are handled honestly:
  // present→enforce, unreadable→throw, absent→throw — none silently channel.)
  const keyLoad = await loadFortressProducerKey(input.fortressStoragePath);
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
        `On the opt-in producer-signed path a published key is REQUIRED — refusing ` +
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
  //
  // FIX 4 (codex HIGH — swallowed drain failure → armed-but-not-draining) +
  // round-3 HIGHs: (1) the NOT-ARMED record must be DURABLE before the
  // health-transition/teardown completes; (2) a SETTLED producer-signature
  // refusal must NOT stop the loop like a transport failure.
  //
  // In opt-in producer-signed mode the drain loop is LOAD-BEARING: if the
  // transport to the daemon wedges, the daemon's signed enforcement evidence
  // never reaches the consumer, so a "running" lifecycle would be silently
  // armed-but-not-draining. We trip a durable NOT-ARMED signal + tear the
  // activation down ONLY on an UNSETTLED drain FAULT (`onDrainFault`): a
  // transport/persistence failure or a malformed entry — never on a settled
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
  const callerOnError = input.drainOptions?.onError;
  const callerOnDrainFault = input.drainOptions?.onDrainFault;
  const markDrainUnhealthy = (err: Error): void => {
    if (drainUnhealthy) return;
    // Flip health to false SYNCHRONOUSLY: the instant a fault is observed the
    // wall is not draining, so `drainHealthy()` must already read false even
    // before the durable record lands.
    drainUnhealthy = true;
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
            evidence_basis: "producer_signed",
            armed: false,
            note: "drain transport/persistence fault — wall is NOT armed (signed enforcement evidence is not reaching the consumer)",
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

  if (input.startDrainLoop !== false) {
    const drainOptions: LinuxAuditDrainOptions = {
      ...input.drainOptions,
      // Settled diagnostics (e.g. a durably-recorded producer-signature refusal):
      // pass through to the caller; the loop CONTINUES; health is untouched.
      onError: (err: Error) => {
        callerOnError?.(err);
      },
      // Unsettled FAULT (transport/persistence failure, malformed entry): this is
      // the load-bearing NOT-ARMED case. Pass through to the caller, then trip
      // the durable not-armed signal + teardown.
      onDrainFault: (err: Error) => {
        callerOnDrainFault?.(err);
        markDrainUnhealthy(err);
      },
    };

    // CODEX HIGH (round-4 — fail-OPEN at the arming boundary): the continuous
    // loop's first cycle is started fire-and-forget by `startLinuxAuditDrainLoop`,
    // so without this step the activation would return `activated: true` (and
    // `drainHealthy()` would read true) the instant the loop is *scheduled* —
    // BEFORE a single drain round-trip has succeeded. A daemon that completes the
    // handshake but then wedges the very first `audit_drain_request` would report
    // ARMED for the whole request-timeout window (`IpcClient.requestTimeoutMs`,
    // default 10s) with zero signed evidence having flowed. That is exactly the
    // "armed-but-not-draining" fake-green this file's contract forbids.
    //
    // Fix-CLOSED: PROVE the audit channel is live before reporting armed. Await
    // ONE drain round-trip (an empty batch counts — it proves the link delivers;
    // a SETTLED producer-signature refusal in the batch also counts — the channel
    // works and a refused forgery is the gate working, not a transport failure).
    // A transport failure/timeout makes `drainRequest` REJECT, which `drainOnce`
    // propagates → we fail closed. A transient persistence fault during the probe
    // trips `markDrainUnhealthy` (via the wired `onDrainFault`) → `drainUnhealthy`
    // becomes true → we also fail closed. The continuous loop then resumes from
    // the cursor the probe reached, so no event is drained twice or skipped.
    //
    // `confirmInitialDrain: false` opts a caller out (e.g. a harness that injects
    // a non-responsive transport on purpose); the default is the fail-closed probe.
    const maxEvents =
      input.drainOptions?.maxEvents ?? DEFAULT_AUDIT_DRAIN_MAX_EVENTS;
    let initialCursor: number | null = null;
    if (input.confirmInitialDrain !== false) {
      try {
        await drainOnce(
          lifecycle.client(),
          lifecycle.audit(),
          null,
          maxEvents,
          drainOptions.onError,
          drainOptions.onDrainFault
        );
        // RESUME from the CONSUMER's durable settled floor, NOT the probe's local
        // `nextAfterSeq` (codex round-5 — initialCursor must never outrun
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
      } catch (err) {
        // The initial drain round-trip failed (link dropped / request timed out
        // before any batch arrived). Tear down what we opened and surface
        // NOT-ARMED — never report armed on an unconfirmed audit channel.
        await lifecycle.stop().catch(() => {});
        const message = err instanceof Error ? err.message : String(err);
        throw new RuntimeLinuxActivationError(
          `Castle Wall Linux activation failed (fail-closed, not armed): the initial ` +
            `audit drain did not complete a round-trip, so the signed enforcement ` +
            `evidence channel is unproven (armed-but-not-draining). Cause: ${message}`,
          "drain_failed"
        );
      }
      if (drainUnhealthy) {
        // A persistence fault tripped during the probe (the channel delivered but
        // the consumer could not durably settle). The not-armed record + teardown
        // are already in flight; await them, then surface NOT-ARMED.
        await drainTeardown.catch(() => {});
        await lifecycle.stop().catch(() => {});
        throw new RuntimeLinuxActivationError(
          `Castle Wall Linux activation failed (fail-closed, not armed): the initial ` +
            `audit drain could not be durably settled (audit persistence fault).`,
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
      { ...drainOptions, initialCursor }
    );
  }

  return {
    lifecycle,
    drain,
    dropInPath: launch.dropInPath,
    /** Whether the drain loop has tripped its unhealthy / not-armed signal. */
    drainHealthy: () => !drainUnhealthy,
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
  if (publicKey.length !== 32) {
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
      privateKey.length === 64
        ? privateKey.slice(0, 32)
        : privateKey.length === 32
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
    signingKeyId: `castle-wall:${toBase64url(publicKey)}`,
    encryptedPrivateKey,
    encryptionKey: input.masterKey,
  };
}
