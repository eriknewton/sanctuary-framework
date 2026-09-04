/**
 * The PRODUCTION Castle Wall runtime detector for the MCP server process.
 *
 * # Why this file exists
 *
 * `evaluateCastleWall`'s lifecycle/runtime branch, and the whole
 * `castleWallSnapshotFromHealth` mapping, had exactly one non-test consumer: the
 * activation gate's own error string. Every production `buildHealthEvidenceReport`
 * call site (`monitor_health`, `exec_attest`, and the SHR publish payload)
 * omitted `castleWall` entirely, so all three reported `not_configured` on a host
 * whose wall was live, degraded, or faulted alike. The capability had unit tests
 * and no production call path, which is the AGENTS rule-4 / rule-9 shape: a
 * `shipped` claim over an inert sub-capability.
 *
 * The activation handle cannot close that gap on its own, because of a PROCESS
 * boundary: the gate runs in the `wrap` / `castle-wall daemon` CLI process, and
 * `monitor_health` runs in the MCP server process. An in-memory handle is not
 * reachable across it. This detector is the reachable path: a bounded,
 * authenticated status round-trip to the same daemon, from whichever process is
 * asking.
 *
 * # What it proves, and what it deliberately does not
 *
 * PROVES (observed directly, this process, this moment):
 *   - the daemon socket for THIS fortress exists and accepts a connection;
 *   - the daemon completed an Ed25519 handshake against THIS fortress's pinned
 *     key, so the answer came from the daemon this fortress is bound to and not
 *     from any process that happened to bind a socket;
 *   - its self-reported lifecycle, kernel-runtime, manifest, and probe state;
 *   - whether it negotiates confirmed audit ACKs.
 *
 * DOES NOT PROVE, and says so rather than defaulting:
 *   - that the consumer-side drain loop is delivering. That loop lives in the
 *     arming process. The snapshot carries `evidenceChannel: "unobserved"`, which
 *     caps the verdict at `unknown` — never `active`. Defaulting it to healthy
 *     here would fabricate exactly the claim this file exists to stop faking.
 *
 * # Fail directions
 *
 * Three distinct answers, kept distinct because collapsing any two of them loses
 * the fact an operator needs:
 *
 *   - NOT LINUX -> `undefined` -> `not_configured` with "no detector applies on
 *     this platform". The macOS channel-basis path owns that surface.
 *   - NO SOCKET for this fortress -> `configured: false` -> `not_configured`
 *     with the path it looked at. This host is not running the wall.
 *   - SOCKET PRESENT but unreachable, handshake refused, or status timed out ->
 *     `daemonUp: "unknown"` with the cause -> `unknown`. Something IS installed
 *     and it did not answer. Deliberately not `not_configured` (which would
 *     understate it), not `inactive` (a WEDGED daemon is running and produces
 *     this same observation), and not any claim about enforcement.
 */

import { stat } from "node:fs/promises";

import { healthCheck } from "../castle-wall/runtime/lifecycle.js";
import {
  buildLinuxIpcClientKeyMaterial,
  type CastleWallDrainState,
} from "../castle-wall/runtime/linux-activation-gate.js";
import {
  connectLinuxUdsTransport,
  resolveCastleWallSocketPath,
} from "../castle-wall/runtime/linux-daemon.js";
import { IpcClient, type IpcTransport } from "../castle-wall/runtime/ipc-client.js";
import { castleWallSnapshotFromHealth } from "./castle-wall-snapshot.js";
import type { CastleWallRuntimeSnapshot } from "./evidence.js";

/**
 * Wall-clock ceiling for the whole detect call: connect + handshake + one status
 * round-trip.
 *
 * Derived from what it bounds, not chosen: `IpcClient` already applies a 5s
 * handshake deadline and a 10s per-request deadline, so 6s is deliberately
 * TIGHTER than their sum. `monitor_health` is an interactive tool an agent calls
 * synchronously; a health check that can block it for fifteen seconds is a
 * liveness defect of its own, and an unanswered daemon is exactly the case this
 * detector reports as `unknown` rather than waiting out.
 *
 * Failure mode if this is removed: a wedged daemon socket that accepts the
 * connection and never answers hangs `monitor_health` and `shr_generate` for the
 * full request timeout, and the symptom presents as "Sanctuary is hung", not as
 * "the wall is not answering".
 */
export const CASTLE_WALL_DETECT_TIMEOUT_MS = 6_000;

export interface CastleWallDetectorInput {
  /** Fortress storage path; also where the pinned key pair lives. */
  fortressStoragePath: string;
  /** The fortress this report is about. Binds the handshake identity. */
  fortressId: string;
  /** Fortress master key, used to decrypt the pinned private key. */
  masterKey: Uint8Array;
  /** Platform override (tests). Defaults to this process's platform. */
  platform?: NodeJS.Platform;
  /** Socket path override (tests / non-default layout). */
  socketPath?: string;
  /** Overall deadline. Defaults to {@link CASTLE_WALL_DETECT_TIMEOUT_MS}. */
  timeoutMs?: number;
  /** Transport factory override; tests inject an in-process mock daemon. */
  connectTransport?: (socketPath: string) => Promise<IpcTransport>;
  /** Socket-presence probe override (tests). */
  socketExists?: (path: string) => Promise<boolean>;
  /**
   * The drain-loop condition, when the CALLER is the process that armed the wall
   * and therefore genuinely knows it. Omitted from the MCP server process, where
   * it is unknowable — and omission is reported as `unobserved`, never as
   * health.
   */
  drainState?: CastleWallDrainState;
}

/**
 * Take one bounded, authenticated reading of this fortress's Castle Wall daemon.
 *
 * Returns `undefined` when there is no daemon to read (non-Linux, or no socket),
 * which `evaluateCastleWall` renders as `not_configured`.
 */
const DETECTOR_MULTIPLEX_WINDOW_MS = 1_000;
const detectorReads = new Map<
  string,
  { expiresAt: number; promise: Promise<CastleWallRuntimeSnapshot | undefined> }
>();
const detectorObjectIds = new WeakMap<object, number>();
let nextDetectorObjectId = 1;
function detectorObjectId(value: object | undefined): string {
  if (!value) return "default";
  let id = detectorObjectIds.get(value);
  if (id === undefined) {
    id = nextDetectorObjectId++;
    detectorObjectIds.set(value, id);
  }
  return String(id);
}

export async function detectCastleWallRuntimeSnapshot(
  input: CastleWallDetectorInput
): Promise<CastleWallRuntimeSnapshot | undefined> {
  // Production callers for the same fortress coalesce concurrent calls and
  // briefly reuse one authenticated observation, preventing agent polling
  // bursts from consuming the daemon's trusted-UID pre-auth budget. Injected
  // test transports are keyed by object identity so unrelated fixtures never
  // share a reading.
  const platform = input.platform ?? process.platform;
  const key = `${platform}\0${input.fortressId}\0${input.fortressStoragePath}\0${input.socketPath ?? ""}\0${detectorObjectId(input.connectTransport)}\0${detectorObjectId(input.socketExists)}`;
  const existing = detectorReads.get(key);
  if (existing && existing.expiresAt > Date.now()) return await existing.promise;
  const promise = detectCastleWallRuntimeSnapshotUncached(input);
  detectorReads.set(key, {
    expiresAt: Date.now() + DETECTOR_MULTIPLEX_WINDOW_MS,
    promise,
  });
  return await promise;
}

async function detectCastleWallRuntimeSnapshotUncached(
  input: CastleWallDetectorInput
): Promise<CastleWallRuntimeSnapshot | undefined> {
  const platform = input.platform ?? process.platform;
  if (platform !== "linux") {
    // The producer-signed daemon is Linux-only. On macOS the channel-basis path
    // owns this surface; speaking for it from here would be a second, weaker
    // detector for the same claim (AGENTS rule 5).
    return undefined;
  }

  const socketPath =
    input.socketPath ??
    resolveCastleWallSocketPath({
      platform,
      fortressId: input.fortressId,
      fortressPath: input.fortressStoragePath,
    }).path;

  const exists = input.socketExists ?? defaultSocketExists;
  if (!(await exists(socketPath))) {
    // No daemon for this fortress on this host. `configured: false` renders as
    // `not_configured`, and it is a DIFFERENT statement from "installed but
    // silent" below - returning `undefined` here would collapse the two into
    // "no detector is wired", which is no longer true and would hide which of
    // the three it is.
    return {
      platform,
      configured: false,
      detectorName: "Castle Wall daemon (authenticated IPC status)",
      reason:
        `no Castle Wall daemon socket for this fortress at ${socketPath}; ` +
        `this host is not running the producer-signed wall`,
    };
  }

  const deadlineMs = input.timeoutMs ?? CASTLE_WALL_DETECT_TIMEOUT_MS;
  // BOTH are tracked, because ownership transfers partway through: the transport
  // exists before the client wraps it, and the deadline can fire in that gap. A
  // `client`-only cleanup leaked one open socket per health call whenever the
  // race landed there, which is the availability attack this detector must not
  // become against the wall it reports on.
  let transport: IpcTransport | null = null;
  let client: IpcClient | null = null;
  // Set when the deadline has already fired. A pending `await` cannot be
  // interrupted, so cancellation here is COOPERATIVE: the abandoned work checks
  // this flag at every acquisition boundary and releases what it holds instead
  // of proceeding. Without it, the outer `finally` runs while the connect is
  // still in flight, sees nothing to close, and the socket that arrives a moment
  // later is orphaned forever.
  let abandoned = false;

  const releaseOpened = async (): Promise<void> => {
    // The client owns the transport once constructed, so closing it is enough;
    // before that, the raw transport is ours to close. Read through
    // explicitly-typed locals: TypeScript narrows both bindings to `never`
    // because their only assignments happen inside the closure below, which its
    // control-flow analysis does not follow.
    const openedClient = client as IpcClient | null;
    const openedTransport = transport as IpcTransport | null;
    client = null;
    transport = null;
    if (openedClient !== null) {
      await openedClient.close().catch(() => {});
    } else if (openedTransport !== null) {
      await openedTransport.close().catch(() => {});
    }
  };

  /** Give up and release, once the caller has already stopped waiting. */
  const abandonIfLate = async (): Promise<void> => {
    if (!abandoned) return;
    await releaseOpened();
    throw new Error("status detection was abandoned after its deadline");
  };

  try {
    const work = (async () => {
      // The handshake identity is THIS fortress's pinned key pair, loaded
      // through the same helper the activation gate uses. That is what makes the
      // reading fortress-BOUND rather than socket-bound: a daemon serving a
      // different fortress, or any other process squatting the path, cannot
      // complete this handshake, so its status can never be reported as this
      // fortress's wall.
      const key = await buildLinuxIpcClientKeyMaterial({
        fortressPath: input.fortressStoragePath,
        fortressId: input.fortressId,
        masterKey: input.masterKey,
      });
      await abandonIfLate();
      transport = await (input.connectTransport
        ? input.connectTransport(socketPath)
        : connectLinuxUdsTransport({ socketPath }));
      await abandonIfLate();
      // An `IpcClient` directly, NOT `startCastleWall`: this is a READ-ONLY
      // reading and must never construct an audit consumer, a drain loop, or a
      // policy publisher. A detector that is also a writer would be a second
      // owner of state the arming process owns.
      client = IpcClient.create(transport, key);
      await client.start();
      await abandonIfLate();
      const health = await healthCheck(client);
      return castleWallSnapshotFromHealth(health, {
        platform,
        detectorName: "Castle Wall daemon (authenticated IPC status)",
        // The honest core of this file. See the header: omission reads as
        // `unobserved`, which caps the verdict at `unknown`.
        drainState: input.drainState,
        drainStateReason:
          input.drainState === undefined
            ? "the drain loop runs in the process that armed the wall; this " +
              "report was taken from a different process and cannot observe it"
            : undefined,
      });
    })();
    // BACKSTOP for a step that finishes after the last `abandonIfLate` it will
    // ever reach. Both handlers are attached, so the abandoned work can never
    // surface as an unhandled rejection either.
    void work.then(
      () => releaseOpened(),
      () => releaseOpened()
    );
    return await withDeadline(deadlineMs, work);
  } catch (err) {
    abandoned = true;
    // Something IS installed (the socket exists) and it did not answer. That is
    // a positive observation about availability and a NON-observation about
    // enforcement, so it reads `unknown` with the cause, never `not_configured`
    // (which would understate it) and never a claim that the wall failed.
    return {
      platform,
      configured: true,
      // `"unknown"`, NOT `false`. `false` renders as `inactive`, which asserts
      // the daemon is not running - and a daemon that is alive but WEDGED
      // produces exactly this observation. We proved it did not answer; we did
      // not prove it is down.
      daemonUp: "unknown",
      detectorName: "Castle Wall daemon (authenticated IPC status)",
      reason:
        `the Castle Wall daemon socket exists at ${socketPath} but did not ` +
        `answer an authenticated status query within ${deadlineMs}ms: ` +
        `${err instanceof Error ? err.message : String(err)}`,
    };
  } finally {
    // The SUCCESS path's release. The failure paths release through
    // `abandonIfLate` (as soon as the abandoned work reaches its next
    // acquisition boundary) or through the `work.then` backstop; `releaseOpened`
    // nulls both handles, so a second call here is a no-op rather than a double
    // close.
    await releaseOpened();
  }
}

async function defaultSocketExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

/**
 * Await `work` under a hard wall-clock ceiling.
 *
 * Takes an already-started PROMISE rather than a thunk, because the caller must
 * keep its own reference: when the deadline wins, the work is still running and
 * still holding resources, and only the caller can release them.
 *
 * The inner deadlines (`IpcClient`'s handshake and request timeouts) bound each
 * STEP; this bounds the SUM, including the connect that precedes them. Without
 * it a socket that accepts and stalls at each step in turn stays inside every
 * individual budget while blowing the caller's.
 */
async function withDeadline<T>(ms: number, work: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`status detection exceeded ${ms}ms`)),
          ms
        );
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * THE production Castle Wall evidence source for `buildHealthEvidenceReport`.
 *
 * One function, called by every production site that builds a health report
 * (`monitor_health`, `exec_attest`, and the SHR publish payload). Three inline
 * copies of this derivation is the hand-mirrored shape that drifts (AGENTS
 * rule 5), and the drift would be invisible: each site would keep returning a
 * plausible verdict while disagreeing about the same wall.
 *
 * NEVER THROWS. A health tool that fails because the health DETECTOR failed
 * turns an observability gap into an outage, and the honest reading for "the
 * detector could not run" is already expressible: `undefined` renders as
 * `not_configured`, and an installed-but-silent daemon renders as `unknown`
 * with its cause. Neither ever renders as health.
 */
export async function castleWallSnapshotForHealthReport(input: {
  config: { storage_path: string };
  masterKey: Uint8Array;
  /** Test/caller overrides, threaded straight through to the detector. */
  overrides?: Partial<CastleWallDetectorInput>;
}): Promise<CastleWallRuntimeSnapshot | undefined> {
  try {
    // The SAME derivation the composition root and the arming CLI use, imported
    // rather than re-implemented: a second `fortressId` derivation would point
    // this detector at a different socket than the one the wall was armed on,
    // and the report would be honest about a daemon that is not this fortress's.
    const { fortressIdFromStoragePath } = await import(
      "../dashboard/v1_1/wiring.js"
    );
    return await detectCastleWallRuntimeSnapshot({
      fortressStoragePath: input.config.storage_path,
      fortressId: fortressIdFromStoragePath(input.config.storage_path),
      masterKey: input.masterKey,
      ...input.overrides,
    });
  } catch {
    // Deliberately swallowed: see the NEVER THROWS note above. `undefined` is
    // the same answer as "no wall here", which is the weakest claim available
    // and therefore the safe one when the detector itself could not run.
    return undefined;
  }
}
