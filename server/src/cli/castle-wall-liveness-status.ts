/**
 * `castle-wall liveness-status [--json] [--fortress <absolute path>]`: the
 * read-only wall, agent and coverage report, and the shared reader that
 * `castle-wall status` and `castle-wall full-status` use for their wall-only
 * exits. It reads records only; it never probes, repairs, renews or writes.
 */
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";
import { uptime as osUptime } from "node:os";
import {
  IPC_DEADLINE,
  LIVENESS_EXIT_DOWN,
  LIVENESS_EXIT_OK,
  LIVENESS_EXIT_USAGE,
  LIVENESS_EXIT_WARNING,
  LIVENESS_STATUS_INTERNAL_EXIT_CODE,
  SECOND,
  STATUS_BYTES,
  readAndEvaluateLiveness,
  type DeadlineClock,
  type HostClock,
  type HostClockProvider,
  type LivenessEnvelope,
  type ReaderFs,
} from "../castle-wall/liveness/index.js";
import { resolveStoragePath } from "../paths.js";
import { consumeFlagValue } from "./argv.js";

// Exit codes must match the exit constants in server/src/castle-wall/liveness/constants.ts.
export { LIVENESS_STATUS_INTERNAL_EXIT_CODE };

const SYSCTL_PATH = "/usr/sbin/sysctl";
const BOOT_SESSION_KEY = "kern.bootsessionuuid";
/** Bytes of sysctl output accepted: a UUID line is 37 bytes, so one KiB is ample. */
const SYSCTL_MAX_BUFFER = 1024;
/** Hex digits of the fortress id digest. Must match `fortressIdFromStoragePath` in server/src/dashboard/v1_1/wiring.ts. */
const FORTRESS_ID_HEX_DIGITS = 16;

/** The stable fortress id the daemon publishes for a storage path. Must match `fortressIdFromStoragePath` in server/src/dashboard/v1_1/wiring.ts. */
export function livenessFortressId(storagePath: string): string {
  return `fortress-${createHash("sha256").update(storagePath).digest("hex").slice(0, FORTRESS_ID_HEX_DIGITS)}`;
}

/**
 * The production boot and uptime provider: `sysctl -n kern.bootsessionuuid`
 * under IPC_DEADLINE, and `os.uptime()` in milliseconds. It fails fast on a
 * missing binary or a nonzero exit, and the evaluator reads a failure as
 * time_untrusted.
 */
function productionUptimeMs(): number {
  return Math.floor(osUptime() * SECOND);
}

export const productionHostClock: HostClockProvider = {
  read(): Promise<HostClock> {
    return new Promise((resolve, reject) => {
      execFile(SYSCTL_PATH, ["-n", BOOT_SESSION_KEY], { timeout: IPC_DEADLINE, maxBuffer: SYSCTL_MAX_BUFFER, encoding: "utf8" }, (error, stdout) => {
        if (error) { reject(error); return; }
        const bootId = String(stdout).trim();
        if (bootId.length === 0) { reject(new Error("empty boot session id")); return; }
        resolve({ ok: true, bootId, uptimeMs: productionUptimeMs() });
      });
    });
  },
  uptimeMs: productionUptimeMs,
};

/** The full daemon recorder's boot source: the same provider, read once at daemon start. */
export const productionDaemonLivenessClock = {
  async bootId(): Promise<string | null> {
    const host = await productionHostClock.read();
    return host.ok ? host.bootId : null;
  },
  uptimeMs: productionUptimeMs,
};

export interface LivenessReaderContext {
  /** INTERNAL/TEST: the full daemon's boot and uptime source for its recorder. */
  daemonHostClock?: { bootId(): Promise<string | null>; uptimeMs(): number };
  platform?: string;
  getuid?: () => number;
  now?: () => number;
  hostClock?: HostClockProvider;
  readerFs?: ReaderFs;
  deadline?: DeadlineClock;
}

export interface LivenessStatusContext extends LivenessReaderContext {
  out?: NodeJS.WritableStream;
  err?: NodeJS.WritableStream;
  env?: NodeJS.ProcessEnv;
}

function operatorUid(ctx: LivenessReaderContext): number {
  const uid = ctx.getuid?.() ?? process.getuid?.();
  return typeof uid === "number" ? uid : -1;
}

/** Read and evaluate the fortress's stored liveness evidence. */
export function evaluateFortressLiveness(fortressPath: string, ctx: LivenessReaderContext = {}): Promise<LivenessEnvelope> {
  return readAndEvaluateLiveness({
    fortressPath,
    fortressId: livenessFortressId(fortressPath),
    operatorUid: operatorUid(ctx),
    platform: ctx.platform ?? process.platform,
    nowMs: ctx.now ?? Date.now,
    host: ctx.hostClock ?? productionHostClock,
    fs: ctx.readerFs,
    deadline: ctx.deadline,
  });
}

/** The three human-readable Liveness lines appended by status and full-status. */
export function formatLivenessLines(envelope: LivenessEnvelope): string {
  return [
    `Liveness wall: ${envelope.wall.state} (${envelope.wall.reasons.join(", ")})`,
    `Liveness agent: ${envelope.agent.state} (${envelope.agent.reasons.join(", ")})`,
    `Liveness coverage: ${envelope.coverage.state} (${envelope.coverage.reasons.join(", ")})`,
  ].join("\n") + "\n";
}

/**
 * The wall-only exit for `status` and `full-status`: 0 only for a wall OK, 3
 * for a wall warning, and 1 for everything else, including the internal exit,
 * because those commands have no exit 70.
 */
export function wallOnlyStatusExit(envelope: LivenessEnvelope): number {
  // The exit comes from the shared evaluator's wall verdict alone, so a running pid or an agent never sets it.
  if (envelope.exit_code === LIVENESS_EXIT_OK || envelope.exit_code === LIVENESS_EXIT_WARNING) return envelope.exit_code;
  return LIVENESS_EXIT_DOWN;
}

function writeTo(stream: NodeJS.WritableStream, text: string): void {
  stream.write(text);
}

/** `castle-wall liveness-status`. */
export async function runLivenessStatus(argv: string[] = [], ctx: LivenessStatusContext = {}): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const fortressFlag = consumeFlagValue(argv, "--fortress");
  if (fortressFlag.error !== undefined) {
    writeTo(err, `castle-wall liveness-status: ${fortressFlag.error}\n`);
    return LIVENESS_EXIT_USAGE;
  }
  let json = false;
  for (const arg of fortressFlag.argv) {
    if (arg === "--json") json = true;
    else {
      // The refused token is never echoed, so an argv secret cannot reach the terminal or a log.
      writeTo(err, "castle-wall liveness-status: unknown argument\n");
      return LIVENESS_EXIT_USAGE;
    }
  }
  if (fortressFlag.value !== undefined && !isAbsolute(fortressFlag.value)) {
    writeTo(err, "castle-wall liveness-status: --fortress must be an absolute path\n");
    return LIVENESS_EXIT_USAGE;
  }
  const fortressPath = fortressFlag.value ?? resolveStoragePath(env);
  let envelope: LivenessEnvelope;
  try {
    envelope = await evaluateFortressLiveness(fortressPath, ctx);
  } catch {
    // No valid envelope can be built, so print nothing and report the internal exit.
    return LIVENESS_STATUS_INTERNAL_EXIT_CODE;
  }
  if (json) {
    const text = `${JSON.stringify(envelope)}\n`;
    if (Buffer.byteLength(text) > STATUS_BYTES) return LIVENESS_STATUS_INTERNAL_EXIT_CODE;
    writeTo(out, text);
  } else {
    writeTo(out, formatLivenessLines(envelope));
  }
  return envelope.exit_code;
}
