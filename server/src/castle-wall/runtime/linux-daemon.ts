/**
 * Linux Castle Wall daemon launcher + producer-signed activation path (Slice
 * "PR 2b" + C4 tamper-proof half).
 *
 * The Linux enforcing daemon runs as a root systemd service
 * (`castle-wall-daemon/systemd/sanctuary-castle-wall.service`): an unprivileged
 * TS process cannot rewrite a root unit or `systemctl edit`. The RATIFIED model
 * (split-process + Tier-A, 2026-06-16) keeps the daemon systemd-managed and has
 * the launcher PATCH the unit via a drop-in that splices
 * `producerKeyDaemonLaunchArgs(fortressStoragePath)` so the daemon publishes its
 * `audit-producer.pub` to EXACTLY `resolveProducerPubKeyPath(fortressStoragePath)`
 * — the same path the in-process TS server reads. Deriving both halves from one
 * storage root closes the daemon↔TS path divergence by construction.
 *
 * # Security posture
 *
 * - The daemon's PRIVATE producer key stays root-owned (the drop-in points
 *   `--producer-key` into the fortress `policy/egress` dir; the daemon writes
 *   the priv key `0600` root-owned and the pub key world-readable per
 *   `producer-signature.ts` / the Rust `producer_sig` module). The TS server
 *   only ever reads the PUBLIC key.
 * - FAIL-CLOSED: every failure mode here (daemon won't start, unit not active,
 *   key unreadable, handshake fails) throws `RuntimeLinuxActivationError`. The
 *   caller surfaces NOT-ARMED. There is NO path that swallows a failure and
 *   degrades to the channel basis when a key is expected.
 * - OPT-IN / OFF-BY-DEFAULT: this module is invoked ONLY by the explicit
 *   `activateLinuxProducerSignedCastleWall` entry behind a deliberate gate
 *   (see `linux-activation-gate.ts`). Nothing turns it on by default.
 *
 * # Drill-acceptance caveat (never overclaim)
 *
 * This wires the producer-signed close end-to-end IN CODE on Linux behind an
 * opt-in gate. The external claim that "the fake-arm hole is closed in prod on
 * Linux" still requires a CAPTURED DRILL on real Linux hardware (daemon signs →
 * server pulls + re-verifies → forged entry rejected → dashboard honestly
 * non-green). Until that drill is captured the honest status is:
 * "test/smoke-passed, drill-acceptance pending."
 */

import { createConnection } from "node:net";
import { readFile, writeFile, mkdir, chmod } from "node:fs/promises";
import { join } from "node:path";

import { resolveCastleWallSocketPath } from "./socket-path.js";
import {
  producerKeyDaemonLaunchArgs,
  resolveProducerPubKeyPath,
} from "./producer-signature.js";
import { RuntimeLinuxActivationError } from "./errors.js";
import type { IpcTransport } from "./ipc-client.js";

/**
 * Default path of the privileged daemon binary the unit launches. The drop-in
 * re-states the full `ExecStart` (systemd requires a blank reset line + the new
 * command), so we must know the binary path. Mirrors the base unit's
 * `ExecStart` (`castle-wall-daemon/systemd/sanctuary-castle-wall.service`).
 */
export const CASTLE_WALL_DAEMON_BINARY_DEFAULT =
  "/usr/local/libexec/sanctuary/castle-wall-daemon";

/** The systemd unit name the daemon ships as. */
export const CASTLE_WALL_SYSTEMD_UNIT = "sanctuary-castle-wall.service";

/**
 * Directory under which systemd reads drop-in overrides for the unit. A file
 * `NN-name.conf` here overrides directives in the base unit without editing it.
 */
export function castleWallDropInDir(
  unit: string = CASTLE_WALL_SYSTEMD_UNIT
): string {
  return `/etc/systemd/system/${unit}.d`;
}

/**
 * Render the systemd drop-in `.conf` that splices the producer-key launch args
 * into the daemon's `ExecStart`. systemd requires clearing the inherited
 * `ExecStart` with a blank assignment before re-stating the command, otherwise
 * the directive would be additive (two ExecStart lines = a startup error for
 * `Type=notify`).
 *
 * The spliced command keeps the base `--fortress-id` and appends the
 * `--policy-dir/--producer-key/--producer-pub-key` flags so the daemon's
 * published pub key lands at `resolveProducerPubKeyPath(fortressStoragePath)`.
 * `ReadWritePaths` is extended to the fortress `policy/egress` dir so the
 * hardened (`ProtectSystem=strict`) daemon may write the key files there.
 *
 * Exported pure so tests assert the rendered text WITHOUT touching the host.
 */
export function renderProducerKeyDropIn(input: {
  fortressId: string;
  fortressStoragePath: string;
  daemonBinary?: string;
}): string {
  const daemon = input.daemonBinary ?? CASTLE_WALL_DAEMON_BINARY_DEFAULT;
  const egressDir = join(input.fortressStoragePath, "policy", "egress");
  // producerKeyDaemonLaunchArgs derives every flag from the one storage root,
  // so the publish path is equal-by-construction to the TS read path.
  const keyArgs = producerKeyDaemonLaunchArgs(input.fortressStoragePath);
  const execLine = [
    daemon,
    "--fortress-id",
    shellQuote(input.fortressId),
    ...keyArgs.map(shellQuote),
  ].join(" ");
  return [
    "# Managed by Sanctuary — producer-signed audit activation (C4).",
    "# Splices the audit-producer key flags so the daemon publishes its",
    "# public key where the in-process Sanctuary server reads it. Regenerated",
    "# on each activation; do not edit by hand.",
    "[Service]",
    // Clear the inherited ExecStart, then re-state with the spliced flags.
    "ExecStart=",
    `ExecStart=${execLine}`,
    // The daemon (ProtectSystem=strict) must be able to write the key files
    // into the fortress egress dir.
    `ReadWritePaths=${egressDir}`,
    "",
  ].join("\n");
}

/**
 * Minimal `systemctl`-style command runner the launcher depends on. Injected in
 * tests so the unit orchestration is hermetic; in production it shells out to
 * `systemctl`. Returns the exit code + captured stderr for honest failure
 * surfacing.
 */
export interface SystemctlRunner {
  run(args: string[]): Promise<{ code: number; stdout: string; stderr: string }>;
}

/**
 * Filesystem ops the launcher needs, injectable for hermetic tests. Production
 * uses `node:fs/promises`.
 */
export interface LauncherFs {
  mkdir(path: string): Promise<void>;
  writeFile(path: string, contents: string, mode: number): Promise<void>;
  chmod(path: string, mode: number): Promise<void>;
}

const realFs: LauncherFs = {
  mkdir: async (path) => {
    await mkdir(path, { recursive: true });
  },
  writeFile: async (path, contents, mode) => {
    await writeFile(path, contents, { mode });
  },
  chmod: async (path, mode) => {
    await chmod(path, mode);
  },
};

/** Inputs to launch (or re-launch) the Linux daemon with producer-key flags. */
export interface LaunchLinuxDaemonInput {
  fortressId: string;
  fortressStoragePath: string;
  daemonBinary?: string;
  unit?: string;
  /** Drop-in directory override (tests). Defaults to the real systemd path. */
  dropInDir?: string;
  /** Drop-in filename. Defaults to `10-sanctuary-producer-key.conf`. */
  dropInFileName?: string;
  systemctl: SystemctlRunner;
  fs?: LauncherFs;
}

/** Result of a launch attempt. */
export interface LaunchLinuxDaemonResult {
  dropInPath: string;
  unit: string;
  active: boolean;
}

/**
 * P-1: render + install the producer-key drop-in, reload systemd, (re)start the
 * unit, and VERIFY it is active. FAIL-CLOSED: any systemctl failure or a unit
 * that is not active after start throws `RuntimeLinuxActivationError` — the
 * launcher never reports success it cannot prove.
 */
export async function launchLinuxCastleWallDaemon(
  input: LaunchLinuxDaemonInput
): Promise<LaunchLinuxDaemonResult> {
  const fs = input.fs ?? realFs;
  const unit = input.unit ?? CASTLE_WALL_SYSTEMD_UNIT;
  const dropInDir = input.dropInDir ?? castleWallDropInDir(unit);
  const dropInFileName =
    input.dropInFileName ?? "10-sanctuary-producer-key.conf";
  const dropInPath = join(dropInDir, dropInFileName);

  const contents = renderProducerKeyDropIn({
    fortressId: input.fortressId,
    fortressStoragePath: input.fortressStoragePath,
    daemonBinary: input.daemonBinary,
  });

  // Install the drop-in (root-owned, 0644 — the daemon's ExecStart override is
  // not a secret; the secret is the private key, which the daemon writes 0600).
  try {
    await fs.mkdir(dropInDir);
    await fs.writeFile(dropInPath, contents, 0o644);
    await fs.chmod(dropInPath, 0o644);
  } catch (err) {
    throw new RuntimeLinuxActivationError(
      `failed to install producer-key drop-in at ${dropInPath}: ${errMsg(err)}`,
      "daemon_start_failed"
    );
  }

  // Reload so systemd picks up the spliced ExecStart, then (re)start the unit.
  await runOrThrow(input.systemctl, ["daemon-reload"], "daemon_start_failed");
  await runOrThrow(
    input.systemctl,
    ["restart", unit],
    "daemon_start_failed"
  );

  // VERIFY active — the load-bearing honesty check. `is-active` exits 0 + prints
  // "active" only when the unit actually came up. Anything else = not armed.
  const active = await input.systemctl.run(["is-active", unit]);
  const isActive = active.code === 0 && active.stdout.trim() === "active";
  if (!isActive) {
    throw new RuntimeLinuxActivationError(
      `Castle Wall daemon unit ${unit} is not active after start ` +
        `(is-active exit=${active.code}, state="${active.stdout.trim()}"${
          active.stderr.trim() ? `, stderr="${active.stderr.trim()}"` : ""
        }).`,
      "daemon_not_active"
    );
  }

  return { dropInPath, unit, active: true };
}

/**
 * Production `SystemctlRunner` that shells out to `systemctl`. Imported lazily by
 * the activation gate so test/non-Linux code never loads `child_process` for it.
 */
export function realSystemctlRunner(
  systemctlBinary: string = "systemctl"
): SystemctlRunner {
  return {
    run: async (args) => {
      const { spawn } = await import("node:child_process");
      return await new Promise((resolve, reject) => {
        const child = spawn(systemctlBinary, args, {
          stdio: ["ignore", "pipe", "pipe"],
        });
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
        child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
        child.on("error", (err) => reject(err));
        child.on("close", (code) =>
          resolve({ code: code ?? -1, stdout, stderr })
        );
      });
    },
  };
}

/**
 * P-2 (transport half): a real Unix-domain-socket `IpcTransport` bound to the
 * Linux daemon socket. Mirrors the in-process mock transport's contract
 * (`send`/`onData`/`close`) but over `node:net`. Connection failure rejects the
 * returned promise so the activation path fails closed rather than hanging.
 */
export interface ConnectUdsTransportInput {
  socketPath: string;
  /** Connect timeout (ms). Default 5000. */
  connectTimeoutMs?: number;
}

export async function connectLinuxUdsTransport(
  input: ConnectUdsTransportInput
): Promise<IpcTransport> {
  const connectTimeoutMs = input.connectTimeoutMs ?? 5000;
  return await new Promise<IpcTransport>((resolve, reject) => {
    const socket = createConnection({ path: input.socketPath });
    let settled = false;
    const onConnectError = (err: Error): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(
        new RuntimeLinuxActivationError(
          `failed to connect to Castle Wall daemon socket at ${input.socketPath}: ${err.message}`,
          "daemon_not_active"
        )
      );
    };
    socket.once("error", onConnectError);
    socket.setTimeout(connectTimeoutMs, () =>
      onConnectError(new Error(`connect timed out after ${connectTimeoutMs}ms`))
    );
    socket.once("connect", () => {
      if (settled) return;
      settled = true;
      socket.setTimeout(0);
      socket.removeListener("error", onConnectError);
      resolve(adaptSocketToTransport(socket));
    });
  });
}

/** Wrap a connected `net.Socket` in the `IpcTransport` interface. */
function adaptSocketToTransport(socket: import("node:net").Socket): IpcTransport {
  const listeners = new Set<(bytes: Uint8Array) => void>();
  socket.on("data", (chunk: Buffer) => {
    const bytes = new Uint8Array(chunk);
    for (const l of listeners) l(bytes);
  });
  return {
    send: (bytes: Uint8Array) =>
      new Promise<void>((resolve, reject) => {
        socket.write(bytes, (err) => (err ? reject(err) : resolve()));
      }),
    onData: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    close: () =>
      new Promise<void>((resolve) => {
        listeners.clear();
        socket.end(() => {
          socket.destroy();
          resolve();
        });
      }),
  };
}

/**
 * Resolve the producer pub-key path for a fortress + assert the published key is
 * READABLE by this (unprivileged) process. The daemon writes it world-readable;
 * if it is missing or unreadable AFTER a successful daemon start, that is a
 * fail-closed condition (a key is EXPECTED — `startCastleWall` will throw
 * `unreadable`, which the caller surfaces as not-armed). This helper exists so a
 * launcher can give a precise diagnostic before the lifecycle's generic throw.
 */
export async function readPublishedProducerPubKey(
  fortressStoragePath: string
): Promise<Uint8Array> {
  const path = resolveProducerPubKeyPath(fortressStoragePath);
  return new Uint8Array(await readFile(path));
}

// ---------- helpers ----------

async function runOrThrow(
  systemctl: SystemctlRunner,
  args: string[],
  reason: RuntimeLinuxActivationError["reason"]
): Promise<void> {
  const result = await systemctl.run(args);
  if (result.code !== 0) {
    throw new RuntimeLinuxActivationError(
      `systemctl ${args.join(" ")} failed (exit=${result.code})${
        result.stderr.trim() ? `: ${result.stderr.trim()}` : ""
      }`,
      reason
    );
  }
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Quote a value for a systemd `ExecStart` token. systemd uses a restricted
 * shell-like quoting; double-quote and escape embedded quotes/backslashes. We
 * only ever pass our own derived paths + the fortress id, but quoting keeps a
 * path with a space (or a hostile fortress id) from splitting the command.
 */
function shellQuote(value: string): string {
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(value)) return value;
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

export { resolveCastleWallSocketPath };
