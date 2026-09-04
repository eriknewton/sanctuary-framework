/**
 * Linux Castle Wall daemon launcher + producer-signed activation path (Slice
 * "PR 2b" + C4 tamper-proof half).
 *
 * The Linux enforcing daemon is a pre-provisioned root systemd service. Runtime
 * activation never writes `/etc`, rewrites ExecStart, or restarts the service:
 * doing so from a user-owned Node process would collapse the privilege boundary.
 * A privileged installer owns unit/environment/key placement; this module only
 * verifies the service and attaches through authenticated IPC.
 *
 * # Security posture
 *
 * - The daemon's PRIVATE producer key stays root-owned below
 *   `/var/lib/sanctuary/<fortress-id>/policy/egress`. On each boot it republishes
 *   only the public half at
 *   `/run/sanctuary/<fortress-id>/audit-producer.pub`, where the dedicated
 *   non-root broker can traverse and read it. The TS server never receives the
 *   private seed.
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
 * This wires the producer-signed channel and authenticated byte-only policy
 * broker behind an opt-in gate. It still does not make a Linux capability
 * claim: that remains unavailable until a CAPTURED DRILL on real Linux hardware
 * passes.
 */

import { createConnection } from "node:net";
import { readFile } from "node:fs/promises";
import { join, isAbsolute, normalize } from "node:path";

import { resolveCastleWallSocketPath } from "./socket-path.js";
import {
  producerKeyDaemonLaunchArgs,
  resolveProducerPubKeyPath,
} from "./producer-signature.js";
import { RuntimeLinuxActivationError } from "./errors.js";
import type { IpcTransport } from "./ipc-client.js";

/**
 * Default path of the privileged daemon binary installed by the root-owned
 * provisioning flow. Runtime activation never rewrites this value.
 */
export const CASTLE_WALL_DAEMON_BINARY_DEFAULT =
  "/usr/local/libexec/sanctuary/castle-wall-daemon";

/** The systemd unit name the daemon ships as. */
export const CASTLE_WALL_SYSTEMD_UNIT = "sanctuary-castle-wall.service";

/**
 * Legacy pure installer helper. Runtime activation never writes this directory;
 * the privileged offline installer owns the fixed unit and environment.
 */
export function castleWallDropInDir(
  unit: string = CASTLE_WALL_SYSTEMD_UNIT
): string {
  return `/etc/systemd/system/${unit}.d`;
}

/**
 * Legacy pure installer renderer for pre-server-profile fixtures. It is not a
 * runtime activation primitive and must not be used for the hardened server
 * profile, whose fixed root unit uses `/var/lib` private state and `/run` public
 * state. Render the historical systemd drop-in `.conf` that splices the producer-key launch args
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
/** @deprecated Use the shipped root-owned unit and deployment procedure. */
export function renderProducerKeyDropIn(input: {
  fortressId: string;
  fortressStoragePath: string;
  daemonBinary?: string;
}): string {
  // FIX 5 (codex MEDIUM - systemd unit injection). Validate the operator-derived
  // inputs BEFORE splicing them into the unit. A newline or control char in the
  // storage path or fortress id could otherwise smuggle a second directive (e.g.
  // an extra `ExecStart=` or a `User=root`) into the rendered drop-in. We reject
  // control chars outright, require the storage path to be absolute + normalized,
  // and quote/escape EVERY token we emit (daemon path, key flags, fortress id,
  // ReadWritePaths) so even a value with whitespace stays a single token.
  const fortressStoragePath = assertSafeAbsolutePath(
    input.fortressStoragePath,
    "fortress storage path"
  );
  const fortressId = assertSafeSystemdToken(input.fortressId, "fortress id");
  const daemon = assertSafeAbsolutePath(
    input.daemonBinary ?? CASTLE_WALL_DAEMON_BINARY_DEFAULT,
    "daemon binary path"
  );
  const egressDir = join(fortressStoragePath, "policy", "egress");
  // producerKeyDaemonLaunchArgs derives every flag from the one storage root,
  // so the publish path is equal-by-construction to the TS read path.
  const keyArgs = producerKeyDaemonLaunchArgs(fortressStoragePath);
  const execLine = [
    shellQuote(daemon),
    "--fortress-id",
    shellQuote(fortressId),
    ...keyArgs.map(shellQuote),
  ].join(" ");
  return [
    "# Managed by Sanctuary - producer-signed audit activation (C4).",
    "# Splices the audit-producer key flags so the daemon publishes its",
    "# public key where the in-process Sanctuary server reads it. Regenerated",
    "# on each activation; do not edit by hand.",
    "[Service]",
    // Clear the inherited ExecStart, then re-state with the spliced flags.
    "ExecStart=",
    `ExecStart=${execLine}`,
    // The daemon (ProtectSystem=strict) must be able to write the key files
    // into the fortress egress dir. Quoted so a path with whitespace stays one
    // token (systemd accepts a quoted ReadWritePaths value).
    `ReadWritePaths=${shellQuote(egressDir)}`,
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

/** Inputs to attach to the pre-provisioned Linux daemon. */
export interface LaunchLinuxDaemonInput {
  fortressId: string;
  fortressStoragePath: string;
  systemctl: SystemctlRunner;
}

/** Result of a launch attempt. */
export interface LaunchLinuxDaemonResult {
  unit: string;
  active: boolean;
}

/**
 * Verify the fixed, pre-provisioned root service is active. This runtime path
 * has deliberately no unit-name, binary-path, drop-in, or filesystem mutation
 * parameters: those belong to the privileged installer, not to a user process.
 */
export async function launchLinuxCastleWallDaemon(
  input: LaunchLinuxDaemonInput
): Promise<LaunchLinuxDaemonResult> {
  const unit = CASTLE_WALL_SYSTEMD_UNIT;
  // Verify the already-provisioned service without mutating host state.
  const active = await input.systemctl.run(["is-active", unit]);
  const isActive = active.code === 0 && active.stdout.trim() === "active";
  if (!isActive) {
    throw new RuntimeLinuxActivationError(
      `Castle Wall daemon unit ${unit} is not active (runtime activation is attach-only) ` +
        `(is-active exit=${active.code}, state="${active.stdout.trim()}"${
          active.stderr.trim() ? `, stderr="${active.stderr.trim()}"` : ""
        }).`,
      "daemon_not_active"
    );
  }

  return { unit, active: true };
}

/**
 * Production `SystemctlRunner` that shells out to `systemctl`. Imported lazily by
 * the activation gate so test/non-Linux code never loads `child_process` for it.
 */
export function realSystemctlRunner(
  systemctlBinary: string = "systemctl"
): SystemctlRunner {
  const timeoutMs = 5_000;
  return {
    run: async (args) => {
      const { spawn } = await import("node:child_process");
      return await new Promise((resolve, reject) => {
        const child = spawn(systemctlBinary, args, {
          stdio: ["ignore", "pipe", "pipe"],
        });
        let stdout = "";
        let stderr = "";
        let settled = false;
        const finish = (result: { code: number; stdout: string; stderr: string }): void => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          resolve(result);
        };
        const timer = setTimeout(() => {
          child.kill("SIGKILL");
          finish({
            code: -1,
            stdout,
            stderr: `${stderr}${stderr ? "; " : ""}systemctl timed out after ${timeoutMs}ms`,
          });
        }, timeoutMs);
        child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
        child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
        child.on("error", (err) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          reject(err);
        });
        child.on("close", (code) =>
          finish({ code: code ?? -1, stdout, stderr })
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
  const closeListeners = new Set<(reason: Error) => void>();
  let terminalReason: Error | null = null;
  let terminalDelivered = false;
  const deliverTerminal = (reason: Error): void => {
    if (terminalDelivered) return;
    terminalDelivered = true;
    terminalReason = reason;
    for (const listener of closeListeners) listener(reason);
  };
  socket.on("data", (chunk: Buffer) => {
    const bytes = new Uint8Array(chunk);
    for (const l of listeners) l(bytes);
  });
  // Keep an error listener for the entire connected lifetime. Removing the
  // connect-phase listener without replacing it makes a later ECONNRESET an
  // uncaught EventEmitter `error` that can terminate Sanctuary main.
  socket.on("error", (err) => deliverTerminal(err));
  socket.on("close", (hadError) =>
    deliverTerminal(
      terminalReason ??
        new Error(
          hadError
            ? "Castle Wall daemon socket closed after a transport error"
            : "Castle Wall daemon socket closed"
        )
    )
  );
  return {
    send: (bytes: Uint8Array) =>
      new Promise<void>((resolve, reject) => {
        socket.write(bytes, (err) => (err ? reject(err) : resolve()));
      }),
    onData: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    onClose: (listener) => {
      if (terminalDelivered && terminalReason) {
        queueMicrotask(() => listener(terminalReason!));
        return () => {};
      }
      closeListeners.add(listener);
      return () => closeListeners.delete(listener);
    },
    close: () =>
      new Promise<void>((resolve) => {
        listeners.clear();
        closeListeners.clear();
        socket.end(() => {
          socket.destroy();
          resolve();
        });
      }),
  };
}

/**
 * Resolve the legacy/test fortress-relative producer pub-key path + assert it is
 * READABLE by this (unprivileged) process. The daemon writes it world-readable;
 * if it is missing or unreadable AFTER a successful daemon start, that is a
 * fail-closed condition (a key is EXPECTED - `startCastleWall` will throw
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

/**
 * Quote a value for a systemd `ExecStart` token. systemd uses a restricted
 * shell-like quoting; double-quote and escape embedded quotes/backslashes. We
 * only ever pass our own derived paths + the fortress id, but quoting keeps a
 * path with a space (or a hostile fortress id) from splitting the command.
 *
 * Callers MUST validate for control characters first (see `assertNoControlChars`
 * / `assertSafe*`): quoting alone does not neutralize a newline, which systemd
 * treats as a directive separator regardless of surrounding quotes.
 */
function shellQuote(value: string): string {
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(value)) return value;
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/**
 * Reject any value containing an ASCII control character (incl. newline, CR,
 * tab, NUL). FIX 5: a newline is the injection primitive for a systemd drop-in -
 * it ends the current directive and starts a new one, which quoting does NOT
 * prevent. We refuse rather than try to escape, so a hostile path/id can never
 * smuggle an extra `[Service]` directive.
 */
function assertNoControlChars(value: string, label: string): void {
  // Explicit code-point scan (no literal control bytes in source). C0 controls
  // 0x00-0x1F (includes \t \n \r \0) and DEL 0x7F are the systemd-drop-in
  // injection primitives; reject rather than try to escape.
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) {
      throw new RuntimeLinuxActivationError(
        `Castle Wall Linux activation: ${label} contains a control character (code 0x${code
          .toString(16)
          .padStart(2, "0")}); refusing to render a systemd drop-in (injection guard).`,
        "daemon_start_failed"
      );
    }
  }
}

/**
 * Validate a value that becomes a single systemd token (e.g. the fortress id):
 * no control chars, non-empty. Returned verbatim for the caller to `shellQuote`.
 */
function assertSafeSystemdToken(value: string, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new RuntimeLinuxActivationError(
      `Castle Wall Linux activation: ${label} must be a non-empty string.`,
      "daemon_start_failed"
    );
  }
  assertNoControlChars(value, label);
  return value;
}

/**
 * Validate a filesystem path spliced into the unit: non-empty, no control
 * chars, ABSOLUTE, and normalized (no `..` traversal segments). Returns the
 * normalized path. FIX 5: requiring absolute + normalized removes the
 * relative-path / traversal ambiguity from `ReadWritePaths` and `ExecStart`.
 */
function assertSafeAbsolutePath(value: string, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new RuntimeLinuxActivationError(
      `Castle Wall Linux activation: ${label} must be a non-empty path.`,
      "daemon_start_failed"
    );
  }
  assertNoControlChars(value, label);
  if (!isAbsolute(value)) {
    throw new RuntimeLinuxActivationError(
      `Castle Wall Linux activation: ${label} must be an absolute path (got "${value}").`,
      "daemon_start_failed"
    );
  }
  // Check the RAW value for `..` traversal segments BEFORE normalize() collapses
  // them away - the concern is a traversal in the operator-supplied input, not in
  // the resolved result.
  if (value.split("/").includes("..")) {
    throw new RuntimeLinuxActivationError(
      `Castle Wall Linux activation: ${label} must not contain ".." traversal segments (got "${value}").`,
      "daemon_start_failed"
    );
  }
  // Refuse a non-canonical path (normalize would change it): keeps the value the
  // daemon receives equal to the value we validated.
  const normalized = normalize(value);
  if (normalized !== value) {
    throw new RuntimeLinuxActivationError(
      `Castle Wall Linux activation: ${label} must be a normalized absolute path (got "${value}", normalizes to "${normalized}").`,
      "daemon_start_failed"
    );
  }
  return normalized;
}

export { resolveCastleWallSocketPath };
