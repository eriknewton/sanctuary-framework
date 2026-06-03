import { execSync as nodeExecSync } from "node:child_process";
import { createConnection } from "node:net";
import { createHash, randomBytes as nodeRandomBytes } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { Writable } from "node:stream";
import { ed25519 } from "@noble/curves/ed25519";
import { deriveMasterKey, type KeyDerivationParams } from "../core/key-derivation.js";
import { bytesToString, fromBase64url, stringToBytes } from "../core/encoding.js";
import { encrypt } from "../core/encryption.js";
import { randomBytes } from "../core/random.js";
import { resolveStoragePath } from "../paths.js";
import { getOrCreatePassphrase } from "../wrap/passphrase.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { AuditLog, type AuditEntry } from "../l2-operational/audit-log.js";
import { frame, parseFrame } from "../castle-wall/ipc/framing.js";
import { resolveCastleWallSocketPath } from "../castle-wall/runtime/socket-path.js";
import { validateAgentOrigin } from "../castle-wall/allowlist/agent-origin.js";
import type {
  CastleWallMessage,
  DecisionResponse,
  PolicyReloadResponse,
} from "../castle-wall/ipc/messages.js";

const CASTLE_PINNED_PUBKEY = "castle-pinned-pubkey.bin";
const CASTLE_PINNED_PRIVKEY = "castle-pinned-privkey.enc";
const CASTLE_GLOBAL_PINNED_PUBKEY_DIR = "/Library/Application Support/Sanctuary";
const CASTLE_GLOBAL_PINNED_PUBKEY_PATH = `${CASTLE_GLOBAL_PINNED_PUBKEY_DIR}/${CASTLE_PINNED_PUBKEY}`;

export interface CastleWallCommandContext {
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  execSyncFn?: (command: string) => string;
  getuid?: () => number;
}

export interface CastleWallParsedArgs {
  fortress?: string;
  since?: string;
  scope?: "once" | "session" | "always";
  requestId?: string;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

function fingerprintFromPublicKey(publicKey: Uint8Array): string {
  return createHash("sha256")
    .update(publicKey)
    .digest("hex")
    .slice(0, 16);
}

function parseCastleWallState(raw: string): "[activated enabled]" | "[activated waiting for user]" | "not loaded" {
  if (raw.includes("[activated enabled]")) return "[activated enabled]";
  if (raw.includes("[activated waiting for user]")) {
    return "[activated waiting for user]";
  }
  return "not loaded";
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

async function resolveMasterKey(
  storagePath: string,
  env: NodeJS.ProcessEnv
): Promise<Uint8Array> {
  if (env.SANCTUARY_RECOVERY_KEY) {
    const key = fromBase64url(env.SANCTUARY_RECOVERY_KEY);
    if (key.length !== 32) {
      throw new Error("SANCTUARY_RECOVERY_KEY must decode to 32 bytes.");
    }
    return key;
  }

  const storage = new FilesystemStorage(join(storagePath, "state"));
  const passphrase =
    env.SANCTUARY_PASSPHRASE ??
    (await getOrCreatePassphrase({ storagePath })).value;

  let existingParams: KeyDerivationParams | undefined;
  try {
    const raw = await storage.read("_meta", "key-params");
    if (raw) existingParams = JSON.parse(bytesToString(raw));
  } catch {
    // first run
  }

  const { key: masterKey, params } = await deriveMasterKey(
    passphrase,
    existingParams
  );
  if (!existingParams) {
    await storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params))
    );
  }
  return masterKey;
}

export async function runProvisionPin(
  ctx: CastleWallCommandContext = {}
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const storagePath = resolveStoragePath(env);
  const pubPath = join(storagePath, CASTLE_PINNED_PUBKEY);
  const privPath = join(storagePath, CASTLE_PINNED_PRIVKEY);

  try {
    await mkdir(storagePath, { recursive: true, mode: 0o700 });

    try {
      const existingPub = await readFile(pubPath);
      if (existingPub.length !== 32) {
        throw new Error(
          `Pinned public key at ${pubPath} must be 32 bytes (found ${existingPub.length}).`
        );
      }
      await writeGlobalPinnedPublicKey(existingPub);
      const fingerprint = fingerprintFromPublicKey(existingPub);
      write(out, `${fingerprint}\n`);
      write(
        out,
        "Pinned key already provisioned; leaving existing key in place.\n"
      );
      return 0;
    } catch (readError) {
      if (
        !(readError instanceof Error) ||
        !("code" in readError) ||
        (readError as NodeJS.ErrnoException).code !== "ENOENT"
      ) {
        throw readError;
      }
    }

    const masterKey = await resolveMasterKey(storagePath, env);
    const privateSeed = randomBytes(32);
    const publicKey = ed25519.getPublicKey(privateSeed);
    const encryptedPrivateKey = encrypt(privateSeed, masterKey);
    const fingerprint = fingerprintFromPublicKey(publicKey);

    await writeFile(pubPath, publicKey, { mode: 0o600 });
    await chmod(pubPath, 0o600);
    await writeGlobalPinnedPublicKey(publicKey);
    await writeFile(privPath, JSON.stringify(encryptedPrivateKey), {
      mode: 0o600,
    });
    await chmod(privPath, 0o600);

    privateSeed.fill(0);
    masterKey.fill(0);

    write(out, `${fingerprint}\n`);
    return 0;
  } catch (error) {
    write(
      err,
      `Error: ${
        error instanceof Error ? error.message : String(error)
      }\n`
    );
    return 1;
  }
}

async function writeGlobalPinnedPublicKey(
  publicKey: Uint8Array,
): Promise<void> {
  try {
    await mkdir(CASTLE_GLOBAL_PINNED_PUBKEY_DIR, { recursive: true, mode: 0o755 });
    await writeFile(CASTLE_GLOBAL_PINNED_PUBKEY_PATH, publicKey, { mode: 0o644 });
    await chmod(CASTLE_GLOBAL_PINNED_PUBKEY_PATH, 0o644);
  } catch (error) {
    // SAFETY: provision-pin warnings are operator-facing CLI stderr output.
    console.warn(
      `[castle-wall] warning: unable to write shared pinned key at ${CASTLE_GLOBAL_PINNED_PUBKEY_PATH}: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

export async function runStatus(
  ctx: CastleWallCommandContext = {}
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;
  const execSyncFn =
    ctx.execSyncFn ??
    ((command: string) =>
      nodeExecSync(`sh -lc '${command.replace(/'/g, "'\\''")}'`, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim());
  const storagePath = resolveStoragePath(env);
  const pubPath = join(storagePath, CASTLE_PINNED_PUBKEY);

  try {
    const publicKey = await readFile(pubPath);
    if (publicKey.length !== 32) {
      throw new Error(
        `Pinned public key at ${pubPath} must be 32 bytes (found ${publicKey.length}).`
      );
    }
    write(out, `Pinned key fingerprint: ${fingerprintFromPublicKey(publicKey)}\n`);
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error as NodeJS.ErrnoException).code === "ENOENT"
    ) {
      write(
        out,
        "No pinned key provisioned. Run: sanctuary castle-wall provision-pin\n"
      );
    } else {
      throw error;
    }
  }

  if (platform !== "darwin") {
    write(out, "Castle Wall sysext: not applicable (non-macOS)\n");
    return 0;
  }

  let sysextState: "[activated enabled]" | "[activated waiting for user]" | "not loaded" = "not loaded";
  try {
    const raw = execSyncFn(
      "systemextensionsctl list 2>/dev/null | grep castle-wall"
    );
    sysextState = parseCastleWallState(raw);
  } catch {
    sysextState = "not loaded";
  }

  write(out, `Castle Wall sysext: ${sysextState}\n`);
  return 0;
}

export async function runSetupSharedDir(
  ctx: CastleWallCommandContext = {}
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;
  const getuid = ctx.getuid ?? process.getuid?.bind(process);
  const execSyncFn =
    ctx.execSyncFn ??
    ((command: string) =>
      nodeExecSync(`sh -lc '${command.replace(/'/g, "'\\''")}'`, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim());

  if (platform !== "darwin") {
    write(out, "Castle Wall shared dir: not applicable (non-macOS)\n");
    return 0;
  }

  if (getuid?.() !== 0) {
    write(
      err,
      "setup-shared-dir must run as root. Re-run: sudo sanctuary castle-wall setup-shared-dir\n",
    );
    return 1;
  }

  const sudoUser = env.SUDO_USER;
  if (!sudoUser) {
    write(
      err,
      "Cannot determine the operator account (SUDO_USER unset). Run via sudo, not as a raw root shell.\n",
    );
    return 1;
  }

  if (!/^[a-zA-Z0-9._-]+$/.test(sudoUser)) {
    write(
      err,
      "Invalid SUDO_USER value; refusing to build a shell command from it.\n",
    );
    return 1;
  }

  try {
    const dir = shellQuote(CASTLE_GLOBAL_PINNED_PUBKEY_DIR);
    execSyncFn(`mkdir -p ${dir}`);
    execSyncFn(`chown ${shellQuote(`${sudoUser}:admin`)} ${dir}`);
    execSyncFn(`chmod 0755 ${dir}`);
  } catch (error) {
    write(err, `${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }

  write(out, `${CASTLE_GLOBAL_PINNED_PUBKEY_DIR}\n`);
  write(
    out,
    "Shared dir ready. Re-run 'sanctuary castle-wall provision-pin' (or restart the daemon) to populate the pinned key; no per-fortress sudo cp needed.\n",
  );
  return 0;
}

export async function runReload(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {}
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const parsed = parseCastleWallArgs(argv);
  const fortressPath = resolveFortressArg(parsed.fortress, env);
  const socketPath = resolveCastleWallSocketPath({
    platform: ctx.platform ?? process.platform,
    fortressPath,
  }).path;

  try {
    const reply = await sendCastleWallMessage<PolicyReloadResponse>(
      socketPath,
      {
        type: "policy_reload_request",
        request_id: nodeRandomBytes(16).toString("hex"),
        manifest_path: join(fortressPath, "policy", "egress", "manifest.json"),
      },
      "policy_reload_response",
    );
    if (!reply.ok) {
      write(err, `Error: ${reply.error ?? "policy reload failed"}\n`);
      return 1;
    }
    write(out, `Castle Wall policy reloaded (${reply.loaded_rule_count} rules).\n`);
    return 0;
  } catch (error) {
    if (isSocketUnavailable(error)) {
      write(
        out,
        `No Castle Wall daemon running for fortress ${fortressIdLabel(fortressPath)}. Run 'sanctuary wrap' to start one.\n`,
      );
      return 0;
    }
    write(err, `Error: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

export async function runApprove(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {}
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const parsed = parseCastleWallArgs(argv);
  const requestId = parsed.requestId;
  if (!requestId) {
    write(err, "Error: castle-wall approve requires <request_id>\n");
    return 2;
  }
  const fortressPath = resolveFortressArg(parsed.fortress, env);
  const socketPath = resolveCastleWallSocketPath({
    platform: ctx.platform ?? process.platform,
    fortressPath,
  }).path;
  const scope = parsed.scope ?? "once";
  const message: DecisionResponse = {
    type: "decision_response",
    request_id: requestId,
    decision:
      scope === "always"
        ? "allow_always"
        : "allow_once",
    ...(scope === "session"
      ? { learn: { granularity: "per_template_domain" as const } }
      : {}),
  };

  try {
    const reply = await sendCastleWallMessage<CastleWallMessage>(
      socketPath,
      message,
      "decision_response_ack",
    );
    if ("ok" in reply && reply.ok === true) {
      write(out, `Castle Wall request ${requestId} approved (${scope}).\n`);
      return 0;
    }
    write(err, `Error: no pending request matches ${requestId}\n`);
    return 1;
  } catch (error) {
    write(err, `Error: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

export async function runAuditDump(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {}
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const parsed = parseCastleWallArgs(argv);
  const fortressPath = resolveFortressArg(parsed.fortress, env);
  const sinceIso = parsed.since
    ? new Date(Date.now() - parseDurationMs(parsed.since)).toISOString()
    : undefined;

  try {
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const masterKey = await resolveMasterKey(fortressPath, env);
    const auditLog = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
    const query = await auditLog.query({
      ...(sinceIso ? { since: sinceIso } : {}),
      layer: "l1",
      limit: 100_000,
    });
    for (const entry of query.entries.filter(isCastleWallAuditEntry)) {
      write(out, JSON.stringify(entry) + "\n");
    }
    return 0;
  } catch (error) {
    write(err, `Error: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

export async function runConfigureOrigin(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {}
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const parsed = parseCastleWallArgs(argv);
  const fortressPath = resolveFortressArg(parsed.fortress, env);
  const originPath = join(fortressPath, "policy", "egress", "agent-origin.json");

  // Parse remaining positional args: configure-origin <mode> [options]
  // Usage:
  //   castle-wall configure-origin uid --agent-uid=502 [--ceiling=500]
  //   castle-wall configure-origin nat --signing-id=ai.sanctuaryprotocol.egress-helper [--team-id=YFQSWQ9BJN] [--ceiling=500]
  const modeArg = argv.find((a) => a === "uid" || a === "nat");
  if (!modeArg) {
    write(err, "Usage: castle-wall configure-origin <uid|nat> [options]\n");
    write(err, "  uid mode: --agent-uid=<uid> [--ceiling=<uid>]\n");
    write(err, "  nat mode: --signing-id=<id> [--team-id=<id>] [--ceiling=<uid>]\n");
    return 2;
  }

  const getFlag = (name: string): string | undefined => {
    const prefix = `--${name}=`;
    const match = argv.find((a) => a.startsWith(prefix));
    return match ? match.slice(prefix.length) : undefined;
  };

  const candidate: Record<string, unknown> = {
    mode: modeArg,
    system_uid_allow_ceiling: parseInt(getFlag("ceiling") ?? "500", 10),
  };

  if (modeArg === "uid") {
    const uidStr = getFlag("agent-uid");
    if (!uidStr) {
      write(err, "Error: uid mode requires --agent-uid=<uid>\n");
      return 2;
    }
    candidate.agent_uid = parseInt(uidStr, 10);
  } else {
    const signingId = getFlag("signing-id");
    const teamId = getFlag("team-id");
    if (!signingId && !teamId) {
      write(err, "Error: nat mode requires --signing-id=<id> and/or --team-id=<id>\n");
      return 2;
    }
    if (signingId) candidate.egress_helper_signing_id = signingId;
    if (teamId) candidate.egress_helper_team_id = teamId;
    const portRange = getFlag("port-range");
    if (portRange) {
      const parts = portRange.split("-").map(Number);
      if (parts.length === 2) candidate.agent_runtime_port_range = parts;
    }
  }

  const validated = validateAgentOrigin(candidate);
  if (validated === null) {
    write(err, "Error: agent-origin descriptor is structurally invalid.\n");
    return 1;
  }

  try {
    await mkdir(join(fortressPath, "policy", "egress"), {
      recursive: true,
      mode: 0o700,
    });
    await writeFile(originPath, JSON.stringify(validated, null, 2) + "\n", {
      mode: 0o600,
    });
    write(out, `Agent origin configured: mode=${validated.mode}\n`);
    write(out, `Written to: ${originPath}\n`);
    write(out, "Run 'sanctuary castle-wall reload' to apply.\n");
    return 0;
  } catch (error) {
    write(err, `Error: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

export function parseCastleWallArgs(argv: string[]): CastleWallParsedArgs {
  const parsed: CastleWallParsedArgs = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--fortress") {
      parsed.fortress = argv[++i];
    } else if (arg === "--since") {
      parsed.since = argv[++i];
    } else if (arg.startsWith("--scope=")) {
      parsed.scope = parseScope(arg.slice("--scope=".length));
    } else if (arg === "--scope") {
      parsed.scope = parseScope(argv[++i]);
    } else if (!arg.startsWith("-") && !parsed.requestId) {
      parsed.requestId = arg;
    }
  }
  return parsed;
}

function parseScope(value: string | undefined): "once" | "session" | "always" {
  if (value === "session" || value === "always" || value === "once") return value;
  throw new Error("--scope must be once, session, or always");
}

function resolveFortressArg(
  fortress: string | undefined,
  env: NodeJS.ProcessEnv,
): string {
  if (!fortress) return resolveStoragePath(env);
  return isAbsolute(fortress) ? fortress : resolve(process.cwd(), fortress);
}

function fortressIdLabel(fortressPath: string): string {
  return fortressPath;
}

function parseDurationMs(value: string): number {
  const match = /^(\d+)([mhd])$/.exec(value);
  if (!match) throw new Error("--since must use forms like 5m, 1h, or 2d");
  const amount = Number(match[1]);
  const unit = match[2];
  const multiplier = unit === "m" ? 60_000 : unit === "h" ? 3_600_000 : 86_400_000;
  return amount * multiplier;
}

function isCastleWallAuditEntry(entry: AuditEntry): boolean {
  return CASTLE_WALL_AUDIT_OPERATIONS.has(entry.operation);
}

const CASTLE_WALL_AUDIT_OPERATIONS = new Set([
  "egress_allowed",
  "egress_blocked",
  "operator_decision",
  "policy_loaded",
  "policy_validation_failed",
  "filter_started",
  "filter_stopped",
  "filter_crashed",
  "queue_saturated",
  "no_wall_engaged",
  "no_wall_expired",
  "wal_overflow",
  "external_firewall_clobber",
  "flow_decision_rejected",
  "flow_pending_approval_rejected",
]);

async function sendCastleWallMessage<T extends CastleWallMessage>(
  socketPath: string,
  message: CastleWallMessage,
  expectedType: T["type"],
): Promise<T> {
  return await new Promise<T>((resolvePromise, reject) => {
    const socket = createConnection(socketPath);
    let inbound = new Uint8Array(0);
    let settled = false;
    const timer = setTimeout(() => {
      finish(new Error("Castle Wall IPC request timed out"));
    }, 5_000);
    const finish = (result: T | Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (result instanceof Error) reject(result);
      else resolvePromise(result);
    };
    socket.on("connect", () => {
      socket.write(frame(JSON.stringify({
        jsonrpc: "2.0",
        method: `castle-wall.${message.type}`,
        params: message,
      })));
    });
    socket.on("data", (chunk: Buffer) => {
      const merged = new Uint8Array(inbound.length + chunk.length);
      merged.set(inbound, 0);
      merged.set(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.length), inbound.length);
      inbound = merged;
      while (inbound.length > 0) {
        const parsed = parseFrame(inbound);
        if (parsed.kind === "need_more") break;
        if (parsed.kind === "error") {
          finish(new Error(`Castle Wall IPC framing error: ${parsed.reason}`));
          return;
        }
        inbound = inbound.slice(parsed.consumedBytes);
        try {
          const envelope = JSON.parse(parsed.body) as { params?: CastleWallMessage };
          if (envelope.params?.type === expectedType) {
            finish(envelope.params as T);
            return;
          }
        } catch {
          // Ignore malformed frames from non-admin peers until timeout.
        }
      }
    });
    socket.on("error", finish);
  });
}

function isSocketUnavailable(error: unknown): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    ((error as NodeJS.ErrnoException).code === "ENOENT" ||
      (error as NodeJS.ErrnoException).code === "ECONNREFUSED")
  );
}
