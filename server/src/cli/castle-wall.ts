import { execSync as nodeExecSync } from "node:child_process";
import { createConnection } from "node:net";
import { createHash, randomBytes as nodeRandomBytes } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { Writable } from "node:stream";
import { ed25519 } from "@noble/curves/ed25519";
import { deriveMasterKey, type KeyDerivationParams } from "../core/key-derivation.js";
import { bytesToString, fromBase64url, stringToBytes, toBase64url } from "../core/encoding.js";
import { encrypt, type EncryptedPayload } from "../core/encryption.js";
import { sign as identitySign, type RotationEvent } from "../core/identity.js";
import { randomBytes } from "../core/random.js";
import {
  HelperSignerClient,
  type ShimInvoker,
} from "../castle-wall/runtime/helper-signer.js";
import { resolveStoragePath } from "../paths.js";
import { getOrCreatePassphrase } from "../wrap/passphrase.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { AuditLog, type AuditEntry } from "../l2-operational/audit-log.js";
import { frame, parseFrame } from "../castle-wall/ipc/framing.js";
import { resolveCastleWallSocketPath } from "../castle-wall/runtime/socket-path.js";
import { validateAgentOrigin } from "../castle-wall/allowlist/agent-origin.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
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
  /** Path to the signer-client shim (re-pin). Defaults to env. */
  signerClientPath?: string;
  /** Override the shim runner (tests drive re-pin without a real helper). */
  signerClientInvoke?: ShimInvoker;
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
    const code =
      error instanceof Error && "code" in error
        ? (error as NodeJS.ErrnoException).code
        : undefined;
    // SAFETY: provision-pin diagnostics are operator-facing CLI stderr output.
    // Under A2 the global pin is root:wheel 0644 and owned by the signer helper;
    // an operator-UID provision-pin CANNOT (and must not) overwrite it. Make
    // that explicit and actionable rather than a vague warn — the trust anchor
    // is migrated via `castle-wall re-pin`, not provision-pin.
    if (code === "EACCES" || code === "EPERM") {
      console.warn(
        `[castle-wall] global pin ${CASTLE_GLOBAL_PINNED_PUBKEY_PATH} is root-owned (A2); provision-pin does not write it. Run 'sanctuary castle-wall re-pin' to migrate the trust anchor to the signer helper.`,
      );
      return;
    }
    console.warn(
      `[castle-wall] warning: unable to write shared pinned key at ${CASTLE_GLOBAL_PINNED_PUBKEY_PATH}: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

/**
 * Build the audit-continuity rotation proof binding the OLD pin key to the new
 * helper key (§4.5 step 4). The OLD key signs the binding, proving the holder of
 * the retiring key authorized the migration. Reuses the `RotationEvent` shape
 * from core/identity.ts (already "signature over the event by the OLD key").
 */
export function buildPinRotationProof(opts: {
  oldPublicKey: Uint8Array;
  oldEncryptedPrivateKey: EncryptedPayload;
  encryptionKey: Uint8Array;
  newPublicKey: Uint8Array;
  rotatedAt: string;
}): RotationEvent {
  const oldB64 = toBase64url(opts.oldPublicKey);
  const newB64 = toBase64url(opts.newPublicKey);
  const identityId = `castle-wall:${oldB64}`;
  const reason = "castle-wall-pin-rotation-a2-b2";
  // Match identity.ts rotateKeys: sign the JSON of the 5 fields (no signature).
  const eventData = JSON.stringify({
    old_public_key: oldB64,
    new_public_key: newB64,
    identity_id: identityId,
    reason,
    rotated_at: opts.rotatedAt,
  });
  const signature = identitySign(
    stringToBytes(eventData),
    opts.oldEncryptedPrivateKey,
    opts.encryptionKey,
  );
  return {
    old_public_key: oldB64,
    new_public_key: newB64,
    identity_id: identityId,
    reason,
    rotated_at: opts.rotatedAt,
    signature: toBase64url(signature),
  };
}

/**
 * One-time, operator-approved trust-anchor migration (A2/B2 re-pin). Tells the
 * root signer helper to (re)write the global pin with ITS key (K_helper), then
 * records a rotation proof signed by the retiring passphrase-derived key
 * (K_old). Idempotent: when the global pin already holds K_helper, this
 * re-asserts state rather than rotating again.
 *
 * This is a Tier-1-class irreversible op (hard constraint #3): it runs only when
 * the operator is present and has just approved the helper — never silently,
 * never agent-triggerable.
 */
export async function runRePin(
  ctx: CastleWallCommandContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;

  if (platform !== "darwin") {
    write(err, "castle-wall re-pin is macOS-only.\n");
    return 1;
  }

  const storagePath = resolveStoragePath(env);
  const clientBinaryPath = ctx.signerClientPath ?? env.SANCTUARY_CASTLE_SIGNER_CLIENT;
  if (!clientBinaryPath && !ctx.signerClientInvoke) {
    write(
      err,
      "Cannot re-pin: signer-client shim path unknown. Set SANCTUARY_CASTLE_SIGNER_CLIENT or install the Castle Wall app (which bundles it).\n",
    );
    return 1;
  }

  const client = new HelperSignerClient({
    clientBinaryPath: clientBinaryPath ?? "castle-wall-signer-client",
    ...(ctx.signerClientInvoke ? { invoke: ctx.signerClientInvoke } : {}),
  });

  try {
    // Ask the helper to (re)write the root-owned pin with K_helper and return it.
    const helperPub = await client.installPin();
    if (helperPub.length !== 32) {
      write(err, `Helper returned a ${helperPub.length}-byte key (expected 32).\n`);
      return 1;
    }
    const helperFingerprint = fingerprintFromPublicKey(helperPub);

    // Read the retiring K_old (the passphrase-derived key provision-pin minted).
    // Its presence lets us emit the old-signs-new rotation proof for audit
    // continuity. If it is already gone (a prior re-pin retired it), treat this
    // as an idempotent re-assert.
    const pubPath = join(storagePath, CASTLE_PINNED_PUBKEY);
    const privPath = join(storagePath, CASTLE_PINNED_PRIVKEY);
    let oldPub: Uint8Array | null = null;
    let oldEnc: EncryptedPayload | null = null;
    try {
      oldPub = await readFile(pubPath);
      oldEnc = JSON.parse(await readFile(privPath, "utf8")) as EncryptedPayload;
    } catch {
      oldPub = null;
      oldEnc = null;
    }

    const storage = new FilesystemStorage(join(storagePath, "state"));
    const masterKey = await resolveMasterKey(storagePath, env);
    const auditLog = new AuditLog(storage, masterKey);

    if (oldPub && oldPub.length === 32 && oldEnc) {
      const oldFingerprint = fingerprintFromPublicKey(oldPub);
      if (oldFingerprint === helperFingerprint) {
        // Already migrated (K_old already equals K_helper would be unusual, but
        // re-running after a prior re-pin where the helper key is now the pin is
        // the idempotent case handled below). Treat equal fingerprints as a
        // no-op re-assert.
        write(out, `${helperFingerprint}\n`);
        write(out, "Pin already holds the helper key; re-asserted (no rotation).\n");
        return 0;
      }
      const proof = buildPinRotationProof({
        oldPublicKey: oldPub,
        oldEncryptedPrivateKey: oldEnc,
        encryptionKey: masterKey,
        newPublicKey: helperPub,
        rotatedAt: new Date().toISOString(),
      });
      await auditLog.append(
        "l1",
        "policy_loaded",
        fortressIdFromStoragePath(storagePath),
        {
          source: "castle-wall-re-pin",
          rotation_proof: proof,
          old_pin_fingerprint: oldFingerprint,
          new_pin_fingerprint: helperFingerprint,
        },
        "success",
      );
      await auditLog.flush();
      write(out, `${helperFingerprint}\n`);
      write(
        out,
        `Trust anchor migrated to the signer helper (was ${oldFingerprint}). Rotation proof recorded in the audit log.\n`,
      );
      masterKey.fill(0);
      return 0;
    }

    // No retiring key on disk: idempotent re-assert (already migrated earlier).
    await auditLog.append(
      "l1",
      "policy_loaded",
      fortressIdFromStoragePath(storagePath),
      {
        source: "castle-wall-re-pin",
        new_pin_fingerprint: helperFingerprint,
        note: "re-assert (no retiring key present)",
      },
      "success",
    );
    await auditLog.flush();
    masterKey.fill(0);
    write(out, `${helperFingerprint}\n`);
    write(out, "Pin re-asserted to the helper key (no retiring key to rotate).\n");
    return 0;
  } catch (error) {
    write(err, `Error: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
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

/**
 * Start the Castle Wall enforcement daemon standalone, using the EXISTING
 * fortress signing key, without wrapping a live agent. This is the
 * acceptance-drill bring-up path (A1/B2): `sanctuary wrap` couples the daemon
 * to a wrapped agent's MCP-server lifetime, which is unsuitable for a
 * multi-step, multi-reboot armed-wall drill.
 *
 * B2: by default the daemon signs via the root signer helper, so signing no
 * longer needs the passphrase at all. The derived master key is still required
 * to open the encrypted audit log (residual R2 — a boot-time daemon still needs
 * it; that is F1's problem, not closed here). The legacy local-sign path
 * (`SANCTUARY_CASTLE_LOCAL_SIGN=1`) still decrypts `castle-pinned-privkey.enc`
 * and proves the passphrase matches the pin by construction.
 *
 * This verb refuses to mint a fresh passphrase (which could never open the
 * existing audit log) and requires an existing fortress (key-params present).
 *
 * Runs in the foreground until SIGINT/SIGTERM, then tears the daemon down.
 */
export async function runDaemon(
  ctx: CastleWallCommandContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;

  if (platform !== "darwin") {
    write(err, "castle-wall daemon is macOS-only.\n");
    return 1;
  }

  const storagePath = resolveStoragePath(env);
  const localSign = env.SANCTUARY_CASTLE_LOCAL_SIGN === "1";

  // Report the active pin fingerprint. In helper mode the trust anchor is the
  // root-owned global pin (K_helper); in local mode it is the per-fortress key.
  const pubPath = join(storagePath, CASTLE_PINNED_PUBKEY);
  let pinFingerprint: string;
  try {
    let publicKey: Uint8Array;
    if (!localSign) {
      try {
        publicKey = await readFile(CASTLE_GLOBAL_PINNED_PUBKEY_PATH);
      } catch {
        publicKey = await readFile(pubPath);
      }
    } else {
      publicKey = await readFile(pubPath);
    }
    if (publicKey.length !== 32) {
      write(err, `Pinned public key must be 32 bytes (found ${publicKey.length}).\n`);
      return 1;
    }
    pinFingerprint = fingerprintFromPublicKey(publicKey);
  } catch {
    write(
      err,
      `No pinned key found. Run 'sanctuary castle-wall provision-pin' (local) or 'sanctuary castle-wall re-pin' (helper) first.\n`,
    );
    return 1;
  }
  write(out, `Pinned key fingerprint: ${pinFingerprint}\n`);

  // Resolve the EXISTING fortress passphrase. Refuse to generate a fresh one:
  // a new key could never match the pin, and arming with it would fail-closed
  // the whole machine to deny-all.
  let passphrase: string;
  if (env.SANCTUARY_PASSPHRASE) {
    passphrase = env.SANCTUARY_PASSPHRASE;
  } else {
    const resolved = await getOrCreatePassphrase({ storagePath });
    if (resolved.source === "generated") {
      write(err, "Refusing to start: no existing fortress passphrase found (would mint a new key that cannot match the pin). Run where the fortress Keychain entry is unlocked, or set SANCTUARY_PASSPHRASE.\n");
      return 1;
    }
    passphrase = resolved.value;
  }

  // Require existing key-derivation params (an already-provisioned fortress).
  const storage = new FilesystemStorage(join(storagePath, "state"));
  let existingParams: KeyDerivationParams | undefined;
  try {
    const raw = await storage.read("_meta", "key-params");
    if (raw) {
      existingParams = JSON.parse(bytesToString(raw)) as KeyDerivationParams;
    }
  } catch {
    // none
  }
  if (!existingParams) {
    write(err, "Refusing to start: no existing key-params under the fortress (nothing provisioned to bring up).\n");
    return 1;
  }

  const derived = await deriveMasterKey(passphrase, existingParams);
  const auditLog = new AuditLog(storage, derived.key);

  const { startMacOSCastleWallDaemon } = await import("../castle-wall/runtime/index.js");
  let daemon: { socketPath: string; stop: () => Promise<void> };
  try {
    daemon = await startMacOSCastleWallDaemon({
      fortressPath: storagePath,
      fortressId: fortressIdFromStoragePath(storagePath),
      masterKey: derived.key,
      auditLog,
      ...(localSign ? { localSign: true } : {}),
      ...(env.SANCTUARY_CASTLE_SIGNER_CLIENT
        ? { signerClientPath: env.SANCTUARY_CASTLE_SIGNER_CLIENT }
        : {}),
    });
  } catch (error) {
    write(err, `Daemon failed to start: ${(error as Error).message}\n`);
    if (localSign) {
      write(err, "Local-sign mode: a decrypt error means the passphrase does not match the pinned key. Refusing to arm with a mismatched key.\n");
    } else {
      write(err, "Helper-sign mode: the signer helper is unreachable. Confirm the helper is installed + approved and SANCTUARY_CASTLE_SIGNER_CLIENT points at the shim. Refusing to arm without a signer (fail-closed).\n");
    }
    return 1;
  }

  write(out, `Castle Wall daemon listening on ${daemon.socketPath}\n`);
  if (localSign) {
    write(out, `Signing via the local key; matches pin ${pinFingerprint} (decryption succeeded).\n`);
  } else {
    write(out, `Signing via the root signer helper (no passphrase used for signing); pin ${pinFingerprint}.\n`);
  }
  write(out, "Daemon running in the foreground. Ctrl-C (SIGINT) or SIGTERM to stop.\n");

  await new Promise<void>((resolveWait) => {
    let stopping = false;
    const stop = () => {
      if (stopping) return;
      stopping = true;
      write(err, "\nStopping Castle Wall daemon...\n");
      void daemon
        .stop()
        .catch(() => undefined)
        .finally(() => resolveWait());
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
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
