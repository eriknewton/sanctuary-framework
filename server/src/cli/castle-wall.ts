import { execFile as nodeExecFile, execSync as nodeExecSync } from "node:child_process";
import { createConnection } from "node:net";
import { createHash, randomBytes as nodeRandomBytes } from "node:crypto";
import { chmod, mkdir, readFile, stat, unlink, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
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
  /** Override the host-app headless runner (tests drive enable/disable without the real app). */
  hostAppInvoke?: HostAppInvoker;
  /** Override the host-app binary probe list (tests). */
  hostAppCandidates?: string[];
  /** Override the daemon-socket reachability probe (tests). */
  daemonProbe?: (socketPath: string) => Promise<boolean>;
  /**
   * Override the `open` runner used by the DEFAULT LaunchServices invoker
   * (tests exercise the report-file round-trip without shelling out to real
   * `open`). Ignored when `hostAppInvoke` is supplied.
   */
  openRunner?: OpenRunner;
  /**
   * Override the report-file path factory used by the default LaunchServices
   * invoker (tests pin a known temp path). Ignored when `hostAppInvoke` is set.
   */
  reportPathFactory?: () => string;
  /** Override running-app handling for LaunchServices tests. */
  runningAppController?: RunningAppController;
  /**
   * Override the system-extension state probe used by the enable gate (tests).
   * Defaults to `systemextensionsctl list | grep castle-wall`.
   */
  sysextProbe?: () => Promise<SysextState>;
}

export interface CastleWallParsedArgs {
  fortress?: string;
  since?: string;
  scope?: "once" | "session" | "always";
  requestId?: string;
  force?: boolean;
  acceptBrokenChain?: boolean;
  ttlSeconds?: number;
  noTtl?: boolean;
}

/** Runs the host-app binary in headless mode; mirrors execFile semantics. */
export type HostAppInvoker = (
  binaryPath: string,
  args: string[],
) => Promise<{ stdout: string; stderr: string; exitCode: number }>;

/**
 * Runs `open` (or a test double). The default LaunchServices invoker launches
 * the host app through `open` so the child runs as a real LaunchServices
 * instance — the only way to reach NE preferences on macOS Tahoe, where a
 * directly-exec'd binary's `NEFilterManager.loadFromPreferences` hangs forever
 * (Mini1 Tahoe drill, 2026-06-10, finding 1).
 */
export type OpenRunner = (
  command: string,
  args: string[],
) => Promise<{ stdout: string; stderr: string; exitCode: number }>;

/** Parsed `systemextensionsctl list` state for the Castle Wall sysext. */
export type SysextState =
  | "[activated enabled]"
  | "[activated disabled]"
  | "[activated waiting for user]"
  | "not loaded";

/** JSON line emitted by `CastleWallHostApp --headless <action>` (HeadlessFilterCLI.Report). */
interface HeadlessReport {
  ok: boolean;
  action: string;
  state: "enabled" | "disabled" | "needs_user_approval" | "unknown";
  error?: string;
  build?: HeadlessBuildIdentity;
}

interface LeaseStatusFile {
  armed: boolean;
  revoked?: boolean;
  ttl_seconds: number | null;
  heartbeat_interval_seconds: number;
  updated_at: string;
  source: "castle-wall-cli";
}

/** Exit-code contract with HeadlessFilterCLI.ExitCode (Swift side). */
const HEADLESS_EXIT_NEEDS_APPROVAL = 3;
export const CASTLE_WALL_HEADLESS_CONTRACT_VERSION = "2";

interface HeadlessBuildIdentity {
  git_sha?: string;
  headless_contract_version?: string;
}

interface RunningAppController {
  isRunning(processName: string): Promise<boolean>;
  terminate(processName: string): Promise<boolean>;
}

/**
 * Distinct CLI exit code for "the system extension is installed but toggled
 * OFF" — the Tahoe-specific state that needs a one-time console toggle in
 * System Settings (drill finding 1). Kept separate from the generic failure (1)
 * and the consent-missing path (3) so an operator/runbook can branch on it.
 */
const EXIT_SYSEXT_DISABLED = 4;

function write(stream: Writable, text: string): void {
  stream.write(text);
}

function fingerprintFromPublicKey(publicKey: Uint8Array): string {
  return createHash("sha256")
    .update(publicKey)
    .digest("hex")
    .slice(0, 16);
}

function parseCastleWallState(raw: string): SysextState {
  if (raw.includes("[activated enabled]")) return "[activated enabled]";
  if (raw.includes("[activated waiting for user]")) {
    return "[activated waiting for user]";
  }
  // Tahoe ships the sysext toggled OFF ([activated disabled]); surface that
  // distinctly rather than mislabeling it "not loaded" (the false-assurance
  // trap from the 2026-06-10 drill, finding 2).
  if (raw.includes("[activated disabled]")) return "[activated disabled]";
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

/**
 * Operation name for the CLI's audited "operator accepted a broken audit chain"
 * consent entry. Parallels the MCP router's `mcp_accept_broken_chain_override`
 * (router.ts) — a privileged CLI action (daemon bring-up, re-pin) past audit
 * integrity findings records the operator's consent BEFORE it proceeds, so the
 * override is itself auditable. The broken history is NEVER repaired or deleted;
 * it stays on disk, visible to `sanctuary castle-wall audit-findings`.
 */
const CASTLE_WALL_ACCEPT_BROKEN_CHAIN_OP = "castle_wall_accept_broken_chain_override";

/**
 * Build the `AuditLog` a privileged CLI verb (daemon / re-pin) should use,
 * applying the operator-override semantics that mirror the MCP router's
 * `accept_broken_chain` path:
 *
 *  - No `--accept-broken-chain`: return a default (strict) `AuditLog`. If the
 *    chain has integrity findings, the verb's first append throws
 *    `AuditIntegrityError` exactly as today — fail-closed default, unchanged.
 *  - `--accept-broken-chain` + findings present: emit a loud stderr warning,
 *    write an audited critical override entry FIRST (so the consent lands in the
 *    log before the privileged action runs), then return a lenient `AuditLog`
 *    so the verb's own appends proceed past the findings. Nothing is repaired,
 *    rewritten, or deleted — anti-rollback stays intact.
 *  - `--accept-broken-chain` + no findings: return a default (strict)
 *    `AuditLog` and write NO override entry (no spurious consent record).
 *
 * Findings are probed via `getIntegrityFindings()`, which surfaces findings
 * without throwing — the override decision must be made on the actual finding
 * set, not on a thrown error.
 */
async function buildAuditLogForPrivilegedAction(opts: {
  storage: FilesystemStorage;
  masterKey: Uint8Array;
  fortressPath: string;
  verb: "daemon" | "re-pin";
  acceptBrokenChain: boolean;
  err: Writable;
}): Promise<AuditLog> {
  const { storage, masterKey, fortressPath, verb, acceptBrokenChain, err } = opts;
  if (!acceptBrokenChain) {
    return new AuditLog(storage, masterKey);
  }

  // Flag set: probe findings without throwing (lenient read).
  const lenient = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
  const findings = await lenient.getIntegrityFindings();
  if (findings.length === 0) {
    // Clean chain: the override is a no-op. Keep the default strict log and do
    // not write a spurious consent entry.
    return new AuditLog(storage, masterKey);
  }

  // Findings present + operator consented. Make it loud, then record consent
  // BEFORE the privileged action proceeds, mirroring the router ordering.
  write(
    err,
    `WARNING: --accept-broken-chain: proceeding past ${findings.length} audit ` +
      `integrity finding(s) for '${verb}'. Recording an audited override entry ` +
      `(${CASTLE_WALL_ACCEPT_BROKEN_CHAIN_OP}). The broken history is NOT ` +
      `repaired or deleted; inspect it with 'sanctuary castle-wall audit-findings'.\n`,
  );
  await lenient.appendCritical({
    layer: "l2",
    operation: CASTLE_WALL_ACCEPT_BROKEN_CHAIN_OP,
    identity_id: fortressIdFromStoragePath(fortressPath),
    result: "success",
    details: {
      verb,
      finding_count: findings.length,
      findings,
      source: "castle-wall-cli",
    },
  });
  await lenient.flush();
  return lenient;
}

/**
 * Print the current audit-chain integrity findings for a fortress (read-only).
 *
 * This is the "what is actually wrong" diagnostic that lets an operator decide
 * whether `--accept-broken-chain` is warranted. It loads the audit log in
 * lenient mode and reports findings via `getIntegrityFindings()`; it NEVER
 * appends to, repairs, rewrites, or deletes the audit chain. Each finding is
 * emitted as one JSON line (index, kind, message, affected entry key/sequence,
 * expected/actual where present).
 */
export async function runAuditFindings(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const parsed = parseCastleWallArgs(argv);
  const fortressPath = resolveFortressArg(parsed.fortress, env);

  try {
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const masterKey = await resolveMasterKey(fortressPath, env);
    const auditLog = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
    const findings = await auditLog.getIntegrityFindings();
    masterKey.fill(0);

    if (findings.length === 0) {
      write(out, "No audit integrity findings; the chain verifies clean.\n");
      return 0;
    }

    write(
      err,
      `${findings.length} audit integrity finding(s) for fortress ${fortressIdFromStoragePath(fortressPath)}:\n`,
    );
    findings.forEach((finding, index) => {
      write(
        out,
        JSON.stringify({
          index,
          kind: finding.kind,
          message: finding.message,
          ...(finding.key !== undefined ? { key: finding.key } : {}),
          ...(finding.sequence !== undefined ? { sequence: finding.sequence } : {}),
          ...(finding.expected !== undefined ? { expected: finding.expected } : {}),
          ...(finding.actual !== undefined ? { actual: finding.actual } : {}),
        }) + "\n",
      );
    });
    return 0;
  } catch (error) {
    write(err, `Error: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
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
    // A2/B2 (F-A2-1): do NOT `mkdir` the custody directory here. This runs as the
    // operator-UID provision-pin CLI; creating the directory operator-owned is
    // exactly the gap the helper-as-signer design closes (an operator-owned dir
    // lets same-UID malware swap the key + pin). The root signer helper creates
    // + owns the directory. Best-effort write only IF the dir already exists
    // root-owned (it will EACCES, handled below) — never bring it into being.
    await writeFile(CASTLE_GLOBAL_PINNED_PUBKEY_PATH, publicKey, { mode: 0o644 });
    await chmod(CASTLE_GLOBAL_PINNED_PUBKEY_PATH, 0o644);
  } catch (error) {
    const code =
      error instanceof Error && "code" in error
        ? (error as NodeJS.ErrnoException).code
        : undefined;
    // SAFETY: provision-pin diagnostics are operator-facing CLI stderr output.
    // Under A2 the global pin is root:wheel 0644 and owned by the signer helper;
    // an operator-UID provision-pin CANNOT (and must not) overwrite it, and the
    // directory may not exist yet (ENOENT) because only the helper creates it.
    // Both are expected — the trust anchor is migrated via `castle-wall re-pin`.
    if (code === "EACCES" || code === "EPERM" || code === "ENOENT") {
      console.warn(
        `[castle-wall] global pin ${CASTLE_GLOBAL_PINNED_PUBKEY_PATH} is owned by the root signer helper (A2); provision-pin does not write it. Run 'sanctuary castle-wall re-pin' to migrate the trust anchor to the signer helper.`,
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
  argv: string[] = [],
  ctx: CastleWallCommandContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;
  const acceptBrokenChain = parseCastleWallArgs(argv).acceptBrokenChain ?? false;

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
    const auditLog = await buildAuditLogForPrivilegedAction({
      storage,
      masterKey,
      fortressPath: storagePath,
      verb: "re-pin",
      acceptBrokenChain,
      err,
    });

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

  let sysextState: SysextState;
  try {
    const raw = execSyncFn(
      "systemextensionsctl list 2>/dev/null | grep castle-wall"
    );
    sysextState = parseCastleWallState(raw);
  } catch {
    sysextState = "not loaded";
  }

  write(out, `Castle Wall sysext: ${sysextState}\n`);
  const lease = await readLeaseStatus(storagePath);
  if (lease) {
    const ttl = lease.ttl_seconds === null ? "none (--no-ttl)" : `${lease.ttl_seconds}s`;
    write(
      out,
      `Dead-man lease: ${lease.armed ? "armed" : "disarmed"}; ttl=${ttl}; heartbeat=${lease.heartbeat_interval_seconds}s; updated=${lease.updated_at}\n`,
    );
  }

  // Sysext "[activated enabled]" only means installed, not filtering. When the
  // host-app binary is present, corroborate the live NE filter state through
  // its --headless status probe. Binary absent → stay silent so output is
  // unchanged on machines without the app (and on non-Mac CI).
  const resolved = await resolveHostAppBinary(env, ctx);
  if (!("error" in resolved)) {
    const invoke = ctx.hostAppInvoke ?? makeHostAppInvoke(STATUS_PROBE_TIMEOUT_MS);
    try {
      const result = await invoke(resolved.path, ["--headless", "status"]);
      const report = parseHeadlessReport(result.stdout);
      if (
        result.exitCode === 0 &&
        report?.ok &&
        (report.state === "enabled" || report.state === "disabled")
      ) {
        write(out, `Content filter: ${report.state}\n`);
        if (report.build?.git_sha && report.build?.headless_contract_version) {
          write(
            out,
            `Castle Wall app build: ${report.build.git_sha} (headless contract ${report.build.headless_contract_version})\n`,
          );
        } else {
          write(
            out,
            "Castle Wall app build: unknown (host app does not report headless contract identity)\n",
          );
        }
      } else {
        const reason =
          report?.error ??
          (report && report.state !== "enabled" && report.state !== "disabled"
            ? `host app reported state '${report.state}'`
            : undefined) ??
          (result.stderr.trim() ||
            `host app exited with code ${result.exitCode}`);
        write(out, `Content filter: unknown (${reason})\n`);
      }
    } catch (error) {
      write(
        out,
        `Content filter: unknown (${
          error instanceof Error ? error.message : String(error)
        })\n`,
      );
    }
  }
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
  argv: string[] = [],
  ctx: CastleWallCommandContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;
  const acceptBrokenChain = parseCastleWallArgs(argv).acceptBrokenChain ?? false;

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
  const auditLog = await buildAuditLogForPrivilegedAction({
    storage,
    masterKey: derived.key,
    fortressPath: storagePath,
    verb: "daemon",
    acceptBrokenChain,
    err,
  });

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

  // Periodic verifiable-transparency checkpoints. Default cadence 6h;
  // SANCTUARY_TRANSPARENCY_INTERVAL accepts "off", ms, or <n>s|m|h|d. A
  // misconfigured cadence refuses to start the daemon (no silent fallback);
  // a failed emission tick is loud on stderr but never crashes enforcement
  // and never persists a partial checkpoint (the emitter is fail-closed).
  let transparencyScheduler: { stop(): void } | undefined;
  {
    const {
      parseTransparencyInterval,
      startTransparencyScheduler,
      TRANSPARENCY_INTERVAL_ENV,
    } = await import("../transparency/scheduler.js");
    let intervalMs: number | null;
    try {
      intervalMs = parseTransparencyInterval(env[TRANSPARENCY_INTERVAL_ENV]);
    } catch (error) {
      write(err, `${(error as Error).message}\n`);
      await daemon.stop().catch(() => undefined);
      return 1;
    }
    if (intervalMs !== null) {
      const { emitEnforcementCheckpoint } = await import(
        "../transparency/emitter.js"
      );
      const { resolveTransparencySigner } = await import(
        "../transparency/signer.js"
      );
      const { createRequire } = await import("node:module");
      const { realpathSync } = await import("node:fs");
      const { version: pkgVersion } = createRequire(import.meta.url)(
        "../../package.json",
      ) as { version: string };
      transparencyScheduler = startTransparencyScheduler({
        intervalMs,
        emit: async () => {
          const signer = await resolveTransparencySigner({
            fortressPath: storagePath,
            masterKey: derived.key,
            env,
            ...(localSign ? { mode: "local" as const } : {}),
          });
          const record = await emitEnforcementCheckpoint({
            storage,
            auditLog,
            fortressId: fortressIdFromStoragePath(storagePath),
            fortressPath: storagePath,
            masterKey: derived.key,
            signer,
            binaryPath: realpathSync(process.argv[1] ?? ""),
            version: pkgVersion,
          });
          await auditLog.appendCritical({
            layer: "l2",
            operation: "transparency_checkpoint_emitted",
            identity_id: record.fortress_id,
            result: "success",
            details: {
              counter: record.counter,
              merkle_root: record.audit.merkle_root,
              highest_sequence: record.audit.highest_sequence,
              signer_kid: record.signer_kid,
            },
          });
          write(
            out,
            `[transparency] enforcement checkpoint ${record.counter} emitted (audit head seq ${record.audit.highest_sequence}).\n`,
          );
        },
        onError: (error) => {
          write(
            err,
            `[transparency] checkpoint emission FAILED (nothing was persisted): ${error instanceof Error ? error.message : String(error)}\n`,
          );
        },
      });
      write(
        out,
        `[transparency] periodic enforcement checkpoints every ${Math.round(intervalMs / 60_000)}m (set ${TRANSPARENCY_INTERVAL_ENV}=off to disable).\n`,
      );
    }
  }

  await new Promise<void>((resolveWait) => {
    let stopping = false;
    const stop = () => {
      if (stopping) return;
      stopping = true;
      write(err, "\nStopping Castle Wall daemon...\n");
      transparencyScheduler?.stop();
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
    // A2/B2 (F-A2-1): the custody directory holds the root-owned signing key +
    // trust-anchor pin. It MUST be owned by root and not group/other-writable,
    // or an operator-UID process could unlink + substitute those files (POSIX
    // governs unlink/rename by DIRECTORY write permission). Chown to root:wheel,
    // NOT to the operator. SUDO_USER above is validated only to confirm a real
    // sudo invocation; it is no longer interpolated into a privileged command.
    execSyncFn(`chown root:wheel ${dir}`);
    execSyncFn(`chmod 0755 ${dir}`);
  } catch (error) {
    write(err, `${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }

  write(out, `${CASTLE_GLOBAL_PINNED_PUBKEY_DIR}\n`);
  write(
    out,
    "Shared dir ready (root:wheel 0755). The signer helper owns the key + pin inside it; run 'sanctuary castle-wall re-pin' to install the trust anchor.\n",
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

const HOST_APP_RELATIVE_BINARY =
  "Sanctuary-CastleWall.app/Contents/MacOS/CastleWallHostApp";

function defaultHostAppCandidates(env: NodeJS.ProcessEnv): string[] {
  const home = env.HOME ?? homedir();
  return [
    `/Applications/${HOST_APP_RELATIVE_BINARY}`,
    `${home}/Applications/${HOST_APP_RELATIVE_BINARY}`,
  ];
}

/**
 * True iff `path` is an existing regular file owned by root or the current
 * user (mirrors SanctuaryServerBridge.isOwnerTrustedExecutable on the Swift
 * side): prevents invoking a binary an attacker dropped at a probed path.
 */
async function isOwnerTrustedExecutable(
  path: string,
  getuid: (() => number) | undefined,
): Promise<boolean> {
  try {
    const info = await stat(path);
    if (!info.isFile()) return false;
    const uid = getuid?.();
    return info.uid === 0 || (uid !== undefined && info.uid === uid);
  } catch {
    return false;
  }
}

/**
 * Resolve the Castle Wall host-app binary that owns the NE filter
 * configuration. Only that signed binary can toggle the filter without
 * re-triggering the one-time consent, so this is the single arming surface.
 * SANCTUARY_CASTLE_HOSTAPP overrides; an invalid override fails loud rather
 * than silently falling through to a different binary.
 */
async function resolveHostAppBinary(
  env: NodeJS.ProcessEnv,
  ctx: CastleWallCommandContext,
): Promise<{ path: string } | { error: string }> {
  const getuid = ctx.getuid ?? process.getuid?.bind(process);
  const override = env.SANCTUARY_CASTLE_HOSTAPP;
  if (override) {
    if (await isOwnerTrustedExecutable(override, getuid)) {
      return { path: override };
    }
    return {
      error: `SANCTUARY_CASTLE_HOSTAPP is set but does not point at a trusted executable: ${override}`,
    };
  }
  const candidates = ctx.hostAppCandidates ?? defaultHostAppCandidates(env);
  for (const candidate of candidates) {
    if (await isOwnerTrustedExecutable(candidate, getuid)) {
      return { path: candidate };
    }
  }
  return {
    error:
      "Castle Wall app not found (looked in /Applications and ~/Applications). " +
      "Install Sanctuary-CastleWall.app or set SANCTUARY_CASTLE_HOSTAPP to its " +
      `Contents/MacOS/CastleWallHostApp binary.`,
  };
}

function makeHostAppInvoke(timeoutMs: number): HostAppInvoker {
  return (binaryPath, args) =>
    new Promise((resolvePromise) => {
      nodeExecFile(
        binaryPath,
        args,
        { encoding: "utf8", timeout: timeoutMs },
        (error, stdout, stderr) => {
          let exitCode = 0;
          let stderrOut = stderr ?? "";
          if (error) {
            exitCode =
              typeof error.code === "number"
                ? error.code
                : // Spawn failure (ENOENT/EACCES/timeout kill): no exit code exists.
                  -1;
            if (error.killed && !stderrOut.trim()) {
              stderrOut = `host app did not respond within ${timeoutMs}ms`;
            }
          }
          resolvePromise({ stdout: stdout ?? "", stderr: stderrOut, exitCode });
        },
      );
    });
}

/**
 * Resolve the `.app` bundle directory from a path to the binary inside it
 * (`…/Sanctuary-CastleWall.app/Contents/MacOS/CastleWallHostApp` →
 * `…/Sanctuary-CastleWall.app`). `open` launches bundles, not the inner
 * executable. Falls back to the input when no `.app` component is present
 * (e.g. an SANCTUARY_CASTLE_HOSTAPP override pointing at a bare binary).
 */
function resolveAppBundlePath(binaryPath: string): string {
  const marker = ".app/";
  const idx = binaryPath.indexOf(marker);
  if (idx >= 0) return binaryPath.slice(0, idx + ".app".length);
  return binaryPath;
}

function defaultReportPath(): string {
  return join(tmpdir(), `sanctuary-cw-report-${nodeRandomBytes(16).toString("hex")}.json`);
}

export interface LaunchServicesInvokerOptions {
  timeoutMs: number;
  /** Test seam: run `open` (or a double). Defaults to a real `execFile`. */
  openRunner?: OpenRunner;
  /** Test seam: where the host app writes its report. Defaults to a random temp path. */
  reportPathFactory?: () => string;
  /** Test seam: detect/terminate an already-running GUI app before `open -W`. */
  runningAppController?: RunningAppController;
}

/**
 * Host-app invoker that routes through LaunchServices (`open -n -W`) instead of
 * directly exec'ing the binary. On macOS Tahoe a directly-exec'd binary cannot
 * reach NE preferences (`loadFromPreferences` hangs indefinitely); only a
 * LaunchServices-launched app instance can. Because `open` does not relay the
 * child's stdout, the host app also writes its single JSON report line to a
 * caller-supplied `--report-file`; this invoker reads it back, derives an exit
 * code from the report, and returns it in the same shape as the direct invoker.
 *
 * Fail-closed: a missing, empty, or unparseable report file yields a generic
 * failure (exit 1) — never a silent success.
 */
export function makeLaunchServicesHostAppInvoke(
  opts: LaunchServicesInvokerOptions,
): HostAppInvoker {
  const openRunner = opts.openRunner ?? makeDefaultOpenRunner(opts.timeoutMs);
  const reportPathFactory = opts.reportPathFactory ?? defaultReportPath;
  const runningAppController =
    opts.runningAppController ?? makeDefaultRunningAppController();
  return async (binaryPath, args) => {
    const appBundle = resolveAppBundlePath(binaryPath);
    const reportPath = reportPathFactory();
    const processName = binaryPath.split("/").pop() || "CastleWallHostApp";
    let preflight = "";
    if (await runningAppController.isRunning(processName)) {
      const terminated = await runningAppController.terminate(processName);
      if (!terminated) {
        return {
          stdout: "",
          stderr:
            `Castle Wall host app is already running (${processName}) and could not be terminated for headless LaunchServices mode. ` +
            "Quit Sanctuary-CastleWall.app at the console or retry after it exits.",
          exitCode: 1,
        };
      }
      preflight =
        `Castle Wall host app is already running (${processName}); terminating it and relaunching headlessly with the same signed app consent.\n`;
    }
    const openArgs = [
      "-n",
      "-W",
      appBundle,
      "--args",
      ...args,
      `--report-file=${reportPath}`,
    ];

    let openResult: { stdout: string; stderr: string; exitCode: number };
    try {
      openResult = await openRunner("open", openArgs);
    } catch (error) {
      openResult = {
        stdout: "",
        stderr: error instanceof Error ? error.message : String(error),
        exitCode: -1,
      };
    }

    let raw: string;
    try {
      raw = await readFile(reportPath, "utf8");
    } catch {
      raw = "";
    } finally {
      await unlink(reportPath).catch(() => undefined);
    }

    if (!raw.trim()) {
      const reason = openResult.stderr.trim()
        ? `: ${openResult.stderr.trim()}`
        : "";
      return {
        stdout: "",
        stderr:
          `Castle Wall host app produced no report (open exit ${openResult.exitCode}${reason}). ` +
          "On macOS Tahoe, confirm the Castle Wall system extension is toggled on in " +
          "System Settings > General > Login Items & Extensions > Network Extensions.",
        exitCode: 1,
      };
    }

    const report = parseHeadlessReport(raw);
    if (!report) {
      return {
        stdout: raw,
        stderr: "Castle Wall host app report was unparseable.",
        exitCode: 1,
      };
    }

    const exitCode =
      report.state === "needs_user_approval"
        ? HEADLESS_EXIT_NEEDS_APPROVAL
        : report.ok
          ? 0
          : 1;
    return { stdout: raw, stderr: preflight, exitCode };
  };
}

function makeDefaultRunningAppController(): RunningAppController {
  const execFile = (command: string, args: string[], timeoutMs: number) =>
    new Promise<{ exitCode: number }>((resolvePromise) => {
      nodeExecFile(command, args, { timeout: timeoutMs }, (error) => {
        if (!error) {
          resolvePromise({ exitCode: 0 });
          return;
        }
        resolvePromise({
          exitCode: typeof error.code === "number" ? error.code : -1,
        });
      });
    });

  return {
    async isRunning(processName) {
      const result = await execFile("pgrep", ["-x", processName], 2_000);
      return result.exitCode === 0;
    },
    async terminate(processName) {
      await execFile("pkill", ["-TERM", "-x", processName], 2_000);
      const deadline = Date.now() + 5_000;
      while (Date.now() < deadline) {
        if (!(await this.isRunning(processName))) return true;
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
      }
      return !(await this.isRunning(processName));
    },
  };
}

function makeDefaultOpenRunner(timeoutMs: number): OpenRunner {
  return (command, args) =>
    new Promise((resolvePromise) => {
      nodeExecFile(
        command,
        args,
        { encoding: "utf8", timeout: timeoutMs },
        (error, stdout, stderr) => {
          let exitCode = 0;
          let stderrOut = stderr ?? "";
          if (error) {
            exitCode = typeof error.code === "number" ? error.code : -1;
            if (error.killed && !stderrOut.trim()) {
              stderrOut = `open did not return within ${timeoutMs}ms`;
            }
          }
          resolvePromise({ stdout: stdout ?? "", stderr: stderrOut, exitCode });
        },
      );
    });
}

/**
 * Default arm/disarm invoker. LaunchServices-routed so it survives macOS Tahoe
 * (see makeLaunchServicesHostAppInvoke). The direct-exec makeHostAppInvoke is
 * retained for the read-only status probe and pre-Tahoe paths.
 */
const ARM_INVOKE_TIMEOUT_MS = 90_000;
const DISARM_INVOKE_TIMEOUT_MS = 7_000;
function defaultArmInvoke(ctx: CastleWallCommandContext, action: "enable" | "disable"): HostAppInvoker {
  return makeLaunchServicesHostAppInvoke({
    timeoutMs: action === "disable" ? DISARM_INVOKE_TIMEOUT_MS : ARM_INVOKE_TIMEOUT_MS,
    ...(ctx.openRunner ? { openRunner: ctx.openRunner } : {}),
    ...(ctx.reportPathFactory ? { reportPathFactory: ctx.reportPathFactory } : {}),
    ...(ctx.runningAppController
      ? { runningAppController: ctx.runningAppController }
      : {}),
  });
}

/**
 * `status` is a read-only quick check; never let it hang behind a wedged
 * NE-preferences read (observed: --headless status can stall minutes on a
 * host where the filter configuration is in a bad state). 10s is orders of
 * magnitude above the healthy-path latency (~0.1s).
 */
const STATUS_PROBE_TIMEOUT_MS = 10_000;

function parseHeadlessReport(stdout: string): HeadlessReport | null {
  const lines = stdout
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  const last = lines[lines.length - 1];
  if (!last) return null;
  try {
    const parsed = JSON.parse(last) as Partial<HeadlessReport>;
    if (typeof parsed.ok !== "boolean" || typeof parsed.state !== "string") {
      return null;
    }
    return parsed as HeadlessReport;
  } catch {
    return null;
  }
}

function resolveCliBuildSha(
  env: NodeJS.ProcessEnv,
  ctx: CastleWallCommandContext,
): string {
  const envSha =
    env.SANCTUARY_CASTLE_BUILD_SHA ?? env.SANCTUARY_CASTLE_CLI_BUILD_SHA;
  if (envSha?.trim()) return envSha.trim();

  const execSyncFn =
    ctx.execSyncFn ??
    ((command: string) =>
      nodeExecSync(`sh -lc '${command.replace(/'/g, "'\\''")}'`, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim());
  try {
    const sha = execSyncFn("git rev-parse --short=12 HEAD").trim();
    return sha || "unknown";
  } catch {
    return "unknown";
  }
}

function validateHeadlessBuildIdentity(
  report: HeadlessReport,
  cliGitSha: string,
): string | null {
  const appBuild = report.build;
  if (
    !appBuild ||
    typeof appBuild.git_sha !== "string" ||
    typeof appBuild.headless_contract_version !== "string"
  ) {
    return (
      "deployed Castle Wall app did not report a headless build identity; " +
      "rebuild + redeploy the signed app before using headless enable/disable."
    );
  }
  if (
    appBuild.headless_contract_version !== CASTLE_WALL_HEADLESS_CONTRACT_VERSION
  ) {
    return (
      `deployed app headless contract ${appBuild.headless_contract_version} ` +
      `!= CLI ${CASTLE_WALL_HEADLESS_CONTRACT_VERSION}; rebuild + redeploy the signed app.`
    );
  }
  if (appBuild.git_sha !== cliGitSha) {
    return (
      `deployed app ${appBuild.git_sha} != CLI ${cliGitSha} - rebuild + redeploy the signed app.`
    );
  }
  return null;
}

function defaultDaemonProbe(socketPath: string): Promise<boolean> {
  return new Promise((resolvePromise) => {
    let settled = false;
    const socket = createConnection(socketPath);
    const finish = (reachable: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolvePromise(reachable);
    };
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
    setTimeout(() => finish(false), 1_500).unref();
  });
}

/**
 * Best-effort audit record for a CLI arm/disarm. Never blocks the operation:
 * disarm especially is the dead-man recovery lever and must not depend on a
 * decryptable audit log (the authoritative filter_started/filter_stopped
 * events come from the daemon path). A failed write degrades to a warning.
 */
async function appendArmAuditBestEffort(
  action: "enable" | "disable",
  verifiedState: string,
  forced: boolean,
  fortressPath: string,
  env: NodeJS.ProcessEnv,
  err: Writable,
): Promise<void> {
  try {
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const masterKey = await resolveMasterKey(fortressPath, env);
    const auditLog = new AuditLog(storage, masterKey);
    await auditLog.append(
      "l1",
      action === "enable" ? "wall_armed" : "wall_disarmed",
      fortressIdFromStoragePath(fortressPath),
      {
        source: "castle-wall-cli",
        action,
        verified_state: verifiedState,
        forced,
      },
      "success",
    );
    await auditLog.flush();
    masterKey.fill(0);
  } catch (error) {
    write(
      err,
      `Warning: filter state changed but the audit entry could not be written (${
        error instanceof Error ? error.message : String(error)
      }). Corroborate via 'sanctuary castle-wall audit-dump' once the fortress key is available.\n`,
    );
  }
}

function leaseStatusPath(fortressPath: string): string {
  return join(fortressPath, "castle-wall-lease.json");
}

async function writeLeaseStatusBestEffort(
  fortressPath: string,
  lease: LeaseStatusFile,
): Promise<void> {
  try {
    await writeFile(leaseStatusPath(fortressPath), JSON.stringify(lease, null, 2) + "\n", {
      mode: 0o600,
    });
    await chmod(leaseStatusPath(fortressPath), 0o600);
  } catch {
    // Advisory-only status surface; enforcement rides authenticated IPC.
  }
}

async function readLeaseStatus(fortressPath: string): Promise<LeaseStatusFile | null> {
  try {
    const parsed = JSON.parse(await readFile(leaseStatusPath(fortressPath), "utf8")) as LeaseStatusFile;
    if (
      typeof parsed.armed !== "boolean" ||
      typeof parsed.heartbeat_interval_seconds !== "number" ||
      typeof parsed.updated_at !== "string"
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function buildArmLeaseMessage(input: {
  armed: boolean;
  revoked?: boolean;
  ttlSeconds: number | null;
  heartbeatIntervalSeconds?: number;
}): LeaseStatusFile & { type: "arm_lease" } {
  return {
    type: "arm_lease",
    armed: input.armed,
    ...(input.revoked === true ? { revoked: true } : {}),
    ttl_seconds: input.ttlSeconds,
    heartbeat_interval_seconds: input.heartbeatIntervalSeconds ?? 5,
    updated_at: new Date().toISOString(),
    source: "castle-wall-cli",
  };
}

async function sendArmLeaseBestEffort(
  socketPath: string,
  message: ReturnType<typeof buildArmLeaseMessage>,
): Promise<boolean> {
  return await new Promise<boolean>((resolvePromise) => {
    const socket = createConnection(socketPath);
    let settled = false;
    const finish = (ok: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolvePromise(ok);
    };
    const timer = setTimeout(() => finish(false), 1_500);
    timer.unref();
    socket.once("connect", () => {
      socket.write(frame(JSON.stringify({
        jsonrpc: "2.0",
        method: "castle-wall.arm_lease",
        params: message,
      })), () => finish(true));
    });
    socket.once("error", () => finish(false));
  });
}

const NEEDS_APPROVAL_GUIDANCE =
  "The one-time macOS content-filter consent has not been granted on this machine.\n" +
  "That single step is GUI-only (macOS requirement): at the console, launch\n" +
  "Sanctuary-CastleWall.app once and click Allow on the content-filter prompt.\n" +
  "After that, every arm/disarm works headlessly.\n";

const SYSEXT_DISABLED_GUIDANCE =
  "The Castle Wall system extension is installed but toggled OFF.\n" +
  "On macOS Tahoe the extension ships disabled and needs a one-time console\n" +
  "toggle (GUI-only, macOS requirement): at the console, open\n" +
  "System Settings > General > Login Items & Extensions > Network Extensions\n" +
  "and switch Castle Wall on. After that, every arm/disarm works headlessly.\n";

/**
 * Probe the Castle Wall system-extension state via `systemextensionsctl`.
 * Failure (binary missing, e.g. non-macOS CI) degrades to "not loaded" so the
 * caller proceeds rather than blocking on an undetectable state.
 */
async function defaultSysextProbe(
  ctx: CastleWallCommandContext,
): Promise<SysextState> {
  const execSyncFn =
    ctx.execSyncFn ??
    ((command: string) =>
      nodeExecSync(`sh -lc '${command.replace(/'/g, "'\\''")}'`, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim());
  try {
    const raw = execSyncFn(
      "systemextensionsctl list 2>/dev/null | grep castle-wall",
    );
    return parseCastleWallState(raw);
  } catch {
    return "not loaded";
  }
}

async function runArmDisarm(
  action: "enable" | "disable",
  argv: string[],
  ctx: CastleWallCommandContext,
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;

  if (platform !== "darwin") {
    write(err, `castle-wall ${action} is macOS-only.\n`);
    return 1;
  }

  const parsed = parseCastleWallArgs(argv);
  const fortressPath = resolveFortressArg(parsed.fortress, env);
  const socketPath = resolveCastleWallSocketPath({
    platform,
    fortressPath,
  }).path;

  if (action === "enable" && !parsed.force) {
    // Brick-condition gate: filter on + no policy daemon = deny-all with no
    // recovery channel (the 2026-06-09 Hermes drill lockout). Refuse to arm
    // unless the daemon socket answers, or the operator explicitly overrides.
    const probe = ctx.daemonProbe ?? defaultDaemonProbe;
    if (!(await probe(socketPath))) {
      write(
        err,
        `Refusing to arm: no Castle Wall daemon is reachable for this fortress (${socketPath}).\n` +
          "Arming without a policy daemon fail-closes this machine to deny-all\n" +
          "(filter on + daemon down = locked out, including SSH).\n" +
          "Start the daemon first:  sanctuary castle-wall daemon\n" +
          "Or pass --force if the daemon is supervised out-of-band.\n",
      );
      return 1;
    }
  }

  if (action === "enable" && !parsed.noTtl && parsed.ttlSeconds === undefined) {
    write(
      err,
      "Usage: sanctuary castle-wall enable requires either --ttl <duration> for drills or --no-ttl for durable arming.\n",
    );
    return 2;
  }
  if (action === "enable" && parsed.noTtl && parsed.ttlSeconds !== undefined) {
    write(err, "Usage: choose only one dead-man TTL mode: --ttl <duration> or --no-ttl.\n");
    return 2;
  }

  if (action === "enable") {
    // Tahoe ships the sysext toggled OFF; arming over it would save an NE config
    // that never enforces (the false-assurance trap). Detect that distinct state
    // and route the operator to the one-time console toggle. Disable never gates
    // here — it stays the unconditional dead-man lever.
    const sysextProbe = ctx.sysextProbe ?? (() => defaultSysextProbe(ctx));
    if ((await sysextProbe()) === "[activated disabled]") {
      write(err, SYSEXT_DISABLED_GUIDANCE);
      return EXIT_SYSEXT_DISABLED;
    }
  }

  const resolved = await resolveHostAppBinary(env, ctx);
  if ("error" in resolved) {
    write(err, `${resolved.error}\n`);
    return 1;
  }

  const invoke = ctx.hostAppInvoke ?? defaultArmInvoke(ctx, action);
  const cliGitSha = resolveCliBuildSha(env, ctx);
  const headlessArgs = ["--headless", action];
  if (action === "enable") {
    if (parsed.noTtl) headlessArgs.push("--no-ttl");
    else headlessArgs.push(`--ttl=${parsed.ttlSeconds}`);
  } else {
    headlessArgs.push("--timeout=3");
  }
  let leaseRevoked = false;
  if (action === "disable") {
    const leaseMessage = buildArmLeaseMessage({ armed: false, revoked: true, ttlSeconds: null });
    leaseRevoked = await sendArmLeaseBestEffort(socketPath, leaseMessage);
    await writeLeaseStatusBestEffort(fortressPath, leaseMessage);
  }
  const result = await invoke(resolved.path, headlessArgs);
  if (result.stderr.trim()) {
    write(err, result.stderr.trimEnd() + "\n");
  }
  const report = parseHeadlessReport(result.stdout);
  if (report) {
    const buildMismatch = validateHeadlessBuildIdentity(report, cliGitSha);
    if (buildMismatch) {
      write(err, `castle-wall ${action} failed: ${buildMismatch}\n`);
      return 1;
    }
  }

  if (result.exitCode === HEADLESS_EXIT_NEEDS_APPROVAL) {
    write(err, NEEDS_APPROVAL_GUIDANCE);
    return 3;
  }
  if (result.exitCode !== 0 || !report || !report.ok) {
    const detail =
      report?.error ||
      result.stderr.trim() ||
      `host app exited with code ${result.exitCode}`;
    if (action === "disable" && leaseRevoked) {
      write(
        err,
        `Warning: best-effort NE preference disable did not complete (${detail}); the authenticated dead-man lease was revoked, so the provider fail-open path is active.\n`,
      );
      await appendArmAuditBestEffort(
        action,
        "fail_open_deadman",
        parsed.force ?? false,
        fortressPath,
        env,
        err,
      );
      write(out, "Castle Wall disarmed: provider dead-man lease revoked (NE preference disable best-effort did not complete).\n");
      return 0;
    }
    write(err, `castle-wall ${action} failed: ${detail}\n`);
    return 1;
  }

  // Post-change corroboration: re-read the live NE configuration through the
  // host app rather than trusting the mutation call's own report.
  const verify = await invoke(resolved.path, ["--headless", "status"]);
  if (verify.stderr.trim()) {
    write(err, verify.stderr.trimEnd() + "\n");
  }
  const verifyReport = parseHeadlessReport(verify.stdout);
  if (verify.exitCode === 0 && verifyReport) {
    const verifyBuildMismatch = validateHeadlessBuildIdentity(
      verifyReport,
      cliGitSha,
    );
    if (verifyBuildMismatch) {
      write(err, `castle-wall ${action} failed: ${verifyBuildMismatch}\n`);
      return 1;
    }
  }
  const expectedState = action === "enable" ? "enabled" : "disabled";
  const confirmed =
    verify.exitCode === 0 && verifyReport?.state === expectedState;
  const observedState = verifyReport?.state ?? "unparseable";

  if (!confirmed) {
    if (action === "enable") {
      // Arm is the protection-increasing direction: never claim "armed"
      // without a positive corroboration. Fail closed.
      write(
        err,
        `castle-wall enable: state change reported but post-change verification ` +
          `returned '${observedState}' (expected 'enabled').\n`,
      );
      return 1;
    }

    // Disarm is the dead-man recovery lever. Its authoritative signal is the
    // mutation itself (saveToPreferences returned ok, above); the status
    // re-read is only corroboration. On macOS Tahoe that re-read spawns a
    // SECOND LaunchServices app instance, which can time out or yield no report
    // even though the wall is already down — so an INCONCLUSIVE corroboration
    // must not flip a genuine recovery into a reported failure, or the lever
    // stops being trustworthy (the whole point of the SSH-only drill is that
    // `disable` reliably means "wall down"). A corroboration that
    // AFFIRMATIVELY still shows the wall 'enabled' is a real contradiction (the
    // disarm did not stick): fail loud rather than hand back a false recovery
    // assurance (CLAUDE.md invariant 5).
    if (verify.exitCode === 0 && verifyReport?.state === "enabled") {
      write(
        err,
        `castle-wall disable: disarm reported success but post-change ` +
          `verification still shows the wall ENABLED. The wall may still be ` +
          `up — re-run 'sanctuary castle-wall disable' and confirm with ` +
          `'sanctuary castle-wall status'.\n`,
      );
      return 1;
    }
    write(
      err,
      `Warning: castle-wall disable succeeded (the host app confirmed the NE ` +
        `configuration was saved disabled) but post-change corroboration was ` +
        `inconclusive (status returned '${observedState}'). Disarm is the ` +
        `authoritative dead-man lever and is treated as effective; confirm ` +
        `with 'sanctuary castle-wall status' once the host is responsive.\n`,
    );
  }

  await appendArmAuditBestEffort(
    action,
    confirmed ? expectedState : observedState,
    parsed.force ?? false,
    fortressPath,
    env,
    err,
  );

  if (action === "enable") {
    const leaseMessage = buildArmLeaseMessage({
      armed: true,
      ttlSeconds: parsed.noTtl ? null : parsed.ttlSeconds ?? null,
    });
    const leaseSent = await sendArmLeaseBestEffort(socketPath, leaseMessage);
    await writeLeaseStatusBestEffort(fortressPath, leaseMessage);
    if (!leaseSent) {
      write(
        err,
        "Warning: Castle Wall armed, but the daemon did not accept the dead-man lease update. Existing daemon heartbeat state remains authoritative.\n",
      );
    }
    write(out, "Castle Wall armed: content filter enabled (verified via host-app status).\n");
  } else if (confirmed) {
    write(out, "Castle Wall disarmed: content filter disabled (verified via host-app status).\n");
  } else {
    write(
      out,
      "Castle Wall disarmed: content filter disabled (host app confirmed the save; status corroboration pending).\n",
    );
  }
  return 0;
}

/**
 * Headlessly arm the Castle Wall content filter (`sanctuary castle-wall
 * enable`). Drives the signed host-app binary's --headless mode, so it works
 * over SSH once the one-time GUI consent exists. Gated on daemon
 * reachability to avoid the deny-all brick condition; --force overrides.
 */
export async function runEnable(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {},
): Promise<number> {
  return runArmDisarm("enable", argv, ctx);
}

/**
 * Headlessly disarm the Castle Wall content filter (`sanctuary castle-wall
 * disable`). Unconditional by design: this is the remote dead-man lever that
 * makes SSH-only drills recoverable, so it has no preconditions beyond the
 * binary existing.
 */
export async function runDisable(
  argv: string[] = [],
  ctx: CastleWallCommandContext = {},
): Promise<number> {
  return runArmDisarm("disable", argv, ctx);
}

export function parseCastleWallArgs(argv: string[]): CastleWallParsedArgs {
  const parsed: CastleWallParsedArgs = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--fortress") {
      parsed.fortress = argv[++i];
    } else if (arg === "--since") {
      parsed.since = argv[++i];
    } else if (arg === "--ttl") {
      parsed.ttlSeconds = parseLeaseTtlSeconds(argv[++i]);
    } else if (arg.startsWith("--ttl=")) {
      parsed.ttlSeconds = parseLeaseTtlSeconds(arg.slice("--ttl=".length));
    } else if (arg === "--no-ttl") {
      parsed.noTtl = true;
    } else if (arg.startsWith("--scope=")) {
      parsed.scope = parseScope(arg.slice("--scope=".length));
    } else if (arg === "--scope") {
      parsed.scope = parseScope(argv[++i]);
    } else if (arg === "--force") {
      parsed.force = true;
    } else if (arg === "--accept-broken-chain") {
      parsed.acceptBrokenChain = true;
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

function parseLeaseTtlSeconds(value: string | undefined): number {
  if (!value) throw new Error("--ttl requires a duration like 30s, 5m, or 1h");
  const match = /^(\d+)([smh])$/.exec(value);
  if (!match) throw new Error("--ttl must use forms like 30s, 5m, or 1h");
  const amount = Number(match[1]);
  const unit = match[2];
  const multiplier = unit === "s" ? 1 : unit === "m" ? 60 : 3600;
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
  "wall_armed",
  "wall_disarmed",
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
