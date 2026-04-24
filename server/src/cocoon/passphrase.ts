/**
 * Sanctuary wrap — Passphrase management
 *
 * On first run, generates a 32-byte random passphrase and stores it in:
 *   - macOS: Keychain (via `security add-generic-password`)
 *   - Linux: Secret Service via `secret-tool(1)` (D-Bus; GNOME Keyring,
 *     KDE Wallet 6, KeePassXC, and any libsecret-compatible backend)
 *   - Windows / no-OS-keyring fallback: <storage_path>/passphrase.enc
 *     (AES-256-GCM, key derived from hostname + uid via HKDF-SHA256)
 *
 * The Linux branch falls through to the fallback file when `secret-tool` is
 * absent, when no D-Bus session bus is running, or when the keyring refuses
 * the write; production behavior on those hosts matches the pre-existing
 * Linux path so upgrades are never downgrades.
 *
 * On subsequent runs, reads back from the same source. The goal is that a
 * user who ran `sanctuary wrap` once should never have to think about
 * passphrases again unless they want to export / migrate.
 */

import { spawn } from "node:child_process";
import { readFile, writeFile, mkdir, access } from "node:fs/promises";
import { homedir, hostname, platform, userInfo } from "node:os";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { gcm } from "@noble/ciphers/aes.js";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { resolveStoragePath, DEFAULT_STORAGE_DIR } from "../paths.js";

// ── Constants ───────────────────────────────────────────────────────

const KEYCHAIN_ACCOUNT = "sanctuary";
/** Legacy single-tenant Keychain service name — kept for backward compat. */
const KEYCHAIN_SERVICE_DEFAULT = "sanctuary-passphrase";
/** Human-readable label for Linux Secret Service items (shown in Seahorse,
 * KeePassXC, KDE KWalletManager). Invisible on macOS. */
const KEYCHAIN_LABEL = "Sanctuary Passphrase";

/** Human-readable description for an OS keyring location. Platform-aware;
 * stable public contract so callers can key off equality. */
export const OS_KEYRING_LOCATION_MACOS = "macOS Keychain";
export const OS_KEYRING_LOCATION_LINUX = "Linux Secret Service";

/**
 * True when `location` refers to an OS keyring (macOS Keychain or Linux
 * Secret Service). Callers use this instead of equality on a single string
 * when deciding whether to emit the fallback-file warning.
 */
export function isOsKeyringLocation(location: string): boolean {
  return (
    location === OS_KEYRING_LOCATION_MACOS ||
    location === OS_KEYRING_LOCATION_LINUX
  );
}

/** Where does the passphrase live? */
export type PassphraseSource = "keychain" | "fallback-file" | "generated";

export interface PassphraseResult {
  /** The resolved passphrase value (base64 of 32 random bytes). */
  value: string;
  /** Where it came from on this run. */
  source: PassphraseSource;
  /** Human-readable location string for the success notice. */
  location: string;
}

export interface PassphraseOptions {
  /** Override home directory (for tests). */
  home?: string;
  /**
   * Override the storage path (for multi-tenant deployments and tests).
   * When set, the fallback passphrase file lives at `<storagePath>/passphrase.enc`
   * and the Keychain service name is namespaced to this path, so two wrapped
   * agents on one host do not share a passphrase.
   *
   * When unset, `resolveStoragePath()` is consulted (which honours
   * `SANCTUARY_STORAGE_PATH`), and falls back to `<home>/.sanctuary` for
   * single-tenant callers that predate env-var support.
   */
  storagePath?: string;
  /** Override platform detection (for tests). */
  platformOverride?: NodeJS.Platform;
  /**
   * Execute a shell command. Default runs `security` via child_process.
   * Tests inject a mock to avoid touching the real Keychain.
   */
  exec?: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
  /**
   * Override the machine-local key derivation (for tests that simulate
   * host/user migration). Production callers leave this undefined.
   */
  deriveMachineKey?: (home: string) => Uint8Array;
}

/**
 * Raised when the fallback passphrase file exists but cannot be decrypted.
 * Never auto-regenerate in response — that would permanently destroy all
 * state encrypted under the previous passphrase. Surface the error and let
 * the user restore from backup, re-import via SANCTUARY_PASSPHRASE, or run
 * `sanctuary reset-passphrase` to recover (recovery shares, guardian quorum)
 * or destroy and start fresh.
 */
export class PassphraseUnreadableError extends Error {
  readonly path: string;
  readonly reason: string;
  constructor(path: string, reason: string) {
    super(
      `Sanctuary passphrase file at ${path} exists but could not be decrypted (${reason}).\n\n` +
        `Your existing encrypted state cannot be recovered with a new passphrase. Options:\n` +
        `  1. Restore ${path} from a backup.\n` +
        `  2. Re-import the original passphrase via SANCTUARY_PASSPHRASE=<value> sanctuary wrap ...\n` +
        `  3. Run \`sanctuary reset-passphrase\` to recover via shares or guardian quorum, or to destroy state and start fresh.\n` +
        `     See \`sanctuary reset-passphrase --help\` for the three recovery modes.\n\n` +
        `Refusing to regenerate the passphrase, that would permanently destroy the data encrypted under the previous key.`
    );
    this.name = "PassphraseUnreadableError";
    this.path = path;
    this.reason = reason;
  }
}

/** Outcome of reading the fallback passphrase file. */
type FallbackReadResult =
  | { status: "ok"; value: string }
  | { status: "not-found" }
  | { status: "unreadable"; reason: string };

export interface ExecResult {
  stdout: string;
  stderr: string;
  code: number | null;
}

// ── Public API ──────────────────────────────────────────────────────

/**
 * Resolve the passphrase: read from Keychain/fallback, or generate + store.
 *
 * Throws {@link PassphraseUnreadableError} when Keychain is empty/unavailable
 * AND the fallback file exists but cannot be decrypted. Never auto-regenerates
 * in that case — see the error class for remediation steps.
 */
export async function getOrCreatePassphrase(
  opts: PassphraseOptions = {}
): Promise<PassphraseResult> {
  const home = opts.home ?? homedir();
  const storagePath = opts.storagePath ?? resolveStoragePath(process.env, home);
  const service = keychainServiceFor(storagePath, home);
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  const derive = opts.deriveMachineKey ?? deriveMachineKey;

  // 1. Try the OS keyring.
  if (plat === "darwin") {
    const fromKc = await readFromKeychain(exec, service);
    if (fromKc) {
      return { value: fromKc, source: "keychain", location: OS_KEYRING_LOCATION_MACOS };
    }
  } else if (plat === "linux") {
    const fromSs = await readFromSecretService(exec, service);
    if (fromSs) {
      return { value: fromSs, source: "keychain", location: OS_KEYRING_LOCATION_LINUX };
    }
  }

  // 2. Try fallback file.
  const fallback = fallbackFilePath(home, storagePath);
  const fromFile = await readFromFallbackFile(fallback, home, derive);
  if (fromFile.status === "ok") {
    return {
      value: fromFile.value,
      source: "fallback-file",
      location: fallback,
    };
  }
  if (fromFile.status === "unreadable") {
    throw new PassphraseUnreadableError(fallback, fromFile.reason);
  }

  // 3. Generate and store (only reachable when no prior passphrase exists).
  const value = generatePassphrase();
  if (plat === "darwin") {
    const ok = await writeToKeychain(value, exec, service);
    if (ok) {
      return { value, source: "generated", location: OS_KEYRING_LOCATION_MACOS };
    }
  } else if (plat === "linux") {
    const ok = await writeToSecretService(value, exec, service);
    if (ok) {
      return { value, source: "generated", location: OS_KEYRING_LOCATION_LINUX };
    }
  }

  await writeToFallbackFile(fallback, value, home, derive);
  return { value, source: "generated", location: fallback };
}

/**
 * Read the stored passphrase without generating a new one.
 * Used by the `export-passphrase` subcommand.
 *
 * Throws {@link PassphraseUnreadableError} when the fallback file exists but
 * cannot be decrypted (same semantics as {@link getOrCreatePassphrase}).
 */
export async function readStoredPassphrase(
  opts: PassphraseOptions = {}
): Promise<PassphraseResult | null> {
  const home = opts.home ?? homedir();
  const storagePath = opts.storagePath ?? resolveStoragePath(process.env, home);
  const service = keychainServiceFor(storagePath, home);
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  const derive = opts.deriveMachineKey ?? deriveMachineKey;

  if (plat === "darwin") {
    const fromKc = await readFromKeychain(exec, service);
    if (fromKc) {
      return { value: fromKc, source: "keychain", location: OS_KEYRING_LOCATION_MACOS };
    }
  } else if (plat === "linux") {
    const fromSs = await readFromSecretService(exec, service);
    if (fromSs) {
      return { value: fromSs, source: "keychain", location: OS_KEYRING_LOCATION_LINUX };
    }
  }

  const fallback = fallbackFilePath(home, storagePath);
  const fromFile = await readFromFallbackFile(fallback, home, derive);
  if (fromFile.status === "ok") {
    return {
      value: fromFile.value,
      source: "fallback-file",
      location: fallback,
    };
  }
  if (fromFile.status === "unreadable") {
    throw new PassphraseUnreadableError(fallback, fromFile.reason);
  }

  return null;
}

/**
 * Persist a user-supplied passphrase into Keychain (macOS) or the fallback
 * file (all other platforms). Used by `sanctuary wrap --passphrase <value>`
 * so the value never reaches argv or the rewritten agent config.
 *
 * Fails loudly if both storage paths are unavailable — per CLAUDE.md
 * invariant 5 ("Never silently degrade to a less-secure behavior on error").
 */
export async function persistUserProvidedPassphrase(
  value: string,
  opts: PassphraseOptions = {}
): Promise<{ location: string; source: "keychain" | "fallback-file" }> {
  const home = opts.home ?? homedir();
  const storagePath = opts.storagePath ?? resolveStoragePath(process.env, home);
  const service = keychainServiceFor(storagePath, home);
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  const derive = opts.deriveMachineKey ?? deriveMachineKey;

  if (plat === "darwin") {
    const ok = await writeToKeychain(value, exec, service);
    if (ok) {
      return { location: OS_KEYRING_LOCATION_MACOS, source: "keychain" };
    }
    // Keychain failed — try fallback file before giving up.
  } else if (plat === "linux") {
    const ok = await writeToSecretService(value, exec, service);
    if (ok) {
      return { location: OS_KEYRING_LOCATION_LINUX, source: "keychain" };
    }
    // Secret Service failed — try fallback file before giving up.
  }

  const fallback = fallbackFilePath(home, storagePath);
  try {
    await writeToFallbackFile(fallback, value, home, derive);
  } catch (err) {
    throw new Error(
      `Could not persist the provided passphrase to either Keychain or ${fallback}: ` +
        `${(err as Error).message}. ` +
        `Refusing to proceed — writing the passphrase into the rewritten agent config would ` +
        `leak it as plaintext at rest and in process argv.`
    );
  }
  return { location: fallback, source: "fallback-file" };
}

/** Generate a 32-byte base64-encoded passphrase. */
export function generatePassphrase(): string {
  return randomBytes(32).toString("base64");
}

// ── Keychain (macOS) ────────────────────────────────────────────────

async function readFromKeychain(
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>,
  service: string = KEYCHAIN_SERVICE_DEFAULT
): Promise<string | null> {
  try {
    const result = await exec(
      "security",
      ["find-generic-password", "-a", KEYCHAIN_ACCOUNT, "-s", service, "-w"]
    );
    if (result.code !== 0) return null;
    const value = result.stdout.trim();
    return value.length > 0 ? value : null;
  } catch {
    return null;
  }
}

async function writeToKeychain(
  value: string,
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>,
  service: string = KEYCHAIN_SERVICE_DEFAULT
): Promise<boolean> {
  try {
    // -U updates in place if the item already exists.
    const result = await exec(
      "security",
      [
        "add-generic-password",
        "-U",
        "-a", KEYCHAIN_ACCOUNT,
        "-s", service,
        "-w", value,
      ]
    );
    return result.code === 0;
  } catch {
    return false;
  }
}

/**
 * Derive the Keychain service name for a given storage path.
 *
 * Per-tenant isolation on macOS: when two Sanctuary instances run on one
 * host with distinct `SANCTUARY_STORAGE_PATH` values, each gets its own
 * Keychain item so their state cannot be decrypted by the other instance's
 * key material.
 *
 * Backward compatibility: for the default storage path (`~/.sanctuary` with
 * no env override), the service name is the legacy `sanctuary-passphrase`,
 * so pre-existing wraps continue to read their saved passphrase.
 */
export function keychainServiceFor(
  storagePath: string,
  home: string = homedir()
): string {
  const defaultPath = join(home, DEFAULT_STORAGE_DIR);
  if (storagePath === defaultPath) return KEYCHAIN_SERVICE_DEFAULT;

  // Stable 12-char hex hash of the full storage path — short enough to be
  // legible in a Keychain listing, long enough to avoid collisions on any
  // reasonable fleet.
  const digest = sha256(Buffer.from(storagePath, "utf-8"));
  const suffix = Buffer.from(digest).toString("hex").slice(0, 12);
  return `${KEYCHAIN_SERVICE_DEFAULT}-${suffix}`;
}

// ── Secret Service (Linux) ──────────────────────────────────────────
//
// Uses `secret-tool(1)` from libsecret, the cross-desktop Secret Service
// D-Bus client. Any libsecret-compatible backend works: GNOME Keyring, KDE
// Wallet 6, KeePassXC (with the Secret Service integration enabled), or a
// bespoke backend registered on the session bus.
//
// Design choice vs. the `@node-libsecret/*` native binding: the CLI is
// already present on every major Linux distribution's default package set
// (`libsecret-tools` on Debian/Ubuntu, `libsecret` on Fedora/Arch) and
// requires zero build toolchain. A native binding would pull in node-gyp,
// gcc, and platform-specific headers at install time; that's a significant
// regression for an npm-distributed server whose install must be boring.
// The CLI path is slightly slower per call (process spawn) but the unlock
// happens once per boot.
//
// Items are keyed by the same `service` + `account` attribute pair used on
// macOS. The `--label` flag sets the human-readable name that appears in
// Seahorse / KWalletManager; it does not participate in lookup.
//
// Failure modes all fall through to the encrypted fallback file:
//   - `secret-tool` binary missing (ENOENT on spawn)
//   - no D-Bus session bus (headless CI, `DBUS_SESSION_BUS_ADDRESS` unset
//     and `--session` auto-launch fails)
//   - Secret Service daemon absent / refusing connections
//   - user cancels keyring unlock prompt
//
// Graceful degradation is per CLAUDE.md invariant 5: never auto-approve,
// never silently succeed. Here, "fail = try the next path" is the safe
// behavior because the fallback file is itself authenticated encryption.

async function readFromSecretService(
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>,
  service: string = KEYCHAIN_SERVICE_DEFAULT
): Promise<string | null> {
  try {
    const result = await exec("secret-tool", [
      "lookup",
      "service",
      service,
      "account",
      KEYCHAIN_ACCOUNT,
    ]);
    if (result.code !== 0) return null;
    // secret-tool lookup does NOT append a trailing newline to the value
    // (unlike `security -w`); trim defensively in case a future version
    // changes that, and to tolerate keyring backends that wrap the value.
    const value = result.stdout.replace(/\r?\n$/, "");
    return value.length > 0 ? value : null;
  } catch {
    return null;
  }
}

async function writeToSecretService(
  value: string,
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>,
  service: string = KEYCHAIN_SERVICE_DEFAULT
): Promise<boolean> {
  try {
    // `secret-tool store` reads the value from stdin (one line terminated
    // by a newline; the newline is stripped before storage). If an item
    // with the same attributes already exists it is replaced in place.
    const result = await exec(
      "secret-tool",
      [
        "store",
        "--label",
        KEYCHAIN_LABEL,
        "service",
        service,
        "account",
        KEYCHAIN_ACCOUNT,
      ],
      value + "\n"
    );
    return result.code === 0;
  } catch {
    return false;
  }
}

// ── Fallback file (all platforms) ───────────────────────────────────

/**
 * Resolve the encrypted fallback passphrase file path.
 *
 * When `storagePath` is supplied, the file lives at
 * `<storagePath>/passphrase.enc` — per-tenant isolation.
 *
 * When it is omitted, the legacy path `<home>/.sanctuary/passphrase.enc` is
 * returned so existing single-tenant callers keep reading their saved file.
 */
export function fallbackFilePath(home: string, storagePath?: string): string {
  if (storagePath !== undefined) return join(storagePath, "passphrase.enc");
  return join(home, DEFAULT_STORAGE_DIR, "passphrase.enc");
}

async function readFromFallbackFile(
  path: string,
  home: string,
  derive: (home: string) => Uint8Array = deriveMachineKey
): Promise<FallbackReadResult> {
  try {
    await access(path);
  } catch {
    return { status: "not-found" };
  }
  try {
    const raw = await readFile(path);
    if (raw.length < 13) {
      return { status: "unreadable", reason: "file too short to contain a valid nonce + ciphertext" };
    }
    const nonce = raw.subarray(0, 12);
    const ciphertext = raw.subarray(12);
    const key = derive(home);
    const cipher = gcm(key, nonce);
    const plain = cipher.decrypt(ciphertext);
    return { status: "ok", value: Buffer.from(plain).toString("utf-8") };
  } catch (err) {
    return {
      status: "unreadable",
      reason: (err as Error).message ?? "unknown decryption error",
    };
  }
}

async function writeToFallbackFile(
  path: string,
  value: string,
  home: string,
  derive: (home: string) => Uint8Array = deriveMachineKey
): Promise<void> {
  // Derive the parent directory from the resolved path rather than assuming
  // `<home>/.sanctuary`, so multi-tenant callers with a custom storage path
  // create the correct directory.
  const dir = dirname(path);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const nonce = randomBytes(12);
  const key = derive(home);
  const cipher = gcm(key, nonce);
  const ciphertext = cipher.encrypt(Buffer.from(value, "utf-8"));
  const payload = Buffer.concat([nonce, Buffer.from(ciphertext)]);
  await writeFile(path, payload, { mode: 0o600 });
}

/**
 * Derive a machine-local key from hostname + uid + home path.
 * This is NOT cryptographically strong authentication — it only ensures that
 * the encrypted file cannot be read off a different machine. If an attacker
 * already has local access, they can trivially re-derive this.
 */
function deriveMachineKey(home: string): Uint8Array {
  const info = userInfo();
  const material = Buffer.from(
    `${hostname()}:${info.uid}:${info.username}:${home}`,
    "utf-8"
  );
  return hkdf(sha256, material, undefined, "sanctuary-passphrase-v1", 32);
}

// ── Default exec implementation ─────────────────────────────────────

async function defaultExec(
  cmd: string,
  args: string[],
  input?: string
): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => { stdout += d.toString(); });
    child.stderr.on("data", (d) => { stderr += d.toString(); });
    child.on("error", reject);
    child.on("close", (code) => resolve({ stdout, stderr, code }));
    if (input !== undefined) {
      child.stdin.write(input);
    }
    child.stdin.end();
  });
}
