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
import { dirname, join, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { gcm } from "@noble/ciphers/aes.js";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { resolveStoragePath, DEFAULT_STORAGE_DIR } from "../paths.js";
import { fromBase64url, toBase64url } from "../core/encoding.js";

// ── Constants ───────────────────────────────────────────────────────

const KEYCHAIN_ACCOUNT = "sanctuary";
/** Legacy single-tenant Keychain service name — kept for backward compat. */
const KEYCHAIN_SERVICE_DEFAULT = "sanctuary-passphrase";
const FALLBACK_FILE_VERSION = 2;
const FALLBACK_FILE_ALG = "aes-256-gcm";
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
  | { status: "ok"; value: string; legacy: boolean }
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

  const legacyService = legacyKeychainServiceFor(storagePath, home);

  // 1. Try the OS keyring (current 16-hex name, then legacy 12-hex fallback).
  if (plat === "darwin") {
    const fromKc = await readFromKeychain(exec, service);
    if (fromKc) {
      return { value: fromKc, source: "keychain", location: OS_KEYRING_LOCATION_MACOS };
    }
    // Legacy fallback: try the old 12-hex service name for pre-v1.2.3 entries.
    if (legacyService !== service) {
      const fromLegacy = await readFromKeychain(exec, legacyService);
      if (fromLegacy) {
        return { value: fromLegacy, source: "keychain", location: OS_KEYRING_LOCATION_MACOS };
      }
    }
  } else if (plat === "linux") {
    const fromSs = await readFromSecretService(exec, service);
    if (fromSs) {
      return { value: fromSs, source: "keychain", location: OS_KEYRING_LOCATION_LINUX };
    }
    if (legacyService !== service) {
      const fromLegacy = await readFromSecretService(exec, legacyService);
      if (fromLegacy) {
        return { value: fromLegacy, source: "keychain", location: OS_KEYRING_LOCATION_LINUX };
      }
    }
  }

  // 2. Try fallback file.
  const fallback = fallbackFilePath(home, storagePath);
  const fromFile = await readFromFallbackFile(fallback, home, derive);
  if (fromFile.status === "ok") {
    if (fromFile.legacy) {
      await writeToFallbackFile(fallback, fromFile.value, home, derive);
    }
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
  //    Writes always go to the new 16-hex service name.
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
  const legacyService = legacyKeychainServiceFor(storagePath, home);
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  const derive = opts.deriveMachineKey ?? deriveMachineKey;

  if (plat === "darwin") {
    const fromKc = await readFromKeychain(exec, service);
    if (fromKc) {
      return { value: fromKc, source: "keychain", location: OS_KEYRING_LOCATION_MACOS };
    }
    if (legacyService !== service) {
      const fromLegacy = await readFromKeychain(exec, legacyService);
      if (fromLegacy) {
        return { value: fromLegacy, source: "keychain", location: OS_KEYRING_LOCATION_MACOS };
      }
    }
  } else if (plat === "linux") {
    const fromSs = await readFromSecretService(exec, service);
    if (fromSs) {
      return { value: fromSs, source: "keychain", location: OS_KEYRING_LOCATION_LINUX };
    }
    if (legacyService !== service) {
      const fromLegacy = await readFromSecretService(exec, legacyService);
      if (fromLegacy) {
        return { value: fromLegacy, source: "keychain", location: OS_KEYRING_LOCATION_LINUX };
      }
    }
  }

  const fallback = fallbackFilePath(home, storagePath);
  const fromFile = await readFromFallbackFile(fallback, home, derive);
  if (fromFile.status === "ok") {
    if (fromFile.legacy) {
      await writeToFallbackFile(fallback, fromFile.value, home, derive);
    }
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
        `leak it as plaintext at rest and in process argv.`,
      { cause: err }
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

/**
 * Escape a value for a double-quoted token in a `security -i` batch script.
 * The security binary treats backslash as an escape inside quoted strings, so
 * backslash and double-quote must be escaped.
 */
function escapeForSecurity(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

async function writeToKeychain(
  value: string,
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>,
  service: string = KEYCHAIN_SERVICE_DEFAULT
): Promise<boolean> {
  // F5 (HIGH): never pass the secret as an argv element. Process argv is
  // world-readable on macOS (`ps -ww`), so `add-generic-password -w <value>`
  // would leak the master passphrase to any other local user. Deliver the
  // value through a `security -i` batch script on stdin, where it never appears
  // in argv. (`security`'s own `-w` prompt reads /dev/tty, not stdin, so batch
  // mode is the only argv-safe non-interactive path.) Mirrors the broker
  // keychain backend's create/unlock pattern.
  //
  // A batch script is line-delimited, so a value containing a newline cannot be
  // embedded; reject it rather than truncating or falling back to a leaky form.
  if (/[\r\n]/.test(value)) return false;
  try {
    // -U updates in place if the item already exists.
    const batch =
      `add-generic-password -U -a "${escapeForSecurity(KEYCHAIN_ACCOUNT)}" ` +
      `-s "${escapeForSecurity(service)}" -w "${escapeForSecurity(value)}"\n`;
    const result = await exec("security", ["-i"], batch);
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
 *
 * Path canonicalization: uses `path.resolve()` (NOT `realpath`) to normalize
 * `.`, `..`, doubled separators, and trailing slashes before comparison and
 * hashing. Two processes targeting the same canonical path always produce the
 * same service name regardless of cosmetic path differences.
 */
export function keychainServiceFor(
  storagePath: string,
  home: string = homedir()
): string {
  const defaultPath = resolve(join(home, DEFAULT_STORAGE_DIR));
  const canonicalStorage = resolve(storagePath);
  if (canonicalStorage === defaultPath) return KEYCHAIN_SERVICE_DEFAULT;

  // Stable 16-char hex hash of the canonical storage path. Birthday bound
  // ~2^32 paths (was 12 hex / 2^24 prior to v1.2.3).
  const digest = sha256(Buffer.from(canonicalStorage, "utf-8"));
  const suffix = Buffer.from(digest).toString("hex").slice(0, 16);
  return `${KEYCHAIN_SERVICE_DEFAULT}-${suffix}`;
}

/**
 * Legacy service name (12-hex suffix) for backward-compatible keychain reads.
 * Used by the fallback path in keychain lookup: try the current 16-hex name
 * first, fall back to the legacy 12-hex name for pre-v1.2.3 entries.
 */
export function legacyKeychainServiceFor(
  storagePath: string,
  home: string = homedir()
): string {
  const defaultPath = resolve(join(home, DEFAULT_STORAGE_DIR));
  const canonicalStorage = resolve(storagePath);
  if (canonicalStorage === defaultPath) return KEYCHAIN_SERVICE_DEFAULT;

  const digest = sha256(Buffer.from(canonicalStorage, "utf-8"));
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
    const parsed = parseFallbackEnvelope(raw);
    const key = derive(home);
    if (parsed) {
      const cipher = gcm(key, parsed.nonce, fallbackFileAad(path));
      const plain = cipher.decrypt(parsed.ciphertext);
      return {
        status: "ok",
        value: Buffer.from(plain).toString("utf-8"),
        legacy: false,
      };
    }
    if (raw.length < 13) {
      return { status: "unreadable", reason: "file too short to contain a valid nonce + ciphertext" };
    }
    const nonce = raw.subarray(0, 12);
    const ciphertext = raw.subarray(12);
    const cipher = gcm(key, nonce);
    const plain = cipher.decrypt(ciphertext);
    return {
      status: "ok",
      value: Buffer.from(plain).toString("utf-8"),
      legacy: true,
    };
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
  const cipher = gcm(key, nonce, fallbackFileAad(path));
  const ciphertext = cipher.encrypt(Buffer.from(value, "utf-8"));
  const payload = Buffer.from(
    JSON.stringify({
      v: FALLBACK_FILE_VERSION,
      alg: FALLBACK_FILE_ALG,
      aad: "storage-path",
      nonce: toBase64url(nonce),
      ct: toBase64url(ciphertext),
    }),
    "utf-8",
  );
  await writeFile(path, payload, { mode: 0o600 });
}

function fallbackFileAad(path: string): Uint8Array {
  return Buffer.from(`sanctuary-passphrase:${resolve(dirname(path))}`, "utf-8");
}

function parseFallbackEnvelope(raw: Buffer): {
  nonce: Uint8Array;
  ciphertext: Uint8Array;
} | null {
  if (raw[0] !== 0x7b) return null;
  try {
    const parsed = JSON.parse(raw.toString("utf-8")) as Record<string, unknown>;
    if (
      parsed.v !== FALLBACK_FILE_VERSION ||
      parsed.alg !== FALLBACK_FILE_ALG ||
      parsed.aad !== "storage-path" ||
      typeof parsed.nonce !== "string" ||
      typeof parsed.ct !== "string"
    ) {
      return null;
    }
    return {
      nonce: fromBase64url(parsed.nonce),
      ciphertext: fromBase64url(parsed.ct),
    };
  } catch {
    return null;
  }
}

/**
 * Derive a machine-local key from hostname + uid + home path.
 * This is NOT cryptographically strong authentication, it only ensures that
 * the encrypted file cannot be read off a different machine. If an attacker
 * already has local access, they can trivially re-derive this.
 *
 * Threat model: see `server/docs/keychain-schema.md`, "Windows or
 * no-OS-keyring fallback: encrypted file" section. The fallback file is
 * intended for single-user machines without an OS keyring, NOT for
 * multi-user machines, shared CI runners, or snapshotted VMs.
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
