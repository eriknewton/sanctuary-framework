/**
 * Sanctuary wrap — Passphrase management
 *
 * On first run, generates a 32-byte random passphrase and stores it in:
 *   - macOS: Keychain (via `security add-generic-password`)
 *   - Linux: Secret Service via `secret-tool(1)` (D-Bus; GNOME Keyring,
 *     KDE Wallet 6, KeePassXC, and any libsecret-compatible backend)
 *
 * F3 (sovereign-custody build, 2026-06-12): when no OS keyring is usable,
 * generation FAILS CLOSED (SilentCustodyRefusedError) instead of silently
 * writing a machine-bound fallback file the user never sees — that was a
 * lockout generator. The encrypted fallback file remains supported for
 *   - READING passphrases persisted by earlier versions, and
 *   - USER-SUPPLIED passphrases (persistUserProvidedPassphrase) — the user
 *     holds the secret, so machine loss is not custody loss.
 *
 * On subsequent runs, reads back from the same source. The goal is that a
 * user who ran `sanctuary wrap` once should never have to think about
 * passphrases again unless they want to export / migrate.
 */

import { mkdir } from "node:fs/promises";
import { homedir, hostname, platform, userInfo } from "node:os";
import { dirname, join, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { gcm } from "@noble/ciphers/aes.js";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { resolveStoragePath, DEFAULT_STORAGE_DIR } from "../paths.js";
import { fromBase64url, toBase64url } from "../core/encoding.js";
import { readFileCustody, writeFileCustody } from "../storage/custody-fs.js";
import type { ExecResult } from "./exec-result.js";
import { execKeychain } from "./keychain-exec.js";
import {
  classifyDarwinFailure,
  classifyLinuxFailure,
  type KeychainReadStatus,
} from "./keychain-custody.js";

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

/**
 * Raised when the OS keyring is reachable-but-LOCKED (or not interactive in
 * this session) so the stored passphrase cannot be read: typically a locked
 * macOS login Keychain over SSH (error 36 / errSecInteractionNotAllowed) or a
 * Linux Secret Service with no D-Bus session bus / a refused collection.
 *
 * This is a HARD fail-closed, not a fall-through. The bug it closes
 * (fortress-key-root-cause-2026-06-23 class, live in the wrap path): a locked
 * keyring used to read as "passphrase absent", so wrap generated a NEW
 * passphrase and wrote it with `add-generic-password -U`, CLOBBERING the
 * existing entry and stranding the fortress. We now refuse to generate or
 * overwrite when the keyring is merely unreachable: the original stored
 * passphrase is untouched, and the operator is told to unlock and retry.
 *
 * The message names NO secret material (CLAUDE.md #6): it carries the keyring
 * location and remediation only, never the passphrase or any key bytes.
 */
export class PassphraseKeyringUnreachableError extends Error {
  readonly location: string;
  readonly detail: string;
  constructor(location: string, detail: string) {
    // Double-quoted concatenation (not template literals) on purpose: the
    // structure guard's comment-stripper mis-tracks backtick balance when a
    // new backtick template message sits next to the escaped-backtick message
    // above, which made downstream JSDoc em-dashes leak into the code scan.
    super(
      "Sanctuary: the OS keyring (" + location + ") is LOCKED or not " +
        "reachable in this session, so your stored passphrase could not be " +
        "read (" + detail + ").\n\n" +
        "Sanctuary did NOT modify your stored passphrase and did NOT generate " +
        "a new one (doing so would overwrite and strand your existing " +
        "custody).\n\n" +
        "To continue:\n" +
        "  - Run from a desktop session and unlock the keyring via its GUI\n" +
        "    (Keychain Access on macOS; Seahorse / KWallet / your Secret " +
        "Service keyring on Linux), then retry; or\n" +
        "  - Provide the passphrase explicitly for this run:\n" +
        "      SANCTUARY_PASSPHRASE=<your fortress passphrase> sanctuary " +
        "wrap ...\n\n" +
        "This is common over SSH or right after a reboot, when the login " +
        "keyring is still locked."
    );
    this.name = "PassphraseKeyringUnreachableError";
    this.location = location;
    this.detail = detail;
  }
}

/**
 * Three-state outcome of reading the passphrase from an OS keyring. Mirrors the
 * keychain-custody.ts {@link KeychainReadStatus} contract so both paths agree
 * on what "unreachable" means (locked / error 36 / no D-Bus), but carries the
 * passphrase string when found rather than raw key bytes.
 */
type KeyringReadResult =
  | { status: "found"; value: string }
  | { status: "not-found" }
  | { status: "unreachable"; detail: string };

/** Outcome of reading the fallback passphrase file. */
type FallbackReadResult =
  | { status: "ok"; value: string; legacy: boolean }
  | { status: "not-found" }
  | { status: "unreadable"; reason: string };

// `ExecResult` now lives in the leaf module exec-result.ts so passphrase.ts and
// keychain-custody.ts can share it without an import cycle (passphrase.ts also
// imports the failure classifiers from keychain-custody.ts). Re-exported here
// to preserve the public surface: tests import { ExecResult } from
// "./passphrase.js".
export type { ExecResult } from "./exec-result.js";

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
  const fromKeyring = await readPassphraseFromKeyring(
    exec,
    plat,
    service,
    legacyService
  );
  if (fromKeyring.status === "found") return fromKeyring.result;

  // 2. Try the encrypted fallback file. This is a NON-DESTRUCTIVE read and is
  //    safe even when the keyring was unreachable: an existing user-supplied
  //    fallback value is a legitimate custody source (the documented F3 Linux
  //    no-Secret-Service path). We try it BEFORE failing closed so a locked
  //    keyring does not block a fortress that has a usable fallback file.
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

  // 3. HARD FAIL-CLOSED: the keyring was LOCKED / unreachable (macOS error 36 /
  //    no D-Bus) AND there is no fallback custody. The ONLY remaining action
  //    would be to generate a NEW passphrase and write it with `-U`, which on
  //    a re-wrap CLOBBERS the (likely present but unreadable) keyring entry and
  //    strands the fortress (fortress-key-root-cause-2026-06-23 class). Refuse:
  //    tell the operator to unlock the keyring and retry; the stored passphrase
  //    is left untouched.
  if (fromKeyring.status === "unreachable") {
    throw new PassphraseKeyringUnreachableError(
      fromKeyring.location,
      fromKeyring.detail
    );
  }

  // 4. Generate and store (only reachable when no prior passphrase exists and
  //    the keyring was genuinely reachable-but-empty). Writes always go to the
  //    new 16-hex service name.
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

  // F3 (sovereign-custody build): NEVER silently generate a custody secret
  // the user never sees into a machine-bound fallback file. That was a
  // lockout generator — lose or wipe the machine and the fortress is gone,
  // with the user holding no factor at all. Fail closed with remediation
  // instead. (A USER-SUPPLIED passphrase may still be persisted to the
  // fallback file via persistUserProvidedPassphrase — the user holds it.)
  const { SilentCustodyRefusedError } = await import(
    "../core/master-custody.js"
  );
  throw new SilentCustodyRefusedError(
    plat === "darwin" || plat === "linux"
      ? "OS keyring unavailable or refused the write"
      : `no OS keyring integration on platform '${plat}'`
  );
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

  // Same precedence as getOrCreatePassphrase: keyring, then the non-destructive
  // fallback file, then fail closed on an unreachable keyring (so a locked
  // keyring with no fallback custody is reported, never silently "absent").
  const fromKeyring = await readPassphraseFromKeyring(
    exec,
    plat,
    service,
    legacyService
  );
  if (fromKeyring.status === "found") return fromKeyring.result;

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

  // Keyring locked / unreachable and no fallback custody: fail closed rather
  // than report a misleading "no passphrase stored" (which a caller might act
  // on by regenerating and clobbering the locked entry).
  if (fromKeyring.status === "unreachable") {
    throw new PassphraseKeyringUnreachableError(
      fromKeyring.location,
      fromKeyring.detail
    );
  }

  return null;
}

/**
 * Outcome of probing the OS keyring for the passphrase across the current and
 * legacy service names.
 *  - "found":       a value was read; return it.
 *  - "not-found":   the keyring is reachable and reports no item; the caller
 *                   proceeds to the fallback file / first-wrap generation.
 *  - "unreachable": the keyring is locked / not reachable in this session
 *                   (macOS error 36, no D-Bus, etc.). The caller may still read
 *                   an existing encrypted fallback file (a non-destructive
 *                   recovery), but it must NEVER generate a new passphrase and
 *                   `-U`-overwrite, which would clobber the (likely present but
 *                   unreadable) keyring entry. When no fallback custody exists,
 *                   the caller fails closed with PassphraseKeyringUnreachableError.
 */
type KeyringLookup =
  | { status: "found"; result: PassphraseResult }
  | { status: "not-found" }
  | { status: "unreachable"; location: string; detail: string };

/**
 * Read the passphrase from the OS keyring (current service name, then the legacy
 * fallback). Returns a {@link KeyringLookup} the caller acts on: an
 * "unreachable" keyring (locked / error 36 / no D-Bus) is reported, NOT thrown
 * here, so the caller can still read a non-destructive encrypted fallback file
 * before deciding to fail closed. The one thing the caller must never do on
 * "unreachable" is generate + `-U`-overwrite (the clobber bug); that decision
 * lives in the caller, which knows whether a fallback custody source exists.
 */
async function readPassphraseFromKeyring(
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>,
  plat: NodeJS.Platform,
  service: string,
  legacyService: string
): Promise<KeyringLookup> {
  let read: (svc: string) => Promise<KeyringReadResult>;
  let location: string;
  if (plat === "darwin") {
    read = (svc) => readFromKeychain(exec, svc);
    location = OS_KEYRING_LOCATION_MACOS;
  } else if (plat === "linux") {
    read = (svc) => readFromSecretService(exec, svc);
    location = OS_KEYRING_LOCATION_LINUX;
  } else {
    return { status: "not-found" };
  }

  const primary = await read(service);
  if (primary.status === "found") {
    return {
      status: "found",
      result: { value: primary.value, source: "keychain", location },
    };
  }
  if (primary.status === "unreachable") {
    return { status: "unreachable", location, detail: primary.detail };
  }

  // Legacy fallback: try the old 12-hex service name for pre-v1.2.3 entries.
  if (legacyService !== service) {
    const legacy = await read(legacyService);
    if (legacy.status === "found") {
      return {
        status: "found",
        result: { value: legacy.value, source: "keychain", location },
      };
    }
    if (legacy.status === "unreachable") {
      return { status: "unreachable", location, detail: legacy.detail };
    }
  }

  return { status: "not-found" };
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

/**
 * Read the passphrase from the macOS Keychain, classifying the outcome into
 * found / not-found / unreachable. REUSES the keychain-custody.ts
 * {@link classifyDarwinFailure} classifier so a locked login keychain (exit 36
 * / errSecInteractionNotAllowed, the SSH / fresh-reboot case) reads as
 * "unreachable" and never as "not-found" (the latter is what let the caller
 * silently regenerate + `-U`-clobber the existing entry).
 *
 * A spawn failure (the `security` binary missing) is treated as "not-found":
 * on real macOS `security` always exists, and a platform without it should
 * fall through to the fallback file exactly as before, not hard-fail.
 */
async function readFromKeychain(
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>,
  service: string = KEYCHAIN_SERVICE_DEFAULT
): Promise<KeyringReadResult> {
  let result: ExecResult;
  try {
    result = await exec(
      "security",
      ["find-generic-password", "-a", KEYCHAIN_ACCOUNT, "-s", service, "-w"]
    );
  } catch {
    // Binary missing / spawn error: not reachable here, but on macOS this does
    // not happen. Fall through to the fallback file rather than hard-failing.
    return { status: "not-found" };
  }
  if (result.code === 0) {
    const value = result.stdout.trim();
    return value.length > 0
      ? { status: "found", value }
      : { status: "not-found" };
  }
  const classified = classifyDarwinFailure(result);
  return toKeyringReadResult(classified.status, classified.detail);
}

/** Map a keychain-custody classification onto the passphrase read result. */
function toKeyringReadResult(
  status: KeychainReadStatus,
  detail: string | undefined
): KeyringReadResult {
  if (status === "unreachable") {
    return { status: "unreachable", detail: detail ?? "keyring unreachable" };
  }
  // "found" cannot occur here (the classifiers only run on a non-zero exit);
  // any non-unreachable classification is treated as a genuine miss.
  return { status: "not-found" };
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

/**
 * Read the passphrase from the Linux Secret Service, classifying the outcome
 * into found / not-found / unreachable. REUSES the keychain-custody.ts
 * {@link classifyLinuxFailure} classifier so a locked collection / no-D-Bus
 * session reads as "unreachable" (hard fail-closed) and a clean empty result
 * reads as "not-found".
 *
 * A spawn failure (`secret-tool` not installed) is treated as "not-found": the
 * documented Linux degradation path falls through to the encrypted fallback
 * file when no Secret Service client is present, and that behavior is
 * preserved: only a reachable-but-locked keyring is a hard fail.
 */
async function readFromSecretService(
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>,
  service: string = KEYCHAIN_SERVICE_DEFAULT
): Promise<KeyringReadResult> {
  let result: ExecResult;
  try {
    result = await exec("secret-tool", [
      "lookup",
      "service",
      service,
      "account",
      KEYCHAIN_ACCOUNT,
    ]);
  } catch {
    // secret-tool not installed: fall through to the fallback file (the
    // documented no-Secret-Service degradation), not a hard fail.
    return { status: "not-found" };
  }
  if (result.code === 0) {
    // secret-tool lookup does NOT append a trailing newline to the value
    // (unlike `security -w`); trim defensively in case a future version
    // changes that, and to tolerate keyring backends that wrap the value.
    const value = result.stdout.replace(/\r?\n$/, "");
    return value.length > 0
      ? { status: "found", value }
      : { status: "not-found" };
  }
  const classified = classifyLinuxFailure(result);
  return toKeyringReadResult(classified.status, classified.detail);
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
  let raw: Buffer;
  try {
    raw = await readFileCustody(path, {
      mode: { rejectGroupOrOther: true },
      verifyPathIdentity: true,
    });
  } catch (err) {
    const code =
      err instanceof Error && "code" in err
        ? (err as NodeJS.ErrnoException).code
        : undefined;
    if (code === "ENOENT") return { status: "not-found" };
    return {
      status: "unreadable",
      reason: (err as Error).message ?? "unknown read error",
    };
  }
  try {
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
  await writeFileCustody(path, payload, { mode: 0o600, parentMode: 0o700 });
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
  // Routed through the single credential-CLI chokepoint so tests can never
  // reach the operator's real login keychain. See src/wrap/keychain-exec.ts.
  return execKeychain(cmd, args, input);
}
