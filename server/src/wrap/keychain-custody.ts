/**
 * Sanctuary wrap - OS-keyring-held custody key (second factor)
 *
 * A random 32-byte key stored in the OS keyring (macOS Keychain / Linux
 * Secret Service) that wraps the fortress master alongside the user-held
 * recovery key. Machine-resident but user-visible (Keychain Access /
 * Seahorse) and OS-managed; it is only ever a *second* factor - never the
 * sole custody of a trust-bearing fortress.
 *
 * Deliberately NO fallback file: a machine-bound file secret the user never
 * sees is the F3 lockout generator this build removes. When no OS keyring
 * is available this module returns null and the caller enrolls a different
 * second factor (or records an explicit degraded install mode).
 *
 * RATIFIED POSTURE (2026-07-22, docs/custody-recovery-posture.md): this
 * machine-resident factor may UNLOCK the master for daily use but must never
 * BOOTSTRAP new human-held custody. No verb enrolls a new passphrase, mints a
 * recovery key, or rotates the master from a keychain-only unlock — the OS
 * keyring releases this key to any process in the logged-in session, so such
 * a verb would let anyone at an unlocked machine silently take over custody.
 * Custody-changing ceremonies require a human-held credential (passphrase or
 * recovery key). The absence of that verb is the security property; do not
 * "fix" it without superseding the posture doc.
 */

import { spawn } from "node:child_process";
import { homedir, platform } from "node:os";
import { join, resolve } from "node:path";
import { sha256 } from "@noble/hashes/sha256";

import { generateRandomKey } from "../core/random.js";
import { toBase64url, fromBase64url } from "../core/encoding.js";
import { DEFAULT_STORAGE_DIR } from "../paths.js";
import type { ExecResult } from "./exec-result.js";

const CUSTODY_ACCOUNT = "sanctuary";
const CUSTODY_SERVICE_PREFIX = "sanctuary-custody";
const CUSTODY_LABEL = "Sanctuary Custody Key";
const RECOVERY_SERVICE_PREFIX = "sanctuary-recovery";
const RECOVERY_LABEL = "Sanctuary Recovery Key";

export interface KeychainCustodyOptions {
  /** Override home directory (for tests). */
  home?: string;
  /** Override platform detection (for tests). */
  platformOverride?: NodeJS.Platform;
  /** Command executor (tests inject a mock). */
  exec?: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
}

export class RecoveryKeyKeychainStoreError extends Error {
  readonly service: string;

  constructor(service: string) {
    super(
      `Recovery key could not be stored in OS keyring service '${service}'; refusing to continue.`
    );
    this.name = "RecoveryKeyKeychainStoreError";
    this.service = service;
  }
}

function serviceForStoragePath(
  prefix: string,
  storagePath: string,
  home: string
): string {
  const defaultPath = resolve(join(home, DEFAULT_STORAGE_DIR));
  const canonicalStorage = resolve(storagePath);
  if (canonicalStorage === defaultPath) return prefix;
  const digest = sha256(Buffer.from(canonicalStorage, "utf-8"));
  const suffix = Buffer.from(digest).toString("hex").slice(0, 16);
  return `${prefix}-${suffix}`;
}

/**
 * Keyring service name for the fortress's custody key. Same canonical-path
 * hashing scheme as the passphrase service (stable across cosmetic path
 * differences), distinct prefix so the custody key and the passphrase are
 * separate keyring items.
 */
export function custodyServiceFor(
  storagePath: string,
  home: string = homedir()
): string {
  return serviceForStoragePath(CUSTODY_SERVICE_PREFIX, storagePath, home);
}

/**
 * Keyring service name for the fortress recovery key. Same canonical-path
 * hashing as passphrase and custody services, but with a separate prefix so
 * the recovery key is a distinct OS-keyring item.
 */
export function recoveryKeyServiceFor(
  storagePath: string,
  home: string = homedir()
): string {
  return serviceForStoragePath(RECOVERY_SERVICE_PREFIX, storagePath, home);
}

function escapeForSecurity(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

/**
 * Why a keyring read produced no key. The boot diagnostic (element 2/3) needs
 * to tell "the keyring item is genuinely absent" apart from "the keyring is
 * present but this process cannot reach it". Collapsing both to `null`
 * (the old behavior) silently dropped the keychain factor with zero signal,
 * which is exactly how the headless/SSH lockout surfaced (the macOS login
 * Keychain returns error 36 / errSecInteractionNotAllowed over SSH).
 *
 *  - "found":        a valid 32-byte key was returned.
 *  - "not-found":    the keyring is reachable and reports no such item.
 *  - "unreachable":  the keyring exists but could not be queried in this
 *                    session (macOS error 36 / errSecInteractionNotAllowed,
 *                    a locked keychain, no GUI / no D-Bus session bus, or the
 *                    keyring binary missing). The item MAY exist; we cannot say.
 */
export type KeychainReadStatus = "found" | "not-found" | "unreachable";

export interface KeychainReadResult {
  status: KeychainReadStatus;
  /** Present only when status === "found". */
  key?: Uint8Array;
  /** Non-secret reason string for the boot diagnostic (never key material). */
  detail?: string;
}

/**
 * macOS `security` exit code for errSecInteractionNotAllowed. The CLI maps the
 * Security.framework status -25308 to exit code 36 (the classic "user
 * interaction is not allowed" / locked-keychain-over-SSH signal). We treat
 * this (and the textual marker, in case a future CLI changes the numeric code)
 * as "unreachable", not "not-found".
 */
const SECURITY_INTERACTION_NOT_ALLOWED_CODE = 36;
const SECURITY_INTERACTION_NOT_ALLOWED_MARKERS = [
  "interaction is not allowed",
  "interactionnotallowed",
  "-25308",
  "25308",
];

/** macOS `security` exit code for errSecItemNotFound (status -25300). */
const SECURITY_ITEM_NOT_FOUND_CODE = 44;

/**
 * Classify a non-zero macOS `security` outcome into found / not-found /
 * unreachable. Exported so the wrap passphrase path (passphrase.ts) reuses
 * the SAME error-36 / errSecInteractionNotAllowed detection rather than
 * re-implementing it (the fortress-key-root-cause-2026-06-23 class: a locked
 * login keychain over SSH must read as "unreachable", never "not-found").
 */
export function classifyDarwinFailure(result: ExecResult): KeychainReadResult {
  const stderr = (result.stderr ?? "").toLowerCase();
  const interactionBlocked =
    result.code === SECURITY_INTERACTION_NOT_ALLOWED_CODE ||
    SECURITY_INTERACTION_NOT_ALLOWED_MARKERS.some((m) => stderr.includes(m));
  if (interactionBlocked) {
    return {
      status: "unreachable",
      detail:
        "macOS Keychain is locked or unreachable in this session " +
        "(error 36 / interaction not allowed), typical over SSH / headless",
    };
  }
  if (result.code === SECURITY_ITEM_NOT_FOUND_CODE) {
    return { status: "not-found", detail: "no such keychain item" };
  }
  // Any other non-zero exit: be conservative and treat as unreachable so the
  // factor is never silently dropped as "absent" when it may exist.
  return {
    status: "unreachable",
    detail: `keychain query failed (security exit ${result.code ?? "unknown"})`,
  };
}

/**
 * Classify a non-zero Linux `secret-tool` outcome into not-found vs
 * unreachable. Exported so the wrap passphrase path (passphrase.ts) reuses
 * the SAME D-Bus/locked-collection detection rather than re-implementing it.
 */
export function classifyLinuxFailure(result: ExecResult): KeychainReadResult {
  // secret-tool exits 1 with empty stdout for BOTH "no such item" and a
  // refused/locked Secret Service. Distinguish by stderr: a D-Bus / collection
  // error means the keyring is unreachable; a clean empty result means the
  // item is simply absent.
  const stderr = (result.stderr ?? "").toLowerCase();
  const reachableButAbsent =
    stderr.length === 0 ||
    stderr.includes("no such") ||
    stderr.includes("not found");
  if (reachableButAbsent) {
    return { status: "not-found", detail: "no such secret-service item" };
  }
  return {
    status: "unreachable",
    detail:
      "Linux Secret Service is locked or unreachable in this session " +
      "(no D-Bus session bus, locked collection, or refused connection)",
  };
}

/**
 * Read a keyring item by service, classifying the outcome (element 3).
 * Never throws on a keyring failure: a spawn error (binary missing, no
 * keyring at all) is "unreachable", same as a locked keychain, so the caller
 * always falls through to explicit env factors rather than treating the
 * keyring as authoritatively empty.
 */
async function readKeyClassified(
  exec: NonNullable<KeychainCustodyOptions["exec"]>,
  plat: NodeJS.Platform,
  service: string
): Promise<KeychainReadResult> {
  let result: ExecResult;
  try {
    if (plat === "darwin") {
      result = await exec("security", [
        "find-generic-password",
        "-a",
        CUSTODY_ACCOUNT,
        "-s",
        service,
        "-w",
      ]);
    } else if (plat === "linux") {
      result = await exec("secret-tool", [
        "lookup",
        "service",
        service,
        "account",
        CUSTODY_ACCOUNT,
      ]);
    } else {
      return {
        status: "unreachable",
        detail: "no supported OS keyring on this platform",
      };
    }
  } catch {
    // Spawn failed (binary missing / ENOENT): the keyring is not usable here.
    return {
      status: "unreachable",
      detail:
        plat === "linux"
          ? "secret-tool not installed (no Secret Service access)"
          : "OS keyring binary unavailable",
    };
  }

  if (result.code === 0) {
    const value = result.stdout.replace(/\r?\n$/, "").trim();
    if (value.length === 0) {
      return { status: "not-found", detail: "keychain item empty" };
    }
    let bytes: Uint8Array;
    try {
      bytes = fromBase64url(value);
    } catch {
      // A present-but-malformed value is a real item that is corrupt; treat as
      // unreachable (the operator should investigate) rather than "not-found".
      return { status: "unreachable", detail: "keychain item is malformed" };
    }
    if (bytes.length !== 32) {
      return { status: "unreachable", detail: "keychain item has wrong length" };
    }
    return { status: "found", key: bytes };
  }

  return plat === "darwin"
    ? classifyDarwinFailure(result)
    : classifyLinuxFailure(result);
}

/**
 * Read-and-classify a keyring item by service, for the boot diagnostic and
 * orphan detection. Public so the boot paths can probe a factor's reachability
 * without resolving the master.
 */
export async function readKeychainKeyStatus(
  service: string,
  opts: KeychainCustodyOptions = {}
): Promise<KeychainReadResult> {
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  return readKeyClassified(exec, plat, service);
}

/**
 * Read a keyring item by service, returning the key bytes or null. Thin
 * compatibility wrapper over {@link readKeyClassified}: callers that only need
 * the key (not the reachability reason) keep the original null-on-miss shape,
 * but error-36 / locked / not-installed all still return null here exactly as
 * before; they just no longer LOSE the distinction, because the classifying
 * read is available separately.
 */
async function readKey(
  exec: NonNullable<KeychainCustodyOptions["exec"]>,
  plat: NodeJS.Platform,
  service: string
): Promise<Uint8Array | null> {
  const result = await readKeyClassified(exec, plat, service);
  return result.status === "found" ? (result.key ?? null) : null;
}

async function writeKey(
  exec: NonNullable<KeychainCustodyOptions["exec"]>,
  plat: NodeJS.Platform,
  service: string,
  value: string,
  label: string
): Promise<boolean> {
  if (/[\r\n]/.test(value)) return false;
  try {
    if (plat === "darwin") {
      // Secret via `security -i` batch script on stdin, never argv (F5).
      const batch =
        `add-generic-password -U -a "${escapeForSecurity(CUSTODY_ACCOUNT)}" ` +
        `-s "${escapeForSecurity(service)}" -w "${escapeForSecurity(value)}"\n`;
      const result = await exec("security", ["-i"], batch);
      return result.code === 0;
    }
    if (plat === "linux") {
      const result = await exec(
        "secret-tool",
        [
          "store",
          "--label",
          label,
          "service",
          service,
          "account",
          CUSTODY_ACCOUNT,
        ],
        value + "\n"
      );
      return result.code === 0;
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Read the fortress's keyring custody key, creating it if absent. Returns
 * null when no OS keyring is usable (no fallback file by design - F3).
 * Creation is read-back-verified so a keyring that accepts the write but
 * cannot return it never counts as an enrolled factor.
 */
export async function getOrCreateKeychainCustodyKey(
  storagePath: string,
  opts: KeychainCustodyOptions = {}
): Promise<Uint8Array | null> {
  const home = opts.home ?? homedir();
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  const service = custodyServiceFor(storagePath, home);

  const existing = await readKey(exec, plat, service);
  if (existing) return existing;

  const key = generateRandomKey();
  const encoded = toBase64url(key);
  const wrote = await writeKey(exec, plat, service, encoded, CUSTODY_LABEL);
  if (!wrote) return null;

  const readBack = await readKey(exec, plat, service);
  if (!readBack || !buffersEqual(readBack, key)) return null;
  return key;
}

/** Read-only variant for unlock paths. */
export async function readKeychainCustodyKey(
  storagePath: string,
  opts: KeychainCustodyOptions = {}
): Promise<Uint8Array | null> {
  const home = opts.home ?? homedir();
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  return readKey(exec, plat, custodyServiceFor(storagePath, home));
}

/**
 * Classify the keychain CUSTODY-KEY item for a fortress (the second factor
 * that wraps the master). Feeds the boot diagnostic (element 2) and orphan
 * detection (element 5): "found" / "not-found" / "unreachable", with the
 * service name so the operator can locate / unlock it.
 */
export async function probeKeychainCustodyKey(
  storagePath: string,
  opts: KeychainCustodyOptions = {}
): Promise<KeychainReadResult & { service: string }> {
  const home = opts.home ?? homedir();
  const service = custodyServiceFor(storagePath, home);
  const result = await readKeychainKeyStatus(service, opts);
  return { ...result, service };
}

/**
 * Classify the keychain RECOVERY-KEY escrow item for a fortress (the
 * convenient machine-local copy of the user-held recovery key that #661
 * escrows). Feeds orphan detection (element 5): if a fortress was provisioned
 * with a keychain recovery escrow and that item is now "not-found", the only
 * recovery copy may have been deleted; warn before lockout.
 */
export async function probeKeychainRecoveryKey(
  storagePath: string,
  opts: KeychainCustodyOptions = {}
): Promise<KeychainReadResult & { service: string }> {
  const home = opts.home ?? homedir();
  const service = recoveryKeyServiceFor(storagePath, home);
  const result = await readKeychainKeyStatus(service, opts);
  // Zero the recovered key immediately: orphan detection only needs presence,
  // never the secret itself.
  if (result.key) result.key.fill(0);
  const safe: KeychainReadResult & { service: string } = {
    status: result.status,
    service,
  };
  if (result.detail !== undefined) safe.detail = result.detail;
  return safe;
}

/**
 * Store the user fortress recovery key in the OS keyring and verify it by
 * reading it back. This is the convenient, machine-local store for the same
 * already-minted recovery key that is disclosed once to the operator. It is
 * never a wrap derivation change, and failure is fail-closed.
 */
export async function storeRecoveryKeyInKeychain(
  storagePath: string,
  recoveryKey: string,
  opts: KeychainCustodyOptions = {}
): Promise<{ service: string }> {
  const home = opts.home ?? homedir();
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  const service = recoveryKeyServiceFor(storagePath, home);
  let recoveryKeyBytes: Uint8Array;

  try {
    recoveryKeyBytes = fromBase64url(recoveryKey);
  } catch {
    throw new RecoveryKeyKeychainStoreError(service);
  }

  try {
    if (recoveryKeyBytes.length !== 32) {
      throw new RecoveryKeyKeychainStoreError(service);
    }
    const wrote = await writeKey(
      exec,
      plat,
      service,
      recoveryKey,
      RECOVERY_LABEL
    );
    if (!wrote) throw new RecoveryKeyKeychainStoreError(service);

    const readBack = await readKey(exec, plat, service);
    if (!readBack || !buffersEqual(readBack, recoveryKeyBytes)) {
      throw new RecoveryKeyKeychainStoreError(service);
    }
    return { service };
  } finally {
    recoveryKeyBytes.fill(0);
  }
}

function buffersEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

async function defaultExec(
  cmd: string,
  args: string[],
  input?: string
): Promise<ExecResult> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(cmd, args, { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => {
      stdout += d.toString();
    });
    child.stderr.on("data", (d) => {
      stderr += d.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => resolvePromise({ stdout, stderr, code }));
    if (input !== undefined) {
      child.stdin.write(input);
    }
    child.stdin.end();
  });
}
