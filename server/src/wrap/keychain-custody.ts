/**
 * Sanctuary wrap — OS-keyring-held custody key (second factor)
 *
 * A random 32-byte key stored in the OS keyring (macOS Keychain / Linux
 * Secret Service) that wraps the fortress master alongside the user-held
 * recovery key. Machine-resident but user-visible (Keychain Access /
 * Seahorse) and OS-managed; it is only ever a *second* factor — never the
 * sole custody of a trust-bearing fortress.
 *
 * Deliberately NO fallback file: a machine-bound file secret the user never
 * sees is the F3 lockout generator this build removes. When no OS keyring
 * is available this module returns null and the caller enrolls a different
 * second factor (or records an explicit degraded install mode).
 */

import { spawn } from "node:child_process";
import { homedir, platform } from "node:os";
import { join, resolve } from "node:path";
import { sha256 } from "@noble/hashes/sha256";

import { generateRandomKey } from "../core/random.js";
import { toBase64url, fromBase64url } from "../core/encoding.js";
import { DEFAULT_STORAGE_DIR } from "../paths.js";
import type { ExecResult } from "./passphrase.js";

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

async function readKey(
  exec: NonNullable<KeychainCustodyOptions["exec"]>,
  plat: NodeJS.Platform,
  service: string
): Promise<Uint8Array | null> {
  try {
    let result: ExecResult;
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
      return null;
    }
    if (result.code !== 0) return null;
    const value = result.stdout.replace(/\r?\n$/, "").trim();
    if (value.length === 0) return null;
    const bytes = fromBase64url(value);
    return bytes.length === 32 ? bytes : null;
  } catch {
    return null;
  }
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
 * null when no OS keyring is usable (no fallback file by design — F3).
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
