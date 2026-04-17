/**
 * Sanctuary wrap — Passphrase management
 *
 * On first run, generates a 32-byte random passphrase and stores it in:
 *   - macOS: Keychain (via `security add-generic-password`)
 *   - Linux / Windows / fallback: ~/.sanctuary/passphrase.enc (AES-256-GCM,
 *     key derived from hostname + uid via HKDF-SHA256)
 *
 * On subsequent runs, reads back from the same source. The goal is that a
 * user who ran `sanctuary wrap` once should never have to think about
 * passphrases again unless they want to export / migrate.
 */

import { spawn } from "node:child_process";
import { readFile, writeFile, mkdir, access } from "node:fs/promises";
import { homedir, hostname, platform, userInfo } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { gcm } from "@noble/ciphers/aes.js";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

// ── Constants ───────────────────────────────────────────────────────

const KEYCHAIN_ACCOUNT = "sanctuary";
const KEYCHAIN_SERVICE = "sanctuary-passphrase";

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
  /** Override platform detection (for tests). */
  platformOverride?: NodeJS.Platform;
  /**
   * Execute a shell command. Default runs `security` via child_process.
   * Tests inject a mock to avoid touching the real Keychain.
   */
  exec?: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  code: number | null;
}

// ── Public API ──────────────────────────────────────────────────────

/**
 * Resolve the passphrase: read from Keychain/fallback, or generate + store.
 */
export async function getOrCreatePassphrase(
  opts: PassphraseOptions = {}
): Promise<PassphraseResult> {
  const home = opts.home ?? homedir();
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;

  // 1. Try Keychain (macOS only).
  if (plat === "darwin") {
    const fromKc = await readFromKeychain(exec);
    if (fromKc) {
      return { value: fromKc, source: "keychain", location: "macOS Keychain" };
    }
  }

  // 2. Try fallback file.
  const fallback = fallbackFilePath(home);
  const fromFile = await readFromFallbackFile(fallback, home);
  if (fromFile) {
    return {
      value: fromFile,
      source: "fallback-file",
      location: fallback,
    };
  }

  // 3. Generate and store.
  const value = generatePassphrase();
  if (plat === "darwin") {
    const ok = await writeToKeychain(value, exec);
    if (ok) {
      return { value, source: "generated", location: "macOS Keychain" };
    }
  }

  await writeToFallbackFile(fallback, value, home);
  return { value, source: "generated", location: fallback };
}

/**
 * Read the stored passphrase without generating a new one.
 * Used by the `export-passphrase` subcommand.
 */
export async function readStoredPassphrase(
  opts: PassphraseOptions = {}
): Promise<PassphraseResult | null> {
  const home = opts.home ?? homedir();
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;

  if (plat === "darwin") {
    const fromKc = await readFromKeychain(exec);
    if (fromKc) {
      return { value: fromKc, source: "keychain", location: "macOS Keychain" };
    }
  }

  const fallback = fallbackFilePath(home);
  const fromFile = await readFromFallbackFile(fallback, home);
  if (fromFile) {
    return {
      value: fromFile,
      source: "fallback-file",
      location: fallback,
    };
  }

  return null;
}

/** Generate a 32-byte base64-encoded passphrase. */
export function generatePassphrase(): string {
  return randomBytes(32).toString("base64");
}

// ── Keychain (macOS) ────────────────────────────────────────────────

async function readFromKeychain(
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>
): Promise<string | null> {
  try {
    const result = await exec(
      "security",
      ["find-generic-password", "-a", KEYCHAIN_ACCOUNT, "-s", KEYCHAIN_SERVICE, "-w"]
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
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>
): Promise<boolean> {
  try {
    // -U updates in place if the item already exists.
    const result = await exec(
      "security",
      [
        "add-generic-password",
        "-U",
        "-a", KEYCHAIN_ACCOUNT,
        "-s", KEYCHAIN_SERVICE,
        "-w", value,
      ]
    );
    return result.code === 0;
  } catch {
    return false;
  }
}

// ── Fallback file (all platforms) ───────────────────────────────────

export function fallbackFilePath(home: string): string {
  return join(home, ".sanctuary", "passphrase.enc");
}

async function readFromFallbackFile(
  path: string,
  home: string
): Promise<string | null> {
  try {
    await access(path);
  } catch {
    return null;
  }
  try {
    const raw = await readFile(path);
    if (raw.length < 13) return null;
    const nonce = raw.subarray(0, 12);
    const ciphertext = raw.subarray(12);
    const key = deriveMachineKey(home);
    const cipher = gcm(key, nonce);
    const plain = cipher.decrypt(ciphertext);
    return Buffer.from(plain).toString("utf-8");
  } catch {
    return null;
  }
}

async function writeToFallbackFile(
  path: string,
  value: string,
  home: string
): Promise<void> {
  const dir = join(home, ".sanctuary");
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const nonce = randomBytes(12);
  const key = deriveMachineKey(home);
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
