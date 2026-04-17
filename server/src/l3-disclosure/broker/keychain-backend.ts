/**
 * Sanctuary MCP Server — L3 Secret Broker: macOS Keychain Backend
 *
 * Uses a dedicated Sanctuary keychain (NOT the user's login keychain) via
 * the `/usr/bin/security` CLI. The keychain is unlocked once at daemon
 * start with a passphrase supplied out-of-band (env or interactive); all
 * subsequent reads are silent.
 *
 * Design rationale: see Review/Sanctuary/V0.10.0_Spike_KeychainUnlock.md
 * (option C — dedicated keychain). We explicitly DO NOT use `-A`
 * (allow-any-app) or `-T <path>` (per-binary ACL) because both lose
 * security guarantees compared to the dedicated-keychain model.
 *
 * Secret values NEVER touch disk outside the keychain file itself, which
 * is AES-encrypted at rest by macOS under the passphrase. Secret values
 * NEVER appear in argv for long-lived commands (passed only via the
 * `security -w ... -s ...` add/rotate path at write time; reads return
 * on stdout, not in argv).
 */

import { spawn } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import {
  type Backend,
  BackendLockedError,
  BackendUnavailableError,
  SecretNotFoundError,
} from "./backend-interface.js";

const SECURITY_BIN = "/usr/bin/security";
/** Service prefix for every item stored by the broker. */
const SERVICE = "sanctuary-broker";

export interface KeychainBackendOptions {
  /** Absolute path to the keychain file. Defaults to ~/Library/Keychains/sanctuary.keychain-db. */
  keychainPath?: string;
}

interface SpawnResult {
  stdout: string;
  stderr: string;
  code: number;
}

/**
 * Execute the `security` binary. `input` is written to stdin if provided
 * (used for interactive unlock so the passphrase never appears in argv).
 */
async function runSecurity(args: string[], input?: string): Promise<SpawnResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(SECURITY_BIN, args, { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", (err: Error & { code?: string }) => {
      if (err.code === "ENOENT") {
        reject(
          new BackendUnavailableError(
            `/usr/bin/security not found — KeychainBackend requires macOS`
          )
        );
        return;
      }
      reject(err);
    });
    child.on("close", (code: number | null) => {
      resolve({ stdout, stderr, code: code ?? -1 });
    });
    if (input !== undefined) {
      child.stdin.write(input);
    }
    child.stdin.end();
  });
}

export class KeychainBackend implements Backend {
  private readonly keychainPath: string;
  /** In-process unlock flag. Represents our belief about keychain state; a
   * separate `security unlock-keychain` call is still issued on init. */
  private unlocked = false;

  constructor(opts?: KeychainBackendOptions) {
    this.keychainPath =
      opts?.keychainPath ??
      join(homedir(), "Library", "Keychains", "sanctuary.keychain-db");
  }

  async ensureInitialized(passphrase: string): Promise<void> {
    if (this.isPlatformUnsupported()) {
      throw new BackendUnavailableError(
        "KeychainBackend requires macOS (darwin). Use a different Backend on Linux/Windows."
      );
    }
    if (!passphrase || passphrase.length < 1) {
      throw new Error("ensureInitialized requires a non-empty passphrase");
    }
    if (existsSync(this.keychainPath)) {
      await this.unlock(passphrase);
      return;
    }
    // Ensure parent dir exists
    mkdirSync(dirname(this.keychainPath), { recursive: true });

    // Use `security -i` batch mode so the passphrase travels via stdin
    // and never appears in process argv (where it would be visible to
    // `ps`). See Spike 1 for threat-model rationale.
    const createBatch =
      `create-keychain -p "${escapeForSecurity(passphrase)}" "${this.keychainPath}"\n`;
    const create = await runSecurity(["-i"], createBatch);
    if (create.code !== 0) {
      throw new BackendUnavailableError(
        `Failed to create broker keychain: ${create.stderr.trim() || "unknown error"}`
      );
    }
    // Note: we intentionally do NOT call set-keychain-settings here.
    // On a keychain not in the user's search list, set-keychain-settings
    // triggers a SecurityAgent GUI prompt even when invoked non-
    // interactively — which deadlocks a headless daemon. The default
    // keychain settings (10-minute idle timeout, lock-on-sleep enabled)
    // are acceptable for v0.10.0: the broker unlocks on every startup
    // and, if a relock occurs mid-session, the next readSecret will
    // fail with a BackendLockedError that the wrap process can recover
    // from by re-unlocking with the cached passphrase. v0.10.1 will
    // surface a cleaner auto-relock handler.
    // Fresh keychains are created unlocked; trust that and mark in-memory.
    this.unlocked = true;
  }

  async unlock(passphrase: string): Promise<void> {
    if (this.isPlatformUnsupported()) {
      throw new BackendUnavailableError(
        "KeychainBackend requires macOS (darwin)"
      );
    }
    if (!existsSync(this.keychainPath)) {
      throw new BackendUnavailableError(
        `Broker keychain not found at ${this.keychainPath}. Run 'sanctuary secrets add' to create it.`
      );
    }
    const batch =
      `unlock-keychain -p "${escapeForSecurity(passphrase)}" "${this.keychainPath}"\n`;
    const result = await runSecurity(["-i"], batch);
    if (result.code !== 0) {
      throw new BackendUnavailableError(
        `Failed to unlock broker keychain: ${result.stderr.trim() || "incorrect passphrase"}`
      );
    }
    this.unlocked = true;
  }

  async isUnlocked(): Promise<boolean> {
    if (!this.unlocked) return false;
    if (!existsSync(this.keychainPath)) return false;
    return true;
  }

  async addSecret(name: string, value: string): Promise<void> {
    this.assertUnlocked();
    validateSecretName(name);
    // Check existence first to preserve explicit "rotate required" semantics.
    const existing = await this.findGeneric(name, { returnValue: false });
    if (existing !== null) {
      throw new Error(`Secret already exists: ${name} (use rotateSecret to replace)`);
    }
    // `add-generic-password` with -U would update; we intentionally don't use -U
    // to keep add/rotate distinct.
    const res = await runSecurity([
      "add-generic-password",
      "-s",
      SERVICE,
      "-a",
      name,
      "-w",
      value,
      this.keychainPath,
    ]);
    if (res.code !== 0) {
      throw new Error(
        `Failed to add secret: ${redactSecurityError(res.stderr)}`
      );
    }
  }

  async readSecret(name: string): Promise<string> {
    this.assertUnlocked();
    validateSecretName(name);
    const value = await this.findGeneric(name, { returnValue: true });
    if (value === null) {
      throw new SecretNotFoundError(name);
    }
    return value;
  }

  async rotateSecret(name: string, newValue: string): Promise<void> {
    this.assertUnlocked();
    validateSecretName(name);
    const existing = await this.findGeneric(name, { returnValue: false });
    if (existing === null) {
      throw new SecretNotFoundError(name);
    }
    // Delete then re-add atomically. If re-add fails, callers will see
    // the secret as missing — strictly safer than leaving stale value.
    await this.deleteSecret(name);
    const res = await runSecurity([
      "add-generic-password",
      "-s",
      SERVICE,
      "-a",
      name,
      "-w",
      newValue,
      this.keychainPath,
    ]);
    if (res.code !== 0) {
      throw new Error(
        `Failed to rotate secret: ${redactSecurityError(res.stderr)}`
      );
    }
  }

  async deleteSecret(name: string): Promise<void> {
    this.assertUnlocked();
    validateSecretName(name);
    const res = await runSecurity([
      "delete-generic-password",
      "-s",
      SERVICE,
      "-a",
      name,
      this.keychainPath,
    ]);
    if (res.code !== 0) {
      throw new SecretNotFoundError(name);
    }
  }

  async listSecretNames(): Promise<string[]> {
    this.assertUnlocked();
    const res = await runSecurity([
      "dump-keychain",
      this.keychainPath,
    ]);
    if (res.code !== 0) {
      throw new Error(`Failed to list secrets: ${redactSecurityError(res.stderr)}`);
    }
    // Parse dump-keychain output: items are separated by "keychain:" lines.
    // Each item's account name appears as `"acct"<blob>="<name>"` when it
    // is a generic-password item from our SERVICE. We filter by SERVICE.
    const names: string[] = [];
    const blocks = res.stdout.split(/^keychain: /m);
    for (const block of blocks) {
      if (!block.includes(`"svce"<blob>="${SERVICE}"`)) continue;
      const match = block.match(/"acct"<blob>="([^"]+)"/);
      if (match && match[1]) names.push(match[1]);
    }
    // Dedupe just in case.
    return Array.from(new Set(names));
  }

  private assertUnlocked(): void {
    if (!this.unlocked) {
      throw new BackendLockedError();
    }
  }

  private isPlatformUnsupported(): boolean {
    return process.platform !== "darwin";
  }

  /**
   * Find a generic-password item by account name. Returns the value (if
   * returnValue) or empty string on match, or null on absent.
   */
  private async findGeneric(
    name: string,
    opts: { returnValue: boolean }
  ): Promise<string | null> {
    const args = [
      "find-generic-password",
      "-s",
      SERVICE,
      "-a",
      name,
    ];
    if (opts.returnValue) args.push("-w");
    args.push(this.keychainPath);
    const res = await runSecurity(args);
    if (res.code !== 0) {
      // security exits 44 ("SecKeychainSearchCopyNext: The specified item
      // could not be found") when the item is absent. Treat any non-zero
      // with stderr containing "could not be found" as absent.
      if (
        res.stderr.includes("could not be found") ||
        res.stderr.includes("SecKeychain")
      ) {
        return null;
      }
      // Other failure modes.
      throw new Error(`find-generic-password failed: ${redactSecurityError(res.stderr)}`);
    }
    if (opts.returnValue) {
      // `-w` prints the value on stdout with a trailing newline.
      return res.stdout.replace(/\n$/, "");
    }
    return "";
  }
}

/**
 * Validate a secret name. Reject anything that could be abused to inject
 * into a security CLI argument or break our dump-keychain parser.
 */
function validateSecretName(name: string): void {
  if (!name || name.length > 256) {
    throw new Error("Secret name must be 1..256 characters");
  }
  if (!/^[A-Za-z0-9._\-:/]+$/.test(name)) {
    throw new Error(
      `Secret name contains invalid characters: ${JSON.stringify(name)} (allowed: letters, digits, .-_/:)`
    );
  }
}

/**
 * Scrub any value-looking substrings from security stderr before passing
 * to the caller. Current security(1) versions do not echo values in
 * stderr, but we are defensive.
 */
function redactSecurityError(stderr: string): string {
  // Drop anything that looks like a hex/base64 blob (>=16 chars).
  return stderr
    .replace(/[A-Za-z0-9+/=]{16,}/g, "[REDACTED]")
    .replace(/\n/g, " ")
    .trim();
}

/**
 * Escape a passphrase for the `security -i` batch protocol, which uses
 * shell-like quoting. Security binary interprets backslash as escape
 * within quoted strings.
 */
function escapeForSecurity(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}
