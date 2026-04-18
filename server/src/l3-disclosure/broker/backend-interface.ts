/**
 * Sanctuary MCP Server — L3 Selective Disclosure: Secret Broker Backend Interface
 *
 * Pluggable backend interface for the credential broker. v0.10.0 ships a
 * macOS Keychain backend only. v0.10.1 will add Linux Secret Service
 * (libsecret via `secret-tool`) and Windows Credential Manager backends
 * implementing this same interface.
 *
 * Design principles:
 * - Raw credential values never touch disk outside the OS keychain.
 * - The backend owns unlock state — callers cannot bypass it.
 * - `readSecret` is the hot path; implementations MUST be silent (no GUI
 *   prompt) once `ensureInitialized`/`unlock` has succeeded.
 * - A failed `readSecret` throws — callers MUST NOT fall back to plaintext.
 */

export type SecretScope = "read" | "rotate";

export interface SecretMetadata {
  name: string;
  created_at: string;
  last_accessed_at?: string;
}

export class BackendLockedError extends Error {
  constructor(message = "Broker backend is locked; unlock before reading secrets") {
    super(message);
    this.name = "BackendLockedError";
  }
}

export class SecretNotFoundError extends Error {
  constructor(name: string) {
    super(`Secret not found: ${name}`);
    this.name = "SecretNotFoundError";
  }
}

export class BackendUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BackendUnavailableError";
  }
}

export interface Backend {
  /**
   * Initialize the backing store on first run. Idempotent — callable on
   * every startup. If the backing store does not exist, create it protected
   * by the passphrase. If it exists, this is a no-op and unlock() is used
   * instead.
   */
  ensureInitialized(passphrase: string): Promise<void>;

  /**
   * Unlock the backing store so subsequent reads are silent.
   * Throws if the passphrase is incorrect or the backing store does not exist.
   */
  unlock(passphrase: string): Promise<void>;

  /**
   * Report whether the backing store is currently unlocked and ready for reads.
   */
  isUnlocked(): Promise<boolean>;

  /**
   * Store a new secret. Throws if `name` already exists; callers must
   * explicitly `rotateSecret` to replace.
   */
  addSecret(name: string, value: string): Promise<void>;

  /**
   * Read a secret value. Silent — throws BackendLockedError if backend is
   * locked and SecretNotFoundError if the name is unknown. Returns the
   * raw credential value.
   */
  readSecret(name: string): Promise<string>;

  /**
   * Replace an existing secret's value. Throws if the secret does not exist.
   */
  rotateSecret(name: string, newValue: string): Promise<void>;

  /**
   * Permanently delete a secret.
   */
  deleteSecret(name: string): Promise<void>;

  /**
   * List stored secret names. MUST NOT return values. Used by
   * `sanctuary secrets list`.
   */
  listSecretNames(): Promise<string[]>;
}
