/**
 * Sanctuary MCP Server — local fortress unlock (Rung 1 fresh-host onboarding)
 *
 * ONE credential-resolution + master-unlock chokepoint for the ordinary local
 * memory verbs (`memory_ingest` / `memory_emit` / `memory_transcode` /
 * `memory_transcode_restore` and the memory-archive export/import carriage).
 * Before this module those verbs resolved credentials inline and only ever
 * consulted argv/stdin/env; on a fresh host the operator's fortress passphrase
 * already lives in the OS keyring (put there by `sanctuary protect`), so the
 * first memory call had no way to reach it without the operator re-typing a
 * secret. This helper adds that final fallback — the EXACT-fortress keyring —
 * without changing the wire/at-rest surface and without ever minting custody.
 *
 * Precedence (first present source wins, then that ONE credential is tried):
 *   1. passphrase read from stdin (`--passphrase-stdin`)
 *   2. legacy `--passphrase` argv value (already warned about by the caller)
 *   3. SANCTUARY_PASSPHRASE
 *   4. SANCTUARY_RECOVERY_KEY
 *   5. the EXACT-fortress stored passphrase — the OS keyring
 *      (macOS Keychain / Linux Secret Service) or the encrypted fallback file
 *      NAMESPACED to this fortress's storage path, via {@link readStoredPassphrase}.
 *
 * Custody-safety invariants (why this is a distinct module, not a flag on the
 * old path):
 *  - It calls {@link readStoredPassphrase}, NEVER `getOrCreatePassphrase`: a
 *    read-only lookup that can fail closed but can never GENERATE a passphrase
 *    and `-U`-clobber a locked keyring entry (the strand-the-fortress bug).
 *  - It passes the EXACT `storagePath` so the keyring service name is the one
 *    bound to THIS fortress (`keychainServiceFor`), never the default fortress's
 *    entry read by mistake against a `--fortress` target.
 *  - It NEVER bootstraps: the master unlock runs without a first-run policy, so
 *    a virgin/absent fortress fails closed rather than inventing fresh custody.
 *  - A `readOnly` session additionally refuses the one journaled pre-envelope
 *    custody migration, which is the module's only write, so a diagnostic verb
 *    can promise the fortress is unchanged on EVERY fortress shape.
 *  - The failure result carries a secret-free remediation string only — never a
 *    passphrase, recovery key, or key byte (CLAUDE.md #6).
 *  - Success returns ONLY the master key (and a non-secret source label); the
 *    resolved credential string is never returned to the caller.
 */

import { homedir, platform } from "node:os";

import type { StorageBackend } from "../storage/interface.js";
import {
  unlockExistingMasterReadOnly,
  resolveCliMasterKey,
  acquireFortressMasterWriteBarrier,
  CustodyUnlockError,
  CustodyCredentialMissingError,
} from "../core/master-custody.js";
import {
  CrossProcessLockError,
  type MasterWriteBarrierLease,
  type MasterWriteBarrierOptions,
} from "../storage/cross-process-lock.js";
import {
  readStoredPassphrase,
  PassphraseKeyringUnreachableError,
  PassphrasePathIdentityError,
  PassphraseUnreadableError,
  type ExecResult,
} from "../wrap/passphrase.js";
import {
  readKeychainCustodyKeyStatus,
  type KeychainReadResult,
} from "../wrap/keychain-custody.js";

/**
 * Non-secret label naming which of the five precedence sources supplied the
 * credential that unlocked the fortress. Safe to log/audit; carries no bytes.
 */
export type LocalFortressCredentialSource =
  | "passphrase-stdin"
  | "passphrase-argv"
  | "env-passphrase"
  | "env-recovery-key"
  | "stored-passphrase"
  | "stored-custody-key";

/**
 * Failure taxonomy for a secret-free remediation. Each maps to a distinct
 * operator action; none of them ever carries credential material.
 *  - "absent":     no credential could be resolved from ANY of the five sources
 *                  (nothing on stdin/argv/env, and the keyring reports no stored
 *                  passphrase for this fortress), OR the fortress has no custody
 *                  envelope to unlock. The operator must supply a credential.
 *  - "locked":     the OS keyring holds the passphrase but is locked / not
 *                  reachable in this session (SSH, fresh reboot). Unlock it or
 *                  pass the passphrase explicitly.
 *  - "unreadable": the encrypted fallback passphrase file exists but will not
 *                  decrypt on this machine (host/user migration, corruption).
 *  - "mismatch":   a credential was resolved but does not unlock THIS fortress.
 *  - "other":      any other custody-establishment refusal (rotation in
 *                  progress, orphaned state); the underlying message is
 *                  already secret-free and is surfaced verbatim.
 *  - "migration_required": NOT a credential problem. The credential resolved
 *                  and is valid, but this fortress predates the custody
 *                  envelope and the caller declared {@link
 *                  LocalFortressUnlockOptions.readOnly}, so the one-time
 *                  migration write was refused. A caller that renders this as
 *                  "no credential available" tells the operator to fix a
 *                  credential that is already correct.
 */
export type LocalFortressUnlockFailure =
  | "absent"
  | "locked"
  | "unreadable"
  | "mismatch"
  | "other"
  | "migration_required";

export type LocalFortressUnlockResult =
  | {
      readonly ok: true;
      /** The 32-byte fortress master key. The caller owns zeroing it. */
      readonly masterKey: Uint8Array;
      /** Which precedence source supplied the credential (non-secret). */
      readonly source: LocalFortressCredentialSource;
      /**
       * Present only for a `writeIntent` unlock: the shared master-rotation
       * barrier the caller MUST hold until its final fortress write and then
       * release. Absent for a read/export unlock. A write verb that drops this
       * without holding it reopens the concurrent-rotation corruption window
       * (S1 / AGENTS rule 12).
       */
      readonly barrier?: MasterWriteBarrierLease;
    }
  | {
      readonly ok: false;
      readonly failure: LocalFortressUnlockFailure;
      /** Secret-free, operator-facing remediation. Never key material. */
      readonly message: string;
    };

export interface LocalFortressUnlockOptions {
  /** Connected fortress storage backend (`<storagePath>/state`). */
  storage: StorageBackend;
  /**
   * The EXACT resolved fortress storage path. Used ONLY to namespace the
   * keyring lookup ({@link readStoredPassphrase}) to this fortress and as the
   * `storagePathHint` for diagnostics — never for crypto. Must be the same path
   * whose `state` subdirectory `storage` reads, or the keyring service name will
   * not match the fortress being unlocked.
   */
  storagePath: string;
  /**
   * One line already read from stdin (`--passphrase-stdin`). Empty string or
   * undefined means "no stdin credential"; the module never reads stdin itself.
   */
  passphraseFromStdin?: string;
  /** Legacy `--passphrase` argv value, when the caller accepts one. */
  passphraseFromArgv?: string;
  /** Environment to read SANCTUARY_PASSPHRASE / SANCTUARY_RECOVERY_KEY from. */
  env?: NodeJS.ProcessEnv;
  /** Override home directory (tests; keyring fallback-file location). */
  home?: string;
  /** Override platform detection (tests). Passed through to the keyring read. */
  platformOverride?: NodeJS.Platform;
  /**
   * Override the keyring/`security`/`secret-tool` exec (tests). Passed through
   * to {@link readStoredPassphrase}; production leaves it undefined.
   */
  exec?: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
  /**
   * Test seam for the stored-passphrase read. Defaults to the real
   * {@link readStoredPassphrase}. Injected so a test can exercise the
   * precedence and refusal logic without a real keyring.
   */
  readStored?: typeof readStoredPassphrase;
  /** Test seam for the read-only machine-local custody-factor lookup. */
  readCustody?: (
    storagePath: string,
    opts?: KeychainCustodyOptions,
  ) => Promise<KeychainReadResult>;
  /**
   * Declare a WRITE session. When true, the shared master-rotation barrier is
   * acquired BEFORE the master is unlocked and returned in the success result;
   * the caller holds it through its final fortress write, then releases it, so a
   * concurrent `rotate-master` serializes behind the writer or the writer fails
   * closed — never commits old-master ciphertext (S1 / AGENTS rule 12). Omitted
   * or false keeps the pre-existing lock-free read/export behavior.
   */
  writeIntent?: boolean;
  /**
   * Declare a READ-ONLY session: this unlock must leave the fortress
   * byte-for-byte unchanged. The ordinary read/export unlock is already
   * lock-free and uses {@link unlockExistingMasterReadOnly}, but it retains ONE
   * write path — the journaled pre-envelope custody migration below — which a
   * diagnostic must never trigger on the operator's behalf. With this set that
   * migration is refused instead of performed, so "this command wrote nothing"
   * stays true on a legacy fortress too.
   *
   * Failure mode to expect: on a pre-envelope fortress a read-only caller gets
   * a refusal where a write-capable caller would have succeeded. That is the
   * point; the remedy is to run a custody verb first, not to drop this flag.
   *
   * Mutually exclusive with {@link writeIntent}.
   */
  readOnly?: boolean;
  /**
   * The storage instance the write barrier binds to (writeIntent only). Defaults
   * to `storage`. Pass the RAW backend when `storage` is a wrapper that delegates
   * `write` to a base instance (e.g. the exit-admission write guard), because the
   * local write fence keys on the instance whose `write` actually runs. The
   * unlock READS are unaffected: the wrapper and its base read the same bytes.
   */
  barrierStorage?: StorageBackend;
  /** TEST ONLY: drive the shared master-rotation barrier seams (writeIntent). */
  __testMasterWriteBarrierOptions?: MasterWriteBarrierOptions;
}

type KeychainCustodyOptions = Parameters<typeof readKeychainCustodyKeyStatus>[1];

/**
 * Resolve a credential by precedence and unlock the fortress master key, adding
 * the EXACT-fortress keyring as the final fallback. Returns ONLY the master key
 * on success (never the credential), or a secret-free remediation on failure.
 * Never generates custody and never mutates the stored passphrase.
 */
export async function unlockLocalFortress(
  opts: LocalFortressUnlockOptions,
): Promise<LocalFortressUnlockResult> {
  if (opts.readOnly === true && opts.writeIntent === true) {
    // A caller bug, not an operator condition: one session cannot both promise
    // to write nothing and reserve the write barrier. Throwing fails the call
    // closed rather than silently honoring whichever flag is checked first.
    throw new Error(
      "unlockLocalFortress: readOnly and writeIntent are mutually exclusive",
    );
  }
  if (!opts.writeIntent) {
    // Read/export unlock: pre-existing lock-free behavior, no barrier.
    return resolveLocalFortressMaster(opts);
  }
  // Write unlock: hold the shared master-rotation barrier from BEFORE the
  // unlock until the caller's final write. Acquired first so a rotator that is
  // already draining cannot admit this writer late. Fails closed (no degrade)
  // on an environmental capability loss: a write verb must refuse, never write
  // unbarriered (S1 / S5 coordination).
  let barrier: MasterWriteBarrierLease;
  try {
    barrier = await acquireFortressMasterWriteBarrier(
      opts.barrierStorage ?? opts.storage,
      opts.__testMasterWriteBarrierOptions,
    );
  } catch (error) {
    if (error instanceof CrossProcessLockError) {
      return {
        ok: false,
        failure: "other",
        message:
          `the fortress write barrier could not be acquired: ${error.message}`,
      };
    }
    throw error;
  }
  let result: LocalFortressUnlockResult;
  try {
    result = await resolveLocalFortressMaster(opts);
  } catch (error) {
    await barrier.release().catch(() => undefined);
    throw error;
  }
  if (!result.ok) {
    await barrier.release().catch(() => undefined);
    return result;
  }
  return { ...result, barrier };
}

async function resolveLocalFortressMaster(
  opts: LocalFortressUnlockOptions,
): Promise<LocalFortressUnlockResult> {
  const env = opts.env ?? process.env;
  const home = opts.home ?? homedir();
  const readStored = opts.readStored ?? readStoredPassphrase;

  const stdinPassphrase =
    opts.passphraseFromStdin && opts.passphraseFromStdin.length > 0
      ? opts.passphraseFromStdin
      : undefined;

  // Resolve credentials by precedence. Sources 1–4 are caller-held; source 5
  // is the exact-fortress stored passphrase and source 6 is the machine-local
  // custody key enrolled by interactive init. Explicit credentials always win.
  // When both stored factors exist, passphrase is tried first and custody-key
  // is retained only as an authenticated fallback for a stale passphrase.
  let passphrase: string | undefined;
  let recoveryKey: string | undefined;
  let custodyKey: Uint8Array | undefined;
  let custodyFallbackKey: Uint8Array | undefined;
  let custodyUnavailableDetail: string | undefined;
  let source: LocalFortressCredentialSource | undefined;
  try {
    if (stdinPassphrase !== undefined) {
      passphrase = stdinPassphrase;
      source = "passphrase-stdin";
    } else if (opts.passphraseFromArgv !== undefined) {
      passphrase = opts.passphraseFromArgv;
      source = "passphrase-argv";
    } else if (env.SANCTUARY_PASSPHRASE) {
      passphrase = env.SANCTUARY_PASSPHRASE;
      source = "env-passphrase";
    } else if (env.SANCTUARY_RECOVERY_KEY) {
      recoveryKey = env.SANCTUARY_RECOVERY_KEY;
      source = "env-recovery-key";
    } else {
    // Source 5: the EXACT-fortress stored passphrase. `readStoredPassphrase`
    // NEVER generates — it reads the keyring/fallback for THIS storage path and
    // fails closed (throws) when the keyring is locked or the fallback file is
    // corrupt, so a locked keyring can never be mistaken for "no credential".
    let stored: Awaited<ReturnType<typeof readStoredPassphrase>> = null;
    let storedFailure: LocalFortressUnlockFailure | undefined;
    let storedMessage: string | undefined;
    try {
      stored = await readStored({
        storagePath: opts.storagePath,
        home,
        // Read-only: a memory verb must never rewrite the at-rest passphrase
        // file, so a legacy-format upgrade is deferred to a custody verb.
        readOnly: true,
        ...(opts.platformOverride !== undefined
          ? { platformOverride: opts.platformOverride }
          : {}),
        ...(opts.exec !== undefined ? { exec: opts.exec } : {}),
      });
    } catch (error) {
      if (error instanceof PassphraseKeyringUnreachableError) {
        storedFailure = "locked";
        storedMessage = error.message;
      } else if (error instanceof PassphraseUnreadableError) {
        storedFailure = "unreadable";
        storedMessage = error.message;
      } else if (error instanceof PassphrasePathIdentityError) {
        storedFailure = "other";
        storedMessage = error.message;
      } else {
        storedFailure = "other";
        storedMessage =
          "the stored fortress passphrase could not be read; no credential or secret detail was emitted";
      }
    }
    if (stored && stored.value.length > 0) {
      passphrase = stored.value;
      source = "stored-passphrase";
    }

    const readCustody = opts.readCustody ?? readKeychainCustodyKeyStatus;
    let custody: KeychainReadResult;
    try {
      custody = await readCustody(opts.storagePath, {
        home,
        ...(opts.platformOverride !== undefined
          ? { platformOverride: opts.platformOverride }
          : {}),
        ...(opts.exec !== undefined ? { exec: opts.exec } : {}),
      });
    } catch {
      custody = {
        status: "unreachable",
        detail: "the stored custody-key identity could not be determined",
      };
    }
    if (custody.status === "found" && custody.key) {
      if (source === undefined) {
        custodyKey = custody.key;
        source = "stored-custody-key";
      } else {
        custodyFallbackKey = custody.key;
      }
    } else if (source === undefined) {
      if (storedFailure !== undefined) {
        return {
          ok: false,
          failure: storedFailure,
          message: storedMessage ?? "the stored fortress credential could not be read",
        };
      }
      if (custody.status === "unreachable") {
        custodyUnavailableDetail = custody.detail;
        return {
          ok: false,
          failure: "locked",
          message:
            custody.detail ??
            "the OS keyring custody factor is locked or unreachable in this session",
        };
      }
    } else if (custody.status === "unreachable") {
      custodyUnavailableDetail = custody.detail;
    }
    }

  if (source === undefined) {
    return {
      ok: false,
      failure: "absent",
      message: absentCredentialRemediation(opts.storagePath),
    };
  }

  let masterKey: Uint8Array;
  try {
    masterKey = await unlockExistingMasterReadOnly(opts.storage, {
      // Existing envelope only: a read/export verb cannot mint or migrate
      // custody and therefore remains usable without a custody-write lock.
      ...(passphrase !== undefined ? { passphrase } : {}),
      ...(recoveryKey !== undefined ? { recoveryKey } : {}),
      ...(custodyKey !== undefined ? { keychainKey: custodyKey } : {}),
      storagePathHint: opts.storagePath,
    });
  } catch (error) {
    // CustodyCredentialMissingError EXTENDS CustodyUnlockError, so check the
    // subclass first: "no custody envelope to unlock" (absent) is a different
    // remediation than "credential does not match" (mismatch).
    if (error instanceof CustodyCredentialMissingError) {
      if (source === "stored-custody-key") {
        return { ok: false, failure: "absent", message: error.message };
      }
      const host = opts.platformOverride ?? platform();
      if (host === "darwin" || host === "linux") {
        // A supplied/stored credential is not evidence that this directory is
        // a legacy fortress. Require the marker for the exact credential kind;
        // otherwise a virgin directory plus a stray keyring item could mint a
        // new envelope during a read/export operation.
        const legacyMarker = await opts.storage.read(
          "_meta",
          passphrase !== undefined ? "key-params" : "recovery-key-hash",
        );
        if (legacyMarker === null) {
          return {
            ok: false,
            failure: "absent",
            message: absentCredentialRemediation(opts.storagePath),
          };
        }
        if (opts.readOnly === true) {
          // INVARIANT: this is the ONLY write this module can perform, and a
          // read-only caller (a diagnostic) may not perform it. Refusing here,
          // rather than before the marker check above, keeps a virgin
          // directory reporting "absent" and reserves this message for the one
          // fortress shape that would actually have been migrated.
          return {
            ok: false,
            failure: "migration_required",
            message:
              "this fortress still uses the pre-envelope custody format, and a read-only command will not migrate it; the credential is valid, so run `sanctuary protect` on this fortress once to perform the one-time custody migration, then retry",
          };
        }
        // Compatibility only: a pre-envelope fortress needs one journaled
        // migration under the custody write lock. Existing envelopes never
        // enter this path, so read/export remains lock-free on Windows.
        try {
          masterKey = await resolveCliMasterKey(opts.storage, {
            ...(passphrase !== undefined ? { passphrase } : {}),
            ...(recoveryKey !== undefined ? { recoveryKey } : {}),
            storagePathHint: opts.storagePath,
          });
          return { ok: true, masterKey, source };
        } catch (migrationError) {
          if (migrationError instanceof CustodyUnlockError) {
            return { ok: false, failure: "mismatch", message: migrationError.message };
          }
          return {
            ok: false,
            failure: "other",
            message: "legacy fortress custody could not be migrated; no credential or secret detail was emitted",
          };
        }
      }
      return { ok: false, failure: "absent", message: error.message };
    }
    if (error instanceof CustodyUnlockError) {
      if (source === "stored-passphrase" && custodyFallbackKey) {
        try {
          masterKey = await unlockExistingMasterReadOnly(opts.storage, {
            keychainKey: custodyFallbackKey,
            storagePathHint: opts.storagePath,
          });
          source = "stored-custody-key";
          return { ok: true, masterKey, source };
        } catch {
          // Both local credentials failed to authenticate this exact fortress.
        }
      }
      if (source === "stored-passphrase" && custodyUnavailableDetail !== undefined) {
        return {
          ok: false,
          failure: "locked",
          message: custodyUnavailableDetail,
        };
      }
      return { ok: false, failure: "mismatch", message: error.message };
    }
    // Rotation-in-progress, orphaned state, etc. carry their own secret-free
    // messages; surface them under "other" rather than a generic string.
    return {
      ok: false,
      failure: "other",
      message: "fortress custody could not be unlocked; no credential or secret detail was emitted",
    };
  }

    return { ok: true, masterKey, source };
  } finally {
    custodyKey?.fill(0);
    custodyFallbackKey?.fill(0);
  }
}

/**
 * Secret-free remediation for the "no credential anywhere" case. Names every
 * supported way to supply one, including the fresh-host keyring path, without
 * revealing which the fortress actually uses.
 */
function absentCredentialRemediation(storagePath: string): string {
  return (
    "no fortress credential is available for " +
    storagePath +
    ".\n" +
    "Supply one of:\n" +
    "  - SANCTUARY_PASSPHRASE=<fortress passphrase> (env), or --passphrase-stdin, or\n" +
    "  - SANCTUARY_RECOVERY_KEY=<recovery key> (env), or\n" +
    "  - store this fortress's passphrase in the OS keyring on this host by\n" +
    "    running `sanctuary protect` for it, then retry (no secret is typed here).\n" +
    "Refusing to generate a passphrase: that would strand any existing state."
  );
}
