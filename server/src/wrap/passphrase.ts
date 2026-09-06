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

import { lstat, mkdir, unlink } from "node:fs/promises";
import { realpathSync, statSync } from "node:fs";
import { homedir, platform, userInfo } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
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
import {
  hostnameMigrationCandidates,
  resolveMachineIdentity,
  type MachineIdentity,
} from "./host-identity.js";

// ── Constants ───────────────────────────────────────────────────────

const KEYCHAIN_ACCOUNT = "sanctuary";
/** Legacy single-tenant Keychain service name — kept for backward compat. */
const KEYCHAIN_SERVICE_DEFAULT = "sanctuary-passphrase";
const FALLBACK_FILE_VERSION = 3;
const LEGACY_FALLBACK_FILE_VERSION = 2;
const FALLBACK_FILE_ALG = "aes-256-gcm";
/** Raw (pre-envelope) fallback layout: a 12-byte AES-GCM nonce, then ciphertext. */
const FALLBACK_NONCE_BYTES = 12;
/**
 * 13 = the 12-byte nonce plus at least one ciphertext byte. Below this the file
 * cannot even be split into its two parts, so it is rejected before any key is
 * derived.
 */
const MIN_RAW_FALLBACK_BYTES = FALLBACK_NONCE_BYTES + 1;
/** 32 = the AES-256-GCM key width named by {@link FALLBACK_FILE_ALG}. */
const MACHINE_KEY_BYTES = 32;
/**
 * HKDF info label for the machine-local fallback-file key.
 *
 * v2 is the label EVERY write uses. Its host fact is the host's stable identity
 * where the platform exposes one (see `wrap/host-identity.ts`), and the
 * resolved hostname where it does not. v1 bound the key to `os.hostname()`
 * unconditionally, which is not boot-invariant, so a file written on one boot
 * could stop authenticating on the next with the file and the machine both
 * untouched.
 *
 * INVARIANT (enforcement site): the label is BUMPED rather than reused, and v1
 * is derived on the READ path only, so a v1 key and a v2 key can never both be
 * valid for one file. That is what makes the read-time ladder below sound: an
 * authenticated decryption under v1 material is positive evidence the file
 * predates the migration, and only that evidence authorizes the in-place
 * re-wrap.
 *
 * Both labels must match their rows in
 * `server/docs/hkdf-info-string-registry.md` and
 * `server/test/fixtures/at-rest/hkdf-label-classification.json`.
 */
const MACHINE_KEY_HKDF_INFO = "sanctuary-passphrase-v2-host-identity";
/** Superseded label; still derived on the READ path only, never on a write. */
const LEGACY_HOSTNAME_MACHINE_KEY_HKDF_INFO = "sanctuary-passphrase-v1";
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

/**
 * Read-side evidence retained for callers that must distinguish a definitely
 * absent/mismatched local credential from an OS keyring whose contents are
 * temporarily unknowable. A usable fallback can still positively authenticate
 * custody while the keyring is unavailable; a missing, unreadable, or stale
 * fallback cannot turn that keyring ambiguity into a negative claim.
 */
export type StoredPassphraseObservation =
  | {
      status: "found";
      result: PassphraseResult;
      keyringUnreachable: boolean;
    }
  | {
      status: "absent";
      keyringUnreachable: boolean;
      keyringLocation?: string;
      keyringDetail?: string;
    }
  | {
      status: "fallback-unreadable";
      path: string;
      reason: string;
      keyringUnreachable: boolean;
      keyringLocation?: string;
      keyringDetail?: string;
    };

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
   * Override the machine-local key derivation ENTIRELY (for tests that simulate
   * host/user migration). Production callers leave this undefined.
   *
   * A caller that supplies this owns the whole derivation authority, so the
   * built-in read-time migration ladder is NOT run underneath it: letting a key
   * the caller never named decrypt the file would silently widen what that
   * caller accepts. Use {@link machineIdentityOverride} instead to model a
   * different HOST while keeping the product's own derivations.
   */
  deriveMachineKey?: (home: string) => Uint8Array;
  /**
   * Override the host facts the built-in fallback-file key derivations read
   * from the machine (for tests that model a host whose resolved hostname
   * changed, or a host that exposes no stable identity). Production callers
   * leave this undefined, in which case the facts come from
   * `wrap/host-identity.ts` and describe the REAL running host. This is the
   * ONLY way to model a different host: {@link platformOverride} selects the
   * keyring backend and never the host identity. Ignored when
   * {@link deriveMachineKey} is supplied, which replaces the derivations these
   * facts feed.
   */
  machineIdentityOverride?: MachineIdentity;
  /**
   * Declared-read-only caller: perform NO writes of any kind while reading.
   * Honored by {@link readStoredPassphrase}, whose one write path is the
   * in-place repair of a fallback file that is not in the current at-rest form
   * (a superseded envelope, a superseded machine key, or both); under this flag
   * that repair is skipped and the file is left byte-identical. Read-only
   * diagnostics (the audit-chain repair-plan verb)
   * MUST set this: their no-mutation contract covers the whole fortress
   * directory, and `passphrase.enc` lives inside it. Meaningless to
   * {@link getOrCreatePassphrase}, which exists to mint custody and never
   * takes this flag.
   */
  readOnly?: boolean;
  /**
   * Ceremony-scoped identity captured before an inode-bound lock begins. It
   * prevents a renamed/replaced fortress path from changing keyring service or
   * fallback AAD while an external credential-store await is in flight.
   */
  credentialIdentity?: {
    keychainService: string;
    keychainReadServices: readonly string[];
    fallbackAadIdentity: string;
  };
  /** Inode-bound fallback-file I/O supplied by FilesystemStorage's live lease. */
  fallbackCapability?: {
    read(): Promise<Uint8Array | null>;
    write(data: Uint8Array): Promise<void>;
    delete(): Promise<boolean>;
  };
  /**
   * Refuse to persist into the machine-local encrypted fallback file, failing
   * closed when no OS keyring can hold the credential (S3). A caller that mints
   * a passphrase the operator NEVER sees (the recovery-key rekey) sets this so a
   * generated secret cannot silently land in a machine-bound file — which would
   * collapse vault confidentiality to "possession of the fortress dir + four
   * public host facts" with no operator-held copy. The persist throws
   * {@link PassphrasePersistenceError} instead of writing the fallback file.
   */
  refuseFallbackFile?: boolean;
}

export function capturePassphraseCredentialIdentity(
  storagePath: string,
  home: string = homedir(),
): NonNullable<PassphraseOptions["credentialIdentity"]> {
  try {
    const existing = statSync(storagePath);
    if (!existing.isDirectory()) {
      throw new Error("existing fortress path is not a directory");
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw new PassphrasePathIdentityError(storagePath, error);
    }
  }
  return {
    // External credential authority is always the canonical realpath service.
    // The live lease binds fallback-file I/O to an inode; an inode-derived
    // keyring name is not durable across restore/copy and must never shadow or
    // become the sole credential restored by a recovery transaction.
    keychainService: canonicalKeychainServiceFor(storagePath, home),
    keychainReadServices: fortressKeychainReadServices(storagePath, home),
    fallbackAadIdentity: canonicalStoragePathOf(storagePath),
  };
}

export type ExistingCustodyMaterialStatus = "present" | "absent" | "unknown";

/**
 * Presence-only, read-only observation used to distinguish a true first
 * custody ceremony from wrapping an additional harness around an existing
 * fortress. No secret bytes are opened here. Validity is still decided by the
 * ordinary authenticated read/unlock path before any unrelated wrap mutation.
 */
export async function probeExistingCustodyMaterial(
  storagePath: string,
  home: string = homedir(),
): Promise<ExistingCustodyMaterialStatus> {
  const candidates = [
    fallbackFilePath(home, storagePath),
    join(storagePath, "state", "_meta", "custody-envelope.enc"),
  ];
  let present = false;
  for (const path of candidates) {
    try {
      const stats = await lstat(path);
      if (!stats.isFile() || stats.isSymbolicLink()) return "unknown";
      present = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") return "unknown";
    }
  }
  return present ? "present" : "absent";
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
        `  3. If you hold the human recovery key, run \`sanctuary reset-passphrase --mode recovery-key --fortress <path>\` in a private terminal.\n` +
        `     It preserves the master and data. Use configured shares/guardian next; destroy state only as a last resort.\n` +
        `     See \`sanctuary reset-passphrase --help\` for all recovery modes.\n\n` +
        `Refusing to regenerate the passphrase, that would permanently destroy the data encrypted under the previous key.`
    );
    this.name = "PassphraseUnreadableError";
    this.path = path;
    this.reason = reason;
  }
}

/** A storage path could not be reduced to one unambiguous fortress identity. */
export class PassphrasePathIdentityError extends Error {
  readonly storagePath: string;
  constructor(storagePath: string, cause: unknown) {
    super(
      `Sanctuary could not establish the canonical identity of fortress path ${storagePath}; ` +
        `refusing to read or mutate credentials (${errorMessage(cause)}).`,
      { cause },
    );
    this.name = "PassphrasePathIdentityError";
    this.storagePath = storagePath;
  }
}

/** Neither supported credential store durably accepted a supplied passphrase. */
export class PassphrasePersistenceError extends Error {
  readonly fallbackPath: string;
  constructor(fallbackPath: string, cause: unknown) {
    super(
      `Could not persist the provided passphrase to either the OS keyring or ${fallbackPath}: ` +
        `${errorMessage(cause)}. Refusing to proceed; the passphrase will not be written ` +
        `into agent configuration or process arguments.`,
      { cause },
    );
    this.name = "PassphrasePersistenceError";
    this.fallbackPath = fallbackPath;
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
  | {
      status: "ok";
      value: string;
      /**
       * The file authenticated, but not in the CURRENT at-rest form: either its
       * envelope predates the canonical-AAD shape, or it opened under a
       * superseded machine key. Both are repaired by the same in-place re-wrap,
       * and a caller that declared itself read-only skips it. The value read is
       * identical either way.
       */
      staleAtRest: boolean;
    }
  | { status: "not-found" }
  | { status: "unreadable"; reason: string };

/**
 * The machine-local key material for the fallback file, as a ladder.
 *
 * `primary` is what a WRITE uses and what a read tries first. `legacy` is the
 * bounded, ordered set of superseded derivations a read may fall back to before
 * declaring the file unreadable; it is empty when the caller supplied its own
 * derivation. Both take `home` because the home path is part of the material.
 */
interface MachineKeyLadder {
  primary(home: string): Uint8Array;
  legacy(home: string): Uint8Array[];
}

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
  const identity = opts.credentialIdentity ??
    capturePassphraseCredentialIdentity(storagePath, home);
  // Writes go to the CANONICAL identity derived from the deepest existing
  // realpath ancestor plus any not-yet-created suffix.
  const service = identity.keychainService;
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  const keys = resolveMachineKeyLadder(opts);

  // 1. Try the OS keyring (canonical realpath name, then lexical + 12-hex legacy).
  const fromKeyring = await readPassphraseFromKeyring(
    exec,
    plat,
    [...identity.keychainReadServices]
  );
  if (fromKeyring.status === "found") return fromKeyring.result;

  // 2. Try the encrypted fallback file. This is a NON-DESTRUCTIVE read and is
  //    safe even when the keyring was unreachable: an existing user-supplied
  //    fallback value is a legitimate custody source (the documented F3 Linux
  //    no-Secret-Service path). We try it BEFORE failing closed so a locked
  //    keyring does not block a fortress that has a usable fallback file.
  const fallback = fallbackFilePath(home, storagePath);
  const fromFile = await readFromFallbackFile(
    fallback,
    identity.fallbackAadIdentity,
    home,
    keys,
    opts.fallbackCapability,
  );
  if (fromFile.status === "ok") {
    if (fromFile.staleAtRest) {
      // BEST EFFORT: the value is already authenticated, so a failed
      // modernization write must not deny custody. See
      // repairFallbackAtRestBestEffort.
      await repairFallbackAtRestBestEffort(
        fallback,
        identity.fallbackAadIdentity,
        fromFile.value,
        home,
        keys,
        opts.fallbackCapability,
      );
    }
    return {
      value: fromFile.value,
      source: "fallback-file",
      location: fallback,
    };
  }
  if (fromFile.status === "unreadable") {
    if (fromKeyring.status === "unreachable") {
      throw new PassphraseKeyringUnreachableError(
        fromKeyring.location,
        `${fromKeyring.detail}; the fallback credential is also unreadable, so keyring contents remain unknown`,
      );
    }
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
  let keyringWriteFailure: string | undefined;
  if (plat === "darwin") {
    const write = await writeToKeychain(value, exec, service);
    if (write.status === "written") {
      return { value, source: "generated", location: OS_KEYRING_LOCATION_MACOS };
    }
    if (write.status === "unavailable") {
      throw new PassphraseKeyringUnreachableError(
        OS_KEYRING_LOCATION_MACOS,
        write.detail,
      );
    }
    keyringWriteFailure = write.detail;
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
      ? keyringWriteFailure === undefined
        ? "OS keyring unavailable or refused the write"
        : `OS keyring refused the write (${keyringWriteFailure})`
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
  const observed = await observeStoredPassphrase(opts);
  if (observed.status === "found") return observed.result;
  if (observed.status === "fallback-unreadable") {
    if (observed.keyringUnreachable) {
      throw new PassphraseKeyringUnreachableError(
        observed.keyringLocation ?? "OS keyring",
        `${observed.keyringDetail ?? "keyring unreachable"}; the fallback credential is also unreadable, so keyring contents remain unknown`,
      );
    }
    throw new PassphraseUnreadableError(observed.path, observed.reason);
  }
  if (observed.keyringUnreachable) {
    throw new PassphraseKeyringUnreachableError(
      observed.keyringLocation ?? "OS keyring",
      observed.keyringDetail ?? "keyring unreachable",
    );
  }
  return null;
}

/**
 * Observe stored-passphrase sources without collapsing an unavailable keyring
 * into fallback absence/unreadability. Recovery transactions use this richer
 * result to avoid replaying or superseding custody while a possibly-committed
 * keyring credential is merely hidden by a temporary outage.
 */
export async function observeStoredPassphrase(
  opts: PassphraseOptions = {}
): Promise<StoredPassphraseObservation> {
  const home = opts.home ?? homedir();
  const storagePath = opts.storagePath ?? resolveStoragePath(process.env, home);
  const identity = opts.credentialIdentity ??
    capturePassphraseCredentialIdentity(storagePath, home);
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  const keys = resolveMachineKeyLadder(opts);

  // Same precedence as getOrCreatePassphrase: keyring (canonical realpath name,
  // then lexical and 12-hex legacy for pre-realpath / pre-v1.2.3 entries), then
  // the non-destructive fallback file, then fail closed on an unreachable keyring
  // (so a locked keyring with no fallback custody is reported, never silently
  // "absent"). This is a READ-only chain: it NEVER promotes/deletes a legacy
  // entry. Consolidating legacy keychain names to the canonical realpath service
  // is a separate writable authority that has no shipped consumer today, so it is
  // deliberately not implemented here (S8: an inert capability was removed rather
  // than left claiming to ship).
  const fromKeyring = await readPassphraseFromKeyring(
    exec,
    plat,
    [...identity.keychainReadServices]
  );
  if (fromKeyring.status === "found") {
    return {
      status: "found",
      result: fromKeyring.result,
      keyringUnreachable: false,
    };
  }
  const keyringUnreachable = fromKeyring.status === "unreachable";

  const fallback = fallbackFilePath(home, storagePath);
  const fromFile = await readFromFallbackFile(
    fallback,
    identity.fallbackAadIdentity,
    home,
    keys,
    opts.fallbackCapability,
  );
  if (fromFile.status === "ok") {
    // A file in a superseded at-rest form is normally repaired in place here
    // (fresh nonce, current envelope, current machine key). A caller that
    // declared itself read-only must not trigger that rewrite: "read the stored
    // passphrase" and "modernize the file holding it" are different
    // authorities, and a diagnostic holds only the first. The value read is
    // identical either way; the repair is deferred to the next non-read-only
    // caller, and the ladder keeps opening the file until then.
    //
    // The repair is also BEST EFFORT for a writable caller: an unwritable or
    // transiently failing storage path must not turn a successful authenticated
    // read into a custody denial. See repairFallbackAtRestBestEffort.
    if (fromFile.staleAtRest && !opts.readOnly) {
      await repairFallbackAtRestBestEffort(
        fallback,
        identity.fallbackAadIdentity,
        fromFile.value,
        home,
        keys,
        opts.fallbackCapability,
      );
    }
    return {
      status: "found",
      result: {
        value: fromFile.value,
        source: "fallback-file",
        location: fallback,
      },
      keyringUnreachable,
    };
  }
  if (fromFile.status === "unreadable") {
    return {
      status: "fallback-unreadable",
      path: fallback,
      reason: fromFile.reason,
      keyringUnreachable,
      ...(fromKeyring.status === "unreachable"
        ? {
            keyringLocation: fromKeyring.location,
            keyringDetail: fromKeyring.detail,
          }
        : {}),
    };
  }

  // Keyring locked / unreachable and no fallback custody: fail closed rather
  // than report a misleading "no passphrase stored" (which a caller might act
  // on by regenerating and clobbering the locked entry).
  if (fromKeyring.status === "unreachable") {
    return {
      status: "absent",
      keyringUnreachable: true,
      keyringLocation: fromKeyring.location,
      keyringDetail: fromKeyring.detail,
    };
  }

  return { status: "absent", keyringUnreachable: false };
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
  services: string[]
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

  // Try the identities newest-first (canonical realpath, then lexical, then the
  // 12-hex legacy). An "unreachable" from ANY probe is reported immediately so a
  // locked keyring is never mistaken for "no credential" (the strand-the-fortress
  // clobber guard).
  for (const service of services) {
    const found = await read(service);
    if (found.status === "found") {
      return {
        status: "found",
        result: { value: found.value, source: "keychain", location },
      };
    }
    if (found.status === "unreachable") {
      return { status: "unreachable", location, detail: found.detail };
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
  const identity = opts.credentialIdentity ??
    capturePassphraseCredentialIdentity(storagePath, home);
  // The user-supplied value is authoritative, so it lands on the CANONICAL
  // deepest-existing-realpath identity.
  const service = identity.keychainService;
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  const keys = resolveMachineKeyLadder(opts);

  if (plat === "darwin") {
    const write = await writeToKeychain(value, exec, service);
    if (write.status === "written") {
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
    await writeToFallbackFile(
      fallback,
      identity.fallbackAadIdentity,
      value,
      home,
      keys,
      opts.fallbackCapability,
    );
  } catch (err) {
    throw new PassphrasePersistenceError(fallback, err);
  }
  return { location: fallback, source: "fallback-file" };
}

/** Persist, then prove the exact value is readable from the authoritative path. */
export async function persistAndConfirmUserProvidedPassphrase(
  value: string,
  opts: PassphraseOptions = {},
): Promise<{ location: string; source: "keychain" | "fallback-file" }> {
  const home = opts.home ?? homedir();
  const storagePath = opts.storagePath ?? resolveStoragePath(process.env, home);
  const identity = opts.credentialIdentity ??
    capturePassphraseCredentialIdentity(storagePath, home);
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  const keys = resolveMachineKeyLadder(opts);
  const fallback = fallbackFilePath(home, storagePath);

  const keyringSnapshot = new Map<string, KeyringReadResult>();
  if (plat === "darwin" || plat === "linux") {
    for (const service of identity.keychainReadServices) {
      keyringSnapshot.set(service, await readOneKeyring(exec, plat, service));
    }
    if ([...keyringSnapshot.values()].some((result) => result.status === "unreachable")) {
      throw new PassphrasePersistenceError(
        fallback,
        new Error("keyring state is indeterminate; refusing to overwrite or create fallback custody"),
      );
    }
    const canonicalBefore = keyringSnapshot.get(identity.keychainService) ?? {
      status: "not-found" as const,
    };
    const wrote = plat === "darwin"
      ? (await writeToKeychain(value, exec, identity.keychainService)).status === "written"
      : await writeToSecretService(value, exec, identity.keychainService);
    if (wrote) {
      const confirmed = await readOneKeyring(exec, plat, identity.keychainService);
      if (confirmed.status === "found" && confirmed.value === value) {
        return {
          location: plat === "darwin"
            ? OS_KEYRING_LOCATION_MACOS
            : OS_KEYRING_LOCATION_LINUX,
          source: "keychain",
        };
      }
      await restoreOneKeyring(
        exec,
        plat,
        identity.keychainService,
        canonicalBefore,
      );
      throw new PassphrasePersistenceError(
        fallback,
        new Error("canonical keyring readback did not match the supplied passphrase"),
      );
    }
    const afterFailedWrite = await readOneKeyring(
      exec,
      plat,
      identity.keychainService,
    );
    if (afterFailedWrite.status === "found" && afterFailedWrite.value === value) {
      return {
        location: plat === "darwin"
          ? OS_KEYRING_LOCATION_MACOS
          : OS_KEYRING_LOCATION_LINUX,
        source: "keychain",
      };
    }
    if (afterFailedWrite.status === "found") {
      await restoreOneKeyring(
        exec,
        plat,
        identity.keychainService,
        canonicalBefore,
      );
      throw new PassphrasePersistenceError(
        fallback,
        new Error("keyring write failed and changed the canonical credential unexpectedly"),
      );
    }
    if (afterFailedWrite.status === "unreachable") {
      throw new PassphrasePersistenceError(
        fallback,
        new Error("keyring write result and resulting state are indeterminate"),
      );
    }
    // Falling back while any compatible keyring identity is present or
    // unreachable creates two authorities and lets the stale keyring win on the
    // next read. Only an authoritative all-absent snapshot permits fallback.
    if ([...keyringSnapshot.values()].some((result) => result.status !== "not-found")) {
      throw new PassphrasePersistenceError(
        fallback,
        new Error("keyring update failed while prior keyring state was present or indeterminate"),
      );
    }
  }

  // S3: a caller that minted a passphrase the operator never sees refuses to
  // land it in the machine-local fallback file. Reaching here means no OS keyring
  // could hold it (Windows, or a headless host with no Secret Service), so the
  // only remaining sink is the fallback file — which for a generated secret has
  // no operator-held copy and collapses confidentiality to the fortress dir plus
  // host facts. Fail closed rather than write it.
  if (opts.refuseFallbackFile) {
    throw new PassphrasePersistenceError(
      fallback,
      new Error(
        "no OS keyring is available to hold the credential and machine-local " +
          "fallback storage was refused",
      ),
    );
  }

  let priorRaw: Buffer | null | undefined;
  try {
    priorRaw = await readFallbackRaw(fallback, opts.fallbackCapability);
    await writeToFallbackFile(
      fallback,
      identity.fallbackAadIdentity,
      value,
      home,
      keys,
      opts.fallbackCapability,
    );
    const confirmed = await readFromFallbackFile(
      fallback,
      identity.fallbackAadIdentity,
      home,
      keys,
      opts.fallbackCapability,
    );
    if (confirmed.status !== "ok" || confirmed.value !== value) {
      throw new Error("fallback readback did not match the supplied passphrase");
    }
    return { location: fallback, source: "fallback-file" };
  } catch (error) {
    if (priorRaw !== undefined) {
      await restoreFallbackRaw(fallback, priorRaw, opts.fallbackCapability);
    }
    throw new PassphrasePersistenceError(fallback, error);
  }
}

/**
 * After a rekey has committed and the authoritative stored credential has been
 * read back, remove only retired service-name aliases that hold that exact same
 * value. Distinct values are preserved; an indeterminate keyring read fails so
 * the authenticated rekey journal can drive a later retry.
 */
export async function deleteRetiredMatchingPassphraseServices(opts: {
  value: string;
  credentialIdentity: NonNullable<PassphraseOptions["credentialIdentity"]>;
  platformOverride: NodeJS.Platform;
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
}): Promise<void> {
  if (opts.platformOverride !== "darwin" && opts.platformOverride !== "linux") {
    return;
  }
  const authoritative = await readOneKeyring(
    opts.exec,
    opts.platformOverride,
    opts.credentialIdentity.keychainService,
  );
  if (
    authoritative.status !== "found" ||
    authoritative.value !== opts.value
  ) {
    throw new Error(
      "authoritative credential service did not confirm the committed rekey; refusing retired-service deletion",
    );
  }
  for (const service of opts.credentialIdentity.keychainReadServices) {
    if (service === opts.credentialIdentity.keychainService) continue;
    const observed = await readOneKeyring(
      opts.exec,
      opts.platformOverride,
      service,
    );
    if (observed.status === "unreachable") {
      throw new Error(
        `retired credential service ${service} could not be inspected after committed rekey`,
      );
    }
    if (observed.status !== "found" || observed.value !== opts.value) continue;
    await deleteFromKeyring(opts.exec, opts.platformOverride, service);
    const confirmed = await readOneKeyring(
      opts.exec,
      opts.platformOverride,
      service,
    );
    if (confirmed.status !== "not-found") {
      throw new Error(
        `retired credential service ${service} could not be deleted after committed rekey`,
      );
    }
  }
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

type DarwinKeychainWriteResult =
  | { status: "written" }
  | { status: "unavailable"; detail: string }
  | { status: "failed"; detail: string };

async function writeToKeychain(
  value: string,
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>,
  service: string = KEYCHAIN_SERVICE_DEFAULT
): Promise<DarwinKeychainWriteResult> {
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
  if (/[\r\n]/.test(value)) {
    return { status: "failed", detail: "generated value contained a forbidden line break" };
  }
  try {
    // -U updates in place if the item already exists.
    const batch =
      `add-generic-password -U -a "${escapeForSecurity(KEYCHAIN_ACCOUNT)}" ` +
      `-s "${escapeForSecurity(service)}" -w "${escapeForSecurity(value)}"\n`;
    const result = await exec("security", ["-i"], batch);
    if (result.code === 0) return { status: "written" };
    const classified = classifyDarwinFailure(result);
    if (classified.status === "unreachable") {
      const interactionBlocked =
        result.code === 36 ||
        /(?:interaction is not allowed|interactionnotallowed|-?25308)/i.test(result.stderr);
      return {
        status: "unavailable",
        detail: interactionBlocked
          ? `macOS Keychain refused the write (security exit ${result.code ?? "unknown"} / interaction not allowed)`
          : `keychain write failed (security exit ${result.code ?? "unknown"})`,
      };
    }
    return {
      status: "failed",
      detail: `keychain write failed (security exit ${result.code ?? "unknown"})`,
    };
  } catch {
    return { status: "failed", detail: "macOS security tool could not be started" };
  }
}

/** Read ONE keyring service name without collapsing absence and unavailability. */
async function readOneKeyring(
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>,
  plat: NodeJS.Platform,
  service: string
): Promise<KeyringReadResult> {
  let r: KeyringReadResult;
  if (plat === "darwin") r = await readFromKeychain(exec, service);
  else if (plat === "linux") r = await readFromSecretService(exec, service);
  else return { status: "not-found" };
  return r;
}

/**
 * Delete ONE keyring service entry (best-effort). Removing a superseded legacy
 * factor must never throw and abort the caller: a failed delete just leaves a
 * harmless stale entry that the canonical-first read chain already ignores.
 */
async function deleteFromKeyring(
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>,
  plat: NodeJS.Platform,
  service: string
): Promise<boolean> {
  try {
    if (plat === "darwin") {
      const r = await exec("security", [
        "delete-generic-password",
        "-a",
        KEYCHAIN_ACCOUNT,
        "-s",
        service,
      ]);
      return r.code === 0;
    }
    if (plat === "linux") {
      const r = await exec("secret-tool", [
        "clear",
        "service",
        service,
        "account",
        KEYCHAIN_ACCOUNT,
      ]);
      return r.code === 0;
    }
  } catch {
    // Best-effort; see doc comment.
  }
  return false;
}

async function restoreOneKeyring(
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>,
  plat: NodeJS.Platform,
  service: string,
  snapshot: KeyringReadResult,
): Promise<void> {
  if (snapshot.status === "unreachable") {
    throw new Error("cannot restore indeterminate keyring state");
  }
  if (snapshot.status === "found") {
    const wrote = plat === "darwin"
      ? (await writeToKeychain(snapshot.value, exec, service)).status === "written"
      : await writeToSecretService(snapshot.value, exec, service);
    if (!wrote) throw new Error("could not restore prior keyring credential");
    const verified = await readOneKeyring(exec, plat, service);
    if (verified.status !== "found" || verified.value !== snapshot.value) {
      throw new Error("restored keyring credential did not verify");
    }
    return;
  }
  await deleteFromKeyring(exec, plat, service);
  const verified = await readOneKeyring(exec, plat, service);
  if (verified.status !== "not-found") {
    throw new Error("new keyring credential could not be removed during rollback");
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

/**
 * Symlink-resolved (realpath) canonicalization of a storage path, for the
 * CANONICAL fortress keyring identity.
 *
 * Why realpath, not `path.resolve()`: `resolve()` only normalizes `.`/`..`/
 * separators lexically; it does NOT follow symlinks. So the SAME physical
 * fortress reached via a symlink alias and via its real path produced two
 * DIFFERENT lexical paths → two DIFFERENT service names → two credentials, and
 * a fortress opened through an alias could not find the credential stored for
 * its real path (an orphaned custody). realpath collapses both to one identity.
 *
 * A fresh path may not exist yet even though one of its ancestors is a symlink
 * (`/tmp` -> `/private/tmp` on macOS). Walk upward only on ENOENT, realpath the
 * deepest existing ancestor, then append the untouched nonexistent suffix.
 * Permission errors, symlink loops, ENOTDIR, and other indeterminate failures
 * propagate fail-closed instead of silently splitting one fortress identity.
 */
function canonicalStoragePathOf(storagePath: string): string {
  const absolute = resolve(storagePath);
  const suffix: string[] = [];
  let cursor = absolute;
  while (true) {
    try {
      return join(realpathSync(cursor), ...suffix);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw new PassphrasePathIdentityError(storagePath, error);
      }
      const parent = dirname(cursor);
      if (parent === cursor) throw new PassphrasePathIdentityError(storagePath, error);
      suffix.unshift(basename(cursor));
      cursor = parent;
    }
  }
}

/**
 * CANONICAL fortress keyring service name: the realpath-resolved identity, so an
 * alias and the real path map to ONE credential. It matches
 * {@link keychainServiceFor} only when every existing path component is already
 * canonical. It intentionally diverges for a symlinked existing ancestor even
 * when the final fortress path is not yet created; legacy lexical credentials
 * remain READABLE under this name (compat reads). Consolidating them to this
 * canonical name is a writable authority with no shipped consumer today, so it
 * is not implemented (S8). The 16-hex derivation must match
 * {@link keychainServiceFor} exactly on the canonical input — the ONLY
 * difference between the two is which path canonicalization feeds the hash.
 */
export function canonicalKeychainServiceFor(
  storagePath: string,
  home: string = homedir()
): string {
  const defaultPath = canonicalStoragePathOf(join(home, DEFAULT_STORAGE_DIR));
  const canonicalStorage = canonicalStoragePathOf(storagePath);
  if (canonicalStorage === defaultPath) return KEYCHAIN_SERVICE_DEFAULT;

  const digest = sha256(Buffer.from(canonicalStorage, "utf-8"));
  const suffix = Buffer.from(digest).toString("hex").slice(0, 16);
  return `${KEYCHAIN_SERVICE_DEFAULT}-${suffix}`;
}

/**
 * Pre-v1.2.3 (12-hex) service name for the canonical realpath identity. This
 * fourth compatibility name matters when an old fortress was enrolled through
 * its real path and is later reached through a symlink alias: alias-lexical-12
 * is not the same keyring item as realpath-12.
 */
export function canonicalLegacyKeychainServiceFor(
  storagePath: string,
  home: string = homedir()
): string {
  const defaultPath = canonicalStoragePathOf(join(home, DEFAULT_STORAGE_DIR));
  const canonicalStorage = canonicalStoragePathOf(storagePath);
  if (canonicalStorage === defaultPath) return KEYCHAIN_SERVICE_DEFAULT;

  const digest = sha256(Buffer.from(canonicalStorage, "utf-8"));
  const suffix = Buffer.from(digest).toString("hex").slice(0, 12);
  return `${KEYCHAIN_SERVICE_DEFAULT}-${suffix}`;
}

/**
 * The ordered, de-duplicated keyring service names to try when READING this
 * fortress's stored passphrase, newest identity first:
 *   1. canonical (realpath-16hex) — where writes now land,
 *   2. lexical  (resolve-16hex, the pre-realpath {@link keychainServiceFor}) —
 *      a symlink-reached fortress's legacy credential lives here,
 *   3. canonical legacy (realpath-12hex, pre-v1.2.3 reached by an alias),
 *   4. lexical legacy   (resolve-12hex, pre-v1.2.3).
 * When every existing ancestor is already canonical, (1) === (2), so the chain
 * collapses to the exact two names the pre-realpath code used.
 */
export function fortressKeychainReadServices(
  storagePath: string,
  home: string = homedir()
): string[] {
  const ordered = [
    canonicalKeychainServiceFor(storagePath, home),
    keychainServiceFor(storagePath, home),
    canonicalLegacyKeychainServiceFor(storagePath, home),
    legacyKeychainServiceFor(storagePath, home),
  ];
  return ordered.filter((name, i) => ordered.indexOf(name) === i);
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

/**
 * Repair a fallback file that authenticated under a superseded at-rest form,
 * BEST EFFORT, on behalf of a caller whose purpose was to READ.
 *
 * INVARIANT (enforcement site): a failed modernization write must not turn a
 * SUCCESSFUL authenticated read into a custody denial. The old ciphertext is
 * still on disk and still valid; the value in hand was already proven by an AEAD
 * tag. Aborting here would deny custody on a read-only mount, a full disk, or a
 * transient storage fault, which is strictly worse than carrying the older
 * at-rest form for one more run — the ladder keeps opening it until a later
 * writable read succeeds.
 *
 * This softening is scoped to the READ path on purpose. The persist entry points
 * (`persistUserProvidedPassphrase`, `persistAndConfirmUserProvidedPassphrase`)
 * exist to place a credential, so a write failure there IS the failure of the
 * operation and stays strict.
 *
 * FAILURE MODE, from the outside: a deferred repair is invisible except for the
 * warning below, so an operator who never looks at stderr will simply keep
 * running on the older at-rest form. That is why the warning names the path and
 * says the read succeeded; it is a maintenance notice, not an error. The one
 * case that is NOT a maintenance notice is a file that no longer opens under
 * either form after the failed write; that is raised, not warned about.
 */
async function repairFallbackAtRestBestEffort(
  path: string,
  aadIdentity: string,
  value: string,
  home: string,
  keys: MachineKeyLadder,
  capability?: NonNullable<PassphraseOptions["fallbackCapability"]>,
): Promise<void> {
  try {
    await writeToFallbackFile(path, aadIdentity, value, home, keys, capability);
  } catch (err) {
    const reason = (err as Error)?.message ?? "unknown write error";
    // INVARIANT (enforcement site): a caught write error is NOT evidence that
    // the file on disk is still the old one, so this branch observes rather
    // than claims. The custody writer renames the new file into place BEFORE
    // the directory fsync, and an injected capability may commit its bytes and
    // then reject, so the failure can be raised with the new ciphertext already
    // installed. Re-read through the SAME ladder and report what is actually
    // there.
    const observed = await readFromFallbackFile(
      path,
      aadIdentity,
      home,
      keys,
      capability,
    );
    if (observed.status !== "ok") {
      // Neither the superseded form nor the current one opens the file any
      // more. That is not a deferred repair, it is custody genuinely lost, and
      // reporting it as a maintenance notice would hide the one failure the
      // operator must act on. Raise the original write error.
      throw err;
    }
    // Each branch states only what the re-read proved. An authenticated read
    // under a superseded form proves the file still opens that way; it does
    // not prove the bytes are the ones from before the attempt, so "unchanged"
    // is never claimed. An authenticated read under the current key proves the
    // rewrite landed despite the reported error.
    const message = observed.staleAtRest
      ? `sanctuary: the in-place re-wrap of the passphrase fallback file at ${path} reported ` +
        `an error (${reason}). The stored passphrase was read successfully and the file still ` +
        `opens under a superseded at-rest form; the repair is retried on the next read by a ` +
        `caller that may write.\n`
      : `sanctuary: the in-place re-wrap of the passphrase fallback file at ${path} reported ` +
        `an error (${reason}), but the file now opens under the current key, so the rewrite ` +
        `landed and no repair remains. The stored passphrase was read successfully.\n`;
    // The custody VALUE never appears in either branch. The path, the storage
    // error, and the observed at-rest state are the only facts reported,
    // matching what PassphraseUnreadableError already discloses on the failing
    // branch of the same read.
    process.stderr.write(message);
  }
}

async function readFromFallbackFile(
  path: string,
  aadIdentity: string,
  home: string,
  keys: MachineKeyLadder,
  capability?: NonNullable<PassphraseOptions["fallbackCapability"]>,
): Promise<FallbackReadResult> {
  let raw: Buffer;
  try {
    const captured = await readFallbackRaw(path, capability);
    if (captured === null) return { status: "not-found" };
    raw = captured;
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
    if (!parsed && raw.length < MIN_RAW_FALLBACK_BYTES) {
      return { status: "unreadable", reason: "file too short to contain a valid nonce + ciphertext" };
    }
    const attempt = parsed
      ? decryptWithMachineKeyLadder(
          {
            nonce: parsed.nonce,
            ciphertext: parsed.ciphertext,
            // V2 used dirname(the actual fallback path) as AAD.
            aad: parsed.canonicalAad
              ? fallbackFileAad(aadIdentity)
              : legacyFallbackFileAad(path),
          },
          keys,
          home,
        )
      : decryptWithMachineKeyLadder(
          {
            nonce: raw.subarray(0, FALLBACK_NONCE_BYTES),
            ciphertext: raw.subarray(FALLBACK_NONCE_BYTES),
          },
          keys,
          home,
        );
    if (!attempt.ok) return { status: "unreadable", reason: attempt.reason };
    return {
      status: "ok",
      value: attempt.value,
      // Only an AUTHENTICATED success authorizes the writable promotion below.
      // Three superseded at-rest forms map onto one repair: the pre-envelope
      // raw layout, the V2 AAD, and a superseded machine key.
      staleAtRest: !parsed || !parsed.canonicalAad || attempt.legacyMachineKey,
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
  aadIdentity: string,
  value: string,
  home: string,
  keys: MachineKeyLadder,
  capability?: NonNullable<PassphraseOptions["fallbackCapability"]>,
): Promise<void> {
  // Derive the parent directory from the resolved path rather than assuming
  // `<home>/.sanctuary`, so multi-tenant callers with a custom storage path
  // create the correct directory.
  const dir = dirname(path);
  if (!capability) await mkdir(dir, { recursive: true, mode: 0o700 });
  // A fresh nonce every write, including the in-place migration re-wrap: the
  // new ciphertext is under a different key, but reusing a nonce is never the
  // safe default to leave available to a later edit.
  const nonce = randomBytes(FALLBACK_NONCE_BYTES);
  // INVARIANT (enforcement site): a write NEVER uses a legacy ladder key. The
  // superseded derivations exist so an old file can be read once and repaired,
  // not so a new file can be produced in the form that caused the repair.
  const key = keys.primary(home);
  let ciphertext: Uint8Array;
  try {
    const cipher = gcm(key, nonce, fallbackFileAad(aadIdentity));
    ciphertext = cipher.encrypt(Buffer.from(value, "utf-8"));
  } finally {
    key.fill(0);
  }
  const payload = Buffer.from(
    JSON.stringify({
      v: FALLBACK_FILE_VERSION,
      alg: FALLBACK_FILE_ALG,
      aad: "canonical-storage-path",
      nonce: toBase64url(nonce),
      ct: toBase64url(ciphertext),
    }),
    "utf-8",
  );
  if (capability) await capability.write(payload);
  else await writeFileCustody(path, payload, { mode: 0o600, parentMode: 0o700 });
}

async function readFallbackRaw(
  path: string,
  capability?: NonNullable<PassphraseOptions["fallbackCapability"]>,
): Promise<Buffer | null> {
  if (capability) {
    const raw = await capability.read();
    return raw === null ? null : Buffer.from(raw);
  }
  try {
    return await readFileCustody(path, {
      mode: { rejectGroupOrOther: true },
      verifyPathIdentity: true,
    });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

async function restoreFallbackRaw(
  path: string,
  raw: Buffer | null,
  capability?: NonNullable<PassphraseOptions["fallbackCapability"]>,
): Promise<void> {
  if (raw === null) {
    if (capability) await capability.delete();
    else {
      await unlink(path).catch((error: NodeJS.ErrnoException) => {
        if (error.code !== "ENOENT") throw error;
      });
    }
    return;
  }
  if (capability) await capability.write(raw);
  else await writeFileCustody(path, raw, { mode: 0o600, parentMode: 0o700 });
}

function fallbackFileAad(canonicalIdentity: string): Uint8Array {
  return Buffer.from(`sanctuary-passphrase:${canonicalIdentity}`, "utf-8");
}

/** Exact V2 contract: AAD was derived from dirname(the actual fallback path). */
function legacyFallbackFileAad(fallbackPath: string): Uint8Array {
  return Buffer.from(
    `sanctuary-passphrase:${resolve(dirname(fallbackPath))}`,
    "utf-8",
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function parseFallbackEnvelope(raw: Buffer): {
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  canonicalAad: boolean;
} | null {
  if (raw[0] !== 0x7b) return null;
  try {
    const parsed = JSON.parse(raw.toString("utf-8")) as Record<string, unknown>;
    const canonicalShape =
      parsed.v === FALLBACK_FILE_VERSION &&
      parsed.aad === "canonical-storage-path";
    const legacyShape =
      parsed.v === LEGACY_FALLBACK_FILE_VERSION &&
      parsed.aad === "storage-path";
    if (
      (!canonicalShape && !legacyShape) ||
      parsed.alg !== FALLBACK_FILE_ALG ||
      typeof parsed.nonce !== "string" ||
      typeof parsed.ct !== "string"
    ) {
      return null;
    }
    return {
      nonce: fromBase64url(parsed.nonce),
      ciphertext: fromBase64url(parsed.ct),
      canonicalAad: canonicalShape,
    };
  } catch {
    return null;
  }
}

/**
 * The material every machine-local key derivation hashes: one host fact, then
 * uid, username, and home path.
 *
 * Must match the mirrored derivation in
 * `server/test/wrap/passphrase-host-identity.test.ts` and the one in
 * `server/test/cli/audit-chain-repair-plan.test.ts`, both of which plant a file
 * in the superseded form to prove the migration read works. If the field order
 * or the separator changes here, those planted files stop being the artifact
 * under test and the tests pass while proving nothing.
 */
function machineKeyMaterial(home: string, hostFact: string): Buffer {
  const info = userInfo();
  return Buffer.from(
    `${hostFact}:${info.uid}:${info.username}:${home}`,
    "utf-8"
  );
}

/**
 * Derive the machine-local key from the host's STABLE identity + uid + username
 * + home path.
 *
 * This is NOT cryptographically strong authentication, it only ensures that
 * the encrypted file cannot be read off a different machine. If an attacker
 * already has local access, they can trivially re-derive this.
 *
 * Threat model: see `server/docs/keychain-schema.md`, "Windows or
 * no-OS-keyring fallback: encrypted file" section. The fallback file is
 * intended for single-user machines without an OS keyring, NOT for
 * multi-user machines, shared CI runners, or snapshotted VMs. Binding to a
 * stable host identity rather than to the resolved hostname changes NOTHING
 * about that threat model: both facts are readable by any local user. What it
 * changes is that the key survives a reboot on which the host answers to a
 * different spelling of its own name.
 *
 * AUDITED COST on a host that exposes no stable identity (Windows, or a host
 * whose probe did not answer): the host fact falls back to the resolved
 * hostname, so such a host KEEPS the hostname sensitivity the stable identity
 * exists to remove — a rename can still strand its file, exactly as before this
 * migration. It is stated here rather than silently absorbed. What it does NOT
 * do is write under the superseded label.
 */
function deriveMachineKey(home: string, identity: MachineIdentity): Uint8Array {
  // INVARIANT (enforcement site): every WRITE derives under
  // MACHINE_KEY_HKDF_INFO, whichever host fact was available. The superseded
  // label is read-only — the registry rows in
  // `server/docs/hkdf-info-string-registry.md` and
  // `server/test/fixtures/at-rest/hkdf-label-classification.json` state that as
  // a property, so a host with no stable identity must not be the one exception
  // that quietly falsifies it. Absent evidence is not a pass and it is not a
  // licence to reuse a retired label; it is a weaker host fact under the
  // current one, which also keeps the two labels from ever colliding on one
  // file.
  const hostFact = identity.stableHostId ?? identity.hostname;
  return hkdf(
    sha256,
    machineKeyMaterial(home, hostFact),
    undefined,
    MACHINE_KEY_HKDF_INFO,
    MACHINE_KEY_BYTES
  );
}

/**
 * The SUPERSEDED derivation: machine-local key from a resolved hostname.
 * Derived on the read path only, so a file written before the migration still
 * opens. Never used for a write.
 */
function deriveLegacyHostnameMachineKey(
  home: string,
  host: string
): Uint8Array {
  return hkdf(
    sha256,
    machineKeyMaterial(home, host),
    undefined,
    LEGACY_HOSTNAME_MACHINE_KEY_HKDF_INFO,
    MACHINE_KEY_BYTES
  );
}

/**
 * Resolve the key ladder for one call.
 *
 * INVARIANT (enforcement site): an injected `deriveMachineKey` yields an EMPTY
 * legacy set. That caller declared the whole derivation authority, and running
 * the product's host-derived candidates underneath it would let a key it never
 * named authenticate the file.
 *
 * INVARIANT (enforcement site): the host facts come from the REAL platform, and
 * `platformOverride` is deliberately not consulted. That option selects which
 * OS-keyring backend to exercise; the host identity is a fact about the machine
 * this process is running on, and the file on that machine's disk was sealed
 * under it. Deriving it from the simulated platform makes a write and a read of
 * one file disagree whenever the two disagree about the override, which reads
 * from the outside as an undecryptable fallback file on an untouched machine.
 * A caller that needs to model a different HOST supplies
 * {@link PassphraseOptions.machineIdentityOverride}, which says so explicitly.
 *
 * The host facts are read LAZILY, on the first key derivation rather than here.
 * Resolving a stable host identity costs a subprocess on macOS, and the common
 * path never needs one: a fortress whose credential is in the OS keyring
 * returns before any fallback key is derived. Every entry point below builds a
 * ladder unconditionally, so an eager probe would put that subprocess on every
 * custody read on the machine.
 */
function resolveMachineKeyLadder(opts: PassphraseOptions): MachineKeyLadder {
  const injected = opts.deriveMachineKey;
  if (injected) return { primary: injected, legacy: () => [] };
  let identity: MachineIdentity | undefined;
  const hostFacts = (): MachineIdentity =>
    (identity ??= opts.machineIdentityOverride ?? resolveMachineIdentity());
  return {
    primary: (home) => deriveMachineKey(home, hostFacts()),
    legacy: (home) => {
      const candidates = hostnameMigrationCandidates(hostFacts().hostname);
      return [
        // The CURRENT label over each hostname candidate. This rung exists
        // because a run whose stable-identity probe did not answer writes a
        // perfectly current file under the hostname host fact; on a later run
        // the probe succeeds, the primary key becomes the stable-identity one,
        // and without this rung nothing would ever reach that file again. It is
        // reported as legacy so the first writable read re-wraps it under the
        // primary key and the window closes.
        ...candidates.map((host) =>
          deriveMachineKey(home, { stableHostId: null, hostname: host })
        ),
        // The SUPERSEDED label over the same candidates: a file written before
        // the migration at all.
        ...candidates.map((host) =>
          deriveLegacyHostnameMachineKey(home, host)
        ),
      ];
    },
  };
}

/** One authenticated-decryption attempt against the whole key ladder. */
type MachineKeyLadderAttempt =
  | { ok: true; value: string; legacyMachineKey: boolean }
  | { ok: false; reason: string };

/**
 * Try the current machine key, then each superseded hostname-derived key, until
 * one AUTHENTICATES the ciphertext.
 *
 * INVARIANT (enforcement site): every candidate key is zeroed on the way out,
 * including the one that succeeded, and the walk stops at the first AEAD
 * success. `legacyMachineKey` is reported ONLY from an authenticated
 * decryption, so a failed candidate can never widen what the caller is then
 * allowed to do with the file.
 */
function decryptWithMachineKeyLadder(
  parts: { nonce: Uint8Array; ciphertext: Uint8Array; aad?: Uint8Array },
  keys: MachineKeyLadder,
  home: string
): MachineKeyLadderAttempt {
  const candidates = [
    { key: keys.primary(home), legacyMachineKey: false },
    ...keys.legacy(home).map((key) => ({ key, legacyMachineKey: true })),
  ];
  let reason = "no machine key authenticated the fallback file";
  try {
    for (const candidate of candidates) {
      try {
        const cipher =
          parts.aad === undefined
            ? gcm(candidate.key, parts.nonce)
            : gcm(candidate.key, parts.nonce, parts.aad);
        const plain = cipher.decrypt(parts.ciphertext);
        return {
          ok: true,
          value: Buffer.from(plain).toString("utf-8"),
          legacyMachineKey: candidate.legacyMachineKey,
        };
      } catch (err) {
        reason = (err as Error).message ?? "unknown decryption error";
      }
    }
  } finally {
    for (const candidate of candidates) candidate.key.fill(0);
  }
  return { ok: false, reason };
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
