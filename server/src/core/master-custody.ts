/**
 * Sanctuary MCP Server — Master-Key Custody (the custody envelope)
 *
 * One master key per fortress, stored ONLY as a set of independent wraps.
 * This module is the single source of truth for master-key establishment:
 * every entry point (MCP server boot, standalone dashboard, castle-wall CLI,
 * `sanctuary init`/`wrap`) converges on `establishMaster`, ending the class
 * of bugs where two tools derive two different masters for one fortress
 * (the 2026-06-12 D4 Hermes drill incident: a passphrase-mode fortress whose
 * printed recovery key was a *parallel* random master that unlocked nothing).
 *
 * Layout (stored as plaintext JSON at `_meta/custody-envelope`; every wrap
 * payload is AES-256-GCM ciphertext, so the envelope itself is not secret):
 *
 *   master = random 32 bytes, generated exactly once, never stored bare
 *   wrap_passphrase   = AEAD(Argon2id(passphrase, per-wrap salt), master)
 *   wrap_recovery-key = AEAD(HKDF(recoveryKey, "recovery-key-wrap"), master)
 *   wrap_keychain     = AEAD(HKDF(custodyKey,  "keychain-wrap"),     master)
 *
 * Security invariants (CLAUDE.md "WHAT THESE TOOLS MUST NEVER DO"):
 *  - Fail closed: a credential that does not authenticate (GCM tag) throws;
 *    there is no fallback to a weaker derivation or plaintext path (#5).
 *  - No key material in errors, logs, or audit details (#6).
 *  - Migration never re-encrypts data and never changes the master: the
 *    same master that already encrypts the fortress is wrapped under the
 *    supplied credential. Legacy markers are kept, so an interrupted
 *    migration leaves a pure-legacy fortress (no un-unlockable window).
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "./encryption.js";
import {
  deriveMasterKey,
  type KeyDerivationParams,
} from "./key-derivation.js";
import { generateRandomKey } from "./random.js";
import { hashToString } from "./hashing.js";
import {
  toBase64url,
  fromBase64url,
  stringToBytes,
  bytesToString,
  constantTimeEqual,
} from "./encoding.js";

// ── Envelope types ──────────────────────────────────────────────────

export type CustodyWrapType = "passphrase" | "recovery-key" | "keychain";

/**
 * How the fortress's custody was established. Anything other than
 * "interactive" is a degraded mode: it is recorded here, audited at
 * creation, and exempted from the two-factor floor — a *distinct, visible*
 * install path, never a silent relaxation of the interactive one (F6).
 */
export type CustodyInstallMode =
  | "interactive"
  | "headless"
  | "stdio-server"
  | "legacy-migrated";

export interface CustodyWrap {
  type: CustodyWrapType;
  /** AES-256-GCM wrap of the 32-byte master key. */
  payload: EncryptedPayload;
  /** Argon2id parameters — present only for passphrase wraps. */
  kdf?: KeyDerivationParams;
  /**
   * True when the factor has been verified end-to-end: round-trip for
   * passphrase/keychain wraps, operator re-entry for recovery-key wraps.
   * Only verified wraps count toward the two-factor floor.
   */
  verified: boolean;
  created_at: string;
}

export interface CustodyEnvelope {
  v: 1;
  install_mode: CustodyInstallMode;
  wraps: CustodyWrap[];
  created_at: string;
}

/** `_meta` key holding the envelope. */
export const CUSTODY_ENVELOPE_KEY = "custody-envelope";

/** Verified-wrap count required before trust-bearing state may persist. */
export const CUSTODY_FLOOR_WRAPS = 2;

const CUSTODY_HKDF_SALT = "sanctuary-custody-v1";

// ── Errors ──────────────────────────────────────────────────────────

/**
 * A credential failed to unwrap the master. Deliberately generic: it never
 * reveals which wrap was tried or why it failed beyond "did not match"
 * (CLAUDE.md #7 — denials must not leak rule structure; #6 — no material).
 */
export class CustodyUnlockError extends Error {
  constructor(detail?: string) {
    super(
      detail ??
        "Sanctuary: the supplied credential does not unlock this fortress.\n" +
          "Provide the exact passphrase (SANCTUARY_PASSPHRASE) or recovery key\n" +
          "(SANCTUARY_RECOVERY_KEY) for this fortress. Refusing to start with a\n" +
          "credential that does not verify."
    );
    this.name = "CustodyUnlockError";
  }
}

/** No credential was supplied and the fortress has existing custody state. */
export class CustodyCredentialMissingError extends CustodyUnlockError {
  constructor(storagePathHint?: string) {
    super(
      `Sanctuary: existing encrypted data found${storagePathHint ? ` at ${storagePathHint}` : ""} but no credentials provided.\n` +
        "Provide one of:\n" +
        "  - SANCTUARY_PASSPHRASE (the fortress passphrase)\n" +
        "  - SANCTUARY_RECOVERY_KEY (the recovery key captured at creation)\n" +
        "Without a valid credential, encrypted state cannot be accessed.\n" +
        "Refusing to start to prevent silent data loss."
    );
    this.name = "CustodyCredentialMissingError";
  }
}

/**
 * Migration refused because the derived master failed to decrypt existing
 * fortress data. Writing an envelope from an unverified master would lock
 * in a wrong credential and brick boots with the right one — fail closed
 * and keep the fortress pure-legacy instead.
 */
export class CustodyMigrationRefusedError extends Error {
  constructor() {
    super(
      "Sanctuary: refusing to migrate this fortress to the unified custody scheme.\n" +
        "The supplied credential derives a key that does not decrypt the fortress's\n" +
        "existing encrypted data, so wrapping it would capture the wrong master.\n" +
        "Unlock with the credential this fortress was actually created with, then retry."
    );
    this.name = "CustodyMigrationRefusedError";
  }
}

/**
 * The two-factor custody floor (I4/F6) refused a trust-bearing write.
 * Raised from the server core — identity creation/import, reputation
 * import, Castle-pin provisioning — so SDK/wrapper/scripted paths cannot
 * bypass it the way a CLI-only check could.
 */
export class CustodyFloorError extends Error {
  constructor(action: string) {
    super(
      `Sanctuary: refusing to persist trust-bearing state (${action}).\n` +
        `This fortress has fewer than ${CUSTODY_FLOOR_WRAPS} verified recovery factors enrolled\n` +
        "and was not created through an explicit, audited headless install.\n" +
        "Complete custody setup first: re-run `sanctuary init` (or `sanctuary wrap`)\n" +
        "interactively to capture and verify a recovery key. Until the floor is met,\n" +
        "this fortress holds nothing precious, so re-initializing it is safe."
    );
    this.name = "CustodyFloorError";
  }
}

/**
 * Generating a custody secret the user would never see is a lockout, not a
 * convenience (F3). Raised instead of silently writing a machine-bound
 * secret when no user-held factor is available.
 */
export class SilentCustodyRefusedError extends Error {
  constructor(context: string) {
    super(
      `Sanctuary: refusing to invent a custody secret you would never see (${context}).\n` +
        "A secret held only by this machine is a lockout generator: lose or wipe the\n" +
        "machine and the fortress is gone, with no warning. Choose a user-held factor:\n" +
        "  - supply a passphrase explicitly (SANCTUARY_PASSPHRASE or --passphrase), or\n" +
        "  - enable an OS keyring (macOS Keychain / Linux Secret Service), or\n" +
        "  - create the fortress with `sanctuary init` and capture the recovery key."
    );
    this.name = "SilentCustodyRefusedError";
  }
}

// ── Wrap primitives ─────────────────────────────────────────────────

function custodyAad(type: CustodyWrapType): Uint8Array {
  return stringToBytes(`${CUSTODY_HKDF_SALT}:${type}`);
}

function recoveryWrapKey(recoveryKeyBytes: Uint8Array): Uint8Array {
  if (recoveryKeyBytes.length !== 32) {
    throw new CustodyUnlockError(
      "Sanctuary: recovery key has incorrect length. Use the exact recovery key captured at creation."
    );
  }
  return hkdf(
    sha256,
    recoveryKeyBytes,
    stringToBytes(CUSTODY_HKDF_SALT),
    stringToBytes("recovery-key-wrap"),
    32
  );
}

function keychainWrapKey(custodyKeyBytes: Uint8Array): Uint8Array {
  if (custodyKeyBytes.length !== 32) {
    throw new CustodyUnlockError(
      "Sanctuary: keychain custody key has incorrect length."
    );
  }
  return hkdf(
    sha256,
    custodyKeyBytes,
    stringToBytes(CUSTODY_HKDF_SALT),
    stringToBytes("keychain-wrap"),
    32
  );
}

function assertMaster(master: Uint8Array): void {
  if (master.length !== 32) {
    throw new Error("Master key must be 32 bytes");
  }
}

/** Wrap the master under a passphrase (Argon2id with a fresh per-wrap salt). */
export async function wrapMasterWithPassphrase(
  master: Uint8Array,
  passphrase: string,
  opts?: { verified?: boolean; now?: () => Date }
): Promise<CustodyWrap> {
  assertMaster(master);
  const { key: wrapKey, params } = await deriveMasterKey(passphrase);
  const payload = encrypt(master, wrapKey, custodyAad("passphrase"));
  wrapKey.fill(0);
  return {
    type: "passphrase",
    payload,
    kdf: params,
    verified: opts?.verified ?? true,
    created_at: (opts?.now ?? (() => new Date()))().toISOString(),
  };
}

/** Wrap the master under a recovery key (HKDF-derived wrap key). */
export function wrapMasterWithRecoveryKey(
  master: Uint8Array,
  recoveryKeyBytes: Uint8Array,
  opts?: { verified?: boolean; now?: () => Date }
): CustodyWrap {
  assertMaster(master);
  const wrapKey = recoveryWrapKey(recoveryKeyBytes);
  const payload = encrypt(master, wrapKey, custodyAad("recovery-key"));
  wrapKey.fill(0);
  return {
    type: "recovery-key",
    payload,
    verified: opts?.verified ?? false,
    created_at: (opts?.now ?? (() => new Date()))().toISOString(),
  };
}

/** Wrap the master under an OS-keyring-held custody key. */
export function wrapMasterWithKeychainKey(
  master: Uint8Array,
  custodyKeyBytes: Uint8Array,
  opts?: { verified?: boolean; now?: () => Date }
): CustodyWrap {
  assertMaster(master);
  const wrapKey = keychainWrapKey(custodyKeyBytes);
  const payload = encrypt(master, wrapKey, custodyAad("keychain"));
  wrapKey.fill(0);
  return {
    type: "keychain",
    payload,
    verified: opts?.verified ?? true,
    created_at: (opts?.now ?? (() => new Date()))().toISOString(),
  };
}

export type CustodyCredential =
  | { passphrase: string }
  | { recoveryKey: Uint8Array }
  | { keychainKey: Uint8Array };

/**
 * Unwrap the master from the envelope with one credential. Tries every wrap
 * of the matching type; GCM authentication decides. Throws
 * {@link CustodyUnlockError} when nothing matches — fail closed, no
 * downgrade (#5).
 */
export async function unwrapMaster(
  envelope: CustodyEnvelope,
  credential: CustodyCredential
): Promise<Uint8Array> {
  const type: CustodyWrapType =
    "passphrase" in credential
      ? "passphrase"
      : "recoveryKey" in credential
        ? "recovery-key"
        : "keychain";

  for (const wrap of envelope.wraps) {
    if (wrap.type !== type) continue;
    try {
      let wrapKey: Uint8Array;
      if ("passphrase" in credential) {
        if (!wrap.kdf) continue;
        const derived = await deriveMasterKey(credential.passphrase, wrap.kdf);
        wrapKey = derived.key;
      } else if ("recoveryKey" in credential) {
        wrapKey = recoveryWrapKey(credential.recoveryKey);
      } else {
        wrapKey = keychainWrapKey(credential.keychainKey);
      }
      try {
        return decrypt(wrap.payload, wrapKey, custodyAad(type));
      } finally {
        wrapKey.fill(0);
      }
    } catch {
      // Wrong credential for this wrap (or malformed wrap) — try the next
      // wrap of the same type. Never fall back to a weaker path.
    }
  }
  throw new CustodyUnlockError();
}

// ── Envelope persistence ────────────────────────────────────────────

export async function readCustodyEnvelope(
  storage: StorageBackend
): Promise<CustodyEnvelope | null> {
  let raw: Uint8Array | null;
  try {
    raw = await storage.read("_meta", CUSTODY_ENVELOPE_KEY);
  } catch {
    return null;
  }
  if (!raw) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToString(raw));
  } catch {
    throw new Error(
      "Sanctuary: custody envelope exists but is unreadable (malformed JSON).\n" +
        "Refusing to start: regenerating custody state could orphan the data\n" +
        "encrypted under the current master. Restore _meta/custody-envelope from backup."
    );
  }
  const envelope = parsed as CustodyEnvelope;
  if (
    envelope === null ||
    typeof envelope !== "object" ||
    envelope.v !== 1 ||
    !Array.isArray(envelope.wraps)
  ) {
    throw new Error(
      "Sanctuary: custody envelope exists but has an unsupported shape or version.\n" +
        "Refusing to start. Restore _meta/custody-envelope from backup or upgrade Sanctuary."
    );
  }
  return envelope;
}

export async function writeCustodyEnvelope(
  storage: StorageBackend,
  envelope: CustodyEnvelope
): Promise<void> {
  await storage.write(
    "_meta",
    CUSTODY_ENVELOPE_KEY,
    stringToBytes(JSON.stringify(envelope))
  );
}

// ── Two-factor floor (I4 / F6) ──────────────────────────────────────

export function countVerifiedWraps(envelope: CustodyEnvelope): number {
  return envelope.wraps.filter((w) => w.verified).length;
}

/**
 * Enforce the two-factor custody floor at a "persist trust-bearing state"
 * boundary. Passes when:
 *  - the fortress predates the envelope (legacy compat — it becomes
 *    `legacy-migrated` on first unified unlock), or
 *  - ≥ {@link CUSTODY_FLOOR_WRAPS} verified wraps exist, or
 *  - the fortress was created through an explicit degraded install mode
 *    (`headless`, `stdio-server`, `legacy-migrated`) — those modes are
 *    audited at creation and visible in the envelope, never silent.
 *
 * Refuses (throws {@link CustodyFloorError}) for an `interactive` install
 * that never completed verification — by construction such a fortress holds
 * nothing precious yet, so re-initializing it is safe.
 */
export async function enforceCustodyFloor(
  storage: StorageBackend,
  action: string
): Promise<void> {
  const envelope = await readCustodyEnvelope(storage);
  if (!envelope) return; // pre-envelope legacy fortress
  if (countVerifiedWraps(envelope) >= CUSTODY_FLOOR_WRAPS) return;
  if (envelope.install_mode !== "interactive") return;
  throw new CustodyFloorError(action);
}

// ── Migration evidence check ────────────────────────────────────────

/**
 * Verify a candidate master against existing fortress ciphertext before
 * trusting it for migration. Uses the first stored identity (encrypted
 * under HKDF(master, "identity-encryption")) as evidence. Returns:
 *  - "confirmed": evidence decrypted — the master is right.
 *  - "contradicted": evidence exists but does not decrypt — wrong master.
 *  - "no-evidence": nothing to check against (empty fortress).
 */
async function checkMasterEvidence(
  storage: StorageBackend,
  master: Uint8Array
): Promise<"confirmed" | "contradicted" | "no-evidence"> {
  let entries: Array<{ key: string }>;
  try {
    entries = await storage.list("_identities");
  } catch {
    return "no-evidence";
  }
  if (entries.length === 0) return "no-evidence";

  const { derivePurposeKey } = await import("./key-derivation.js");
  const identityKey = derivePurposeKey(master, "identity-encryption");
  for (const entry of entries) {
    const raw = await storage.read("_identities", entry.key);
    if (!raw) continue;
    try {
      const payload = JSON.parse(bytesToString(raw)) as EncryptedPayload;
      decrypt(payload, identityKey);
      return "confirmed";
    } catch {
      // try the next identity; a single corrupt file must not condemn the key
    }
  }
  return "contradicted";
}

// ── Unified establishment ───────────────────────────────────────────

export interface EstablishMasterOptions {
  storage: StorageBackend;
  /** Fortress passphrase, when the caller has one. */
  passphrase?: string;
  /** base64url recovery key, when the caller has one. */
  recoveryKey?: string;
  /** Pre-resolved OS-keyring custody key, when the caller has one. */
  keychainKey?: Uint8Array;
  /**
   * First-run policy. Omit to refuse first runs (existing-state callers).
   * `installMode` is recorded in the envelope and audited by the caller;
   * `mintRecoveryKey` mints a fresh recovery key as a wrap of the true
   * master and returns it for disclosure.
   */
  firstRun?: {
    installMode: CustodyInstallMode;
    mintRecoveryKey: boolean;
  };
  /** Storage-path hint for error messages only (never used for crypto). */
  storagePathHint?: string;
}

export interface EstablishMasterResult {
  masterKey: Uint8Array;
  envelope: CustodyEnvelope;
  origin:
    | "envelope"
    | "migrated-passphrase"
    | "migrated-recovery-key"
    | "first-run";
  keyProtection: "passphrase" | "recovery-key";
  /** Present only when a fresh recovery key was minted on this call. */
  mintedRecoveryKey?: string;
}

function decodeRecoveryKey(recoveryKey: string): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = fromBase64url(recoveryKey);
  } catch {
    throw new CustodyUnlockError(
      "Sanctuary: SANCTUARY_RECOVERY_KEY is not valid base64url. " +
        "Use the exact recovery key captured at creation."
    );
  }
  if (bytes.length !== 32) {
    throw new CustodyUnlockError(
      "Sanctuary: SANCTUARY_RECOVERY_KEY has incorrect length. " +
        "Use the exact recovery key captured at creation."
    );
  }
  return bytes;
}

/**
 * THE master-establishment path. Envelope-first; legacy markers honored and
 * migrated in place (same master, no data re-encryption, markers kept so an
 * interrupted migration leaves a pure-legacy fortress); first runs create
 * the envelope. Precedence among supplied credentials matches the legacy
 * boot order: passphrase, then recovery key, then keychain custody key.
 */
export async function establishMaster(
  opts: EstablishMasterOptions
): Promise<EstablishMasterResult> {
  const { storage } = opts;
  const now = new Date().toISOString();

  const envelope = await readCustodyEnvelope(storage);
  if (envelope) {
    if (opts.passphrase !== undefined) {
      const masterKey = await unwrapMaster(envelope, {
        passphrase: opts.passphrase,
      });
      return { masterKey, envelope, origin: "envelope", keyProtection: "passphrase" };
    }
    if (opts.recoveryKey !== undefined) {
      const masterKey = await unwrapMaster(envelope, {
        recoveryKey: decodeRecoveryKey(opts.recoveryKey),
      });
      return { masterKey, envelope, origin: "envelope", keyProtection: "recovery-key" };
    }
    if (opts.keychainKey !== undefined) {
      const masterKey = await unwrapMaster(envelope, {
        keychainKey: opts.keychainKey,
      });
      return { masterKey, envelope, origin: "envelope", keyProtection: "passphrase" };
    }
    throw new CustodyCredentialMissingError(opts.storagePathHint);
  }

  // No envelope — inspect legacy markers.
  const legacyParamsRaw = await storage.read("_meta", "key-params");
  const legacyHashRaw = await storage.read("_meta", "recovery-key-hash");

  if (opts.passphrase !== undefined && legacyParamsRaw) {
    // Legacy passphrase fortress: master = Argon2id(passphrase, key-params).
    const params = JSON.parse(
      bytesToString(legacyParamsRaw)
    ) as KeyDerivationParams;
    const { key: masterKey } = await deriveMasterKey(opts.passphrase, params);

    // Never lock in a wrong credential: verify against existing ciphertext.
    const evidence = await checkMasterEvidence(storage, masterKey);
    if (evidence === "contradicted") {
      masterKey.fill(0);
      throw new CustodyMigrationRefusedError();
    }

    const wrap = await wrapMasterWithPassphrase(masterKey, opts.passphrase, {
      verified: true,
    });
    const migrated: CustodyEnvelope = {
      v: 1,
      install_mode: "legacy-migrated",
      wraps: [wrap],
      created_at: now,
    };
    await writeCustodyEnvelope(storage, migrated);
    return {
      masterKey,
      envelope: migrated,
      origin: "migrated-passphrase",
      keyProtection: "passphrase",
    };
  }

  if (opts.recoveryKey !== undefined && legacyHashRaw) {
    // Legacy recovery-key fortress: the recovery key IS the master.
    const recoveryKeyBytes = decodeRecoveryKey(opts.recoveryKey);
    const providedHash = stringToBytes(hashToString(recoveryKeyBytes));
    const storedHash = stringToBytes(bytesToString(legacyHashRaw));
    if (!constantTimeEqual(providedHash, storedHash)) {
      throw new CustodyUnlockError(
        "Sanctuary: recovery key does not match the stored key hash.\n" +
          "The recovery key provided via SANCTUARY_RECOVERY_KEY is incorrect.\n" +
          "Use the exact recovery key that was displayed at first run."
      );
    }
    const masterKey = recoveryKeyBytes;

    // The hash proves the key matches the marker, not the data — a fortress
    // touched by both legacy paths can have data under the *other* master.
    // Never lock in a master the evidence contradicts.
    const evidence = await checkMasterEvidence(storage, masterKey);
    if (evidence === "contradicted") {
      masterKey.fill(0);
      throw new CustodyMigrationRefusedError();
    }

    const wrap = wrapMasterWithRecoveryKey(masterKey, recoveryKeyBytes, {
      verified: true,
    });
    const migrated: CustodyEnvelope = {
      v: 1,
      install_mode: "legacy-migrated",
      wraps: [wrap],
      created_at: now,
    };
    await writeCustodyEnvelope(storage, migrated);
    return {
      masterKey,
      envelope: migrated,
      origin: "migrated-recovery-key",
      keyProtection: "recovery-key",
    };
  }

  // Legacy markers exist but the matching credential was not supplied.
  if (legacyHashRaw && opts.recoveryKey === undefined && opts.passphrase === undefined) {
    throw new CustodyCredentialMissingError(opts.storagePathHint);
  }
  if (legacyParamsRaw && opts.passphrase === undefined) {
    throw new CustodyUnlockError(
      "Sanctuary: passphrase required.\n\n" +
        "The fortress at this path uses passphrase-mode key derivation.\n" +
        "Set SANCTUARY_PASSPHRASE in your environment, or run\n" +
        "'sanctuary export-passphrase' to retrieve it from the macOS Keychain."
    );
  }
  if (legacyHashRaw) {
    // A passphrase was supplied against a recovery-key-mode fortress. The
    // legacy code path would silently derive a NEW master and orphan the
    // existing data; fail closed instead (#5).
    throw new CustodyUnlockError(
      "Sanctuary: this fortress uses recovery-key custody.\n" +
        "Supply SANCTUARY_RECOVERY_KEY (the key captured at creation) instead of\n" +
        "a passphrase. Refusing to derive a new master over existing data."
    );
  }

  // Genuine first run.
  if (!opts.firstRun) {
    throw new CustodyCredentialMissingError(opts.storagePathHint);
  }

  const wraps: CustodyWrap[] = [];
  let masterKey: Uint8Array;
  let keyProtection: "passphrase" | "recovery-key";
  let mintedRecoveryKey: string | undefined;

  if (opts.passphrase !== undefined) {
    masterKey = generateRandomKey();
    keyProtection = "passphrase";
    wraps.push(
      await wrapMasterWithPassphrase(masterKey, opts.passphrase, {
        verified: true,
      })
    );
  } else if (opts.recoveryKey !== undefined) {
    // Operator-supplied recovery key on a virgin fortress (legacy `init`
    // compatibility): preserve the legacy semantics where that key IS the
    // master — it is operator-held, so it is a user-held factor.
    masterKey = decodeRecoveryKey(opts.recoveryKey);
    keyProtection = "recovery-key";
    wraps.push(
      wrapMasterWithRecoveryKey(masterKey, masterKey, { verified: true })
    );
  } else {
    masterKey = generateRandomKey();
    keyProtection = "recovery-key";
  }

  if (opts.firstRun.mintRecoveryKey) {
    const recoveryKeyBytes = generateRandomKey();
    mintedRecoveryKey = toBase64url(recoveryKeyBytes);
    wraps.push(
      wrapMasterWithRecoveryKey(masterKey, recoveryKeyBytes, {
        // Non-interactive callers cannot re-entry-verify; interactive
        // callers upgrade this flag after the operator re-enters the key.
        verified: false,
      })
    );
    recoveryKeyBytes.fill(0);
  }

  if (opts.keychainKey !== undefined) {
    wraps.push(
      wrapMasterWithKeychainKey(masterKey, opts.keychainKey, { verified: true })
    );
  }

  if (wraps.length === 0) {
    // No credential and no minting requested: there is nothing the user
    // could ever present to unlock this fortress. Refuse (F3 spirit).
    masterKey.fill(0);
    throw new SilentCustodyRefusedError("first run with no enrollable factor");
  }

  const fresh: CustodyEnvelope = {
    v: 1,
    install_mode: opts.firstRun.installMode,
    wraps,
    created_at: now,
  };
  await writeCustodyEnvelope(storage, fresh);

  const result: EstablishMasterResult = {
    masterKey,
    envelope: fresh,
    origin: "first-run",
    keyProtection,
  };
  if (mintedRecoveryKey !== undefined) {
    result.mintedRecoveryKey = mintedRecoveryKey;
  }
  return result;
}

/**
 * Thin adapter for CLI verbs that need the fortress master key. Replaces
 * the copy-pasted "read key-params → deriveMasterKey → maybe persist params"
 * blocks that re-implemented master establishment per verb — each of those
 * was an F2-class divergence generator (a verb could derive, and even
 * persist, a DIFFERENT master than the fortress's real one).
 *
 * `bootstrap: true` allows establishing custody on a virgin fortress
 * (recorded as a headless install); without it, virgin fortresses fail
 * closed — operating verbs must not invent custody.
 */
export async function resolveCliMasterKey(
  storage: StorageBackend,
  opts: {
    passphrase?: string;
    recoveryKey?: string;
    bootstrap?: boolean;
    storagePathHint?: string;
  }
): Promise<Uint8Array> {
  const result = await establishMaster({
    storage,
    ...(opts.passphrase !== undefined ? { passphrase: opts.passphrase } : {}),
    ...(opts.recoveryKey !== undefined ? { recoveryKey: opts.recoveryKey } : {}),
    ...(opts.bootstrap
      ? {
          firstRun: {
            installMode: "headless" as CustodyInstallMode,
            mintRecoveryKey: false,
          },
        }
      : {}),
    ...(opts.storagePathHint !== undefined
      ? { storagePathHint: opts.storagePathHint }
      : {}),
  });
  return result.masterKey;
}

/**
 * Mark the recovery-key wrap as operator-verified (after re-entry). The
 * re-entered key is proven by unwrapping the master with it — an end-to-end
 * "the string the user saved unlocks everything" check, not a string compare.
 */
export async function verifyRecoveryWrapByReentry(
  storage: StorageBackend,
  envelope: CustodyEnvelope,
  reenteredKey: string
): Promise<CustodyEnvelope> {
  const master = await unwrapMaster(envelope, {
    recoveryKey: decodeRecoveryKey(reenteredKey),
  });
  master.fill(0);
  const updated: CustodyEnvelope = {
    ...envelope,
    wraps: envelope.wraps.map((w) =>
      w.type === "recovery-key" ? { ...w, verified: true } : w
    ),
  };
  await writeCustodyEnvelope(storage, updated);
  return updated;
}

/**
 * Add a freshly minted recovery-key wrap of the (already unlocked) master to
 * an existing envelope — the migration completion step that makes a
 * passphrase-mode fortress actually recoverable. Returns the new recovery
 * key for disclosure; the wrap starts unverified until re-entry.
 */
export async function mintRecoveryWrap(
  storage: StorageBackend,
  envelope: CustodyEnvelope,
  masterKey: Uint8Array
): Promise<{ envelope: CustodyEnvelope; recoveryKey: string }> {
  const recoveryKeyBytes = generateRandomKey();
  const recoveryKey = toBase64url(recoveryKeyBytes);
  const wrap = wrapMasterWithRecoveryKey(masterKey, recoveryKeyBytes, {
    verified: false,
  });
  recoveryKeyBytes.fill(0);
  const updated: CustodyEnvelope = {
    ...envelope,
    wraps: [...envelope.wraps, wrap],
  };
  await writeCustodyEnvelope(storage, updated);
  return { envelope: updated, recoveryKey };
}

// ── Castle-pin custody diagnostic ───────────────────────────────────

/**
 * Check that the fortress's Castle Wall pinned private key decrypts under
 * the established master. A mismatch is the dual-path damage signature from
 * the 2026-06-12 incident (pin wrapped under a master nobody can produce).
 * Diagnostic only: the caller audits/warns; boot proceeds (the cure is an
 * operator-gated re-pin, not a silent rewrite).
 */
export async function checkCastlePinCustody(
  fortressPath: string,
  masterKey: Uint8Array
): Promise<"ok" | "mismatch" | "absent"> {
  let raw: string;
  try {
    raw = await readFile(
      join(fortressPath, "castle-pinned-privkey.enc"),
      "utf-8"
    );
  } catch {
    return "absent";
  }
  try {
    const payload = JSON.parse(raw) as EncryptedPayload;
    const seed = decrypt(payload, masterKey);
    seed.fill(0);
    return "ok";
  } catch {
    return "mismatch";
  }
}
