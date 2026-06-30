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
  derivePurposeKey,
  type KeyDerivationParams,
} from "./key-derivation.js";
import { generateRandomKey } from "./random.js";
import { hashToString, hmacSha256 } from "./hashing.js";
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
  /**
   * Random per-wrap id, bound into the wrap's AEAD AAD so a wrap cannot be
   * duplicated or transplanted between envelopes without detection (the
   * envelope MAC covers the id list and ciphertext digests).
   */
  id: string;
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
  /**
   * Anti-rollback epoch (Stage 1): the #501 master-rotation count, 0 at
   * creation. ADDITIVE and version-tolerant — absent reads as epoch 0 for
   * pre-Stage-1 fortresses. Bound into the envelope MAC ONLY WHEN PRESENT
   * (see {@link envelopeCanonicalMetadata}), so an existing fortress's MAC
   * does not change until it next acquires an epoch. A boot-time cross-check
   * (core/anti-rollback.ts) compares this against the on-disk witnesses; a
   * regression freezes trust-bearing writes (never bricks boot). See
   * {@link readEnvelopeEpoch}.
   */
  epoch?: number;
  /** Last rotation_id (or a creation nonce at epoch 0). Bound into the MAC
   * only when `epoch` is present. Advisory provenance for the operator. */
  epoch_id?: string;
  /**
   * HMAC-SHA256 over the envelope's policy-bearing metadata (install_mode,
   * wrap ids/types/verified flags, wrap-ciphertext digests, and the epoch
   * when present), keyed from HKDF(master, "custody-envelope-mac"). An
   * attacker with bare write access to `_meta` cannot flip install_mode or
   * verified flags, nor splice wraps in or out, nor lower the epoch, without
   * the master (codex finding H2/M2; anti-rollback Stage 1).
   */
  mac: string;
  /**
   * TRANSIENT read-only flag, NEVER persisted. Set by
   * {@link readCustodyEnvelope} when it accepts a structurally-valid
   * PRE-MAC legacy envelope, one written by a Sanctuary build before the
   * "one master per fortress" change added the top-level `mac` and per-wrap
   * `id` (#496). Such an envelope has no authenticated `install_mode` to have
   * been tampered, so it is accepted on read (additive backward-compat, the
   * same "absent field = older shape, allowed" philosophy as the epoch-absent
   * handling) and RE-STAMPED in place by {@link establishMaster} on the first
   * unlock, once the master is available and verified against existing
   * ciphertext. Callers that perform the strict {@link verifyEnvelopeMac}
   * check must migrate first (the synthesized `mac` is empty and will not
   * verify). This field is stripped before any write (see
   * {@link writeCustodyEnvelope}).
   */
  needsMacMigration?: boolean;
}

/**
 * The on-disk custody epoch for the anti-rollback cross-check (Stage 1).
 * Absent `epoch` reads as 0 — a pre-Stage-1 fortress is "epoch 0" and trips
 * nothing until a rotation or an explicit witness raises the floor. Reads the
 * persisted envelope directly so callers that only have a `StorageBackend`
 * (the boot detector) do not need the unwrapped envelope object.
 */
export async function readEnvelopeEpoch(
  storage: StorageBackend
): Promise<number> {
  const envelope = await readCustodyEnvelope(storage);
  return envelopeEpochOf(envelope);
}

/** The epoch of a read envelope (absent → 0). */
export function envelopeEpochOf(envelope: CustodyEnvelope | null): number {
  if (!envelope || typeof envelope.epoch !== "number") return 0;
  return envelope.epoch;
}

const CUSTODY_INSTALL_MODES: ReadonlySet<string> = new Set([
  "interactive",
  "headless",
  "stdio-server",
  "legacy-migrated",
]);

/** `_meta` key holding the envelope. */
export const CUSTODY_ENVELOPE_KEY = "custody-envelope";

/**
 * `_meta` key holding the master-rotation journal (core/master-rotation.ts).
 * Its PRESENCE means a rotation is in flight: some fortress data may be under
 * the old master and some under the new. Every establishment path refuses to
 * proceed until the rotation is resumed to completion (or rolled back from
 * the staging phase) — booting half-keyed is exactly the split-state lockout
 * the custody work exists to kill.
 */
export const ROTATION_JOURNAL_KEY = "rotation-journal";

/** `_meta` keys staged by an in-flight rotation (promoted at finalize). */
export const STAGED_CUSTODY_ENVELOPE_KEY = "custody-envelope-next";
export const STAGED_CUSTODY_SENTINEL_KEY = "custody-sentinel-next";

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
 * Non-secret factor inventory for the actionable unlock-failure diagnostic
 * (element 2). Built from the custody envelope's policy metadata (wrap types,
 * verified flags, install mode) — NEVER any key material or KDF parameters
 * (CLAUDE.md #6) — plus the live OS-keyring reachability the boot path probed.
 */
export interface UnlockDiagnosticInput {
  /** Distinct enrolled custody factor types (passphrase / recovery-key / keychain). */
  enrolledFactors: CustodyWrapType[];
  /** Whether a passphrase wrap exists. */
  hasPassphraseFactor: boolean;
  /** Whether a keychain (OS-keyring) custody wrap exists. */
  hasKeychainFactor: boolean;
  /**
   * Live reachability of the OS keyring, when the boot path probed it:
   *  - "unreachable": the keyring is locked / no GUI / error 36 (element 3),
   *  - "not-found": reachable but the item is absent,
   *  - "found": the item is present (so a missing factor is NOT the keyring),
   *  - undefined: not probed.
   */
  keychainReachability?: "found" | "not-found" | "unreachable";
  /** Operator-facing storage path (hint only; never crypto). */
  storagePathHint?: string;
  /** The per-tenant passphrase keyring service name, for the GUI-unlock hint. */
  keychainServiceHint?: string;
}

/**
 * Build the actionable unlock-failure message (element 2). States which
 * factors are enrolled, whether the OS keyring is locked vs the item absent,
 * the GUI unlock step, and the literal `SANCTUARY_RECOVERY_KEY=...` recovery
 * command. Deliberately does NOT print where any key is stored on disk — on
 * the durable-fix boot paths there is no on-disk recovery copy, and pointing
 * at one would be the at-rest co-located secret this fix removes.
 */
export function buildActionableUnlockMessage(
  input: UnlockDiagnosticInput
): string {
  const lines: string[] = [];
  lines.push(
    "Sanctuary: cannot unlock this fortress" +
      (input.storagePathHint ? ` at ${input.storagePathHint}` : "") +
      " with the available factors."
  );
  lines.push("");

  // What is enrolled (non-secret metadata only).
  if (input.enrolledFactors.length > 0) {
    const human = input.enrolledFactors
      .map((f) =>
        f === "passphrase"
          ? "passphrase"
          : f === "recovery-key"
            ? "recovery key"
            : "OS keyring (Keychain / Secret Service)"
      )
      .join(", ");
    lines.push(`Enrolled recovery factors on this fortress: ${human}.`);
  } else {
    lines.push(
      "No custody envelope factor metadata is readable; this may be a legacy fortress."
    );
  }

  // Keychain-locked guidance (the headless / SSH lockout, element 3).
  if (input.hasKeychainFactor) {
    if (input.keychainReachability === "unreachable") {
      lines.push("");
      lines.push(
        "The OS keyring factor is enrolled but the keyring is LOCKED or unreachable\n" +
          "in this session (typical over SSH / headless: macOS error 36, or no D-Bus\n" +
          "session bus on Linux). Either:\n" +
          "  - run from a desktop session and unlock the keyring via its GUI\n" +
          "    (Keychain Access on macOS, Seahorse / KWallet on Linux), or\n" +
          "  - provide an explicit factor below instead."
      );
    } else if (input.keychainReachability === "not-found") {
      lines.push("");
      lines.push(
        "The OS keyring factor is enrolled but its item is MISSING from the keyring\n" +
          "(it may have been deleted). Use an explicit factor below to recover."
      );
    }
  }

  // The explicit, always-available recovery commands.
  lines.push("");
  lines.push("Provide ONE of these explicitly to start:");
  if (input.hasPassphraseFactor) {
    lines.push("  SANCTUARY_PASSPHRASE=<your fortress passphrase>");
  }
  lines.push(
    "  SANCTUARY_RECOVERY_KEY=<the recovery key you saved in your password manager>"
  );
  lines.push("");
  lines.push(
    "Example:\n" +
      "  SANCTUARY_RECOVERY_KEY=... sanctuary dashboard" +
      (input.storagePathHint ? ` --fortress ${input.storagePathHint}` : "")
  );
  if (input.keychainServiceHint) {
    lines.push("");
    lines.push(
      `This tenant's passphrase keyring service: ${input.keychainServiceHint}\n` +
        "(see server/docs/keychain-schema.md for the keychain layout)."
    );
  }
  lines.push("");
  lines.push(
    "Refusing to start without a valid credential (starting with a wrong master\n" +
      "would split state, not recover it)."
  );
  return lines.join("\n");
}

/**
 * Read the non-secret factor inventory from a fortress's custody envelope for
 * the unlock diagnostic. Returns empty when there is no readable envelope
 * (legacy / first run). Never touches key material or KDF params.
 */
export async function readEnrolledFactors(storage: StorageBackend): Promise<{
  enrolledFactors: CustodyWrapType[];
  hasPassphraseFactor: boolean;
  hasKeychainFactor: boolean;
}> {
  let envelope: CustodyEnvelope | null = null;
  try {
    envelope = await readCustodyEnvelope(storage);
  } catch {
    // Unreadable envelope: report nothing rather than throw from a diagnostic.
  }
  if (!envelope) {
    return {
      enrolledFactors: [],
      hasPassphraseFactor: false,
      hasKeychainFactor: false,
    };
  }
  const distinct = Array.from(new Set(envelope.wraps.map((w) => w.type)));
  return {
    enrolledFactors: distinct,
    hasPassphraseFactor: distinct.includes("passphrase"),
    hasKeychainFactor: distinct.includes("keychain"),
  };
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
 * A suspected custody rollback has FROZEN trust-bearing writes (anti-rollback
 * Stage 1). Raised from the same `enforceCustodyFloor` chokepoint as the
 * two-factor floor so identity creation / reputation import / Castle-pin
 * provisioning all refuse uniformly until the operator runs an audited
 * `restore-attest`. Boot is NEVER refused — only trust-bearing writes are.
 */
export class CustodyRollbackFrozenError extends Error {
  constructor(action: string) {
    super(
      `Sanctuary: refusing to persist trust-bearing state (${action}).\n` +
        "A SUSPECTED CUSTODY ROLLBACK has frozen trust-bearing writes on this\n" +
        "fortress: its on-disk custody epoch is older than a surviving witness, so\n" +
        "a snapshot may have been restored (legitimately) or rolled back by an\n" +
        "attacker to resurrect a retired credential. Reads and boot are unaffected.\n" +
        "Acknowledge and unfreeze with an audited attestation:\n" +
        "  sanctuary restore-attest   (requires the fortress passphrase)\n" +
        "If you did not restore anything, rotate the master before attesting."
    );
    this.name = "CustodyRollbackFrozenError";
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

/**
 * Custody envelope integrity failure: the envelope's MAC does not verify
 * under the established master. Either the envelope was tampered with or
 * it belongs to a different fortress. Always fail closed.
 */
export class CustodyEnvelopeIntegrityError extends Error {
  constructor(detail?: string) {
    super(
      detail ??
        "Sanctuary: custody envelope failed its integrity check.\n" +
          "The envelope's policy metadata (install mode, enrolled factors) does not\n" +
          "verify under this fortress's master key — it may have been tampered with\n" +
          "or replaced. Refusing to proceed. Restore _meta/custody-envelope from a\n" +
          "trusted backup."
    );
    this.name = "CustodyEnvelopeIntegrityError";
  }
}

/**
 * A master rotation is in flight (the rotation journal exists). Normal
 * establishment refuses: the fortress may hold a mix of old-master and
 * new-master ciphertext until the rotation completes.
 */
export class CustodyRotationInProgressError extends Error {
  constructor() {
    super(
      "Sanctuary: a master-key rotation is in progress on this fortress.\n" +
        "Some data may still be encrypted under the previous master. Refusing to\n" +
        "start until the rotation completes. Run:\n" +
        "  sanctuary rotate-master --resume\n" +
        "to finish it (or `sanctuary rotate-master --abort` if it never left the\n" +
        "staging phase). Both require the fortress passphrase."
    );
    this.name = "CustodyRotationInProgressError";
  }
}

/** Message for "the sentinel proves an envelope existed, but it is gone". */
function envelopeMissingButSentinelPresent(): CustodyEnvelopeIntegrityError {
  return new CustodyEnvelopeIntegrityError(
    "Sanctuary: this fortress's custody sentinel exists but its custody envelope\n" +
      "is missing or unreadable. The envelope was deleted, hidden, or corrupted —\n" +
      "refusing to fall back to legacy custody or re-create the envelope (that\n" +
      "would strip enrolled factors and policy). Restore _meta/custody-envelope\n" +
      "from a trusted backup."
  );
}

/**
 * Message for "a pre-mac legacy envelope exists but a sentinel is present":
 * a sentinel proves a MAC'd envelope was written, so a mac-ABSENT envelope is
 * tampering (the mac was stripped), not a genuine pre-mac fortress. Fail
 * closed; never re-stamp (re-stamping would launder a stripped mac and could
 * resurrect a downgraded install_mode). Mirrors
 * {@link envelopeMissingButSentinelPresent}.
 */
function legacyEnvelopeButSentinelPresent(): CustodyEnvelopeIntegrityError {
  return new CustodyEnvelopeIntegrityError(
    "Sanctuary: this fortress's custody sentinel exists but its custody envelope\n" +
      "has no integrity MAC. A sentinel is only written alongside a MAC'd\n" +
      "envelope, so the MAC was stripped. Refusing to re-stamp it (that would\n" +
      "launder a tampered envelope and could downgrade the install mode).\n" +
      "Restore _meta/custody-envelope from a trusted backup."
  );
}

/**
 * Existing encrypted data was found with no custody envelope and no legacy
 * markers. Creating fresh custody over it would orphan the data (split
 * state) — fail closed instead (codex finding H1).
 */
export class OrphanedFortressStateError extends Error {
  constructor() {
    super(
      "Sanctuary: this fortress contains existing data but no custody envelope\n" +
        "and no legacy key markers. Refusing to create a fresh master over it —\n" +
        "that would orphan the existing encrypted state.\n" +
        "Restore _meta/custody-envelope (or _meta/key-params / _meta/recovery-key-hash)\n" +
        "from backup, or explicitly re-initialize the fortress at a clean path."
    );
    this.name = "OrphanedFortressStateError";
  }
}

// ── Wrap primitives ─────────────────────────────────────────────────

function custodyAad(type: CustodyWrapType, id: string): Uint8Array {
  return stringToBytes(`${CUSTODY_HKDF_SALT}:${type}:${id}`);
}

/**
 * AEAD AAD for a PRE-MAC legacy wrap, one written before per-wrap ids
 * existed (#496 backward-compat). Such a wrap's payload was bound WITHOUT an
 * id, so it must be decrypted with this id-less AAD. The current id-bound
 * {@link custodyAad} cannot recover it because the id it would supply
 * (synthesized at read time) was never part of the ciphertext's AAD. On
 * migration the wrap is RE-wrapped under the current id-bound AAD, after which
 * this legacy AAD is never used for it again.
 */
function legacyCustodyAad(type: CustodyWrapType): Uint8Array {
  return stringToBytes(`${CUSTODY_HKDF_SALT}:${type}`);
}

function newWrapId(): string {
  return toBase64url(generateRandomKey().subarray(0, 16));
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
  const id = newWrapId();
  const { key: wrapKey, params } = await deriveMasterKey(passphrase);
  const payload = encrypt(master, wrapKey, custodyAad("passphrase", id));
  wrapKey.fill(0);
  return {
    id,
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
  const id = newWrapId();
  const wrapKey = recoveryWrapKey(recoveryKeyBytes);
  const payload = encrypt(master, wrapKey, custodyAad("recovery-key", id));
  wrapKey.fill(0);
  return {
    id,
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
  const id = newWrapId();
  const wrapKey = keychainWrapKey(custodyKeyBytes);
  const payload = encrypt(master, wrapKey, custodyAad("keychain", id));
  wrapKey.fill(0);
  return {
    id,
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

  // A PRE-MAC legacy envelope (#496 backward-compat) carries wraps whose
  // ciphertext was bound WITHOUT a per-wrap id, so the unwrap must also try
  // the id-less legacy AAD. GCM authentication still decides; the legacy AAD
  // is just an additional candidate, never a weaker derivation (#5).
  const match = await unwrapMatchingWrap(envelope.wraps, credential, type, {
    legacyNoId: envelope.needsMacMigration === true,
  });
  if (!match) throw new CustodyUnlockError();
  return match.master;
}

/**
 * Unwrap a master from a bare list of custody wraps with one credential.
 * Used by flows that carry wraps OUTSIDE a fortress envelope (e.g. the
 * exit bundle's `source_custody` block, where the source fortress's
 * user-held wraps travel with the bundle so import can recover the source
 * master without any parallel derivation path). Returns null when no wrap
 * of the credential's type authenticates — the caller decides the error.
 * GCM authentication decides; there is no weaker fallback (#5).
 */
export async function unwrapMasterFromWraps(
  wraps: CustodyWrap[],
  credential: CustodyCredential
): Promise<Uint8Array | null> {
  const type: CustodyWrapType =
    "passphrase" in credential
      ? "passphrase"
      : "recoveryKey" in credential
        ? "recovery-key"
        : "keychain";
  const match = await unwrapMatchingWrap(wraps, credential, type);
  return match ? match.master : null;
}

/**
 * Try every wrap of `type`; return the master AND the exact wrap that
 * decrypted it (so verification flows mark only that wrap — codex M1).
 */
async function unwrapMatchingWrap(
  wraps: CustodyWrap[],
  credential: CustodyCredential,
  type: CustodyWrapType,
  opts?: { legacyNoId?: boolean }
): Promise<{ master: Uint8Array; wrapId: string } | null> {
  for (const wrap of wraps) {
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
        // Candidate AADs in order. The current id-bound AAD is the norm; a
        // pre-mac legacy envelope additionally allows the id-less AAD its
        // wraps were actually bound with. GCM authentication accepts at most
        // one. There is no weaker fallback, only an additional candidate.
        const aads = opts?.legacyNoId
          ? [legacyCustodyAad(type), custodyAad(type, wrap.id)]
          : [custodyAad(type, wrap.id)];
        for (const aad of aads) {
          try {
            const master = decrypt(wrap.payload, wrapKey, aad);
            return { master, wrapId: wrap.id };
          } catch {
            // Wrong AAD for this wrap; try the next candidate.
          }
        }
      } finally {
        wrapKey.fill(0);
      }
    } catch {
      // Wrong credential for this wrap (or malformed wrap) — try the next
      // wrap of the same type. Never fall back to a weaker path.
    }
  }
  return null;
}

// ── Envelope MAC (codex H2/M2) ──────────────────────────────────────

const ENVELOPE_MAC_DOMAIN = "sanctuary-custody-envelope-mac-v1\n";

function envelopeCanonicalMetadata(
  envelope: Omit<CustodyEnvelope, "mac">
): string {
  // Field order is fixed by construction; ciphertext digests bind the wrap
  // payloads without putting key-derived bytes in the MAC input.
  const base: Record<string, unknown> = {
    v: envelope.v,
    install_mode: envelope.install_mode,
    wraps: envelope.wraps.map((w) => ({
      id: w.id,
      type: w.type,
      verified: w.verified,
      ct: hashToString(stringToBytes(w.payload.ct)),
    })),
  };
  // Anti-rollback Stage 1: bind the epoch into the MAC ONLY WHEN PRESENT, so a
  // pre-Stage-1 envelope (no epoch) verifies under its existing MAC unchanged.
  // Once an envelope carries an epoch, the epoch + epoch_id are authenticated,
  // so an attacker cannot lower the epoch on disk without the master.
  if (typeof envelope.epoch === "number") {
    base.epoch = envelope.epoch;
    base.epoch_id = envelope.epoch_id ?? "";
  }
  return JSON.stringify(base);
}

function computeEnvelopeMac(
  envelope: Omit<CustodyEnvelope, "mac">,
  master: Uint8Array
): string {
  const macKey = derivePurposeKey(master, "custody-envelope-mac");
  const mac = hmacSha256(
    macKey,
    stringToBytes(ENVELOPE_MAC_DOMAIN + envelopeCanonicalMetadata(envelope))
  );
  macKey.fill(0);
  return toBase64url(mac);
}

/**
 * Verify the envelope's policy MAC under the established master. Throws
 * {@link CustodyEnvelopeIntegrityError} on mismatch — always fail closed.
 */
export function verifyEnvelopeMac(
  envelope: CustodyEnvelope,
  master: Uint8Array
): void {
  const expected = computeEnvelopeMac(envelope, master);
  if (
    !constantTimeEqual(stringToBytes(expected), stringToBytes(envelope.mac))
  ) {
    throw new CustodyEnvelopeIntegrityError();
  }
}

// ── Envelope persistence ────────────────────────────────────────────

export async function readCustodyEnvelope(
  storage: StorageBackend,
  opts?: { envelopeKey?: string }
): Promise<CustodyEnvelope | null> {
  // A storage READ ERROR propagates (fail closed): treating an unreadable
  // envelope as "absent" let an attacker who could make the file unreadable
  // demote the fortress to floor-exempt legacy custody (codex round-2 H2).
  const raw = await storage.read(
    "_meta",
    opts?.envelopeKey ?? CUSTODY_ENVELOPE_KEY
  );
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

  // Common structural floor shared by both the current and the pre-mac legacy
  // shapes. A genuinely-malformed envelope (bad version, non-array wraps,
  // wraps missing type/verified/payload, malformed epoch) is ALWAYS rejected;
  // the only fields a legacy envelope is permitted to lack are the top-level
  // `mac` and the per-wrap `id` (both added by #496 "one master per fortress").
  const structurallyValid =
    envelope !== null &&
    typeof envelope === "object" &&
    envelope.v === 1 &&
    Array.isArray(envelope.wraps) &&
    CUSTODY_INSTALL_MODES.has(envelope.install_mode) &&
    // Anti-rollback Stage 1: when present, epoch must be a non-negative safe
    // integer and epoch_id a string — a malformed epoch fails closed (the MAC
    // would not verify anyway, but reject early so the boot detector never
    // sees a garbage epoch). Absent epoch is the pre-Stage-1 shape: allowed.
    !(
      envelope.epoch !== undefined &&
      (typeof envelope.epoch !== "number" ||
        !Number.isSafeInteger(envelope.epoch) ||
        envelope.epoch < 0)
    ) &&
    !(envelope.epoch_id !== undefined && typeof envelope.epoch_id !== "string") &&
    envelope.wraps.every(
      (w) =>
        w !== null &&
        typeof w === "object" &&
        typeof w?.type === "string" &&
        typeof w?.verified === "boolean" &&
        typeof w?.payload === "object"
    );

  if (!structurallyValid) {
    throw new Error(
      "Sanctuary: custody envelope exists but has an unsupported shape or version.\n" +
        "Refusing to start. Restore _meta/custody-envelope from backup or upgrade Sanctuary."
    );
  }

  // PRE-MAC legacy detection (#496 backward-compat): a top-level `mac` that is
  // not a string, OR any wrap whose `id` is not a string, marks an envelope
  // written before the mac+wrap-id fields existed. Distinguish it from a
  // genuinely-malformed envelope (already rejected above) and from a current
  // envelope, then accept it as needs-migration. The master is NOT available
  // here, so the re-stamp (computing the real `mac`, assigning persistent wrap
  // `id`s, verifying the master against existing ciphertext, and writing the
  // upgraded envelope) is performed by `establishMaster` on the first unlock,
  // NEVER silently here. Same additive "absent field = older shape, allowed"
  // philosophy as the epoch-absent handling above.
  const macAbsent = typeof envelope.mac !== "string";
  const anyWrapIdAbsent = envelope.wraps.some((w) => typeof w?.id !== "string");

  if (macAbsent || anyWrapIdAbsent) {
    // Assign DETERMINISTIC, STABLE synthetic wrap ids by position so the
    // recomputed MAC is reproducible across repeated reads of the same
    // on-disk envelope. These synthetic ids are TRANSIENT, not persisted: the
    // re-stamp in `establishMaster` re-wraps every wrap via `reWrapLegacyWrap`,
    // which assigns a FRESH random id (`newWrapId`) and persists THAT; the
    // `legacy-${i}` ids never reach disk. They serve only read-to-read MAC
    // reproducibility here. Wraps that already carry an id (mixed/partial
    // legacy) keep theirs. The AEAD AAD for each wrap was bound with the wrap's
    // id at WRITE time; a pre-mac legacy wrap was written before per-wrap ids
    // existed, so its payload decrypts under the id-less `legacyCustodyAad` and
    // the synthetic id never affects decryption (see `establishMaster`).
    const migrated: CustodyEnvelope = {
      ...envelope,
      wraps: envelope.wraps.map((w, i) => ({
        ...w,
        id: typeof w?.id === "string" ? w.id : `legacy-${i}`,
      })),
      mac: typeof envelope.mac === "string" ? envelope.mac : "",
      needsMacMigration: true,
    };
    return migrated;
  }

  return envelope;
}

/** Plaintext + purpose label for the custody sentinel (see write below). */
export const CUSTODY_SENTINEL_KEY = "custody-sentinel";
const CUSTODY_SENTINEL_PLAINTEXT = "sanctuary-custody-sentinel-v1";

/**
 * Persist the envelope: stamps the policy MAC (requires the master) and
 * maintains the custody sentinel — a small ciphertext under
 * HKDF(master, "custody-sentinel") that future recovery/diagnostic flows
 * can verify a candidate master against even if the envelope itself is
 * lost or damaged.
 */
export async function writeCustodyEnvelope(
  storage: StorageBackend,
  envelope: Omit<CustodyEnvelope, "mac"> | CustodyEnvelope,
  master: Uint8Array,
  opts?: {
    /**
     * Alternate `_meta` keys for the envelope + sentinel. Used ONLY by the
     * master-rotation engine to STAGE the next custody envelope at
     * `custody-envelope-next` while the live envelope stays authoritative;
     * the staged pair is promoted to the real keys at finalize.
     */
    envelopeKey?: string;
    sentinelKey?: string;
  }
): Promise<CustodyEnvelope> {
  assertMaster(master);
  const stamped: CustodyEnvelope = {
    v: envelope.v,
    install_mode: envelope.install_mode,
    wraps: envelope.wraps,
    created_at: envelope.created_at,
    // Anti-rollback Stage 1: carry the epoch through when present (additive).
    ...(typeof envelope.epoch === "number"
      ? { epoch: envelope.epoch, epoch_id: envelope.epoch_id ?? "" }
      : {}),
    mac: computeEnvelopeMac(envelope, master),
  };
  await storage.write(
    "_meta",
    opts?.envelopeKey ?? CUSTODY_ENVELOPE_KEY,
    stringToBytes(JSON.stringify(stamped))
  );
  const sentinelKey = derivePurposeKey(master, "custody-sentinel");
  const sentinel = encrypt(
    stringToBytes(CUSTODY_SENTINEL_PLAINTEXT),
    sentinelKey,
    stringToBytes(CUSTODY_SENTINEL_PLAINTEXT)
  );
  sentinelKey.fill(0);
  await storage.write(
    "_meta",
    opts?.sentinelKey ?? CUSTODY_SENTINEL_KEY,
    stringToBytes(JSON.stringify(sentinel))
  );
  return stamped;
}

// ── Two-factor floor (I4 / F6) ──────────────────────────────────────

/**
 * Count DISTINCT verified factor types (codex M1: duplicated wraps of one
 * factor must not satisfy a two-factor floor).
 */
export function countVerifiedWraps(envelope: CustodyEnvelope): number {
  return new Set(
    envelope.wraps.filter((w) => w.verified).map((w) => w.type)
  ).size;
}

/**
 * Enforce the two-factor custody floor at a "persist trust-bearing state"
 * boundary. The caller supplies the fortress master so the envelope's
 * policy metadata can be authenticated first (codex H2: never honor
 * unauthenticated install_mode / verified flags). Passes when:
 *  - the fortress predates the envelope (legacy compat — it becomes
 *    `legacy-migrated` on first unified unlock), or
 *  - ≥ {@link CUSTODY_FLOOR_WRAPS} distinct verified factor types exist, or
 *  - the fortress was created through an explicit degraded install mode
 *    (`headless`, `stdio-server`, `legacy-migrated`) — those modes are
 *    audited at creation and visible in the envelope, never silent.
 *
 * Refuses (throws {@link CustodyFloorError}) for an `interactive` install
 * that never completed verification — by construction such a fortress holds
 * nothing precious yet, so re-initializing it is safe. Throws
 * {@link CustodyEnvelopeIntegrityError} on a tampered envelope.
 */
export async function enforceCustodyFloor(
  storage: StorageBackend,
  action: string,
  masterKey: Uint8Array
): Promise<void> {
  // Anti-rollback Stage 1: a suspected rollback freezes trust-bearing writes at
  // this same chokepoint. Checked FIRST. `isRollbackFrozenWithRecompute` is
  // fail-closed on a tampered freeze marker AND re-derives the verdict from the
  // witness set when the marker is ABSENT (codex r2 MEDIUM) — so deleting the
  // freeze cache cannot unfreeze trust-bearing writes. Lazy import avoids a
  // static cycle (anti-rollback dynamically reads back into this module).
  const { isRollbackFrozenWithRecompute } = await import("./anti-rollback.js");
  if ((await isRollbackFrozenWithRecompute(storage, masterKey)).frozen) {
    throw new CustodyRollbackFrozenError(action);
  }
  const envelope = await readCustodyEnvelope(storage);
  if (!envelope) {
    // The sentinel proves envelope-format custody existed: an absent
    // envelope is then tampering, not legacy (codex round-2 H2). Only a
    // fortress with NEITHER artifact is genuine pre-envelope legacy.
    if (await storage.read("_meta", CUSTODY_SENTINEL_KEY)) {
      throw envelopeMissingButSentinelPresent();
    }
    return;
  }
  if (envelope.needsMacMigration) {
    // PRE-MAC legacy envelope reaching the floor before its first unlock-time
    // migration. It has no MAC to verify, so do NOT call verifyEnvelopeMac
    // (an empty MAC would always throw). A sentinel beside a mac-absent
    // envelope is tamper (the MAC was stripped): fail closed; otherwise this
    // is a genuine pre-#496 fortress: treat as legacy-compatible (it migrates
    // to a degraded `legacy-migrated`/headless install on first unlock, which
    // is floor-exempt and audited), so do not block trust-bearing writes here.
    if (await storage.read("_meta", CUSTODY_SENTINEL_KEY)) {
      throw legacyEnvelopeButSentinelPresent();
    }
    return;
  }
  verifyEnvelopeMac(envelope, masterKey);
  if (countVerifiedWraps(envelope) >= CUSTODY_FLOOR_WRAPS) return;
  if (envelope.install_mode !== "interactive") return;
  throw new CustodyFloorError(action);
}

// ── Migration evidence check ────────────────────────────────────────

const EVIDENCE_PROBE_LIMIT = 3;

function parseEncryptedPayload(raw: Uint8Array): EncryptedPayload | null {
  try {
    const parsed = JSON.parse(bytesToString(raw)) as EncryptedPayload;
    if (
      parsed &&
      typeof parsed === "object" &&
      parsed.v === 1 &&
      parsed.alg === "aes-256-gcm" &&
      typeof parsed.iv === "string" &&
      typeof parsed.ct === "string"
    ) {
      return parsed;
    }
  } catch {
    // not an EncryptedPayload — no signal either way
  }
  return null;
}

/**
 * Verify a candidate master against existing fortress ciphertext before
 * trusting it for migration. Probes fortress-wide (codex H3), in order:
 * the custody sentinel, stored identities, reputation attestations, and
 * the encrypted audit chain. Returns:
 *  - "confirmed": some evidence decrypted — the master is right.
 *  - "contradicted": well-formed evidence exists but none decrypts.
 *  - "no-evidence": nothing checkable was found.
 */
async function checkMasterEvidence(
  storage: StorageBackend,
  master: Uint8Array
): Promise<"confirmed" | "contradicted" | "no-evidence"> {
  let sawWellFormed = false;

  // Sentinel (present on every envelope-format fortress).
  try {
    const raw = await storage.read("_meta", CUSTODY_SENTINEL_KEY);
    if (raw) {
      const payload = parseEncryptedPayload(raw);
      if (payload) {
        sawWellFormed = true;
        try {
          const sentinelKey = derivePurposeKey(master, "custody-sentinel");
          try {
            decrypt(payload, sentinelKey, stringToBytes(CUSTODY_SENTINEL_PLAINTEXT));
            return "confirmed";
          } finally {
            sentinelKey.fill(0);
          }
        } catch {
          // contradiction vote — fall through to other probes
        }
      }
    }
  } catch {
    // unreadable storage — no signal; the caller's data-presence check
    // decides whether migration may proceed
  }

  const purposeProbes: Array<{ namespace: string; purpose: string }> = [
    { namespace: "_identities", purpose: "identity-encryption" },
    { namespace: "_reputation", purpose: "l4-reputation" },
  ];
  for (const probe of purposeProbes) {
    let entries: Array<{ key: string }>;
    try {
      entries = await storage.list(probe.namespace);
    } catch {
      continue;
    }
    const key = derivePurposeKey(master, probe.purpose);
    try {
      for (const entry of entries.slice(0, EVIDENCE_PROBE_LIMIT)) {
        const raw = await storage.read(probe.namespace, entry.key);
        if (!raw) continue;
        const payload = parseEncryptedPayload(raw);
        if (!payload) continue;
        sawWellFormed = true;
        try {
          decrypt(payload, key);
          return "confirmed";
        } catch {
          // contradiction vote; keep probing
        }
      }
    } finally {
      key.fill(0);
    }
  }

  // Audit chain: entries are { ..., encrypted_payload_bytes: base64url(
  // JSON(EncryptedPayload)) } under HKDF(master, "audit-log").
  try {
    const entries = await storage.list("_audit");
    const auditKey = derivePurposeKey(master, "audit-log");
    try {
      for (const entry of entries.slice(0, EVIDENCE_PROBE_LIMIT)) {
        const raw = await storage.read("_audit", entry.key);
        if (!raw) continue;
        try {
          const outer = JSON.parse(bytesToString(raw)) as {
            encrypted_payload_bytes?: string;
          };
          if (typeof outer?.encrypted_payload_bytes !== "string") continue;
          const payload = parseEncryptedPayload(
            fromBase64url(outer.encrypted_payload_bytes)
          );
          if (!payload) continue;
          sawWellFormed = true;
          decrypt(payload, auditKey);
          return "confirmed";
        } catch {
          // malformed entry or contradiction vote; keep probing
        }
      }
    } finally {
      auditKey.fill(0);
    }
  } catch {
    // no audit namespace — no signal
  }

  return sawWellFormed ? "contradicted" : "no-evidence";
}

/**
 * True when the fortress holds any data beyond the legacy custody markers.
 * Used to (a) refuse first-run creation over orphaned state (codex H1) and
 * (b) defer migration when existing data cannot be evidence-checked
 * (codex H3 — never capture an unverifiable master into the envelope).
 * Errors count as "has data": the safe direction is to defer/refuse.
 */
async function fortressHasDataBeyondMarkers(
  storage: StorageBackend
): Promise<boolean> {
  try {
    const total = await storage.totalSize();
    if (total === 0) return false;
    const KNOWN_MARKERS = new Set(["key-params", "recovery-key-hash"]);
    const metaEntries = await storage.list("_meta");
    if (metaEntries.some((e) => !KNOWN_MARKERS.has(e.key))) return true;
    const markerBytes = metaEntries.reduce((sum, e) => sum + e.size_bytes, 0);
    return total > markerBytes;
  } catch {
    return true;
  }
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
  /**
   * Null only for `legacy-deferred`: the legacy unlock succeeded but the
   * fortress holds data the evidence probe could not verify the master
   * against, so NO envelope was written (capturing an unverifiable master
   * would risk locking out the real credential — codex H3). The fortress
   * stays pure-legacy and migrates on a later unlock once verifiable
   * evidence exists.
   */
  envelope: CustodyEnvelope | null;
  origin:
    | "envelope"
    | "migrated-passphrase"
    | "migrated-recovery-key"
    | "legacy-deferred"
    | "first-run";
  keyProtection: "passphrase" | "recovery-key";
  /** Present only when a fresh recovery key was minted on this call. */
  mintedRecoveryKey?: string;
  /**
   * True ONLY when this call re-stamped a pre-mac legacy envelope in place
   * (`needsMacMigration`): a full re-wrap under id-bound AAD + a fresh policy
   * MAC + a new sentinel. `origin` stays "envelope" (the master was unwrapped
   * from a real envelope, and a second unlock is an ordinary strict-MAC read),
   * so this flag is the ONLY signal that a security-relevant custody state
   * transition occurred. Boot paths gate the `custody_legacy_migrated` audit
   * event on it; without it the re-stamp would leave no audit trail.
   */
  migratedInPlace?: boolean;
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
 * Re-wrap ONE legacy wrap under the current id-bound AEAD AAD, re-deriving the
 * wrap key from the supplied credential (the only secret we hold). The wrap's
 * payload was bound with the id-less {@link legacyCustodyAad}; after this it is
 * bound with {@link custodyAad}`(type, freshId)` so a future strict read works.
 * The master is NOT re-derived or changed; only the AAD binding is upgraded.
 * Returns null when the wrap's type does not match the supplied credential
 * (we cannot re-derive that wrap key without its secret).
 */
async function reWrapLegacyWrap(
  wrap: CustodyWrap,
  master: Uint8Array,
  credential: CustodyCredential
): Promise<CustodyWrap | null> {
  const id = newWrapId();
  let wrapKey: Uint8Array;
  let kdf: KeyDerivationParams | undefined;
  if ("passphrase" in credential && wrap.type === "passphrase") {
    // Reuse the wrap's existing Argon2id params so the operator's SAME
    // passphrase keeps unlocking the fortress (no credential change).
    if (!wrap.kdf) return null;
    const derived = await deriveMasterKey(credential.passphrase, wrap.kdf);
    wrapKey = derived.key;
    kdf = wrap.kdf;
  } else if ("recoveryKey" in credential && wrap.type === "recovery-key") {
    wrapKey = recoveryWrapKey(credential.recoveryKey);
  } else if ("keychainKey" in credential && wrap.type === "keychain") {
    wrapKey = keychainWrapKey(credential.keychainKey);
  } else {
    return null;
  }
  try {
    const payload = encrypt(master, wrapKey, custodyAad(wrap.type, id));
    return {
      id,
      type: wrap.type,
      payload,
      ...(kdf ? { kdf } : {}),
      verified: wrap.verified,
      created_at: wrap.created_at,
    };
  } finally {
    wrapKey.fill(0);
  }
}

/**
 * Migrate a structurally-valid PRE-MAC legacy envelope (#496 backward-compat)
 * IN PLACE, now that the master has been unwrapped from it. A `v:1` envelope
 * that lacks the top-level `mac` and per-wrap `id` fields is ACCEPTED and
 * re-stamped here rather than rejected at read time.
 *
 * REACHABILITY (honest note, do not overclaim): the entire CustodyEnvelope
 * shape (`v:1`, `install_mode`, `wraps`, `mac`, per-wrap `id`) was introduced
 * together in #496, and `writeCustodyEnvelope` has computed the `mac` on every
 * write since that commit. No released Sanctuary build is known to have written
 * a mac-absent `v:1` envelope, so this branch is defense-in-depth for that
 * never-observed shape, NOT a remedy for a confirmed field brick. Genuine
 * pre-envelope (pre-#496) fortresses stored the master via legacy markers
 * (`_meta/key-params`, `_meta/recovery-key-hash`) and migrate through the
 * SEPARATE legacy-marker path below, never through this envelope branch. If an
 * on-disk mac-absent corpus is ever observed in the wild, cite the sample here.
 *
 * Models the legacy-marker migration writes below: verify the master against
 * existing ciphertext, then write a MAC'd v:1 envelope.
 *
 * HARD security invariants (fail closed):
 *  - SENTINEL PRESENT ⇒ a MAC'd envelope existed and its MAC was stripped:
 *    tamper, never migrate (mirrors {@link envelopeMissingButSentinelPresent}).
 *    The install_mode is re-stamped from the on-disk value ONLY in the
 *    no-sentinel case, so this is the gate that stops downgrade-laundering
 *    (e.g. flipping interactive→legacy-migrated to dodge the two-factor floor).
 *  - The unwrapped master must be CONFIRMED (or not contradicted) against
 *    existing fortress ciphertext before writing the blessed envelope, so a
 *    wrong/forged credential cannot mint a MAC'd envelope (same evidence check
 *    the legacy-marker paths use).
 *  - Every wrap is re-wrapped under the current id-bound AAD; a wrap we cannot
 *    re-wrap (its secret was not supplied) fails closed rather than silently
 *    breaking on the next strict read.
 */
async function migrateLegacyEnvelopeInPlace(
  storage: StorageBackend,
  envelope: CustodyEnvelope,
  master: Uint8Array,
  credential: CustodyCredential
): Promise<CustodyEnvelope> {
  // DANGEROUS case, fail closed. A sentinel is written only beside a MAC'd
  // envelope (writeCustodyEnvelope), so a mac-absent envelope WITH a sentinel
  // means the mac was stripped: treat as tamper, never re-stamp.
  if (await storage.read("_meta", CUSTODY_SENTINEL_KEY)) {
    throw legacyEnvelopeButSentinelPresent();
  }

  // Never bless a master the fortress's existing ciphertext contradicts:
  // a wrong/forged credential must not be able to mint a MAC'd envelope.
  const evidence = await checkMasterEvidence(storage, master);
  if (evidence === "contradicted") {
    throw new CustodyMigrationRefusedError();
  }
  // "no-evidence" is acceptable here: unlike the legacy-marker paths, the
  // master was just proven by GCM-authenticating an actual wrap of this
  // envelope, so it is the fortress's real master regardless of how much
  // checkable ciphertext exists.

  // Re-wrap every wrap under the current id-bound AAD. The supplied credential
  // is the only secret we hold; a wrap of another factor type cannot be
  // re-wrapped without its secret, so fail closed rather than silently strip
  // or corrupt it (legacy-migrated envelopes carry exactly one wrap).
  const reWrapped: CustodyWrap[] = [];
  for (const wrap of envelope.wraps) {
    const next = await reWrapLegacyWrap(wrap, master, credential);
    if (!next) {
      throw new CustodyEnvelopeIntegrityError(
        "Sanctuary: cannot upgrade this pre-mac legacy custody envelope.\n" +
          "It enrolls a recovery factor whose secret was not supplied, so its\n" +
          "wrap cannot be re-bound under the current scheme. Unlock with the\n" +
          "original creating credential, or re-initialize the fortress with\n" +
          "`sanctuary init` after exporting any state you need to keep."
      );
    }
    reWrapped.push(next);
  }

  // Re-stamp: install_mode is taken from the on-disk value, SAFE only because
  // the sentinel-absent gate above proved no prior authenticated install_mode
  // could have been tampered. writeCustodyEnvelope computes the MAC + writes
  // the sentinel, so the next unlock passes the strict verifyEnvelopeMac path.
  return writeCustodyEnvelope(
    storage,
    {
      v: 1,
      install_mode: envelope.install_mode,
      wraps: reWrapped,
      created_at: envelope.created_at,
      ...(typeof envelope.epoch === "number"
        ? { epoch: envelope.epoch, epoch_id: envelope.epoch_id ?? "" }
        : {}),
    },
    master
  );
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

  // Master-rotation guard: while the rotation journal exists, fortress data
  // may be split between the old and new masters. NO establishment path may
  // proceed — not even with a valid credential — until the rotation is
  // resumed to completion. (The rotation engine itself unwraps the envelopes
  // directly and never goes through establishMaster.)
  if (await storage.read("_meta", ROTATION_JOURNAL_KEY)) {
    throw new CustodyRotationInProgressError();
  }

  const envelope = await readCustodyEnvelope(storage);
  if (envelope) {
    let masterKey: Uint8Array;
    let keyProtection: "passphrase" | "recovery-key";
    let credential: CustodyCredential;
    if (opts.passphrase !== undefined) {
      credential = { passphrase: opts.passphrase };
      masterKey = await unwrapMaster(envelope, credential);
      keyProtection = "passphrase";
    } else if (opts.recoveryKey !== undefined) {
      credential = { recoveryKey: decodeRecoveryKey(opts.recoveryKey) };
      masterKey = await unwrapMaster(envelope, credential);
      keyProtection = "recovery-key";
    } else if (opts.keychainKey !== undefined) {
      credential = { keychainKey: opts.keychainKey };
      masterKey = await unwrapMaster(envelope, credential);
      keyProtection = "passphrase";
    } else {
      throw new CustodyCredentialMissingError(opts.storagePathHint);
    }

    // PRE-MAC legacy envelope (#496 backward-compat): the credential unwrapped
    // the master, but the on-disk envelope predates the policy MAC and the
    // per-wrap ids, so there is no MAC to verify yet. Re-stamp it IN PLACE
    // now that the master is in hand, never reject, never silently trust an
    // unauthenticated install_mode.
    if (envelope.needsMacMigration) {
      let upgraded: CustodyEnvelope;
      try {
        upgraded = await migrateLegacyEnvelopeInPlace(
          storage,
          envelope,
          masterKey,
          credential
        );
      } catch (err) {
        // Scrub the transient plaintext master before propagating, matching
        // the legacy-marker establishment paths' zeroize-before-throw
        // discipline (the migration helper can throw on sentinel-present,
        // contradicted-master, or un-rewrappable-wrap).
        masterKey.fill(0);
        throw err;
      }
      return {
        masterKey,
        envelope: upgraded,
        origin: "envelope",
        keyProtection,
        migratedInPlace: true,
      };
    }

    // Authenticate the envelope's policy metadata under the unwrapped
    // master before anyone trusts install_mode / verified flags (H2).
    verifyEnvelopeMac(envelope, masterKey);
    return { masterKey, envelope, origin: "envelope", keyProtection };
  }

  // No envelope. If the custody sentinel exists, an envelope existed before
  // — refuse the legacy/first-run paths entirely (codex round-2: deleting
  // the envelope while legacy markers remain must not downgrade a migrated
  // fortress to fresh one-wrap custody).
  if (await storage.read("_meta", CUSTODY_SENTINEL_KEY)) {
    throw envelopeMissingButSentinelPresent();
  }

  // Inspect legacy markers.
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
    if (
      evidence === "no-evidence" &&
      (await fortressHasDataBeyondMarkers(storage))
    ) {
      // Data exists that the probe could not verify the master against
      // (H3). Do NOT capture this master into an envelope — proceed
      // legacy-style; migration retries once verifiable evidence exists.
      return {
        masterKey,
        envelope: null,
        origin: "legacy-deferred",
        keyProtection: "passphrase",
      };
    }

    const wrap = await wrapMasterWithPassphrase(masterKey, opts.passphrase, {
      verified: true,
    });
    const migrated = await writeCustodyEnvelope(
      storage,
      {
        v: 1,
        install_mode: "legacy-migrated",
        wraps: [wrap],
        created_at: now,
      },
      masterKey
    );
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
    if (
      evidence === "no-evidence" &&
      (await fortressHasDataBeyondMarkers(storage))
    ) {
      return {
        masterKey,
        envelope: null,
        origin: "legacy-deferred",
        keyProtection: "recovery-key",
      };
    }

    const wrap = wrapMasterWithRecoveryKey(masterKey, recoveryKeyBytes, {
      verified: true,
    });
    const migrated = await writeCustodyEnvelope(
      storage,
      {
        v: 1,
        install_mode: "legacy-migrated",
        wraps: [wrap],
        created_at: now,
      },
      masterKey
    );
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

  // H1 guard: never create fresh custody over existing data. A fortress
  // with state but no envelope and no legacy markers is damaged/orphaned —
  // generating a new master here would silently split state.
  if (await fortressHasDataBeyondMarkers(storage)) {
    throw new OrphanedFortressStateError();
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

  const fresh = await writeCustodyEnvelope(
    storage,
    {
      v: 1,
      install_mode: opts.firstRun.installMode,
      wraps,
      created_at: now,
    },
    masterKey
  );

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
 * Mark a recovery-key wrap as operator-verified (after re-entry). The
 * re-entered key is proven by unwrapping the master with it — an end-to-end
 * "the string the user saved unlocks everything" check, not a string
 * compare. Only the EXACT wrap the re-entered key decrypted is marked
 * (codex M1: never bulk-promote other recovery wraps).
 */
export async function verifyRecoveryWrapByReentry(
  storage: StorageBackend,
  envelope: CustodyEnvelope,
  reenteredKey: string,
  opts?: { envelopeKey?: string; sentinelKey?: string }
): Promise<CustodyEnvelope> {
  const match = await unwrapMatchingWrap(
    envelope.wraps,
    { recoveryKey: decodeRecoveryKey(reenteredKey) },
    "recovery-key"
  );
  if (!match) throw new CustodyUnlockError();
  try {
    const updated = await writeCustodyEnvelope(
      storage,
      {
        ...envelope,
        wraps: envelope.wraps.map((w) =>
          w.id === match.wrapId ? { ...w, verified: true } : w
        ),
      },
      match.master,
      opts
    );
    return updated;
  } finally {
    match.master.fill(0);
  }
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
  const updated = await writeCustodyEnvelope(
    storage,
    {
      ...envelope,
      wraps: [...envelope.wraps, wrap],
    },
    masterKey
  );
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
