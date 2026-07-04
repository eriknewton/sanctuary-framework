/**
 * Durable persistence codec for the OPTIONAL M-of-N guardian revocation
 * requirement (competitor-readiness item 6: "no single person can kill the
 * fleet").
 *
 * COMPOSITION ONLY. This module adds NO cryptography and NO new at-rest HKDF
 * label. It is the encode/decode/verify seam that lets the existing durable
 * federation security-state record ({@link FederationSyncStateStore}) carry the
 * operator's guardian-revocation requirement so the requirement SURVIVES A
 * RESTART. Before this seam the requirement lived in memory only
 * (`_federationGuardianRevocationRequirement`), so a daemon restart silently
 * reverted the fleet to single-operator kill: the "no single person can kill the
 * fleet" guarantee evaporated on every reboot. That is the standing weakness this
 * closes.
 *
 * WHY REUSE THE SYNC-STATE RECORD (no new HKDF label): the requirement is small,
 * derived, per-fortress config that must survive rotate-master exactly like the
 * revoked-node / revoked-root projections already persisted in that record. It
 * rides in the SAME AES-256-GCM blob under the SAME purpose key, so it inherits:
 *   - the AEAD tag (an at-rest tamper of the persisted roster fails decryption),
 *   - the fail-closed load contract (a corrupt record THROWS; the caller denies),
 *   - the rotate-master recipe coverage (no new label to register), and
 *   - the cross-process monotonic merge.
 *
 * FAIL-CLOSED VERIFICATION ON LOAD: the persisted requirement carries the
 * fortress-master-SIGNED guardian roster. On rehydrate the caller re-verifies
 * that roster signature against the CURRENT pinned fortress-master via
 * {@link verifyGuardianRoster}. If it does NOT verify (at-rest tamper that
 * survived AEAD only via a same-key re-encrypt, a roster for a different
 * fortress, or a stale roster after a legitimate master rotation), the caller
 * MUST NOT silently drop to single-operator kill. {@link
 * loadGuardianRevocationRequirement} returns a discriminated result so the caller
 * can distinguish "no requirement configured" (legacy single-operator, allowed)
 * from "a requirement is configured but its roster failed verification"
 * (fail-closed: the revoke path must refuse every revocation until an operator
 * re-pins a valid roster). Collapsing those two into "no requirement" would be a
 * silent security downgrade (AGENTS.md constraint 5).
 */

import type { SignatureScheme } from "../mesh/constants.js";
import { verifyGuardianRoster } from "../mesh/guardian/guardian-roster.js";
import type {
  GuardianIdentity,
  GuardianRoster,
} from "../mesh/guardian/types.js";
import type { FortressMasterPublicKey } from "../mesh/types.js";
import {
  LOWERED_THRESHOLD_AUTHORIZATION_DOMAIN,
  type GuardianRevocationRequirement,
  type LoweredThresholdAuthorization,
} from "./federation-revocation-guardian-gate.js";

/**
 * The at-rest JSON shape of a persisted guardian revocation requirement. Carries
 * the whole fortress-master-signed roster verbatim (so its master signature can
 * be re-verified on load) plus the optional pinned expected roster version.
 *
 * ADDITIVE + OPTIONAL on read: a record written before this field existed decodes
 * to "no requirement configured" (the legacy single-operator revoke path). The
 * AEAD tag of the enclosing sync-state record authenticates this sub-object; a
 * tampered blob still fails closed at the enclosing decrypt.
 */
export interface PersistedGuardianRevocationRequirement {
  /** Format version for forward-compat within the enclosing v1 record. */
  v: 1;
  /** The fortress-master-signed guardian roster (verbatim, re-verified on load). */
  roster: PersistedGuardianRoster;
  /** Optional pinned expected roster version (extra stale-roster guard). */
  expected_roster_version?: number;
  /**
   * OPTIONAL master-signed lowered effective-M record (F1 chokepoint slice).
   * ADDITIVE + optional on read: a pre-lower `v:1` record omits it and decodes
   * with `loweredThreshold` absent -> effective M = `roster.m`. NO new HKDF
   * label, NO `v` bump, NO migration - it rides inside this same requirement
   * sub-object under the same generation selector so the roster and its
   * lowered-M can never decouple across a rotate-root merge. The roster's own
   * signed body is NEVER mutated to represent the lowering (INV-B). PRESENT-
   * but-malformed THROWS (same fail-closed-on-corrupt contract as the roster).
   */
  lowered_threshold?: LoweredThresholdAuthorization;
}

interface PersistedGuardianRoster {
  m: number;
  n: number;
  guardians: GuardianIdentity[];
  signature_scheme: SignatureScheme;
  version: number;
  created_at: string;
  fortress_id: string;
  master_signature: string;
}

/**
 * Result of loading + verifying a persisted guardian revocation requirement.
 *
 *   - `kind: "none"`     -> no requirement was persisted (fresh fortress or an
 *                           operator who never opted in). The revoke path runs the
 *                           legacy single-operator path. NOT a security downgrade.
 *   - `kind: "verified"` -> a requirement was persisted AND its roster signature
 *                           verifies against the current pinned master. Enforce.
 *   - `kind: "invalid"`  -> a requirement was persisted but its roster did NOT
 *                           verify (tamper / wrong fortress / stale after master
 *                           rotation). FAIL CLOSED: the caller must refuse every
 *                           revocation, NOT silently drop to single-operator.
 */
export type LoadedGuardianRevocationRequirement =
  | { kind: "none" }
  | { kind: "verified"; requirement: GuardianRevocationRequirement }
  | { kind: "invalid"; reason: string };

/** Serialize a live requirement for at-rest persistence. */
export function encodeGuardianRevocationRequirement(
  requirement: GuardianRevocationRequirement,
): PersistedGuardianRevocationRequirement {
  const roster = requirement.roster;
  const persisted: PersistedGuardianRevocationRequirement = {
    v: 1,
    roster: {
      m: roster.m,
      n: roster.n,
      guardians: roster.guardians.map((g) => ({ ...g })),
      signature_scheme: roster.signature_scheme,
      version: roster.version,
      created_at: roster.created_at,
      fortress_id: roster.fortress_id,
      master_signature: roster.master_signature,
    },
  };
  if (requirement.expectedRosterVersion !== undefined) {
    persisted.expected_roster_version = requirement.expectedRosterVersion;
  }
  if (requirement.loweredThreshold !== undefined) {
    // The lowered-threshold record is carried VERBATIM (its own master signature
    // rides along) so it can be re-verified against the pinned master on load,
    // exactly like the roster's `master_signature`.
    persisted.lowered_threshold = {
      body: { ...requirement.loweredThreshold.body },
      signature: requirement.loweredThreshold.signature,
    };
  }
  return persisted;
}

/**
 * Structurally decode a persisted requirement. Returns `undefined` when the field
 * is absent (legitimate back-compat: no requirement configured) and throws only
 * when the field is PRESENT but structurally malformed (never accept a
 * half-decoded requirement, mirroring the enclosing record's fail-closed decode).
 *
 * This is STRUCTURE only; it does NOT verify the master signature. Signature
 * re-verification against the pinned master happens in {@link
 * verifyLoadedGuardianRevocationRequirement} because the pinned master is not
 * available at pure-decode time.
 */
export function decodeGuardianRevocationRequirement(
  value: unknown,
): PersistedGuardianRevocationRequirement | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new GuardianRevocationPolicyDecodeError("requirement is not an object");
  }
  const obj = value as Record<string, unknown>;
  if (obj.v !== 1) {
    throw new GuardianRevocationPolicyDecodeError(
      `unsupported requirement version: ${String(obj.v)}`,
    );
  }
  const roster = decodeRoster(obj.roster);
  const expectedRosterVersion = obj.expected_roster_version;
  if (expectedRosterVersion !== undefined) {
    if (
      typeof expectedRosterVersion !== "number" ||
      !Number.isSafeInteger(expectedRosterVersion) ||
      expectedRosterVersion < 1
    ) {
      throw new GuardianRevocationPolicyDecodeError(
        "expected_roster_version is invalid",
      );
    }
  }
  // Optional on read (a pre-lower v1 record omits it -> undefined -> effective M
  // = roster.m). PRESENT-but-malformed THROWS (never accept a half-decoded
  // lowered record). Signature re-verification against the pinned master is done
  // by the consumer on rehydrate, mirroring the roster's own re-verification.
  const loweredThreshold = decodeLoweredThreshold(obj.lowered_threshold);
  return {
    v: 1,
    roster,
    ...(expectedRosterVersion !== undefined
      ? { expected_roster_version: expectedRosterVersion }
      : {}),
    ...(loweredThreshold !== undefined
      ? { lowered_threshold: loweredThreshold }
      : {}),
  };
}

/**
 * Structurally decode the optional lowered-threshold record. Returns
 * `undefined` when absent (legitimate back-compat) and throws when present-but-
 * malformed. Does NOT verify the master signature (the pinned master is not
 * available at pure-decode time); the consumer re-verifies on rehydrate.
 */
function decodeLoweredThreshold(
  value: unknown,
): LoweredThresholdAuthorization | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new GuardianRevocationPolicyDecodeError(
      "lowered_threshold is not an object",
    );
  }
  const obj = value as Record<string, unknown>;
  const body = obj.body;
  const signature = obj.signature;
  if (typeof signature !== "string" || signature.length === 0) {
    throw new GuardianRevocationPolicyDecodeError(
      "lowered_threshold signature is invalid",
    );
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new GuardianRevocationPolicyDecodeError(
      "lowered_threshold body is not an object",
    );
  }
  const b = body as Record<string, unknown>;
  if (b.domain !== LOWERED_THRESHOLD_AUTHORIZATION_DOMAIN) {
    throw new GuardianRevocationPolicyDecodeError(
      "lowered_threshold body domain is invalid",
    );
  }
  if (typeof b.fortress_id !== "string" || b.fortress_id.length === 0) {
    throw new GuardianRevocationPolicyDecodeError(
      "lowered_threshold body fortress_id is invalid",
    );
  }
  if (
    typeof b.roster_version !== "number" ||
    !Number.isSafeInteger(b.roster_version) ||
    b.roster_version < 1
  ) {
    throw new GuardianRevocationPolicyDecodeError(
      "lowered_threshold body roster_version is invalid",
    );
  }
  if (
    typeof b.effective_m !== "number" ||
    !Number.isSafeInteger(b.effective_m) ||
    b.effective_m < 1
  ) {
    throw new GuardianRevocationPolicyDecodeError(
      "lowered_threshold body effective_m is invalid",
    );
  }
  if (
    typeof b.disable_nonce !== "number" ||
    !Number.isSafeInteger(b.disable_nonce) ||
    b.disable_nonce < 0
  ) {
    throw new GuardianRevocationPolicyDecodeError(
      "lowered_threshold body disable_nonce is invalid",
    );
  }
  return {
    body: {
      domain: LOWERED_THRESHOLD_AUTHORIZATION_DOMAIN,
      fortress_id: b.fortress_id,
      roster_version: b.roster_version,
      effective_m: b.effective_m,
      disable_nonce: b.disable_nonce,
    },
    signature,
  };
}

/**
 * Verify a decoded persisted requirement against the pinned fortress-master and
 * project it into the live {@link GuardianRevocationRequirement} the gate
 * consumes. FAIL-CLOSED: a roster that does not verify yields `kind: "invalid"`,
 * never a silent `kind: "none"`.
 */
export function verifyLoadedGuardianRevocationRequirement(
  persisted: PersistedGuardianRevocationRequirement | undefined,
  pinnedMaster: FortressMasterPublicKey,
): LoadedGuardianRevocationRequirement {
  if (persisted === undefined) return { kind: "none" };
  const roster: GuardianRoster = { ...persisted.roster };
  try {
    verifyGuardianRoster(roster, pinnedMaster);
  } catch (err) {
    return {
      kind: "invalid",
      reason:
        err instanceof Error ? err.message : "guardian roster failed to verify",
    };
  }
  const requirement: GuardianRevocationRequirement = { roster };
  if (persisted.expected_roster_version !== undefined) {
    requirement.expectedRosterVersion = persisted.expected_roster_version;
  }
  if (persisted.lowered_threshold !== undefined) {
    requirement.loweredThreshold = {
      body: { ...persisted.lowered_threshold.body },
      signature: persisted.lowered_threshold.signature,
    };
  }
  return { kind: "verified", requirement };
}

function decodeRoster(value: unknown): PersistedGuardianRoster {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new GuardianRevocationPolicyDecodeError("roster is not an object");
  }
  const obj = value as Record<string, unknown>;
  const m = obj.m;
  const n = obj.n;
  const guardians = obj.guardians;
  const signatureScheme = obj.signature_scheme;
  const version = obj.version;
  const createdAt = obj.created_at;
  const fortressId = obj.fortress_id;
  const masterSignature = obj.master_signature;
  if (typeof m !== "number" || !Number.isSafeInteger(m) || m < 1) {
    throw new GuardianRevocationPolicyDecodeError("roster m is invalid");
  }
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < 1) {
    throw new GuardianRevocationPolicyDecodeError("roster n is invalid");
  }
  if (!Array.isArray(guardians)) {
    throw new GuardianRevocationPolicyDecodeError("roster guardians is not an array");
  }
  const decodedGuardians = guardians.map((g) => decodeGuardian(g));
  if (typeof signatureScheme !== "string" || signatureScheme.length === 0) {
    throw new GuardianRevocationPolicyDecodeError("roster signature_scheme is invalid");
  }
  if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 1) {
    throw new GuardianRevocationPolicyDecodeError("roster version is invalid");
  }
  if (typeof createdAt !== "string" || createdAt.length === 0) {
    throw new GuardianRevocationPolicyDecodeError("roster created_at is invalid");
  }
  if (typeof fortressId !== "string" || fortressId.length === 0) {
    throw new GuardianRevocationPolicyDecodeError("roster fortress_id is invalid");
  }
  if (typeof masterSignature !== "string" || masterSignature.length === 0) {
    throw new GuardianRevocationPolicyDecodeError("roster master_signature is invalid");
  }
  return {
    m,
    n,
    guardians: decodedGuardians,
    signature_scheme: signatureScheme as SignatureScheme,
    version,
    created_at: createdAt,
    fortress_id: fortressId,
    master_signature: masterSignature,
  };
}

function decodeGuardian(value: unknown): GuardianIdentity {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new GuardianRevocationPolicyDecodeError("guardian is not an object");
  }
  const obj = value as Record<string, unknown>;
  const guardianId = obj.guardian_id;
  const publicKey = obj.public_key;
  const kind = obj.kind;
  const invitedAt = obj.invited_at;
  if (typeof guardianId !== "string" || guardianId.length === 0) {
    throw new GuardianRevocationPolicyDecodeError("guardian_id is invalid");
  }
  if (typeof publicKey !== "string" || publicKey.length === 0) {
    throw new GuardianRevocationPolicyDecodeError("guardian public_key is invalid");
  }
  if (typeof kind !== "string" || kind.length === 0) {
    throw new GuardianRevocationPolicyDecodeError("guardian kind is invalid");
  }
  if (typeof invitedAt !== "string" || invitedAt.length === 0) {
    throw new GuardianRevocationPolicyDecodeError("guardian invited_at is invalid");
  }
  return {
    guardian_id: guardianId,
    public_key: publicKey,
    kind,
    invited_at: invitedAt,
  };
}

export class GuardianRevocationPolicyDecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GuardianRevocationPolicyDecodeError";
  }
}
