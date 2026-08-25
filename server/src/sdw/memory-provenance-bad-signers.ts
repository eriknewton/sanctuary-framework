import { createHash } from "node:crypto";

import { decrypt, encrypt, type EncryptedPayload } from "../core/encryption.js";
import { stringToBytes } from "../core/encoding.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import type { AuditLog } from "../operational/audit-log.js";
import type { StorageBackend } from "../storage/interface.js";
import { withExitAdmissionLock } from "../storage/exit-import-journal.js";
import type { MemoryProvenanceCompanion } from "./memory-provenance-contract.js";

export const MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE = "_sdw_memory_bad_signers";
export const MEMORY_PROVENANCE_BAD_SIGNER_MARK_AUDIT =
  "MEMORY_PROVENANCE_BAD_SIGNER_MARK";
export const MEMORY_PROVENANCE_BAD_SIGNER_CLEAR_AUDIT =
  "MEMORY_PROVENANCE_BAD_SIGNER_CLEAR";
export const MAX_MEMORY_PROVENANCE_BAD_SIGNER_MARKS = 2_000;
export const MAX_MEMORY_PROVENANCE_BAD_SIGNER_REASON_BYTES = 256;

const KEY_PURPOSE = "sdw-memory-bad-signers-v1";
const AAD_DOMAIN = "sanctuary.sdw.memory-bad-signer.v1";
const DID = /^did:[A-Za-z0-9:._-]{1,252}$/;
const FINGERPRINT = /^[a-f0-9]{64}$/;
const APPROVAL = /^[A-Za-z0-9:._-]{1,256}$/;

export interface MemoryProvenanceBadSignerMark {
  readonly version: 1;
  readonly signer_did: string;
  readonly public_key_sha256: string;
  readonly reason: string;
  readonly approval_audit_id: string;
  readonly marked_at: string;
}

export interface MemoryProvenanceBadSignerAuthority {
  isMarked(signerDid: string, rawPublicKey: Uint8Array): Promise<boolean>;
}

export interface MemoryProvenanceForeignDependencyScan {
  readonly complete: boolean;
  readonly scanned: number;
  readonly affected: number;
}

export interface MemoryProvenanceBadSignerStoreOptions {
  readonly storage: StorageBackend;
  readonly masterKey: Uint8Array;
  readonly fortressId: string;
  readonly resolveSignerPublicKey: (did: string) => Uint8Array | undefined;
  readonly isLocallyRootedSigner: (did: string, publicKey: Uint8Array) => boolean;
  readonly scanForeignDependencies: (
    did: string,
    publicKeySha256: string,
  ) => Promise<MemoryProvenanceForeignDependencyScan>;
  readonly now?: () => string;
  readonly maxMarks?: number;
}

export function memoryProvenancePublicKeyFingerprint(rawPublicKey: Uint8Array): string {
  if (rawPublicKey.byteLength !== 32) throw new Error("memory provenance signer key must be 32 bytes");
  return createHash("sha256").update(rawPublicKey).digest("hex");
}

export class MemoryProvenanceBadSignerStore implements MemoryProvenanceBadSignerAuthority {
  private readonly key: Uint8Array;
  private readonly now: () => string;
  private readonly maxMarks: number;

  constructor(private readonly options: MemoryProvenanceBadSignerStoreOptions) {
    this.key = derivePurposeKey(options.masterKey, KEY_PURPOSE);
    this.now = options.now ?? (() => new Date().toISOString());
    this.maxMarks = options.maxMarks ?? MAX_MEMORY_PROVENANCE_BAD_SIGNER_MARKS;
    if (!Number.isSafeInteger(this.maxMarks) || this.maxMarks < 1 ||
        this.maxMarks > MAX_MEMORY_PROVENANCE_BAD_SIGNER_MARKS) {
      throw new Error("invalid memory provenance bad-signer mark cap");
    }
  }

  async isMarked(signerDid: string, rawPublicKey: Uint8Array): Promise<boolean> {
    validateDid(signerDid);
    const fingerprint = memoryProvenancePublicKeyFingerprint(rawPublicKey);
    const mark = await this.read(signerDid, fingerprint);
    return mark !== null && mark.signer_did === signerDid &&
      mark.public_key_sha256 === fingerprint;
  }

  async mark(input: {
    readonly signerDid: string;
    readonly publicKeySha256: string;
    readonly reason: string;
    readonly approvalAuditId: string;
  }, auditLog: AuditLog): Promise<MemoryProvenanceBadSignerMark> {
    validateInput(input);
    return withExitAdmissionLock(this.options.storage, "memory_bad_signer", async () => {
      const resolved = this.options.resolveSignerPublicKey(input.signerDid);
      if (resolved === undefined) throw new Error("foreign signer mapping is unknown");
      const recomputed = memoryProvenancePublicKeyFingerprint(resolved);
      if (recomputed !== input.publicKeySha256) {
        throw new Error("foreign signer fingerprint does not match the resolved raw key");
      }
      if (this.options.isLocallyRootedSigner(input.signerDid, resolved)) {
        throw new Error("local signer compromise is outside foreign bad-signer marking");
      }
      const scan = await this.options.scanForeignDependencies(input.signerDid, recomputed);
      if (!scan.complete || scan.affected < 1) {
        throw new Error("foreign signer dependency scan was incomplete or found no foreign dependency");
      }
      const existing = await this.read(input.signerDid, recomputed);
      if (existing !== null) return existing;
      const rows = await this.options.storage.list(MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE);
      if (rows.length >= this.maxMarks) throw new Error("memory provenance bad-signer mark cap exceeded");
      const record: MemoryProvenanceBadSignerMark = {
        version: 1,
        signer_did: input.signerDid,
        public_key_sha256: recomputed,
        reason: input.reason,
        approval_audit_id: input.approvalAuditId,
        marked_at: this.now(),
      };
      await auditLog.appendCritical({
        layer: "l1",
        operation: MEMORY_PROVENANCE_BAD_SIGNER_MARK_AUDIT,
        identity_id: "principal",
        result: "success",
        details: {
          signer_did: record.signer_did,
          public_key_sha256: record.public_key_sha256,
          reason: record.reason,
          approval_audit_id: record.approval_audit_id,
          marked_at: record.marked_at,
          affected: scan.affected,
        },
      });
      try {
        await this.write(record);
      } catch (error) {
        // A failed or unverifiable state publication must not change live
        // eligibility. This is a new mark, so its exact pre-image is absence.
        await this.options.storage.delete(
          MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE,
          storageKey(record.signer_did, record.public_key_sha256),
          true,
        ).catch(() => false);
        if (await this.read(record.signer_did, record.public_key_sha256).catch(() => null) !== null) {
          throw new Error("partial_scope: bad-signer mark rollback could not restore absence", { cause: error });
        }
        throw error;
      }
      return record;
    });
  }

  async clear(input: {
    readonly signerDid: string;
    readonly publicKeySha256: string;
    readonly approvalAuditId: string;
  }, auditLog: AuditLog): Promise<MemoryProvenanceForeignDependencyScan> {
    validateDid(input.signerDid);
    validateFingerprint(input.publicKeySha256);
    validateApproval(input.approvalAuditId);
    return withExitAdmissionLock(this.options.storage, "memory_bad_signer", async () => {
      const resolved = this.options.resolveSignerPublicKey(input.signerDid);
      if (resolved !== undefined &&
          memoryProvenancePublicKeyFingerprint(resolved) !== input.publicKeySha256) {
        throw new Error("foreign signer mapping conflicts with the exact marked fingerprint");
      }
      const existing = await this.read(input.signerDid, input.publicKeySha256);
      if (existing === null) throw new Error("foreign signer is not marked");
      const key = storageKey(input.signerDid, input.publicKeySha256);
      const preState = await this.options.storage.read(MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE, key);
      if (preState === null) throw new Error("foreign signer mark disappeared under the admission lock");
      await auditLog.appendCritical({
        layer: "l1",
        operation: MEMORY_PROVENANCE_BAD_SIGNER_CLEAR_AUDIT,
        identity_id: "principal",
        result: "success",
        details: {
          signer_did: input.signerDid,
          public_key_sha256: input.publicKeySha256,
          approval_audit_id: input.approvalAuditId,
        },
      });
      // The mark remains visible while the complete bounded scan re-verifies
      // every dependency. Only the final single-key delete restores eligibility.
      const scan = await this.options.scanForeignDependencies(
        input.signerDid,
        input.publicKeySha256,
      );
      if (!scan.complete) {
        throw new Error("foreign signer clear refused: dependency scan incomplete");
      }
      try {
        if (!await this.options.storage.delete(
          MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE,
          key,
          true,
        )) throw new Error("foreign signer clear failed before state removal");
        if (await this.options.storage.read(MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE, key) !== null) {
          throw new Error("foreign signer clear state removal was not durable");
        }
      } catch (error) {
        const current = await this.options.storage.read(MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE, key)
          .catch(() => null);
        if (current === null) {
          await this.options.storage.write(
            MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE,
            key,
            preState,
          ).catch(() => undefined);
        }
        const restored = await this.options.storage.read(MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE, key)
          .catch(() => null);
        if (restored === null || !Buffer.from(restored).equals(Buffer.from(preState))) {
          throw new Error("partial_scope: bad-signer clear rollback could not restore exact pre-state", {
            cause: error,
          });
        }
        throw error;
      }
      return scan;
    });
  }

  private async read(did: string, fingerprint: string): Promise<MemoryProvenanceBadSignerMark | null> {
    const key = storageKey(did, fingerprint);
    const raw = await this.options.storage.read(MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE, key);
    if (raw === null) return null;
    const aad = aadBytes(this.options.fortressId, key);
    const plaintext = decrypt(JSON.parse(new TextDecoder().decode(raw)) as EncryptedPayload, this.key, aad);
    try {
      const value = JSON.parse(new TextDecoder().decode(plaintext)) as MemoryProvenanceBadSignerMark;
      validateRecord(value, did, fingerprint);
      return value;
    } finally {
      plaintext.fill(0);
    }
  }

  private async write(record: MemoryProvenanceBadSignerMark): Promise<void> {
    const key = storageKey(record.signer_did, record.public_key_sha256);
    const plaintext = stringToBytes(JSON.stringify(record));
    try {
      const envelope = encrypt(plaintext, this.key, aadBytes(this.options.fortressId, key));
      await this.options.storage.write(
        MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE,
        key,
        stringToBytes(JSON.stringify(envelope)),
      );
      const reread = await this.read(record.signer_did, record.public_key_sha256);
      if (reread === null || reread.approval_audit_id !== record.approval_audit_id) {
        throw new Error("memory provenance bad-signer state verification failed");
      }
    } finally {
      plaintext.fill(0);
    }
  }
}

export async function evaluateMemoryProvenanceSignerEligibility(input: {
  readonly companion: MemoryProvenanceCompanion;
  readonly resolveSignerPublicKey: (identityId: string, did: string) => Uint8Array | undefined;
  readonly badSignerAuthority?: MemoryProvenanceBadSignerAuthority;
  /** Exit admission makes every carried origin foreign to the destination. */
  readonly foreignAdmission?: boolean;
}): Promise<{ readonly eligible: true } | { readonly eligible: false; readonly reason: string }> {
  const tier = input.companion.admission.body.origin_trust_tier;
  if (!input.foreignAdmission && tier !== "foreign_direct" && tier !== "foreign_relayed") {
    return { eligible: true };
  }
  const origin = input.companion.origin.body;
  const key = input.resolveSignerPublicKey(origin.signer_identity_id, origin.signer_did);
  if (key === undefined) return { eligible: false, reason: "foreign_signer_unresolved" };
  if (input.badSignerAuthority !== undefined &&
      await input.badSignerAuthority.isMarked(origin.signer_did, key)) {
    return { eligible: false, reason: "foreign_bad_signer" };
  }
  return { eligible: true };
}

function storageKey(did: string, fingerprint: string): string {
  return createHash("sha256").update(`${did}\n${fingerprint}`, "utf8").digest("hex");
}

function aadBytes(fortressId: string, key: string): Uint8Array {
  return stringToBytes(`${AAD_DOMAIN}\n${fortressId}\n${key}`);
}

function validateInput(input: { signerDid: string; publicKeySha256: string; reason: string; approvalAuditId: string }): void {
  validateDid(input.signerDid);
  validateFingerprint(input.publicKeySha256);
  validateApproval(input.approvalAuditId);
  const reasonBytes = Buffer.byteLength(input.reason, "utf8");
  if (reasonBytes < 1 || reasonBytes > MAX_MEMORY_PROVENANCE_BAD_SIGNER_REASON_BYTES ||
      [...input.reason].some((character) => {
        const code = character.codePointAt(0)!;
        return code <= 31 || code === 127;
      })) throw new Error("invalid bad-signer reason");
}

function validateDid(value: string): void {
  if (!DID.test(value)) throw new Error("invalid foreign signer DID");
}

function validateFingerprint(value: string): void {
  if (!FINGERPRINT.test(value)) throw new Error("invalid foreign signer fingerprint");
}

function validateApproval(value: string): void {
  if (!APPROVAL.test(value)) throw new Error("invalid approval audit id");
}

function validateRecord(value: MemoryProvenanceBadSignerMark, did: string, fingerprint: string): void {
  validateInput({
    signerDid: value.signer_did,
    publicKeySha256: value.public_key_sha256,
    reason: value.reason,
    approvalAuditId: value.approval_audit_id,
  });
  if (value.version !== 1 || value.signer_did !== did ||
      value.public_key_sha256 !== fingerprint ||
      !Number.isFinite(Date.parse(value.marked_at)) ||
      new Date(value.marked_at).toISOString() !== value.marked_at) {
    throw new Error("invalid authenticated bad-signer state");
  }
}
