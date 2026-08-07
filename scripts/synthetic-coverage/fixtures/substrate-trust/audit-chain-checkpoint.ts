import { bytesToString, toBase64url } from "../../../../server/src/core/encoding.js";
import { createIdentity, sign as identitySign } from "../../../../server/src/core/identity.js";
import { derivePurposeKey } from "../../../../server/src/core/key-derivation.js";
import { generateRandomKey } from "../../../../server/src/core/random.js";
import {
  checkpointSigningBytes,
  computeAuditRoot,
  verifyCheckpointSignature,
  type AuditCheckpointRecord,
  type AuditCheckpointSigningPayload,
} from "../../../../server/src/audit/chain.js";
import {
  AuditLog,
  type PersistedAuditEnvelopeV2,
} from "../../../../server/src/operational/audit-log.js";
import { MemoryStorage } from "../../../../server/src/storage/memory.js";
import { verifyAuditChainRecords } from "../../../../server/src/cli/audit-chain-verify.js";
import { registerFixture } from "../../registry.js";
import {
  failedSince,
  ROW_AUDIT_CHAIN,
  ROW_AUDIT_CHAIN_LABEL,
} from "./helpers.js";

// Entrypoints: AuditLog checkpoint writing, audit/chain checkpoint signing
// helpers, and cli/audit-chain-verify standalone verification.
// Existing mirrors: server/test/operational/audit-log-chain.test.ts and
// server/test/audit/external-verifier-drill.test.ts.
// ASSURANCE_MATRIX row: 4, Tamper-evident audit chain.
//
// HONEST BOUND, do not read these fixtures as evidence of a shipped path.
// The signed-checkpoint fixtures below construct AuditLog with an explicit
// `checkpointSigner` (see makeCheckpointSigner and its two call sites). No
// production `new AuditLog(...)` site in server/src supplies that dependency,
// so every checkpoint on a real install persists `signature: null,
// unsigned: true` and both verifiers skip the signature leg. What these
// fixtures exercise is the checkpoint FORMAT and the verifier's behavior when a
// signer IS present; they do not exercise any code path an operator runs.
// Open defect: IC-05 (Review/Sanctuary/Inert_Capability_Sweep_2026-08-07.md).
// Deleting the injected signer here would not fix that; the fix is to supply a
// signer at the production construction sites.

async function appendCritical(log: AuditLog, operation: string): Promise<void> {
  await log.appendCritical({
    layer: "l1",
    operation,
    identity_id: "synthetic-id",
    result: "success",
    details: { operation },
  });
}

async function auditKeys(storage: MemoryStorage): Promise<string[]> {
  return (await storage.list("_audit")).map((entry) => entry.key).sort();
}

async function readEnvelope(
  storage: MemoryStorage,
  key: string,
): Promise<PersistedAuditEnvelopeV2> {
  const raw = await storage.read("_audit", key);
  if (!raw) {
    throw new Error(`missing audit entry: ${key}`);
  }
  return JSON.parse(bytesToString(raw)) as PersistedAuditEnvelopeV2;
}

function makeCheckpointSigner(masterKey: Uint8Array) {
  const identityKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity(
    "synthetic-checkpoint-signer",
    identityKey,
    "recovery-key",
  );
  return {
    storedIdentity,
    signer: async (payload: AuditCheckpointSigningPayload) => ({
      signer_kid: storedIdentity.identity_id,
      signature: toBase64url(
        identitySign(
          checkpointSigningBytes(payload),
          storedIdentity.encrypted_private_key,
          identityKey,
        ),
      ),
      public_key: storedIdentity.public_key,
    }),
  };
}

async function readFirstCheckpoint(storage: MemoryStorage): Promise<AuditCheckpointRecord> {
  const checkpointKey = (await storage.list("_audit_checkpoints", "audit-checkpoint-"))[0]?.key;
  if (!checkpointKey) {
    throw new Error("missing audit checkpoint");
  }
  const raw = await storage.read("_audit_checkpoints", checkpointKey);
  return JSON.parse(bytesToString(raw!)) as AuditCheckpointRecord;
}

registerFixture(
  ROW_AUDIT_CHAIN,
  ROW_AUDIT_CHAIN_LABEL,
  "appendCritical produces a verifiable signed checkpoint",
  async () => {
    const start = performance.now();
    try {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const { storedIdentity, signer } = makeCheckpointSigner(masterKey);
      const writer = new AuditLog(storage, masterKey, {
        checkpointInterval: 1,
        checkpointSigner: signer,
        checkpointPublicKeyResolver: () => storedIdentity.public_key,
      });
      await appendCritical(writer, "synthetic_signed_checkpoint");
      const checkpoint = await readFirstCheckpoint(storage);
      const payload: AuditCheckpointSigningPayload = {
        checkpoint_kind: checkpoint.checkpoint_kind,
        checkpoint_sequence: checkpoint.checkpoint_sequence,
        from_sequence: checkpoint.from_sequence,
        root_hash: checkpoint.root_hash,
        previous_checkpoint_sequence: checkpoint.previous_checkpoint_sequence,
        signed_at: checkpoint.signed_at,
      };
      const valid = verifyCheckpointSignature(
        payload,
        checkpoint.signature!,
        storedIdentity.public_key,
      );

      return {
        passed: checkpoint.unsigned === false && valid === true,
        message: `checkpoint_sequence=${checkpoint.checkpoint_sequence}`,
        durationMs: performance.now() - start,
      };
    } catch (error) {
      return failedSince(start, error);
    }
  },
);

registerFixture(
  ROW_AUDIT_CHAIN,
  ROW_AUDIT_CHAIN_LABEL,
  "standalone verifier rejects mid-chain entry mutation",
  async () => {
    const start = performance.now();
    try {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const { signer } = makeCheckpointSigner(masterKey);
      const writer = new AuditLog(storage, masterKey, {
        checkpointInterval: 5,
        checkpointSigner: signer,
      });
      await appendCritical(writer, "synthetic_one");
      await appendCritical(writer, "synthetic_two");
      await appendCritical(writer, "synthetic_three");
      await writer.flush();

      const keys = await auditKeys(storage);
      const records = [];
      for (const key of keys) {
        const envelope = await readEnvelope(storage, key);
        records.push({
          type: "entry" as const,
          seq: envelope.sequence,
          schema_version: envelope.schema_version,
          prev_hash: envelope.prev_hash,
          entry_hash: envelope.entry_hash,
          timestamp: envelope.timestamp,
          encrypted_payload_bytes: envelope.encrypted_payload_bytes,
        });
      }
      records[1]!.entry_hash = "0".repeat(64);
      const report = verifyAuditChainRecords(records, { strict: true });

      return {
        passed: report.verdict === "FAIL" &&
          report.findings.some((finding) => finding.kind === "entry_hash_mismatch"),
        message: `findings=${report.findings.map((finding) => finding.kind).join(",")}`,
        durationMs: performance.now() - start,
      };
    } catch (error) {
      return failedSince(start, error);
    }
  },
);

registerFixture(
  ROW_AUDIT_CHAIN,
  ROW_AUDIT_CHAIN_LABEL,
  "empty-chain checkpoint signs the genesis state",
  async () => {
    const start = performance.now();
    try {
      const masterKey = generateRandomKey();
      const { storedIdentity, signer } = makeCheckpointSigner(masterKey);
      const payload: AuditCheckpointSigningPayload = {
        checkpoint_kind: "audit-checkpoint",
        checkpoint_sequence: 0,
        from_sequence: 0,
        root_hash: computeAuditRoot([]),
        previous_checkpoint_sequence: 0,
        signed_at: "2026-05-19T00:00:00.000Z",
      };
      const signed = await signer(payload);
      const valid = verifyCheckpointSignature(
        payload,
        signed.signature,
        storedIdentity.public_key,
      );

      return {
        passed: valid === true,
        message: `root_hash=${payload.root_hash}`,
        durationMs: performance.now() - start,
      };
    } catch (error) {
      return failedSince(start, error);
    }
  },
);
