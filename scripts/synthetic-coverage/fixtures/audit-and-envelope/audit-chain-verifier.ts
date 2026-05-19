import { registerFixture, type FixtureOutcome } from "../../registry.js";
import {
  AUDIT_CHAIN_GENESIS,
  AUDIT_CHAIN_SCHEMA_VERSION,
  checkpointSigningBytes,
  computeAuditEntryHash,
  computeAuditRoot,
  type AuditCheckpointSigningPayload,
} from "../../../../server/src/audit/chain.js";
import { toBase64url } from "../../../../server/src/core/encoding.js";
import { createIdentity, sign } from "../../../../server/src/core/identity.js";
import { derivePurposeKey } from "../../../../server/src/core/key-derivation.js";
import {
  verifyAuditChainRecords,
  type CheckpointExportRecord,
  type EntryExportRecord,
  type ExportRecord,
  type RecordFindingKind,
} from "../../../../server/src/cli/audit-chain-verify.js";

const CLAIM_ID = "4";
const CLAIM_LABEL = "Tamper-evident audit chain";
const IDENTITY_ENCRYPTION_KEY = derivePurposeKey(new Uint8Array([
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
  0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
  0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
  0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
]), "identity-encryption");
const CHECKPOINT_IDENTITY = createIdentity(
  "synthetic-audit-checkpoint-key",
  IDENTITY_ENCRYPTION_KEY,
  "recovery-key"
).storedIdentity;

function entry(seq: number, prevHash: string): EntryExportRecord {
  const input = {
    sequence: seq,
    prev_hash: prevHash,
    timestamp: `2026-05-19T00:00:0${seq}.000Z`,
    encrypted_payload_bytes: toBase64url(new TextEncoder().encode(`audit-entry-${seq}`)),
    schema_version: AUDIT_CHAIN_SCHEMA_VERSION,
  };

  return {
    type: "entry",
    seq,
    schema_version: input.schema_version,
    prev_hash: input.prev_hash,
    entry_hash: computeAuditEntryHash(input),
    timestamp: input.timestamp,
    encrypted_payload_bytes: input.encrypted_payload_bytes,
  };
}

function checkpoint(entries: EntryExportRecord[]): CheckpointExportRecord {
  const payload: AuditCheckpointSigningPayload & { checkpoint_kind: "audit-checkpoint" } = {
    checkpoint_kind: "audit-checkpoint",
    checkpoint_sequence: entries.at(-1)!.seq,
    from_sequence: entries[0]!.seq,
    root_hash: computeAuditRoot(entries.map((item) => item.entry_hash)),
    previous_checkpoint_sequence: 0,
    signed_at: "2026-05-19T00:00:10.000Z",
  };

  return {
    type: "checkpoint",
    ...payload,
    signer_kid: CHECKPOINT_IDENTITY.identity_id,
    signature: toBase64url(
      sign(
        checkpointSigningBytes(payload),
        CHECKPOINT_IDENTITY.encrypted_private_key,
        IDENTITY_ENCRYPTION_KEY
      )
    ),
    public_key: CHECKPOINT_IDENTITY.public_key,
    unsigned: false,
  };
}

function chain(): ExportRecord[] {
  const entries: EntryExportRecord[] = [];
  let prevHash = AUDIT_CHAIN_GENESIS;
  for (let seq = 1; seq <= 5; seq++) {
    const next = entry(seq, prevHash);
    entries.push(next);
    prevHash = next.entry_hash;
  }
  return [...entries, checkpoint(entries)];
}

async function fixture(
  expectedPassed: boolean,
  records: ExportRecord[],
  expectedFinding?: RecordFindingKind
): Promise<FixtureOutcome> {
  const started = performance.now();
  const report = verifyAuditChainRecords(records);
  const hasExpectedFinding =
    expectedFinding === undefined ||
    report.findings.some((finding) => finding.kind === expectedFinding);
  const passed = report.verdict === (expectedPassed ? "PASS" : "FAIL") && hasExpectedFinding;
  return {
    passed,
    durationMs: Math.round(performance.now() - started),
    message: passed
      ? undefined
      : `Expected ${expectedPassed ? "PASS" : "FAIL"} with ${expectedFinding ?? "no finding"}, got ${report.verdict}: ${report.findings.map((finding) => finding.kind).join(", ")}`,
  };
}

registerFixture(CLAIM_ID, CLAIM_LABEL, "audit-chain-verifier: happy path", async () =>
  fixture(true, chain())
);

registerFixture(CLAIM_ID, CLAIM_LABEL, "audit-chain-verifier: tamper mid-chain", async () => {
  const records = chain().map((record) =>
    record.type === "entry" && record.seq === 3
      ? { ...record, encrypted_payload_bytes: `${record.encrypted_payload_bytes}A` }
      : record
  );
  return fixture(false, records, "entry_hash_mismatch");
});

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "audit-chain-verifier: checkpoint signature invalid",
  async () => {
    const records = chain().map((record) =>
      record.type === "checkpoint"
        ? { ...record, signature: toBase64url(new Uint8Array(64)) }
        : record
    );
    return fixture(false, records, "checkpoint_signature_invalid");
  }
);

registerFixture(CLAIM_ID, CLAIM_LABEL, "audit-chain-verifier: sequence gap", async () => {
  const records = chain().filter((record) => !(record.type === "entry" && record.seq === 3));
  return fixture(false, records, "sequence_gap");
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "audit-chain-verifier: prev-hash skew", async () => {
  const records = chain().map((record) =>
    record.type === "entry" && record.seq === 4
      ? { ...record, prev_hash: "forged-prev-hash" }
      : record
  );
  return fixture(false, records, "prev_hash_mismatch");
});
