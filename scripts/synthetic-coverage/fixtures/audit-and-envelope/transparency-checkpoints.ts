/**
 * Synthetic fixtures for assurance row 23: verifiable transparency
 * checkpoints. Exercises the standalone offline verifier
 * (server/src/transparency/verify.ts) against a synthetic signed chain and
 * its adversarial mutations: forged signature, counter gap, duplicate
 * counter (fork), replaced checkpoint (hash-linkage break), and audit-head
 * rollback.
 */
import { registerFixture, type FixtureOutcome } from "../../registry.js";
import { toBase64url } from "../../../../server/src/core/encoding.js";
import { createIdentity, sign as identitySign } from "../../../../server/src/core/identity.js";
import { derivePurposeKey } from "../../../../server/src/core/key-derivation.js";
import {
  checkpointSigningBytes,
  computeCheckpointHash,
  type EnforcementCheckpointPayload,
  type EnforcementCheckpointRecord,
} from "../../../../server/src/transparency/checkpoint.js";
import {
  verifyTransparencyCheckpoints,
  type TransparencyFindingKind,
} from "../../../../server/src/transparency/verify.js";

const CLAIM_ID = "23";
const CLAIM_LABEL =
  "Verifiable transparency checkpoint format and offline verifier";

const IDENTITY_ENCRYPTION_KEY = derivePurposeKey(
  new Uint8Array(32).fill(7),
  "identity-encryption",
);
const SIGNER_IDENTITY = createIdentity(
  "synthetic-transparency-checkpoint-key",
  IDENTITY_ENCRYPTION_KEY,
  "recovery-key",
).storedIdentity;
const PUBLIC_KEY_B64 = SIGNER_IDENTITY.public_key;

function payload(
  counter: number,
  previousHash: string,
  highestSequence: number,
): EnforcementCheckpointPayload {
  return {
    checkpoint_kind: "enforcement-checkpoint",
    schema_version: 1,
    counter,
    previous_checkpoint_hash: previousHash,
    issued_at: `2026-06-09T00:00:0${counter}.000Z`,
    fortress_id: "synthetic-fortress",
    audit: {
      merkle_root: "a".repeat(64),
      lowest_sequence: 1,
      highest_sequence: highestSequence,
      head_hash: "b".repeat(64),
      entry_count: highestSequence,
    },
    policy: {
      rules_sha256: "c".repeat(64),
      rules_count: 1,
      manifest_sha256: null,
    },
    daemon: { version: "synthetic", binary_sha256: "d".repeat(64) },
    enforcement: { total_allowed: counter, total_blocked: 0, rules: [] },
  };
}

function sign(p: EnforcementCheckpointPayload): EnforcementCheckpointRecord {
  return {
    ...p,
    signer_kid: `castle-wall:${PUBLIC_KEY_B64}`,
    signature: toBase64url(
      identitySign(
        checkpointSigningBytes(p),
        SIGNER_IDENTITY.encrypted_private_key,
        IDENTITY_ENCRYPTION_KEY,
      ),
    ),
    signature_algorithm: "Ed25519",
    payload_encoding: "domain-separated-canonical-json-v1",
    public_key: PUBLIC_KEY_B64,
  };
}

function chain(n: number): EnforcementCheckpointRecord[] {
  const records: EnforcementCheckpointRecord[] = [];
  let previousHash = "GENESIS";
  for (let counter = 1; counter <= n; counter++) {
    const p = payload(counter, previousHash, counter * 10);
    records.push(sign(p));
    previousHash = computeCheckpointHash(p);
  }
  return records;
}

async function fixture(
  expectedPassed: boolean,
  records: unknown,
  expectedFinding?: TransparencyFindingKind,
): Promise<FixtureOutcome> {
  const started = performance.now();
  const report = verifyTransparencyCheckpoints(records, {
    publicKey: PUBLIC_KEY_B64,
  });
  const hasExpectedFinding =
    expectedFinding === undefined ||
    report.findings.some((finding) => finding.kind === expectedFinding);
  const passed =
    report.verdict === (expectedPassed ? "PASS" : "FAIL") && hasExpectedFinding;
  return {
    passed,
    durationMs: Math.round(performance.now() - started),
    message: passed
      ? undefined
      : `Expected ${expectedPassed ? "PASS" : "FAIL"} with ${expectedFinding ?? "no finding"}, got ${report.verdict}: ${report.findings.map((finding) => finding.kind).join(", ")}`,
  };
}

registerFixture(CLAIM_ID, CLAIM_LABEL, "transparency: happy-path chain", async () =>
  fixture(true, chain(3)),
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "transparency: forged signature rejected",
  async () => {
    const records = chain(2);
    records[1] = {
      ...records[1]!,
      enforcement: { ...records[1]!.enforcement, total_blocked: 9999 },
    };
    return fixture(false, records, "signature_invalid");
  },
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "transparency: counter gap detected",
  async () => {
    const records = chain(3);
    return fixture(false, [records[0]!, records[2]!], "counter_gap");
  },
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "transparency: duplicate counter (fork) detected",
  async () => {
    const records = chain(2);
    const fork = sign(payload(2, records[1]!.previous_checkpoint_hash, 999));
    return fixture(false, [...records, fork], "counter_duplicate");
  },
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "transparency: replaced checkpoint breaks hash linkage",
  async () => {
    const records = chain(3);
    const replacement = sign(
      payload(2, records[1]!.previous_checkpoint_hash, 999),
    );
    return fixture(
      false,
      [records[0]!, replacement, records[2]!],
      "previous_hash_mismatch",
    );
  },
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "transparency: audit-head rollback detected",
  async () => {
    const first = payload(1, "GENESIS", 50);
    const second = payload(2, computeCheckpointHash(first), 10);
    return fixture(false, [sign(first), sign(second)], "counter_rollback");
  },
);
