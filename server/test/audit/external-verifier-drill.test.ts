/**
 * External audit-chain verifier drill
 *
 * Integration test that proves the external verifier works correctly against
 * a real exported audit chain and detects three tampering scenarios:
 *
 *   A. Entry payload mutation
 *   B. Entry sequence swap
 *   C. Checkpoint signature invalidation
 *
 * This is the kind of artifact handed to a security reviewer as proof.
 */

import { describe, expect, it, beforeEach } from "vitest";
import { Writable } from "node:stream";
import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  createIdentity,
  sign as identitySign,
} from "../../src/core/identity.js";
import {
  AUDIT_CHAIN_GENESIS,
  computeAuditEntryHash,
  computeAuditRoot,
  checkpointSigningBytes,
  verifyCheckpointSignature,
  type AuditCheckpointSigningPayload,
} from "../../src/audit/chain.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { toBase64url } from "../../src/core/encoding.js";

import {
  exportAuditChain,
  parseExportArgs,
  runExport,
  type EntryExportRecord,
  type CheckpointExportRecord,
} from "../../src/cli/audit-chain-export.js";
import {
  AUDIT_CHAIN_VERIFY_EXIT_OK,
  AUDIT_CHAIN_VERIFY_EXIT_RELAXED_FINDINGS,
  AUDIT_CHAIN_VERIFY_EXIT_STRICT_FINDINGS,
  auditChainVerifyExitCode,
  verifyAuditChainRecords,
  parseJsonl,
  verifyAuditChainContent,
  type ExportRecord as VerifierExportRecord,
  type CheckpointExportRecord as VerifierCheckpointExportRecord,
} from "../../src/cli/audit-chain-verify.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Collect exportAuditChain output into a string. */
async function collectExport(storage: StorageBackend): Promise<string> {
  const chunks: string[] = [];
  const out = new Writable({
    write(chunk: Buffer | string, _enc: BufferEncoding, cb: () => void) {
      chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
      cb();
    },
  });
  await exportAuditChain(storage, out);
  return chunks.join("");
}

/** Mutate a single character in the middle of a base64url string. */
function mutateByte(b64: string, index = Math.floor(b64.length / 2)): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".split("");
  const original = b64[index]!;
  const replacement = chars.find((c) => c !== original) ?? "A";
  return b64.slice(0, index) + replacement + b64.slice(index + 1);
}

function tamperEntryPayload(
  records: readonly VerifierExportRecord[],
  seq: number
): VerifierExportRecord[] {
  return records.map((r) => {
    if (r.type === "entry" && (r as EntryExportRecord).seq === seq) {
      const e = r as EntryExportRecord;
      return {
        ...e,
        encrypted_payload_bytes: mutateByte(e.encrypted_payload_bytes),
      };
    }
    return r;
  });
}

type SignedCheckpointRecord = VerifierCheckpointExportRecord & {
  signature: string;
  public_key: string;
};

function firstSignedCheckpoint(
  records: readonly VerifierExportRecord[]
): SignedCheckpointRecord {
  const checkpoint = records.find(
    (r): r is VerifierCheckpointExportRecord => r.type === "checkpoint"
  );
  if (!checkpoint?.signature || !checkpoint.public_key) {
    throw new Error("expected a signed checkpoint with an embedded public key");
  }
  return checkpoint as SignedCheckpointRecord;
}

function checkpointPayload(record: VerifierCheckpointExportRecord): AuditCheckpointSigningPayload {
  return {
    checkpoint_kind: record.checkpoint_kind,
    checkpoint_sequence: record.checkpoint_sequence,
    from_sequence: record.from_sequence,
    root_hash: record.root_hash,
    previous_checkpoint_sequence: record.previous_checkpoint_sequence,
    signed_at: record.signed_at,
  };
}

async function forgeSelfConsistentTamperedChain(
  records: readonly VerifierExportRecord[],
  tamperedSeq: number,
): Promise<{
  records: VerifierExportRecord[];
  embeddedPublicKey: string;
}> {
  const forgedMasterKey = generateRandomKey();
  const forgedIdentityKey = derivePurposeKey(forgedMasterKey, "identity-encryption");
  const { storedIdentity } = createIdentity(
    "forged-signer",
    forgedIdentityKey,
    "recovery-key",
  );

  const entries = records
    .filter((r): r is EntryExportRecord => r.type === "entry")
    .sort((a, b) => a.seq - b.seq);
  const forgedEntries = new Map<number, EntryExportRecord>();
  let prevHash = AUDIT_CHAIN_GENESIS;
  for (const entry of entries) {
    const encrypted_payload_bytes =
      entry.seq === tamperedSeq
        ? mutateByte(entry.encrypted_payload_bytes)
        : entry.encrypted_payload_bytes;
    const forgedEntry: EntryExportRecord = {
      ...entry,
      prev_hash: prevHash,
      encrypted_payload_bytes,
      entry_hash: computeAuditEntryHash({
        sequence: entry.seq,
        prev_hash: prevHash,
        timestamp: entry.timestamp,
        encrypted_payload_bytes,
        schema_version: entry.schema_version,
      }),
    };
    forgedEntries.set(forgedEntry.seq, forgedEntry);
    prevHash = forgedEntry.entry_hash;
  }

  const forged = records.map((record): VerifierExportRecord => {
    if (record.type === "entry") {
      return forgedEntries.get((record as EntryExportRecord).seq)! as VerifierExportRecord;
    }
    if (record.type !== "checkpoint") {
      return record;
    }
    const checkpoint = record as VerifierCheckpointExportRecord;
    const hashes: string[] = [];
    for (
      let seq = checkpoint.from_sequence;
      seq <= checkpoint.checkpoint_sequence;
      seq++
    ) {
      hashes.push(forgedEntries.get(seq)!.entry_hash);
    }
    const payload: AuditCheckpointSigningPayload = {
      checkpoint_kind: checkpoint.checkpoint_kind,
      checkpoint_sequence: checkpoint.checkpoint_sequence,
      from_sequence: checkpoint.from_sequence,
      root_hash: computeAuditRoot(hashes),
      previous_checkpoint_sequence: checkpoint.previous_checkpoint_sequence,
      signed_at: checkpoint.signed_at,
    };
    return {
      ...checkpoint,
      root_hash: payload.root_hash,
      signer_kid: storedIdentity.identity_id,
      signature: toBase64url(
        identitySign(
          checkpointSigningBytes(payload),
          storedIdentity.encrypted_private_key,
          forgedIdentityKey,
        ),
      ),
      public_key: storedIdentity.public_key,
      unsigned: false,
    };
  });

  forgedMasterKey.fill(0);
  forgedIdentityKey.fill(0);
  return { records: forged, embeddedPublicKey: storedIdentity.public_key };
}

// ---------------------------------------------------------------------------
// Shared setup: 25 critical entries across L1-L4, checkpoint interval=5
// ---------------------------------------------------------------------------

async function buildSignedAuditChain(): Promise<{
  storage: StorageBackend;
  masterKey: Uint8Array;
  publicKey: string;
}> {
  return buildSignedAuditChainInStorage(new MemoryStorage());
}

async function buildSignedAuditChainInStorage(storage: StorageBackend): Promise<{
  storage: StorageBackend;
  masterKey: Uint8Array;
  publicKey: string;
}> {
  const masterKey = generateRandomKey();
  const identityKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity(
    "drill-signer",
    identityKey,
    "recovery-key"
  );

  const signer = async (payload: AuditCheckpointSigningPayload) => ({
    signer_kid: storedIdentity.identity_id,
    signature: toBase64url(
      identitySign(
        checkpointSigningBytes(payload),
        storedIdentity.encrypted_private_key,
        identityKey
      )
    ),
    public_key: storedIdentity.public_key,
  });

  const log = new AuditLog(storage, masterKey, {
    checkpointInterval: 5,
    checkpointSigner: signer,
    checkpointPublicKeyResolver: () => storedIdentity.public_key,
  });

  // Write 25 critical entries across all layers
  const layers: Array<"l1" | "l2" | "l3" | "l4"> = ["l1", "l2", "l3", "l4"];
  for (let i = 0; i < 25; i++) {
    await log.appendCritical({
      layer: layers[i % layers.length]!,
      operation: `drill_op_${i}`,
      identity_id: "drill-identity",
      result: "success",
      details: { index: i },
    });
  }
  await log.flush();

  return { storage, masterKey, publicKey: storedIdentity.public_key };
}

// ---------------------------------------------------------------------------
// Happy-path drill
// ---------------------------------------------------------------------------

describe("external-verifier-drill: happy path", () => {
  it("exports a 25-entry chain and verifies it as PASS", async () => {
    const { storage, publicKey } = await buildSignedAuditChain();

    const jsonl = await collectExport(storage);
    const records = parseJsonl(jsonl);

    // Should have entries and checkpoints
    const entries = records.filter((r) => r.type === "entry");
    const checkpoints = records.filter((r) => r.type === "checkpoint");
    expect(entries.length).toBe(25);
    expect(checkpoints.length).toBeGreaterThanOrEqual(1);

    // All checkpoints must have signatures
    for (const cp of checkpoints) {
      const c = cp as CheckpointExportRecord;
      expect(c.unsigned).toBe(false);
      expect(c.signature).not.toBeNull();
      expect(c.public_key).toBe(publicKey);
    }

    const report = verifyAuditChainRecords(records, { publicKey });
    expect(report.verdict).toBe("PASS");
    expect(report.findings).toHaveLength(0);
    expect(report.entries_verified).toBe(25);
    expect(report.checkpoints_verified).toBeGreaterThanOrEqual(1);
    expect(report.signatures_verified).toBe(checkpoints.length);
    expect(report.signatures_skipped).toBe(0);
  });

  it("verifies a valid chain content string as PASS with the expected entry count", async () => {
    const { storage, publicKey } = await buildSignedAuditChain();

    const report = verifyAuditChainContent(await collectExport(storage), { publicKey });

    expect(report.verdict).toBe("PASS");
    expect(report.entries_verified).toBe(25);
    expect(report.findings).toHaveLength(0);
  });

  it("refuses an embedded-key-only checkpoint basis unless explicitly opted in", async () => {
    const { storage, publicKey } = await buildSignedAuditChain();
    const records = parseJsonl(await collectExport(storage));

    const defaultReport = verifyAuditChainRecords(records);
    expect(defaultReport.verdict).toBe("FAIL");
    expect(defaultReport.signature_basis).toBe("none");
    expect(defaultReport.signatures_verified).toBe(0);
    expect(
      defaultReport.findings.every(
        (finding) => finding.kind === "checkpoint_signature_missing_key",
      ),
    ).toBe(true);

    const pinnedReport = verifyAuditChainRecords(records, { publicKey });
    expect(pinnedReport.verdict).toBe("PASS");
    expect(pinnedReport.signature_basis).toBe("pinned");

    const embeddedReport = verifyAuditChainRecords(records, { trustEmbedded: true });
    expect(embeddedReport.verdict).toBe("PASS");
    expect(embeddedReport.signature_basis).toBe("embedded");
  });

  it("does not PASS a tampered chain re-signed with a fresh embedded key by default", async () => {
    const { storage, publicKey } = await buildSignedAuditChain();
    const original = parseJsonl(await collectExport(storage));
    const forged = await forgeSelfConsistentTamperedChain(original, 3);

    const defaultReport = verifyAuditChainRecords(forged.records);
    expect(defaultReport.verdict).toBe("FAIL");
    expect(defaultReport.signature_basis).toBe("none");
    expect(defaultReport.signatures_verified).toBe(0);
    expect(
      defaultReport.findings.some(
        (finding) => finding.kind === "checkpoint_signature_missing_key",
      ),
    ).toBe(true);
    expect(
      defaultReport.findings.some(
        (finding) =>
          finding.kind === "entry_hash_mismatch" ||
          finding.kind === "prev_hash_mismatch" ||
          finding.kind === "checkpoint_root_mismatch",
      ),
    ).toBe(false);

    const pinnedReport = verifyAuditChainRecords(forged.records, { publicKey });
    expect(pinnedReport.verdict).toBe("FAIL");
    expect(pinnedReport.signature_basis).toBe("pinned");
    expect(
      pinnedReport.findings.some(
        (finding) => finding.kind === "checkpoint_signature_invalid",
      ),
    ).toBe(true);

    const embeddedReport = verifyAuditChainRecords(forged.records, {
      trustEmbedded: true,
    });
    expect(embeddedReport.verdict).toBe("PASS");
    expect(embeddedReport.signature_basis).toBe("embedded");
    expect(embeddedReport.signatures_verified).toBeGreaterThan(0);
    expect(forged.embeddedPublicKey).not.toBe(publicKey);
  });

  it("exports a rotated chain with its rotation anchor and verifies it as PASS", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const log = new AuditLog(storage, masterKey, {
      maxEntries: 5,
      checkpointInterval: 3,
    });
    for (let i = 0; i < 12; i++) {
      await log.appendCritical({
        layer: "l1",
        operation: `rotated_op_${i}`,
        identity_id: "drill-identity",
        result: "success",
      });
    }
    await log.flush();

    const jsonl = await collectExport(storage);
    const records = parseJsonl(jsonl);
    const checkpointCount = records.filter((r) => r.type === "checkpoint").length;

    expect(records.filter((r) => r.type === "entry")).toHaveLength(5);
    expect(records).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "rotation_anchor",
          base_sequence: 8,
        }),
      ])
    );
    const report = verifyAuditChainRecords(records);
    expect(report.verdict).toBe("PASS");
    expect(report.findings).toHaveLength(0);
    expect(report.signatures_verified).toBe(0);
    expect(report.signatures_skipped).toBe(checkpointCount);
  });
});

// ---------------------------------------------------------------------------
// Finding MMMMM: export/verify operator CLI regression coverage
// ---------------------------------------------------------------------------

describe("external-verifier-drill: Finding MMMMM export and input guards", () => {
  it("exports a fortress audit chain from the fortress state directory", async () => {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-audit-export-"));
    const output = join(fortress, "audit.jsonl");
    const storage = new FilesystemStorage(join(fortress, "state"));
    await buildSignedAuditChainInStorage(storage);

    await runExport(parseExportArgs(["--fortress", fortress, "--output", output]));

    const exported = await readFile(output, "utf8");
    expect((await stat(output)).size).toBeGreaterThan(0);
    expect(parseJsonl(exported).filter((r) => r.type === "entry")).toHaveLength(25);
  });

  it("honors an explicit --fortress flag over the environment fortress", async () => {
    const emptyFortress = await mkdtemp(join(tmpdir(), "sanctuary-audit-empty-"));
    const populatedFortress = await mkdtemp(join(tmpdir(), "sanctuary-audit-full-"));
    const output = join(populatedFortress, "audit.jsonl");
    const storage = new FilesystemStorage(join(populatedFortress, "state"));
    await buildSignedAuditChainInStorage(storage);

    await runExport(
      parseExportArgs(["--fortress", populatedFortress, "--output", output], {
        SANCTUARY_FORTRESS_PATH: emptyFortress,
      } as NodeJS.ProcessEnv)
    );

    expect(parseJsonl(await readFile(output, "utf8")).filter((r) => r.type === "entry")).toHaveLength(25);
  });

  it("rejects a zero-byte input with empty_input", () => {
    const report = verifyAuditChainContent("");

    expect(report.verdict).toBe("FAIL");
    expect(report.entries_verified).toBe(0);
    expect(report.findings[0]?.kind).toBe("empty_input");
  });

  it("rejects parsed JSON with zero entries and zero checkpoints with empty_input", () => {
    const report = verifyAuditChainContent('{"entries":[],"checkpoints":[]}');

    expect(report.verdict).toBe("FAIL");
    expect(report.findings[0]?.kind).toBe("empty_input");
  });

  it("rejects malformed JSONL input with malformed_input", () => {
    const report = verifyAuditChainContent("{not-json");

    expect(report.verdict).toBe("FAIL");
    expect(report.findings[0]?.kind).toBe("malformed_input");
  });
});

// ---------------------------------------------------------------------------
// Scenario A: Entry payload mutation
// ---------------------------------------------------------------------------

describe("external-verifier-drill: Scenario A - entry payload mutation", () => {
  it("detects a single mutated byte in one entry's encrypted_payload_bytes", async () => {
    const { storage, publicKey } = await buildSignedAuditChain();
    const jsonl = await collectExport(storage);
    const records = parseJsonl(jsonl);

    // Mutate encrypted_payload_bytes of seq=3
    const tampered = tamperEntryPayload(records, 3);

    const report = verifyAuditChainRecords(tampered, { publicKey });
    expect(report.verdict).toBe("FAIL");

    // Must detect hash mismatch at seq 3
    const hashFinding = report.findings.find(
      (f) => f.kind === "entry_hash_mismatch" && f.seq === 3
    );
    expect(hashFinding).toBeDefined();

    // prev_hash of seq 4 should also fail (chain breaks from seq 3 forward)
    const chainFinding = report.findings.find(
      (f) => f.kind === "prev_hash_mismatch" && f.seq === 4
    );
    expect(chainFinding).toBeDefined();
  });

  it("reports FAIL with findings even when strict mode is disabled", async () => {
    const { storage, publicKey } = await buildSignedAuditChain();
    const tampered = tamperEntryPayload(parseJsonl(await collectExport(storage)), 3);

    const report = verifyAuditChainRecords(tampered, { publicKey, strict: false });

    expect(report.verdict).toBe("FAIL");
    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.findings.some((f) => f.kind === "entry_hash_mismatch")).toBe(true);
  });
});

describe("external-verifier-drill: CLI exit policy", () => {
  it("returns exit 0 for a clean report", async () => {
    const { storage, publicKey } = await buildSignedAuditChain();
    const report = verifyAuditChainRecords(parseJsonl(await collectExport(storage)), {
      publicKey,
    });

    expect(report.verdict).toBe("PASS");
    expect(AUDIT_CHAIN_VERIFY_EXIT_OK).toBe(0);
    expect(auditChainVerifyExitCode(report, true)).toBe(AUDIT_CHAIN_VERIFY_EXIT_OK);
    expect(auditChainVerifyExitCode(report, false)).toBe(AUDIT_CHAIN_VERIFY_EXIT_OK);
  });

  it("returns exit 1 for strict verification findings", async () => {
    const { storage, publicKey } = await buildSignedAuditChain();
    const tampered = tamperEntryPayload(parseJsonl(await collectExport(storage)), 3);
    const report = verifyAuditChainRecords(tampered, { publicKey });

    expect(report.verdict).toBe("FAIL");
    expect(AUDIT_CHAIN_VERIFY_EXIT_STRICT_FINDINGS).toBe(1);
    expect(auditChainVerifyExitCode(report, true)).toBe(
      AUDIT_CHAIN_VERIFY_EXIT_STRICT_FINDINGS,
    );
  });

  it("returns exit 10 for --no-strict verification findings", async () => {
    const { storage, publicKey } = await buildSignedAuditChain();
    const tampered = tamperEntryPayload(parseJsonl(await collectExport(storage)), 3);
    const report = verifyAuditChainRecords(tampered, { publicKey });

    expect(report.verdict).toBe("FAIL");
    expect(AUDIT_CHAIN_VERIFY_EXIT_RELAXED_FINDINGS).toBe(10);
    expect(auditChainVerifyExitCode(report, false)).toBe(
      AUDIT_CHAIN_VERIFY_EXIT_RELAXED_FINDINGS,
    );
  });
});

// ---------------------------------------------------------------------------
// Scenario B: Entry sequence swap
// ---------------------------------------------------------------------------

describe("external-verifier-drill: Scenario B - entry sequence swap", () => {
  it("detects two entries swapped by position", async () => {
    const { storage, publicKey } = await buildSignedAuditChain();
    const jsonl = await collectExport(storage);
    const records = parseJsonl(jsonl);

    // Swap seq=7 and seq=8 in the records array
    const tampered = [...records];
    const idx7 = tampered.findIndex(
      (r) => r.type === "entry" && (r as EntryExportRecord).seq === 7
    );
    const idx8 = tampered.findIndex(
      (r) => r.type === "entry" && (r as EntryExportRecord).seq === 8
    );
    expect(idx7).toBeGreaterThanOrEqual(0);
    expect(idx8).toBeGreaterThanOrEqual(0);
    // Swap the seq numbers so the verifier sees them out of chain order
    const entry7 = { ...(tampered[idx7] as EntryExportRecord), seq: 8 };
    const entry8 = { ...(tampered[idx8] as EntryExportRecord), seq: 7 };
    tampered[idx7] = entry8;
    tampered[idx8] = entry7;

    const report = verifyAuditChainRecords(tampered, { publicKey });
    expect(report.verdict).toBe("FAIL");

    // Should find prev_hash mismatch (chain broken at swap point)
    const discontinuity = report.findings.find(
      (f) => f.kind === "prev_hash_mismatch"
    );
    expect(discontinuity).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Scenario C: Checkpoint signature invalidation
// ---------------------------------------------------------------------------

describe("external-verifier-drill: Scenario C - checkpoint signature invalidation", () => {
  it("detects an invalidated checkpoint signature while entry chain still passes", async () => {
    const { storage, publicKey } = await buildSignedAuditChain();
    const jsonl = await collectExport(storage);
    const records = parseJsonl(jsonl);

    // Invalidate the signature of the first checkpoint
    const tampered = records.map((r) => {
      if (r.type === "checkpoint") {
        const cp = r as CheckpointExportRecord;
        return {
          ...cp,
          signature: toBase64url(new Uint8Array(64)), // zeros - invalid
        };
      }
      return r;
    });

    const report = verifyAuditChainRecords(tampered, { publicKey });
    expect(report.verdict).toBe("FAIL");

    // Must find checkpoint signature invalid
    const sigFinding = report.findings.find(
      (f) => f.kind === "checkpoint_signature_invalid"
    );
    expect(sigFinding).toBeDefined();

    // Entry chain itself has no hash or prev_hash findings
    const entryFindings = report.findings.filter(
      (f) =>
        f.kind === "entry_hash_mismatch" ||
        f.kind === "prev_hash_mismatch" ||
        f.kind === "sequence_gap"
    );
    expect(entryFindings).toHaveLength(0);
  });

  it("runtime checkpoint verification rejects non-canonical base64url signature material", async () => {
    const { storage } = await buildSignedAuditChain();
    const checkpoint = firstSignedCheckpoint(parseJsonl(await collectExport(storage)));
    const payload = checkpointPayload(checkpoint);

    expect(verifyCheckpointSignature(payload, checkpoint.signature, checkpoint.public_key)).toBe(
      true
    );
    expect(
      verifyCheckpointSignature(payload, `${checkpoint.signature}!`, checkpoint.public_key)
    ).toBe(false);
    expect(
      verifyCheckpointSignature(payload, checkpoint.signature, `${checkpoint.public_key}!`)
    ).toBe(false);
  });

  it("standalone verification rejects non-canonical base64url checkpoint strings", async () => {
    const { storage } = await buildSignedAuditChain();
    const records = parseJsonl(await collectExport(storage));
    const checkpoint = firstSignedCheckpoint(records);

    const nonCanonicalSignature = records.map((record) =>
      record === checkpoint
        ? { ...checkpoint, signature: `${checkpoint.signature}!` }
        : record
    );
    const signatureReport = verifyAuditChainRecords(nonCanonicalSignature, {
      trustEmbedded: true,
    });
    expect(signatureReport.verdict).toBe("FAIL");
    expect(
      signatureReport.findings.some((f) => f.kind === "checkpoint_signature_invalid")
    ).toBe(true);

    const nonCanonicalKey = records.map((record) =>
      record === checkpoint
        ? { ...checkpoint, public_key: `${checkpoint.public_key}!` }
        : record
    );
    const keyReport = verifyAuditChainRecords(nonCanonicalKey, {
      trustEmbedded: true,
    });
    expect(keyReport.verdict).toBe("FAIL");
    expect(keyReport.findings.some((f) => f.kind === "checkpoint_signature_invalid")).toBe(
      true
    );
  });
});
