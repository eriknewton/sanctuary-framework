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
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  createIdentity,
  sign as identitySign,
} from "../../src/core/identity.js";
import {
  checkpointSigningBytes,
  type AuditCheckpointSigningPayload,
} from "../../src/audit/chain.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { toBase64url } from "../../src/core/encoding.js";

import {
  exportAuditChain,
  parseExportArgs,
  runExport,
  type ExportRecord,
  type EntryExportRecord,
  type CheckpointExportRecord,
} from "../../src/cli/audit-chain-export.js";
import {
  verifyAuditChainRecords,
  parseJsonl,
  verifyAuditChainContent,
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
  });

  it("verifies a valid chain content string as PASS with the expected entry count", async () => {
    const { storage, publicKey } = await buildSignedAuditChain();

    const report = verifyAuditChainContent(await collectExport(storage), { publicKey });

    expect(report.verdict).toBe("PASS");
    expect(report.entries_verified).toBe(25);
    expect(report.findings).toHaveLength(0);
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
    const tampered = records.map((r) => {
      if (r.type === "entry" && (r as EntryExportRecord).seq === 3) {
        const e = r as EntryExportRecord;
        return {
          ...e,
          encrypted_payload_bytes: mutateByte(e.encrypted_payload_bytes),
        };
      }
      return r;
    });

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
});
