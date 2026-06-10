/**
 * Host-mode (--against-log) verification: the live audit log is the ground
 * truth. Truncated tails, in-window deletions, altered entries, and
 * tampered counters must all surface as specific findings.
 */
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  bytesToString,
  stringToBytes,
  toBase64url,
} from "../../src/core/encoding.js";
import { randomBytes } from "../../src/core/random.js";
import {
  emitEnforcementCheckpoint,
  type TransparencySigner,
} from "../../src/transparency/emitter.js";
import { verifyAgainstLog } from "../../src/transparency/against-log.js";
import type { VerifierCheckpointRecord } from "../../src/transparency/verify.js";

function testSigner(privateKey = randomBytes(32)): TransparencySigner {
  const publicKey = ed25519.getPublicKey(privateKey);
  return {
    signer_kid: `castle-wall:${toBase64url(publicKey)}`,
    publicKey,
    sign: async (bytes) => ed25519.sign(bytes, privateKey),
  };
}

let fortressPath: string;
let storage: FilesystemStorage;
let masterKey: Uint8Array;
let auditLog: AuditLog;

beforeEach(async () => {
  fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-against-log-"));
  const rulesDir = join(fortressPath, "policy", "egress", "rules");
  await mkdir(rulesDir, { recursive: true });
  await writeFile(
    join(rulesDir, "allow-github.json"),
    JSON.stringify({ rule_id: "allow-github" })
  );
  await writeFile(join(fortressPath, "fake-binary.js"), "exit(0)");
  storage = new FilesystemStorage(join(fortressPath, "state"));
  masterKey = randomBytes(32);
  auditLog = new AuditLog(storage, masterKey);
});

afterEach(async () => {
  await rm(fortressPath, { recursive: true, force: true });
});

async function seedAndEmit(): Promise<VerifierCheckpointRecord> {
  for (let i = 0; i < 3; i++) {
    await auditLog.appendCritical({
      layer: "l1",
      operation: i === 0 ? "egress_blocked" : "egress_allowed",
      identity_id: "fortress-test",
      result: "success",
      details: { rule_id: "allow-github" },
    });
  }
  const record = await emitEnforcementCheckpoint({
    storage,
    auditLog,
    fortressId: "fortress-test",
    fortressPath,
    masterKey,
    signer: testSigner(),
    binaryPath: join(fortressPath, "fake-binary.js"),
    version: "0.0.0-test",
  });
  return record as unknown as VerifierCheckpointRecord;
}

async function auditEntryKeys(): Promise<string[]> {
  return (await storage.list("_audit", "entry-")).map((meta) => meta.key);
}

describe("verify-transparency --against-log", () => {
  it("recomputes the Merkle root and recounts counters on an intact log", async () => {
    const record = await seedAndEmit();
    const result = await verifyAgainstLog({
      records: [record],
      storage,
      auditLog,
    });
    expect(result.findings).toHaveLength(0);
    expect(result.merkle_root_recomputed).toBe(true);
    expect(result.counters_recomputed).toBe(true);
    expect(result.checked_counter).toBe(record.counter);
  });

  it("still verifies after the log legitimately advances past the checkpoint", async () => {
    const record = await seedAndEmit();
    await auditLog.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "fortress-test",
      result: "success",
      details: { rule_id: "allow-github" },
    });
    const result = await verifyAgainstLog({
      records: [record],
      storage,
      auditLog,
    });
    expect(result.findings).toHaveLength(0);
    expect(result.merkle_root_recomputed).toBe(true);
    expect(result.counters_recomputed).toBe(true);
  });

  it("DETECTS tail truncation: live head behind the signed head", async () => {
    const record = await seedAndEmit();
    const keys = await auditEntryKeys();
    await storage.delete("_audit", keys.at(-1)!);
    const result = await verifyAgainstLog({ records: [record], storage });
    expect(
      result.findings.some((f) => f.kind === "log_head_behind_checkpoint")
    ).toBe(true);
    expect(result.merkle_root_recomputed).toBe(false);
  });

  it("DETECTS in-window deletion of an audit entry", async () => {
    const record = await seedAndEmit();
    const keys = await auditEntryKeys();
    await storage.delete("_audit", keys[1]!);
    const result = await verifyAgainstLog({ records: [record], storage });
    expect(result.findings.some((f) => f.kind === "log_entry_missing")).toBe(
      true
    );
  });

  it("DETECTS an altered audit entry via Merkle-root mismatch", async () => {
    const record = await seedAndEmit();
    const keys = await auditEntryKeys();
    const raw = await storage.read("_audit", keys[1]!);
    const envelope = JSON.parse(bytesToString(raw!)) as Record<string, unknown>;
    envelope.entry_hash = "0".repeat(64);
    await storage.write(
      "_audit",
      keys[1]!,
      stringToBytes(JSON.stringify(envelope))
    );
    const result = await verifyAgainstLog({ records: [record], storage });
    expect(
      result.findings.some((f) => f.kind === "merkle_root_mismatch")
    ).toBe(true);
  });

  it("DETECTS tampered enforcement counters on recount", async () => {
    const record = await seedAndEmit();
    const tampered: VerifierCheckpointRecord = {
      ...record,
      enforcement: { ...record.enforcement, total_blocked: 0 },
    };
    const result = await verifyAgainstLog({
      records: [tampered],
      storage,
      auditLog,
    });
    expect(result.findings.some((f) => f.kind === "counters_mismatch")).toBe(
      true
    );
    expect(result.counters_recomputed).toBe(false);
  });

  it("states honestly when counters cannot be recounted (no decryption key)", async () => {
    const record = await seedAndEmit();
    const result = await verifyAgainstLog({ records: [record], storage });
    expect(result.counters_recomputed).toBe(false);
    expect(result.notes.join(" ")).toContain("no decryption key");
    // The root is still recomputed without any key (plaintext chain metadata).
    expect(result.merkle_root_recomputed).toBe(true);
  });
});
