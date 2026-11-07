import { expect, it } from "vitest";
import { performance } from "node:perf_hooks";
import { computeAuditEntryHash, computeAuditRoot } from "../../src/audit/chain.js";
import type { CheckpointExportRecord, EntryExportRecord } from "../../src/cli/audit-chain-verify.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
import { auditExtent, verifySnapshotAudit } from "../../src/evidence-pack/snapshot-nested.js";
import { auditFixture, auditBytes, identity, resignCheckpoint, trustRow } from "./snapshot-fixtures.js";

it("audit verification at the real byte and partition caps stays within 120 seconds", () => {
  const identities = Array.from({ length: C.MAX_KEYS }, () => identity());
  const signers = [...identities, identities[0]];
  const records = auditFixture(signers);
  let previous = "GENESIS";
  for (let i = 0; i < signers.length; i++) {
    const entry = records[i * 2] as EntryExportRecord;
    entry.prev_hash = previous;
    // The large entries approach the line cap while leaving room for every signed checkpoint.
    entry.encrypted_payload_bytes = i < C.MAX_KEYS ? "A".repeat(C.MAX_JSONL_LINE_BYTES - 2048) : "AQ";
    entry.entry_hash = computeAuditEntryHash({ sequence: entry.seq, schema_version: entry.schema_version, prev_hash: entry.prev_hash, timestamp: entry.timestamp, encrypted_payload_bytes: entry.encrypted_payload_bytes });
    previous = entry.entry_hash;
    const cp = records[i * 2 + 1] as CheckpointExportRecord;
    cp.root_hash = computeAuditRoot([entry.entry_hash]); resignCheckpoint(cp, signers[i]);
  }
  const unpadded = auditBytes(records);
  const padding = C.MAX_FILE_BYTES - unpadded.length;
  expect(padding).toBeGreaterThan(0);
  const lastLine = Buffer.from(unpadded).toString().trimEnd().split(C.LF).at(-1)!;
  expect(lastLine.length + padding).toBeLessThanOrEqual(C.MAX_JSONL_LINE_BYTES);
  const bytes = new Uint8Array(C.MAX_FILE_BYTES).fill(32);
  bytes.set(unpadded.subarray(0, unpadded.length - 1)); bytes[bytes.length - 1] = 10;
  const keys = identities.map(who => trustRow(who, C.PIN_ROLE.audit));
  expect(bytes.length).toBe(C.MAX_FILE_BYTES); expect(keys.length).toBe(C.MAX_KEYS);
  const start = performance.now();
  const result = verifySnapshotAudit(bytes, auditExtent(records), keys);
  const elapsed = performance.now() - start;
  process.stdout.write(`CAP_TIMING bytes=${bytes.length} partitions=${keys.length} entries=${signers.length} signatures=${signers.length} elapsed_ms=${elapsed.toFixed(1)} budget_ms=120000\n`);
  expect(result.partial).toEqual([]);
  expect(result.report).toMatchObject({ verdict: C.STATUS.PASS, entries_verified: signers.length, checkpoints_verified: signers.length, signatures_verified: signers.length });
  expect(elapsed).toBeLessThan(120_000);
}, 150_000);
