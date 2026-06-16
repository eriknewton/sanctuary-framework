/**
 * F3 — audit-log rotation checkpoint (signed base anchor) regression tests.
 *
 * Turns the overnight-sweep PoCs into regressions:
 *   1. Crossing the rotation cap no longer wedges the log (the bug): a rotated
 *      log reloads with ZERO findings, is readable, and accepts appendCritical.
 *   2. Deleting a SURVIVING post-cut entry is still detected (the chain break
 *      forward of the checkpoint surfaces a finding).
 *   3. Deleting / forging the MAC-authenticated rotation anchor is detected
 *      (fail-closed: a truncation attacker cannot pass it off as rotation).
 *   4. Trust-on-first-use migration: a pre-F3 already-rotated log (no anchor)
 *      that is internally contiguous self-heals once, then is authenticated.
 */

import { describe, expect, it } from "vitest";
import {
  AuditLog,
  type PersistedAuditEnvelopeV2,
} from "../../src/operational/audit-log.js";
import {
  bytesToString,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../../src/core/encoding.js";
import { generateRandomKey } from "../../src/core/random.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type {
  StorageBackend,
  StorageEntryMeta,
} from "../../src/storage/interface.js";

const ROTATION_ANCHOR_KEY = "__rotation_anchor";
const CHECKPOINT_NAMESPACE = "_audit_checkpoints";

/**
 * MemoryStorage that fails the rotation-anchor write specifically while passing
 * every other write (including audit-entry deletes) through. Models "the anchor
 * write fails but entry deletes would succeed" — the case where pruning without a
 * written anchor would leave an unauthenticated post-F3 cut and defeat the
 * fail-closed guarantee.
 */
class AnchorWriteFailingStorage implements StorageBackend {
  constructor(private readonly inner = new MemoryStorage()) {}
  write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (namespace === CHECKPOINT_NAMESPACE && key === ROTATION_ANCHOR_KEY) {
      return Promise.reject(new Error("simulated rotation-anchor write failure"));
    }
    return this.inner.write(namespace, key, data);
  }
  read(namespace: string, key: string): Promise<Uint8Array | null> {
    return this.inner.read(namespace, key);
  }
  delete(namespace: string, key: string, secure?: boolean): Promise<boolean> {
    return this.inner.delete(namespace, key, secure);
  }
  list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]> {
    return this.inner.list(namespace, prefix);
  }
  exists(namespace: string, key: string): Promise<boolean> {
    return this.inner.exists(namespace, key);
  }
  totalSize(): Promise<number> {
    return this.inner.totalSize();
  }
}

async function appendCritical(log: AuditLog, operation: string): Promise<void> {
  await log.appendCritical({
    layer: "l1",
    operation,
    identity_id: "id-1",
    result: "success",
    details: { operation },
  });
}

/** Drive a writer past `maxEntries` so rotation prunes a contiguous prefix. */
async function rotatedLog(
  maxEntries: number,
  total: number,
  checkpointInterval?: number
): Promise<{
  storage: MemoryStorage;
  masterKey: Uint8Array;
}> {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const writer = new AuditLog(storage, masterKey, {
    maxEntries,
    ...(checkpointInterval !== undefined ? { checkpointInterval } : {}),
  });
  for (let i = 0; i < total; i++) {
    await appendCritical(writer, `op-${i}`);
  }
  await writer.flush();
  return { storage, masterKey };
}

async function entrySequences(storage: StorageBackend): Promise<number[]> {
  const metas = await storage.list("_audit", "entry-");
  const seqs: number[] = [];
  for (const meta of metas) {
    const raw = await storage.read("_audit", meta.key);
    if (!raw) continue;
    const env = JSON.parse(bytesToString(raw)) as PersistedAuditEnvelopeV2;
    seqs.push(env.sequence);
  }
  return seqs.sort((a, b) => a - b);
}

/** Storage key of the surviving entry with the given sequence. */
async function keyForSequence(
  storage: StorageBackend,
  sequence: number
): Promise<string> {
  const metas = await storage.list("_audit", "entry-");
  for (const meta of metas) {
    const raw = await storage.read("_audit", meta.key);
    if (!raw) continue;
    const env = JSON.parse(bytesToString(raw)) as PersistedAuditEnvelopeV2;
    if (env.sequence === sequence) return meta.key;
  }
  throw new Error(`no surviving audit entry at sequence ${sequence}`);
}

async function readAnchor(
  storage: MemoryStorage
): Promise<{ [k: string]: unknown; data: { base_sequence: number; base_prev_hash: string }; mac: string }> {
  const raw = await storage.read("_audit_checkpoints", ROTATION_ANCHOR_KEY);
  if (!raw) throw new Error("rotation anchor missing");
  return JSON.parse(bytesToString(raw));
}

async function writeAnchor(
  storage: MemoryStorage,
  envelope: unknown
): Promise<void> {
  await storage.write(
    "_audit_checkpoints",
    ROTATION_ANCHOR_KEY,
    stringToBytes(JSON.stringify(envelope))
  );
}

describe("AuditLog F3 rotation checkpoint", () => {
  it("a rotated log reloads cleanly and stays readable + writable (the wedge is gone)", async () => {
    const { storage, masterKey } = await rotatedLog(5, 12);

    // Rotation pruned a prefix: only the last 5 sequences survive.
    expect(await entrySequences(storage)).toEqual([8, 9, 10, 11, 12]);
    // And an authenticated rotation anchor was recorded.
    const anchor = await readAnchor(storage);
    expect(anchor.data.base_sequence).toBe(8);

    // STRICT reader: zero findings, log readable.
    const reader = new AuditLog(storage, masterKey);
    const result = await reader.query({ limit: 100 });
    expect(result.integrity_findings).toEqual([]);
    expect(result.total).toBe(5);

    // appendCritical works — ensureLoaded no longer throws AuditIntegrityError.
    const writer = new AuditLog(storage, masterKey, { maxEntries: 5 });
    await expect(appendCritical(writer, "after-rotation")).resolves.toBeUndefined();
    await writer.flush();
    expect((await entrySequences(storage)).at(-1)).toBe(13);
  });

  it("detects deletion of a surviving post-cut entry", async () => {
    const { storage, masterKey } = await rotatedLog(5, 12);
    expect(await entrySequences(storage)).toEqual([8, 9, 10, 11, 12]);

    // Delete a middle survivor — a contiguity break forward of the checkpoint.
    await storage.delete("_audit", await keyForSequence(storage, 10));

    const reader = new AuditLog(storage, masterKey);
    await expect(reader.query({ limit: 100 })).rejects.toMatchObject({
      name: "AuditIntegrityError",
      findings: expect.arrayContaining([
        expect.objectContaining({ kind: "sequence_gap_or_reorder" }),
      ]),
    });
  });

  it("detects head-entry deletion against an intact anchor (base_sequence mismatch)", async () => {
    const { storage, masterKey } = await rotatedLog(5, 12);
    expect((await readAnchor(storage)).data.base_sequence).toBe(8);

    // Delete the anchored head (seq 8) but leave the MAC anchor intact. The
    // authenticated base_sequence (8) no longer matches the lowest survivor (9).
    await storage.delete("_audit", await keyForSequence(storage, 8));

    const reader = new AuditLog(storage, masterKey);
    await expect(reader.query({ limit: 100 })).rejects.toMatchObject({
      name: "AuditIntegrityError",
      findings: expect.arrayContaining([
        expect.objectContaining({ kind: "rotation_anchor_invalid" }),
      ]),
    });
  });

  it("detects a forged rotation anchor (flipped MAC byte)", async () => {
    const { storage, masterKey } = await rotatedLog(5, 12);

    const anchor = await readAnchor(storage);
    // Flip a whole MAC byte deterministically: decode the base64url MAC, XOR
    // the first byte (all 8 bits significant), and re-encode. This guarantees
    // the forged anchor ALWAYS decodes to different MAC bytes than the
    // original. A last-character A<->B swap is NOT deterministic: the MAC is a
    // 32-byte HMAC encoded to 43 base64url chars, and the final char carries
    // only 4 significant bits plus 2 trailing padding bits. 'A' (000000) and
    // 'B' (000001) differ solely in a padding bit, so they decode to identical
    // bytes whenever the original MAC's last char is 'A' (~1/16 of random
    // MACs). In that case the "flip" is a no-op, the MAC still verifies, and
    // the forgery goes undetected — the source of the ~1/16 CI flake.
    const macBytes = fromBase64url(anchor.mac);
    macBytes[0] ^= 0xff;
    anchor.mac = toBase64url(macBytes);
    await writeAnchor(storage, anchor);

    const reader = new AuditLog(storage, masterKey);
    await expect(reader.query({ limit: 100 })).rejects.toMatchObject({
      name: "AuditIntegrityError",
      findings: expect.arrayContaining([
        expect.objectContaining({ kind: "rotation_anchor_invalid" }),
      ]),
    });
  });

  it("detects a forged rotation anchor (changed base_sequence, stale MAC)", async () => {
    const { storage, masterKey } = await rotatedLog(5, 12);

    const anchor = await readAnchor(storage);
    anchor.data.base_sequence = anchor.data.base_sequence - 1; // MAC no longer matches
    await writeAnchor(storage, anchor);

    const reader = new AuditLog(storage, masterKey);
    await expect(reader.query({ limit: 100 })).rejects.toMatchObject({
      name: "AuditIntegrityError",
      findings: expect.arrayContaining([
        expect.objectContaining({ kind: "rotation_anchor_invalid" }),
      ]),
    });
  });

  it("flags an anchor deletion that hides a real truncation", async () => {
    const { storage, masterKey } = await rotatedLog(5, 12);

    // Truncate a non-head survivor AND strip the anchor that would have framed
    // the cut. Absent anchor + non-contiguous chain → finding (not TOFU).
    await storage.delete("_audit", await keyForSequence(storage, 10));
    await storage.delete("_audit_checkpoints", ROTATION_ANCHOR_KEY);

    const reader = new AuditLog(storage, masterKey);
    await expect(reader.query({ limit: 100 })).rejects.toMatchObject({
      name: "AuditIntegrityError",
    });
  });

  it("a rotated log with written checkpoints reloads cleanly (no checkpoint_root_mismatch)", async () => {
    // checkpointInterval 3 forces checkpoints at seq 3,6,9,12; maxEntries 5 then
    // prunes 1..7. Those checkpoints reference pruned sequences — pre-fix this
    // produced a flurry of checkpoint_root_mismatch findings and re-wedged the
    // log. Checkpoints spanning the rotated-out region must be tolerated.
    const { storage, masterKey } = await rotatedLog(5, 12, 3);

    const checkpointKeys = (await storage.list("_audit_checkpoints")).map((m) => m.key);
    // Sanity: checkpoints below the rotation floor really were written.
    expect(checkpointKeys).toContain("audit-checkpoint-00000000000000000003");

    const reader = new AuditLog(storage, masterKey, { checkpointInterval: 3 });
    const result = await reader.query({ limit: 100 });
    expect(result.integrity_findings).toEqual([]);
    expect(result.total).toBe(5);
  });

  it("still detects post-cut tampering on a checkpointed rotated log", async () => {
    const { storage, masterKey } = await rotatedLog(5, 12, 3);
    // Tolerating rotated-out checkpoints must NOT mask a real surviving-entry
    // deletion above the floor.
    await storage.delete("_audit", await keyForSequence(storage, 11));

    const reader = new AuditLog(storage, masterKey, { checkpointInterval: 3 });
    await expect(reader.query({ limit: 100 })).rejects.toMatchObject({
      name: "AuditIntegrityError",
      findings: expect.arrayContaining([
        expect.objectContaining({ kind: "sequence_gap_or_reorder" }),
      ]),
    });
  });

  it("prunes to a single surviving entry under a degenerate cap (no unbounded growth)", async () => {
    // maxEntries: 0 would make rotationDeleteCount want to delete everything.
    // Rotation must still make progress (keep exactly one entry as the anchor
    // base) rather than abort and let the namespace grow without bound.
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const writer = new AuditLog(storage, masterKey, { maxEntries: 0 });
    for (let i = 0; i < 5; i++) {
      await appendCritical(writer, `op-${i}`);
    }
    await writer.flush();

    expect(await entrySequences(storage)).toEqual([5]);
    expect((await readAnchor(storage)).data.base_sequence).toBe(5);

    const reader = new AuditLog(storage, masterKey, { maxEntries: 0 });
    const result = await reader.query({ limit: 100 });
    expect(result.integrity_findings).toEqual([]);
    expect(result.total).toBe(1);
  });

  it("aborts the prune when the rotation anchor write fails (fail-closed)", async () => {
    const storage = new AnchorWriteFailingStorage();
    const masterKey = generateRandomKey();
    const writer = new AuditLog(storage, masterKey, { maxEntries: 5 });
    for (let i = 0; i < 12; i++) {
      await writer.appendCritical({
        layer: "l1",
        operation: `op-${i}`,
        identity_id: "id-1",
        result: "success",
      });
    }
    await writer.flush();

    // Rotation could not authenticate the cut (anchor write fails), so it must
    // NOT prune — entries are retained over the cap rather than left as an
    // unauthenticated post-F3 cut. No anchor was written, and the intact chain
    // [1..12] still reads cleanly from genesis.
    const seqs = await entrySequences(storage);
    expect(seqs).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    expect(await storage.read(CHECKPOINT_NAMESPACE, ROTATION_ANCHOR_KEY)).toBeNull();

    const reader = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
    const result = await reader.query({ limit: 100 });
    expect(result.integrity_findings).toEqual([]);
  });

  it("TOFU-migrates a pre-F3 rotated log, then authenticates subsequent cuts", async () => {
    const { storage, masterKey } = await rotatedLog(5, 12);

    // Simulate a log rotated before F3 existed: no rotation anchor on disk.
    await storage.delete("_audit_checkpoints", ROTATION_ANCHOR_KEY);
    expect(await storage.read("_audit_checkpoints", ROTATION_ANCHOR_KEY)).toBeNull();

    // First load self-heals: contiguous surviving chain accepted, anchor written.
    const reader = new AuditLog(storage, masterKey);
    const result = await reader.query({ limit: 100 });
    expect(result.integrity_findings).toEqual([]);
    const healed = await readAnchor(storage);
    expect(healed.data.base_sequence).toBe(8);

    // Now that it is authenticated, a subsequent post-cut deletion is detected.
    await storage.delete("_audit", await keyForSequence(storage, 11));
    const reader2 = new AuditLog(storage, masterKey);
    await expect(reader2.query({ limit: 100 })).rejects.toMatchObject({
      name: "AuditIntegrityError",
      findings: expect.arrayContaining([
        expect.objectContaining({ kind: "sequence_gap_or_reorder" }),
      ]),
    });
  });
});
