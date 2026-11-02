// fail-before-exempt: A1b keeps fault-free entry bytes, sequence linkage, anchors and markers identical to the pinned A1a capture; only transient lock records may change.
import { readdir, readFile, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import * as random from "../../src/core/random.js";
vi.mock("../../src/core/random.js", async original => ({ ...await original<typeof import("../../src/core/random.js")>() }));
let root: string;
afterEach(async () => { vi.restoreAllMocks(); vi.useRealTimers(); vi.unstubAllEnvs(); if (root) await rm(root, { recursive: true, force: true }); });
it("preserves captured A1a fault-free bytes and sequence linkage outside transient lock records", async () => {
  root = await mkdtemp(join(tmpdir(), "audit-parity-")); vi.stubEnv("HOME", root);
  vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(new Date("2026-11-01T12:00:00.000Z"));
  let nonce = 0;
  // Isolated test key and unique deterministic IVs make ciphertext comparison meaningful.
  vi.spyOn(random, "generateIV").mockImplementation(() => { const iv = Buffer.alloc(12); iv.writeUInt32BE(++nonce, 8); return iv; });
  const storage = new FilesystemStorage(join(root, "state"));
  const log = new AuditLog(storage, Buffer.alloc(32, 7), { integrityMode: "lenient", checkpointInterval: 2 });
  for (let n = 0; n < 3; n++) await log.appendCritical({ layer: "l1", operation: "parity", identity_id: "fixture", result: "success", details: { n } });
  const records: Record<string, string> = {};
  for (const namespace of ["_audit", "_audit_checkpoints", "_meta"]) {
    for (const name of (await readdir(join(root, "state", namespace))).sort()) {
      if (name.startsWith(".audit-write.lock")) continue;
      // The per-instance random filename suffix is entropy; compare every persisted byte under its sequence key.
      const comparisonName = name.replace(/-[a-f0-9]{12}\.enc$/, "-<nonce>.enc");
      records[`${namespace}/${comparisonName}`] = (await readFile(join(root, "state", namespace, name))).toString("base64");
    }
  }
  // The capture command runs only in a detached pinned-base worktree.
  if (process.env.AUDIT_PARITY_CAPTURE) await writeFile(process.env.AUDIT_PARITY_CAPTURE, JSON.stringify({ provenance: "captured base 876a94a0487c8c290f7c88ba8707996b6c5c3c13 2026-11-02", command: "npx vitest run test/operational/audit-log-lock-payload-parity.test.ts", env: { Date: "2026-11-01T12:00:00.000Z", IV: "deterministic isolated test only" }, bytes_base64: Buffer.from(JSON.stringify(records)).toString("base64") }, null, 2) + "\n");
  const captured = JSON.parse(await readFile(new URL("../fixtures/audit-lock/fault-free-a1a.json", import.meta.url), "utf8"));
  expect(records).toEqual(JSON.parse(Buffer.from(captured.bytes_base64, "base64").toString()));
  const envelopes = Object.entries(records).filter(([name]) => name.startsWith("_audit/entry-")).map(([, bytes]) => JSON.parse(Buffer.from(bytes, "base64").toString()));
  expect(envelopes.map(e => e.sequence)).toEqual([1, 2, 3]);
  expect(envelopes[1].prev_hash).toBe(envelopes[0].entry_hash);
  expect(envelopes[2].prev_hash).toBe(envelopes[1].entry_hash);
});
