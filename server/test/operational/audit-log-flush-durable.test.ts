/** Durable audit barriers amortize checkpoints while preserving complete reader views. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { spawnSync } from "node:child_process";
import { ed25519 } from "@noble/curves/ed25519";
import { AuditLog, AuditLogPersistenceError, type AuditLogConfig, type AuditEntryInput } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { checkpointSigningBytes, type AuditCheckpointRecord } from "../../src/audit/chain.js";
import { exportAuditChain } from "../../src/cli/audit-chain-export.js";
import { verifyAuditChainRecords } from "../../src/cli/audit-chain-verify.js";
import { runAuditDump } from "../../src/cli/castle-wall.js";
import { buildAuditDigest } from "../../src/principal-policy/posture.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { initializeTestCustody } from "../helpers/custody-fixture.js";

const INTERVAL = 100; // Production checkpoint cadence.
const MAX_AGE_MS = 10 * 60_000; // Ten minutes, independent of the implementation constant.
const signingKey = ed25519.utils.randomPrivateKey();
const publicKey = Buffer.from(ed25519.getPublicKey(signingKey)).toString("base64url");
const masterKey = ed25519.utils.randomPrivateKey();
const signedConfig: AuditLogConfig = {
  integrityMode: "strict", checkpointInterval: INTERVAL,
  checkpointSigner: async (payload) => ({ signer_kid: "fixture", public_key: publicKey,
    signature: Buffer.from(ed25519.sign(checkpointSigningBytes(payload), signingKey)).toString("base64url") }),
  checkpointPublicKeyResolver: () => publicKey,
};
let home: string;
beforeEach(async () => { home = await mkdtemp(join(tmpdir(), "audit-durable-")); vi.stubEnv("HOME", home); });
afterEach(async () => { vi.restoreAllMocks(); vi.unstubAllEnvs(); await rm(home, { recursive: true, force: true }); });
function fixture(config: AuditLogConfig = {}) {
  const storage = new MemoryStorage();
  return { storage, log: new AuditLog(storage, masterKey, { ...signedConfig, ...config }) };
}
async function durable(log: AuditLog) {
  // Base-tree failures are assertions, never missing-method or collection errors.
  expect(typeof log.flushDurable).toBe("function");
  await log.flushDurable();
}
async function append(log: AuditLog, operation = "egress_allowed") {
  await log.append("l1", operation, "fixture", {}, "success");
}
async function checkpoints(storage: StorageBackend): Promise<AuditCheckpointRecord[]> {
  const keys = await storage.list("_audit_checkpoints", "audit-checkpoint-");
  return Promise.all(keys.map(async ({ key }) => JSON.parse(Buffer.from((await storage.read("_audit_checkpoints", key))!).toString())));
}
function capture() {
  let text = "";
  const stream = new Writable({ write(chunk, _encoding, done) { text += String(chunk); done(); } });
  return { stream, text: () => text };
}
async function verify(storage: StorageBackend) {
  const out = capture();
  const exported = await exportAuditChain(storage, out.stream);
  const report = verifyAuditChainRecords(out.text().trim().split("\n").map(line => JSON.parse(line)), { publicKey, strict: true });
  expect(report.findings).toEqual([]);
  expect(report.verdict).toBe("PASS");
  return { exported, report };
}

describe("flushDurable", () => {
  it("T1 performs zero audit reads when not due at 50 and 600 entries", async () => {
    const { storage, log } = fixture({ __testMonotonicNow: () => 0 });
    const reads = vi.spyOn(storage, "read");
    const counts: number[] = [];
    const populations = [50, 600]; // Brief's short-chain and long-chain cost witnesses.
    for (let sequence = 1; sequence <= populations.at(-1)!; sequence++) {
      await append(log);
      reads.mockClear();
      await durable(log);
      if (populations.includes(sequence)) {
        const count = reads.mock.calls.filter(([ns]) => ns === "_audit" || ns === "_audit_checkpoints").length;
        expect(count).toBe(0);
        counts.push(count);
      }
    }
    expect(counts).toEqual([0, 0]);
  });

  it("T2 checkpoints exactly at the interval-th ordinary append after a seal", async () => {
    const { storage, log } = fixture();
    await append(log); await durable(log);
    for (let index = 1; index < INTERVAL; index++) { await append(log); await durable(log); }
    expect(await checkpoints(storage)).toHaveLength(1);
    await append(log); await durable(log);
    expect((await checkpoints(storage)).map(cp => cp.checkpoint_sequence)).toEqual([1, INTERVAL + 1]);
  });

  it("T2 seals a small tail at max age even with interval checkpoints disabled", async () => {
    let now = 0;
    const { storage, log } = fixture({ checkpointInterval: 0, __testMonotonicNow: () => now });
    await append(log); await durable(log);
    await append(log);
    now = MAX_AGE_MS - 1;
    await durable(log);
    expect(await checkpoints(storage)).toHaveLength(1);
    now = MAX_AGE_MS;
    await durable(log);
    expect((await checkpoints(storage)).map(cp => cp.checkpoint_sequence)).toEqual([1, 2]);
    await append(log); await durable(log);
    expect(await checkpoints(storage)).toHaveLength(2);
  });

  it("T2b first seal supports pinned-key verification without sealing each append", async () => {
    const { storage, log } = fixture();
    await append(log); await durable(log);
    expect(await checkpoints(storage)).toHaveLength(1);
    await append(log); await durable(log);
    expect((await checkpoints(storage)).map(cp => cp.checkpoint_sequence)).toEqual([1]);
    await verify(storage);
  });

  it("T3 graceful flush still seals every nonempty tail", async () => {
    const { storage, log } = fixture();
    await append(log); await durable(log);
    await append(log); await durable(log);
    expect(await checkpoints(storage)).toHaveLength(1);
    await log.flush();
    expect((await checkpoints(storage)).map(cp => cp.checkpoint_sequence)).toEqual([1, 2]);
    await append(log); await log.flush();
    expect((await checkpoints(storage)).map(cp => cp.checkpoint_sequence)).toEqual([1, 2, 3]);
  });

  it("T4 strict reload, digest, keyed verify and audit-dump retain a 37-entry uncovered tail", async () => {
    const passphrase = "durable-fixture-passphrase";
    await initializeTestCustody(home, { passphrase });
    const storage = new FilesystemStorage(join(home, "state"));
    const established = await establishMaster({ storage, passphrase });
    const log = new AuditLog(storage, established.masterKey, signedConfig);
    try {
      await append(log); await durable(log);
      const tailLength = 37; // Brief's deliberately non-interval suffix.
      for (let index = 0; index < tailLength; index++) { await append(log); await durable(log); }
      expect((await checkpoints(storage)).map(cp => cp.checkpoint_sequence)).toEqual([1]);
      const reader = new AuditLog(storage, established.masterKey, signedConfig);
      const result = await reader.query({ limit: tailLength + 1 });
      expect(result.integrity_findings).toEqual([]);
      expect(result.entries).toHaveLength(tailLength + 1);
      expect((await reader.getAuditChainVerdict()).status).toBe("verified");
      const digest = await buildAuditDigest({ auditLog: reader, originMachine: "fixture", protectionClaimSubject: null });
      expect(digest.chain_verified).toBe(true);
      await verify(storage);
      const out = capture(); const err = capture();
      expect(await runAuditDump(["--fortress", home], { out: out.stream, err: err.stream,
        env: { HOME: home, SANCTUARY_STORAGE_PATH: home, SANCTUARY_PASSPHRASE: passphrase } })).toBe(0);
      expect(out.text().trim().split("\n").map(line => JSON.parse(line))).toHaveLength(tailLength + 1);
      expect((await checkpoints(storage)).map(cp => cp.checkpoint_sequence)).toEqual([1]);
    } finally { established.masterKey.fill(0); await established.masterWriteBarrier?.release(); }
  });

  it("T6 another process seals both writers and strict verification stays clean", async () => {
    const storage = new FilesystemStorage(join(home, "state"));
    const interval = 4; // One parent tail entry and three child tail entries.
    const log = new AuditLog(storage, masterKey, { ...signedConfig, checkpointInterval: interval });
    await append(log, "parent-seed"); await durable(log);
    await append(log, "parent-tail"); await durable(log);
    const child = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", `
      import { AuditLog } from './src/operational/audit-log.ts';
      import { FilesystemStorage } from './src/storage/filesystem.ts';
      import { checkpointSigningBytes } from './src/audit/chain.ts';
      import { ed25519 } from '@noble/curves/ed25519';
      const key = Buffer.from(process.env.FIXTURE_SIGN_KEY, 'hex');
      const publicKey = Buffer.from(ed25519.getPublicKey(key)).toString('base64url');
      const log = new AuditLog(new FilesystemStorage(process.env.FIXTURE_STATE), Buffer.from(process.env.FIXTURE_MASTER_KEY, 'hex'), {
        checkpointInterval: 4, integrityMode: 'strict', checkpointPublicKeyResolver: () => publicKey,
        checkpointSigner: async payload => ({ signer_kid: 'fixture', public_key: publicKey,
          signature: Buffer.from(ed25519.sign(checkpointSigningBytes(payload), key)).toString('base64url') }),
      });
      for (let i = 0; i < 3; i++) { await log.append('l1', 'child', 'fixture'); await log.flushDurable(); }
    `], { cwd: process.cwd(), encoding: "utf8", timeout: 30_000, // Same bound as Vitest's per-test timeout.
      env: { ...process.env, HOME: home, FIXTURE_STATE: join(home, "state"),
        FIXTURE_SIGN_KEY: Buffer.from(signingKey).toString("hex"), FIXTURE_MASTER_KEY: Buffer.from(masterKey).toString("hex") } });
    expect(child.error).toBeUndefined();
    expect(child.status, child.stderr).toBe(0);
    expect((await checkpoints(storage)).map(cp => [cp.from_sequence, cp.checkpoint_sequence])).toEqual([[1, 1], [2, interval + 1]]);
    const reader = new AuditLog(storage, masterKey, signedConfig);
    expect((await reader.query({ limit: interval + 1 })).integrity_findings).toEqual([]);
    await verify(storage);
  });

  it("drains queue-only work before the durable barrier resolves", async () => {
    const { storage, log } = fixture();
    await append(log); await durable(log);
    let release!: () => void;
    let started!: () => void;
    const entered = new Promise<void>(resolve => { started = resolve; });
    const gate = new Promise<void>(resolve => { release = resolve; });
    const write = storage.write.bind(storage);
    vi.spyOn(storage, "write").mockImplementation(async (...args) => {
      if (args[0] === "_audit") { started(); await gate; }
      return write(...args);
    });
    // Exercise the queue independently of the pending-write tracker, as required by both barriers.
    const queue = log as unknown as { enqueueAppend(entry: AuditEntryInput, options: { verifyDurability: boolean; critical: boolean }): Promise<void> };
    const writing = queue.enqueueAppend({ layer: "l1", operation: "queued", identity_id: "fixture", result: "success" }, { verifyDurability: false, critical: false });
    await entered;
    let resolved = false;
    const flushing = log.flushDurable().then(() => { resolved = true; });
    try {
      await new Promise<void>(resolve => setImmediate(resolve));
      expect(resolved).toBe(false);
    } finally { release(); await writing; await flushing; }
    expect((await storage.list("_audit"))).toHaveLength(2);
  });

  it("aggregates pending persistence failures at the durable barrier", async () => {
    const { storage, log } = fixture();
    await append(log); await durable(log);
    vi.spyOn(storage, "write").mockRejectedValue(new Error("fixture persistence failure"));
    const writing = log.append("l1", "fails", "fixture");
    const result = Promise.allSettled([writing]);
    await expect(log.flushDurable()).rejects.toBeInstanceOf(AuditLogPersistenceError);
    await result;
  });
});
