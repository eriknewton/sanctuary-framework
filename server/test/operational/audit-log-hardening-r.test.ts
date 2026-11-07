// fail-before-exempt: comment-only change that states the derivation of a key-width literal; no assertion changes, so it passes against pre-fix source by construction.
/** Audit log operational witnesses, set R. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { ed25519 } from "@noble/curves/ed25519";
import { AuditLog, type AuditLogConfig } from "../../src/operational/audit-log.js";
import { checkpointSigningBytes, computeAuditRoot, type AuditCheckpointRecord } from "../../src/audit/chain.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageBackend } from "../../src/storage/interface.js";

import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { exportAuditChain } from "../../src/cli/audit-chain-export.js";
import { verifyAuditChainRecords } from "../../src/cli/audit-chain-verify.js";
import { runAuditDump } from "../../src/cli/castle-wall.js";
import { runDoctorChecks } from "../../src/cli/doctor.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { initializeTestCustody } from "../helpers/custody-fixture.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { exportExitBundle, verifyExitBundle } from "../../src/exit/index.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";

const CAP = 2; // Fixture capacity (maxEntries).
const INTERVAL = 100; // Production checkpoint cadence.
const MAX_AGE_MS = 10 * 60_000; // Ten minutes, independently asserting the age contract.
const signingKey = ed25519.utils.randomPrivateKey();
const publicKey = Buffer.from(ed25519.getPublicKey(signingKey)).toString("base64url");
const masterKey = ed25519.utils.randomPrivateKey();
const encode = (value: unknown) => Buffer.from(JSON.stringify(value));
const decode = (value: Uint8Array) => JSON.parse(Buffer.from(value).toString());
const signedConfig: AuditLogConfig = {
  maxEntries: CAP, checkpointInterval: INTERVAL,
  checkpointSigner: async (payload) => ({ signer_kid: "fixture-r", public_key: publicKey,
    signature: Buffer.from(ed25519.sign(checkpointSigningBytes(payload), signingKey)).toString("base64url") }),
  checkpointPublicKeyResolver: () => publicKey,
};
let testHome: string;
beforeEach(async () => {
  testHome = await mkdtemp(join(tmpdir(), "audit-hardening-r-"));
  vi.stubEnv("HOME", testHome);
});
afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  await rm(testHome, { recursive: true, force: true });
});
async function append(log: AuditLog) {
  await log.appendCritical({ layer: "l1", operation: "egress_allowed", identity_id: "fixture",
    result: "success", details: {} });
}
async function checkpoints(storage: StorageBackend): Promise<AuditCheckpointRecord[]> {
  const records = await storage.list("_audit_checkpoints", "audit-checkpoint-");
  return Promise.all(records.map(async ({ key }) => decode((await storage.read("_audit_checkpoints", key))!)));
}
async function seeded(storage: StorageBackend = new MemoryStorage(), key = masterKey, config = signedConfig) {
  let now = 0;
  const log = new AuditLog(storage, key, { ...config, __testMonotonicNow: () => now });
  await append(log);
  await log.flushDurable();
  await append(log);
  await append(log);
  return { log, storage, advance: () => { now += MAX_AGE_MS; } };
}

function capture() {
  let text = "";
  const stream = new Writable({ write(chunk, _encoding, done) { text += String(chunk); done(); } });
  return { stream, text: () => text };
}

describe("audit log witnesses R", () => {
  it("R1", async () => {
    const { log, storage, advance } = await seeded();
    const entries = await storage.list("_audit");
    expect(entries).toHaveLength(1);
    const first = decode((await storage.read("_audit", entries[0]!.key))!);
    expect(first.sequence).toBe(3);
    advance();
    await log.flushDurable();
    expect((await checkpoints(storage)).map(record => record.checkpoint_sequence)).toEqual([1, 3]);
    expect((await checkpoints(storage)).at(-1)).toMatchObject({
      from_sequence: 3, checkpoint_sequence: 3, previous_checkpoint_sequence: 1,
      root_hash: computeAuditRoot([first.entry_hash]), unsigned: false,
    });
    await append(log);
    advance();
    await log.flushDurable();
    expect((await checkpoints(storage)).at(-1)).toMatchObject({ from_sequence: 4, checkpoint_sequence: 4 });
  });


  for (const [label, fault] of [["a", "f1"], ["b", "f2"], ["c", "f3"], ["d", "f4"]] as const) {
    it(`R2${label}`, async () => {
      const { log, storage, advance } = await seeded();
      const recordKey = "__rotation_anchor";
      const namespace = "_audit_checkpoints";
      const original = (await storage.read(namespace, recordKey))!;
      if (fault === "f1") await storage.delete(namespace, recordKey);
      if (fault === "f2") {
        const record = decode(original);
        record.mac = (record.mac[0] === "A" ? "B" : "A") + record.mac.slice(1);
        await storage.write(namespace, recordKey, encode(record));
      }
      if (fault === "f4") await storage.write(namespace, recordKey, encode({ data: { base_sequence: 3 } }));
      const read = storage.read.bind(storage);
      const reads = vi.spyOn(storage, "read");
      if (fault === "f3") reads.mockImplementation(async (ns, key) => {
        if (ns === namespace && key === recordKey) throw new Error("fixture read failure");
        return read(ns, key);
      });
      const writes = vi.spyOn(storage, "write");
      const diagnostic = vi.spyOn(console, "error").mockImplementation(() => {});
      advance();
      await log.flushDurable();
      await log.flushDurable();
      expect((await checkpoints(storage)).map(record => record.checkpoint_sequence)).toEqual([1]);
      expect(writes).not.toHaveBeenCalled();
      expect(diagnostic).toHaveBeenCalledTimes(1);
      expect(diagnostic).toHaveBeenCalledWith(expect.stringContaining("incomplete (gap at sequence 2)"));
      reads.mockRestore();
      await storage.write(namespace, recordKey, original);
      await log.flushDurable();
      expect((await checkpoints(storage)).at(-1)).toMatchObject({ from_sequence: 3, checkpoint_sequence: 3 });
    });
  }

  it("R3", async () => {
    const { log, storage, advance } = await seeded();
    await append(log);
    const retained = await storage.list("_audit");
    // Persisted audit-entry names encode their sequence in twenty decimal digits.
    const base = retained.find(({ key }) => key.startsWith(`entry-${String(3).padStart(20, "0")}-`))!; // Twenty decimal places preserve persisted sequence ordering; must match persistChainedEntry / parseEntryKeySequence in server/src/operational/audit-log.ts.
    await storage.delete("_audit", base.key);
    const writes = vi.spyOn(storage, "write");
    vi.spyOn(console, "error").mockImplementation(() => {});
    advance();
    await log.flushDurable();
    expect((await checkpoints(storage)).map(record => record.checkpoint_sequence)).toEqual([1]);
    expect(writes).not.toHaveBeenCalled();
  });

  it("R4", async () => {
    const interval = 3; // 3 = the two seeded appends plus one.
    const { log, storage } = await seeded(new MemoryStorage(), masterKey,
      { ...signedConfig, checkpointInterval: interval });
    await append(log);
    expect((await checkpoints(storage)).at(-1)).toMatchObject({
      from_sequence: 3, checkpoint_sequence: 4, previous_checkpoint_sequence: 1,
    });
  });

  it("R5", async () => {
    const passphrase = "fixture-r-passphrase";
    await initializeTestCustody(testHome, { passphrase });
    const storage = new FilesystemStorage(join(testHome, "state"));
    const established = await establishMaster({ storage, passphrase });
    try {
      // Production identity wiring lets fresh runtime readers resolve the signer.
      const identities = new IdentityManager(storage, established.masterKey);
      const { storedIdentity } = createIdentity("fixture-r-reader", derivePurposeKey(established.masterKey, "identity-encryption"), "passphrase");
      await identities.save(storedIdentity);
      const { log, advance } = await seeded(storage, established.masterKey,
        { maxEntries: CAP, checkpointInterval: INTERVAL });
      advance();
      await log.flushDurable();
      expect((await checkpoints(storage)).at(-1)).toMatchObject({ from_sequence: 3, checkpoint_sequence: 3 });
      const reader = new AuditLog(storage, established.masterKey);
      expect((await reader.query({ limit: INTERVAL })).integrity_findings).toEqual([]);
      expect((await reader.getAuditChainVerdict()).status).toBe("verified");
      const exported = capture();
      const summary = await exportAuditChain(storage, exported.stream);
      expect(summary.entriesSkipped + summary.checkpointsSkipped).toBe(0);
      const report = verifyAuditChainRecords(exported.text().trim().split("\n").map(line => JSON.parse(line)),
        { publicKey: storedIdentity.public_key });
      expect(report.findings).toEqual([]);
      expect(report.verdict).toBe("PASS");
      expect(report.signatures_verified).toBe(2); // Initial seal and the later seal.
      const env = { HOME: testHome, SANCTUARY_STORAGE_PATH: testHome, SANCTUARY_PASSPHRASE: passphrase };
      const checks = await runDoctorChecks({ storagePath: testHome, env, platform: "linux" });
      expect(checks.find(check => check.name === "audit chain")).toMatchObject({
        status: "WARN", message: "checkpoint signatures were not verified against a pinned public key",
      });
      const out = capture();
      const err = capture();
      expect(await runAuditDump(["--fortress", testHome], { out: out.stream, err: err.stream, env })).toBe(0);
      expect(out.text().trim().split("\n").map(line => JSON.parse(line))).toHaveLength(1);
      expect(err.text()).toBe("");
    } finally {
      established.masterKey.fill(0);
      await established.masterWriteBarrier?.release();
    }
  });

  it("R6", async () => {
    const storage = new MemoryStorage();
    const identities = new IdentityManager(storage, masterKey);
    const { storedIdentity } = createIdentity("fixture-r-exit", derivePurposeKey(masterKey, "identity-encryption"), "recovery-key");
    await identities.save(storedIdentity);
    const { log, advance } = await seeded(storage);
    advance();
    await log.flushDurable();
    expect((await checkpoints(storage)).at(-1)).toMatchObject({ from_sequence: 3, checkpoint_sequence: 3 });
    const bundleDir = join(testHome, "exit-bundle");
    await exportExitBundle({ bundleDir, storage, masterKey, identityManager: identities, auditLog: log,
      policy: DEFAULT_POLICY, keySource: "recovery-key", unpartitionedLegacyExport: true });
    const report = await verifyExitBundle(bundleDir);
    expect(report.passed).toBe(true);
    expect(report.audit).toMatchObject({ receipt_count: 2, individual_signatures_verified: false });
    const receipts = JSON.parse(await readFile(join(bundleDir, "artifacts", "audit_receipts.json"), "utf8"));
    expect(receipts).toMatchObject({ recovery_semantics: "archive_only", normal_audit_query_continuity: false });
    expect(receipts.entries.map((entry: { operation: string }) => entry.operation)).toContain("egress_allowed");
  });
});
