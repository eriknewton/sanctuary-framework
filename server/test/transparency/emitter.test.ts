/**
 * Emitter security properties. Every test here encodes a property that MUST
 * fail without the corresponding fail-closed check:
 *   - no unsigned / partial emission on signer failure
 *   - no emission over a tampered audit chain
 *   - no emission without a Castle Wall policy
 *   - checkpoint-store rollback (deleted checkpoints / deleted floor) refused
 *   - counters and Merkle root bind to the actual log contents
 */
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import {
  AuditIntegrityError,
  AuditLog,
} from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { computeAuditRoot } from "../../src/audit/chain.js";
import {
  bytesToString,
  stringToBytes,
  toBase64url,
} from "../../src/core/encoding.js";
import { randomBytes } from "../../src/core/random.js";
import {
  TRANSPARENCY_CHECKPOINT_NAMESPACE,
  TRANSPARENCY_FLOOR_META_KEY,
  TransparencyEmitError,
  checkpointStorageKey,
  emitEnforcementCheckpoint,
  readPersistedCheckpoints,
  type TransparencySigner,
} from "../../src/transparency/emitter.js";
import {
  checkpointPayloadOf,
  computeCheckpointHash,
  transparencyRuleLabel,
  verifyEnforcementCheckpointSignature,
} from "../../src/transparency/checkpoint.js";

const MASTER_KEY = () => randomBytes(32);

function testSigner(privateKey = randomBytes(32)): TransparencySigner {
  const publicKey = ed25519.getPublicKey(privateKey);
  return {
    signer_kid: `castle-wall:${toBase64url(publicKey)}`,
    publicKey,
    sign: async (bytes) => ed25519.sign(bytes, privateKey),
  };
}

let fortressPath: string;
let binaryPath: string;

beforeEach(async () => {
  fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-transparency-"));
  const rulesDir = join(fortressPath, "policy", "egress", "rules");
  await mkdir(rulesDir, { recursive: true });
  await writeFile(
    join(rulesDir, "allow-github.json"),
    JSON.stringify({ rule_id: "allow-github", host: "github.com" })
  );
  await writeFile(
    join(rulesDir, "allow-api.json"),
    JSON.stringify({ rule_id: "allow-api", host: "api.example.com" })
  );
  binaryPath = join(fortressPath, "fake-binary.js");
  await writeFile(binaryPath, "console.log('sanctuary');");
});

afterEach(async () => {
  await rm(fortressPath, { recursive: true, force: true });
});

interface Env {
  storage: MemoryStorage;
  auditLog: AuditLog;
  masterKey: Uint8Array;
}

function makeEnv(): Env {
  const storage = new MemoryStorage();
  const masterKey = MASTER_KEY();
  const auditLog = new AuditLog(storage, masterKey);
  return { storage, auditLog, masterKey };
}

async function seedAuditEvents(auditLog: AuditLog): Promise<void> {
  await auditLog.appendCritical({
    layer: "l1",
    operation: "egress_blocked",
    identity_id: "fortress-test",
    result: "success",
    details: { rule_id: "deny-default", destination: { host: "evil.example" } },
  });
  await auditLog.appendCritical({
    layer: "l1",
    operation: "egress_allowed",
    identity_id: "fortress-test",
    result: "success",
    details: { rule_id: "allow-github" },
  });
  await auditLog.appendCritical({
    layer: "l1",
    operation: "egress_allowed",
    identity_id: "fortress-test",
    result: "success",
    details: { rule_id: "allow-github" },
  });
  await auditLog.appendCritical({
    layer: "l2",
    operation: "state_write",
    identity_id: "fortress-test",
    result: "success",
  });
}

function emitInput(env: Env, signer: TransparencySigner) {
  return {
    storage: env.storage,
    auditLog: env.auditLog,
    fortressId: "fortress-test",
    fortressPath,
    masterKey: env.masterKey,
    signer,
    binaryPath,
    version: "0.0.0-test",
  };
}

async function storedEnvelopeHashes(storage: MemoryStorage): Promise<string[]> {
  const metas = await storage.list("_audit", "entry-");
  metas.sort((a, b) => a.key.localeCompare(b.key));
  const hashes: string[] = [];
  for (const meta of metas) {
    const raw = await storage.read("_audit", meta.key);
    const parsed = JSON.parse(bytesToString(raw!)) as { entry_hash: string };
    hashes.push(parsed.entry_hash);
  }
  return hashes;
}

describe("transparency emitter", () => {
  it("emits a signed checkpoint whose root and counters bind the actual log", async () => {
    const env = makeEnv();
    await seedAuditEvents(env.auditLog);
    const signer = testSigner();

    const record = await emitEnforcementCheckpoint(emitInput(env, signer));

    expect(record.counter).toBe(1);
    expect(record.previous_checkpoint_hash).toBe("GENESIS");
    expect(record.audit.entry_count).toBe(4);
    expect(record.audit.lowest_sequence).toBe(1);
    expect(record.audit.highest_sequence).toBe(4);
    expect(record.audit.merkle_root).toBe(
      computeAuditRoot(await storedEnvelopeHashes(env.storage))
    );
    expect(record.policy.rules_count).toBe(2);
    expect(record.daemon.version).toBe("0.0.0-test");
    expect(record.enforcement.total_allowed).toBe(2);
    expect(record.enforcement.total_blocked).toBe(1);
    // Per-rule counters use OPAQUE labels; the rule id never appears.
    const githubLabel = transparencyRuleLabel("fortress-test", "allow-github");
    const githubBucket = record.enforcement.rules.find(
      (rule) => rule.rule_label === githubLabel
    );
    expect(githubBucket).toEqual({
      rule_label: githubLabel,
      allowed: 2,
      blocked: 0,
    });
    expect(JSON.stringify(record)).not.toContain("allow-github");
    expect(JSON.stringify(record)).not.toContain("github.com");
    // Signature verifies; record persisted.
    expect(verifyEnforcementCheckpointSignature(record, signer.publicKey)).toBe(
      true
    );
    const persisted = await readPersistedCheckpoints(env.storage);
    expect(persisted).toHaveLength(1);
    expect(persisted[0]).toEqual(record);
  });

  it("chains counters monotonically with previous-checkpoint hash linkage", async () => {
    const env = makeEnv();
    await seedAuditEvents(env.auditLog);
    const signer = testSigner();
    const first = await emitEnforcementCheckpoint(emitInput(env, signer));
    await env.auditLog.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "fortress-test",
      result: "success",
      details: { rule_id: "deny-default" },
    });
    const second = await emitEnforcementCheckpoint(emitInput(env, signer));
    expect(second.counter).toBe(2);
    expect(second.previous_checkpoint_hash).toBe(
      computeCheckpointHash(checkpointPayloadOf(first))
    );
    expect(second.audit.highest_sequence).toBeGreaterThan(
      first.audit.highest_sequence
    );
  });

  it("REFUSES to emit over a tampered audit chain (nothing persisted)", async () => {
    const env = makeEnv();
    await seedAuditEvents(env.auditLog);
    // Tamper: flip the persisted entry_hash of one envelope.
    const metas = await env.storage.list("_audit", "entry-");
    const raw = await env.storage.read("_audit", metas[1]!.key);
    const parsed = JSON.parse(bytesToString(raw!)) as Record<string, unknown>;
    parsed.entry_hash = "0".repeat(64);
    await env.storage.write(
      "_audit",
      metas[1]!.key,
      stringToBytes(JSON.stringify(parsed))
    );

    await expect(
      emitEnforcementCheckpoint(emitInput(env, testSigner()))
    ).rejects.toThrow(AuditIntegrityError);
    expect(
      await env.storage.list(TRANSPARENCY_CHECKPOINT_NAMESPACE)
    ).toHaveLength(0);
  });

  it("REFUSES when the signer fails: no unsigned or partial checkpoint exists", async () => {
    const env = makeEnv();
    await seedAuditEvents(env.auditLog);
    const failingSigner: TransparencySigner = {
      signer_kid: "castle-wall:unreachable",
      publicKey: ed25519.getPublicKey(randomBytes(32)),
      sign: async () => {
        throw new Error("helper unreachable");
      },
    };
    await expect(
      emitEnforcementCheckpoint(emitInput(env, failingSigner))
    ).rejects.toThrow(TransparencyEmitError);
    expect(
      await env.storage.list(TRANSPARENCY_CHECKPOINT_NAMESPACE)
    ).toHaveLength(0);
    expect(await env.storage.read("_meta", TRANSPARENCY_FLOOR_META_KEY)).toBeNull();
  });

  it("REFUSES when the signer returns a signature that does not verify", async () => {
    const env = makeEnv();
    await seedAuditEvents(env.auditLog);
    const garbageSigner: TransparencySigner = {
      signer_kid: "castle-wall:garbage",
      publicKey: ed25519.getPublicKey(randomBytes(32)),
      sign: async () => randomBytes(64),
    };
    await expect(
      emitEnforcementCheckpoint(emitInput(env, garbageSigner))
    ).rejects.toThrow(/does not verify/);
    expect(
      await env.storage.list(TRANSPARENCY_CHECKPOINT_NAMESPACE)
    ).toHaveLength(0);
  });

  it("REFUSES without a Castle Wall policy on disk", async () => {
    const env = makeEnv();
    await seedAuditEvents(env.auditLog);
    await rm(join(fortressPath, "policy"), { recursive: true, force: true });
    await expect(
      emitEnforcementCheckpoint(emitInput(env, testSigner()))
    ).rejects.toThrow(/no Castle Wall policy found/);
  });

  it("REFUSES when the emitting binary cannot be hashed", async () => {
    const env = makeEnv();
    await seedAuditEvents(env.auditLog);
    await rm(binaryPath, { force: true });
    await expect(
      emitEnforcementCheckpoint(emitInput(env, testSigner()))
    ).rejects.toThrow(/emitting binary could not be hashed/);
  });

  it("detects checkpoint-store rollback: deleting the latest checkpoint refuses the next emission", async () => {
    const env = makeEnv();
    await seedAuditEvents(env.auditLog);
    const signer = testSigner();
    await emitEnforcementCheckpoint(emitInput(env, signer));
    await emitEnforcementCheckpoint(emitInput(env, signer));
    // Adversary deletes the newest checkpoint to rewind the chain.
    await env.storage.delete(
      TRANSPARENCY_CHECKPOINT_NAMESPACE,
      checkpointStorageKey(2)
    );
    await expect(
      emitEnforcementCheckpoint(emitInput(env, signer))
    ).rejects.toThrow(/rollback detected/);
  });

  it("detects floor deletion: an established store without its MAC'd floor refuses", async () => {
    const env = makeEnv();
    await seedAuditEvents(env.auditLog);
    const signer = testSigner();
    await emitEnforcementCheckpoint(emitInput(env, signer));
    await env.storage.delete("_meta", TRANSPARENCY_FLOOR_META_KEY);
    await expect(
      emitEnforcementCheckpoint(emitInput(env, signer))
    ).rejects.toThrow(/counter floor is missing/);
  });

  it("detects a forged floor: a MAC mismatch refuses", async () => {
    const env = makeEnv();
    await seedAuditEvents(env.auditLog);
    const signer = testSigner();
    await emitEnforcementCheckpoint(emitInput(env, signer));
    const raw = await env.storage.read("_meta", TRANSPARENCY_FLOOR_META_KEY);
    const parsed = JSON.parse(bytesToString(raw!)) as {
      data: { highest_counter: number };
      mac: string;
    };
    parsed.data.highest_counter = 999; // forged without the MAC key
    await env.storage.write(
      "_meta",
      TRANSPARENCY_FLOOR_META_KEY,
      stringToBytes(JSON.stringify(parsed))
    );
    await expect(
      emitEnforcementCheckpoint(emitInput(env, signer))
    ).rejects.toThrow(/floor failed authentication/);
  });

  it("REFUSES when a persisted checkpoint is malformed (no fork past corruption)", async () => {
    const env = makeEnv();
    await seedAuditEvents(env.auditLog);
    const signer = testSigner();
    await emitEnforcementCheckpoint(emitInput(env, signer));
    await env.storage.write(
      TRANSPARENCY_CHECKPOINT_NAMESPACE,
      checkpointStorageKey(1),
      stringToBytes("{not json")
    );
    await expect(
      emitEnforcementCheckpoint(emitInput(env, signer))
    ).rejects.toThrow(/not valid JSON/);
  });

  it("emits over an empty (but policy-bearing) fortress with an empty-window root", async () => {
    const env = makeEnv();
    const record = await emitEnforcementCheckpoint(emitInput(env, testSigner()));
    expect(record.audit.entry_count).toBe(0);
    expect(record.audit.lowest_sequence).toBe(0);
    expect(record.audit.highest_sequence).toBe(0);
    expect(record.audit.merkle_root).toBe(computeAuditRoot([]));
    expect(record.enforcement.total_allowed).toBe(0);
    expect(record.enforcement.total_blocked).toBe(0);
  });
});
