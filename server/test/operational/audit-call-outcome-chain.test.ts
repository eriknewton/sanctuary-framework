/**
 * Call references and success markers ride the existing chain unchanged: a
 * row written outside any call serializes and hashes exactly as before, and a
 * log mixing such rows, in-call rows and real markers verifies through
 * checkpoint, rotation, chain export, the audit store split and reopen with
 * agent visibility preserved.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import {
  AuditLog,
  __testSetAuditWriterUidForRole,
  CALL_OUTCOME_SUCCESS_OPERATION,
  runInCallScope,
  settleCallOutcome,
  writeCallOutcomeMarkers,
  type AuditEntryInput,
} from "../../src/operational/audit-log.js";
import { checkpointSigningBytes, computeAuditEntryHash, type AuditCheckpointSigningPayload } from "../../src/audit/chain.js";
import { decrypt } from "../../src/core/encryption.js";
import { bytesToString, fromBase64url, toBase64url } from "../../src/core/encoding.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity, sign as identitySign } from "../../src/core/identity.js";
import { generateRandomKey } from "../../src/core/random.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { exportAuditChain } from "../../src/cli/audit-chain-export.js";
import { verifyAuditChainRecords } from "../../src/cli/audit-chain-verify.js";
import { migrateFortressAuditStoreSplit, verifyFortressAuditFullPicture } from "../../src/operational/audit-store-split.js";
import { redactAuditEntryForAgent } from "../../src/operational/agent-audit-redaction.js";

const AGENT = "agent:mixed";

// Plaintext serializations taken from the base output for these fixed inputs; the stored hash covers a fresh-nonce
// ciphertext, so the golden is the plaintext and a hash over fixed envelope inputs, never a stored hash.
const GOLDEN_INPUTS: AuditEntryInput[] = [
  { timestamp: "2026-11-25T00:00:00.000Z", layer: "l2", operation: "golden_plain", identity_id: "agent:golden", result: "success" },
  { timestamp: "2026-11-25T00:00:01.000Z", layer: "l2", operation: "golden_details", identity_id: "agent:golden", result: "failure", details: { k: "v", n: 1 } },
  { timestamp: "2026-11-25T00:00:02.000Z", layer: "l3", operation: "golden_contrib", identity_id: "agent:golden", result: "success", details: { k: "v" }, contributors: [{ plugin_id: "p", fields: ["k"] }] as never },
];
const GOLDEN_PLAINTEXT = [
  '{"timestamp":"2026-11-25T00:00:00.000Z","layer":"l2","operation":"golden_plain","identity_id":"agent:golden","result":"success"}',
  '{"timestamp":"2026-11-25T00:00:01.000Z","layer":"l2","operation":"golden_details","identity_id":"agent:golden","result":"failure","details":{"k":"v","n":1}}',
  '{"timestamp":"2026-11-25T00:00:02.000Z","layer":"l3","operation":"golden_contrib","identity_id":"agent:golden","result":"success","details":{"k":"v"},"contributors":[{"plugin_id":"p","fields":["k"]}]}',
];
const GOLDEN_HASH = "b483fc354d61fdac66291fd88292a2f1fe5496ac4c7374d305d83a8e1146fd6b";

async function storedPlaintexts(storage: MemoryStorage, masterKey: Uint8Array): Promise<string[]> {
  const key = derivePurposeKey(masterKey, "audit-log");
  const out: string[] = [];
  for (const meta of await storage.list("_audit")) {
    const envelope = JSON.parse(bytesToString((await storage.read("_audit", meta.key))!));
    const encrypted = JSON.parse(bytesToString(fromBase64url(envelope.encrypted_payload_bytes)));
    out.push(bytesToString(decrypt(encrypted, key)));
  }
  return out;
}

function signerFixture(masterKey: Uint8Array) {
  const identityKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("checkpoint-signer", identityKey, "recovery-key");
  return {
    publicKey: storedIdentity.public_key,
    signer: async (payload: AuditCheckpointSigningPayload) => ({
      signer_kid: storedIdentity.identity_id,
      signature: toBase64url(identitySign(checkpointSigningBytes(payload), storedIdentity.encrypted_private_key, identityKey)),
      public_key: storedIdentity.public_key,
    }),
  };
}

async function callWith(log: AuditLog, tag: string, outcome: "succeeded" | "refused"): Promise<void> {
  await runInCallScope(async (scope) => {
    await log.appendCritical({ layer: "l2", operation: "mixed_row", identity_id: AGENT, result: "success", details: { tag } });
    settleCallOutcome(scope, outcome);
    writeCallOutcomeMarkers(scope);
  });
  await log.flush();
}

const dirs: string[] = [];
afterEach(async () => {
  __testSetAuditWriterUidForRole("root_daemon", undefined);
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

async function exportAndVerify(storage: FilesystemStorage) {
  let text = "";
  const out = new Writable({ write(chunk, _encoding, done) { text += String(chunk); done(); } });
  const summary = await exportAuditChain(storage, out);
  const report = verifyAuditChainRecords(text.trim().split("\n").map((line) => JSON.parse(line)), { strict: false });
  // This log has no checkpoint signer, so its checkpoint records carry no signature; every other finding counts.
  return { summary, report, chainFindings: report.findings.filter((f) => f.kind !== "checkpoint_unsigned") };
}

async function visibleTags(log: AuditLog): Promise<string[]> {
  return (await log.query({ identity_id: AGENT, agent_visible: true, limit: 1_000 })).entries.map((e) => String(e.details?.tag));
}

describe("rows outside any call are unchanged", () => {
  it("a row appended outside any call scope serializes exactly as before", async () => {
    const storage = new MemoryStorage();
    const masterKey = new Uint8Array(32).fill(7);
    const log = new AuditLog(storage, masterKey);
    for (const input of GOLDEN_INPUTS) await log.appendCritical(input);
    expect(await storedPlaintexts(storage, masterKey)).toEqual(GOLDEN_PLAINTEXT);
  });

  it("the entry hash over fixed envelope inputs is unchanged", () => {
    expect(computeAuditEntryHash({
      sequence: 7,
      prev_hash: "a".repeat(64),
      timestamp: "2026-11-25T00:00:00.000Z",
      encrypted_payload_bytes: "AAAA",
      schema_version: 2,
    } as never)).toBe(GOLDEN_HASH);
  });

  it("has_details is unchanged for an out-of-scope row with and without details", async () => {
    const log = new AuditLog(new MemoryStorage(), generateRandomKey());
    for (const input of GOLDEN_INPUTS) await log.appendCritical(input);
    const rows = (await log.query({ limit: 10 })).entries;
    expect(rows.map((row) => redactAuditEntryForAgent(row).has_details)).toEqual([false, true, true]);
  });
});

describe("mixed rows verify through trusted paths", () => {
  it("checkpoint, rotation and reopen verify a log of plain rows, in-call rows and real markers, and visibility holds", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const { publicKey, signer } = signerFixture(masterKey);
    const config = { checkpointInterval: 2, checkpointSigner: signer, checkpointPublicKeyResolver: () => publicKey, maxEntries: 12 };
    const log = new AuditLog(storage, masterKey, config);
    await log.appendCritical({ layer: "l2", operation: "mixed_row", identity_id: AGENT, result: "success", details: { tag: "plain-0" } });
    for (let i = 0; i < 4; i++) {
      await callWith(log, `ok-${i}`, "succeeded");
      await callWith(log, `refused-${i}`, "refused");
    }
    const check = async (reader: AuditLog) => {
      const raw = await reader.query({ limit: 1_000, include_outcome_markers: true });
      expect(raw.integrity_findings).toEqual([]);
      const tags = await visibleTags(reader);
      expect(tags.some((tag) => tag.startsWith("refused"))).toBe(false);
      expect(tags.filter((tag) => tag.startsWith("ok")).length).toBeGreaterThan(0);
      // Raw counts include the markers.
      expect(raw.entries.some((e) => e.operation === CALL_OUTCOME_SUCCESS_OPERATION)).toBe(true);
      expect(raw.total).toBe(raw.entries.length);
      const usage = await reader.getRetentionUsage();
      expect(usage.entryCount).toBe(raw.total);
    };
    // Checkpoint and rotation (maxEntries 12 prunes the oldest rows) ran during the appends above.
    await check(log);
    const reopened = new AuditLog(storage, masterKey, config);
    await check(reopened);
    expect(await reopened.getAuditChainVerdict()).toMatchObject({ status: "verified" });
    // The out-of-scope rows keep no call reference after every path.
    const raw = (await reopened.query({ limit: 1_000 })).entries;
    for (const row of raw) {
      if (String(row.details?.tag).startsWith("plain")) expect(Object.hasOwn(row, "call_ref")).toBe(false);
    }
  });

  it("a stored call reference and a stored marker survive reopen; a caller append can still write neither", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const log = new AuditLog(storage, masterKey);
    await callWith(log, "ok", "succeeded");
    const before = (await log.query({ limit: 100, include_outcome_markers: true })).entries;
    const after = (await new AuditLog(storage, masterKey).query({ limit: 100, include_outcome_markers: true })).entries;
    expect(after).toEqual(before);
    expect(() => log.append("l2", CALL_OUTCOME_SUCCESS_OPERATION, "system", { call_ref: "a".repeat(16), outcome: "success" })).toThrow();
    await log.appendCritical({ layer: "l2", operation: "forged", identity_id: AGENT, result: "success", call_ref: "b".repeat(16) } as unknown as AuditEntryInput);
    const forged = (await log.query({ operation_type: "forged", limit: 10 })).entries[0]!;
    expect(Object.hasOwn(forged, "call_ref")).toBe(false);
  });

  it("chain export, offline verification and the audit store split keep a mixed log verifiable and its visibility intact", async () => {
    const root = await mkdtemp(join(tmpdir(), "audit-call-outcome-split-"));
    dirs.push(root);
    const storage = new FilesystemStorage(join(root, "state"));
    const masterKey = generateRandomKey();
    // The split re-verifies the chain with no checkpoint key, so this log has no checkpoint signer; the case above
    // carries signed checkpoints.
    const log = new AuditLog(storage, masterKey);
    await log.appendCritical({ layer: "l2", operation: "mixed_row", identity_id: AGENT, result: "success", details: { tag: "plain-0" } });
    for (let i = 0; i < 3; i++) {
      await callWith(log, `ok-${i}`, "succeeded");
      await callWith(log, `refused-${i}`, "refused");
    }
    const stored = (await log.query({ limit: 1_000, include_outcome_markers: true })).total;

    const first = await exportAndVerify(storage);
    expect(first.chainFindings).toEqual([]);
    // The export carries every stored row, markers included.
    expect(first.summary.entriesExported).toBe(stored);

    __testSetAuditWriterUidForRole("root_daemon", 0);
    try {
      await migrateFortressAuditStoreSplit({ storage, masterKey });
    } finally {
      __testSetAuditWriterUidForRole("root_daemon", undefined);
    }

    // The split seals the mixed prefix; it verifies whole, and the live chain continues with calls of both outcomes.
    const picture = await verifyFortressAuditFullPicture({ storage, masterKey });
    expect(picture.operator.status).toBe("verified");
    expect(picture.operator.sealed_region?.status).toBe("verified");
    const continued = new AuditLog(storage, masterKey);
    await callWith(continued, "ok-post", "succeeded");
    await callWith(continued, "refused-post", "refused");
    const reopened = new AuditLog(storage, masterKey);
    const raw = await reopened.query({ limit: 1_000, include_outcome_markers: true });
    expect(raw.integrity_findings).toEqual([]);
    expect(raw.entries.filter((e) => e.operation === CALL_OUTCOME_SUCCESS_OPERATION)).toHaveLength(1);
    expect(await visibleTags(reopened)).toEqual(["ok-post"]);
    expect((await reopened.query({ identity_id: AGENT, limit: 1_000 })).entries.map((e) => e.details?.tag)).toEqual(["ok-post", "refused-post"]);

    const second = await exportAndVerify(storage);
    expect(second.chainFindings).toEqual([]);
    expect(second.report.verdict).toBe(first.report.verdict);
  });
});
