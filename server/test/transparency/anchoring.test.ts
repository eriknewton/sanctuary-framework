/**
 * PR-2 anchoring properties. Every test encodes a contract the build must
 * not regress:
 *
 *   - OPT-IN, DEFAULT OFF: with no consent record nothing is transmitted,
 *     ever (the injected fetch asserts zero calls).
 *   - HASH-ONLY anchors: the bytes handed to Rekor contain the salted
 *     digest, signature, and derived public key and NOTHING traceable
 *     (no fortress id, no counter, no checkpoint hash, no counts).
 *   - FAIL LOUD, NEVER BLOCKING: a Rekor outage yields a failure outcome,
 *     a persisted failure receipt, and a critical audit entry; the local
 *     checkpoint stands; a later catch-up pass anchors it.
 *   - TAMPERED CONFIG REFUSES in both directions (neither silently
 *     enabled nor silently disabled).
 *   - Receipts are evidence: a success receipt is never overwritten.
 *
 * No test in this file touches the network: every Rekor interaction goes
 * through an injected FetchLike fixture (outage, malformed response, and
 * duplicate-entry behaviors included), per the synthetic-fixture rule.
 */
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { bytesToString, stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { randomBytes } from "../../src/core/random.js";
import {
  emitEnforcementCheckpoint,
  type TransparencySigner,
} from "../../src/transparency/emitter.js";
import {
  checkpointPayloadOf,
  computeCheckpointHash,
  type EnforcementCheckpointRecord,
} from "../../src/transparency/checkpoint.js";
import {
  anchorCommitmentDigestHex,
  anchorCommitmentPreimage,
  anchorPublicKeyPem,
  deriveAnchorSigningKey,
  isAnchorReceipt,
  type HashedRekordProposal,
} from "../../src/transparency/anchor.js";
import {
  ANCHOR_CONSENT_TEXT,
  TRANSPARENCY_ANCHOR_CONFIG_META_KEY,
  TRANSPARENCY_ANCHOR_NAMESPACE,
  TransparencyAnchorError,
  anchorCheckpoint,
  anchorPendingCheckpoints,
  anchorReceiptStorageKey,
  disableAnchoring,
  enableAnchoring,
  readAnchorConfig,
  readAnchorReceipts,
} from "../../src/transparency/anchoring.js";
import {
  HttpRekorClient,
  RekorClientError,
  type FetchLike,
} from "../../src/transparency/rekor-client.js";

const FORTRESS_ID = "fortress-anchor-test";

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
  fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-anchoring-"));
  const rulesDir = join(fortressPath, "policy", "egress", "rules");
  await mkdir(rulesDir, { recursive: true });
  await writeFile(
    join(rulesDir, "allow-github.json"),
    JSON.stringify({ rule_id: "allow-github", host: "github.com" })
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
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);
  return { storage, auditLog, masterKey };
}

async function emitOne(env: Env): Promise<EnforcementCheckpointRecord> {
  await env.auditLog.appendCritical({
    layer: "l1",
    operation: "egress_blocked",
    identity_id: FORTRESS_ID,
    result: "success",
    details: { rule_id: "deny-default" },
  });
  return emitEnforcementCheckpoint({
    storage: env.storage,
    auditLog: env.auditLog,
    fortressId: FORTRESS_ID,
    fortressPath,
    masterKey: env.masterKey,
    signer: testSigner(),
    binaryPath,
    version: "0.0.0-test",
  });
}

/** Recording fetch fixture. Default behavior: Rekor 201 success. */
interface FetchFixture {
  fetch: FetchLike;
  calls: Array<{ url: string; method: string; body?: string }>;
}

function rekorSuccessBody(uuid: string, logIndex: number): string {
  return JSON.stringify({
    [uuid]: {
      body: "ZHVtbXk=",
      integratedTime: 1_760_000_000,
      logID: "c0ffee".padEnd(64, "0"),
      logIndex,
      verification: {
        inclusionProof: {
          checkpoint: "rekor.sigstore.dev - 1234\n",
          hashes: ["ab".repeat(32)],
          logIndex,
          rootHash: "cd".repeat(32),
          treeSize: logIndex + 1,
        },
        signedEntryTimestamp: "c2V0LXNpZw==",
      },
    },
  });
}

function makeFetchFixture(
  responder?: (
    url: string,
    init: { method: string; body?: string }
  ) => { status: number; body: string; headers?: Record<string, string> }
): FetchFixture {
  const calls: FetchFixture["calls"] = [];
  let counter = 100;
  const fetch: FetchLike = async (url, init) => {
    calls.push({
      url,
      method: init.method,
      ...(init.body !== undefined ? { body: init.body } : {}),
    });
    const result =
      responder?.(url, init) ??
      ({ status: 201, body: rekorSuccessBody(`uuid-${counter}`, counter++) } as {
        status: number;
        body: string;
        headers?: Record<string, string>;
      });
    return {
      status: result.status,
      headers: {
        get: (name: string) => result.headers?.[name.toLowerCase()] ?? null,
      },
      text: async () => result.body,
    };
  };
  return { fetch, calls };
}

async function enable(env: Env, rekorUrl = "https://rekor.example.test") {
  return enableAnchoring({
    storage: env.storage,
    masterKey: env.masterKey,
    auditLog: env.auditLog,
    fortressId: FORTRESS_ID,
    rekorUrl,
  });
}

async function auditOps(env: Env, operation: string) {
  const { entries } = await env.auditLog.query({ limit: 1000 });
  return entries.filter((entry) => entry.operation === operation);
}

describe("opt-in, default OFF (hard constraint #1)", () => {
  it("performs zero network calls and anchors nothing when never enabled", async () => {
    const env = makeEnv();
    const record = await emitOne(env);
    const fixture = makeFetchFixture();
    const outcome = await anchorCheckpoint({
      storage: env.storage,
      masterKey: env.masterKey,
      auditLog: env.auditLog,
      record,
      fetchFn: fixture.fetch,
    });
    expect(outcome.status).toBe("disabled");
    expect(fixture.calls).toHaveLength(0);
    expect(await readAnchorReceipts(env.storage)).toHaveLength(0);
  });

  it("performs zero network calls after the operator disables anchoring", async () => {
    const env = makeEnv();
    const record = await emitOne(env);
    await enable(env);
    await disableAnchoring({
      storage: env.storage,
      masterKey: env.masterKey,
      auditLog: env.auditLog,
      fortressId: FORTRESS_ID,
    });
    const fixture = makeFetchFixture();
    const outcome = await anchorCheckpoint({
      storage: env.storage,
      masterKey: env.masterKey,
      auditLog: env.auditLog,
      record,
      fetchFn: fixture.fetch,
    });
    expect(outcome.status).toBe("disabled");
    expect(fixture.calls).toHaveLength(0);
  });

  it("records consent (text hash + timestamp) in the config and the audit log", async () => {
    const env = makeEnv();
    const config = await enable(env);
    expect(config.enabled).toBe(true);
    expect(config.consent.text_sha256).toMatch(/^[0-9a-f]{64}$/);
    const enabledEntries = await auditOps(env, "transparency_anchoring_enabled");
    expect(enabledEntries).toHaveLength(1);
    expect(enabledEntries[0]!.details?.consent_text_sha256).toBe(
      config.consent.text_sha256
    );
    // The consent text the hash commits to says hash-only and off-by-default.
    expect(ANCHOR_CONSENT_TEXT).toContain("salted SHA-256 hash");
    expect(ANCHOR_CONSENT_TEXT).toContain("stays off unless you enable it");
  });

  it("disable preserves the salt so earlier anchors stay verifiable", async () => {
    const env = makeEnv();
    const first = await enable(env);
    await disableAnchoring({
      storage: env.storage,
      masterKey: env.masterKey,
      auditLog: env.auditLog,
      fortressId: FORTRESS_ID,
    });
    const second = await enable(env);
    expect(second.salt).toBe(first.salt);
  });
});

describe("hash-only anchors (privacy)", () => {
  it("transmits only the salted digest, signature, and derived public key", async () => {
    const env = makeEnv();
    const record = await emitOne(env);
    const config = await enable(env);
    const fixture = makeFetchFixture();
    const outcome = await anchorCheckpoint({
      storage: env.storage,
      masterKey: env.masterKey,
      auditLog: env.auditLog,
      record,
      fetchFn: fixture.fetch,
    });
    expect(outcome.status).toBe("anchored");
    expect(fixture.calls).toHaveLength(1);
    const body = fixture.calls[0]!.body!;
    const proposal = JSON.parse(body) as HashedRekordProposal;

    // The digest is the salted commitment, recomputable only with the salt.
    const checkpointHash = computeCheckpointHash(checkpointPayloadOf(record));
    const expectedDigest = anchorCommitmentDigestHex(
      anchorCommitmentPreimage({
        saltHex: config.salt,
        counter: record.counter,
        checkpointHash,
      })
    );
    expect(proposal.spec.data.hash.value).toBe(expectedDigest);

    // NOTHING traceable appears in the transmitted bytes.
    expect(body).not.toContain(FORTRESS_ID);
    expect(body).not.toContain(checkpointHash);
    expect(body).not.toContain(config.salt);
    expect(body).not.toContain(record.audit.merkle_root);
    expect(body).not.toContain(record.policy.rules_sha256);
    expect(body).not.toContain(record.public_key);
    // The proposal carries exactly the hashedrekord shape, nothing extra.
    expect(Object.keys(proposal).sort()).toEqual(["apiVersion", "kind", "spec"]);
    expect(Object.keys(proposal.spec).sort()).toEqual(["data", "signature"]);

    // The signature verifies under the derived anchoring key (standard
    // ECDSA P-256 / SHA-256 over the preimage, as Rekor checks it), and
    // that key is NOT the checkpoint custody key.
    const pem = Buffer.from(
      proposal.spec.signature.publicKey.content,
      "base64"
    ).toString("utf8");
    const derived = deriveAnchorSigningKey(env.masterKey);
    expect(pem).toBe(anchorPublicKeyPem(derived.publicKey));
    const preimage = anchorCommitmentPreimage({
      saltHex: config.salt,
      counter: record.counter,
      checkpointHash,
    });
    const ok = cryptoVerify(
      "sha256",
      preimage,
      createPublicKey(pem),
      Buffer.from(proposal.spec.signature.content, "base64")
    );
    expect(ok).toBe(true);
  });

  it("derives the same anchoring pseudonym for the same master key and a different one for another fortress", () => {
    const masterA = randomBytes(32);
    const masterB = randomBytes(32);
    const a1 = deriveAnchorSigningKey(masterA);
    const a2 = deriveAnchorSigningKey(masterA);
    const b = deriveAnchorSigningKey(masterB);
    expect(Buffer.from(a1.publicKey).toString("hex")).toBe(
      Buffer.from(a2.publicKey).toString("hex")
    );
    expect(Buffer.from(a1.publicKey).toString("hex")).not.toBe(
      Buffer.from(b.publicKey).toString("hex")
    );
  });
});

describe("success path", () => {
  it("persists an anchored receipt and a critical audit entry", async () => {
    const env = makeEnv();
    const record = await emitOne(env);
    await enable(env);
    const fixture = makeFetchFixture();
    const outcome = await anchorCheckpoint({
      storage: env.storage,
      masterKey: env.masterKey,
      auditLog: env.auditLog,
      record,
      fetchFn: fixture.fetch,
    });
    expect(outcome.status).toBe("anchored");
    const receipts = await readAnchorReceipts(env.storage);
    expect(receipts).toHaveLength(1);
    expect(receipts[0]!.status).toBe("anchored");
    expect(receipts[0]!.counter).toBe(record.counter);
    expect(isAnchorReceipt(receipts[0])).toBe(true);
    if (receipts[0]!.status === "anchored") {
      expect(receipts[0]!.rekor.log_index).toBeGreaterThanOrEqual(0);
      // Rekor's verification blob is kept verbatim for the PR-3 verifier.
      expect(receipts[0]!.rekor.verification).toBeDefined();
    }
    const anchoredEntries = await auditOps(env, "transparency_checkpoint_anchored");
    expect(anchoredEntries).toHaveLength(1);
    expect(anchoredEntries[0]!.details?.counter).toBe(record.counter);
  });

  it("is idempotent: an already-anchored checkpoint is not re-transmitted", async () => {
    const env = makeEnv();
    const record = await emitOne(env);
    await enable(env);
    const fixture = makeFetchFixture();
    const input = {
      storage: env.storage,
      masterKey: env.masterKey,
      auditLog: env.auditLog,
      record,
      fetchFn: fixture.fetch,
    };
    expect((await anchorCheckpoint(input)).status).toBe("anchored");
    expect((await anchorCheckpoint(input)).status).toBe("already_anchored");
    expect(fixture.calls).toHaveLength(1);
  });

  it("treats a Rekor duplicate (409 + Location) as anchored with real log coordinates", async () => {
    const env = makeEnv();
    const record = await emitOne(env);
    await enable(env);
    const fixture = makeFetchFixture((url, init) => {
      if (init.method === "POST") {
        return {
          status: 409,
          body: "",
          headers: { location: "/api/v1/log/entries/uuid-dup" },
        };
      }
      return { status: 200, body: rekorSuccessBody("uuid-dup", 41) };
    });
    const outcome = await anchorCheckpoint({
      storage: env.storage,
      masterKey: env.masterKey,
      auditLog: env.auditLog,
      record,
      fetchFn: fixture.fetch,
    });
    expect(outcome.status).toBe("anchored");
    if (outcome.status === "anchored") {
      expect(outcome.duplicate).toBe(true);
      expect(outcome.receipt.rekor.uuid).toBe("uuid-dup");
      expect(outcome.receipt.rekor.log_index).toBe(41);
    }
  });
});

describe("fail loud, never blocking (outage fixture)", () => {
  it("a Rekor outage yields a failure outcome + receipt + critical audit entry, and a catch-up pass recovers", async () => {
    const env = makeEnv();
    const record = await emitOne(env);
    await enable(env);

    // Outage: every request is refused at the socket.
    const outage = makeFetchFixture();
    const outageFetch: FetchLike = async () => {
      throw new Error("connect ECONNREFUSED 127.0.0.1:443");
    };
    const failed = await anchorCheckpoint({
      storage: env.storage,
      masterKey: env.masterKey,
      auditLog: env.auditLog,
      record,
      fetchFn: outageFetch,
    });
    expect(failed.status).toBe("failed");
    if (failed.status === "failed") {
      expect(failed.error).toContain("ECONNREFUSED");
    }
    expect(outage.calls).toHaveLength(0);

    // LOUD: failure receipt persisted, critical audit entry written.
    const receipts = await readAnchorReceipts(env.storage);
    expect(receipts).toHaveLength(1);
    expect(receipts[0]!.status).toBe("failed");
    const failedEntries = await auditOps(env, "transparency_anchor_failed");
    expect(failedEntries).toHaveLength(1);
    expect(failedEntries[0]!.result).toBe("failure");

    // NEVER BLOCKING: the local store still holds the emitted checkpoint
    // and the next emission proceeds (anchoring failure gates nothing).
    const second = await emitOne(env);
    expect(second.counter).toBe(record.counter + 1);

    // Catch-up after the outage anchors everything pending.
    const fixture = makeFetchFixture();
    const result = await anchorPendingCheckpoints({
      storage: env.storage,
      masterKey: env.masterKey,
      auditLog: env.auditLog,
      fetchFn: fixture.fetch,
    });
    expect(result).toMatchObject({ anchored: 2, failed: 0 });
    const after = await readAnchorReceipts(env.storage);
    expect(after.map((receipt) => receipt.status)).toEqual([
      "anchored",
      "anchored",
    ]);
  });

  it("an HTTP error from Rekor is a failure, not silently skipped", async () => {
    const env = makeEnv();
    const record = await emitOne(env);
    await enable(env);
    const fixture = makeFetchFixture(() => ({
      status: 503,
      body: "service unavailable",
    }));
    const outcome = await anchorCheckpoint({
      storage: env.storage,
      masterKey: env.masterKey,
      auditLog: env.auditLog,
      record,
      fetchFn: fixture.fetch,
    });
    expect(outcome.status).toBe("failed");
    expect((await auditOps(env, "transparency_anchor_failed"))).toHaveLength(1);
  });

  it("a malformed Rekor response is NEVER recorded as anchored", async () => {
    const env = makeEnv();
    const record = await emitOne(env);
    await enable(env);
    for (const body of [
      "not json",
      "{}",
      JSON.stringify({ a: {}, b: {} }),
      JSON.stringify({ uuid: { logIndex: "not-a-number", logID: "x", integratedTime: 1 } }),
    ]) {
      const fixture = makeFetchFixture(() => ({ status: 201, body }));
      const outcome = await anchorCheckpoint({
        storage: env.storage,
        masterKey: env.masterKey,
        auditLog: env.auditLog,
        record,
        fetchFn: fixture.fetch,
      });
      expect(outcome.status).toBe("failed");
    }
    const receipts = await readAnchorReceipts(env.storage);
    expect(receipts.every((receipt) => receipt.status === "failed")).toBe(true);
  });

  it("a success receipt is never overwritten by a later failure", async () => {
    const env = makeEnv();
    const record = await emitOne(env);
    await enable(env);
    const fixture = makeFetchFixture();
    await anchorCheckpoint({
      storage: env.storage,
      masterKey: env.masterKey,
      auditLog: env.auditLog,
      record,
      fetchFn: fixture.fetch,
    });
    const raw = await env.storage.read(
      TRANSPARENCY_ANCHOR_NAMESPACE,
      anchorReceiptStorageKey(record.counter)
    );
    const before = JSON.parse(bytesToString(raw!)) as { status: string };
    expect(before.status).toBe("anchored");
    // Even a direct attempt to persist a failure over it is refused
    // (anchorCheckpoint itself would short-circuit on the success receipt,
    // so this asserts the deeper guard via the idempotence path).
    const again = await anchorCheckpoint({
      storage: env.storage,
      masterKey: env.masterKey,
      auditLog: env.auditLog,
      record,
      fetchFn: async () => {
        throw new Error("offline");
      },
    });
    expect(again.status).toBe("already_anchored");
  });
});

describe("tampered config refuses in both directions", () => {
  it("a bit-flipped config is neither enabled nor disabled: it throws", async () => {
    const env = makeEnv();
    const record = await emitOne(env);
    await enable(env);
    const raw = await env.storage.read("_meta", TRANSPARENCY_ANCHOR_CONFIG_META_KEY);
    const envelope = JSON.parse(bytesToString(raw!)) as {
      data: { enabled: boolean; rekor_url: string };
    };
    // Attacker tries to silently disable evidence anchoring.
    envelope.data.enabled = false;
    await env.storage.write(
      "_meta",
      TRANSPARENCY_ANCHOR_CONFIG_META_KEY,
      stringToBytes(JSON.stringify(envelope))
    );
    await expect(
      readAnchorConfig({ storage: env.storage, masterKey: env.masterKey })
    ).rejects.toThrow(TransparencyAnchorError);
    const fixture = makeFetchFixture();
    await expect(
      anchorCheckpoint({
        storage: env.storage,
        masterKey: env.masterKey,
        auditLog: env.auditLog,
        record,
        fetchFn: fixture.fetch,
      })
    ).rejects.toThrow(/failed authentication/);
    expect(fixture.calls).toHaveLength(0);
  });

  it("a forged enabled=true config without the right key cannot switch transmission on", async () => {
    const env = makeEnv();
    const record = await emitOne(env);
    // Forge a config envelope wholesale (attacker without the master key).
    const forged = {
      __sanctuary_transparency_anchor_config_v1: true,
      data: {
        enabled: true,
        salt: "ab".repeat(32),
        rekor_url: "https://attacker.example",
        consent: { accepted_at: new Date().toISOString(), text_sha256: "cd".repeat(32) },
      },
      mac: toBase64url(randomBytes(32)),
    };
    await env.storage.write(
      "_meta",
      TRANSPARENCY_ANCHOR_CONFIG_META_KEY,
      stringToBytes(JSON.stringify(forged))
    );
    const fixture = makeFetchFixture();
    await expect(
      anchorCheckpoint({
        storage: env.storage,
        masterKey: env.masterKey,
        auditLog: env.auditLog,
        record,
        fetchFn: fixture.fetch,
      })
    ).rejects.toThrow(TransparencyAnchorError);
    expect(fixture.calls).toHaveLength(0);
  });

  it("an explicit operator enable/disable rewrites a tampered config (the promised recovery path)", async () => {
    const env = makeEnv();
    await enable(env);
    // Corrupt the config wholesale.
    await env.storage.write(
      "_meta",
      TRANSPARENCY_ANCHOR_CONFIG_META_KEY,
      stringToBytes("garbage")
    );
    await expect(
      readAnchorConfig({ storage: env.storage, masterKey: env.masterKey })
    ).rejects.toThrow(TransparencyAnchorError);
    // The explicit operator verb recovers; automatic paths above refuse.
    const config = await enable(env);
    expect(config.enabled).toBe(true);
    const state = await readAnchorConfig({
      storage: env.storage,
      masterKey: env.masterKey,
    });
    expect(state.status).toBe("enabled");
    // And disable recovers from tamper too.
    await env.storage.write(
      "_meta",
      TRANSPARENCY_ANCHOR_CONFIG_META_KEY,
      stringToBytes("garbage")
    );
    const disabled = await disableAnchoring({
      storage: env.storage,
      masterKey: env.masterKey,
      auditLog: env.auditLog,
      fortressId: FORTRESS_ID,
    });
    expect(disabled.enabled).toBe(false);
    const after = await readAnchorConfig({
      storage: env.storage,
      masterKey: env.masterKey,
    });
    expect(after.status).toBe("disabled");
  });

  it("rejects a non-http(s) Rekor URL at enable time", async () => {
    const env = makeEnv();
    await expect(enable(env, "file:///etc/passwd")).rejects.toThrow(
      /must be http/
    );
  });
});

describe("HttpRekorClient", () => {
  const proposal: HashedRekordProposal = {
    apiVersion: "0.0.1",
    kind: "hashedrekord",
    spec: {
      data: { hash: { algorithm: "sha256", value: "ef".repeat(32) } },
      signature: { content: "c2ln", publicKey: { content: "cGVt" } },
    },
  };

  it("POSTs to /api/v1/log/entries and parses a 201 entry", async () => {
    const fixture = makeFetchFixture(() => ({
      status: 201,
      body: rekorSuccessBody("uuid-1", 7),
    }));
    const client = new HttpRekorClient({
      baseUrl: "https://rekor.example.test/",
      fetchFn: fixture.fetch,
    });
    const result = await client.submit(proposal);
    expect(fixture.calls[0]!.url).toBe(
      "https://rekor.example.test/api/v1/log/entries"
    );
    expect(result.duplicate).toBe(false);
    expect(result.entry).toMatchObject({
      uuid: "uuid-1",
      log_index: 7,
      integrated_time: 1_760_000_000,
    });
  });

  it("a 409 without a Location header is an error, not a silent success", async () => {
    const fixture = makeFetchFixture(() => ({ status: 409, body: "" }));
    const client = new HttpRekorClient({
      baseUrl: "https://rekor.example.test",
      fetchFn: fixture.fetch,
    });
    await expect(client.submit(proposal)).rejects.toThrow(RekorClientError);
  });

  it("surfaces the HTTP status and body on rejection", async () => {
    const fixture = makeFetchFixture(() => ({
      status: 400,
      body: "malformed entry",
    }));
    const client = new HttpRekorClient({
      baseUrl: "https://rekor.example.test",
      fetchFn: fixture.fetch,
    });
    await expect(client.submit(proposal)).rejects.toThrow(/HTTP 400/);
  });
});
