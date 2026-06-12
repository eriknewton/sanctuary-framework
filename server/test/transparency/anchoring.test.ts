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
  TRANSPARENCY_ANCHOR_CONFIG_MAC_PURPOSE,
  anchorCommitmentDigestHex,
  anchorCommitmentPreimage,
  anchorConfigMacInput,
  anchorPublicKeyPem,
  deriveAnchorSigningKey,
  isAnchorReceipt,
  type AnchorConfigData,
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
  validateRekorUrl,
} from "../../src/transparency/anchoring.js";
import { hmacSha256 } from "../../src/core/hashing.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
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

function rekorSuccessBody(
  uuid: string,
  logIndex: number,
  bodyB64 = "ZHVtbXk="
): string {
  return JSON.stringify({
    [uuid]: {
      body: bodyB64,
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

async function enable(
  env: Env,
  rekorUrl = "https://rekor.example.test",
  allowUnsafeRekorUrl = false
) {
  return enableAnchoring({
    storage: env.storage,
    masterKey: env.masterKey,
    auditLog: env.auditLog,
    fortressId: FORTRESS_ID,
    rekorUrl,
    ...(allowUnsafeRekorUrl ? { allowUnsafeRekorUrl: true } : {}),
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

  it("treats a Rekor duplicate (409 + Location) as anchored with real log coordinates after verifying the entry matches", async () => {
    const env = makeEnv();
    const record = await emitOne(env);
    await enable(env);
    let postBody = "";
    const fixture = makeFetchFixture((url, init) => {
      if (init.method === "POST") {
        postBody = init.body!;
        return {
          status: 409,
          body: "",
          headers: { location: "/api/v1/log/entries/uuid-dup" },
        };
      }
      // The duplicate entry's body carries OUR proposal (the honest case).
      return {
        status: 200,
        body: rekorSuccessBody(
          "uuid-dup",
          41,
          Buffer.from(postBody).toString("base64")
        ),
      };
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
        allow_unsafe_url: false,
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

describe("Rekor URL guard (SSRF, fail-closed)", () => {
  it("requires https at enable time unless the unsafe override is passed", async () => {
    const env = makeEnv();
    await expect(enable(env, "http://rekor.example.test")).rejects.toThrow(
      /must use https/
    );
    expect(
      await readAnchorConfig({ storage: env.storage, masterKey: env.masterKey })
    ).toEqual({ status: "absent" });
  });

  it("rejects loopback, private, link-local, reserved, and metadata IP literals (including encoded forms)", () => {
    for (const url of [
      "https://127.0.0.1",
      "https://127.8.9.10:3000",
      "https://0.0.0.0",
      "https://10.1.2.3",
      "https://100.64.0.1",
      "https://169.254.169.254", // AWS/GCP metadata endpoint
      "https://169.254.0.7",
      "https://172.16.0.1",
      "https://172.31.255.255",
      "https://192.0.0.192",
      "https://192.168.1.10",
      "https://198.18.0.1",
      "https://192.88.99.1", // 6to4 relay anycast
      "https://198.51.100.7", // TEST-NET-2
      "https://203.0.113.9", // TEST-NET-3
      "https://224.0.0.1",
      "https://255.255.255.255",
      "https://0x7f000001", // hex-encoded 127.0.0.1 (WHATWG-normalized)
      "https://2130706433", // integer-encoded 127.0.0.1
      "https://[::1]",
      "https://[::]",
      "https://[fe80::1]",
      "https://[fd00::1]",
      "https://[fc00::1]",
      "https://[2001:db8::1]", // documentation prefix
      "https://[ff02::1]", // multicast
      "https://[::ffff:127.0.0.1]", // IPv4-mapped loopback
      "https://[::ffff:a9fe:a9fe]", // IPv4-mapped 169.254.169.254
    ]) {
      expect(() => validateRekorUrl(url, false), url).toThrow(/SSRF guard/);
    }
  });

  it("rejects well-known metadata and local hostnames", () => {
    for (const url of [
      "https://metadata.google.internal",
      "https://metadata.google.internal./", // trailing-dot variant is not exempted
      "https://anything.internal",
      "https://metadata.goog",
      "https://localhost",
      "https://localhost:3000",
      "https://dev.localhost",
    ]) {
      // The trailing-dot hostname keeps its dot in WHATWG parsing; the
      // suffix check catches ".internal" while the exact-match set catches
      // the rest. Validate each form rejects.
      expect(() => validateRekorUrl(url, false), url).toThrow(
        TransparencyAnchorError
      );
    }
  });

  it("accepts the default public Rekor URL and ordinary https hosts", async () => {
    expect(() => validateRekorUrl("https://rekor.sigstore.dev", false)).not.toThrow();
    expect(() => validateRekorUrl("https://rekor.example.test:8443/prefix", false)).not.toThrow();
    const env = makeEnv();
    const config = await enableAnchoring({
      storage: env.storage,
      masterKey: env.masterKey,
      auditLog: env.auditLog,
      fortressId: FORTRESS_ID,
    });
    expect(config.rekor_url).toBe("https://rekor.sigstore.dev");
    expect(config.allow_unsafe_url).toBe(false);
  });

  it("the unsafe override never allows non-http(s) schemes", () => {
    expect(() => validateRekorUrl("file:///etc/passwd", true)).toThrow(
      /must be http/
    );
    expect(() => validateRekorUrl("gopher://127.0.0.1", true)).toThrow(
      /must be http/
    );
  });

  it("escape hatch: --allow-unsafe-rekor-url permits a local dev log and is recorded in the config AND the audit entry", async () => {
    const env = makeEnv();
    const config = await enable(env, "http://127.0.0.1:3000", true);
    expect(config.allow_unsafe_url).toBe(true);
    expect(config.rekor_url).toBe("http://127.0.0.1:3000");
    const entries = await auditOps(env, "transparency_anchoring_enabled");
    expect(entries).toHaveLength(1);
    expect(entries[0]!.details?.allow_unsafe_rekor_url).toBe(true);
    // The safe default is recorded explicitly too (never ambiguous).
    const env2 = makeEnv();
    await enable(env2);
    const safeEntries = await auditOps(env2, "transparency_anchoring_enabled");
    expect(safeEntries[0]!.details?.allow_unsafe_rekor_url).toBe(false);
  });

  it("the unsafe override is never inherited: a plain re-enable over an unsafe URL fails closed", async () => {
    const env = makeEnv();
    await enable(env, "http://127.0.0.1:3000", true);
    await disableAnchoring({
      storage: env.storage,
      masterKey: env.masterKey,
      auditLog: env.auditLog,
      fortressId: FORTRESS_ID,
    });
    // Re-enable without the flag inherits the URL but NOT the override.
    await expect(
      enableAnchoring({
        storage: env.storage,
        masterKey: env.masterKey,
        auditLog: env.auditLog,
        fortressId: FORTRESS_ID,
      })
    ).rejects.toThrow(/must use https/);
  });

  it("revalidates at anchor time: an authenticated config carrying an unsafe URL without the override refuses with zero network calls", async () => {
    const env = makeEnv();
    const record = await emitOne(env);
    // Simulate a config written by an older build (valid MAC, no override,
    // unsafe URL): forge the envelope with the real master key.
    const data: AnchorConfigData = {
      enabled: true,
      salt: "ab".repeat(32),
      rekor_url: "http://169.254.169.254/latest/meta-data",
      allow_unsafe_url: false,
      consent: {
        accepted_at: new Date().toISOString(),
        text_sha256: "cd".repeat(32),
      },
    };
    const macKey = derivePurposeKey(
      env.masterKey,
      TRANSPARENCY_ANCHOR_CONFIG_MAC_PURPOSE
    );
    const envelope = {
      __sanctuary_transparency_anchor_config_v1: true,
      data,
      mac: toBase64url(hmacSha256(macKey, anchorConfigMacInput(data))),
    };
    await env.storage.write(
      "_meta",
      TRANSPARENCY_ANCHOR_CONFIG_META_KEY,
      stringToBytes(JSON.stringify(envelope))
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
    ).rejects.toThrow(/must use https/);
    expect(fixture.calls).toHaveLength(0);
    // The catch-up verb refuses the same way, even with nothing pending.
    await expect(
      anchorPendingCheckpoints({
        storage: env.storage,
        masterKey: env.masterKey,
        auditLog: env.auditLog,
        fetchFn: fixture.fetch,
      })
    ).rejects.toThrow(/must use https/);
    expect(fixture.calls).toHaveLength(0);
  });
});

describe("409 duplicate handling (verified, same-origin, time-bounded)", () => {
  it("a cross-origin Location is a failure receipt + critical audit entry, never anchored and never fetched", async () => {
    const env = makeEnv();
    const record = await emitOne(env);
    await enable(env);
    const fixture = makeFetchFixture((url, init) => {
      if (init.method === "POST") {
        return {
          status: 409,
          body: "",
          headers: { location: "https://evil.example/api/v1/log/entries/uuid-x" },
        };
      }
      throw new Error("the off-origin Location must never be fetched");
    });
    const outcome = await anchorCheckpoint({
      storage: env.storage,
      masterKey: env.masterKey,
      auditLog: env.auditLog,
      record,
      fetchFn: fixture.fetch,
    });
    expect(outcome.status).toBe("failed");
    if (outcome.status === "failed") {
      expect(outcome.error).toContain("off-origin");
    }
    // Only the POST happened; the cross-origin GET was refused.
    expect(fixture.calls).toHaveLength(1);
    expect(fixture.calls[0]!.method).toBe("POST");
    const receipts = await readAnchorReceipts(env.storage);
    expect(receipts).toHaveLength(1);
    expect(receipts[0]!.status).toBe("failed");
    expect(await auditOps(env, "transparency_anchor_failed")).toHaveLength(1);
    expect(await auditOps(env, "transparency_checkpoint_anchored")).toHaveLength(0);
  });

  it("a duplicate entry whose body does not match the submitted proposal is a failure receipt + critical audit entry", async () => {
    const env = makeEnv();
    const record = await emitOne(env);
    await enable(env);
    // The fetched entry parses cleanly but carries SOMEONE ELSE'S proposal.
    const foreign = {
      apiVersion: "0.0.1",
      kind: "hashedrekord",
      spec: {
        data: { hash: { algorithm: "sha256", value: "99".repeat(32) } },
        signature: { content: "Zm9yZWlnbg==", publicKey: { content: "cGVt" } },
      },
    };
    const fixture = makeFetchFixture((url, init) => {
      if (init.method === "POST") {
        return {
          status: 409,
          body: "",
          headers: { location: "/api/v1/log/entries/uuid-foreign" },
        };
      }
      return {
        status: 200,
        body: rekorSuccessBody(
          "uuid-foreign",
          7,
          Buffer.from(JSON.stringify(foreign)).toString("base64")
        ),
      };
    });
    const outcome = await anchorCheckpoint({
      storage: env.storage,
      masterKey: env.masterKey,
      auditLog: env.auditLog,
      record,
      fetchFn: fixture.fetch,
    });
    expect(outcome.status).toBe("failed");
    if (outcome.status === "failed") {
      expect(outcome.error).toContain("does not match the submitted proposal");
    }
    const receipts = await readAnchorReceipts(env.storage);
    expect(receipts).toHaveLength(1);
    expect(receipts[0]!.status).toBe("failed");
    expect(await auditOps(env, "transparency_anchor_failed")).toHaveLength(1);
    expect(await auditOps(env, "transparency_checkpoint_anchored")).toHaveLength(0);
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

  function duplicateResponder(location: string) {
    return (url: string, init: { method: string; body?: string }) => {
      if (init.method === "POST") {
        return { status: 409, body: "", headers: { location } };
      }
      return {
        status: 200,
        body: rekorSuccessBody(
          "uuid-dup",
          41,
          Buffer.from(JSON.stringify(proposal)).toString("base64")
        ),
      };
    };
  }

  it("follows a same-origin ABSOLUTE Location on 409", async () => {
    const fixture = makeFetchFixture(
      duplicateResponder("https://rekor.example.test/api/v1/log/entries/uuid-dup")
    );
    const client = new HttpRekorClient({
      baseUrl: "https://rekor.example.test",
      fetchFn: fixture.fetch,
    });
    const result = await client.submit(proposal);
    expect(result.duplicate).toBe(true);
    expect(result.entry.uuid).toBe("uuid-dup");
    expect(fixture.calls[1]!.url).toBe(
      "https://rekor.example.test/api/v1/log/entries/uuid-dup"
    );
  });

  it("refuses a cross-origin 409 Location (absolute URL) without fetching it", async () => {
    for (const location of [
      "https://evil.example/api/v1/log/entries/uuid-dup",
      "http://rekor.example.test/api/v1/log/entries/uuid-dup", // scheme downgrade = different origin
      "https://rekor.example.test:8443/api/v1/log/entries/uuid-dup", // port change = different origin
    ]) {
      const fixture = makeFetchFixture(duplicateResponder(location));
      const client = new HttpRekorClient({
        baseUrl: "https://rekor.example.test",
        fetchFn: fixture.fetch,
      });
      await expect(client.submit(proposal)).rejects.toThrow(/off-origin/);
      expect(fixture.calls, location).toHaveLength(1); // POST only, no GET
    }
  });

  it("refuses a protocol-relative 409 Location (//host/...) without fetching it", async () => {
    const fixture = makeFetchFixture(
      duplicateResponder("//evil.example/api/v1/log/entries/uuid-dup")
    );
    const client = new HttpRekorClient({
      baseUrl: "https://rekor.example.test",
      fetchFn: fixture.fetch,
    });
    await expect(client.submit(proposal)).rejects.toThrow(/off-origin/);
    expect(fixture.calls).toHaveLength(1);
  });

  it("a duplicate entry without a body cannot be confirmed and is an error", async () => {
    const fixture = makeFetchFixture((url, init) => {
      if (init.method === "POST") {
        return {
          status: 409,
          body: "",
          headers: { location: "/api/v1/log/entries/uuid-dup" },
        };
      }
      // Entry parses (logIndex etc. present) but carries no body field.
      return {
        status: 200,
        body: JSON.stringify({
          "uuid-dup": {
            integratedTime: 1_760_000_000,
            logID: "c0ffee".padEnd(64, "0"),
            logIndex: 41,
          },
        }),
      };
    });
    const client = new HttpRekorClient({
      baseUrl: "https://rekor.example.test",
      fetchFn: fixture.fetch,
    });
    await expect(client.submit(proposal)).rejects.toThrow(/carried no body/);
  });

  it("a duplicate entry whose body is not base64 JSON is an error", async () => {
    const fixture = makeFetchFixture((url, init) => {
      if (init.method === "POST") {
        return {
          status: 409,
          body: "",
          headers: { location: "/api/v1/log/entries/uuid-dup" },
        };
      }
      return { status: 200, body: rekorSuccessBody("uuid-dup", 41, "!!!not-base64-json!!!") };
    });
    const client = new HttpRekorClient({
      baseUrl: "https://rekor.example.test",
      fetchFn: fixture.fetch,
    });
    await expect(client.submit(proposal)).rejects.toThrow(/did not decode/);
  });

  it("applies the submit timeout (same abort signal) to the duplicate-entry GET", async () => {
    let getSignal: AbortSignal | undefined;
    const fetchFn: FetchLike = async (url, init) => {
      if (init.method === "POST") {
        return {
          status: 409,
          headers: {
            get: (name: string) =>
              name.toLowerCase() === "location"
                ? "/api/v1/log/entries/uuid-dup"
                : null,
          },
          text: async () => "",
        };
      }
      getSignal = init.signal;
      // Hang until the client's timeout aborts us; if the signal were not
      // wired through, this promise would never settle and the test would
      // time out instead of passing.
      return new Promise((_resolve, reject) => {
        init.signal?.addEventListener("abort", () =>
          reject(new Error("aborted by timeout signal"))
        );
      });
    };
    const client = new HttpRekorClient({
      baseUrl: "https://rekor.example.test",
      fetchFn,
      timeoutMs: 25,
    });
    await expect(client.submit(proposal)).rejects.toThrow(
      /duplicate-entry lookup failed.*aborted by timeout signal/
    );
    expect(getSignal).toBeDefined();
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
