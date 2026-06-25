/**
 * Concordia Bridge — Tests
 *
 * Tests for the Sanctuary-Concordia bridge: commitment creation,
 * verification, canonical serialization, and attestation linking.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import {
  toBase64url,
  fromBase64url,
  stringToBytes,
  bytesToString,
} from "../../src/core/encoding.js";
import { hash } from "../../src/core/hashing.js";
import { encrypt, decrypt, type EncryptedPayload } from "../../src/core/encryption.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { createBridgeTools } from "../../src/bridge/tools.js";
import { ReputationStore } from "../../src/reputation/reputation-store.js";
import {
  createBridgeCommitment,
  verifyBridgeCommitment,
  canonicalize,
} from "../../src/bridge/bridge.js";
import type { ConcordiaOutcome, BridgeCommitment } from "../../src/bridge/types.js";
import type { AuditLog } from "../../src/operational/audit-log.js";
import type { ToolDefinition } from "../../src/router.js";

// ─── Test Helpers ────────────────────────────────────────────────────────

function makeOutcome(overrides?: Partial<ConcordiaOutcome>): ConcordiaOutcome {
  const terms = { price: 100, currency: "USD", delivery: "2026-04-15" };
  const termsHash = toBase64url(hash(stringToBytes(stableStringify(terms))));

  return {
    session_id: "concordia-session-001",
    protocol_version: "concordia-v1",
    proposer_did: "did:sanctuary:proposer123",
    acceptor_did: "did:sanctuary:acceptor456",
    terms,
    terms_hash: termsHash,
    rounds: 3,
    accepted_at: "2026-03-28T12:00:00.000Z",
    ...overrides,
  };
}

function parseToolResult(result: Awaited<ReturnType<ToolDefinition["handler"]>>): Record<string, unknown> {
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

function stubAuditLog(): AuditLog {
  return {
    append: () => {},
    appendCritical: async () => {},
  } as unknown as AuditLog;
}

async function makeBridgeHarness() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const identityManager = new IdentityManager(storage, masterKey);
  const signer = createIdentity("bridge-tool-signer", identityEncKey, "recovery-key");
  const counterparty = createIdentity("bridge-tool-counterparty", identityEncKey, "recovery-key");
  const outsider = createIdentity("bridge-tool-outsider", identityEncKey, "recovery-key");

  await identityManager.save(signer.storedIdentity);
  await identityManager.save(counterparty.storedIdentity);
  await identityManager.save(outsider.storedIdentity);
  await identityManager.setPrimary(signer.storedIdentity.identity_id);

  const { tools } = createBridgeTools(
    storage,
    masterKey,
    identityManager,
    stubAuditLog()
  );

  const byName = (name: string): ToolDefinition => {
    const tool = tools.find((t) => t.name === name);
    if (!tool) throw new Error(`Missing tool: ${name}`);
    return tool;
  };

  return {
    storage,
    masterKey,
    byName,
    signer,
    counterparty,
    outsider,
  };
}

/** Same stable stringify used in the bridge module */
function stableStringify(value: unknown): string {
  if (value === null) return "null";
  if (value === undefined) {
    throw new Error("Cannot canonicalize undefined");
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("Cannot canonicalize non-finite number");
    }
    if (Object.is(value, -0)) {
      throw new Error("Cannot canonicalize negative zero");
    }
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new Error("Cannot canonicalize unsafe integer");
    }
    return JSON.stringify(value);
  }
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map((v) => stableStringify(v)).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  const pairs = keys.map((k) => JSON.stringify(k) + ":" + stableStringify(obj[k]));
  return "{" + pairs.join(",") + "}";
}

// ─── Tests ───────────────────────────────────────────────────────────────

describe("Concordia Bridge", () => {
  let masterKey: Uint8Array;
  let identityEncKey: Uint8Array;
  let identity: ReturnType<typeof createIdentity>["storedIdentity"];
  let publicKey: Uint8Array;

  beforeEach(() => {
    masterKey = generateRandomKey();
    identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const created = createIdentity("bridge-test", identityEncKey, "recovery-key");
    identity = created.storedIdentity;
    publicKey = fromBase64url(created.publicIdentity.public_key);
  });

  // ── Canonical Serialization ────────────────────────────────────────────

  describe("canonicalize()", () => {
    it("produces deterministic output regardless of key order", () => {
      const outcome1 = makeOutcome();
      const outcome2: ConcordiaOutcome = {
        accepted_at: outcome1.accepted_at,
        rounds: outcome1.rounds,
        terms_hash: outcome1.terms_hash,
        terms: outcome1.terms,
        acceptor_did: outcome1.acceptor_did,
        proposer_did: outcome1.proposer_did,
        protocol_version: outcome1.protocol_version,
        session_id: outcome1.session_id,
      };

      const bytes1 = canonicalize(outcome1);
      const bytes2 = canonicalize(outcome2);

      expect(toBase64url(bytes1)).toBe(toBase64url(bytes2));
    });

    it("produces different output for different outcomes", () => {
      const outcome1 = makeOutcome({ rounds: 3 });
      const outcome2 = makeOutcome({ rounds: 5 });

      const bytes1 = canonicalize(outcome1);
      const bytes2 = canonicalize(outcome2);

      expect(toBase64url(bytes1)).not.toBe(toBase64url(bytes2));
    });

    it("handles nested terms objects deterministically", () => {
      const terms1 = { z: { b: 2, a: 1 }, a: "first" };
      const terms2 = { a: "first", z: { a: 1, b: 2 } };

      const termsHash = toBase64url(hash(stringToBytes(stableStringify(terms1))));

      const outcome1 = makeOutcome({ terms: terms1, terms_hash: termsHash });
      const outcome2 = makeOutcome({ terms: terms2, terms_hash: termsHash });

      expect(toBase64url(canonicalize(outcome1))).toBe(
        toBase64url(canonicalize(outcome2))
      );
    });

    it("omits undefined optional properties before canonicalization to match Concordia bytes", () => {
      const outcomeWithAssignedUndefined = makeOutcome({
        session_receipt: undefined,
      });
      const outcomeWithAbsentOptional = makeOutcome();

      const canonical = bytesToString(canonicalize(outcomeWithAssignedUndefined));
      const absentCanonical = bytesToString(canonicalize(outcomeWithAbsentOptional));

      // Concordia's signing.py canonical_json omits absent optionals before
      // json.dumps(sort_keys=True, separators=(",", ":")); these bytes mirror
      // that Python canonical_json output for the same logical outcome.
      const expectedConcordiaBytes =
        '{"accepted_at":"2026-03-28T12:00:00.000Z",' +
        '"acceptor_did":"did:sanctuary:acceptor456",' +
        '"proposer_did":"did:sanctuary:proposer123",' +
        '"protocol_version":"concordia-v1",' +
        '"rounds":3,' +
        '"session_id":"concordia-session-001",' +
        '"terms":{"currency":"USD","delivery":"2026-04-15","price":100},' +
        `"terms_hash":"${outcomeWithAbsentOptional.terms_hash}"}`;

      expect(canonical).toBe(absentCanonical);
      expect(canonical).toBe(expectedConcordiaBytes);
      expect(canonical).not.toContain("session_receipt");
      expect(canonical).not.toContain(":null");
    });

    it("rejects integers outside JavaScript's safe range", () => {
      expect(() =>
        canonicalize({ ...makeOutcome(), rounds: Number.MAX_SAFE_INTEGER + 1 })
      ).toThrow(/unsafe integer/i);
    });
  });

  // ── Cross-Language Canonical JSON Vectors (SEC-003) ───────────────────
  // These vectors MUST produce byte-identical output in both TypeScript
  // (stableStringify) and Python (canonical_json). The expected values
  // here are the shared contract between both repos.

  describe("cross-language canonical JSON vectors (SEC-003)", () => {
    // We need access to stableStringify through canonicalize + decode
    const canon = (v: unknown): string =>
      new TextDecoder().decode(canonicalize(v as ConcordiaOutcome));

    // For primitives/non-outcome objects, use the local stableStringify
    const ss = stableStringify;

    it("sorts keys alphabetically", () => {
      expect(ss({ z: 1, a: 2, m: 3 })).toBe('{"a":2,"m":3,"z":1}');
    });

    it("sorts nested keys recursively", () => {
      expect(ss({ b: { d: 1, c: 2 }, a: 3 })).toBe(
        '{"a":3,"b":{"c":2,"d":1}}'
      );
    });

    it("uses compact separators (no whitespace)", () => {
      expect(ss({ a: [1, 2, 3] })).toBe('{"a":[1,2,3]}');
    });

    it("formats integer numbers without decimal point", () => {
      expect(ss({ v: 1 })).toBe('{"v":1}');
      expect(ss({ v: 42 })).toBe('{"v":42}');
      expect(ss({ v: 0 })).toBe('{"v":0}');
      expect(ss({ v: -7 })).toBe('{"v":-7}');
    });

    it("formats boolean and null correctly", () => {
      expect(ss({ a: true, b: false, c: null })).toBe(
        '{"a":true,"b":false,"c":null}'
      );
    });

    it("handles empty structures", () => {
      expect(ss({})).toBe("{}");
      expect(ss({ a: [] })).toBe('{"a":[]}');
      expect(ss({ a: {} })).toBe('{"a":{}}');
    });

    it("handles string escaping for control characters", () => {
      expect(ss({ a: "line1\nline2" })).toBe('{"a":"line1\\nline2"}');
      expect(ss({ a: 'quote"here' })).toBe('{"a":"quote\\"here"}');
      expect(ss({ a: "back\\slash" })).toBe('{"a":"back\\\\slash"}');
    });

    it("preserves non-ASCII Unicode without escaping", () => {
      // V8's JSON.stringify does not escape non-ASCII
      expect(ss({ a: "café" })).toBe('{"a":"café"}');
      expect(ss({ a: "你好" })).toBe('{"a":"你好"}');
      expect(ss({ emoji: "☺" })).toBe('{"emoji":"☺"}');
    });

    it("handles deeply nested structures", () => {
      expect(ss({ a: { b: { c: { d: 1 } } } })).toBe(
        '{"a":{"b":{"c":{"d":1}}}}'
      );
    });

    it("handles arrays with mixed types", () => {
      expect(ss({ a: [1, "two", true, null, { k: "v" }] })).toBe(
        '{"a":[1,"two",true,null,{"k":"v"}]}'
      );
    });

    it("rejects negative zero", () => {
      // Must use canonicalize (the production function) to test rejection
      expect(() =>
        canonicalize({ v: -0 } as unknown as ConcordiaOutcome)
      ).toThrow(/negative zero/i);
    });

    it("rejects NaN", () => {
      expect(() =>
        canonicalize({ v: NaN } as unknown as ConcordiaOutcome)
      ).toThrow(/non-finite/i);
    });

    it("rejects Infinity", () => {
      expect(() =>
        canonicalize({ v: Infinity } as unknown as ConcordiaOutcome)
      ).toThrow(/non-finite/i);
      expect(() =>
        canonicalize({ v: -Infinity } as unknown as ConcordiaOutcome)
      ).toThrow(/non-finite/i);
    });

    // Exact byte-level vectors: the Python test suite must produce
    // the same expected string for each input.
    it("matches shared cross-language test vectors", () => {
      const vectors: Array<{ input: unknown; expected: string }> = [
        { input: { a: 1 }, expected: '{"a":1}' },
        { input: { b: "hello", a: "world" }, expected: '{"a":"world","b":"hello"}' },
        { input: { x: [1, 2, 3] }, expected: '{"x":[1,2,3]}' },
        { input: { n: null }, expected: '{"n":null}' },
        { input: { t: true, f: false }, expected: '{"f":false,"t":true}' },
        { input: { nested: { z: 1, a: 2 } }, expected: '{"nested":{"a":2,"z":1}}' },
        { input: { s: "café" }, expected: '{"s":"café"}' },
        { input: { s: "你好世界" }, expected: '{"s":"你好世界"}' },
        { input: { s: "line\nnew" }, expected: '{"s":"line\\nnew"}' },
        { input: { empty: {} }, expected: '{"empty":{}}' },
        { input: { arr: [] }, expected: '{"arr":[]}' },
        { input: { v: -42 }, expected: '{"v":-42}' },
        { input: { v: 0 }, expected: '{"v":0}' },
        { input: { mix: [null, true, "a", 1, { k: "v" }] }, expected: '{"mix":[null,true,"a",1,{"k":"v"}]}' },
      ];

      for (const { input, expected } of vectors) {
        expect(ss(input)).toBe(expected);
      }
    });
  });

  // ── Bridge Commit ──────────────────────────────────────────────────────

  describe("createBridgeCommitment()", () => {
    it("creates a valid bridge commitment", () => {
      const outcome = makeOutcome();
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey,
        false
      );

      expect(commitment.bridge_commitment_id).toMatch(/^bridge-/);
      expect(commitment.session_id).toBe(outcome.session_id);
      expect(commitment.sha256_commitment).toBeTruthy();
      expect(commitment.blinding_factor).toBeTruthy();
      expect(commitment.committer_did).toBe(identity.did);
      expect(commitment.signature).toBeTruthy();
      expect(commitment.bridge_version).toBe("sanctuary-concordia-bridge-v1");
      expect(commitment.pedersen_commitment).toBeUndefined();
    });

    it("includes Pedersen commitment when requested", () => {
      const outcome = makeOutcome({ rounds: 5 });
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey,
        true
      );

      expect(commitment.pedersen_commitment).toBeDefined();
      expect(commitment.pedersen_commitment!.commitment).toBeTruthy();
      expect(commitment.pedersen_commitment!.blinding_factor).toBeTruthy();
    });

    it("produces unique commitment IDs", () => {
      const outcome = makeOutcome();
      const c1 = createBridgeCommitment(outcome, identity, identityEncKey);
      const c2 = createBridgeCommitment(outcome, identity, identityEncKey);

      expect(c1.bridge_commitment_id).not.toBe(c2.bridge_commitment_id);
    });

    it("produces unique blinding factors", () => {
      const outcome = makeOutcome();
      const c1 = createBridgeCommitment(outcome, identity, identityEncKey);
      const c2 = createBridgeCommitment(outcome, identity, identityEncKey);

      expect(c1.blinding_factor).not.toBe(c2.blinding_factor);
      expect(c1.sha256_commitment).not.toBe(c2.sha256_commitment);
    });
  });

  // ── Bridge Verify ──────────────────────────────────────────────────────

  describe("verifyBridgeCommitment()", () => {
    it("verifies a valid commitment", () => {
      const outcome = makeOutcome();
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey,
        false
      );

      const result = verifyBridgeCommitment(commitment, outcome, publicKey);

      expect(result.valid).toBe(true);
      expect(result.checks.sha256_match).toBe(true);
      expect(result.checks.signature_valid).toBe(true);
      expect(result.checks.session_id_match).toBe(true);
      expect(result.checks.terms_hash_match).toBe(true);
    });

    it("verifies commitment with Pedersen", () => {
      const outcome = makeOutcome({ rounds: 7 });
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey,
        true
      );

      const result = verifyBridgeCommitment(commitment, outcome, publicKey);

      expect(result.valid).toBe(true);
      expect(result.checks.pedersen_match).toBe(true);
    });

    it("detects tampered terms", () => {
      const outcome = makeOutcome();
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey,
        false
      );

      // Tamper with the terms
      const tamperedOutcome = makeOutcome({
        terms: { price: 999, currency: "USD", delivery: "2026-04-15" },
      });

      const result = verifyBridgeCommitment(
        commitment,
        tamperedOutcome,
        publicKey
      );

      expect(result.valid).toBe(false);
      expect(result.checks.sha256_match).toBe(false);
    });

    it("detects tampered session ID", () => {
      const outcome = makeOutcome();
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey,
        false
      );

      const tamperedOutcome = makeOutcome({
        session_id: "tampered-session-id",
      });

      const result = verifyBridgeCommitment(
        commitment,
        tamperedOutcome,
        publicKey
      );

      expect(result.valid).toBe(false);
      expect(result.checks.session_id_match).toBe(false);
    });

    it("detects wrong public key (signature fails)", () => {
      const outcome = makeOutcome();
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey,
        false
      );

      // Create a different identity's public key
      const otherIdentity = createIdentity("other", identityEncKey, "recovery-key");
      const wrongKey = fromBase64url(otherIdentity.publicIdentity.public_key);

      const result = verifyBridgeCommitment(commitment, outcome, wrongKey);

      expect(result.valid).toBe(false);
      expect(result.checks.signature_valid).toBe(false);
    });

    it("detects tampered round count (Pedersen fails)", () => {
      const outcome = makeOutcome({ rounds: 3 });
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey,
        true
      );

      const tamperedOutcome = makeOutcome({ rounds: 10 });

      const result = verifyBridgeCommitment(
        commitment,
        tamperedOutcome,
        publicKey
      );

      expect(result.valid).toBe(false);
      // SHA-256 fails too since the canonical serialization includes rounds
      expect(result.checks.sha256_match).toBe(false);
      expect(result.checks.pedersen_match).toBe(false);
    });

    it("detects mismatched terms_hash", () => {
      const outcome = makeOutcome();
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey,
        false
      );

      // Change the terms_hash to something wrong
      const tamperedOutcome = {
        ...outcome,
        terms_hash: toBase64url(hash(stringToBytes("wrong"))),
      };

      const result = verifyBridgeCommitment(
        commitment,
        tamperedOutcome,
        publicKey
      );

      expect(result.valid).toBe(false);
      // SHA-256 fails because terms_hash is part of the canonical serialization
      expect(result.checks.sha256_match).toBe(false);
      expect(result.checks.terms_hash_match).toBe(false);
    });
  });

  // ── Bridge Tools ───────────────────────────────────────────────────────

  describe("bridge tools", () => {
    it("bridge_verify checks a revealed outcome instead of only stored provenance", async () => {
      const { byName, signer, counterparty } = await makeBridgeHarness();
      const outcome = makeOutcome({
        proposer_did: signer.publicIdentity.did,
        acceptor_did: counterparty.publicIdentity.did,
      });
      const commit = byName("bridge_commit");
      const verify = byName("bridge_verify");

      const committed = parseToolResult(await commit.handler({
        ...outcome,
        identity_id: signer.publicIdentity.identity_id,
      }));

      const revealed = makeOutcome({
        ...outcome,
        rounds: outcome.rounds + 1,
      });
      const result = parseToolResult(await verify.handler({
        bridge_commitment_id: committed.bridge_commitment_id,
        outcome: revealed,
      }));

      expect(result.valid).toBe(false);
      expect((result.checks as Record<string, unknown>).sha256_match).toBe(false);
    });

    it("bridge_verify rejects an external public key that does not derive the committer DID", async () => {
      const { byName, signer, counterparty, outsider } = await makeBridgeHarness();
      const outcome = makeOutcome({
        proposer_did: signer.publicIdentity.did,
        acceptor_did: counterparty.publicIdentity.did,
      });
      const committed = parseToolResult(await byName("bridge_commit").handler({
        ...outcome,
        identity_id: signer.publicIdentity.identity_id,
      }));

      const result = parseToolResult(await byName("bridge_verify").handler({
        bridge_commitment_id: committed.bridge_commitment_id,
        committer_public_key: outsider.publicIdentity.public_key,
        outcome,
      }));

      expect(result.error).toMatch(/committer_public_key resolves to/);
      expect(result.signature_valid).toBe(false);
    });

    it("bridge_attest refuses identities that are not negotiation parties", async () => {
      const { byName, signer, counterparty, outsider } = await makeBridgeHarness();
      const outcome = makeOutcome({
        proposer_did: signer.publicIdentity.did,
        acceptor_did: counterparty.publicIdentity.did,
      });
      const committed = parseToolResult(await byName("bridge_commit").handler({
        ...outcome,
        identity_id: signer.publicIdentity.identity_id,
      }));

      const result = parseToolResult(await byName("bridge_attest").handler({
        bridge_commitment_id: committed.bridge_commitment_id,
        outcome_result: "completed",
        identity_id: outsider.publicIdentity.identity_id,
      }));

      expect(result.error).toMatch(/neither the proposer nor the acceptor/);
    });

    it("bridge_attest refuses records whose stored outcome fails commitment verification", async () => {
      const { storage, masterKey, byName, signer, counterparty } = await makeBridgeHarness();
      const outcome = makeOutcome({
        proposer_did: signer.publicIdentity.did,
        acceptor_did: counterparty.publicIdentity.did,
      });
      const committed = parseToolResult(await byName("bridge_commit").handler({
        ...outcome,
        identity_id: signer.publicIdentity.identity_id,
      }));

      const commitmentId = committed.bridge_commitment_id as string;
      const encryptedRaw = await storage.read("_bridge", commitmentId);
      expect(encryptedRaw).not.toBeNull();
      const bridgeKey = derivePurposeKey(masterKey, "bridge-commitments");
      const encrypted = JSON.parse(bytesToString(encryptedRaw!)) as EncryptedPayload;
      const record = JSON.parse(
        bytesToString(decrypt(encrypted, bridgeKey))
      ) as { commitment: BridgeCommitment; outcome: ConcordiaOutcome };
      record.outcome = { ...record.outcome, rounds: record.outcome.rounds + 1 };
      await storage.write(
        "_bridge",
        commitmentId,
        stringToBytes(JSON.stringify(encrypt(stringToBytes(JSON.stringify(record)), bridgeKey)))
      );

      const result = parseToolResult(await byName("bridge_attest").handler({
        bridge_commitment_id: commitmentId,
        outcome_result: "completed",
        identity_id: counterparty.publicIdentity.identity_id,
      }));

      expect(result.error).toMatch(/failed verification/);
      expect((result.verification as Record<string, unknown>).valid).toBe(false);
    });

    it("bridge_attest rejects raw-term metric keys and persists no attestation", async () => {
      const { storage, masterKey, byName, signer, counterparty } = await makeBridgeHarness();
      const outcome = makeOutcome({
        proposer_did: signer.publicIdentity.did,
        acceptor_did: counterparty.publicIdentity.did,
      });
      const committed = parseToolResult(await byName("bridge_commit").handler({
        ...outcome,
        identity_id: signer.publicIdentity.identity_id,
      }));

      const result = parseToolResult(await byName("bridge_attest").handler({
        bridge_commitment_id: committed.bridge_commitment_id,
        outcome_result: "completed",
        identity_id: signer.publicIdentity.identity_id,
        metrics: { price: 150 },
      }));

      expect(result.error).toMatch(/only behavioral metrics are allowed/i);
      expect(result.error).toMatch(/price/);
      expect(result.attestation_id).toBeUndefined();

      const reputationStore = new ReputationStore(storage, masterKey);
      const summary = await reputationStore.query({ context: "concordia-bridge" });
      expect(summary.total_interactions).toBe(0);
      expect(await storage.list("_reputation")).toHaveLength(0);
    });

    it("bridge_attest accepts allowlisted behavioral metrics and persists them", async () => {
      const { storage, masterKey, byName, signer, counterparty } = await makeBridgeHarness();
      const outcome = makeOutcome({
        proposer_did: signer.publicIdentity.did,
        acceptor_did: counterparty.publicIdentity.did,
      });
      const committed = parseToolResult(await byName("bridge_commit").handler({
        ...outcome,
        identity_id: signer.publicIdentity.identity_id,
      }));

      const result = parseToolResult(await byName("bridge_attest").handler({
        bridge_commitment_id: committed.bridge_commitment_id,
        outcome_result: "completed",
        identity_id: signer.publicIdentity.identity_id,
        metrics: {
          rounds: 3,
          response_time_ms: 450,
          concession_magnitude: 0.25,
          offers_made: 2,
          reasoning_provided: 1,
        },
      }));

      expect(result.error).toBeUndefined();
      expect(result.attestation_id).toBeDefined();

      const reputationStore = new ReputationStore(storage, masterKey);
      const stored = await reputationStore.findExistingAttestation({
        interaction_id: outcome.session_id,
        participant_did: signer.publicIdentity.did,
        counterparty_did: counterparty.publicIdentity.did,
        context: "concordia-bridge",
      });
      expect(stored?.attestation.data.metrics).toEqual({
        rounds: 3,
        response_time_ms: 450,
        concession_magnitude: 0.25,
        offers_made: 2,
        reasoning_provided: 1,
        negotiation_rounds: outcome.rounds,
      });

      const summary = await reputationStore.query({ context: "concordia-bridge" });
      expect(summary.total_interactions).toBe(1);
      expect(summary.aggregate_metrics.response_time_ms.mean).toBe(450);
      expect(summary.aggregate_metrics.negotiation_rounds.mean).toBe(outcome.rounds);
    });

    it("bridge_attest names every offending metric key in the rejection error", async () => {
      const { byName, signer, counterparty } = await makeBridgeHarness();
      const outcome = makeOutcome({
        proposer_did: signer.publicIdentity.did,
        acceptor_did: counterparty.publicIdentity.did,
      });
      const committed = parseToolResult(await byName("bridge_commit").handler({
        ...outcome,
        identity_id: signer.publicIdentity.identity_id,
      }));

      const result = parseToolResult(await byName("bridge_attest").handler({
        bridge_commitment_id: committed.bridge_commitment_id,
        outcome_result: "completed",
        identity_id: signer.publicIdentity.identity_id,
        metrics: {
          price: 150,
          quantity: 1000,
        },
      }));

      expect(result.error).toMatch(/offending metric key/);
      expect(result.error).toMatch(/price/);
      expect(result.error).toMatch(/quantity/);
    });

    // F1 make-or-break: idempotent bridge_attest (no reputation double-count)
    it("bridge_attest records reputation exactly once across repeated attests of the same commitment", async () => {
      const { storage, masterKey, byName, signer, counterparty } = await makeBridgeHarness();
      const outcome = makeOutcome({
        proposer_did: signer.publicIdentity.did,
        acceptor_did: counterparty.publicIdentity.did,
      });
      const committed = parseToolResult(await byName("bridge_commit").handler({
        ...outcome,
        identity_id: signer.publicIdentity.identity_id,
      }));
      const commitmentId = committed.bridge_commitment_id as string;

      const reputationStore = new ReputationStore(storage, masterKey);

      const first = parseToolResult(await byName("bridge_attest").handler({
        bridge_commitment_id: commitmentId,
        outcome_result: "completed",
        identity_id: signer.publicIdentity.identity_id,
      }));
      expect(first.already_attested).toBe(false);
      expect(first.attestation_id).toBeDefined();

      const afterFirst = await reputationStore.query({ context: "concordia-bridge" });
      expect(afterFirst.total_interactions).toBe(1);

      const second = parseToolResult(await byName("bridge_attest").handler({
        bridge_commitment_id: commitmentId,
        outcome_result: "completed",
        identity_id: signer.publicIdentity.identity_id,
      }));
      // Second call returns the EXISTING attestation idempotently, signals it,
      // and does NOT record a second.
      expect(second.already_attested).toBe(true);
      expect(second.attestation_id).toBe(first.attestation_id);

      const afterSecond = await reputationStore.query({ context: "concordia-bridge" });
      expect(afterSecond.total_interactions).toBe(1);
    });

    it("bridge_attest still records a DIFFERENT commitment (no over-dedup)", async () => {
      const { storage, masterKey, byName, signer, counterparty } = await makeBridgeHarness();
      const outcomeA = makeOutcome({
        session_id: "concordia-session-A",
        proposer_did: signer.publicIdentity.did,
        acceptor_did: counterparty.publicIdentity.did,
      });
      const outcomeB = makeOutcome({
        session_id: "concordia-session-B",
        proposer_did: signer.publicIdentity.did,
        acceptor_did: counterparty.publicIdentity.did,
      });
      const committedA = parseToolResult(await byName("bridge_commit").handler({
        ...outcomeA,
        identity_id: signer.publicIdentity.identity_id,
      }));
      const committedB = parseToolResult(await byName("bridge_commit").handler({
        ...outcomeB,
        identity_id: signer.publicIdentity.identity_id,
      }));

      const attestA = parseToolResult(await byName("bridge_attest").handler({
        bridge_commitment_id: committedA.bridge_commitment_id,
        outcome_result: "completed",
        identity_id: signer.publicIdentity.identity_id,
      }));
      const attestB = parseToolResult(await byName("bridge_attest").handler({
        bridge_commitment_id: committedB.bridge_commitment_id,
        outcome_result: "completed",
        identity_id: signer.publicIdentity.identity_id,
      }));

      expect(attestA.already_attested).toBe(false);
      expect(attestB.already_attested).toBe(false);
      expect(attestB.attestation_id).not.toBe(attestA.attestation_id);

      const reputationStore = new ReputationStore(storage, masterKey);
      const summary = await reputationStore.query({ context: "concordia-bridge" });
      expect(summary.total_interactions).toBe(2);
    });

    // Fail-closed dedup: a storage/decrypt error during the dedup scan must
    // DENY the second attest, not silently record a duplicate (double-count).
    it("bridge_attest denies (does not double-record) when the dedup scan cannot read the store", async () => {
      // A storage proxy that delegates to a real MemoryStorage but can be flipped
      // to throw on read() for the _reputation namespace, simulating a transient
      // store fault during the dedup scan after one attestation already exists.
      const backing = new MemoryStorage();
      let failReputationReads = false;
      const faulting: StorageBackend = {
        write: (ns, key, data) => backing.write(ns, key, data),
        read: (ns, key) => {
          if (failReputationReads && ns === "_reputation") {
            return Promise.reject(new Error("simulated reputation read fault"));
          }
          return backing.read(ns, key);
        },
        delete: (ns, key, secure) => backing.delete(ns, key, secure),
        list: (ns, prefix) => backing.list(ns, prefix),
        exists: (ns, key) => backing.exists(ns, key),
        totalSize: () => backing.totalSize(),
        listNamespaces: () => backing.listNamespaces!(),
      };

      const harnessMasterKey = generateRandomKey();
      const harnessIdentityEncKey = derivePurposeKey(
        harnessMasterKey,
        "identity-encryption"
      );
      const identityManager = new IdentityManager(faulting, harnessMasterKey);
      const signer = createIdentity(
        "fail-closed-signer",
        harnessIdentityEncKey,
        "recovery-key"
      );
      const counterparty = createIdentity(
        "fail-closed-counterparty",
        harnessIdentityEncKey,
        "recovery-key"
      );
      await identityManager.save(signer.storedIdentity);
      await identityManager.save(counterparty.storedIdentity);
      await identityManager.setPrimary(signer.storedIdentity.identity_id);

      const { tools } = createBridgeTools(
        faulting,
        harnessMasterKey,
        identityManager,
        stubAuditLog()
      );
      const byName = (name: string): ToolDefinition => {
        const tool = tools.find((t) => t.name === name);
        if (!tool) throw new Error(`Missing tool: ${name}`);
        return tool;
      };

      const outcome = makeOutcome({
        proposer_did: signer.publicIdentity.did,
        acceptor_did: counterparty.publicIdentity.did,
      });
      const committed = parseToolResult(
        await byName("bridge_commit").handler({
          ...outcome,
          identity_id: signer.publicIdentity.identity_id,
        })
      );
      const commitmentId = committed.bridge_commitment_id as string;

      // First attest succeeds and records exactly one attestation.
      const first = parseToolResult(
        await byName("bridge_attest").handler({
          bridge_commitment_id: commitmentId,
          outcome_result: "completed",
          identity_id: signer.publicIdentity.identity_id,
        })
      );
      expect(first.already_attested).toBe(false);
      expect(first.attestation_id).toBeDefined();

      const reputationStore = new ReputationStore(faulting, harnessMasterKey);
      expect(
        (await reputationStore.query({ context: "concordia-bridge" }))
          .total_interactions
      ).toBe(1);

      // Now the dedup scan cannot read the store: the second attest must DENY,
      // not record a second attestation.
      failReputationReads = true;
      const second = parseToolResult(
        await byName("bridge_attest").handler({
          bridge_commitment_id: commitmentId,
          outcome_result: "completed",
          identity_id: signer.publicIdentity.identity_id,
        })
      );
      expect(second.error).toMatch(/could not be fully read|not recorded/i);
      expect(second.attestation_id).toBeUndefined();

      // No second attestation was written: still exactly one on record.
      failReputationReads = false;
      expect(
        (await reputationStore.query({ context: "concordia-bridge" }))
          .total_interactions
      ).toBe(1);
    });

    // F2 make-or-break: terms_hash recomputed at commit, mismatch rejected
    it("bridge_commit rejects a terms_hash that does not match the canonical terms", async () => {
      const { storage, byName, signer, counterparty } = await makeBridgeHarness();
      const outcome = makeOutcome({
        proposer_did: signer.publicIdentity.did,
        acceptor_did: counterparty.publicIdentity.did,
        terms_hash: toBase64url(hash(stringToBytes("not-the-real-hash"))),
      });

      await expect(
        byName("bridge_commit").handler({
          ...outcome,
          identity_id: signer.publicIdentity.identity_id,
        })
      ).rejects.toThrow(/terms_hash/);

      // Nothing was persisted or signed: the bridge store has no commitment.
      const entries = await storage.list("_bridge");
      expect(entries.length).toBe(0);
    });

    it("bridge_commit accepts a matching terms_hash and signs only a true hash", async () => {
      const { byName, signer, counterparty } = await makeBridgeHarness();
      const outcome = makeOutcome({
        proposer_did: signer.publicIdentity.did,
        acceptor_did: counterparty.publicIdentity.did,
      });

      const committed = parseToolResult(await byName("bridge_commit").handler({
        ...outcome,
        identity_id: signer.publicIdentity.identity_id,
      }));
      expect(committed.bridge_commitment_id).toBeDefined();

      // The committed outcome verifies, and the recompute-at-commit matches the
      // recompute verifyBridgeCommitment performs (terms_hash_match true).
      const verified = parseToolResult(await byName("bridge_verify").handler({
        bridge_commitment_id: committed.bridge_commitment_id,
        outcome,
      }));
      expect(verified.valid).toBe(true);
      expect((verified.checks as Record<string, unknown>).terms_hash_match).toBe(true);
    });
  });

  // ── Bridge Commitment Structure ────────────────────────────────────────

  describe("commitment structure", () => {
    it("uses the correct bridge version", () => {
      const outcome = makeOutcome();
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey
      );

      expect(commitment.bridge_version).toBe("sanctuary-concordia-bridge-v1");
    });

    it("sets committer_did from the signing identity", () => {
      const outcome = makeOutcome();
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey
      );

      expect(commitment.committer_did).toBe(identity.did);
    });

    it("includes a timestamp", () => {
      const outcome = makeOutcome();
      const commitment = createBridgeCommitment(
        outcome,
        identity,
        identityEncKey
      );

      expect(commitment.committed_at).toBeTruthy();
      // Should be a valid ISO 8601 date
      expect(new Date(commitment.committed_at).toISOString()).toBe(
        commitment.committed_at
      );
    });
  });
});
