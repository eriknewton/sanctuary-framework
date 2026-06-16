/**
 * PR-3 anchor verification properties. The contracts under test:
 *
 *   - REAL-PATH INTEGRATION: receipts produced by the PR-2 anchoring
 *     engine (through the real Rekor client against the synthetic log
 *     fixture) verify under the standalone anchor verifier with a pinned
 *     log key, so the standalone module's duplicated constants cannot
 *     drift from anchor.ts silently.
 *   - EVERY BINDING IS ENFORCED: salt, checkpoint hash, commitment digest,
 *     entry body digest, anchoring key, P-256 signature, UUID leaf hash,
 *     proof-index-to-signed-log-index binding (duplicate leaves make a
 *     proof for a different index forgeable), Merkle inclusion arithmetic,
 *     note consistency, SET and note signatures, logID. Each tampered
 *     independently yields its specific finding; none can be skipped into
 *     a pass.
 *   - MISSING EVIDENCE IS NEVER VERIFIED: absent bodies/proofs produce
 *     "unverified" coverage plus not_checked notes, not findings, and
 *     never "verified". Without a pinned log key NOTHING is "verified":
 *     anchors top out at "consistent" (operator-supplied evidence checked
 *     for internal consistency only).
 *   - WITHHELD SUFFIX IS EVIDENCE: an anchored receipt above the bundle's
 *     top counter is a finding (anchor_beyond_bundle).
 *   - FRESHNESS IS LOG-ATTESTED OR NOTHING: --expect-fresh without a
 *     pinned log key refuses (finding), stale log-attested time fails,
 *     fresh passes.
 *   - FORK DETECTION (--compare) flags duplicate counters with divergent
 *     signed contents and stays quiet for consistent prefixes.
 *
 * No test touches the network: all Rekor interaction goes through the
 * FakeRekorLog fixture (a real in-memory RFC 6962 log with P-256 note and
 * SET signatures), per the synthetic-fixture rule.
 */
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { toBase64url } from "../../src/core/encoding.js";
import { randomBytes } from "../../src/core/random.js";
import {
  emitEnforcementCheckpoint,
  type TransparencySigner,
} from "../../src/transparency/emitter.js";
import type { EnforcementCheckpointRecord } from "../../src/transparency/checkpoint.js";
import {
  anchorCheckpoint,
  buildAnchorsExport,
  enableAnchoring,
  readAnchorReceipts,
} from "../../src/transparency/anchoring.js";
import {
  parseFreshnessWindow,
  rfc6962LeafHash,
  rootFromInclusionProof,
  verifyAnchorEvidence,
  type TransparencyAnchorsExport,
} from "../../src/transparency/anchor-verify.js";
import {
  compareTransparencyChains,
  checkpointPayloadHash,
  type VerifierCheckpointRecord,
} from "../../src/transparency/verify.js";
import { FakeRekorLog, inclusionProof, merkleRoot } from "./fake-rekor-log.js";

const FORTRESS_ID = "fortress-anchor-verify-test";
const REKOR_URL = "https://rekor.fixture.test";
const FIXTURE_TIME = 1_760_000_000; // FakeRekorLog default integratedTime

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
  fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-anchor-verify-"));
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

interface Scenario {
  records: EnforcementCheckpointRecord[];
  anchorsDoc: TransparencyAnchorsExport;
  log: FakeRekorLog;
}

/**
 * Run the REAL pipeline: emit n checkpoints, anchor each through the real
 * anchoring engine + Rekor client against the synthetic log (with foreign
 * entries interleaved so trees are odd-shaped), then export the anchors
 * evidence exactly as the CLI verb would.
 */
async function buildScenario(n: number): Promise<Scenario> {
  const storage = new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);
  const signer = testSigner();
  const log = new FakeRekorLog();
  log.appendNoise("pre-existing-entry");
  await enableAnchoring({
    storage,
    masterKey,
    auditLog,
    fortressId: FORTRESS_ID,
    rekorUrl: REKOR_URL,
  });
  const records: EnforcementCheckpointRecord[] = [];
  for (let i = 0; i < n; i++) {
    await auditLog.appendCritical({
      layer: "l1",
      operation: i % 2 === 0 ? "egress_blocked" : "egress_allowed",
      identity_id: FORTRESS_ID,
      result: "success",
      details: { rule_id: `rule-${i}` },
    });
    const record = await emitEnforcementCheckpoint({
      storage,
      auditLog,
      fortressId: FORTRESS_ID,
      fortressPath,
      masterKey,
      signer,
      binaryPath,
      version: "0.0.0-test",
    });
    records.push(record);
    const outcome = await anchorCheckpoint({
      storage,
      masterKey,
      auditLog,
      record,
      fetchFn: log.fetchLike(),
    });
    expect(outcome.status).toBe("anchored");
    log.appendNoise(`foreign-after-${i}`);
  }
  const receipts = await readAnchorReceipts(storage);
  expect(receipts.filter((r) => r.status === "anchored")).toHaveLength(n);
  const anchorsDoc = await buildAnchorsExport({
    storage,
    masterKey,
    fortressId: FORTRESS_ID,
  });
  return { records, anchorsDoc, log };
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function anchoredReceipt(doc: TransparencyAnchorsExport, counter: number) {
  const receipt = doc.receipts.find(
    (r) => r.counter === counter && r.status === "anchored"
  );
  if (!receipt || receipt.status !== "anchored") {
    throw new Error(`no anchored receipt for counter ${counter}`);
  }
  return receipt;
}

describe("RFC 6962 inclusion-proof arithmetic", () => {
  it("recomputes the generator's root for every leaf at sizes 1..9", () => {
    const leaves: Uint8Array[] = [];
    for (let size = 1; size <= 9; size++) {
      leaves.push(rfc6962LeafHash(new TextEncoder().encode(`leaf-${size}`)));
      const root = merkleRoot(leaves);
      for (let index = 0; index < size; index++) {
        const computed = rootFromInclusionProof({
          leafHash: leaves[index]!,
          leafIndex: index,
          treeSize: size,
          proofHashes: inclusionProof(index, leaves),
        });
        expect(computed).not.toBeNull();
        expect(Buffer.from(computed!).toString("hex")).toBe(
          Buffer.from(root).toString("hex")
        );
      }
    }
  });

  it("refuses impossible proof shapes instead of passing them", () => {
    const leaf = rfc6962LeafHash(new TextEncoder().encode("leaf"));
    expect(
      rootFromInclusionProof({ leafHash: leaf, leafIndex: 2, treeSize: 2, proofHashes: [] })
    ).toBeNull();
    expect(
      rootFromInclusionProof({ leafHash: leaf, leafIndex: 0, treeSize: 4, proofHashes: [] })
    ).toBeNull(); // too short
    expect(
      rootFromInclusionProof({
        leafHash: leaf,
        leafIndex: 0,
        treeSize: 1,
        proofHashes: [leaf],
      })
    ).toBeNull(); // too long
  });
});

describe("parseFreshnessWindow", () => {
  it("parses suffixed and bare windows", () => {
    expect(parseFreshnessWindow("36h")).toBe(36 * 3_600_000);
    expect(parseFreshnessWindow("90m")).toBe(90 * 60_000);
    expect(parseFreshnessWindow("7d")).toBe(7 * 86_400_000);
    expect(parseFreshnessWindow("45s")).toBe(45_000);
    expect(parseFreshnessWindow("120")).toBe(120_000);
  });

  it("rejects malformed windows", () => {
    expect(() => parseFreshnessWindow("soon")).toThrow();
    expect(() => parseFreshnessWindow("-3h")).toThrow();
    expect(() => parseFreshnessWindow("0")).toThrow();
  });
});

describe("anchor evidence verification (real anchoring pipeline)", () => {
  it("verifies real receipts end-to-end under the pinned log key", async () => {
    const { records, anchorsDoc, log } = await buildScenario(3);
    const result = verifyAnchorEvidence(records, anchorsDoc, {
      rekorPublicKeyPem: log.publicKeyPem(),
    });
    expect(result.findings).toEqual([]);
    expect(result.coverage.checkpoints).toBe(3);
    expect(result.coverage.verified).toBe(3);
    expect(result.coverage.invalid).toBe(0);
    expect(result.coverage.unverified).toBe(0);
    expect(result.coverage.log_signature_basis).toBe("pinned-rekor-key");
    expect(result.coverage.newest_verified_integrated_time).toBe(FIXTURE_TIME);
  });

  it("without a pinned log key anchors are at most consistent, NEVER verified", async () => {
    const { records, anchorsDoc } = await buildScenario(2);
    const result = verifyAnchorEvidence(records, anchorsDoc, {});
    expect(result.findings).toEqual([]);
    // Every input here (salt, anchoring key, bodies, proofs, roots, notes,
    // timestamps) came from the operator-supplied evidence; "verified"
    // would be self-referential. The pin: zero verified, all consistent.
    expect(result.coverage.verified).toBe(0);
    expect(result.coverage.consistent).toBe(2);
    expect(result.coverage.invalid).toBe(0);
    expect(result.coverage.statuses.every((s) => s.status !== "verified")).toBe(
      true
    );
    expect(result.coverage.newest_verified_integrated_time).toBeNull();
    expect(result.coverage.log_signature_basis).toBe("none");
    expect(
      result.not_checked.some((note) => note.includes("no log public key was pinned"))
    ).toBe(true);
  });

  it("a wrong salt fails every commitment (anchor_commitment_mismatch)", async () => {
    const { records, anchorsDoc, log } = await buildScenario(2);
    const tampered = clone(anchorsDoc);
    tampered.salt = "ab".repeat(32);
    const result = verifyAnchorEvidence(records, tampered, {
      rekorPublicKeyPem: log.publicKeyPem(),
    });
    expect(
      result.findings.filter((f) => f.kind === "anchor_commitment_mismatch")
    ).toHaveLength(2);
    expect(result.coverage.invalid).toBe(2);
    expect(result.coverage.verified).toBe(0);
  });

  it("a receipt re-pointed at a different checkpoint hash is caught (anchor_checkpoint_mismatch)", async () => {
    const { records, anchorsDoc, log } = await buildScenario(2);
    const tampered = clone(anchorsDoc);
    anchoredReceipt(tampered, 1).checkpoint_hash = checkpointPayloadHash(
      records[1] as unknown as VerifierCheckpointRecord
    );
    const result = verifyAnchorEvidence(records, tampered, {
      rekorPublicKeyPem: log.publicKeyPem(),
    });
    expect(result.findings.some((f) => f.kind === "anchor_checkpoint_mismatch" && f.counter === 1)).toBe(true);
    expect(result.coverage.invalid).toBe(1);
    expect(result.coverage.verified).toBe(1);
  });

  it("an entry body swapped with another anchor's body breaks entry binding", async () => {
    const { records, anchorsDoc, log } = await buildScenario(2);
    const tampered = clone(anchorsDoc);
    anchoredReceipt(tampered, 1).rekor.body_b64 =
      anchoredReceipt(anchorsDoc, 2).rekor.body_b64;
    const result = verifyAnchorEvidence(records, tampered, {
      rekorPublicKeyPem: log.publicKeyPem(),
    });
    expect(
      result.findings.some(
        (f) => f.kind === "anchor_entry_binding_invalid" && f.counter === 1
      )
    ).toBe(true);
    expect(result.coverage.invalid).toBe(1);
  });

  it("a foreign anchoring key in the entry is caught even with a valid digest", async () => {
    const { records, anchorsDoc, log } = await buildScenario(1);
    const tampered = clone(anchorsDoc);
    // Replace the export's anchoring key with a DIFFERENT valid key: the
    // receipts' entries no longer bind to the claimed fortress pseudonym.
    const foreign = new FakeRekorLog();
    tampered.anchor_public_key_pem = foreign.publicKeyPem();
    const result = verifyAnchorEvidence(records, tampered, {
      rekorPublicKeyPem: log.publicKeyPem(),
    });
    expect(
      result.findings.some(
        (f) =>
          f.kind === "anchor_entry_binding_invalid" &&
          f.message.includes("DIFFERENT key")
      )
    ).toBe(true);
  });

  it("a tampered inclusion-proof hash is caught (anchor_inclusion_proof_invalid)", async () => {
    const { records, anchorsDoc, log } = await buildScenario(2);
    const tampered = clone(anchorsDoc);
    const proof = anchoredReceipt(tampered, 2).rekor.verification as {
      inclusionProof: { hashes: string[] };
    };
    proof.inclusionProof.hashes[0] = "00".repeat(32);
    const result = verifyAnchorEvidence(records, tampered, {
      rekorPublicKeyPem: log.publicKeyPem(),
    });
    expect(
      result.findings.some(
        (f) => f.kind === "anchor_inclusion_proof_invalid" && f.counter === 2
      )
    ).toBe(true);
  });

  it("a valid proof for a DIFFERENT index over a duplicate leaf is rejected (index binding)", async () => {
    const { records, anchorsDoc } = await buildScenario(1);
    const tampered = clone(anchorsDoc);
    const receipt = anchoredReceipt(tampered, 1);
    // RFC 6962 trees allow duplicate leaves. Build a tree carrying the SAME
    // leaf at indices 0 and 1, and supply the (genuinely valid) inclusion
    // proof for index 1 while the entry and its signed timestamp name log
    // index 0. Before the index-binding check, every other check passes:
    // same body, same UUID leaf hash, proof recomputes to the root.
    const bodyBytes = new Uint8Array(
      Buffer.from(receipt.rekor.body_b64!, "base64")
    );
    const leaf = rfc6962LeafHash(bodyBytes);
    const leaves = [leaf, leaf];
    const root = merkleRoot(leaves);
    const proofForIndexOne = inclusionProof(1, leaves);
    // Sanity: the forged proof is real Merkle arithmetic for index 1.
    const recomputed = rootFromInclusionProof({
      leafHash: leaf,
      leafIndex: 1,
      treeSize: 2,
      proofHashes: proofForIndexOne,
    });
    expect(Buffer.from(recomputed!).toString("hex")).toBe(
      Buffer.from(root).toString("hex")
    );
    receipt.rekor.log_index = 0;
    receipt.rekor.verification = {
      inclusionProof: {
        checkpoint: `rekor.fixture.test - 1066\n2\n${Buffer.from(root).toString("base64")}\n\n\u2014 rekor.fixture.test ${Buffer.from("notasig!").toString("base64")}\n`,
        hashes: proofForIndexOne.map((h) => Buffer.from(h).toString("hex")),
        logIndex: 1,
        rootHash: Buffer.from(root).toString("hex"),
        treeSize: 2,
      },
    };
    const result = verifyAnchorEvidence(records, tampered, {});
    expect(
      result.findings.some(
        (f) =>
          f.kind === "anchor_inclusion_proof_invalid" &&
          f.counter === 1 &&
          f.message.includes("leaf index 1") &&
          f.message.includes("log index 0")
      )
    ).toBe(true);
    expect(result.coverage.invalid).toBe(1);
    expect(result.coverage.verified).toBe(0);
    expect(result.coverage.consistent).toBe(0);
  });

  it("an entry log index at or beyond the proof's claimed tree size is rejected", async () => {
    const { records, anchorsDoc, log } = await buildScenario(1);
    const tampered = clone(anchorsDoc);
    const receipt = anchoredReceipt(tampered, 1);
    const proof = (
      receipt.rekor.verification as {
        inclusionProof: { logIndex: number; treeSize: number };
      }
    ).inclusionProof;
    // Keep the two indices EQUAL so only the range check can refuse it.
    receipt.rekor.log_index = proof.treeSize;
    proof.logIndex = proof.treeSize;
    const result = verifyAnchorEvidence(records, tampered, {
      rekorPublicKeyPem: log.publicKeyPem(),
    });
    expect(
      result.findings.some(
        (f) =>
          f.kind === "anchor_inclusion_proof_invalid" &&
          f.counter === 1 &&
          f.message.includes("not inside the inclusion proof's claimed tree")
      )
    ).toBe(true);
    expect(result.coverage.invalid).toBe(1);
    expect(result.coverage.verified).toBe(0);
  });

  it("a swapped signed entry timestamp fails under the pinned log key and only then", async () => {
    const { records, anchorsDoc, log } = await buildScenario(2);
    const tampered = clone(anchorsDoc);
    const v1 = anchoredReceipt(tampered, 1).rekor.verification as Record<string, unknown>;
    const v2 = anchoredReceipt(anchorsDoc, 2).rekor.verification as Record<string, unknown>;
    v1.signedEntryTimestamp = v2.signedEntryTimestamp;
    const pinned = verifyAnchorEvidence(records, tampered, {
      rekorPublicKeyPem: log.publicKeyPem(),
    });
    expect(
      pinned.findings.some(
        (f) => f.kind === "anchor_log_signature_invalid" && f.counter === 1
      )
    ).toBe(true);
    // Without the pinned key the SET is honestly out of scope: weaker
    // basis, no finding, and the anchor still cannot claim log attestation.
    const unpinned = verifyAnchorEvidence(records, tampered, {});
    expect(unpinned.findings).toEqual([]);
    expect(unpinned.coverage.log_signature_basis).toBe("none");
    expect(unpinned.coverage.verified).toBe(0);
    expect(unpinned.coverage.consistent).toBe(2);
  });

  it("an entry from a different log (wrong logID) is caught under the pinned key", async () => {
    const { records, anchorsDoc } = await buildScenario(1);
    const otherLog = new FakeRekorLog();
    const result = verifyAnchorEvidence(records, anchorsDoc, {
      rekorPublicKeyPem: otherLog.publicKeyPem(),
    });
    expect(
      result.findings.some((f) => f.kind === "anchor_log_signature_invalid")
    ).toBe(true);
  });

  it("missing entry body yields unverified coverage, never verified and never a finding", async () => {
    const { records, anchorsDoc, log } = await buildScenario(2);
    const degraded = clone(anchorsDoc);
    delete anchoredReceipt(degraded, 1).rekor.body_b64;
    const result = verifyAnchorEvidence(records, degraded, {
      rekorPublicKeyPem: log.publicKeyPem(),
    });
    expect(result.findings).toEqual([]);
    expect(result.coverage.verified).toBe(1);
    expect(result.coverage.unverified).toBe(1);
    expect(
      result.not_checked.some((note) => note.includes("entry body unavailable"))
    ).toBe(true);
  });

  it("live-fetched entries override receipt-embedded material", async () => {
    const { records, anchorsDoc, log } = await buildScenario(2);
    const degraded = clone(anchorsDoc);
    delete anchoredReceipt(degraded, 1).rekor.body_b64;
    delete anchoredReceipt(degraded, 1).rekor.verification;
    // Simulate --fetch-anchors: pull the entry back out of the log fixture.
    const { HttpRekorClient } = await import("../../src/transparency/rekor-client.js");
    const client = new HttpRekorClient({
      baseUrl: REKOR_URL,
      fetchFn: log.fetchLike(),
    });
    const fetched = await client.fetchEntry(anchoredReceipt(anchorsDoc, 1).rekor.uuid);
    const result = verifyAnchorEvidence(records, degraded, {
      rekorPublicKeyPem: log.publicKeyPem(),
      fetchedEntries: new Map([[1, fetched]]),
    });
    expect(result.findings).toEqual([]);
    expect(result.coverage.verified).toBe(2);
  });

  it("an anchored receipt above the bundle's top counter proves a withheld suffix", async () => {
    const { records, anchorsDoc, log } = await buildScenario(3);
    const truncated = records.slice(0, 2);
    const result = verifyAnchorEvidence(truncated, anchorsDoc, {
      rekorPublicKeyPem: log.publicKeyPem(),
    });
    expect(
      result.findings.some(
        (f) => f.kind === "anchor_beyond_bundle" && f.counter === 3
      )
    ).toBe(true);
    expect(result.coverage.verified).toBe(2);
  });

  it("an anchors export for a different fortress is rejected as evidence", async () => {
    const { records, anchorsDoc, log } = await buildScenario(1);
    const foreign = clone(anchorsDoc);
    foreign.fortress_id = "some-other-fortress";
    const result = verifyAnchorEvidence(records, foreign, {
      rekorPublicKeyPem: log.publicKeyPem(),
    });
    expect(
      result.findings.some((f) => f.kind === "anchors_fortress_mismatch")
    ).toBe(true);
  });

  it("a malformed anchors document is a single honest finding", async () => {
    const { records } = await buildScenario(1);
    const result = verifyAnchorEvidence(records, { nope: true }, {});
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.kind).toBe("anchors_input_invalid");
    expect(result.coverage.checkpoints).toBe(0);
  });
});

describe("--expect-fresh staleness policy", () => {
  it("refuses without a pinned log key (freshness on operator-supplied time is theater)", async () => {
    const { records, anchorsDoc } = await buildScenario(1);
    const result = verifyAnchorEvidence(records, anchorsDoc, {
      expectFreshMs: 3_600_000,
      now: () => new Date(FIXTURE_TIME * 1000),
    });
    expect(
      result.findings.some((f) => f.kind === "anchor_freshness_unverifiable")
    ).toBe(true);
  });

  it("fails a stale view and passes a fresh one against log-attested time", async () => {
    const { records, anchorsDoc, log } = await buildScenario(2);
    const stale = verifyAnchorEvidence(records, anchorsDoc, {
      rekorPublicKeyPem: log.publicKeyPem(),
      expectFreshMs: 3_600_000,
      now: () => new Date((FIXTURE_TIME + 48 * 3600) * 1000),
    });
    expect(stale.findings.some((f) => f.kind === "anchor_freshness_stale")).toBe(
      true
    );
    const fresh = verifyAnchorEvidence(records, anchorsDoc, {
      rekorPublicKeyPem: log.publicKeyPem(),
      expectFreshMs: 3_600_000,
      now: () => new Date((FIXTURE_TIME + 600) * 1000),
    });
    expect(fresh.findings).toEqual([]);
  });

  it("with no end-to-end verified anchor there is no freshness basis (finding, not silence)", async () => {
    const { records, anchorsDoc, log } = await buildScenario(1);
    const degraded = clone(anchorsDoc);
    delete anchoredReceipt(degraded, 1).rekor.body_b64;
    const result = verifyAnchorEvidence(records, degraded, {
      rekorPublicKeyPem: log.publicKeyPem(),
      expectFreshMs: 3_600_000,
      now: () => new Date(FIXTURE_TIME * 1000),
    });
    expect(
      result.findings.some((f) => f.kind === "anchor_freshness_unverifiable")
    ).toBe(true);
  });
});

describe("compareTransparencyChains (--compare split-view detection)", () => {
  function asVerifier(records: EnforcementCheckpointRecord[]): VerifierCheckpointRecord[] {
    return records as unknown as VerifierCheckpointRecord[];
  }

  it("flags a forked duplicate counter with divergent contents", async () => {
    const { records } = await buildScenario(3);
    const forked = clone(records);
    forked[2]!.enforcement.total_blocked += 7; // divergent signed payload
    const result = compareTransparencyChains(asVerifier(records), asVerifier(forked));
    expect(result.relation).toBe("fork");
    expect(result.divergent_counter).toBe(3);
    expect(result.findings.some((f) => f.kind === "fork_detected" && f.counter === 3)).toBe(true);
  });

  it("treats a stale prefix as consistent, noting which view is staler", async () => {
    const { records } = await buildScenario(3);
    const result = compareTransparencyChains(
      asVerifier(records),
      asVerifier(records.slice(0, 2))
    );
    expect(result.relation).toBe("consistent");
    expect(result.findings).toEqual([]);
    expect(result.notes.some((note) => note.includes("STALER view"))).toBe(true);
  });

  it("identical bundles compare as identical with no findings", async () => {
    const { records } = await buildScenario(2);
    const result = compareTransparencyChains(asVerifier(records), asVerifier(clone(records)));
    expect(result.relation).toBe("identical");
    expect(result.findings).toEqual([]);
  });

  it("non-overlapping ranges are an honest inconclusive finding", async () => {
    const { records } = await buildScenario(3);
    const result = compareTransparencyChains(
      asVerifier(records.slice(0, 1)),
      asVerifier(records.slice(2))
    );
    expect(result.relation).toBe("no_overlap");
    expect(result.findings.some((f) => f.kind === "compare_no_overlap")).toBe(true);
  });

  it("bundles from different fortresses are not comparable views", async () => {
    const { records } = await buildScenario(1);
    const foreign = clone(records);
    foreign[0]!.fortress_id = "someone-else";
    const result = compareTransparencyChains(asVerifier(records), asVerifier(foreign));
    expect(result.findings.some((f) => f.kind === "fortress_id_mismatch")).toBe(true);
  });
});
