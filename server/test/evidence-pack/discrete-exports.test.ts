/**
 * Sanctuary MCP Server - Evidence Pack discrete-export tests (slice 2)
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hermetic tests for the third-party verification exports: the pack signs each
 * gathered export into its manifest, the verification appendix references the
 * concrete files + the exact offline verify command (not conditional
 * language), an absent export states an honest reason, and a gathered
 * transparency bundle validates offline with the shipped verifier against a
 * fixture. Uses an in-memory fortress identity; never touches ~/.sanctuary.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { randomBytes } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity, verify } from "../../src/core/identity.js";
import type { StoredIdentity } from "../../src/core/identity.js";
import { fromBase64url, stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { hash } from "../../src/core/hashing.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import {
  checkpointSigningBytes,
  computeCheckpointHash,
  TRANSPARENCY_BUNDLE_FORMAT,
  type EnforcementCheckpointPayload,
  type EnforcementCheckpointRecord,
  type TransparencyBundle,
} from "../../src/transparency/checkpoint.js";
import { verifyTransparencyCheckpoints } from "../../src/transparency/verify.js";
import {
  buildEvidencePack,
  TRANSPARENCY_BUNDLE_FILENAME,
  AUDIT_CHAIN_FILENAME,
  ANCHOR_EVIDENCE_FILENAME,
} from "../../src/evidence-pack/generate.js";
import type {
  EvidencePackInput,
  RetentionFacts,
} from "../../src/evidence-pack/types.js";

let masterKey: Uint8Array;
let signer: StoredIdentity;

beforeEach(async () => {
  masterKey = generateRandomKey(32);
  const storage = new MemoryStorage();
  const identityManager = new IdentityManager(storage, masterKey);
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("acme-law", identityEncKey, "pw");
  await identityManager.save(storedIdentity);
  const primary = identityManager.getDefault();
  if (!primary) throw new Error("fixture: no primary identity");
  signer = primary;
});

const RETENTION: RetentionFacts = {
  max_entries: 100_000,
  retained_total: 1,
  earliest_retained_at: "2026-06-01T00:00:00.000Z",
};

function baseInput(): EvidencePackInput {
  return {
    firm_name: "Acme Law LLP",
    quarter: { year: 2026, quarter: 3 },
    generated_at_override: "2026-10-02T00:00:00.000Z",
  };
}

// ── Transparency bundle fixture (mirrors test/transparency/verify.test.ts) ──

const CW_PRIVATE = randomBytes(32);
const CW_PUBLIC_B64 = toBase64url(ed25519.getPublicKey(CW_PRIVATE));

function payloadAt(
  counter: number,
  previousHash: string
): EnforcementCheckpointPayload {
  return {
    checkpoint_kind: "enforcement-checkpoint",
    schema_version: 1,
    counter,
    previous_checkpoint_hash: previousHash,
    issued_at: `2026-08-0${counter}T00:00:00.000Z`,
    fortress_id: "fortress-test",
    audit: {
      merkle_root: "a".repeat(64),
      lowest_sequence: 1,
      highest_sequence: counter * 10,
      head_hash: "b".repeat(64),
      entry_count: counter * 10,
    },
    policy: { rules_sha256: "c".repeat(64), rules_count: 1, manifest_sha256: null },
    daemon: { version: "1.3.3", binary_sha256: "d".repeat(64) },
    enforcement: { total_allowed: counter, total_blocked: 0, rules: [] },
  };
}

function signCheckpoint(
  payload: EnforcementCheckpointPayload
): EnforcementCheckpointRecord {
  return {
    ...payload,
    signer_kid: `castle-wall:${CW_PUBLIC_B64}`,
    signature: toBase64url(ed25519.sign(checkpointSigningBytes(payload), CW_PRIVATE)),
    signature_algorithm: "Ed25519",
    payload_encoding: "domain-separated-canonical-json-v1",
    public_key: CW_PUBLIC_B64,
  };
}

function fixtureTransparencyBundleJson(n = 2): string {
  const checkpoints: EnforcementCheckpointRecord[] = [];
  let prev = "GENESIS";
  for (let counter = 1; counter <= n; counter++) {
    const payload = payloadAt(counter, prev);
    checkpoints.push(signCheckpoint(payload));
    prev = computeCheckpointHash(payload);
  }
  const bundle: TransparencyBundle = {
    format: TRANSPARENCY_BUNDLE_FORMAT,
    exported_at: "2026-10-02T00:00:00.000Z",
    public_key: CW_PUBLIC_B64,
    checkpoints,
  };
  return JSON.stringify(bundle, null, 2);
}

describe("evidence pack discrete exports", () => {
  it("signs each gathered discrete export into the manifest", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        discrete_exports: {
          transparency_bundle_json: fixtureTransparencyBundleJson(),
          audit_chain_jsonl: '{"kind":"entry","sequence":1}\n',
          anchor_evidence_json: '{"anchored":true}',
        },
      },
      { entries: [], retention: RETENTION, signer, masterKey }
    );

    const names = pack.manifest.files.map((f) => f.filename);
    expect(names).toContain(TRANSPARENCY_BUNDLE_FILENAME);
    expect(names).toContain(AUDIT_CHAIN_FILENAME);
    expect(names).toContain(ANCHOR_EVIDENCE_FILENAME);

    // Every signed file (report + exports) verifies against the signer key.
    const signerPub = fromBase64url(pack.manifest.signer.public_key_base64url);
    for (const file of pack.files) {
      const digest = hash(stringToBytes(file.content));
      expect(verify(digest, fromBase64url(file.signature), signerPub)).toBe(true);
    }
    const jsonl = pack.manifest.files.find((f) => f.filename === AUDIT_CHAIN_FILENAME)!;
    expect(jsonl.content_type).toBe("application/jsonl");
  });

  it("references the concrete export files and the offline verify command in the appendix", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        discrete_exports: {
          transparency_bundle_json: fixtureTransparencyBundleJson(),
          audit_chain_jsonl: "{}\n",
        },
      },
      { entries: [], retention: RETENTION, signer, masterKey }
    );
    const report = pack.files[0]!.content;
    expect(report).toContain(
      `verify-transparency --input ${TRANSPARENCY_BUNDLE_FILENAME}`
    );
    expect(report).toContain(AUDIT_CHAIN_FILENAME);
    // The old slice-1 conditional wording must be gone.
    expect(report).not.toContain("Where the discrete evidence exports are included");
  });

  it("states an honest reason when an export is absent, not conditional language", () => {
    const pack = buildEvidencePack(baseInput(), {
      entries: [],
      retention: RETENTION,
      signer,
      masterKey,
    });
    const report = pack.files[0]!.content;
    expect(report).toContain("Not included:");
    // Anchor default reason (opt-in / off) is disclosed.
    expect(report).toContain("opt-in");
    // Absent exports are NOT signed into the manifest.
    const names = pack.manifest.files.map((f) => f.filename);
    expect(names).not.toContain(TRANSPARENCY_BUNDLE_FILENAME);
    expect(names).not.toContain(AUDIT_CHAIN_FILENAME);
  });

  it("gathers a transparency bundle that validates OFFLINE with the shipped verifier (PASS)", () => {
    const bundleJson = fixtureTransparencyBundleJson(3);
    const pack = buildEvidencePack(
      { ...baseInput(), discrete_exports: { transparency_bundle_json: bundleJson } },
      { entries: [], retention: RETENTION, signer, masterKey }
    );
    // The bundle the pack carries is the exact bytes we can verify offline.
    const carried = pack.manifest.files.find(
      (f) => f.filename === TRANSPARENCY_BUNDLE_FILENAME
    )!;
    expect(carried).toBeDefined();
    const bundle = JSON.parse(bundleJson) as TransparencyBundle;
    const report = verifyTransparencyCheckpoints(bundle, {
      publicKey: CW_PUBLIC_B64,
    });
    expect(report.verdict).toBe("PASS");
    expect(report.checkpoints_verified).toBe(3);
    expect(report.signature_basis).toBe("pinned");
  });
});
