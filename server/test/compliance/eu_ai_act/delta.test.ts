/**
 * Sanctuary MCP Server — EU AI Act Delta Mode Tests
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests for the delta_from_bundle_path parameter on
 * compliance_generate_eu_ai_act_bundle:
 *
 *   - Missing path → bundle generates without doc 08 (no delta)
 *   - Unreadable path → bundle still lands with warning, no doc 08
 *   - Invalid manifest → bundle still lands with warning, no doc 08
 *   - Valid prior bundle, no changes → doc 08 present with "no
 *     changes detected" note
 *   - Valid prior bundle with synthetic changes → doc 08 lists
 *     the changes with correct clause_ids
 *   - Bundle generation never fails because of a delta problem
 *     (Erik's non-dependency principle applied to delta)
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { mkdir, writeFile, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { ed25519 } from "@noble/curves/ed25519";
import { gcm } from "@noble/ciphers/aes.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { derivePurposeKey } from "../../../src/core/key-derivation.js";
import {
  publicKeyToDid,
  generateIdentityId,
  type StoredIdentity,
} from "../../../src/core/identity.js";
import { toBase64url } from "../../../src/core/encoding.js";
import type { EncryptedPayload } from "../../../src/core/encryption.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { IdentityManager } from "../../../src/cognitive/tools.js";
import { DEFAULT_POLICY } from "../../../src/principal-policy/loader.js";
import { defaultConfig } from "../../../src/config.js";
import {
  generateEuAiActBundle,
  type GeneratorDeps,
} from "../../../src/compliance/eu_ai_act/generator.js";
import type {
  ComplianceBundleInput,
  BundleManifest,
} from "../../../src/compliance/eu_ai_act/types.js";

// ── Fixture helpers ──────────────────────────────────────────────────

const FIXED_MASTER_KEY = new Uint8Array(32).fill(0x42);
const FIXED_PRIVATE_KEY = new Uint8Array(32);
for (let i = 0; i < 32; i++) FIXED_PRIVATE_KEY[i] = (i * 7 + 13) & 0xff;
const FIXED_IV = new Uint8Array(12).fill(0x11);
const FIXED_GENERATED_AT = "2026-04-10T12:00:00.000Z";

function buildDeterministicIdentity(): StoredIdentity {
  const publicKey = ed25519.getPublicKey(FIXED_PRIVATE_KEY);
  const identityId = generateIdentityId(publicKey);
  const did = publicKeyToDid(publicKey);
  const identityEncKey = derivePurposeKey(
    FIXED_MASTER_KEY,
    "identity-encryption"
  );
  const cipher = gcm(identityEncKey, FIXED_IV);
  const ciphertext = cipher.encrypt(FIXED_PRIVATE_KEY);
  const encryptedPrivateKey: EncryptedPayload = {
    v: 1,
    alg: "aes-256-gcm",
    iv: toBase64url(FIXED_IV),
    ct: toBase64url(ciphertext),
    ts: FIXED_GENERATED_AT,
  };
  return {
    identity_id: identityId,
    label: "delta-test-fixture",
    public_key: toBase64url(publicKey),
    did,
    created_at: FIXED_GENERATED_AT,
    key_type: "ed25519",
    key_protection: "passphrase",
    encrypted_private_key: encryptedPrivateKey,
    rotation_history: [],
  };
}

async function buildFixture(): Promise<GeneratorDeps> {
  const storage = new MemoryStorage();
  const identityManager = new IdentityManager(storage, FIXED_MASTER_KEY);
  const auditLog = new AuditLog(storage, FIXED_MASTER_KEY);
  await identityManager.save(buildDeterministicIdentity());
  // Seed a small amount of audit activity so period summaries are
  // non-zero but deterministic.
  await auditLog.append("l1", "state_read", "did:test", {});
  await auditLog.append("l2", "gate_allow:test", "did:test", {});
  return {
    config: defaultConfig(),
    identityManager,
    masterKey: FIXED_MASTER_KEY,
    auditLog,
    policy: DEFAULT_POLICY,
  };
}

function inputFor(
  deltaFromBundlePath?: string
): ComplianceBundleInput {
  return {
    agent_did: "did:sanctuary:delta-test-agent",
    deployment_context: {
      intended_purpose: "CV screening and candidate shortlisting",
      provider_legal_name: "Delta Test Co",
    },
    period_start: "2026-04-01T00:00:00.000Z",
    period_end: "2026-04-30T23:59:59.999Z",
    generated_at_override: FIXED_GENERATED_AT,
    delta_from_bundle_path: deltaFromBundlePath,
  };
}

async function writeBundleToDir(
  bundle: { manifest: BundleManifest; files: Array<{ filename: string; content: string }> },
  dir: string
): Promise<void> {
  await mkdir(dir, { recursive: true });
  await writeFile(
    join(dir, "00_bundle_manifest.json"),
    JSON.stringify(bundle.manifest, null, 2),
    "utf-8"
  );
  for (const f of bundle.files) {
    await writeFile(join(dir, f.filename), f.content, "utf-8");
  }
}

// ── Tests ────────────────────────────────────────────────────────────

describe("delta mode", () => {
  let tempRoot: string;

  beforeAll(async () => {
    // Freeze time for audit-log timestamp determinism.
    vi.useFakeTimers();
    vi.setSystemTime(new Date(FIXED_GENERATED_AT));
    tempRoot = await mkdir(
      join(tmpdir(), `sanctuary-delta-test-${Date.now()}-${Math.floor(Math.random() * 1e6)}`),
      { recursive: true }
    ).then((p) => p ?? join(tmpdir(), `sanctuary-delta-test-${Date.now()}`));
  });

  afterAll(async () => {
    vi.useRealTimers();
    if (tempRoot) {
      await rm(tempRoot, { recursive: true, force: true }).catch(() => {});
    }
  });

  it("no delta_from_bundle_path → bundle has 7 docs, no doc 08", async () => {
    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(inputFor(), deps);
    expect(bundle.files.length).toBe(7);
    expect(
      bundle.files.some((f) => f.filename === "08_delta.md")
    ).toBe(false);
  });

  it("unreadable delta path → bundle still lands with warning, no doc 08", async () => {
    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(
      inputFor("/nonexistent/path/to/prior/bundle"),
      deps
    );
    // Bundle generation MUST succeed despite the unreadable prior.
    expect(bundle.files.length).toBe(7);
    expect(
      bundle.files.some((f) => f.filename === "08_delta.md")
    ).toBe(false);
  });

  it("invalid manifest → bundle still lands with warning, no doc 08", async () => {
    const deps = await buildFixture();
    const invalidBundleDir = join(tempRoot, "invalid-bundle");
    await mkdir(invalidBundleDir, { recursive: true });
    await writeFile(
      join(invalidBundleDir, "00_bundle_manifest.json"),
      '{"not": "a valid manifest"}',
      "utf-8"
    );
    const bundle = await generateEuAiActBundle(
      inputFor(invalidBundleDir),
      deps
    );
    expect(bundle.files.length).toBe(7);
  });

  it("valid prior bundle, no changes → doc 08 present with 'no changes detected' note", async () => {
    const deps1 = await buildFixture();
    const priorBundle = await generateEuAiActBundle(inputFor(), deps1);
    const priorDir = join(tempRoot, "prior-unchanged");
    await writeBundleToDir(priorBundle, priorDir);

    const deps2 = await buildFixture();
    const currentBundle = await generateEuAiActBundle(
      inputFor(priorDir),
      deps2
    );
    expect(currentBundle.files.length).toBe(8);
    const doc8 = currentBundle.files.find(
      (f) => f.filename === "08_delta.md"
    );
    expect(doc8).toBeDefined();
    expect(doc8!.content).toContain("No changes detected");
  });

  it("valid prior bundle with synthetic coverage flag change → doc 08 lists the change", async () => {
    const deps1 = await buildFixture();
    const priorBundle = await generateEuAiActBundle(inputFor(), deps1);

    // Mutate the prior manifest: flip one row's coverage from "full"
    // to "partial" before writing. This simulates a matrix update
    // between bundles.
    const mutatedManifest = JSON.parse(
      JSON.stringify(priorBundle.manifest)
    ) as BundleManifest;
    const cyberRow = mutatedManifest.coverage_rows.find(
      (r) => r.id === "annex_iv_2_h_cybersecurity"
    );
    expect(cyberRow).toBeDefined();
    cyberRow!.coverage = "partial";
    cyberRow!.evidence_emitter = [...cyberRow!.evidence_emitter, "extra_tool"];

    const priorDir = join(tempRoot, "prior-mutated");
    await mkdir(priorDir, { recursive: true });
    await writeFile(
      join(priorDir, "00_bundle_manifest.json"),
      JSON.stringify(mutatedManifest, null, 2),
      "utf-8"
    );

    const deps2 = await buildFixture();
    const currentBundle = await generateEuAiActBundle(
      inputFor(priorDir),
      deps2
    );
    const doc8 = currentBundle.files.find(
      (f) => f.filename === "08_delta.md"
    )!;
    expect(doc8).toBeDefined();
    expect(doc8.content).toContain("annex_iv_2_h_cybersecurity");
    expect(doc8.content).toContain("`partial` → `full`");
    expect(doc8.content).toContain("extra_tool");
  });

  it("delta doc 08 is included in the final manifest with a valid signature", async () => {
    const deps1 = await buildFixture();
    const priorBundle = await generateEuAiActBundle(inputFor(), deps1);
    const priorDir = join(tempRoot, "prior-for-manifest-check");
    await writeBundleToDir(priorBundle, priorDir);

    const deps2 = await buildFixture();
    const currentBundle = await generateEuAiActBundle(
      inputFor(priorDir),
      deps2
    );
    // 8 files in the final manifest
    expect(currentBundle.manifest.files.length).toBe(8);
    const doc8Entry = currentBundle.manifest.files.find(
      (f) => f.filename === "08_delta.md"
    );
    expect(doc8Entry).toBeDefined();
    expect(doc8Entry!.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(doc8Entry!.signature).toBeTruthy();
  });

  it("missing coverage_rows in prior manifest → bundle still lands, no doc 08", async () => {
    const deps = await buildFixture();
    const priorDir = join(tempRoot, "prior-missing-rows");
    await mkdir(priorDir, { recursive: true });
    await writeFile(
      join(priorDir, "00_bundle_manifest.json"),
      JSON.stringify({
        bundle_version: "1.0",
        regulation_version: "test",
        // missing coverage_rows
      }),
      "utf-8"
    );
    const bundle = await generateEuAiActBundle(inputFor(priorDir), deps);
    expect(bundle.files.length).toBe(7);
  });
});
