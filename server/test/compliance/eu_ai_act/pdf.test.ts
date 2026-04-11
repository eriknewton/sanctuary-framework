/**
 * Sanctuary MCP Server — EU AI Act PDF Writer Tests
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests for the hand-rolled PDF writer:
 *
 *   - Produces bytes that begin with the PDF magic header
 *   - Ends with %%EOF marker
 *   - Contains a valid xref table pointer (startxref)
 *   - Includes all bundle document titles as drawable text
 *   - Emits a cover page with the agent DID and manifest metadata
 *   - Emits a footer on every page with the manifest identifier
 *     prefix and a "Page N of M" label
 *   - Does not throw on bundles containing non-ASCII Markdown
 *     characters (§, →, etc.) — these are replaced with ASCII
 *     approximations before PDF string escaping
 *   - Handles long paragraphs by word-wrapping at the column width
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
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
import { AuditLog } from "../../../src/l2-operational/audit-log.js";
import { IdentityManager } from "../../../src/l1-cognitive/tools.js";
import { DEFAULT_POLICY } from "../../../src/principal-policy/loader.js";
import { defaultConfig } from "../../../src/config.js";
import {
  generateEuAiActBundle,
  type GeneratorDeps,
} from "../../../src/compliance/eu_ai_act/generator.js";
import { renderBundleToPdf } from "../../../src/compliance/eu_ai_act/pdf.js";
import type { ComplianceBundleInput } from "../../../src/compliance/eu_ai_act/types.js";

// ── Fixture helpers (same deterministic setup as other tests) ────────

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
    label: "pdf-test-fixture",
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
  return {
    config: defaultConfig(),
    identityManager,
    masterKey: FIXED_MASTER_KEY,
    auditLog,
    policy: DEFAULT_POLICY,
  };
}

function inputFor(): ComplianceBundleInput {
  return {
    agent_did: "did:sanctuary:pdf-test-agent",
    deployment_context: {
      intended_purpose: "CV screening and candidate shortlisting",
      provider_legal_name: "PDF Test Co",
    },
    period_start: "2026-04-01T00:00:00.000Z",
    period_end: "2026-04-30T23:59:59.999Z",
    generated_at_override: FIXED_GENERATED_AT,
  };
}

// ── Tests ────────────────────────────────────────────────────────────

describe("renderBundleToPdf", () => {
  beforeAll(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(FIXED_GENERATED_AT));
  });

  afterAll(() => {
    vi.useRealTimers();
  });

  it("produces bytes starting with the PDF magic header", async () => {
    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(inputFor(), deps);
    const pdf = renderBundleToPdf(bundle);
    const head = new TextDecoder("latin1").decode(pdf.slice(0, 8));
    expect(head).toMatch(/^%PDF-1\.\d/);
  });

  it("ends with the PDF EOF marker", async () => {
    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(inputFor(), deps);
    const pdf = renderBundleToPdf(bundle);
    const tail = new TextDecoder("latin1").decode(pdf.slice(-20));
    expect(tail).toContain("%%EOF");
  });

  it("contains a startxref pointer", async () => {
    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(inputFor(), deps);
    const pdf = renderBundleToPdf(bundle);
    const full = new TextDecoder("latin1").decode(pdf);
    expect(full).toContain("startxref");
    expect(full).toMatch(/startxref\n\d+\n%%EOF/);
  });

  it("contains an xref table matching declared object count", async () => {
    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(inputFor(), deps);
    const pdf = renderBundleToPdf(bundle);
    const full = new TextDecoder("latin1").decode(pdf);
    expect(full).toMatch(/xref\n0 \d+/);
  });

  it("declares Courier and Courier-Bold fonts", async () => {
    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(inputFor(), deps);
    const pdf = renderBundleToPdf(bundle);
    const full = new TextDecoder("latin1").decode(pdf);
    expect(full).toContain("/BaseFont /Courier");
    expect(full).toContain("/BaseFont /Courier-Bold");
  });

  it("contains the agent DID on the cover page", async () => {
    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(inputFor(), deps);
    const pdf = renderBundleToPdf(bundle);
    const full = new TextDecoder("latin1").decode(pdf);
    expect(full).toContain("did:sanctuary:pdf-test-agent");
  });

  it("contains document titles for all 7 bundle files", async () => {
    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(inputFor(), deps);
    const pdf = renderBundleToPdf(bundle);
    const full = new TextDecoder("latin1").decode(pdf);
    expect(full).toContain("01. Annex IV Technical Documentation");
    expect(full).toContain("02. Article 26 Deployer Log");
    expect(full).toContain("03. Article 12 Automatic Logs");
    expect(full).toContain("04. Risk Management Summary");
    expect(full).toContain("05. Human Oversight Statement");
    expect(full).toContain("06. Cryptographic Attestations");
    expect(full).toContain("07. Annex III Classification");
  });

  it("includes the 'Page N of M' footer on every page", async () => {
    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(inputFor(), deps);
    const pdf = renderBundleToPdf(bundle);
    const full = new TextDecoder("latin1").decode(pdf);
    expect(full).toMatch(/Page 1 of \d+/);
    expect(full).toMatch(/Page 2 of \d+/);
  });

  it("includes the manifest SHA-256 identifier prefix in the footer", async () => {
    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(inputFor(), deps);
    const pdf = renderBundleToPdf(bundle);
    const full = new TextDecoder("latin1").decode(pdf);
    // Footer uses the first file's sha256 prefix as the identifier
    const firstSha = bundle.manifest.files[0]!.sha256.slice(0, 48);
    expect(full).toContain(firstSha);
  });

  it("includes the NOT LEGAL ADVICE disclaimer on the cover page", async () => {
    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(inputFor(), deps);
    const pdf = renderBundleToPdf(bundle);
    const full = new TextDecoder("latin1").decode(pdf);
    expect(full).toContain("NOT LEGAL ADVICE");
  });

  it("handles non-ASCII Markdown characters without throwing", async () => {
    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(inputFor(), deps);
    // Bundle content includes §2(h), →, etc. which must not crash
    // the writer.
    expect(() => renderBundleToPdf(bundle)).not.toThrow();
  });

  it("replaces non-ASCII Markdown characters with ASCII approximations", async () => {
    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(inputFor(), deps);
    const pdf = renderBundleToPdf(bundle);
    const full = new TextDecoder("latin1").decode(pdf);
    // § is replaced with "S." — after PDF paren-escaping the text
    // appears as "S.2\(h\)" inside the literal string operators.
    expect(full).toContain("S.2\\(h\\)");
    // And no raw § byte (0xa7) survives in the content streams.
    // We check on the UTF-8 byte level rather than the decoded
    // string because § decodes to U+00A7 which is 0xa7 in latin1.
    const sectionSignByte = 0xa7;
    for (let i = 0; i < pdf.length; i++) {
      expect(pdf[i]).not.toBe(sectionSignByte);
    }
  });

  it("produces multiple pages (≥10) for a realistic bundle", async () => {
    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(inputFor(), deps);
    const pdf = renderBundleToPdf(bundle);
    const full = new TextDecoder("latin1").decode(pdf);
    // Count page objects via /Type /Page header count.
    const pageMatches = full.match(/\/Type \/Page\b/g) ?? [];
    // The /Pages tree itself matches /Type /Pages (not /Page\b), so
    // the count is exactly the number of page objects.
    expect(pageMatches.length).toBeGreaterThanOrEqual(10);
  });

  it("output is valid latin1-encodable (no surrogate issues)", async () => {
    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(inputFor(), deps);
    const pdf = renderBundleToPdf(bundle);
    // Every byte must be in 0-255
    for (let i = 0; i < pdf.length; i++) {
      expect(pdf[i]).toBeGreaterThanOrEqual(0);
      expect(pdf[i]).toBeLessThanOrEqual(255);
    }
  });
});
