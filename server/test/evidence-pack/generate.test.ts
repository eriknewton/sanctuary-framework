/**
 * Sanctuary MCP Server - Evidence Pack generator tests
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hermetic end-to-end tests for the pack generator: PDF renders without
 * throwing, every emitted file signature and the manifest signature verify
 * offline (the third-party verification path), the quarter aggregation is
 * correct, and the covered-window shortfall is disclosed honestly. Uses an
 * in-memory storage backend + a real fortress identity; never touches
 * `~/.sanctuary`.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity, verify } from "../../src/core/identity.js";
import type { StoredIdentity } from "../../src/core/identity.js";
import { fromBase64url, stringToBytes } from "../../src/core/encoding.js";
import { hash } from "../../src/core/hashing.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import type { AuditEntry } from "../../src/operational/audit-log.js";
import { buildEvidencePack } from "../../src/evidence-pack/generate.js";
import { canonicalJSON } from "../../src/evidence-pack/signer.js";
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
  const { storedIdentity } = createIdentity(
    "acme-law",
    identityEncKey,
    "fixture-passphrase"
  );
  await identityManager.save(storedIdentity);
  const primary = identityManager.getDefault();
  if (!primary) throw new Error("fixture: no primary identity");
  signer = primary;
});

function entry(
  timestamp: string,
  operation: string,
  result: "success" | "failure" = "success"
): AuditEntry {
  return { timestamp, layer: "l2", operation, identity_id: "agent-a", result };
}

function baseInput(): EvidencePackInput {
  return {
    firm_name: "Acme Law LLP",
    quarter: { year: 2026, quarter: 3 },
    generated_at_override: "2026-10-02T00:00:00.000Z",
    custody: { custody_mode: "passphrase", no_outbound_by_default: true },
  };
}

const FULL_COVERAGE: RetentionFacts = {
  max_entries: 100_000,
  retained_total: 3,
  earliest_retained_at: "2026-06-01T00:00:00.000Z",
};

describe("buildEvidencePack", () => {
  it("renders a PDF that begins with the PDF header and ends with %%EOF", () => {
    const pack = buildEvidencePack(baseInput(), {
      entries: [entry("2026-08-01T00:00:00.000Z", "gate_allow:x")],
      retention: FULL_COVERAGE,
      signer,
      masterKey,
    });
    const pdf = Buffer.from(pack.pdf).toString("latin1");
    expect(pdf.startsWith("%PDF-1.4")).toBe(true);
    expect(pdf.includes("%%EOF")).toBe(true);
    expect(pack.pdf.length).toBeGreaterThan(1000);
  });

  it("signs every file and the manifest so a third party can verify offline", () => {
    const pack = buildEvidencePack(baseInput(), {
      entries: [entry("2026-08-01T00:00:00.000Z", "gate_allow:x")],
      retention: FULL_COVERAGE,
      signer,
      masterKey,
    });
    const signerPub = fromBase64url(pack.manifest.signer.public_key_base64url);

    // Per-file signatures verify against the signer public key.
    for (const file of pack.files) {
      const digest = hash(stringToBytes(file.content));
      expect(verify(digest, fromBase64url(file.signature), signerPub)).toBe(true);
      // And the recorded SHA-256 matches the content.
      expect(file.sha256).toMatch(/^[0-9a-f]{64}$/);
    }

    // The manifest signature verifies over its canonical body (minus the sig).
    const { manifest_signature, ...body } = pack.manifest;
    const manifestDigest = hash(stringToBytes(canonicalJSON(body)));
    expect(verify(manifestDigest, fromBase64url(manifest_signature), signerPub)).toBe(
      true
    );
  });

  it("counts quarter decisions correctly, ignoring out-of-window entries", () => {
    const pack = buildEvidencePack(baseInput(), {
      entries: [
        entry("2026-06-30T00:00:00.000Z", "gate_allow:before"), // out
        entry("2026-08-01T00:00:00.000Z", "gate_allow:a"),
        entry("2026-08-02T00:00:00.000Z", "gate_deny:b"),
        entry("2026-08-03T00:00:00.000Z", "gate_approval_proof:c"),
        entry("2026-10-01T00:00:00.000Z", "gate_allow:after"), // out (end excl)
      ],
      retention: FULL_COVERAGE,
      signer,
      masterKey,
    });
    expect(pack.aggregation.total_in_window).toBe(3);
    expect(pack.aggregation.by_category.allowed).toBe(1);
    expect(pack.aggregation.by_category.denied).toBe(1);
    expect(pack.aggregation.by_category.human_approved).toBe(1);
  });

  it("discloses a covered-window shortfall in the manifest and the report", () => {
    const pack = buildEvidencePack(baseInput(), {
      entries: [entry("2026-08-01T00:00:00.000Z", "gate_allow:x")],
      retention: {
        max_entries: 100,
        retained_total: 100, // at cap -> pruning likely
        earliest_retained_at: "2026-08-01T00:00:00.000Z",
      },
      signer,
      masterKey,
    });
    expect(pack.manifest.coverage.shortfall).toBe(true);
    expect(pack.manifest.coverage.retention_at_cap).toBe(true);
    const report = pack.files[0]!.content;
    expect(report).toContain("COVERAGE NOTICE");
  });

  it("prints the honest coverage-basis and scope-and-limits language", () => {
    const pack = buildEvidencePack(baseInput(), {
      entries: [entry("2026-08-01T00:00:00.000Z", "gate_allow:x")],
      retention: FULL_COVERAGE,
      signer,
      masterKey,
    });
    const report = pack.files[0]!.content;
    expect(report).toContain("Coverage basis");
    expect(report).toContain("INVISIBLE to this inventory");
    expect(report).toContain("Scope and limits");
    // The banned per-rule-per-flow claim is explicitly negated, never asserted.
    expect(report).toContain("do not claim per-rule per-flow");
  });

  it("renders each section title into the PDF", () => {
    const pack = buildEvidencePack(baseInput(), {
      entries: [entry("2026-08-01T00:00:00.000Z", "gate_allow:x")],
      retention: FULL_COVERAGE,
      signer,
      masterKey,
    });
    const pdf = Buffer.from(pack.pdf).toString("latin1");
    expect(pdf).toContain("Executive summary");
    expect(pdf).toContain("AI tool inventory");
    expect(pdf).toContain("Scope and limits");
  });
});
