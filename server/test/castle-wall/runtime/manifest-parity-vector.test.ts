import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";

import { canonicalize } from "../../../src/mesh/canonical-json.js";
import type { AllowlistManifest } from "../../../src/castle-wall/allowlist/manifest.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";

interface ManifestParityFixture {
  manifest_signed_body: AllowlistManifest;
  rules: AllowlistRule[];
  expected_canonical_json_b64: string;
  expected_canonical_json_hex: string;
  test_public_key_b64url: string;
  test_signature_b64url: string;
}

async function loadFixture(): Promise<ManifestParityFixture> {
  const here = dirname(fileURLToPath(import.meta.url));
  const fixturePath = join(here, "../fixtures/manifest-parity-vector.json");
  return JSON.parse(await readFile(fixturePath, "utf8")) as ManifestParityFixture;
}

async function loadSlashFixture(): Promise<ManifestParityFixture> {
  const here = dirname(fileURLToPath(import.meta.url));
  const fixturePath = join(here, "../fixtures/manifest-parity-vector-slash.json");
  return JSON.parse(await readFile(fixturePath, "utf8")) as ManifestParityFixture;
}

describe("castle-wall manifest canonical parity vector", () => {
  it("TS canonicalizer matches fixture bytes and signature", async () => {
    const fixture = await loadFixture();

    const actualCanonical = new TextEncoder().encode(
      canonicalize(fixture.manifest_signed_body),
    );
    const expectedCanonical = Buffer.from(
      fixture.expected_canonical_json_b64,
      "base64",
    );

    expect(Buffer.from(actualCanonical).toString("hex")).toBe(
      fixture.expected_canonical_json_hex,
    );
    expect(Buffer.compare(Buffer.from(actualCanonical), expectedCanonical)).toBe(0);

    const verified = ed25519.verify(
      Buffer.from(fixture.test_signature_b64url, "base64url"),
      actualCanonical,
      Buffer.from(fixture.test_public_key_b64url, "base64url"),
    );
    expect(verified).toBe(true);
  });

  it("slash vector: rule content with forward slashes stays raw (the 2026-07-12 Mini1 rejection bug)", async () => {
    const fixture = await loadSlashFixture();

    const actualCanonical = new TextEncoder().encode(
      canonicalize(fixture.manifest_signed_body),
    );
    expect(Buffer.from(actualCanonical).toString("hex")).toBe(
      fixture.expected_canonical_json_hex,
    );

    const verified = ed25519.verify(
      Buffer.from(fixture.test_signature_b64url, "base64url"),
      actualCanonical,
      Buffer.from(fixture.test_public_key_b64url, "base64url"),
    );
    expect(verified).toBe(true);

    // Per-rule digest parity: the digests inside the signed body must
    // recompute from the raw rule JSON, whose canonical bytes carry the
    // forward slash UNESCAPED ("443/tcp"). A consumer that escapes "/"
    // (JSONSerialization-style "\/") computes different digests and
    // rejects the manifest -- the live Mini1 failure mode.
    const { createHash } = await import("node:crypto");
    for (const [index, rule] of fixture.rules.entries()) {
      const ruleCanonical = canonicalize(rule);
      if (index === 0) {
        expect(ruleCanonical).toContain("443/tcp");
        expect(ruleCanonical).not.toContain("\\/");
      }
      const digest = createHash("sha256")
        .update(Buffer.from(ruleCanonical))
        .digest("hex");
      expect(digest).toBe(fixture.manifest_signed_body.rules[index]?.sha256);
    }
  });
});
