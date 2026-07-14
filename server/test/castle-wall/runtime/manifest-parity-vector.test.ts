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

async function loadNamedFixture(name: string): Promise<ManifestParityFixture> {
  const here = dirname(fileURLToPath(import.meta.url));
  const fixturePath = join(here, `../fixtures/${name}.json`);
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

  // #915 adversarial-review follow-up (LOW): the slash fixture above only
  // covers happy-path ASCII plus one escaping bug. These vectors broaden the
  // parity surface to the adversarial classes the review named: U+2028/U+2029
  // raw emission, astral scalar pairs, and lone-surrogate fail-closed
  // behavior. See castle-wall-macos/Tests/CastleWallExtensionTests/ManifestParityVectorTests.swift
  // for the Swift-side half of each vector.
  it("unicode-edge vector: U+2028/U+2029 stay raw and astral scalar pairs round-trip byte-identically", async () => {
    const fixture = await loadNamedFixture("manifest-parity-vector-unicode-edge");

    // fortress_id carries raw U+2028/U+2029 -- JSON grammar does not require
    // escaping them (only JS *source text* treats them as line terminators),
    // so both the Node canonicalizer and Swift's Foundation-independent
    // string emitter must pass them through unescaped.
    expect(fixture.manifest_signed_body.fortress_id).toContain(" ");
    expect(fixture.manifest_signed_body.fortress_id).toContain(" ");

    const actualCanonical = new TextEncoder().encode(
      canonicalize(fixture.manifest_signed_body),
    );
    expect(Buffer.from(actualCanonical).toString("hex")).toBe(
      fixture.expected_canonical_json_hex,
    );
    expect(
      Buffer.compare(
        Buffer.from(actualCanonical),
        Buffer.from(fixture.expected_canonical_json_b64, "base64"),
      ),
    ).toBe(0);

    const verified = ed25519.verify(
      Buffer.from(fixture.test_signature_b64url, "base64url"),
      actualCanonical,
      Buffer.from(fixture.test_public_key_b64url, "base64url"),
    );
    expect(verified).toBe(true);

    // Per-rule digest parity, same as the slash vector, but the rule content
    // itself carries the astral pair (rule[0]) and a second astral scalar in
    // an otherwise-ASCII-id rule (rule[1]) -- exercising the digest path,
    // not just the top-level manifest signature.
    const { createHash: sha } = await import("node:crypto");
    let sawAstral = false;
    for (const [index, rule] of fixture.rules.entries()) {
      const ruleCanonical = canonicalize(rule);
      if (/\u{1F600}|\u{1F3F0}/u.test(ruleCanonical)) sawAstral = true;
      const digest = sha("sha256").update(Buffer.from(ruleCanonical)).digest("hex");
      expect(digest).toBe(fixture.manifest_signed_body.rules[index]?.sha256);
    }
    expect(sawAstral).toBe(true);
  });

  it("lone-surrogate vector: Node canonicalizes deterministically where Swift decode fails closed", async () => {
    // Structural incompatibility, not a bug: Swift's String type is
    // Unicode-scalar-based and cannot represent an unpaired surrogate at
    // all, so Foundation's JSONDecoder/JSONSerialization reject this fixture
    // outright (see the Swift-side
    // testLoneSurrogateFixtureFailsClosedOnDecode, which asserts the throw).
    // This TS test only proves the Node half: canonicalize() succeeds and is
    // deterministic (ES2019 "well-formed JSON.stringify" escapes the lone
    // surrogate as \ud800 rather than emitting ill-formed UTF-8), matching
    // "Node JSON.stringify(\"\ud800\") emits \"\\ud800\"" from the #915 review.
    const fixture = await loadNamedFixture("manifest-parity-vector-lone-surrogate");

    expect(fixture.manifest_signed_body.fortress_id).toContain("\ud800");

    const actualCanonical = new TextEncoder().encode(
      canonicalize(fixture.manifest_signed_body),
    );
    expect(Buffer.from(actualCanonical).toString("hex")).toBe(
      fixture.expected_canonical_json_hex,
    );
    // The escaped lone surrogate renders as plain ASCII backslash-u-d800 in
    // the output text, so the canonical bytes are themselves well-formed
    // UTF-8 even though the logical string is not well-formed Unicode.
    expect(Buffer.from(actualCanonical).toString("utf8")).toContain("\\ud800");
  });

  // S5-0 (2026-07-14 two-confined-uid extension): the new `agent_origin.gate_uid`
  // field and a rule carrying `scope.uids` inside the SAME signed body. Proves
  // the TS canonicalizer + signature verify byte-for-byte for the twin-uid
  // shape -- the #1 risk the S5-0 feasibility spike named (cross-language
  // canonical-JSON drift on the new field). See the Swift-side half of this
  // vector in castle-wall-macos/Tests/CastleWallExtensionTests/ManifestParityVectorTests.swift.
  it("two-uid vector: agent_origin.gate_uid and rule scope.uids canonicalize and verify", async () => {
    const fixture = await loadNamedFixture("manifest-parity-vector-two-uid");

    expect(fixture.manifest_signed_body.agent_origin?.gate_uid).toBe(601);
    expect(fixture.rules[1]?.scope.uids).toEqual([601]);

    const actualCanonical = new TextEncoder().encode(
      canonicalize(fixture.manifest_signed_body),
    );
    expect(Buffer.from(actualCanonical).toString("hex")).toBe(
      fixture.expected_canonical_json_hex,
    );
    expect(
      Buffer.compare(
        Buffer.from(actualCanonical),
        Buffer.from(fixture.expected_canonical_json_b64, "base64"),
      ),
    ).toBe(0);

    const verified = ed25519.verify(
      Buffer.from(fixture.test_signature_b64url, "base64url"),
      actualCanonical,
      Buffer.from(fixture.test_public_key_b64url, "base64url"),
    );
    expect(verified).toBe(true);

    // Per-rule digest parity for both rules, including the uids-scoped one.
    const { createHash } = await import("node:crypto");
    for (const [index, rule] of fixture.rules.entries()) {
      const ruleCanonical = canonicalize(rule);
      const digest = createHash("sha256")
        .update(Buffer.from(ruleCanonical))
        .digest("hex");
      expect(digest).toBe(fixture.manifest_signed_body.rules[index]?.sha256);
    }
  });
});
