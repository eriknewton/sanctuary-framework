import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";

import { canonicalize } from "../../../src/mesh/canonical-json.js";
import type {
  AllowlistManifest,
  SignedManifest,
} from "../../../src/castle-wall/allowlist/manifest.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";

interface ManifestParityFixture {
  manifest_signed_body: AllowlistManifest;
  rules: AllowlistRule[];
  expected_canonical_json_b64: string;
  expected_canonical_json_hex: string;
  test_public_key_b64url: string;
  test_signature_b64url: string;
}

interface ManifestSignatureCase {
  name: string;
  signed_manifest: SignedManifest;
  expected_canonical_json_b64: string;
  expected_canonical_json_hex: string;
  test_signature_b64url: string;
}

interface ManifestSignatureFixture {
  test_public_key_b64url: string;
  cases: ManifestSignatureCase[];
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

async function loadSignatureFixture(name: string): Promise<ManifestSignatureFixture> {
  const here = dirname(fileURLToPath(import.meta.url));
  const fixturePath = join(here, `../fixtures/${name}.json`);
  return JSON.parse(await readFile(fixturePath, "utf8")) as ManifestSignatureFixture;
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

  it("exclusive-routing vector (S5-4): gate-scoped provisioned rule + agent-scoped gate channel canonicalize and verify", async () => {
    const fixture = await loadNamedFixture("manifest-parity-vector-exclusive-routing");

    // The S5-4 composition shapes: the provisioned endpoint rule is RE-SCOPED
    // to the gate principal (601), and the derived gate-channel rule binds to
    // the AGENT principal (600). Regenerate both from the REAL producers so
    // the fixture can never drift from what the composition actually emits.
    expect(fixture.manifest_signed_body.agent_origin?.gate_uid).toBe(601);
    expect(fixture.rules[0]?.scope.uids).toEqual([601]);
    expect(fixture.rules[1]?.id).toBe("derived_exclusive_egress_gate");
    expect(fixture.rules[1]?.scope.uids).toEqual([600]);

    const { buildProvisionedEgressRules } = await import(
      "../../../src/castle-wall/provision/egress.js"
    );
    const { deriveGateAllowRule } = await import(
      "../../../src/castle-wall/allowlist/gate-derivation.js"
    );
    const createdAt = fixture.rules[0]!.created_at;
    const [expectedProvisioned] = buildProvisionedEgressRules(
      {
        harnessId: "hermes",
        endpoints: [
          {
            name: "LLM (Venice)",
            host: "api.venice.ai",
            port: 443,
            protocol: "tcp",
            riskClass: "standard",
          },
        ],
      },
      createdAt,
      { mode: "exclusive", gate_uid: 601 },
    );
    expect(fixture.rules[0]).toEqual(expectedProvisioned);
    expect(fixture.rules[1]).toEqual(
      deriveGateAllowRule({ agent_uid: 600, gate_port: 49152 }, createdAt, {
        scope_to_agent_uid: true,
      }),
    );

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

    // Per-rule digest parity for both S5-4 shapes.
    const { createHash } = await import("node:crypto");
    for (const [index, rule] of fixture.rules.entries()) {
      const ruleCanonical = canonicalize(rule);
      const digest = createHash("sha256")
        .update(Buffer.from(ruleCanonical))
        .digest("hex");
      expect(digest).toBe(fixture.manifest_signed_body.rules[index]?.sha256);
    }
  });

  it("operator-baseline signature fixture: TS canonicalizer verifies all Rust-consumed cases", async () => {
    const fixture = await loadSignatureFixture("manifest-operator-baseline-cross-lang");
    const cases = new Map(fixture.cases.map((entry) => [entry.name, entry]));

    expect(cases.get("without-operator-baseline")?.signed_manifest.manifest)
      .not.toHaveProperty("operator_baseline");
    expect(
      cases.get("with-operator-baseline")?.signed_manifest.manifest.operator_baseline,
    ).toEqual({
      essentials: [
        {
          name: "allfields",
          signing_id: "com.example.operator.allfields",
          team_id: "TEAM123456",
          source_app_identifier: "com.example.operator.source",
        },
        {
          name: "teamonly",
          team_id: "TEAM654321",
        },
      ],
    });
    expect(
      cases.get("empty-operator-baseline")?.signed_manifest.manifest.operator_baseline,
    ).toEqual({ essentials: [] });

    for (const entry of fixture.cases) {
      const actualCanonical = new TextEncoder().encode(
        canonicalize(entry.signed_manifest.manifest),
      );
      expect(Buffer.from(actualCanonical).toString("hex")).toBe(
        entry.expected_canonical_json_hex,
      );
      expect(
        Buffer.compare(
          Buffer.from(actualCanonical),
          Buffer.from(entry.expected_canonical_json_b64, "base64"),
        ),
      ).toBe(0);
      expect(entry.signed_manifest.signature.signature_b64url).toBe(
        entry.test_signature_b64url,
      );
      expect(
        ed25519.verify(
          Buffer.from(entry.test_signature_b64url, "base64url"),
          actualCanonical,
          Buffer.from(fixture.test_public_key_b64url, "base64url"),
        ),
      ).toBe(true);
    }
  });
});
