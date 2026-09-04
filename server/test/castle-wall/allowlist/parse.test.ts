/**
 * Castle Wall allowlist manifest parse + verify tests.
 *
 * Exercises verifyManifestSignature (Ed25519) and verifyAndParseRules
 * (SHA-256 + schema gate) on real-shape inputs.
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import {
  CASTLE_WALL_SCHEMA_VERSION_V1,
  CASTLE_WALL_SIGNATURE_SCHEME_V1,
} from "../../../src/castle-wall/constants.js";
import { canonicalize } from "../../../src/mesh/canonical-json.js";
import { toBase64url, stringToBytes } from "../../../src/core/encoding.js";
import {
  castleWallSigningKeyId,
  legacyCastleWallSigningKeyId,
  verifyManifestSignature,
  verifyAndParseRules,
  type RuleFileBytes,
} from "../../../src/castle-wall/allowlist/parse.js";
import type {
  AllowlistManifest,
  SignedManifest,
  ManifestRuleEntry,
} from "../../../src/castle-wall/allowlist/manifest.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i] ?? 0;
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

function makeRule(id: string): AllowlistRule {
  return {
    id,
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: "2026-05-03T12:00:00.000Z",
    match: { host: `api.${id}.example.com`, port: 443, protocol: "tcp" },
    scope: { template_ids: ["claude-code"] },
    disposition: "allow",
  };
}

interface Fixture {
  signed: SignedManifest;
  ruleFiles: Map<string, Uint8Array>;
  pinnedPubkey: Uint8Array;
}

function buildSignedManifest(ruleIds: string[]): Fixture {
  const privateKey = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(privateKey);

  const ruleFiles = new Map<string, Uint8Array>();
  const ruleEntries: ManifestRuleEntry[] = [];
  for (const id of ruleIds) {
    const rule = makeRule(id);
    const bytes = stringToBytes(JSON.stringify(rule));
    const filePath = `${id}.json`;
    ruleFiles.set(filePath, bytes);
    ruleEntries.push({
      rule_id: id,
      file: filePath,
      sha256: toHex(sha256(bytes)),
    });
  }

  const manifest: AllowlistManifest = {
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    fortress_id: "fortress-test-001",
    issued_at: "2026-05-03T12:00:00.000Z",
    rules: ruleEntries,
  };

  const payloadBytes = stringToBytes(canonicalize(manifest));
  const signature = ed25519.sign(payloadBytes, privateKey);

  const signed: SignedManifest = {
    manifest,
    signature: {
      signature_scheme: CASTLE_WALL_SIGNATURE_SCHEME_V1,
      signing_key_id: castleWallSigningKeyId(publicKey),
      signature_b64url: toBase64url(signature),
    },
  };

  return { signed, ruleFiles, pinnedPubkey: publicKey };
}

describe("castle-wall/allowlist/parse : manifest signature", () => {
  it("derives the same canonical signing-key fingerprint as Rust", () => {
    const publicKey = Uint8Array.from(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        .match(/../g)!
        .map((byte) => Number.parseInt(byte, 16))
    );
    expect(castleWallSigningKeyId(publicKey)).toBe("21fe31dfa154a261");
  });

  it("verifies a well-formed signed manifest", () => {
    const f = buildSignedManifest(["rule-a", "rule-b"]);
    const result = verifyManifestSignature(f.signed, f.pinnedPubkey);
    expect(result.ok).toBe(true);
  });

  it("accepts the one-release legacy key id while keeping the canonical publisher id", () => {
    const f = buildSignedManifest(["rule-a"]);
    const canonical = castleWallSigningKeyId(f.pinnedPubkey);
    const legacy = legacyCastleWallSigningKeyId(f.pinnedPubkey);
    expect(legacy).toMatch(/^castle-wall:/);
    expect(legacy).not.toBe(canonical);
    f.signed.signature.signing_key_id = legacy;
    expect(verifyManifestSignature(f.signed, f.pinnedPubkey).ok).toBe(true);
    expect(castleWallSigningKeyId(f.pinnedPubkey)).toBe(canonical);
  });

  it("rejects a manifest signed by an unrelated key", () => {
    const f = buildSignedManifest(["rule-a"]);
    const wrongPub = ed25519.getPublicKey(ed25519.utils.randomSecretKey());
    const result = verifyManifestSignature(f.signed, wrongPub);
    expect(result.ok).toBe(false);
  });

  it("rejects a valid signature whose signing-key identifier was relabelled", () => {
    const f = buildSignedManifest(["rule-a"]);
    f.signed.signature.signing_key_id = "castle-wall:attacker-label";
    const result = verifyManifestSignature(f.signed, f.pinnedPubkey);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("signing_key_id");
  });

  it("rejects unsupported signature_scheme", () => {
    const f = buildSignedManifest(["rule-a"]);
    const tampered: SignedManifest = {
      ...f.signed,
      signature: { ...f.signed.signature, signature_scheme: "rsa-v1" as unknown as typeof f.signed.signature.signature_scheme },
    };
    const result = verifyManifestSignature(tampered, f.pinnedPubkey);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("signature_scheme");
  });

  it("rejects a tampered manifest body (signature no longer matches)", () => {
    const f = buildSignedManifest(["rule-a"]);
    const tampered: SignedManifest = {
      ...f.signed,
      manifest: { ...f.signed.manifest, fortress_id: "evil-fortress" },
    };
    const result = verifyManifestSignature(tampered, f.pinnedPubkey);
    expect(result.ok).toBe(false);
  });

  it("rejects a manifest with unsupported schema_version", () => {
    const f = buildSignedManifest(["rule-a"]);
    const bad: SignedManifest = {
      ...f.signed,
      manifest: { ...f.signed.manifest, schema_version: 99 as unknown as typeof CASTLE_WALL_SCHEMA_VERSION_V1 },
    };
    const result = verifyManifestSignature(bad, f.pinnedPubkey);
    expect(result.ok).toBe(false);
  });
});

describe("castle-wall/allowlist/parse : rule body verification", () => {
  it("preflights every manifest identity issue before consuming an unsafe filename", () => {
    const f = buildSignedManifest(["rule-a"]);
    f.signed.manifest.rules.push({
      rule_id: "rule-a",
      file: "rule-a.json",
      sha256: "00",
    });
    f.signed.manifest.rules.push({
      rule_id: "unsafe/path",
      file: "unsafe/path.json",
      sha256: "00",
    });
    let reads = 0;
    class ReadTrackingMap extends Map<string, Uint8Array> {
      override get(key: string): Uint8Array | undefined {
        reads += 1;
        return super.get(key);
      }
    }
    const result = verifyAndParseRules(f.signed, new ReadTrackingMap());
    expect(result.ok).toBe(false);
    expect(reads).toBe(0);
    if (!result.ok) expect(result.issues).toHaveLength(3);
  });

  it("parses every rule when manifest references match disk bytes", () => {
    const f = buildSignedManifest(["rule-a", "rule-b", "rule-c"]);
    const result = verifyAndParseRules(f.signed, f.ruleFiles as RuleFileBytes);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.length).toBe(3);
  });

  it("flags missing rule files", () => {
    const f = buildSignedManifest(["rule-a", "rule-b"]);
    const partial = new Map(f.ruleFiles);
    partial.delete("rule-b.json");
    const result = verifyAndParseRules(f.signed, partial);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.issues?.some((s) => s.includes("missing"))).toBe(true);
  });

  it("flags sha256 mismatch when a rule file has been altered", () => {
    const f = buildSignedManifest(["rule-a"]);
    const tampered = new Map(f.ruleFiles);
    tampered.set("rule-a.json", stringToBytes('{"id":"rule-a","tampered":true}'));
    const result = verifyAndParseRules(f.signed, tampered);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.issues?.some((s) => s.includes("sha256 mismatch"))).toBe(true);
  });

  it("flags rule whose internal id does not match manifest entry", () => {
    const privateKey = ed25519.utils.randomSecretKey();
    const publicKey = ed25519.getPublicKey(privateKey);

    const declaredRule = makeRule("rule-mismatch-claim");
    const declaredBytes = stringToBytes(JSON.stringify(declaredRule));
    const fileEntry: ManifestRuleEntry = {
      rule_id: "rule-different-id",
      file: "rule-different-id.json",
      sha256: toHex(sha256(declaredBytes)),
    };

    const manifest: AllowlistManifest = {
      schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
      fortress_id: "fortress-test",
      issued_at: "2026-05-03T12:00:00.000Z",
      rules: [fileEntry],
    };
    const sig = ed25519.sign(stringToBytes(canonicalize(manifest)), privateKey);
    const signed: SignedManifest = {
      manifest,
      signature: {
        signature_scheme: CASTLE_WALL_SIGNATURE_SCHEME_V1,
        signing_key_id: castleWallSigningKeyId(publicKey),
        signature_b64url: toBase64url(sig),
      },
    };
    expect(verifyManifestSignature(signed, publicKey).ok).toBe(true);

    const ruleFiles = new Map<string, Uint8Array>([["rule-different-id.json", declaredBytes]]);
    const result = verifyAndParseRules(signed, ruleFiles);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.issues?.some((s) => s.includes("declares id"))).toBe(true);
  });
});
