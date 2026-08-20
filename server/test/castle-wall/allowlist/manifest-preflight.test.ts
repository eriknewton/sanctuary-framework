import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";

import {
  CASTLE_WALL_SCHEMA_VERSION_V1,
  CASTLE_WALL_SIGNATURE_SCHEME_V1,
} from "../../../src/castle-wall/constants.js";
import { canonicalize } from "../../../src/mesh/canonical-json.js";
import { stringToBytes, toBase64url } from "../../../src/core/encoding.js";
import { encodeRuleFilename, parseRuleId } from "../../../src/castle-wall/allowlist/rule-identity.js";
import { preflightPersistedManifestRuleIdentities } from "../../../src/castle-wall/allowlist/manifest-preflight.js";
import type { AllowlistManifest, SignedManifest } from "../../../src/castle-wall/allowlist/manifest.js";

function signedManifest(entries: AllowlistManifest["rules"]): {
  envelope: SignedManifest;
  publicKey: Uint8Array;
} {
  const privateKey = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  const manifest: AllowlistManifest = {
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    fortress_id: "preflight-test",
    issued_at: "2026-08-20T00:00:00.000Z",
    rules: entries,
  };
  return {
    envelope: {
      manifest,
      signature: {
        signature_scheme: CASTLE_WALL_SIGNATURE_SCHEME_V1,
        signing_key_id: "test-key",
        signature_b64url: toBase64url(ed25519.sign(stringToBytes(canonicalize(manifest)), privateKey)),
      },
    },
    publicKey,
  };
}

function validEncodedFilename(id: string): string {
  const parsed = parseRuleId(id);
  if (!parsed.ok) throw new Error(parsed.error);
  return encodeRuleFilename(parsed.value);
}

function sha256Hex(bytes: Uint8Array): string {
  return [...sha256(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("manifest persisted-rule compatibility preflight", () => {
  it("aggregates every persisted relation finding before consuming an unsafe referenced filename", async () => {
    const { envelope, publicKey } = signedManifest([
      { rule_id: "bad/id", file: "bad/id.json", sha256: "0".repeat(64) },
      { rule_id: "safe-id", file: "safe-id.json", sha256: "0".repeat(64) },
      { rule_id: "safe-id", file: "safe-id.json", sha256: "0".repeat(64) },
      { rule_id: "other-id", file: "outside.json", sha256: "0".repeat(64) },
    ]);
    const consumed: string[] = [];

    const report = await preflightPersistedManifestRuleIdentities(envelope, publicKey, {
      readRuleBody: async (filename) => {
        consumed.push(filename);
        throw new Error("must not be called");
      },
    });

    expect(report.signature).toBe("verified");
    expect(report.relation_preflight).toBe("failed");
    expect(report.rule_bodies_scanned).toBe(0);
    expect(report.issue_count).toBe(4);
    expect(report.issues.map((issue) => issue.kind)).toEqual([
      "manifest_relation",
      "manifest_relation",
      "manifest_relation",
      "manifest_relation",
    ]);
    expect(report.issues.map((issue) => issue.entry_index)).toEqual([0, 2, 2, 3]);
    expect(report.issues.map((issue) => issue.rule_id)).toEqual([undefined, "safe-id", "safe-id", "other-id"]);
    expect(JSON.stringify(report)).not.toContain("bad/id");
    expect(consumed).toEqual([]);
  });

  it("scans every validly referenced body and aggregates invalid and mismatched identities", async () => {
    const encoded = validEncodedFilename("encoded-id");
    const legacyBody = stringToBytes(JSON.stringify({ id: "different-id" }));
    const encodedBody = stringToBytes(JSON.stringify({ id: "bad/id" }));
    const { envelope, publicKey } = signedManifest([
      { rule_id: "legacy-id", file: "legacy-id.json", sha256: sha256Hex(legacyBody) },
      { rule_id: "encoded-id", file: encoded, sha256: sha256Hex(encodedBody) },
    ]);
    const bodies = new Map<string, Uint8Array>([
      ["legacy-id.json", legacyBody],
      [encoded, encodedBody],
    ]);

    const report = await preflightPersistedManifestRuleIdentities(envelope, publicKey, {
      readRuleBody: async (filename) => {
        const body = bodies.get(filename);
        if (!body) throw new Error("missing test body");
        return body;
      },
    });

    expect(report.signature).toBe("verified");
    expect(report.relation_preflight).toBe("passed");
    expect(report.rule_bodies_scanned).toBe(2);
    expect(report.issue_count).toBe(3);
    expect(report.issues).toEqual([
      expect.objectContaining({ kind: "rule_body_id", entry_index: 0, rule_id: "legacy-id", message: expect.stringContaining("does not match") }),
      expect.objectContaining({ kind: "rule_body_id", entry_index: 1, rule_id: "encoded-id", message: expect.stringContaining("invalid") }),
      expect.objectContaining({ kind: "rule_body_id", entry_index: 1, rule_id: "encoded-id", message: expect.stringContaining("does not match") }),
    ]);
  });

  it("keeps envelope signature failure separate and refuses every referenced path", async () => {
    const { envelope, publicKey } = signedManifest([
      { rule_id: "safe-id", file: "safe-id.json", sha256: "0".repeat(64) },
    ]);
    const sentinel = `untrusted-signature-scheme-${"x".repeat(8_192)}`;
    (envelope.signature as unknown as { signature_scheme: string }).signature_scheme = sentinel;
    const consumed: string[] = [];

    const report = await preflightPersistedManifestRuleIdentities(
      envelope,
      publicKey,
      {
        readRuleBody: async (filename) => {
          consumed.push(filename);
          return stringToBytes(JSON.stringify({ id: "safe-id" }));
        },
      },
    );

    expect(report.signature).toBe("not_verified");
    expect(report.relation_preflight).toBe("passed");
    expect(report.issue_count).toBe(1);
    expect(report.issues[0]).toEqual({
      kind: "manifest_signature",
      message: "manifest signature verification did not succeed",
    });
    expect(JSON.stringify(report)).not.toContain(sentinel);
    expect(JSON.stringify(report).length).toBeLessThan(1_000);
    expect(consumed).toEqual([]);
  });

  it("returns a bounded signature finding instead of throwing for a malformed signature object", async () => {
    const { envelope, publicKey } = signedManifest([]);
    Object.defineProperty(envelope.signature, "signature_scheme", {
      get: () => {
        throw new Error("malformed signature value");
      },
    });

    const report = await preflightPersistedManifestRuleIdentities(envelope, publicKey, {
      readRuleBody: async () => stringToBytes("{}"),
    });

    expect(report).toMatchObject({
      signature: "not_verified",
      relation_preflight: "passed",
      rule_bodies_scanned: 0,
      issue_count: 1,
      issues: [
        {
          kind: "manifest_signature",
          message: "manifest signature verification could not be completed",
        },
      ],
    });
  });

  it("returns a bounded envelope finding when manifest rule entries cannot be inspected", async () => {
    const { envelope, publicKey } = signedManifest([]);
    Object.defineProperty(envelope.manifest, "rules", {
      get: () => {
        throw new Error("malformed rules accessor");
      },
    });
    const consumed: string[] = [];

    const report = await preflightPersistedManifestRuleIdentities(envelope, publicKey, {
      readRuleBody: async (filename) => {
        consumed.push(filename);
        return stringToBytes("{}");
      },
    });

    expect(report).toMatchObject({
      relation_preflight: "not_checked",
      rule_bodies_scanned: 0,
      issues: expect.arrayContaining([
        {
          kind: "manifest_envelope",
          message: "manifest rule entries could not be inspected",
        },
      ]),
    });
    expect(consumed).toEqual([]);
  });

  it("reports a digest mismatch without drawing a rule-id conclusion", async () => {
    const { envelope, publicKey } = signedManifest([
      { rule_id: "safe-id", file: "safe-id.json", sha256: "0".repeat(64) },
    ]);

    const report = await preflightPersistedManifestRuleIdentities(envelope, publicKey, {
      readRuleBody: async () => stringToBytes(JSON.stringify({ id: "different-id" })),
    });

    expect(report).toMatchObject({
      signature: "verified",
      relation_preflight: "passed",
      rule_bodies_scanned: 1,
      issue_count: 1,
      issues: [
        {
          kind: "rule_body_digest",
          rule_id: "safe-id",
          message: "manifest rule 0: referenced rule body digest does not match manifest",
        },
      ],
    });
  });

  it("reports a typed body-read failure without exposing the reader path", async () => {
    const { envelope, publicKey } = signedManifest([
      { rule_id: "safe-id", file: "safe-id.json", sha256: "0".repeat(64) },
    ]);

    const report = await preflightPersistedManifestRuleIdentities(envelope, publicKey, {
      readRuleBody: async () => {
        throw new Error("/private/secret/rules/safe-id.json");
      },
    });

    expect(report).toMatchObject({
      signature: "verified",
      relation_preflight: "passed",
      issue_count: 1,
      issues: [
        {
          kind: "rule_body_read",
          rule_id: "safe-id",
          message: "manifest rule 0: referenced rule body could not be read",
        },
      ],
    });
    expect(JSON.stringify(report)).not.toContain("/private/secret");
  });

  it("caps rendered detail while retaining the full finding count", async () => {
    const { envelope, publicKey } = signedManifest(
      Array.from({ length: 101 }, (_, index) => ({
        rule_id: `safe-${index}`,
        file: "outside.json",
        sha256: "0".repeat(64),
      })),
    );

    const report = await preflightPersistedManifestRuleIdentities(envelope, publicKey, {
      readRuleBody: async () => stringToBytes("{}"),
    });

    expect(report.relation_preflight).toBe("failed");
    expect(report.issue_count).toBe(201);
    expect(report.issues).toHaveLength(100);
    expect(report.omitted_issue_count).toBe(101);
  });
});
