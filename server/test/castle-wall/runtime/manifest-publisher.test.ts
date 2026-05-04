/**
 * Castle Wall manifest publisher tests.
 *
 * Asserts:
 *  - buildSignedManifest produces a SignedManifest verifiable by the
 *    PR-1 parse.ts verifier (round-trip through the consumer surface);
 *  - publishSignedManifest performs writes-then-rename per scope-lock §4
 *    atomicity;
 *  - orphaned rule files are removed only AFTER the manifest is in place.
 */

import { describe, it, expect, beforeEach } from "vitest";

import {
  buildSignedManifest,
  publishSignedManifest,
  renderRuleFile,
  renderSignedManifest,
  sha256Hex,
  type ManifestStorage,
  type ManifestSigningKey,
} from "../../../src/castle-wall/runtime/manifest-publisher.js";
import {
  verifyAndParseRules,
  verifyManifestSignature,
} from "../../../src/castle-wall/allowlist/parse.js";
import {
  CASTLE_WALL_SCHEMA_VERSION_V1,
  CASTLE_WALL_SIGNATURE_SCHEME_V1,
} from "../../../src/castle-wall/constants.js";
import {
  createIdentity,
  publicKeyToDid as _did,
} from "../../../src/core/identity.js";
import { fromBase64url } from "../../../src/core/encoding.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { derivePurposeKey } from "../../../src/core/key-derivation.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";

void _did;

class InMemoryStorage implements ManifestStorage {
  rules = new Map<string, Uint8Array>();
  manifestBytes: Uint8Array | null = null;
  writeOrder: string[] = [];

  async writeRule(filename: string, bytes: Uint8Array): Promise<void> {
    this.rules.set(filename, bytes);
    this.writeOrder.push(`writeRule:${filename}`);
  }
  async atomicRenameManifest(bytes: Uint8Array): Promise<void> {
    this.manifestBytes = bytes;
    this.writeOrder.push("atomicRenameManifest");
  }
  async listRules(): Promise<string[]> {
    return Array.from(this.rules.keys());
  }
  async removeRule(filename: string): Promise<void> {
    this.rules.delete(filename);
    this.writeOrder.push(`removeRule:${filename}`);
  }
}

function makeRule(id: string, host: string): AllowlistRule {
  return {
    id,
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: "2026-05-04T00:00:00Z",
    description: `${host} test rule`,
    match: { host: [host], port: [443], protocol: "tcp" },
    scope: {},
    disposition: "allow",
  };
}

describe("castle-wall/runtime/manifest-publisher : buildSignedManifest", () => {
  let signingKey: ManifestSigningKey;
  let pinnedPublicKey: Uint8Array;

  beforeEach(() => {
    const masterKey = generateRandomKey();
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const { publicIdentity, storedIdentity } = createIdentity(
      "castle-wall-test",
      identityEncKey,
      "passphrase"
    );
    signingKey = {
      signingKeyId: storedIdentity.identity_id,
      encryptedPrivateKey: storedIdentity.encrypted_private_key,
      encryptionKey: identityEncKey,
    };
    pinnedPublicKey = fromBase64url(publicIdentity.public_key);
  });

  it("produces a signed manifest the PR-1 parser verifies", () => {
    const { signed } = buildSignedManifest({
      fortressId: "deadbeef",
      issuedAt: "2026-05-04T00:00:00Z",
      rules: [makeRule("rule-1", "api.anthropic.com")],
      signingKey,
    });

    expect(signed.signature.signature_scheme).toBe(CASTLE_WALL_SIGNATURE_SCHEME_V1);
    expect(signed.manifest.schema_version).toBe(CASTLE_WALL_SCHEMA_VERSION_V1);

    const result = verifyManifestSignature(signed, pinnedPublicKey);
    expect(result.ok).toBe(true);
  });

  it("orders rules by rule_id deterministically", () => {
    const { signed } = buildSignedManifest({
      fortressId: "f",
      issuedAt: "t",
      rules: [
        makeRule("rule-c", "c.example"),
        makeRule("rule-a", "a.example"),
        makeRule("rule-b", "b.example"),
      ],
      signingKey,
    });
    const ids = signed.manifest.rules.map((r) => r.rule_id);
    expect(ids).toEqual(["rule-a", "rule-b", "rule-c"]);
  });

  it("rejects duplicate rule ids", () => {
    expect(() =>
      buildSignedManifest({
        fortressId: "f",
        issuedAt: "t",
        rules: [makeRule("dup", "a"), makeRule("dup", "b")],
        signingKey,
      })
    ).toThrow(/duplicate rule id/);
  });

  it("renderRuleFile emits canonical-JSON bytes", () => {
    const rule = makeRule("rule-1", "host");
    const bytes = renderRuleFile(rule);
    expect(bytes.byteLength).toBeGreaterThan(0);
    expect(sha256Hex(bytes)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("manifest entries use sha256 of the rule file bytes the publisher emitted", () => {
    const rule = makeRule("rule-1", "api.anthropic.com");
    const { signed, ruleFiles } = buildSignedManifest({
      fortressId: "f",
      issuedAt: "t",
      rules: [rule],
      signingKey,
    });
    const entry = signed.manifest.rules[0]!;
    const file = ruleFiles[0]!;
    expect(entry.sha256).toBe(sha256Hex(file.bytes));
  });

  it("verifyAndParseRules accepts the bytes the publisher produced", () => {
    const rule = makeRule("rule-1", "api.anthropic.com");
    const { signed, ruleFiles } = buildSignedManifest({
      fortressId: "f",
      issuedAt: "t",
      rules: [rule],
      signingKey,
    });
    const map = new Map<string, Uint8Array>();
    for (const f of ruleFiles) map.set(f.filename, f.bytes);
    const result = verifyAndParseRules(signed, map);
    expect(result.ok).toBe(true);
  });
});

describe("castle-wall/runtime/manifest-publisher : publishSignedManifest", () => {
  let signingKey: ManifestSigningKey;

  beforeEach(() => {
    const masterKey = generateRandomKey();
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const { storedIdentity } = createIdentity(
      "publisher-test",
      identityEncKey,
      "passphrase"
    );
    signingKey = {
      signingKeyId: storedIdentity.identity_id,
      encryptedPrivateKey: storedIdentity.encrypted_private_key,
      encryptionKey: identityEncKey,
    };
  });

  it("writes rule files BEFORE the atomic manifest rename", async () => {
    const storage = new InMemoryStorage();
    await publishSignedManifest(
      {
        fortressId: "f",
        issuedAt: "t",
        rules: [makeRule("rule-a", "a")],
        signingKey,
      },
      storage
    );
    const order = storage.writeOrder;
    const ruleIdx = order.findIndex((s) => s.startsWith("writeRule:"));
    const renameIdx = order.findIndex((s) => s === "atomicRenameManifest");
    expect(ruleIdx).toBeGreaterThanOrEqual(0);
    expect(renameIdx).toBeGreaterThan(ruleIdx);
  });

  it("removes orphan rule files AFTER the manifest is in place", async () => {
    const storage = new InMemoryStorage();
    storage.rules.set("orphan.json", new Uint8Array([1, 2, 3]));
    await publishSignedManifest(
      {
        fortressId: "f",
        issuedAt: "t",
        rules: [makeRule("rule-a", "a")],
        signingKey,
      },
      storage
    );
    const renameIdx = storage.writeOrder.findIndex((s) => s === "atomicRenameManifest");
    const removeIdx = storage.writeOrder.findIndex((s) =>
      s.startsWith("removeRule:")
    );
    expect(renameIdx).toBeGreaterThanOrEqual(0);
    expect(removeIdx).toBeGreaterThan(renameIdx);
  });

  it("does not remove the live manifest", async () => {
    const storage = new InMemoryStorage();
    await publishSignedManifest(
      {
        fortressId: "f",
        issuedAt: "t",
        rules: [makeRule("rule-a", "a")],
        signingKey,
      },
      storage
    );
    expect(
      storage.writeOrder.some((s) => s === "removeRule:manifest.json")
    ).toBe(false);
  });

  it("renderSignedManifest produces non-empty bytes", () => {
    const { signed } = buildSignedManifest({
      fortressId: "f",
      issuedAt: "t",
      rules: [makeRule("rule-1", "a")],
      signingKey,
    });
    const bytes = renderSignedManifest(signed);
    expect(bytes.byteLength).toBeGreaterThan(0);
  });
});
