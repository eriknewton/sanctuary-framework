/**
 * Castle Wall manifest publisher tests.
 *
 * Asserts:
 *  - buildSignedManifest produces a SignedManifest verifiable by the
 *    PR-1 parse.ts verifier (round-trip through the consumer surface);
 *  - publishSignedManifest performs writes-then-rename per scope-lock §4
 *    atomicity;
 *  - orphaned rule files are removed only AFTER the manifest is in place.
 *
 * B2: buildSignedManifest now takes an async `ManifestSigner` handle instead of
 * raw key material. These tests use `localManifestSigner` to wrap a local key —
 * the production daemon uses a helper-backed signer (no key bytes in-process).
 */

import { describe, it, expect, beforeEach } from "vitest";

import {
  buildSignedManifest,
  publishSignedManifest,
  renderRuleFile,
  renderSignedManifest,
  sha256Hex,
  localManifestSigner,
  type ManifestStorage,
  type ManifestSigner,
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
import {
  DERIVED_DNS_RULE_ID,
  deriveDnsRuleForHostnameRules,
} from "../../../src/castle-wall/allowlist/dns-derivation.js";

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
  let signer: ManifestSigner;
  let pinnedPublicKey: Uint8Array;

  beforeEach(() => {
    const masterKey = generateRandomKey();
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const { publicIdentity, storedIdentity } = createIdentity(
      "castle-wall-test",
      identityEncKey,
      "passphrase"
    );
    signer = localManifestSigner({
      signingKeyId: storedIdentity.identity_id,
      encryptedPrivateKey: storedIdentity.encrypted_private_key,
      encryptionKey: identityEncKey,
    });
    pinnedPublicKey = fromBase64url(publicIdentity.public_key);
  });

  it("produces a signed manifest the PR-1 parser verifies", async () => {
    const { signed } = await buildSignedManifest({
      fortressId: "deadbeef",
      issuedAt: "2026-05-04T00:00:00Z",
      rules: [makeRule("rule-1", "api.anthropic.com")],
      signer,
    });

    expect(signed.signature.signature_scheme).toBe(CASTLE_WALL_SIGNATURE_SCHEME_V1);
    expect(signed.manifest.schema_version).toBe(CASTLE_WALL_SCHEMA_VERSION_V1);

    const result = verifyManifestSignature(signed, pinnedPublicKey);
    expect(result.ok).toBe(true);
  });

  it("orders rules by rule_id deterministically", async () => {
    const { signed } = await buildSignedManifest({
      fortressId: "f",
      issuedAt: "t",
      rules: [
        makeRule("rule-c", "c.example"),
        makeRule("rule-a", "a.example"),
        makeRule("rule-b", "b.example"),
      ],
      signer,
    });
    const ids = signed.manifest.rules.map((r) => r.rule_id);
    expect(ids).toEqual(["rule-a", "rule-b", "rule-c"]);
  });

  it("signs a valid operator_baseline into the manifest body", async () => {
    const { signed } = await buildSignedManifest({
      fortressId: "f",
      issuedAt: "t",
      rules: [makeRule("rule-1", "api.anthropic.com")],
      signer,
      operatorBaseline: {
        essentials: [
          {
            name: "tailscaled",
            signing_id: "com.tailscale.ipn.macos.network-extension",
          },
          {
            name: "sshd",
            source_app_identifier: "com.openssh.sshd",
          },
        ],
      },
    });

    expect(signed.manifest.operator_baseline).toEqual({
      essentials: [
        {
          name: "sshd",
          source_app_identifier: "com.openssh.sshd",
        },
        {
          name: "tailscaled",
          signing_id: "com.tailscale.ipn.macos.network-extension",
        },
      ],
    });
    expect(verifyManifestSignature(signed, pinnedPublicKey).ok).toBe(true);
  });

  it("omits malformed operator_baseline candidates", async () => {
    const { signed } = await buildSignedManifest({
      fortressId: "f",
      issuedAt: "t",
      rules: [makeRule("rule-1", "api.anthropic.com")],
      signer,
      operatorBaseline: {
        essentials: [{ name: "tailscaled" }],
      },
    });

    expect(signed.manifest).not.toHaveProperty("operator_baseline");
    expect(verifyManifestSignature(signed, pinnedPublicKey).ok).toBe(true);
  });

  it("rejects duplicate rule ids", async () => {
    await expect(
      buildSignedManifest({
        fortressId: "f",
        issuedAt: "t",
        rules: [makeRule("dup", "a"), makeRule("dup", "b")],
        signer,
      })
    ).rejects.toThrow(/duplicate rule id/);
  });

  it("renderRuleFile emits canonical-JSON bytes", () => {
    const rule = makeRule("rule-1", "host");
    const bytes = renderRuleFile(rule);
    expect(bytes.byteLength).toBeGreaterThan(0);
    expect(sha256Hex(bytes)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("manifest entries use sha256 of the rule file bytes the publisher emitted", async () => {
    const rule = makeRule("rule-1", "api.anthropic.com");
    const { signed, ruleFiles } = await buildSignedManifest({
      fortressId: "f",
      issuedAt: "t",
      rules: [rule],
      signer,
    });
    const entry = signed.manifest.rules[0]!;
    const file = ruleFiles[0]!;
    expect(entry.sha256).toBe(sha256Hex(file.bytes));
  });

  it("publishes the derived DNS rule with the captured stable digest", async () => {
    const hostnameRule: AllowlistRule = {
      id: "allow-openrouter",
      schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
      created_at: "2026-06-11T00:14:32Z",
      description: "Agent may reach inference endpoint",
      match: { host: "openrouter.ai", port: 443, protocol: "tcp" },
      scope: {},
      disposition: "allow",
    };
    const denyRule: AllowlistRule = {
      id: "deny-exfil",
      schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
      created_at: "2026-06-11T00:14:32Z",
      description: "Pinned benign exfil target",
      match: { host: "1.1.1.1" },
      scope: {},
      disposition: "deny",
    };
    const derivedDns = deriveDnsRuleForHostnameRules({
      rules: [hostnameRule, denyRule],
      resolvers: ["100.100.100.100", "fd7a:115c:a1e0::53", "192.168.4.1"],
      createdAt: "2026-06-11T18:47:42.985Z",
    });
    expect(derivedDns).not.toBeNull();

    const { signed, ruleFiles } = await buildSignedManifest({
      fortressId: "fortress-capture",
      issuedAt: "2026-06-11T18:47:42.986Z",
      rules: [hostnameRule, denyRule, derivedDns!],
      signer,
      agentOrigin: {
        mode: "uid",
        agent_uid: 502,
        system_uid_allow_ceiling: 500,
      },
      operatorBaseline: {
        essentials: [
          { name: "mdnsresponder", signing_id: "com.apple.mDNSResponder" },
          { name: "screensharing", signing_id: "com.apple.screensharing.agent" },
          { name: "sshd", signing_id: "com.openssh.sshd" },
          {
            name: "tailscaled",
            signing_id: "io.tailscale.ipn.macsys.network-extension",
          },
        ],
      },
    });

    const derivedEntry = signed.manifest.rules.find(
      (entry) => entry.rule_id === DERIVED_DNS_RULE_ID
    );
    expect(derivedEntry).toEqual({
      rule_id: DERIVED_DNS_RULE_ID,
      file: `${DERIVED_DNS_RULE_ID}.json`,
      sha256: "5fc5aba5ae6c1e5dfd907528759ff73038d3a6ed7351499d51c84c90843ab26e",
    });
    expect(signed.manifest.rules).toHaveLength(3);
    expect(ruleFiles.map((file) => file.filename)).toContain(
      `${DERIVED_DNS_RULE_ID}.json`
    );
  });

  // --- agent_origin descriptor (2026-05-29 origin-classifier foundation) ---

  it("signs a valid agent_origin into the body and the parser still verifies", async () => {
    const { signed } = await buildSignedManifest({
      fortressId: "f",
      issuedAt: "t",
      rules: [makeRule("rule-1", "api.anthropic.com")],
      signer,
      agentOrigin: {
        mode: "uid",
        agent_uid: 600,
        system_uid_allow_ceiling: 500,
      },
    });
    expect(signed.manifest.agent_origin).toEqual({
      mode: "uid",
      agent_uid: 600,
      system_uid_allow_ceiling: 500,
    });
    // The descriptor is part of the signed body: signature still verifies.
    expect(verifyManifestSignature(signed, pinnedPublicKey).ok).toBe(true);
  });

  it("tampering with agent_origin AFTER signing breaks verification", async () => {
    const { signed } = await buildSignedManifest({
      fortressId: "f",
      issuedAt: "t",
      rules: [makeRule("rule-1", "api.anthropic.com")],
      signer,
      agentOrigin: {
        mode: "uid",
        agent_uid: 600,
        system_uid_allow_ceiling: 500,
      },
    });
    // Attacker flips the agent uid post-signing.
    const tampered = {
      ...signed,
      manifest: {
        ...signed.manifest,
        agent_origin: { mode: "uid" as const, agent_uid: 0, system_uid_allow_ceiling: 500 },
      },
    };
    expect(verifyManifestSignature(tampered, pinnedPublicKey).ok).toBe(false);
  });

  it("omits agent_origin entirely when absent (byte-identical to no-field build)", async () => {
    const withoutField = await buildSignedManifest({
      fortressId: "f",
      issuedAt: "t",
      rules: [makeRule("rule-1", "api.anthropic.com")],
      signer,
    });
    expect(withoutField.signed.manifest).not.toHaveProperty("agent_origin");
    // Canonical bytes carry no agent_origin key.
    const bytes = renderSignedManifest(withoutField.signed);
    expect(new TextDecoder().decode(bytes)).not.toContain("agent_origin");
  });

  it("drops a malformed agent_origin candidate (field omitted, never half-built)", async () => {
    const { signed } = await buildSignedManifest({
      fortressId: "f",
      issuedAt: "t",
      rules: [makeRule("rule-1", "api.anthropic.com")],
      signer,
      // UID mode with no agent_uid is unusable -> dropped.
      agentOrigin: { mode: "uid", system_uid_allow_ceiling: 500 },
    });
    expect(signed.manifest).not.toHaveProperty("agent_origin");
    expect(verifyManifestSignature(signed, pinnedPublicKey).ok).toBe(true);
  });

  it("verifyAndParseRules accepts the bytes the publisher produced", async () => {
    const rule = makeRule("rule-1", "api.anthropic.com");
    const { signed, ruleFiles } = await buildSignedManifest({
      fortressId: "f",
      issuedAt: "t",
      rules: [rule],
      signer,
    });
    const map = new Map<string, Uint8Array>();
    for (const f of ruleFiles) map.set(f.filename, f.bytes);
    const result = verifyAndParseRules(signed, map);
    expect(result.ok).toBe(true);
  });

  it("propagates a signer failure as a publish error (fail-closed)", async () => {
    const failingSigner: ManifestSigner = {
      signingKeyId: "broken",
      sign() {
        throw new Error("helper unreachable");
      },
    };
    await expect(
      buildSignedManifest({
        fortressId: "f",
        issuedAt: "t",
        rules: [makeRule("rule-1", "a")],
        signer: failingSigner,
      })
    ).rejects.toThrow(/manifest signing failed/);
  });
});

describe("castle-wall/runtime/manifest-publisher : publishSignedManifest", () => {
  let signer: ManifestSigner;

  beforeEach(() => {
    const masterKey = generateRandomKey();
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const { storedIdentity } = createIdentity(
      "publisher-test",
      identityEncKey,
      "passphrase"
    );
    signer = localManifestSigner({
      signingKeyId: storedIdentity.identity_id,
      encryptedPrivateKey: storedIdentity.encrypted_private_key,
      encryptionKey: identityEncKey,
    });
  });

  it("writes rule files BEFORE the atomic manifest rename", async () => {
    const storage = new InMemoryStorage();
    await publishSignedManifest(
      {
        fortressId: "f",
        issuedAt: "t",
        rules: [makeRule("rule-a", "a")],
        signer,
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
        signer,
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
        signer,
      },
      storage
    );
    expect(
      storage.writeOrder.some((s) => s === "removeRule:manifest.json")
    ).toBe(false);
  });

  it("renderSignedManifest produces non-empty bytes", async () => {
    const { signed } = await buildSignedManifest({
      fortressId: "f",
      issuedAt: "t",
      rules: [makeRule("rule-1", "a")],
      signer,
    });
    const bytes = renderSignedManifest(signed);
    expect(bytes.byteLength).toBeGreaterThan(0);
  });
});
