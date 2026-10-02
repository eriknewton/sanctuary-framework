/** Workstation signing binds explicit Linux identity before publishing bytes. */
import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { buildInstallBundle } from "../../src/cli/linux-policy-sign.js";
import { castleWallSigningKeyId, verifyManifestSignature } from "../../src/castle-wall/allowlist/parse.js";
import type { SignedManifest } from "../../src/castle-wall/allowlist/manifest.js";
import { composeEffectiveRules } from "../../src/castle-wall/allowlist/habeas-port.js";
import { buildSignedManifest } from "../../src/castle-wall/runtime/manifest-publisher.js";

const seed = new Uint8Array(32).fill(7);
const publicKey = ed25519.getPublicKey(seed);
const signer = { signingKeyId: castleWallSigningKeyId(publicKey), sign: (b: Uint8Array) => ed25519.sign(b, seed) };
const input = { fortressId: "0123456789abcdef", generation: 10, issuedAt: "2026-10-01T00:00:00Z", rules: [], signer, agentOrigin: { mode: "uid", agent_uid: 60123, system_uid_allow_ceiling: 1000 } };
describe("install policy signer", () => {
  it("uses the existing producer's exact manifest bytes", async () => {
    const bundle = await buildInstallBundle(input, publicKey);
    const signed = JSON.parse(Buffer.from(bundle.manifest_b64url, "base64url").toString()) as SignedManifest;
    expect(signed).toEqual((await buildSignedManifest({ ...input, rules: composeEffectiveRules({ operatorRules: [], resolvers: [], createdAt: input.issuedAt }) })).signed);
    expect(verifyManifestSignature(signed, publicKey).ok).toBe(true);
    expect(bundle.rules).toHaveLength(1);
  });
  it.each([undefined, null, {}, { mode: "nat", system_uid_allow_ceiling: 1000 }, { mode: "uid", agent_uid: 0, system_uid_allow_ceiling: 1000 }, { mode: "uid", agent_uid: 60123, gate_uid: 60125, system_uid_allow_ceiling: 1000 }])("refuses absent or unusable origin before signing: %j", async (agentOrigin) => {
    let calls = 0;
    await expect(buildInstallBundle({ ...input, agentOrigin, signer: { ...signer, sign: () => { calls++; return new Uint8Array(64); } } }, publicKey)).rejects.toThrow();
    expect(calls).toBe(0);
  });
  it.each([undefined, 0, -1, Number.MAX_SAFE_INTEGER + 1, 1.5])("refuses invalid generation %s", async (generation) => {
    await expect(buildInstallBundle({ ...input, generation }, publicKey)).rejects.toThrow();
  });
  it("refuses an invalid emitted signature", async () => {
    await expect(buildInstallBundle({ ...input, signer: { ...signer, sign: () => new Uint8Array(64) } }, publicKey)).rejects.toThrow("emitted manifest identity refused");
  });
  it("bounds the complete encoded bundle", async () => {
    const rules = Array.from({ length: 160 }, (_, i) => ({ id: `bounded-${i}`, schema_version: 1 as const, created_at: input.issuedAt, description: "x".repeat(1024), match: { ip: "127.0.0.1", port: 41003, protocol: "tcp" as const }, scope: {}, disposition: "allow" as const }));
    await expect(buildInstallBundle({ ...input, rules }, publicKey)).rejects.toThrow("policy bundle exceeds quota");
  });
  it("requires the existing fortress grammar before invoking the signer", async () => {
    let calls = 0;
    await expect(buildInstallBundle({ ...input, fortressId: "NOT_A_FORTRESS", signer: { ...signer, sign: () => { calls++; return new Uint8Array(64); } } }, publicKey)).rejects.toThrow();
    expect(calls).toBe(0);
  });
  it("refuses Linux-incompatible rules before signing", async () => {
    const rules = [{ id: "test", schema_version: 1 as const, created_at: input.issuedAt, match: { host: "example.com" }, scope: {}, disposition: "allow" as const }];
    await expect(buildInstallBundle({ ...input, rules }, publicKey)).rejects.toThrow();
  });
});

// The package's real executable is the consumer: npm-style links and inherited fd 3 must work.
import { mkdtempSync, writeFileSync, openSync, closeSync, readFileSync, symlinkSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
it("the packaged entry signs through an npm-style link and refuses key/output custody faults", () => {
  const dir = mkdtempSync(join(tmpdir(), "linux-policy-sign-"));
  try {
    const key = join(dir, "seed"); writeFileSync(key, seed, { mode: 0o600 });
    const rules = join(dir, "rules.json"); writeFileSync(rules, "[]");
    const entry = join(dir, "sign"); symlinkSync(resolve("bin/sanctuary-linux-policy-sign"), entry);
    const output = join(dir, "bundle.json");
    const argv = ["--fortress-id", input.fortressId, "--agent-uid", "60123", "--system-uid-ceiling", "1000", "--generation", "10", "--rules", rules, "--key-fd", "3", "--output", output];
    const run = (fd: number, args = argv) => spawnSync(entry, args, { stdio: ["ignore", "pipe", "pipe", fd], timeout: 10_000 });
    const fd = openSync(key, "r");
    try {
      expect(run(fd).status).toBe(0);
      const bundle = JSON.parse(readFileSync(output, "utf8"));
      const signed = JSON.parse(Buffer.from(bundle.manifest_b64url, "base64url").toString()) as SignedManifest;
      expect(verifyManifestSignature(signed, publicKey).ok).toBe(true);
      const before = readFileSync(output);
      expect(run(fd).status).not.toBe(0);
      expect(readFileSync(output)).toEqual(before);
      const linkedOutput = join(dir, "linked.json"); symlinkSync(output, linkedOutput);
      expect(run(fd, argv.map(a => a === output ? linkedOutput : a)).status).not.toBe(0);
      const bad = join(dir, "bad.json");
      expect(run(fd, argv.map(a => a === output ? bad : a === "3" ? "0" : a)).status).not.toBe(0);
      expect(existsSync(bad)).toBe(false);
    } finally { closeSync(fd); }
    for (const size of [31, 33]) {
      const wrong = join(dir, `seed-${size}`); writeFileSync(wrong, Buffer.alloc(size, 7), { mode: 0o600 });
      const wrongFd = openSync(wrong, "r");
      try { expect(run(wrongFd, argv.map(a => a === output ? join(dir, `wrong-${size}`) : a)).status).not.toBe(0); } finally { closeSync(wrongFd); }
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
