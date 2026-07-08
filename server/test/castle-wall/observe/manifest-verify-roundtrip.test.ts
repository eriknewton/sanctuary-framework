/**
 * Castle Wall Observe / Learn Allow-List v1 -- FIX 1 on-disk regression.
 *
 * Proves the promote carry-forward path's `readVerifiedManifest` genuinely
 * verifies a real published manifest against the pinned key AND fails closed
 * on tampering, over REAL publisher output on a real temp dir (not a mock):
 *
 *   - a manifest published by `publishSignedManifest` + the CLI's
 *     `FilesystemManifestStorage` round-trips to `status: "ok"` with the
 *     carried-forward rules;
 *   - flipping the signature, corrupting the manifest JSON, editing a
 *     referenced rule file's bytes, or dropping a referenced rule file all
 *     yield `status: "tampered"` -- the exact attack surface FIX 1 closes (an
 *     attacker who can write the egress dir plants a broad rule; the daemon
 *     already rejects the bad signature, and now promote refuses to re-sign
 *     the unverified ruleset under the good pinned key).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ed25519 } from "@noble/curves/ed25519";

import {
  FilesystemManifestStorage,
  readVerifiedManifest,
} from "../../../src/cli/castle-wall-observe.js";
import {
  localManifestSigner,
  publishSignedManifest,
} from "../../../src/castle-wall/runtime/manifest-publisher.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { encrypt } from "../../../src/core/encryption.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";

function rule(id: string, host: string): AllowlistRule {
  return {
    id,
    schema_version: 1,
    created_at: "2026-07-07T00:00:00Z",
    match: { host: [host], port: [443], protocol: "tcp" },
    scope: { template_ids: ["claude-code"] },
    disposition: "allow",
    derived: true,
  };
}

describe("readVerifiedManifest: real publisher round-trip + tamper detection (FIX 1)", () => {
  let egressDir: string;
  let publicKey: Uint8Array;
  let signer: ReturnType<typeof localManifestSigner>;

  beforeEach(async () => {
    egressDir = await mkdtemp(join(tmpdir(), "cw-observe-manifest-"));
    const privateSeed = generateRandomKey();
    publicKey = ed25519.getPublicKey(privateSeed);
    const encryptionKey = generateRandomKey();
    const encryptedPrivateKey = encrypt(privateSeed, encryptionKey);
    signer = localManifestSigner({ signingKeyId: "test-key", encryptedPrivateKey, encryptionKey });
  });

  afterEach(async () => {
    await rm(egressDir, { recursive: true, force: true });
  });

  async function publish(rules: AllowlistRule[]): Promise<void> {
    await publishSignedManifest(
      { fortressId: "fortress-test", issuedAt: "2026-07-07T00:00:00Z", rules, signer },
      new FilesystemManifestStorage(egressDir),
    );
  }

  it("a validly published manifest verifies OK and returns the carried-forward rules", async () => {
    await publish([rule("r-good", "api.example.com")]);
    const read = await readVerifiedManifest(egressDir, publicKey);
    expect(read.status).toBe("ok");
    if (read.status !== "ok") throw new Error("unreachable");
    expect(read.rules).toHaveLength(1);
    expect(read.rules[0]!.id).toBe("r-good");
    expect(read.digest).toMatch(/^[0-9a-f]{64}$/);
  });

  it("an absent manifest (fresh install) is `absent`, not tampered", async () => {
    const read = await readVerifiedManifest(egressDir, publicKey);
    expect(read.status).toBe("absent");
  });

  it("verifying against the WRONG pinned key is tampered (bad signature)", async () => {
    await publish([rule("r-good", "api.example.com")]);
    const wrongKey = ed25519.getPublicKey(generateRandomKey());
    const read = await readVerifiedManifest(egressDir, wrongKey);
    expect(read.status).toBe("tampered");
  });

  it("editing a referenced rule file's bytes after signing is tampered (sha256 mismatch)", async () => {
    await publish([rule("r-good", "api.example.com")]);
    // The rule file lives next to manifest.json as `<id>.json`.
    const ruleFile = join(egressDir, "r-good.json");
    const original = JSON.parse(await readFile(ruleFile, "utf8")) as AllowlistRule;
    original.match = { host_pattern: "*", port: [443], protocol: "tcp" }; // widen to everything
    await writeFile(ruleFile, JSON.stringify(original));
    const read = await readVerifiedManifest(egressDir, publicKey);
    expect(read.status).toBe("tampered");
  });

  it("dropping a referenced rule file is tampered (missing file), never a silent drop", async () => {
    await publish([rule("r-good", "api.example.com")]);
    await rm(join(egressDir, "r-good.json"));
    const read = await readVerifiedManifest(egressDir, publicKey);
    expect(read.status).toBe("tampered");
    if (read.status !== "tampered") throw new Error("unreachable");
    expect(read.reason).toContain("r-good.json");
  });

  it("corrupting the manifest JSON is tampered", async () => {
    await publish([rule("r-good", "api.example.com")]);
    await writeFile(join(egressDir, "manifest.json"), "{ not valid json");
    const read = await readVerifiedManifest(egressDir, publicKey);
    expect(read.status).toBe("tampered");
  });

  it("the digest changes when the published ruleset changes (compare-and-set token, FIX 2)", async () => {
    await publish([rule("r-good", "api.example.com")]);
    const first = await readVerifiedManifest(egressDir, publicKey);
    await publish([rule("r-good", "api.example.com"), rule("r-two", "pypi.org")]);
    const second = await readVerifiedManifest(egressDir, publicKey);
    expect(first.status).toBe("ok");
    expect(second.status).toBe("ok");
    if (first.status !== "ok" || second.status !== "ok") throw new Error("unreachable");
    expect(first.digest).not.toBe(second.digest);
  });
});
