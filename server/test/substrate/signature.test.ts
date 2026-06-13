/**
 * Signed-manifest tamper suite (design §3.1a; RFC §5, §7.4).
 * One mutation per test, each asserting a NAMED fail-closed rejection.
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { verifyBundle, SubstrateError, sha256Hex } from "../../src/substrate/index.js";
import { buildValidBundle, resign } from "./helpers.js";

function expectReject(fn: () => unknown, reason: string) {
  try {
    fn();
    throw new Error("expected rejection but none thrown");
  } catch (e) {
    expect(e, `expected SubstrateError, got: ${String(e)}`).toBeInstanceOf(SubstrateError);
    expect((e as SubstrateError).reason).toBe(reason);
  }
}

describe("verifyBundle — happy path", () => {
  it("verifies a well-formed signed bundle", () => {
    const b = buildValidBundle();
    const d = verifyBundle(b.signatureFile, b.ctx);
    expect(d.plugin_id).toBe("ai.example.blocklist");
    expect(d.files.length).toBe(2);
  });
});

describe("verifyBundle — tamper suite", () => {
  it("rejects a flipped signature", () => {
    const b = buildValidBundle();
    const bad = { ...b.signatureFile, signature: Buffer.from(new Uint8Array(64)).toString("base64") };
    expectReject(() => verifyBundle(bad, b.ctx), "signature_invalid");
  });

  it("rejects a tampered descriptor field (signature no longer matches)", () => {
    const b = buildValidBundle();
    const tampered = { ...b.signatureFile, descriptor: { ...b.descriptor, version: "9.9.9" } };
    // signature was over the original bytes → verification fails
    expectReject(() => verifyBundle(tampered, b.ctx), "signature_invalid");
  });

  it("rejects an unknown signer (host policy has no key)", () => {
    const b = buildValidBundle();
    const ctx = { ...b.ctx, resolveSigner: () => undefined };
    expectReject(() => verifyBundle(b.signatureFile, ctx), "signature_signer_unknown");
  });

  it("rejects a signature from signer A replayed as signer B", () => {
    // Build a descriptor claiming signer B but signed by A's key; host resolves B → B's real key.
    const a = buildValidBundle({ signerId: "ai.attacker.signer", keyId: "ka" });
    const bPub = ed25519.getPublicKey(ed25519.utils.randomPrivateKey());
    const descClaimingB = { ...a.descriptor, signer_id: "ai.victim.signer", key_id: "kb" };
    const sigFromA = resign(descClaimingB, a.privateKey); // signed by A over a B-claiming descriptor
    const ctx = {
      ...a.ctx,
      resolveSigner: (sid: string, kid: string) =>
        sid === "ai.victim.signer" && kid === "kb"
          ? { signer_id: "ai.victim.signer", key_id: "kb", publicKey: bPub }
          : undefined,
    };
    // host resolves B's real key, signature was A's → fails
    expectReject(() => verifyBundle(sigFromA, ctx), "signature_invalid");
  });

  it("rejects an unsupported algorithm in the descriptor", () => {
    const b = buildValidBundle();
    const desc = { ...b.descriptor, alg: "rsa" } as unknown as typeof b.descriptor;
    const sig = resign(desc as never, b.privateKey);
    expectReject(() => verifyBundle(sig, b.ctx), "signature_algorithm_unsupported");
  });

  it("rejects an on-disk file not in the signed set (unlisted-file smuggling)", () => {
    const b = buildValidBundle();
    const observed = {
      ...b.observed,
      files: [...b.observed.files, { path: "rules/secret.txt", sha256: sha256Hex(new Uint8Array([1])), mode_exec: false, size: 1 }],
    };
    expectReject(() => verifyBundle(b.signatureFile, { ...b.ctx, observed }), "bundle_unlisted_file");
  });

  it("rejects a signed file missing on disk", () => {
    const b = buildValidBundle();
    const observed = { ...b.observed, files: [b.observed.files[0]!] };
    expectReject(() => verifyBundle(b.signatureFile, { ...b.ctx, observed }), "bundle_missing_listed_file");
  });

  it("rejects a swapped file with a different hash", () => {
    const b = buildValidBundle();
    const observed = {
      ...b.observed,
      files: b.observed.files.map((f) =>
        f.path === "rules/blocklist.txt" ? { ...f, sha256: sha256Hex(new Uint8Array([9, 9])) } : f,
      ),
    };
    expectReject(() => verifyBundle(b.signatureFile, { ...b.ctx, observed }), "signature_invalid");
  });

  it("rejects a non-regular (symlink) bundle entry", () => {
    const b = buildValidBundle();
    const observed = { ...b.observed, nonRegular: ["bin/evil-symlink"] };
    expectReject(() => verifyBundle(b.signatureFile, { ...b.ctx, observed }), "bundle_non_regular_file");
  });

  it("rejects a duplicate/absent root SIGNATURE.json", () => {
    const b = buildValidBundle();
    expectReject(
      () => verifyBundle(b.signatureFile, { ...b.ctx, observed: { ...b.observed, signatureFileCount: 2 } }),
      "bundle_duplicate_signature_file",
    );
    expectReject(
      () => verifyBundle(b.signatureFile, { ...b.ctx, observed: { ...b.observed, signatureFileCount: 0 } }),
      "bundle_duplicate_signature_file",
    );
  });

  it("rejects SIGNATURE.json being listed in files[] (non-cyclic rule)", () => {
    const b = buildValidBundle();
    const desc = {
      ...b.descriptor,
      files: [...b.descriptor.files, { path: "SIGNATURE.json", type: "file" as const, mode_exec: false, size: 1, sha256: sha256Hex(new Uint8Array([0])) }],
    };
    const sig = resign(desc, b.privateKey);
    expectReject(() => verifyBundle(sig, b.ctx), "bundle_signature_file_listed");
  });

  it("rejects a path-traversal file path in the descriptor", () => {
    const b = buildValidBundle();
    const desc = {
      ...b.descriptor,
      files: b.descriptor.files.map((f) => (f.path === "bin/blocklist" ? { ...f, path: "../escape" } : f)),
    };
    const sig = resign(desc, b.privateKey);
    expectReject(() => verifyBundle(sig, b.ctx), "bundle_path_traversal");
  });

  it("rejects an entry-point not marked executable", () => {
    const b = buildValidBundle();
    const desc = {
      ...b.descriptor,
      files: b.descriptor.files.map((f) => (f.path === "bin/blocklist" ? { ...f, mode_exec: false } : f)),
    };
    const sig = resign(desc, b.privateKey);
    // observed must agree on exec bit to reach the entry check
    const observed = {
      ...b.observed,
      files: b.observed.files.map((f) => (f.path === "bin/blocklist" ? { ...f, mode_exec: false } : f)),
    };
    expectReject(() => verifyBundle(sig, { ...b.ctx, observed }), "bundle_entry_not_executable");
  });

  it("rejects an entry-point not present in files[]", () => {
    const b = buildValidBundle();
    expectReject(() => verifyBundle(b.signatureFile, { ...b.ctx, entryPath: "bin/missing" }), "bundle_entry_not_listed");
  });

  it("rejects an invalid reverse-DNS plugin id", () => {
    const b = buildValidBundle();
    const desc = { ...b.descriptor, plugin_id: "../etc/passwd" };
    const sig = resign(desc, b.privateKey);
    expectReject(() => verifyBundle(sig, b.ctx), "invalid_plugin_id");
  });
});
