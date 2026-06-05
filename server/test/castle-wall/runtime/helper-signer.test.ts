/**
 * Tests for the Node ↔ root-helper signing bridge (B2).
 *
 * Asserts the happy path (sign/get-pubkey/install-pin via a mock shim) AND the
 * fail-closed contract: every shim failure mode (non-zero exit, empty/garbage
 * output, wrong length, thrown invoker) raises HelperSignerError — there is no
 * silent degrade to local signing here (hard constraint #5).
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import {
  HelperSignerClient,
  HelperSignerError,
  type ShimInvoker,
} from "../../../src/castle-wall/runtime/helper-signer.js";
import { toBase64url } from "../../../src/core/encoding.js";

/** A mock helper: a real Ed25519 key driven through the shim wire shape. */
function makeMockHelper() {
  const seed = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(seed);
  const invoke: ShimInvoker = async (args, stdin) => {
    const mode = args[0];
    if (mode === "get-pubkey" || mode === "re-pin") {
      return { stdout: toBase64url(pub) + "\n", stderr: "", code: 0 };
    }
    if (mode === "sign-manifest" || mode === "sign-nonce") {
      const sig = ed25519.sign(stdin ?? new Uint8Array(0), seed);
      return { stdout: toBase64url(sig), stderr: "", code: 0 };
    }
    return { stdout: "", stderr: `unknown mode ${mode}`, code: 2 };
  };
  return { pub, seed, invoke };
}

describe("castle-wall/runtime/helper-signer : happy path", () => {
  it("get-pubkey returns the helper's 32-byte key", async () => {
    const helper = makeMockHelper();
    const client = new HelperSignerClient({ clientBinaryPath: "x", invoke: helper.invoke });
    const pub = await client.getPublicKey();
    expect(pub).toEqual(helper.pub);
  });

  it("sign-manifest produces a signature that verifies against the helper key", async () => {
    const helper = makeMockHelper();
    const client = new HelperSignerClient({ clientBinaryPath: "x", invoke: helper.invoke });
    const payload = new TextEncoder().encode("opaque-canonical-bytes");
    const sig = await client.signManifest(payload);
    expect(sig.length).toBe(64);
    expect(ed25519.verify(sig, payload, helper.pub)).toBe(true);
  });

  it("sign-nonce uses the same key", async () => {
    const helper = makeMockHelper();
    const client = new HelperSignerClient({ clientBinaryPath: "x", invoke: helper.invoke });
    const nonce = new Uint8Array(32).fill(7);
    const sig = await client.signNonce(nonce);
    expect(ed25519.verify(sig, nonce, helper.pub)).toBe(true);
  });

  it("install-pin returns the pinned public key", async () => {
    const helper = makeMockHelper();
    const client = new HelperSignerClient({ clientBinaryPath: "x", invoke: helper.invoke });
    expect(await client.installPin()).toEqual(helper.pub);
  });
});

describe("castle-wall/runtime/helper-signer : fail-closed", () => {
  const failingClient = (invoke: ShimInvoker) =>
    new HelperSignerClient({ clientBinaryPath: "x", invoke });

  it("non-zero exit throws HelperSignerError", async () => {
    const client = failingClient(async () => ({ stdout: "", stderr: "boom", code: 1 }));
    await expect(client.getPublicKey()).rejects.toBeInstanceOf(HelperSignerError);
  });

  it("empty stdout throws", async () => {
    const client = failingClient(async () => ({ stdout: "   ", stderr: "", code: 0 }));
    await expect(client.getPublicKey()).rejects.toThrow(/empty stdout/);
  });

  it("wrong-length pubkey throws", async () => {
    const client = failingClient(async () => ({
      stdout: toBase64url(new Uint8Array(16)),
      stderr: "",
      code: 0,
    }));
    await expect(client.getPublicKey()).rejects.toThrow(/32/);
  });

  it("wrong-length signature throws", async () => {
    const client = failingClient(async () => ({
      stdout: toBase64url(new Uint8Array(10)),
      stderr: "",
      code: 0,
    }));
    await expect(
      client.signManifest(new Uint8Array([1, 2, 3])),
    ).rejects.toThrow(/64/);
  });

  it("a thrown invoker (e.g. ENOENT spawn) becomes HelperSignerError", async () => {
    const client = failingClient(async () => {
      throw new Error("spawn ENOENT");
    });
    await expect(client.getPublicKey()).rejects.toBeInstanceOf(HelperSignerError);
  });

  it("refuses to sign an empty payload", async () => {
    const helper = makeMockHelper();
    const client = failingClient(helper.invoke);
    await expect(client.signManifest(new Uint8Array(0))).rejects.toThrow(/empty/);
  });
});
