/**
 * Test helpers for the plugin substrate contract surface.
 * Builds a signed BundleDescriptor + matching ObservedBundle so tamper tests can mutate
 * one input at a time.
 */

import { ed25519 } from "@noble/curves/ed25519";

import {
  canonicalizeToBytes,
  type BundleDescriptor,
  type ObservedBundle,
  type SignatureFile,
  type TrustedSigner,
  type VerifyContext,
  sha256Hex,
} from "../../src/substrate/index.js";

export interface BuiltBundle {
  signatureFile: SignatureFile;
  descriptor: BundleDescriptor;
  observed: ObservedBundle;
  ctx: VerifyContext;
  signer: TrustedSigner;
  privateKey: Uint8Array;
}

const enc = (s: string) => new TextEncoder().encode(s);

/** Build a valid, internally-consistent signed bundle for tests. */
export function buildValidBundle(overrides?: {
  signerId?: string;
  keyId?: string;
  pluginId?: string;
  version?: string;
  channel?: string;
}): BuiltBundle {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);

  const signer_id = overrides?.signerId ?? "ai.example.signer";
  const key_id = overrides?.keyId ?? "k1";
  const plugin_id = overrides?.pluginId ?? "ai.example.blocklist";
  const version = overrides?.version ?? "1.0.0";
  const channel = overrides?.channel ?? "stable";

  const entryBytes = enc("#!/bin/sh\necho blocklist\n");
  const ruleBytes = enc("evil.example.com\nexfil.test\n");

  const files = [
    {
      path: "bin/blocklist",
      type: "file" as const,
      mode_exec: true,
      size: entryBytes.length,
      sha256: sha256Hex(entryBytes),
    },
    {
      path: "rules/blocklist.txt",
      type: "file" as const,
      mode_exec: false,
      size: ruleBytes.length,
      sha256: sha256Hex(ruleBytes),
    },
  ].sort((a, b) => (a.path < b.path ? -1 : 1));

  const descriptor: BundleDescriptor = {
    schema: "sanctuary.plugin.bundle/v1",
    alg: "ed25519",
    signer_id,
    key_id,
    plugin_id,
    version,
    channel,
    governance_hash: sha256Hex(enc("governance-placeholder")),
    files,
  };

  const signedBytes = canonicalizeToBytes(descriptor);
  const signature = Buffer.from(ed25519.sign(signedBytes, privateKey)).toString("base64");
  const signatureFile: SignatureFile = { descriptor, signature };

  const observed: ObservedBundle = {
    files: [
      { path: "bin/blocklist", sha256: descriptor.files.find((f) => f.path === "bin/blocklist")!.sha256, mode_exec: true, size: entryBytes.length },
      { path: "rules/blocklist.txt", sha256: descriptor.files.find((f) => f.path === "rules/blocklist.txt")!.sha256, mode_exec: false, size: ruleBytes.length },
    ],
    nonRegular: [],
    signatureFileCount: 1,
  };

  const signer: TrustedSigner = { signer_id, key_id, publicKey };
  const ctx: VerifyContext = {
    resolveSigner: (sid, kid) => (sid === signer_id && kid === key_id ? signer : undefined),
    observed,
    entryPath: "bin/blocklist",
  };

  return { signatureFile, descriptor, observed, ctx, signer, privateKey };
}

/** Re-sign a (possibly mutated) descriptor with a given private key. */
export function resign(descriptor: BundleDescriptor, privateKey: Uint8Array): SignatureFile {
  const signedBytes = canonicalizeToBytes(descriptor);
  const signature = Buffer.from(ed25519.sign(signedBytes, privateKey)).toString("base64");
  return { descriptor, signature };
}
