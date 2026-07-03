#!/usr/bin/env node
/*
 * Build/maintenance script: sign the first-party bundled reference plugins.
 *
 * There are now n>1 first-party bundled reference plugins. EACH gets its own
 * independently signed bundle: its own random keypair, self-shipped in that bundle's
 * first-party-signer.json, with its own SIGNATURE.json over its own on-disk file set.
 * Trust reduces to release integrity per bundle, so each carries the exact key it
 * verifies against. These are FIRST-PARTY BUNDLED reference plugins, NOT third-party
 * or marketplace plugins; third-party install stays F1-gated.
 *
 * First-party bundling (design §7, review L1): each reference plugin ships inside the
 * signed release. The ROOT OF TRUST is the PUBLIC KEY PINNED IN THE COMPILED-IN REGISTRY
 * (BUNDLED_PLUGINS.public_key_b64 in src/substrate/reference-plugin/bundled-plugins.ts),
 * which is baked into the signed release. The bundle's self-shipped first-party-signer.json
 * is NOT the trust root: the host verifies each bundle's signature against the
 * registry-pinned key and rejects a self-shipped key that diverges from it. This script
 * bakes a real, verifiable SIGNATURE.json into each bundle and writes the matching public
 * key alongside it (first-party-signer.json) so the on-disk echo stays in sync; the
 * REGISTRY constant remains the source of truth.
 *
 * Determinism: by default this script is IDEMPOTENT - per bundle, if a valid
 * SIGNATURE.json + first-party-signer.json already exist and verify against that
 * bundle's current on-disk file set, it does nothing (so `npm run build` does not
 * churn signatures on every run). Pass --force to re-key and re-sign every bundle
 * (rotates each first-party signer); after a --force re-key you MUST re-pin the new
 * pubkeys in BUNDLED_PLUGINS. Pass --print-registry to emit each bundle's current
 * (signer_id, key_id, public_key_b64) so the registry constant can be updated to match.
 *
 * The PRIVATE key is never written to the tree; it exists only for the duration of a
 * --force re-sign. In a production release this would be the release signer's key,
 * held offline.
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { ed25519 } from "@noble/curves/ed25519";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REFERENCE_PLUGIN_ROOT = join(__dirname, "..", "src", "substrate", "reference-plugin");
const SIGNATURE_FILENAME = "SIGNATURE.json";
const SIGNER_PUBKEY_FILENAME = "first-party-signer.json";

// Every first-party bundled reference plugin, each independently signed with its own
// key. Each bundle carries a DISTINCT (signerId, keyId) tuple so the identity tuple is
// unique across bundles (a future third-party signer registry may key signers by this
// tuple). These MUST match the (signer_id, key_id) in BUNDLED_PLUGINS in
// src/substrate/reference-plugin/bundled-plugins.ts; the host verifies each bundle's
// signature against the public_key_b64 PINNED in that frozen registry (the trust root),
// not the bundle's self-shipped key.
//
// To add a bundle: add its {dir, entry, signerId, keyId} here, its dir name to
// REFERENCE_PLUGIN_BUNDLES in copy-templates.js, and its row to BUNDLED_PLUGINS; then run
// `node scripts/sign-reference-plugin.mjs --print-registry` and paste the pinned pubkey
// into that row's public_key_b64. First-party bundled only.
const BUNDLES = [
  {
    dir: join(REFERENCE_PLUGIN_ROOT, "blocklist"),
    entry: "bin/blocklist.mjs",
    signerId: "ai.sanctuary.first-party",
    keyId: "release-v1",
  },
  {
    dir: join(REFERENCE_PLUGIN_ROOT, "hosts-blocklist"),
    entry: "bin/hosts-blocklist.mjs",
    signerId: "ai.sanctuary.first-party",
    keyId: "hosts-blocklist-v1",
  },
];

const force = process.argv.includes("--force");

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

/** Canonical JSON: sorted keys at every level, no insignificant whitespace. Mirrors
 *  src/substrate/canonical-json.ts so signer and verifier agree byte-for-byte.
 *
 *  The TS canonicalizer additionally THROWS on non-finite numbers and FILTERS
 *  `undefined` object keys. This script's input (the BundleDescriptor) is value-narrow
 *  - strings, integers, booleans, arrays only - so the two agree byte-for-byte today.
 *  `assertCanonicalizable` guards the divergence: if a future descriptor field ever
 *  carries a float/non-finite/undefined value, the signer FAILS LOUDLY here rather
 *  than emitting a signature the TS verifier would silently reject (or, worse, that a
 *  tampered bundle could satisfy). This keeps the two canonicalizers interchangeable
 *  for the only input that matters. */
function assertCanonicalizable(value, where) {
  if (value === undefined) {
    throw new Error(`sign-reference-plugin: undefined value at ${where}; descriptor must be value-narrow`);
  }
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new Error(`sign-reference-plugin: non-finite number at ${where}; descriptor must be value-narrow`);
  }
  if (Array.isArray(value)) {
    value.forEach((v, i) => assertCanonicalizable(v, `${where}[${i}]`));
  } else if (value !== null && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) assertCanonicalizable(v, `${where}.${k}`);
  }
}

function canonicalize(value) {
  assertCanonicalizable(value, "<root>");
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(",")}}`;
}

function enumerate(dir, entry) {
  const out = [];
  function walk(absDir, relPrefix) {
    for (const dirEntry of readdirSync(absDir, { withFileTypes: true })) {
      const abs = join(absDir, dirEntry.name);
      const rel = relPrefix ? `${relPrefix}/${dirEntry.name}` : dirEntry.name;
      if (dirEntry.isSymbolicLink()) throw new Error(`refusing to sign symlink ${rel}`);
      if (dirEntry.isDirectory()) {
        walk(abs, rel);
        continue;
      }
      if (!dirEntry.isFile()) throw new Error(`refusing to sign non-regular file ${rel}`);
      if (rel === SIGNATURE_FILENAME) continue; // detached, excluded
      const data = readFileSync(abs);
      out.push({
        path: rel.split(sep).join("/"),
        type: "file",
        mode_exec: rel === entry ? true : (statSync(abs).mode & 0o111) !== 0,
        size: data.length,
        sha256: sha256Hex(data),
      });
    }
  }
  walk(dir, "");
  out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return out;
}

function buildDescriptor(bundleDir, files, signerId, keyId) {
  const governanceText = readFileSync(join(bundleDir, "governance.yaml"), "utf8");
  const version = /^version:\s*(\S+)/m.exec(governanceText)?.[1] ?? "0.0.0";
  const channel = /^channel:\s*(\S+)/m.exec(governanceText)?.[1] ?? "stable";
  const pluginId = /^plugin_id:\s*(\S+)/m.exec(governanceText)?.[1] ?? "unknown";
  return {
    schema: "sanctuary.plugin.bundle/v1",
    alg: "ed25519",
    signer_id: signerId,
    key_id: keyId,
    plugin_id: pluginId,
    version,
    channel,
    governance_hash: sha256Hex(governanceText),
    files,
  };
}

function alreadyValid(bundleDir, entry, signerId, keyId) {
  const sigPath = join(bundleDir, SIGNATURE_FILENAME);
  const pubPath = join(bundleDir, SIGNER_PUBKEY_FILENAME);
  if (!existsSync(sigPath) || !existsSync(pubPath)) return false;
  try {
    const sig = JSON.parse(readFileSync(sigPath, "utf8"));
    const pub = JSON.parse(readFileSync(pubPath, "utf8"));
    // Re-build the descriptor from current disk; the existing signature must match
    // it AND verify against the committed pubkey, else we need to re-sign. A changed
    // signer tuple (signerId/keyId) also forces a re-sign here.
    const files = enumerate(bundleDir, entry);
    const expected = buildDescriptor(bundleDir, files, signerId, keyId);
    if (canonicalize(sig.descriptor) !== canonicalize(expected)) return false;
    if (pub.signer_id !== signerId || pub.key_id !== keyId) return false;
    const signedBytes = new TextEncoder().encode(canonicalize(sig.descriptor));
    const signature = Uint8Array.from(Buffer.from(sig.signature, "base64"));
    const publicKey = Uint8Array.from(Buffer.from(pub.public_key_b64, "base64"));
    return ed25519.verify(signature, signedBytes, publicKey);
  } catch {
    return false;
  }
}

function signBundle(bundleDir, entry, signerId, keyId) {
  if (!force && alreadyValid(bundleDir, entry, signerId, keyId)) {
    console.log(`sign-reference-plugin: ${bundleDir} signature already valid (use --force to re-key)`);
    return;
  }
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);

  // Write the signer pubkey FIRST, so it is part of the signed file set (no
  // circular self-hash). The host trusts this self-shipped key by release integrity
  // (no independent host-policy pin); the signature then covers the pubkey file too,
  // so a post-sign pubkey swap is caught by the exact-set hash match.
  writeFileSync(
    join(bundleDir, SIGNER_PUBKEY_FILENAME),
    `${JSON.stringify(
      { signer_id: signerId, key_id: keyId, public_key_b64: Buffer.from(publicKey).toString("base64") },
      null,
      2,
    )}\n`,
  );

  const files = enumerate(bundleDir, entry);
  const descriptor = buildDescriptor(bundleDir, files, signerId, keyId);
  const signedBytes = new TextEncoder().encode(canonicalize(descriptor));
  const signature = Buffer.from(ed25519.sign(signedBytes, privateKey)).toString("base64");

  writeFileSync(
    join(bundleDir, SIGNATURE_FILENAME),
    `${JSON.stringify({ descriptor, signature }, null, 2)}\n`,
  );
  console.log(
    `sign-reference-plugin: signed ${descriptor.files.length} files in ${descriptor.plugin_id} as (${signerId}, ${keyId}); wrote SIGNATURE.json + ${SIGNER_PUBKEY_FILENAME}`,
  );
}

/**
 * Emit each bundle's current (signer_id, key_id, public_key_b64) as the registry rows
 * expect them, so BUNDLED_PLUGINS.public_key_b64 can be updated to match after a re-sign.
 * The registry pin - not the on-disk first-party-signer.json - is the trust root.
 */
function printRegistry() {
  const rows = [];
  for (const bundle of BUNDLES) {
    const pubPath = join(bundle.dir, SIGNER_PUBKEY_FILENAME);
    if (!existsSync(pubPath)) {
      console.error(`sign-reference-plugin: ${pubPath} missing; run without --print-registry first`);
      process.exitCode = 1;
      continue;
    }
    const pub = JSON.parse(readFileSync(pubPath, "utf8"));
    rows.push({
      signer_id: pub.signer_id,
      key_id: pub.key_id,
      public_key_b64: pub.public_key_b64,
    });
  }
  // Machine-readable: paste each public_key_b64 into the matching BUNDLED_PLUGINS row.
  console.log(JSON.stringify({ pinned_registry_keys: rows }, null, 2));
}

function main() {
  if (process.argv.includes("--print-registry")) {
    printRegistry();
    return;
  }
  for (const bundle of BUNDLES) {
    signBundle(bundle.dir, bundle.entry, bundle.signerId, bundle.keyId);
  }
}

main();
