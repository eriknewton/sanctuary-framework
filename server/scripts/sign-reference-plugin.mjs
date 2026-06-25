#!/usr/bin/env node
/*
 * Build/maintenance script: sign the first-party reference plugin bundle.
 *
 * First-party bundling (design §7, review L1): the reference plugin ships inside the
 * signed release. Trust = release integrity: the signer pubkey travels with the bundle,
 * so there is no independent host-policy pin until the third-party signer registry lands
 * (F1-gated). This script bakes a real, verifiable SIGNATURE.json into the bundle and
 * writes the matching public key alongside it (first-party-signer.json) so the host can
 * verify the bundle against that self-shipped release key with NO third-party signer
 * registry (that path stays F1-gated for third-party plugins).
 *
 * Determinism: by default this script is IDEMPOTENT — if a valid SIGNATURE.json +
 * first-party-signer.json already exist and verify against the current on-disk file
 * set, it does nothing (so `npm run build` does not churn the signature on every
 * run). Pass --force to re-key and re-sign (rotates the first-party signer).
 *
 * The PRIVATE key is never written to the tree; it exists only for the duration of a
 * --force re-sign. In a production release this would be the release signer's key,
 * held offline.
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { ed25519 } from "@noble/curves/ed25519";

const __dirname = dirname(fileURLToPath(import.meta.url));
const BUNDLE_DIR = join(__dirname, "..", "src", "substrate", "reference-plugin", "blocklist");
const SIGNATURE_FILENAME = "SIGNATURE.json";
const SIGNER_PUBKEY_FILENAME = "first-party-signer.json";
const SIGNER_ID = "ai.sanctuary.first-party";
const KEY_ID = "release-v1";
const ENTRY = "bin/blocklist.mjs";

const force = process.argv.includes("--force");

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

/** Canonical JSON: sorted keys at every level, no insignificant whitespace. Mirrors
 *  src/substrate/canonical-json.ts so signer and verifier agree byte-for-byte.
 *
 *  The TS canonicalizer additionally THROWS on non-finite numbers and FILTERS
 *  `undefined` object keys. This script's input (the BundleDescriptor) is value-narrow
 *  — strings, integers, booleans, arrays only — so the two agree byte-for-byte today.
 *  `assertCanonicalizable` guards the divergence: if a future descriptor field ever
 *  carries a float/non-finite/undefined value, the signer FAILS LOUDLY here rather
 *  than emitting a signature the TS verifier would silently reject (or, worse, that a
 *  tampered bundle could satisfy). This keeps the two canonicalizers interchangeable
 *  for the only input that matters. */
function assertCanonicalizable(value, where) {
  if (value === undefined) {
    throw new Error(`sign-reference-plugin: undefined value at ${where} — descriptor must be value-narrow`);
  }
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new Error(`sign-reference-plugin: non-finite number at ${where} — descriptor must be value-narrow`);
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

function enumerate(dir) {
  const out = [];
  function walk(absDir, relPrefix) {
    for (const entry of readdirSync(absDir, { withFileTypes: true })) {
      const abs = join(absDir, entry.name);
      const rel = relPrefix ? `${relPrefix}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) throw new Error(`refusing to sign symlink ${rel}`);
      if (entry.isDirectory()) {
        walk(abs, rel);
        continue;
      }
      if (!entry.isFile()) throw new Error(`refusing to sign non-regular file ${rel}`);
      if (rel === SIGNATURE_FILENAME) continue; // detached, excluded
      const data = readFileSync(abs);
      out.push({
        path: rel.split(sep).join("/"),
        type: "file",
        mode_exec: rel === ENTRY ? true : (statSync(abs).mode & 0o111) !== 0,
        size: data.length,
        sha256: sha256Hex(data),
      });
    }
  }
  walk(dir, "");
  out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return out;
}

function buildDescriptor(files) {
  const governanceText = readFileSync(join(BUNDLE_DIR, "governance.yaml"), "utf8");
  const version = /^version:\s*(\S+)/m.exec(governanceText)?.[1] ?? "0.0.0";
  const channel = /^channel:\s*(\S+)/m.exec(governanceText)?.[1] ?? "stable";
  const pluginId = /^plugin_id:\s*(\S+)/m.exec(governanceText)?.[1] ?? "unknown";
  return {
    schema: "sanctuary.plugin.bundle/v1",
    alg: "ed25519",
    signer_id: SIGNER_ID,
    key_id: KEY_ID,
    plugin_id: pluginId,
    version,
    channel,
    governance_hash: sha256Hex(governanceText),
    files,
  };
}

function alreadyValid() {
  const sigPath = join(BUNDLE_DIR, SIGNATURE_FILENAME);
  const pubPath = join(BUNDLE_DIR, SIGNER_PUBKEY_FILENAME);
  if (!existsSync(sigPath) || !existsSync(pubPath)) return false;
  try {
    const sig = JSON.parse(readFileSync(sigPath, "utf8"));
    const pub = JSON.parse(readFileSync(pubPath, "utf8"));
    // Re-build the descriptor from current disk; the existing signature must match
    // it AND verify against the committed pubkey, else we need to re-sign.
    const files = enumerate(BUNDLE_DIR);
    const expected = buildDescriptor(files);
    if (canonicalize(sig.descriptor) !== canonicalize(expected)) return false;
    const signedBytes = new TextEncoder().encode(canonicalize(sig.descriptor));
    const signature = Uint8Array.from(Buffer.from(sig.signature, "base64"));
    const publicKey = Uint8Array.from(Buffer.from(pub.public_key_b64, "base64"));
    return ed25519.verify(signature, signedBytes, publicKey);
  } catch {
    return false;
  }
}

function main() {
  if (!force && alreadyValid()) {
    console.log("sign-reference-plugin: bundle signature already valid (use --force to re-key)");
    return;
  }
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);

  // Write the signer pubkey FIRST, so it is part of the signed file set (no
  // circular self-hash). The host trusts this self-shipped key by release integrity
  // (no independent host-policy pin); the signature then covers the pubkey file too,
  // so a post-sign pubkey swap is caught by the exact-set hash match.
  writeFileSync(
    join(BUNDLE_DIR, SIGNER_PUBKEY_FILENAME),
    `${JSON.stringify(
      { signer_id: SIGNER_ID, key_id: KEY_ID, public_key_b64: Buffer.from(publicKey).toString("base64") },
      null,
      2,
    )}\n`,
  );

  const files = enumerate(BUNDLE_DIR);
  const descriptor = buildDescriptor(files);
  const signedBytes = new TextEncoder().encode(canonicalize(descriptor));
  const signature = Buffer.from(ed25519.sign(signedBytes, privateKey)).toString("base64");

  writeFileSync(
    join(BUNDLE_DIR, SIGNATURE_FILENAME),
    `${JSON.stringify({ descriptor, signature }, null, 2)}\n`,
  );
  console.log(`sign-reference-plugin: signed ${descriptor.files.length} files; wrote SIGNATURE.json + ${SIGNER_PUBKEY_FILENAME}`);
}

main();
