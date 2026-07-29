/**
 * Host-side loader for the first-party reference domain-blocklist plugin (slice S5).
 *
 * This module is the HOST half: it locates the bundled reference plugin on disk,
 * enumerates its real file set, builds the signed `BundleDescriptor` the verifier
 * consumes, and parses the plugin's `governance.yaml` through the SAME contract
 * surface (S1) a third-party bundle would go through. The plugin BINARY itself
 * (bin/blocklist.mjs) imports nothing from here — the dogfood boundary is real.
 *
 * First-party bundling (design §7, review L1): the reference plugin ships inside the
 * signed release, so it bypasses the operator-approval install ceremony and the
 * third-party signer registry (F1-gated). It does NOT bypass integrity: the bundle
 * still passes the §3.1a hash-check via `verifyBundle`, and still runs under the
 * identical launcher/realized-confinement path. "bundled" ≠ "untrusted-input
 * skipped".
 */

import { createHash } from "node:crypto";
import { promises as fs, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ed25519 } from "@noble/curves/ed25519";

import { canonicalizeToBytes } from "../canonical-json.js";
import { parseGovernance, type Governance } from "../governance.js";
import {
  SIGNATURE_FILENAME,
  sha256Hex,
  type BundleDescriptor,
  type BundleFileEntry,
  type ObservedBundle,
  type SignatureFile,
  type TrustedSigner,
} from "../manifest.js";
import { loadBundledPlugin } from "./bundled-plugins.js";

/** Stable identity of the first-party reference plugin (matches governance.yaml). */
export const REFERENCE_BLOCKLIST_PLUGIN_ID = "ai.sanctuary.blocklist";
export const REFERENCE_BLOCKLIST_SIGNER_ID = "ai.sanctuary.first-party";
export const REFERENCE_BLOCKLIST_KEY_ID = "release-v1";
export const REFERENCE_BLOCKLIST_ENTRY = "bin/blocklist.mjs";

/** The committed signer pubkey wrapper the build step writes alongside SIGNATURE.json. */
export const REFERENCE_SIGNER_PUBKEY_FILENAME = "first-party-signer.json";

export interface LoadedReferenceBundle {
  bundleDir: string;
  governance: Governance;
  descriptor: BundleDescriptor;
  observed: ObservedBundle;
  /** sha256 over the canonical descriptor — the exact installed artifact set id. */
  bundleHash: string;
  /** Absolute path to the plugin entry binary. */
  entryPath: string;
}

/**
 * Resolve the bundled reference plugin directory across layouts:
 *   1. Source (ts):  src/substrate/reference-plugin/blocklist.ts → sibling blocklist/
 *   2. Compiled bundled (tsup): dist/index.js → the build copies the bundle into
 *      dist/reference-plugin/blocklist/ via copy-templates.
 *   3. npm install (no src/): only the dist copy exists.
 * The marker file (governance.yaml) must be present for a candidate to win.
 */
export function referenceBlocklistBundleDir(): string {
  const thisDir = path.dirname(fileURLToPath(import.meta.url));
  const marker = "governance.yaml";

  const candidates = [
    // case 1: source layout — bundle is a sibling directory
    path.join(thisDir, "blocklist"),
    // case 2: bundled dist — copy-templates places it under dist/reference-plugin/
    path.join(thisDir, "reference-plugin", "blocklist"),
  ];
  for (const candidate of candidates) {
    if (existsSync(path.join(candidate, marker))) return candidate;
  }

  // case 3: dist fall back to a src checkout (local dev before a build copy)
  if (thisDir.includes(`${path.sep}dist`)) {
    const srcGuess = thisDir
      .replace(`${path.sep}dist`, `${path.sep}src`)
      .concat("");
    const srcCandidate = path.join(srcGuess, "substrate", "reference-plugin", "blocklist");
    if (existsSync(path.join(srcCandidate, marker))) return srcCandidate;
  }

  // Default to the source-layout sibling; callers that read it will get a clear
  // ENOENT rather than a silent wrong directory.
  return candidates[0]!;
}

/**
 * Enumerate a bundle directory into the (files, nonRegular, signatureFileCount)
 * shape the verifier consumes. Rejects nothing here; the verifier is the gate;
 * this only reports what is on disk, including non-regular entries so the verifier
 * can fail closed on them.
 */
export async function enumerateBundle(bundleDir: string): Promise<{
  files: Array<{ path: string; sha256: string; mode_exec: boolean; size: number }>;
  nonRegular: string[];
  signatureFileCount: number;
}> {
  const files: Array<{ path: string; sha256: string; mode_exec: boolean; size: number }> = [];
  const nonRegular: string[] = [];
  let signatureFileCount = 0;

  async function walk(absDir: string, relPrefix: string): Promise<void> {
    const entries = await fs.readdir(absDir, { withFileTypes: true });
    for (const entry of entries) {
      const abs = path.join(absDir, entry.name);
      const rel = relPrefix ? `${relPrefix}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) {
        nonRegular.push(rel);
        continue;
      }
      if (entry.isDirectory()) {
        await walk(abs, rel);
        continue;
      }
      if (!entry.isFile()) {
        nonRegular.push(rel);
        continue;
      }
      if (rel === SIGNATURE_FILENAME) {
        signatureFileCount += 1;
        continue;
      }
      const data = await fs.readFile(abs);
      const stat = await fs.stat(abs);
      files.push({
        path: rel,
        sha256: sha256Hex(new Uint8Array(data)),
        mode_exec: (stat.mode & 0o111) !== 0,
        size: data.length,
      });
    }
  }

  await walk(bundleDir, "");
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return { files, nonRegular, signatureFileCount };
}

/**
 * Build the signed BundleDescriptor for a bundle's on-disk state. The entry binary
 * is forced executable in the descriptor (the contract requires the entry to be a
 * `mode_exec: true` member); a checked-out git tree may not preserve the exec bit,
 * so we set it deterministically for the entry path here. The verifier still cross-
 * checks every OTHER file's exec bit against disk.
 */
export async function buildReferenceDescriptor(
  bundleDir: string,
  governanceText: string,
): Promise<{ descriptor: BundleDescriptor; observed: ObservedBundle; governance: Governance }> {
  const governance = parseGovernance(governanceText);
  const enumerated = await enumerateBundle(bundleDir);

  const files: BundleFileEntry[] = enumerated.files.map((f) => ({
    path: f.path,
    type: "file" as const,
    mode_exec: f.path === REFERENCE_BLOCKLIST_ENTRY ? true : f.mode_exec,
    size: f.size,
    sha256: f.sha256,
  }));

  const observed: ObservedBundle = {
    files: enumerated.files.map((f) => ({
      ...f,
      mode_exec: f.path === REFERENCE_BLOCKLIST_ENTRY ? true : f.mode_exec,
    })),
    nonRegular: enumerated.nonRegular,
    signatureFileCount: enumerated.signatureFileCount,
  };

  const descriptor: BundleDescriptor = {
    schema: "sanctuary.plugin.bundle/v1",
    alg: "ed25519",
    signer_id: REFERENCE_BLOCKLIST_SIGNER_ID,
    key_id: REFERENCE_BLOCKLIST_KEY_ID,
    plugin_id: governance.plugin_id,
    version: governance.version,
    channel: governance.channel,
    governance_hash: sha256Hex(new Uint8Array(createHash("sha256").update(governanceText).digest())),
    files,
  };

  return { descriptor, observed, governance };
}

/**
 * Sign a descriptor with a private key, producing the SIGNATURE.json wrapper. Used
 * by the build step (to bake a first-party signature into the release) and by tests/
 * drills (with an ephemeral key). The signing key never ships; only the public half
 * travels with the bundle (in first-party-signer.json) inside the signed release.
 * There is no independent host-policy pin: trust reduces to release integrity until
 * the third-party signer registry lands (F1-gated).
 */
export function signDescriptor(descriptor: BundleDescriptor, privateKey: Uint8Array): SignatureFile {
  const signedBytes = canonicalizeToBytes(descriptor);
  const signature = Buffer.from(ed25519.sign(signedBytes, privateKey)).toString("base64");
  return { descriptor, signature };
}

/**
 * Load + integrity-verify the bundled reference blocklist plugin.
 *
 * SECURITY (fail-closed, arbitrary-code-execution class): this function's exported NAME
 * and return shape are frozen for compatibility, but it NO LONGER honors a caller-supplied
 * `bundleDir` or `signer`/`signatureFile`. Accepting a caller path + a caller-supplied
 * signer was an arbitrary-code-execution fail-open (a sibling of the loadBundledPlugin
 * path issue): an attacker who could point it at a self-signed bundle got a verified,
 * spawnable entryPath. It now delegates UNCONDITIONALLY to the single chokepoint
 * `loadBundledPlugin('ai.sanctuary.blocklist')`, so trust derives from the frozen,
 * compiled-in registry + the registry-PINNED signer key, never from caller input. The
 * `opts` argument is accepted (frozen signature) but its fields are ignored; the bundle
 * is always the registry blocklist bundle, verified against the registry-pinned key.
 * Throws a named SubstrateError if verification fails (fail-closed).
 */
export async function loadReferenceBlocklistBundle(_opts?: {
  bundleDir?: string;
  /** IGNORED: trust is the registry-pinned key, not a caller-supplied signer. */
  signer?: TrustedSigner;
  /** IGNORED: the committed SIGNATURE.json for the registry bundle is used. */
  signatureFile?: SignatureFile;
}): Promise<LoadedReferenceBundle> {
  // Delegate to the ONE chokepoint. The returned LoadedBundledPlugin is structurally a
  // LoadedReferenceBundle (same fields), verified against the registry-pinned signer.
  return loadBundledPlugin(REFERENCE_BLOCKLIST_PLUGIN_ID);
}

/**
 * Read the committed first-party signer public key from the bundle. This is a read-only
 * helper (frozen exported name). NOTE: it is NOT a trust root - the registry pin in
 * BUNDLED_PLUGINS is. loadBundledPlugin verifies the bundle against the registry-pinned
 * key and rejects a self-shipped key that diverges from it; this helper is retained for
 * inspection/tests only. It does not load, verify, or return a spawnable bundle.
 */
export async function readBundledSigner(bundleDir: string): Promise<TrustedSigner> {
  const raw = await fs.readFile(path.join(bundleDir, REFERENCE_SIGNER_PUBKEY_FILENAME), "utf8");
  const parsed = JSON.parse(raw) as { signer_id?: unknown; key_id?: unknown; public_key_b64?: unknown };
  if (
    typeof parsed.signer_id !== "string" ||
    typeof parsed.key_id !== "string" ||
    typeof parsed.public_key_b64 !== "string"
  ) {
    throw new Error("first-party-signer.json is malformed");
  }
  return {
    signer_id: parsed.signer_id,
    key_id: parsed.key_id,
    publicKey: new Uint8Array(Buffer.from(parsed.public_key_b64, "base64")),
  };
}

/**
 * Load + integrity-verify the bundled reference blocklist plugin the production-honest
 * way. Frozen exported NAME + return shape; the optional `bundleDir` argument is now
 * IGNORED (accepting a caller path was the arbitrary-code-execution fail-open). It
 * delegates UNCONDITIONALLY to the single chokepoint `loadBundledPlugin` by REGISTRY
 * PLUGIN ID, so the directory is resolved internally from the frozen registry,
 * realpath-equality-checked, and the signature is verified against the registry-PINNED
 * key (not a bundle-self-shipped key). No caller-controlled path, no self-signed input.
 */
export async function loadBundledReferenceBlocklist(_bundleDir?: string): Promise<LoadedReferenceBundle> {
  return loadBundledPlugin(REFERENCE_BLOCKLIST_PLUGIN_ID);
}
