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
  verifyBundle,
  type BundleDescriptor,
  type BundleFileEntry,
  type ObservedBundle,
  type SignatureFile,
  type TrustedSigner,
} from "../manifest.js";

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
 * shape the verifier consumes. Rejects nothing here — the verifier is the gate;
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
 * Load + integrity-verify the bundled reference plugin against the first-party signer
 * public key shipped in the signed release. Returns everything the supervisor needs to
 * launch it. Throws a named SubstrateError if verification fails (fail-closed). Trust
 * here reduces to release integrity: the signer pubkey travels with the bundle, so
 * there is no independent host-policy pin until the third-party signer registry lands
 * (F1-gated).
 */
export async function loadReferenceBlocklistBundle(opts: {
  bundleDir?: string;
  /** First-party signer (public key) shipped in the signed release; trust = release integrity, not an independent host-policy pin. */
  signer: TrustedSigner;
  /** The detached SIGNATURE.json wrapper for this bundle. */
  signatureFile: SignatureFile;
}): Promise<LoadedReferenceBundle> {
  const bundleDir = opts.bundleDir ?? referenceBlocklistBundleDir();
  const governanceText = await fs.readFile(path.join(bundleDir, "governance.yaml"), "utf8");
  const governance = parseGovernance(governanceText);
  const enumerated = await enumerateBundle(bundleDir);

  const observed: ObservedBundle = {
    files: enumerated.files.map((f) => ({
      ...f,
      mode_exec: f.path === REFERENCE_BLOCKLIST_ENTRY ? true : f.mode_exec,
    })),
    nonRegular: enumerated.nonRegular,
    signatureFileCount: enumerated.signatureFileCount,
  };

  const descriptor = verifyBundle(opts.signatureFile, {
    resolveSigner: (signer_id, key_id) =>
      signer_id === opts.signer.signer_id && key_id === opts.signer.key_id ? opts.signer : undefined,
    observed,
    entryPath: governance.entry,
    expect: {
      plugin_id: governance.plugin_id,
      version: governance.version,
      channel: governance.channel,
    },
  });

  const bundleHash = sha256Hex(canonicalizeToBytes(descriptor));

  return {
    bundleDir,
    governance,
    descriptor,
    observed,
    bundleHash,
    entryPath: path.join(bundleDir, governance.entry),
  };
}

/**
 * Read the committed first-party signer public key from the bundle. This is the key
 * the host verifies the bundled reference plugin against — it ships with the bundle as
 * part of the signed release (trust = release integrity), NOT an independent host-policy
 * pin and NOT a third-party signer-registry entry (that path is F1-gated).
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
 * Load + integrity-verify the bundled reference plugin using its COMMITTED
 * SIGNATURE.json and the COMMITTED first-party signer pubkey. This is the
 * production-honest path: it proves the on-disk file set matches the signed
 * descriptor and that the signature verifies under the first-party signer key
 * shipped in the signed release (trust = release integrity; there is no independent
 * host-policy pin until the third-party signer registry lands, which is F1-gated). No
 * ephemeral keys, no third-party registry.
 */
export async function loadBundledReferenceBlocklist(bundleDir?: string): Promise<LoadedReferenceBundle> {
  const dir = bundleDir ?? referenceBlocklistBundleDir();
  const signer = await readBundledSigner(dir);
  const signatureRaw = await fs.readFile(path.join(dir, "SIGNATURE.json"), "utf8");
  const signatureFile = JSON.parse(signatureRaw) as SignatureFile;
  return loadReferenceBlocklistBundle({ bundleDir: dir, signer, signatureFile });
}
