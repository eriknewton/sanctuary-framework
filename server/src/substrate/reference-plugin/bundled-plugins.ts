/**
 * Registry + generic loader for the first-party BUNDLED reference plugins (slice S5).
 *
 * There is now more than one first-party bundled reference plugin. This module is the
 * host-side generalization: a small registry of the bundled plugins and a
 * signer-agnostic `loadBundledPlugin` that integrity-verifies ANY bundle against the
 * first-party signer public key shipped inside THAT bundle's own signed release. Each
 * bundle is independently signed with its own key (self-shipped in its own
 * first-party-signer.json); trust reduces to release integrity per bundle.
 *
 * These are FIRST-PARTY BUNDLED reference plugins (second reference plugin included),
 * NOT third-party or marketplace plugins. Third-party install stays F1-gated (design
 * D2). "bundled" never means "integrity-skipped": every bundle passes the same §3.1a
 * verifyBundle hash-check and runs under the identical launcher/confinement path. The
 * supervisor isolates the plugins from each other, so one bundle's fault (a hostile or
 * failing plugin, a tampered SIGNATURE.json) cannot corrupt or take down another.
 *
 * `blocklist.ts` keeps the original blocklist-specific loader surface (frozen exports);
 * it now delegates the shared work here.
 */

import { promises as fs, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalizeToBytes } from "../canonical-json.js";
import { parseGovernance, type Governance } from "../governance.js";
import {
  sha256Hex,
  verifyBundle,
  type BundleDescriptor,
  type ObservedBundle,
  type SignatureFile,
  type TrustedSigner,
} from "../manifest.js";

/** The committed signer pubkey wrapper the build step writes alongside each SIGNATURE.json. */
export const FIRST_PARTY_SIGNER_FILENAME = "first-party-signer.json";

/** A first-party bundled reference plugin: its stable id and its bundle directory name. */
export interface BundledPluginSpec {
  /** Stable plugin id; must match the bundle's governance.yaml plugin_id. */
  plugin_id: string;
  /** Bundle directory name under reference-plugin/ (e.g. "blocklist"). */
  dirName: string;
}

/**
 * The registry of first-party bundled reference plugins. To add a bundled plugin, add
 * a row here, add its dirName to REFERENCE_PLUGIN_BUNDLES in scripts/copy-templates.js,
 * and add its {dir, entry} to BUNDLES in scripts/sign-reference-plugin.mjs. All rows
 * are FIRST-PARTY BUNDLED plugins; third-party install is a separate F1-gated path.
 */
export const BUNDLED_PLUGINS: readonly BundledPluginSpec[] = [
  { plugin_id: "ai.sanctuary.blocklist", dirName: "blocklist" },
  { plugin_id: "ai.sanctuary.hosts-blocklist", dirName: "hosts-blocklist" },
];

export interface LoadedBundledPlugin {
  bundleDir: string;
  governance: Governance;
  descriptor: BundleDescriptor;
  observed: ObservedBundle;
  /** sha256 over the canonical descriptor - the exact installed artifact set id. */
  bundleHash: string;
  /** Absolute path to the plugin entry binary. */
  entryPath: string;
}

/**
 * Resolve a bundled plugin's directory by its spec, across the same layouts the
 * original blocklist resolver handled (source sibling, dist copy, dist->src fallback).
 * The governance.yaml marker must be present for a candidate to win.
 */
export function bundledPluginDir(spec: BundledPluginSpec): string {
  const thisDir = path.dirname(fileURLToPath(import.meta.url));
  const marker = "governance.yaml";

  const candidates = [
    // case 1: source layout - bundle is a sibling directory of this module
    path.join(thisDir, spec.dirName),
    // case 2: bundled dist - copy-templates places it under dist/reference-plugin/
    path.join(thisDir, "reference-plugin", spec.dirName),
  ];
  for (const candidate of candidates) {
    if (existsSync(path.join(candidate, marker))) return candidate;
  }

  // case 3: dist fall back to a src checkout (local dev before a build copy)
  if (thisDir.includes(`${path.sep}dist`)) {
    const srcGuess = thisDir.replace(`${path.sep}dist`, `${path.sep}src`);
    const srcCandidate = path.join(srcGuess, spec.dirName);
    if (existsSync(path.join(srcCandidate, marker))) return srcCandidate;
  }

  // Default to the source-layout sibling; a caller reading it gets a clear ENOENT
  // rather than a silent wrong directory.
  return candidates[0]!;
}

/**
 * Enumerate a bundle directory into the (files, nonRegular, signatureFileCount) shape
 * the verifier consumes. Reports what is on disk (including non-regular entries) so the
 * verifier can fail closed on them; this function is NOT the gate.
 */
export async function enumerateBundleDir(
  bundleDir: string,
  entryRel: string,
): Promise<ObservedBundle> {
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
      if (rel === "SIGNATURE.json") {
        signatureFileCount += 1;
        continue;
      }
      const data = await fs.readFile(abs);
      const stat = await fs.stat(abs);
      files.push({
        path: rel,
        sha256: sha256Hex(new Uint8Array(data)),
        // The entry binary is forced executable to match the signed descriptor; a
        // git checkout may drop the exec bit. Every OTHER file's exec bit is
        // cross-checked against disk by verifyBundle.
        mode_exec: rel === entryRel ? true : (stat.mode & 0o111) !== 0,
        size: data.length,
      });
    }
  }

  await walk(bundleDir, "");
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return { files, nonRegular, signatureFileCount };
}

/**
 * Read the committed first-party signer public key from a bundle. This is the key the
 * host verifies THAT bundle against; it ships with the bundle as part of the signed
 * release (trust = release integrity), NOT an independent host-policy pin and NOT a
 * third-party signer-registry entry (that path is F1-gated).
 */
export async function readBundledSignerFrom(bundleDir: string): Promise<TrustedSigner> {
  const raw = await fs.readFile(path.join(bundleDir, FIRST_PARTY_SIGNER_FILENAME), "utf8");
  const parsed = JSON.parse(raw) as {
    signer_id?: unknown;
    key_id?: unknown;
    public_key_b64?: unknown;
  };
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
 * Load + integrity-verify a first-party bundled plugin using its COMMITTED
 * SIGNATURE.json and the COMMITTED first-party signer pubkey shipped in the same
 * bundle. Production-honest path: it proves the on-disk file set matches the signed
 * descriptor and that the Ed25519 signature verifies under the bundle's own
 * first-party signer key. Throws a named SubstrateError on any verification failure
 * (fail-closed); a bundle that does not verify never runs.
 *
 * Trust reduces to release integrity per bundle; there is no independent host-policy
 * pin and no third-party registry (that path is F1-gated).
 */
export async function loadBundledPlugin(bundleDir: string): Promise<LoadedBundledPlugin> {
  const governanceText = await fs.readFile(path.join(bundleDir, "governance.yaml"), "utf8");
  const governance = parseGovernance(governanceText);

  const signer = await readBundledSignerFrom(bundleDir);
  const signatureRaw = await fs.readFile(path.join(bundleDir, "SIGNATURE.json"), "utf8");
  const signatureFile = JSON.parse(signatureRaw) as SignatureFile;

  const observed = await enumerateBundleDir(bundleDir, governance.entry);

  const descriptor = verifyBundle(signatureFile, {
    resolveSigner: (signer_id, key_id) =>
      signer_id === signer.signer_id && key_id === signer.key_id ? signer : undefined,
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
