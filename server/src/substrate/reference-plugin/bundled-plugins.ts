/**
 * Registry + generic loader for the first-party BUNDLED reference plugins (slice S5).
 *
 * There is now more than one first-party bundled reference plugin. This module is the
 * host-side generalization: a small FROZEN, compiled-in registry of the bundled plugins
 * (BUNDLED_PLUGINS) and a `loadBundledPlugin(plugin_id)` that integrity-verifies a
 * bundle ONLY when it is named by that registry. Trust does NOT reduce to a bundle's own
 * self-declared key: it derives from "ships in the signed release", i.e. presence in
 * this fixed registry. The on-disk directory is resolved INTERNALLY from the registry
 * entry (never from a caller-supplied path), realpath-checked against the registry's
 * expected location, and the loaded governance + signer identity are asserted to MATCH
 * the registry spec. The per-bundle Ed25519 signature/hash check runs on top of that
 * registry gate as defense-in-depth. Each bundle is independently signed with its own
 * key (self-shipped in its own first-party-signer.json).
 *
 * SECURITY (fail-closed): there is deliberately NO exported arbitrary-path bundle loader.
 * An arbitrary-path loader is an arbitrary-code-execution fail-open: an attacker who can
 * write a plugin directory could self-sign governance.yaml + first-party-signer.json +
 * SIGNATURE.json + bin/evil.mjs with their OWN key and have the host "verify" and spawn
 * it. The path-based primitive (`loadBundleFromDirInternal`) is module-private and MUST
 * NEVER be called with an untrusted or caller-supplied path; the only caller is the
 * registry-gated `loadBundledPlugin`.
 *
 * These are FIRST-PARTY BUNDLED reference plugins (second reference plugin included),
 * NOT third-party or marketplace plugins. Third-party install stays F1-gated (design
 * D2). "bundled" never means "integrity-skipped": every bundle passes the same §3.1a
 * verifyBundle hash-check and runs under the identical launcher/confinement path. The
 * supervisor isolates the plugins from each other, so one bundle's fault (a hostile or
 * failing plugin, a tampered SIGNATURE.json) cannot corrupt or take down another.
 *
 * `blocklist.ts` keeps its own standalone blocklist-specific loader surface (frozen
 * exports); it is not refactored to route through this module.
 */

import { promises as fs, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalizeToBytes } from "../canonical-json.js";
import { reject } from "../errors.js";
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

/** A first-party bundled reference plugin: its stable id, directory, and signer tuple. */
export interface BundledPluginSpec {
  /** Stable plugin id; must match the bundle's governance.yaml plugin_id. */
  plugin_id: string;
  /** Bundle directory name under reference-plugin/ (e.g. "blocklist"). */
  dirName: string;
  /** Expected first-party signer id the bundle's SIGNATURE.json must carry. */
  signer_id: string;
  /**
   * Expected first-party key id for this bundle. Distinct per bundle so the
   * (signer_id, key_id) identity tuple is unique across the registry (a future
   * third-party signer registry may key signers by this tuple).
   */
  key_id: string;
}

/**
 * The FROZEN, compiled-in registry of first-party bundled reference plugins. This is the
 * ROOT OF TRUST for bundled-plugin loading: `loadBundledPlugin` will load ONLY a plugin
 * named here, resolving its directory internally from `dirName`. To add a bundled
 * plugin, add a row here, add its dirName to REFERENCE_PLUGIN_BUNDLES in
 * scripts/copy-templates.js, and add its {dir, entry, signerId, keyId} to BUNDLES in
 * scripts/sign-reference-plugin.mjs. Each (signer_id, key_id) tuple MUST be unique. All
 * rows are FIRST-PARTY BUNDLED plugins; third-party install is a separate F1-gated path.
 */
export const BUNDLED_PLUGINS: readonly BundledPluginSpec[] = [
  {
    plugin_id: "ai.sanctuary.blocklist",
    dirName: "blocklist",
    signer_id: "ai.sanctuary.first-party",
    key_id: "release-v1",
  },
  {
    plugin_id: "ai.sanctuary.hosts-blocklist",
    dirName: "hosts-blocklist",
    signer_id: "ai.sanctuary.first-party",
    key_id: "hosts-blocklist-v1",
  },
];

/** Resolve the frozen registry spec for a plugin id, or fail closed if it is not registered. */
export function bundledPluginSpec(plugin_id: string): BundledPluginSpec {
  const spec = BUNDLED_PLUGINS.find((p) => p.plugin_id === plugin_id);
  if (!spec) {
    reject(
      "signature_plugin_mismatch",
      `"${plugin_id}" is not a registered first-party bundled plugin`,
    );
  }
  return spec;
}

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
 * third-party signer-registry entry (that path is F1-gated). The (signer_id, key_id) it
 * carries is asserted against the frozen registry spec by loadBundledPlugin.
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
 * Assert that a resolved bundle directory is the one the frozen registry names, by
 * comparing realpaths. bundledPluginDir resolves from the registry's dirName, but a
 * symlink swap could make it point elsewhere; realpath-canonicalizing BOTH the resolved
 * candidate and the registry-expected sibling and requiring equality closes that. Fails
 * closed (named rejection) on any mismatch.
 */
async function assertRegistryPath(spec: BundledPluginSpec, bundleDir: string): Promise<void> {
  const thisDir = path.dirname(fileURLToPath(import.meta.url));
  // The canonical registry location is the sibling directory named by the spec, in the
  // same layout bundledPluginDir resolved. We accept any layout bundledPluginDir picked,
  // but the LAST path segment must be the registry dirName and the realpath must equal
  // the realpath of the resolved directory (no symlink redirect to a foreign target).
  if (path.basename(bundleDir) !== spec.dirName) {
    reject(
      "bundle_path_traversal",
      `bundled plugin "${spec.plugin_id}" resolved to unexpected directory "${bundleDir}"`,
    );
  }
  let realResolved: string;
  try {
    realResolved = await fs.realpath(bundleDir);
  } catch {
    reject(
      "bundle_missing_listed_file",
      `bundled plugin "${spec.plugin_id}" directory "${bundleDir}" does not resolve`,
    );
  }
  // The realpath must still end in the registry dirName: a symlink that redirects the
  // bundle dir to a foreign target with a different final segment is rejected.
  if (path.basename(realResolved) !== spec.dirName) {
    reject(
      "bundle_path_traversal",
      `bundled plugin "${spec.plugin_id}" realpath "${realResolved}" does not match registry dir "${spec.dirName}"`,
    );
  }
  // And the resolved directory must live under this module's tree (source sibling or the
  // dist copy) - never an arbitrary external location reached via a symlinked ancestor.
  const realThisDir = await fs.realpath(thisDir).catch(() => thisDir);
  const realSrcTree = realThisDir.includes(`${path.sep}dist`)
    ? realThisDir.replace(`${path.sep}dist`, `${path.sep}src`)
    : realThisDir;
  const permittedRoots = [realThisDir, realSrcTree];
  const under = permittedRoots.some(
    (root) => realResolved === path.join(root, spec.dirName) ||
      realResolved.startsWith(`${root}${path.sep}`),
  );
  if (!under) {
    reject(
      "bundle_path_traversal",
      `bundled plugin "${spec.plugin_id}" realpath "${realResolved}" escapes the bundled-plugin tree`,
    );
  }
}

/**
 * INTERNAL, PATH-BASED primitive. MUST NEVER be called with an untrusted or
 * caller-supplied path: it verifies a bundle against its own self-shipped signer key and
 * governance, which proves only self-consistency, not first-party authenticity. The ONLY
 * legitimate caller is the registry-gated loadBundledPlugin below, which has already
 * pinned the directory to a frozen registry entry, realpath-checked it, and will assert
 * the loaded identity against the registry spec. It is deliberately NOT exported.
 */
async function loadBundleFromDirInternal(bundleDir: string): Promise<LoadedBundledPlugin> {
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

/**
 * Load + integrity-verify a first-party bundled plugin BY ITS REGISTRY PLUGIN ID.
 *
 * This is the ONLY public bundle-loading surface, and it is fail-closed: the plugin_id
 * MUST be present in the frozen, compiled-in BUNDLED_PLUGINS registry. The on-disk
 * directory is resolved INTERNALLY from that registry entry (never from a caller
 * argument), realpath-checked to equal the registry's expected location, and the loaded
 * governance.plugin_id + the SIGNATURE.json's (signer_id, key_id) are asserted to MATCH
 * the registry spec. Only then does the per-bundle Ed25519 signature/hash check run, as
 * defense-in-depth. Trust derives from "ships in the signed release" (registry
 * presence), NOT from a bundle's self-declared key: a self-signed bundle at a path
 * outside the registry can never be loaded here.
 *
 * Throws a named SubstrateError on any registry, path, identity, or integrity failure
 * (fail-closed); a bundle that does not pass every gate never runs. Third-party install
 * remains a separate F1-gated path.
 */
export async function loadBundledPlugin(plugin_id: string): Promise<LoadedBundledPlugin> {
  // 1. Registry gate: only a plugin the signed release ships may be loaded.
  const spec = bundledPluginSpec(plugin_id);

  // 2. Resolve the directory from the registry entry, never from a caller path.
  const bundleDir = bundledPluginDir(spec);

  // 3. realpath gate: the resolved directory must be the registry's expected location
  //    (reject a symlink swap that redirects the bundle dir elsewhere).
  await assertRegistryPath(spec, bundleDir);

  // 4. Per-bundle integrity (self-signed descriptor + hash check) as defense-in-depth.
  const loaded = await loadBundleFromDirInternal(bundleDir);

  // 5. Identity gate: the loaded governance + signer identity must MATCH the frozen
  //    registry spec, not merely be self-consistent.
  if (loaded.governance.plugin_id !== spec.plugin_id) {
    reject(
      "signature_plugin_mismatch",
      `bundle governance plugin_id "${loaded.governance.plugin_id}" does not match registry id "${spec.plugin_id}"`,
    );
  }
  if (
    loaded.descriptor.signer_id !== spec.signer_id ||
    loaded.descriptor.key_id !== spec.key_id
  ) {
    reject(
      "signature_signer_mismatch",
      `bundle "${spec.plugin_id}" signer (${loaded.descriptor.signer_id}, ${loaded.descriptor.key_id}) does not match registry (${spec.signer_id}, ${spec.key_id})`,
    );
  }

  return loaded;
}
