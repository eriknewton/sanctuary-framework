/**
 * F2 (Codex re-gate 2 on #1303, 2026-08-23, AGENTS.md rule 4): the exit
 * bundle directory-walk gate added alongside the known_signers artifact
 * (`verifier.ts` - `listBundleFiles`, the exact-artifact-SET check, and the
 * duplicate-kind check) shipped with zero tests naming its own failure
 * classes. This file drives each one directly: an extra unlisted file (the
 * common real-world case - a Finder `.DS_Store` or AppleDouble sidecar left
 * behind by a USB or SMB copy), an unreadable subdirectory, the walk's own
 * entry-count cap, and a manifest declaring the wrong artifact set for its
 * version (private register EXIT-KS-01).
 */

import { afterEach, describe, expect, it } from "vitest";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { hash } from "../../src/core/hashing.js";
import { sign as identitySign } from "../../src/core/identity.js";
import { canonicalize, canonicalizeToBytes } from "../../src/mesh/canonical-json.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createL4Tools } from "../../src/reputation/tools.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { defaultConfig } from "../../src/config.js";
import { exportExitBundle } from "../../src/exit/index.js";
import { verifyExitBundle, listBundleFiles } from "../../src/exit/verifier.js";
import type { ExitBundleManifest } from "../../src/contracts/v1.1/exit-bundle-manifest.js";
import { EXIT_BUNDLE_MANIFEST_VERSION } from "../../src/contracts/v1.1/constants.js";

interface ToolDef {
  name: string;
  handler: (args: Record<string, unknown>) => Promise<{
    content: Array<{ type: string; text: string }>;
  }>;
}

async function callTool(
  tools: ToolDef[],
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`Tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

async function makeHarness() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  const { tools: l1Tools, identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog
  );
  await identityManager.load();
  const { tools: l4Tools, reputationStore } = createL4Tools(
    storage,
    masterKey,
    identityManager,
    auditLog
  );
  return {
    storage,
    masterKey,
    auditLog,
    identityManager,
    reputationStore,
    tools: [...l1Tools, ...l4Tools] as ToolDef[],
  };
}

type Harness = Awaited<ReturnType<typeof makeHarness>>;

async function createIdentity(harness: Harness, label: string): Promise<string> {
  const created = await callTool(harness.tools, "identity_create", { label });
  return created.identity_id as string;
}

async function exportBundle(source: Harness, bundleDir: string) {
  return exportExitBundle({
    unpartitionedLegacyExport: true,
    bundleDir,
    storage: source.storage,
    masterKey: source.masterKey,
    identityManager: source.identityManager,
    auditLog: source.auditLog,
    reputationStore: source.reputationStore,
    policy: DEFAULT_POLICY,
    config: defaultConfig(),
    keySource: "recovery-key",
  });
}

/** Recompute the manifest's aggregate hash and re-sign it - the same two steps `exportExitBundle` performs, run again after hand-mutating the bundle directory on disk. */
async function resignManifest(bundleDir: string, signer: Harness): Promise<void> {
  const manifestPath = join(bundleDir, "manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as ExitBundleManifest;
  manifest.body.artifacts_aggregate_hash = Array.from(
    hash(stringToBytes(canonicalize(manifest.body.artifacts)))
  )
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  const identity = signer.identityManager.getDefault();
  if (!identity) throw new Error("missing manifest-signing identity");
  manifest.signature = toBase64url(
    identitySign(
      canonicalizeToBytes(manifest.body),
      identity.encrypted_private_key,
      derivePurposeKey(signer.masterKey, "identity-encryption")
    )
  );
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
}

describe("exit bundle directory-walk failure classes (F2, Codex re-gate 2 on #1303)", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function newBundleDir(prefix: string): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), prefix));
    tempDirs.push(dir);
    return dir;
  }

  it("an extra unlisted file (e.g. a Finder .DS_Store left by a USB copy) fails as artifact_directory_unlisted_file and names the path in warnings", async () => {
    const source = await makeHarness();
    await createIdentity(source, "walk-unlisted");
    const bundleDir = await newBundleDir("sanctuary-walk-unlisted-");
    await exportBundle(source, bundleDir);

    await writeFile(join(bundleDir, ".DS_Store"), "not part of the manifest");

    const verified = await verifyExitBundle(bundleDir);
    expect(verified.passed).toBe(false);
    expect(verified.failure_class).toBe("artifact_directory_unlisted_file");
    expect(verified.warnings.some((w) => w.includes(".DS_Store"))).toBe(true);
  });

  it("an unlisted file nested under artifacts/ is caught the same way, at its relative path", async () => {
    const source = await makeHarness();
    await createIdentity(source, "walk-unlisted-nested");
    const bundleDir = await newBundleDir("sanctuary-walk-unlisted-nested-");
    await exportBundle(source, bundleDir);

    await writeFile(
      join(bundleDir, "artifacts", "._known_signers.json"),
      "AppleDouble sidecar"
    );

    const verified = await verifyExitBundle(bundleDir);
    expect(verified.passed).toBe(false);
    expect(verified.failure_class).toBe("artifact_directory_unlisted_file");
    expect(
      verified.warnings.some((w) => w.includes("artifacts/._known_signers.json"))
    ).toBe(true);
  });

  it("a subdirectory the walk cannot read fails closed as artifact_directory_unlisted_file, not as an empty directory", async () => {
    const source = await makeHarness();
    await createIdentity(source, "walk-unreadable");
    const bundleDir = await newBundleDir("sanctuary-walk-unreadable-");
    await exportBundle(source, bundleDir);

    const lockedDir = join(bundleDir, "locked");
    await mkdir(lockedDir);
    await writeFile(join(lockedDir, "irrelevant"), "irrelevant");
    await chmod(lockedDir, 0o000);

    try {
      const verified = await verifyExitBundle(bundleDir);
      expect(verified.passed).toBe(false);
      expect(verified.failure_class).toBe("artifact_directory_unlisted_file");
      expect(
        verified.warnings.some((w) => w.toLowerCase().includes("could not read"))
      ).toBe(true);
    } finally {
      // Restore permissions so afterEach's recursive rm can delete it.
      await chmod(lockedDir, 0o700);
    }
  });

  it("listBundleFiles returns too_many once the entry count (files AND directories) exceeds maxEntries, without a 10,000-directory fixture", async () => {
    const dir = await newBundleDir("sanctuary-walk-toomany-");
    // 4 empty sibling directories against maxEntries=3: the SAME counter
    // this function uses in production (every entry, not only pushed
    // files - see its doc comment) trips on the 4th, regardless of any of
    // them ever containing a file.
    for (let i = 0; i < 4; i++) {
      await mkdir(join(dir, `empty-${i}`));
    }
    const result = await listBundleFiles(dir, 3);
    expect(result).toBe("too_many");

    const underCap = await listBundleFiles(dir, 4);
    expect(underCap).not.toBe("too_many");
    expect(underCap).not.toBe("error");
  });

  it("a kind repeated at a second artifact path is refused as artifact_kind_duplicate before the walk even runs", async () => {
    const source = await makeHarness();
    await createIdentity(source, "walk-dup-kind");
    const bundleDir = await newBundleDir("sanctuary-walk-dupkind-");
    await exportBundle(source, bundleDir);

    const manifestPath = join(bundleDir, "manifest.json");
    const manifest = JSON.parse(
      await readFile(manifestPath, "utf8")
    ) as ExitBundleManifest;
    const knownSignersEntry = manifest.body.artifacts.find(
      (a) => a.kind === "known_signers"
    );
    if (!knownSignersEntry) throw new Error("missing known_signers artifact entry");
    // A second manifest entry claiming the SAME kind at a DIFFERENT path -
    // both paths exist on disk (the duplicate is a byte-copy), so this
    // exercises the duplicate-KIND check specifically, not a missing-file
    // or unlisted-file failure.
    await writeFile(
      join(bundleDir, "artifacts", "known_signers_2.json"),
      await readFile(join(bundleDir, "artifacts", "known_signers.json"))
    );
    manifest.body.artifacts.push({
      ...knownSignersEntry,
      path: "artifacts/known_signers_2.json",
    });
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
    await resignManifest(bundleDir, source);

    const verified = await verifyExitBundle(bundleDir);
    expect(verified.passed).toBe(false);
    expect(verified.failure_class).toBe("artifact_kind_duplicate");
  });

  it("a bundle declaring the ORIGINAL V1 manifest version while still carrying all 8 known-signers-era artifact kinds is refused as artifact_set_invalid", async () => {
    const source = await makeHarness();
    await createIdentity(source, "walk-set-invalid");
    const bundleDir = await newBundleDir("sanctuary-walk-setinvalid-");
    await exportBundle(source, bundleDir);

    // Every current export already declares the known-signers manifest
    // version and carries all 8 kinds (verifier.ts's version-gate INVARIANT
    // - see reorg-surface-manifest.md). Forcing the OLD 7-kind literal back
    // onto an 8-artifact manifest is exactly the "declares a set outside
    // its own version's contract" shape the exact-set check exists to
    // catch, without needing to fabricate a 7-kind bundle by hand.
    const manifestPath = join(bundleDir, "manifest.json");
    const manifest = JSON.parse(
      await readFile(manifestPath, "utf8")
    ) as ExitBundleManifest;
    manifest.body.manifest_version = EXIT_BUNDLE_MANIFEST_VERSION;
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
    await resignManifest(bundleDir, source);

    const verified = await verifyExitBundle(bundleDir);
    expect(verified.passed).toBe(false);
    expect(verified.failure_class).toBe("artifact_set_invalid");
  });
});
