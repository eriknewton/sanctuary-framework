/**
 * Exit-cluster defects A8 / A9 (2026-08-06).
 *
 *  A8: a zero-entry `encrypted_state.json` was indistinguishable from an
 *      export bug. The signed manifest covers an empty artifact exactly as a
 *      full one, `exit verify` printed no state count, and import mapped zero
 *      entries to `state.status: "not_requested"` even when the operator had
 *      supplied source credentials (i.e. had explicitly asked for state).
 *      Fixed with an `empty_reason` marker INSIDE the artifact (signed
 *      transitively via the artifact hash, so no manifest schema change), a
 *      verifier `state` block, and the additive `"empty_bundle"` status.
 *  A9: option-shape refusals fired only AFTER `mkdir` + the export audit
 *      append + `artifacts/public_identity.json` had landed, leaving a partial
 *      unsigned directory a later run could mistake for a bundle.
 *
 * Backward compatibility is asserted here too: a marker-less zero-entry bundle
 * (what every pre-fix exporter wrote) must still verify and still import.
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile, access } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Writable } from "node:stream";
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
import {
  exportExitBundle,
  importExitBundle,
  verifyExitBundle,
} from "../../src/exit/index.js";
import { runExitCommand } from "../../src/exit/cli.js";

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
    stateStore,
    identityManager,
    reputationStore,
    tools: [...l1Tools, ...l4Tools] as ToolDef[],
  };
}

type Harness = Awaited<ReturnType<typeof makeHarness>>;

async function exportFrom(
  source: Harness,
  bundleDir: string,
  namespaces?: string[]
) {
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
    ...(namespaces !== undefined ? { stateNamespaces: namespaces } : {}),
    keySource: "recovery-key",
    mintStateRekeyKey: true,
  });
}

function sha256Hex(bytes: Uint8Array): string {
  return Array.from(hash(bytes))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Turn a freshly-written bundle back into what a PRE-marker exporter produced:
 * strip `empty_reason` and re-sign. This is the backward-compatibility fixture;
 * without it "old bundles still work" would be an untested claim.
 */
async function stripEmptyReasonAndResign(
  bundleDir: string,
  source: Harness
): Promise<void> {
  const artifactPath = join(bundleDir, "artifacts", "encrypted_state.json");
  const artifact = JSON.parse(await readFile(artifactPath, "utf8")) as Record<
    string,
    unknown
  >;
  delete artifact.empty_reason;
  await writeFile(artifactPath, JSON.stringify(artifact, null, 2) + "\n");

  const manifestPath = join(bundleDir, "manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
    body: {
      artifacts: Array<{ path: string; hash: string; size_bytes: number }>;
      artifacts_aggregate_hash: string;
    };
    signature: string;
  };
  for (const entry of manifest.body.artifacts) {
    const bytes = new Uint8Array(await readFile(join(bundleDir, entry.path)));
    entry.hash = sha256Hex(bytes);
    entry.size_bytes = bytes.length;
  }
  manifest.body.artifacts_aggregate_hash = sha256Hex(
    stringToBytes(canonicalize(manifest.body.artifacts))
  );
  const identity = source.identityManager.getDefault()!;
  manifest.signature = toBase64url(
    identitySign(
      canonicalizeToBytes(manifest.body),
      identity.encrypted_private_key,
      derivePurposeKey(source.masterKey, "identity-encryption")
    )
  );
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
}

function captureCli(): { chunks: string[]; out: Writable; err: Writable } {
  const chunks: string[] = [];
  const sink = {
    write(s: string | Uint8Array): boolean {
      chunks.push(typeof s === "string" ? s : Buffer.from(s).toString());
      return true;
    },
  } as unknown as Writable;
  return { chunks, out: sink, err: sink };
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

describe("exit cluster A8: an empty bundle must say why it is empty", () => {
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

  it("export: a zero-entry artifact carries empty_reason=fortress_state_empty", async () => {
    const source = await makeHarness();
    await callTool(source.tools, "identity_create", { label: "empty-source" });
    const bundleDir = await newBundleDir("sanctuary-a8-export-");
    await exportFrom(source, bundleDir);

    const artifact = JSON.parse(
      await readFile(join(bundleDir, "artifacts", "encrypted_state.json"), "utf8")
    ) as { total_keys: number; empty_reason?: string };
    expect(artifact.total_keys).toBe(0);
    expect(artifact.empty_reason).toBe("fortress_state_empty");
  });

  it("export: a partition that excludes everything says so, distinctly", async () => {
    const source = await makeHarness();
    const identity = await callTool(source.tools, "identity_create", {
      label: "partition-source",
    });
    await callTool(source.tools, "state_write", {
      namespace: "user-data",
      key: "k1",
      value: "v1",
      identity_id: identity.identity_id as string,
    });

    const bundleDir = await newBundleDir("sanctuary-a8-partition-");
    // Partition on with no consent releases: every unsealed entry fails toward
    // "stays with the operator", so the bundle is empty for a REASON that is
    // not "the fortress was empty".
    await exportExitBundle({
      bundleDir,
      storage: source.storage,
      masterKey: source.masterKey,
      identityManager: source.identityManager,
      auditLog: source.auditLog,
      reputationStore: source.reputationStore,
      policy: DEFAULT_POLICY,
      config: defaultConfig(),
      stateNamespaces: ["user-data"],
      keySource: "recovery-key",
      memoryClassPartition: {},
    });

    const artifact = JSON.parse(
      await readFile(join(bundleDir, "artifacts", "encrypted_state.json"), "utf8")
    ) as { total_keys: number; empty_reason?: string };
    expect(artifact.total_keys).toBe(0);
    expect(artifact.empty_reason).toBe("partition_excluded_all");
  });

  it("export: a NON-empty bundle carries no empty_reason at all", async () => {
    const source = await makeHarness();
    const identity = await callTool(source.tools, "identity_create", {
      label: "nonempty-source",
    });
    await callTool(source.tools, "state_write", {
      namespace: "user-data",
      key: "k1",
      value: "v1",
      identity_id: identity.identity_id as string,
    });
    const bundleDir = await newBundleDir("sanctuary-a8-nonempty-");
    await exportFrom(source, bundleDir, ["user-data"]);

    const artifact = JSON.parse(
      await readFile(join(bundleDir, "artifacts", "encrypted_state.json"), "utf8")
    ) as { total_keys: number; empty_reason?: string };
    expect(artifact.total_keys).toBe(1);
    expect(artifact.empty_reason).toBeUndefined();
  });

  it("verify: the state block surfaces the entry count and the marker", async () => {
    const source = await makeHarness();
    await callTool(source.tools, "identity_create", { label: "verify-source" });
    const bundleDir = await newBundleDir("sanctuary-a8-verify-");
    await exportFrom(source, bundleDir);

    const result = await verifyExitBundle(bundleDir);
    expect(result.passed).toBe(true);
    expect(result.state?.entry_count).toBe(0);
    expect(result.state?.empty_reason).toBe("fortress_state_empty");
    expect(result.state?.empty_reason_missing).toBe(false);
    expect(result.state?.credential_path).toBe("none-required");

    const { chunks, out, err } = captureCli();
    await runExitCommand({ argv: ["verify", bundleDir], out, err });
    const printed = chunks.join("");
    expect(printed).toContain("state_entries: 0");
    expect(printed).toContain("empty_reason: fortress_state_empty");
  });

  it("import: zero entries WITH credentials reports empty_bundle, not not_requested", async () => {
    const source = await makeHarness();
    await callTool(source.tools, "identity_create", { label: "import-source" });
    const bundleDir = await newBundleDir("sanctuary-a8-import-");
    await exportFrom(source, bundleDir);

    const destination = await makeHarness();
    const destIdentity = await callTool(destination.tools, "identity_create", {
      label: "dest-signer",
    });
    const result = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
      forceRebind: true,
      // The operator explicitly asked for state by supplying a credential.
      sourceRecoveryKey: toBase64url(generateRandomKey()),
      destinationSignerIdentityId: destIdentity.identity_id as string,
    });
    expect(result.state.status).toBe("empty_bundle");
    expect(result.warnings.join("\n")).toContain(
      "empty_reason=fortress_state_empty"
    );
  });

  it("import: zero entries WITHOUT credentials keeps not_requested plus a warning", async () => {
    const source = await makeHarness();
    await callTool(source.tools, "identity_create", { label: "nocred-source" });
    const bundleDir = await newBundleDir("sanctuary-a8-nocred-");
    await exportFrom(source, bundleDir);

    const destination = await makeHarness();
    const destIdentity = await callTool(destination.tools, "identity_create", {
      label: "dest-signer",
    });
    const result = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
      forceRebind: true,
      destinationSignerIdentityId: destIdentity.identity_id as string,
    });
    expect(result.state.status).toBe("not_requested");
    expect(result.warnings.join("\n")).toContain("zero state entries");
  });

  // ---- Backward compatibility: pre-marker bundles --------------------------

  it("compat: a marker-LESS zero-entry bundle still verifies, with a loud warning", async () => {
    const source = await makeHarness();
    await callTool(source.tools, "identity_create", { label: "compat-source" });
    const bundleDir = await newBundleDir("sanctuary-a8-compat-verify-");
    await exportFrom(source, bundleDir);
    await stripEmptyReasonAndResign(bundleDir, source);

    const result = await verifyExitBundle(bundleDir);
    // No failure: an old bundle verifies exactly as it did before.
    expect(result.passed).toBe(true);
    expect(result.state?.empty_reason).toBeUndefined();
    expect(result.state?.empty_reason_missing).toBe(true);
    expect(result.warnings.join("\n")).toContain("no empty_reason marker");
  });

  it("compat: a marker-LESS zero-entry bundle still imports as not_requested", async () => {
    const source = await makeHarness();
    await callTool(source.tools, "identity_create", { label: "compat2-source" });
    const bundleDir = await newBundleDir("sanctuary-a8-compat-import-");
    await exportFrom(source, bundleDir);
    await stripEmptyReasonAndResign(bundleDir, source);

    const destination = await makeHarness();
    const destIdentity = await callTool(destination.tools, "identity_create", {
      label: "dest-signer",
    });
    const result = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
      forceRebind: true,
      destinationSignerIdentityId: destIdentity.identity_id as string,
    });
    expect(result.state.status).toBe("not_requested");
    expect(result.warnings.join("\n")).toContain("NO empty_reason marker");
  });
});

describe("exit cluster A9: no side effects before an option-shape refusal", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("a supplied-but-empty stateNamespaces leaves NO partial bundle directory", async () => {
    const source = await makeHarness();
    await callTool(source.tools, "identity_create", { label: "a9-source" });
    const parent = await mkdtemp(join(tmpdir(), "sanctuary-a9-"));
    tempDirs.push(parent);
    // Deliberately a path that does not exist yet, so "was anything created?"
    // is a clean yes/no rather than a diff against a pre-existing directory.
    const bundleDir = join(parent, "bundle");

    await expect(exportFrom(source, bundleDir, [])).rejects.toThrow(
      /stateNamespaces was supplied but empty/
    );
    // Pre-fix this directory existed and held artifacts/public_identity.json:
    // a partial, unsigned artifact tree a later run could mistake for a bundle.
    expect(await exists(bundleDir)).toBe(false);
  });

  it("the partition/legacy-opt-out XOR also refuses before any write", async () => {
    const source = await makeHarness();
    await callTool(source.tools, "identity_create", { label: "a9-xor-source" });
    const parent = await mkdtemp(join(tmpdir(), "sanctuary-a9-xor-"));
    tempDirs.push(parent);
    const bundleDir = join(parent, "bundle");

    await expect(
      exportExitBundle({
        bundleDir,
        storage: source.storage,
        masterKey: source.masterKey,
        identityManager: source.identityManager,
        auditLog: source.auditLog,
        reputationStore: source.reputationStore,
        policy: DEFAULT_POLICY,
        config: defaultConfig(),
        keySource: "recovery-key",
        // Neither memoryClassPartition nor unpartitionedLegacyExport.
      })
    ).rejects.toThrow(/exactly one of memoryClassPartition/);
    expect(await exists(bundleDir)).toBe(false);
  });

  it("a malformed --did-web binding also refuses before any write", async () => {
    // The third option-shape refusal on this path. It used to fire AFTER all
    // seven artifacts had been written, leaving a complete-looking artifact
    // tree with no manifest.json - exactly the partial directory A9 is about.
    const source = await makeHarness();
    await callTool(source.tools, "identity_create", { label: "a9-didweb-source" });
    const parent = await mkdtemp(join(tmpdir(), "sanctuary-a9-didweb-"));
    tempDirs.push(parent);
    const bundleDir = join(parent, "bundle");

    await expect(
      exportExitBundle({
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
        didWeb: { identifier: "did:web:one.example", authority_host: "two.example" },
      })
    ).rejects.toThrow(/does not match did_web.authority_host/);
    expect(await exists(bundleDir)).toBe(false);
  });

  it("a VALID export is unaffected by the hoisted check", async () => {
    const source = await makeHarness();
    const identity = await callTool(source.tools, "identity_create", {
      label: "a9-valid-source",
    });
    await callTool(source.tools, "state_write", {
      namespace: "user-data",
      key: "k1",
      value: "v1",
      identity_id: identity.identity_id as string,
    });
    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-a9-valid-"));
    tempDirs.push(bundleDir);
    const result = await exportFrom(source, bundleDir, ["user-data"]);
    expect(result.state_entry_count).toBe(1);
    expect(await exists(join(bundleDir, "manifest.json"))).toBe(true);
  });
});
