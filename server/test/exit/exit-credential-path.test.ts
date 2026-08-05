/**
 * Exit-cluster defects A3 / A4 (2026-08-05).
 *
 * One operator story, two composing failures:
 *
 *  A3: `_meta/key-params` was read with a bare JSON.parse and spread into
 *      `encrypted_state.json`, which the Ed25519-signed manifest then pins - so
 *      a malformed marker produced a cryptographically perfect bundle whose
 *      legacy re-key path NO import can use, and `exit verify` said PASS.
 *      Fixed at BOTH gates: the export refuses to sign it, and the import
 *      refuses to feed unvalidated params to Argon2id.
 *  A4: `--source-recovery-key` on a bundle with no `source_custody` block was
 *      SILENTLY reinterpreted as the raw source master. Every entry then failed
 *      to decrypt and the operator's first signal was a downstream
 *      SOURCE_KEY_MISMATCH naming the symptom, never the cause. Now refused
 *      (SOURCE_RECOVERY_KEY_AMBIGUOUS) unless the operator confirms the legacy
 *      interpretation with --legacy-source-master.
 *
 * This file also pins two properties of the import path that no fix in this PR
 * changes and that a later "hardening" would plausibly break:
 *
 *  - the custody gate's per-wrap TOLERANCE (`validateSourceCustody` in
 *    server/src/exit/bundle.ts). A block carrying one intact wrap beside one
 *    damaged wrap imports, because `unwrapMatchingWrap` catches per-wrap
 *    failures and returns on the first wrap that authenticates. An earlier cut
 *    of this cluster made that gate require EVERY wrap to be individually
 *    openable and thereby turned a working import into a refusal on the exit
 *    path, where the source fortress may already be gone.
 *  - an unreadable `entries` list is not an empty one (A8 state visibility).
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile, access } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Writable } from "node:stream";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { deriveMasterKey, derivePurposeKey } from "../../src/core/key-derivation.js";
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
  type ExportExitBundleResult,
} from "../../src/exit/index.js";
import { runExitCommand } from "../../src/exit/cli.js";

const SOURCE_PASSPHRASE = "correct horse battery fortress";

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

async function buildHarness(storage: MemoryStorage, masterKey: Uint8Array) {
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  const { tools: l1Tools, identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "passphrase",
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

type Harness = Awaited<ReturnType<typeof buildHarness>>;

/** A source fortress with one state entry and a bare random master. */
async function makeSource(label: string): Promise<Harness & { identityId: string }> {
  const harness = await buildHarness(new MemoryStorage(), generateRandomKey());
  const identity = await callTool(harness.tools, "identity_create", { label });
  const identityId = identity.identity_id as string;
  await callTool(harness.tools, "state_write", {
    namespace: "agent-memory",
    key: "handoff",
    value: "state that must survive the exit",
    identity_id: identityId,
  });
  return { ...harness, identityId };
}

async function makeDestination(): Promise<Harness & { identityId: string }> {
  const harness = await buildHarness(new MemoryStorage(), generateRandomKey());
  const identity = await callTool(harness.tools, "identity_create", {
    label: "destination-signer",
  });
  return { ...harness, identityId: identity.identity_id as string };
}

async function exportBundle(
  source: Harness,
  bundleDir: string,
  opts?: { mint?: boolean }
): Promise<ExportExitBundleResult> {
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
    stateNamespaces: ["agent-memory"],
    keySource: "passphrase",
    mintStateRekeyKey: opts?.mint ?? false,
  });
}

function sha256Hex(bytes: Uint8Array): string {
  return Array.from(hash(bytes))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Rewrite `artifacts/encrypted_state.json` and RE-SIGN the manifest so the
 * bundle verifies again. This is how a pre-A3-fix damaged bundle (one already
 * in the wild, signed with garbage `source_key_derivation`) is reproduced
 * without needing an exporter that still emits garbage.
 *
 * FAILURE MODE if done wrong: forgetting the aggregate hash or the size field
 * leaves a bundle that fails verification, and the import then refuses for the
 * WRONG reason - the test would pass while proving nothing about A3.
 */
async function patchEncryptedStateAndResign(
  bundleDir: string,
  source: Harness,
  mutate: (artifact: Record<string, unknown>) => void
): Promise<void> {
  const artifactPath = join(bundleDir, "artifacts", "encrypted_state.json");
  const artifact = JSON.parse(await readFile(artifactPath, "utf8")) as Record<
    string,
    unknown
  >;
  mutate(artifact);
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
  const out = {
    write(s: string | Uint8Array): boolean {
      chunks.push(typeof s === "string" ? s : Buffer.from(s).toString());
      return true;
    },
  } as unknown as Writable;
  const err = {
    write(s: string | Uint8Array): boolean {
      chunks.push(typeof s === "string" ? s : Buffer.from(s).toString());
      return true;
    },
  } as unknown as Writable;
  return { chunks, out, err };
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

describe("exit cluster A3/A4: which credential opens this bundle", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function newBundleDir(prefix = "sanctuary-exit-cred-"): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), prefix));
    tempDirs.push(dir);
    return dir;
  }

  // ---- A3: export gate -----------------------------------------------------

  it("A3 export: a malformed _meta/key-params marker is REFUSED, never signed", async () => {
    const source = await makeSource("a3-export-source");
    await source.storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify({ alg: "scrypt", salt: 42 }))
    );
    const bundleDir = await newBundleDir("sanctuary-a3-export-");

    await expect(exportBundle(source, bundleDir)).rejects.toThrow(
      /_meta\/key-params is malformed/
    );
    // The refusal happens before the manifest is signed, so no signed artifact
    // carrying the garbage exists. This is the whole point: a signed bundle
    // with an unusable re-key path is discovered only after the source
    // fortress is gone.
    expect(await exists(join(bundleDir, "manifest.json"))).toBe(false);
    expect(
      await exists(join(bundleDir, "artifacts", "encrypted_state.json"))
    ).toBe(false);
  });

  it("A3 export: the refusal names the remedy, not just the failure", async () => {
    const source = await makeSource("a3-remedy-source");
    await source.storage.write(
      "_meta",
      "key-params",
      stringToBytes("{ this is not json")
    );
    const bundleDir = await newBundleDir("sanctuary-a3-remedy-");
    await expect(exportBundle(source, bundleDir)).rejects.toThrow(
      /Repair the marker/
    );
  });

  it("A3 export: a GENUINE legacy marker still exports (no over-rejection)", async () => {
    const source = await makeSource("a3-genuine-source");
    const { params } = await deriveMasterKey("legacy-fortress-passphrase");
    await source.storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params))
    );
    const bundleDir = await newBundleDir("sanctuary-a3-genuine-");
    await exportBundle(source, bundleDir);

    const artifact = JSON.parse(
      await readFile(join(bundleDir, "artifacts", "encrypted_state.json"), "utf8")
    ) as { source_key_derivation?: Record<string, unknown> };
    expect(artifact.source_key_derivation).toEqual(params);
  });

  // ---- A3: import gate -----------------------------------------------------

  it("A3 import: malformed bundle-carried KDF params fail closed, not into Argon2id", async () => {
    // A pre-fix-damaged bundle already in the wild: signed, verifiable, and
    // carrying `l: 64` - a width no downstream HKDF here can consume.
    const source = await makeSource("a3-import-source");
    const { params } = await deriveMasterKey(SOURCE_PASSPHRASE);
    await source.storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params))
    );
    const bundleDir = await newBundleDir("sanctuary-a3-import-");
    await exportBundle(source, bundleDir);
    await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
      artifact.source_key_derivation = { ...params, l: 64 };
    });

    const destination = await makeDestination();
    await expect(
      importExitBundle({
        bundleDir,
        storage: destination.storage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
        forceRebind: true,
        sourcePassphrase: SOURCE_PASSPHRASE,
        destinationSignerIdentityId: destination.identityId,
      })
    ).rejects.toMatchObject({ code: "SOURCE_KDF_PARAMS_MALFORMED" });
    // Fail-closed, not partial: nothing staged, nothing written.
    expect(await destination.storage.list("_exit_imports")).toEqual([]);
    expect(
      await destination.stateStore.read("agent-memory", "handoff")
    ).toBeNull();
  });

  it("A3 import: an out-of-bounds Argon2id COST is refused before any derivation", async () => {
    // 2**30 KiB = 1 TiB of Argon2id memory. Post-fix this never reaches
    // hash-wasm; the cost bound is the point of the check.
    const source = await makeSource("a3-cost-source");
    const { params } = await deriveMasterKey(SOURCE_PASSPHRASE);
    await source.storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params))
    );
    const bundleDir = await newBundleDir("sanctuary-a3-cost-");
    await exportBundle(source, bundleDir);
    await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
      artifact.source_key_derivation = { ...params, m: 2 ** 30 };
    });

    const destination = await makeDestination();
    await expect(
      importExitBundle({
        bundleDir,
        storage: destination.storage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
        forceRebind: true,
        sourcePassphrase: SOURCE_PASSPHRASE,
        destinationSignerIdentityId: destination.identityId,
      })
    ).rejects.toMatchObject({ code: "SOURCE_KDF_PARAMS_MALFORMED" });
  });

  it("A3 verify: a damaged legacy marker is WARNED about, not passed silently", async () => {
    const source = await makeSource("a3-verify-source");
    const { params } = await deriveMasterKey(SOURCE_PASSPHRASE);
    await source.storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params))
    );
    const bundleDir = await newBundleDir("sanctuary-a3-verify-");
    await exportBundle(source, bundleDir);
    await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
      artifact.source_key_derivation = { ...params, l: 64 };
    });

    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({ argv: ["verify", bundleDir], out, err });
    const printed = chunks.join("");
    // The signature and every artifact hash are genuinely intact, so the
    // verdict stays PASS - overstating it as a verification failure would be
    // its own lie. What must not happen is a SILENT pass: the operator is told,
    // on the verify surface, that the bundle's passphrase re-key path is dead.
    expect(code).toBe(0);
    expect(printed).toContain("verdict: PASS");
    expect(printed).toContain(
      "malformed legacy re-key parameters (source_key_derivation)"
    );
    expect(printed).toContain("passphrase re-key path cannot run");
  });

  // ---- A4: the silent legacy reinterpretation ------------------------------

  it("A4: a recovery key with no source_custody is REFUSED, naming both causes", async () => {
    const source = await makeSource("a4-source");
    const bundleDir = await newBundleDir("sanctuary-a4-refuse-");
    await exportBundle(source, bundleDir, { mint: false });

    const destination = await makeDestination();
    let caught: unknown;
    try {
      await importExitBundle({
        bundleDir,
        storage: destination.storage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
        forceRebind: true,
        sourceRecoveryKey: toBase64url(generateRandomKey()),
        destinationSignerIdentityId: destination.identityId,
      });
    } catch (err) {
      caught = err;
    }
    expect((caught as { code?: string }).code).toBe(
      "SOURCE_RECOVERY_KEY_AMBIGUOUS"
    );
    // The refusal must render the re-run command VERBATIM (coordinator ruling
    // §8 Q2): a loud refusal that does not say what to type is a dead end.
    expect((caught as Error).message).toContain(
      "sanctuary exit import <dir> --activate --import-state " +
        "--source-recovery-key <key> --legacy-source-master"
    );
    expect(await destination.storage.list("_exit_imports")).toEqual([]);
  });

  it("A4: the legacy interpretation still works behind the explicit opt-in", async () => {
    const source = await makeSource("a4-optin-source");
    const bundleDir = await newBundleDir("sanctuary-a4-optin-");
    await exportBundle(source, bundleDir, { mint: false });

    const destination = await makeDestination();
    const result = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
      forceRebind: true,
      // The legacy semantics: this key IS the source master.
      sourceRecoveryKey: toBase64url(source.masterKey),
      legacyRecoveryKeyIsMaster: true,
      destinationSignerIdentityId: destination.identityId,
    });
    expect(result.state.status).toBe("rekeyed");
    expect(result.state.imported_keys).toBe(1);
    const read = await destination.stateStore.read("agent-memory", "handoff");
    expect(read?.value).toBe("state that must survive the exit");
  });

  it("A4: a WRONG key under the opt-in still fails closed, and names the interpretation", async () => {
    const source = await makeSource("a4-wrong-source");
    const bundleDir = await newBundleDir("sanctuary-a4-wrong-");
    await exportBundle(source, bundleDir, { mint: false });

    const destination = await makeDestination();
    let caught: unknown;
    try {
      await importExitBundle({
        bundleDir,
        storage: destination.storage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
        forceRebind: true,
        sourceRecoveryKey: toBase64url(generateRandomKey()),
        legacyRecoveryKeyIsMaster: true,
        destinationSignerIdentityId: destination.identityId,
      });
    } catch (err) {
      caught = err;
    }
    expect((caught as { code?: string }).code).toBe("SOURCE_KEY_MISMATCH");
    expect((caught as Error).message).toContain(
      "legacy raw-master semantics (--legacy-source-master)"
    );
  });

  it("A4: an envelope bundle is UNAFFECTED (source_custody path unchanged)", async () => {
    const source = await makeSource("a4-envelope-source");
    const bundleDir = await newBundleDir("sanctuary-a4-envelope-");
    const exported = await exportBundle(source, bundleDir, { mint: true });
    expect(exported.state_rekey_key).toBeDefined();

    const destination = await makeDestination();
    const result = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
      forceRebind: true,
      sourceRecoveryKey: exported.state_rekey_key!,
      destinationSignerIdentityId: destination.identityId,
    });
    expect(result.state.status).toBe("rekeyed");
  });

  it("A4: the CLI refuses --legacy-source-master without --source-recovery-key", async () => {
    // A real bundle: the import branch validates the directory + manifest
    // before any flag shape (so a wrong path is diagnosed first), and this
    // assertion is about the FLAG refusal, not the path refusal.
    const source = await makeSource("a4-cli-source");
    const bundleDir = await newBundleDir("sanctuary-a4-cli-");
    await exportBundle(source, bundleDir, { mint: false });

    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({
      argv: ["import", bundleDir, "--legacy-source-master"],
      out,
      err,
      env: {},
    });
    expect(code).toBe(2);
    expect(chunks.join("")).toContain(
      "--legacy-source-master requires --source-recovery-key"
    );
  });

  // ---- Import custody gate: per-wrap tolerance is load-bearing ------------

  it("import: a block with one intact wrap and one DAMAGED wrap still imports", async () => {
    // THE REGRESSION PIN. `unwrapMatchingWrap` (server/src/core/master-custody.ts)
    // walks the wraps in order, catches each wrap's failure individually, and
    // returns on the first that authenticates, so this bundle has always been
    // importable with the real re-key key. An intermediate cut of this cluster
    // moved the import gate onto a predicate that required EVERY wrap to be
    // individually openable, which converted this exact bundle from "imports"
    // into SOURCE_CUSTODY_MALFORMED - a new, unrecoverable refusal on the exit
    // path, where the source fortress may already be gone.
    //
    // The damaged wrap is `payload: null` specifically: that is the shape a
    // per-wrap payload check rejects and the shipped gate's
    // `typeof payload === "object"` admits, so this test fails against the
    // over-strict gate and passes against both the shipped one and any future
    // one that keeps the tolerance.
    const source = await makeSource("custody-tolerance-source");
    const bundleDir = await newBundleDir("sanctuary-custody-tolerance-");
    const exported = await exportBundle(source, bundleDir, { mint: true });
    const rekeyKey = exported.state_rekey_key!;
    expect(rekeyKey).toBeDefined();

    await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
      const custody = artifact.source_custody as Record<string, unknown>;
      const wraps = custody.wraps as Record<string, unknown>[];
      const intact = wraps[0]!;
      // Intact wrap FIRST, damaged wrap second: the damaged one is reached only
      // by a gate that inspects every wrap up front, never by the unwrap loop,
      // which has already returned.
      artifact.source_custody = {
        ...custody,
        wraps: [intact, { ...intact, id: "damaged-second-wrap", payload: null }],
      };
    });

    const destination = await makeDestination();
    const result = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
      forceRebind: true,
      sourceRecoveryKey: rekeyKey,
      destinationSignerIdentityId: destination.identityId,
    });
    expect(result.state.status).toBe("rekeyed");
    expect(result.state.imported_keys).toBeGreaterThan(0);
  });

  it("import: a wrap of the WRONG TYPE is still refused, even beside an intact one", async () => {
    // The other side of the same coin, so the tolerance above cannot be read as
    // "the gate stopped caring". The recovery-key-only rule IS per-wrap: one
    // smuggled passphrase wrap is enough to reopen the offline guessing oracle
    // and feed bundle-controlled Argon2id parameters into the unwrap path, so
    // "some wrap is safe" would not be a safety claim.
    const source = await makeSource("custody-type-source");
    const bundleDir = await newBundleDir("sanctuary-custody-type-");
    const exported = await exportBundle(source, bundleDir, { mint: true });
    const rekeyKey = exported.state_rekey_key!;

    await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
      const custody = artifact.source_custody as Record<string, unknown>;
      const wraps = custody.wraps as Record<string, unknown>[];
      const intact = wraps[0]!;
      artifact.source_custody = {
        ...custody,
        wraps: [intact, { ...intact, id: "passphrase-wrap", type: "passphrase" }],
      };
    });

    const destination = await makeDestination();
    await expect(
      importExitBundle({
        bundleDir,
        storage: destination.storage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
        forceRebind: true,
        sourceRecoveryKey: rekeyKey,
        destinationSignerIdentityId: destination.identityId,
      })
    ).rejects.toMatchObject({ code: "SOURCE_CUSTODY_MALFORMED" });
  });

  // ---- A8 state visibility: unreadable is not empty ------------------------

  it("A8 verify: an unreadable entries list is reported as unreadable, never as zero", async () => {
    // `entries` absent is the artifact-level twin of the wrap-payload defect:
    // the natural narrowing (`Array.isArray(x) ? x : []`) turns a corrupt
    // artifact into a confident "0 entries" and then fires the empty_reason
    // warning, which names the wrong defect entirely. The import path reads
    // `entries.length` off the same JSON and does not agree that it is empty.
    const source = await makeSource("a8-unreadable-source");
    const bundleDir = await newBundleDir("sanctuary-a8-unreadable-");
    await exportBundle(source, bundleDir, { mint: true });
    await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
      delete artifact.entries;
    });

    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({ argv: ["verify", bundleDir], out, err });
    const printed = chunks.join("");
    expect(code).toBe(0);
    expect(printed).toContain("state_entries: unreadable");
    expect(printed).not.toContain("state_entries: 0");
    expect(printed).toContain("no readable entries list");
    // The empty-bundle warning must NOT fire: this is not an empty bundle.
    expect(printed).not.toContain("no empty_reason marker");
  });

  // ---- Frozen-surface regression ------------------------------------------

  it("verify's previously-shipped text lines stay byte-identical and in order", async () => {
    const source = await makeSource("verify-shape-source");
    const bundleDir = await newBundleDir("sanctuary-verify-shape-");
    await exportBundle(source, bundleDir, { mint: true });

    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({ argv: ["verify", bundleDir], out, err });
    expect(code).toBe(0);
    const lines = chunks.join("").split("\n");
    // Every one of these shipped before this change and must survive
    // byte-for-byte (reorg-surface-manifest: user-visible display strings).
    expect(lines.slice(0, 6)).toEqual([
      "verdict: PASS",
      "manifest: verified",
      `identity: ${source.identityId}`,
      "artifacts: 7",
      "reputation: 0/0 attestations verified",
      "reputation completeness: verified",
    ]);
    // The A8 line is APPENDED, never interleaved.
    expect(lines[6]).toBe("state_entries: 1");
  });
});
