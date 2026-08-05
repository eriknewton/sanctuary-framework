/**
 * Exit-cluster defects A3 / A4 / A5 (2026-08-05).
 *
 * One operator story, three composing failures:
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
 *  A5: nothing answered "which credential does this bundle actually need?".
 *      `sanctuary exit inspect <dir>` answers it read-only.
 *
 * Fix round 1 (2026-08-05): A5's first cut classified ANY object-shaped
 * `source_custody` as the bundle re-key path, while import ran the full
 * shape-check and refused a malformed one. `exit inspect` therefore printed the
 * re-key import command and exited 0 for a bundle no key could ever open. The
 * custody differential below is the mechanical form of that fix: it drives the
 * SAME crafted bundles through `exit inspect` and a real `importExitBundle` and
 * asserts they agree case for case, so the "must mirror import" pin in
 * server/src/exit/verifier.ts is checked rather than asserted.
 *
 * Fix round 2 (2026-08-05): the same bug one level down. Round 1's shared
 * predicate checked the BLOCK and the wrap's declared fields but stopped at
 * `typeof payload === "object"`, so a wrap carrying `payload: null`, a missing
 * `iv`, or a ciphertext of the wrong length still classified `valid` and still
 * printed `credential: bundle-rekey-key` for a bundle that imports with
 * SOURCE_CREDENTIAL_INVALID. The differential table is therefore no longer a
 * list of reported bugs: it enumerates the class - block shape, wrap shape, and
 * every field the unwrap path reads, in each way it can be wrong - and it
 * carries three kinds of row on purpose:
 *
 *   `malformed`             no credential can open it; both sides must refuse.
 *   `opens`                 must survive; these are what stop the classifier
 *                           from degenerating to "everything is unusable", and
 *                           three of them mutate fields the unwrap path never
 *                           reads so an OVER-strict predicate fails too.
 *   `credential-dependent`  structurally perfect, opens only for the right
 *                           secret. Inspect names the path AND must print the
 *                           limit; this row is where the tool's honesty about
 *                           what it did not check is enforced.
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

describe("exit cluster A3/A4/A5: which credential opens this bundle", () => {
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

  it("A3 verify: a damaged bundle is diagnosed rather than passed silently", async () => {
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
    const code = await runExitCommand({ argv: ["inspect", bundleDir], out, err });
    const printed = chunks.join("");
    expect(printed).toContain("legacy_kdf_params: malformed");
    expect(printed).toContain("credential: unusable");
    // A verified-but-unopenable bundle must not report success.
    expect(code).toBe(1);
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

  // ---- A5: `sanctuary exit inspect` ---------------------------------------

  it("A5: inspect names the bundle re-key key path and exits 0", async () => {
    const source = await makeSource("a5-source");
    const bundleDir = await newBundleDir("sanctuary-a5-inspect-");
    await exportBundle(source, bundleDir, { mint: true });

    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({ argv: ["inspect", bundleDir], out, err });
    const printed = chunks.join("");
    expect(code).toBe(0);
    expect(printed).toContain("verdict: PASS");
    expect(printed).toContain("credential: bundle-rekey-key");
    expect(printed).toContain("state_entries: 1");
    expect(printed).toContain("namespaces: agent-memory");
    // The checkable runbook instruction that replaces the possession rule.
    expect(printed).toContain(
      "sanctuary exit import <dir> --activate --import-state " +
        "--source-recovery-key <bundle re-key key shown at export>"
    );
  });

  it("A5: inspect classifies a legacy passphrase bundle", async () => {
    const source = await makeSource("a5-legacy-source");
    const { params } = await deriveMasterKey(SOURCE_PASSPHRASE);
    await source.storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params))
    );
    const bundleDir = await newBundleDir("sanctuary-a5-legacy-");
    await exportBundle(source, bundleDir, { mint: false });

    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({ argv: ["inspect", bundleDir], out, err });
    expect(code).toBe(0);
    expect(chunks.join("")).toContain("credential: source-passphrase-legacy");
    expect(chunks.join("")).toContain("legacy_kdf_params: valid");
  });

  it("A5: inspect classifies a bundle with neither block as legacy-recovery-key-as-master", async () => {
    const source = await makeSource("a5-bare-source");
    const bundleDir = await newBundleDir("sanctuary-a5-bare-");
    await exportBundle(source, bundleDir, { mint: false });

    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({ argv: ["inspect", bundleDir], out, err });
    expect(code).toBe(0);
    const printed = chunks.join("");
    expect(printed).toContain("credential: legacy-recovery-key-as-master");
    expect(printed).toContain("--legacy-source-master");
  });

  it("A5: inspect is READ-ONLY - it never touches fortress state or credentials", async () => {
    const source = await makeSource("a5-readonly-source");
    const bundleDir = await newBundleDir("sanctuary-a5-readonly-");
    await exportBundle(source, bundleDir, { mint: true });

    // No SANCTUARY_PASSPHRASE, no SANCTUARY_RECOVERY_KEY. `openExitContext`
    // would throw on that env; inspect must not call it at all.
    const { out, err } = captureCli();
    const code = await runExitCommand({
      argv: ["inspect", bundleDir],
      out,
      err,
      env: {},
    });
    expect(code).toBe(0);
  });

  it("A5: inspect requires a directory argument", async () => {
    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({ argv: ["inspect"], out, err, env: {} });
    expect(code).toBe(2);
    expect(chunks.join("")).toContain("Usage: sanctuary exit inspect <dir>");
  });

  it("A5: inspect reports a non-bundle directory as an error, not a crash", async () => {
    const dir = await newBundleDir("sanctuary-a5-notabundle-");
    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({ argv: ["inspect", dir], out, err, env: {} });
    expect(code).toBe(1);
    expect(chunks.join("")).toContain("Not a valid SANCTUARY_EXIT_BUNDLE_V1 directory");
  });

  // ---- A5 fix round: inspect must agree with import about custody ---------

  /**
   * What `exit inspect` is allowed to conclude about a `source_custody` block,
   * holding NO credential.
   *
   *  - `opens`: the block is intact and the real re-key key imports it.
   *  - `malformed`: NO credential of any kind can open it, so inspect must say
   *    so and exit non-zero. Import refuses it with SOURCE_CUSTODY_MALFORMED.
   *  - `credential-dependent`: the block is structurally everything import can
   *    check before it needs a secret, and only the secret itself can decide.
   *    Inspect names the re-key path AND must state that bound; import with the
   *    right-shaped-but-non-authenticating wrap fails SOURCE_CREDENTIAL_INVALID.
   *    This row is the honest edge of the tool, not a hole in it.
   */
  type CustodyOutcome = "opens" | "malformed" | "credential-dependent";

  /** Replace the single minted wrap's payload, leaving the rest of the block. */
  function withPayload(
    real: Record<string, unknown>,
    patch: (payload: Record<string, unknown>) => unknown
  ): unknown {
    const wrap = { ...((real.wraps as Record<string, unknown>[])[0] ?? {}) };
    const payload = { ...(wrap.payload as Record<string, unknown>) };
    const replacement = patch(payload);
    if (replacement === undefined) delete wrap.payload;
    else wrap.payload = replacement;
    return { ...real, wraps: [wrap] };
  }

  /** A base64url string that decodes to exactly `n` bytes. */
  function b64OfLength(n: number): string {
    return toBase64url(new Uint8Array(n).fill(0x41));
  }

  /**
   * Every way a `source_custody` block can be damaged, plus the untouched
   * control. Each case is applied to a REAL minted bundle and re-signed, so the
   * only thing under test is the block itself.
   *
   * The table is the enumeration of the equivalence class, not a list of
   * reported bugs: block shape, wrap shape, and then EVERY field the unwrap
   * path (`core/master-custody.ts` unwrapMatchingWrap -> `core/encryption.ts`
   * decrypt) actually reads, in each way it can be wrong - absent, wrong type,
   * wrong constant, undecodable, wrong decoded length.
   *
   * FAILURE MODE if a case is written wrong: a mutation that leaves the block
   * VALID makes the case assert the happy path twice and prove nothing. The
   * `opens` rows are what keep the whole table honest - if the classifier ever
   * degenerates to "everything is unusable", every one of them fails. Three of
   * them mutate fields the unwrap path never reads (`ts`, `verified`,
   * `created_at`) or duplicate a wrap id, precisely so an over-strict predicate
   * that validates the DECLARED type instead of the CONSUMED fields is caught.
   */
  const custodyCases: Array<{
    label: string;
    /** Returns the replacement block, given the real minted one. */
    mutate: (real: Record<string, unknown>) => unknown;
    outcome: CustodyOutcome;
  }> = [
    // ---- block shape ----
    {
      label: "valid custody (control)",
      mutate: (real) => real,
      outcome: "opens",
    },
    {
      label: "wrong format token",
      mutate: (real) => ({ ...real, format: "SANCTUARY_EXIT_SOURCE_CUSTODY_V2" }),
      outcome: "malformed",
    },
    {
      label: "format field missing entirely",
      mutate: (real) => ({ wraps: real.wraps }),
      outcome: "malformed",
    },
    {
      label: "wraps is not an array",
      mutate: (real) => ({ ...real, wraps: { id: "w1" } }),
      outcome: "malformed",
    },
    {
      label: "wraps is empty",
      mutate: (real) => ({ ...real, wraps: [] }),
      outcome: "malformed",
    },
    {
      label: "more wraps than the cap allows",
      // 5 > SOURCE_CUSTODY_MAX_WRAPS (4). The cap bounds unwrap work on a
      // crafted bundle; a classifier that ignores it advertises a re-key path
      // the import gate will refuse.
      mutate: (real) => ({
        ...real,
        wraps: Array.from({ length: 5 }, () => (real.wraps as unknown[])[0]),
      }),
      outcome: "malformed",
    },
    {
      label: "source_custody is null",
      mutate: () => null,
      outcome: "malformed",
    },
    // ---- wrap shape ----
    {
      label: "passphrase-type wrap smuggled in",
      // The security-relevant case: a passphrase wrap here would reintroduce
      // the offline guessing oracle and feed bundle-controlled Argon2id
      // parameters into the unwrap path. Import refuses it, so inspect must
      // never present it as an openable bundle.
      mutate: (real) => ({
        ...real,
        wraps: [
          {
            ...((real.wraps as Record<string, unknown>[])[0] ?? {}),
            type: "passphrase",
          },
        ],
      }),
      outcome: "malformed",
    },
    {
      label: "wrap missing its id",
      mutate: (real) => {
        const wrap = { ...((real.wraps as Record<string, unknown>[])[0] ?? {}) };
        delete wrap.id;
        return { ...real, wraps: [wrap] };
      },
      outcome: "malformed",
    },
    // ---- wrap payload container ----
    {
      label: "wrap payload is null",
      // `typeof null === "object"`, which is exactly how the round-2 predicate
      // let this through while import died on `payload.v`.
      mutate: (real) => withPayload(real, () => null),
      outcome: "malformed",
    },
    {
      label: "wrap payload is an array",
      mutate: (real) => withPayload(real, () => []),
      outcome: "malformed",
    },
    {
      label: "wrap payload is a string",
      mutate: (real) => withPayload(real, () => "not-a-payload"),
      outcome: "malformed",
    },
    {
      label: "wrap payload missing entirely",
      mutate: (real) => withPayload(real, () => undefined),
      outcome: "malformed",
    },
    // ---- payload version / algorithm ----
    {
      label: "payload version missing",
      mutate: (real) =>
        withPayload(real, (payload) => {
          delete payload.v;
          return payload;
        }),
      outcome: "malformed",
    },
    {
      label: "payload version is 2",
      mutate: (real) => withPayload(real, (payload) => ({ ...payload, v: 2 })),
      outcome: "malformed",
    },
    {
      label: "payload version is the string \"1\"",
      // decrypt compares with `!==`, so "1" is a different value, not a
      // coercible one. A predicate using `==` would wrongly pass this.
      mutate: (real) => withPayload(real, (payload) => ({ ...payload, v: "1" })),
      outcome: "malformed",
    },
    {
      label: "payload alg missing",
      mutate: (real) =>
        withPayload(real, (payload) => {
          delete payload.alg;
          return payload;
        }),
      outcome: "malformed",
    },
    {
      label: "payload alg is aes-128-gcm",
      mutate: (real) =>
        withPayload(real, (payload) => ({ ...payload, alg: "aes-128-gcm" })),
      outcome: "malformed",
    },
    // ---- payload iv ----
    {
      label: "payload iv missing",
      mutate: (real) =>
        withPayload(real, (payload) => {
          delete payload.iv;
          return payload;
        }),
      outcome: "malformed",
    },
    {
      label: "payload iv is a number",
      mutate: (real) => withPayload(real, (payload) => ({ ...payload, iv: 12 })),
      outcome: "malformed",
    },
    {
      label: "payload iv is empty",
      mutate: (real) => withPayload(real, (payload) => ({ ...payload, iv: "" })),
      outcome: "malformed",
    },
    {
      label: "payload iv decodes below the GCM nonce floor",
      // 6 < 8. `fromBase64url` is lenient, so the ONLY observable defect is the
      // decoded byte count; the AES-GCM construction refuses it outright.
      mutate: (real) =>
        withPayload(real, (payload) => ({ ...payload, iv: b64OfLength(6) })),
      outcome: "malformed",
    },
    {
      label: "payload iv is not base64url at all",
      // Lenient decoding drops every out-of-alphabet character, so this decodes
      // to zero bytes rather than throwing - a classifier that only checks
      // `typeof iv === "string"` sees nothing wrong.
      mutate: (real) =>
        withPayload(real, (payload) => ({ ...payload, iv: "!!!!" })),
      outcome: "malformed",
    },
    // ---- payload ciphertext ----
    {
      label: "payload ct missing",
      mutate: (real) =>
        withPayload(real, (payload) => {
          delete payload.ct;
          return payload;
        }),
      outcome: "malformed",
    },
    {
      label: "payload ct is a number",
      mutate: (real) => withPayload(real, (payload) => ({ ...payload, ct: 0 })),
      outcome: "malformed",
    },
    {
      label: "payload ct is empty",
      mutate: (real) => withPayload(real, (payload) => ({ ...payload, ct: "" })),
      outcome: "malformed",
    },
    {
      label: "payload ct is one byte short of master+tag",
      mutate: (real) =>
        withPayload(real, (payload) => ({ ...payload, ct: b64OfLength(47) })),
      outcome: "malformed",
    },
    {
      label: "payload ct is longer than master+tag",
      mutate: (real) =>
        withPayload(real, (payload) => ({ ...payload, ct: b64OfLength(64) })),
      outcome: "malformed",
    },
    // ---- structurally perfect, only the credential can tell ----
    {
      label: "payload ct is the right length but does not authenticate",
      // THE BOUND. Nothing readable without the re-key key distinguishes this
      // from the control; only GCM authentication does. Inspect must still name
      // the re-key path and must say, in its own output, that it checked shape
      // and not the key.
      mutate: (real) =>
        withPayload(real, (payload) => ({ ...payload, ct: b64OfLength(48) })),
      outcome: "credential-dependent",
    },
    // ---- fields the unwrap path never reads: must NOT be rejected ----
    {
      label: "payload ts removed (never read by decrypt)",
      mutate: (real) =>
        withPayload(real, (payload) => {
          delete payload.ts;
          return payload;
        }),
      outcome: "opens",
    },
    {
      label: "wrap verified/created_at removed (never read by unwrap)",
      mutate: (real) => {
        const wrap = { ...((real.wraps as Record<string, unknown>[])[0] ?? {}) };
        delete wrap.verified;
        delete wrap.created_at;
        return { ...real, wraps: [wrap] };
      },
      outcome: "opens",
    },
    {
      label: "one intact wrap and one damaged wrap",
      // Adversarial: the damaged wrap is not the one a key would open, so a
      // classifier that stopped at the first usable wrap would call this
      // openable. Import runs the shape gate over EVERY wrap before it tries
      // any of them, so it refuses the block whole; inspect must do the same.
      mutate: (real) => {
        const wrap = (real.wraps as Record<string, unknown>[])[0]!;
        return {
          ...real,
          wraps: [wrap, { ...wrap, id: "second-wrap", payload: null }],
        };
      },
      outcome: "malformed",
    },
    {
      label: "ciphertext carries a newline the lenient decoder drops",
      // Adversarial, and the reason this file decodes with `fromBase64url` and
      // not `fromBase64urlStrict`: Node's base64 decoder silently drops
      // whitespace, so this still decodes to the same 48 real bytes and the
      // import opens it. A predicate that decoded STRICTLY would report
      // `unusable` for a bundle that works - the same disagreement, inverted.
      mutate: (real) => {
        const wrap = { ...((real.wraps as Record<string, unknown>[])[0] ?? {}) };
        const payload = { ...(wrap.payload as Record<string, unknown>) };
        const ct = payload.ct as string;
        payload.ct = ct.slice(0, 10) + "\n" + ct.slice(10);
        wrap.payload = payload;
        return { ...real, wraps: [wrap] };
      },
      outcome: "opens",
    },
    {
      label: "a non-authenticating wrap listed BEFORE the real one",
      // Adversarial: `unwrapMatchingWrap` walks wraps in order and returns on
      // the first that authenticates, so a decoy in front does not stop the
      // import. Inspect must not treat "some wrap is a decoy" as unusable.
      mutate: (real) => {
        const wrap = (real.wraps as Record<string, unknown>[])[0]!;
        const decoy = {
          ...wrap,
          id: "decoy-wrap",
          payload: {
            ...(wrap.payload as Record<string, unknown>),
            ct: b64OfLength(48),
          },
        };
        return { ...real, wraps: [decoy, wrap] };
      },
      outcome: "opens",
    },
    {
      label: "wrap id rewritten so no AAD can match",
      // Adversarial, and a SECOND member of the credential-dependent class with
      // a different mechanism than a corrupted ciphertext: the id is bound into
      // the AEAD's associated data, so rewriting it breaks authentication while
      // leaving every readable field perfect. Nothing without the key can tell
      // this from the control, and inspect must not pretend otherwise.
      mutate: (real) => ({
        ...real,
        wraps: [
          {
            ...((real.wraps as Record<string, unknown>[])[0] ?? {}),
            id: "rewritten-wrap-id",
          },
        ],
      }),
      outcome: "credential-dependent",
    },
    {
      label: "the same wrap listed twice (duplicate ids)",
      // Enumerated and DELIBERATELY not rejected: `unwrapMatchingWrap` tries
      // wraps in order and the first one authenticates, so a duplicate id does
      // not stop an import. Rejecting it would make inspect say "unusable"
      // about a bundle that opens - the same disagreement, mirrored.
      mutate: (real) => ({
        ...real,
        wraps: [(real.wraps as unknown[])[0], (real.wraps as unknown[])[0]],
      }),
      outcome: "opens",
    },
  ];

  for (const custodyCase of custodyCases) {
    it(`A5 differential: inspect and import agree on "${custodyCase.label}"`, async () => {
      const source = await makeSource("a5-differential-source");
      const bundleDir = await newBundleDir("sanctuary-a5-diff-");
      const exported = await exportBundle(source, bundleDir, { mint: true });
      const rekeyKey = exported.state_rekey_key!;
      expect(rekeyKey).toBeDefined();

      const artifactPath = join(bundleDir, "artifacts", "encrypted_state.json");
      const realCustody = (
        JSON.parse(await readFile(artifactPath, "utf8")) as {
          source_custody: Record<string, unknown>;
        }
      ).source_custody;
      await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
        artifact.source_custody = custodyCase.mutate(realCustody);
      });

      // What the operator is told, read-only, with the source fortress gone.
      const { chunks, out, err } = captureCli();
      const inspectCode = await runExitCommand({
        argv: ["inspect", bundleDir],
        out,
        err,
      });
      const printed = chunks.join("");
      const inspectSaysOpenable =
        inspectCode === 0 && printed.includes("credential: bundle-rekey-key");

      // What actually happens when they try it, with the real re-key key.
      const destination = await makeDestination();
      let importCode: string | undefined;
      let importSucceeded = false;
      try {
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
        importSucceeded = result.state.status === "rekeyed";
      } catch (e) {
        importCode = (e as { code?: string }).code;
      }

      // THE ASSERTION: the advice and the reality are the same answer.
      if (custodyCase.outcome === "opens") {
        expect(importSucceeded).toBe(true);
        expect(inspectSaysOpenable).toBe(true);
        expect(printed).toContain("source_custody: valid");
        expect(inspectCode).toBe(0);
        return;
      }

      if (custodyCase.outcome === "credential-dependent") {
        // Inspect still names the re-key path (it cannot know better), and the
        // import fails on AUTHENTICATION, not on shape. The two are only
        // consistent because inspect states the limit in its own output; an
        // unqualified "bundle-rekey-key" here would be the original overclaim.
        expect(importSucceeded).toBe(false);
        expect(importCode).toBe("SOURCE_CREDENTIAL_INVALID");
        expect(inspectSaysOpenable).toBe(true);
        expect(printed).toContain("source_custody: valid");
        expect(printed).toContain(
          "credential check: structure only (no credential held)"
        );
        expect(inspectCode).toBe(0);
        return;
      }

      expect(importSucceeded).toBe(false);
      expect(importCode).toBe("SOURCE_CUSTODY_MALFORMED");
      // Not merely "not bundle-rekey-key": a verified-but-unopenable bundle is
      // a FAILURE for this command, and the report must name the damaged block
      // so the operator knows what to re-export.
      expect(inspectSaysOpenable).toBe(false);
      expect(printed).toContain("credential: unusable");
      expect(printed).toContain("source_custody: malformed");
      expect(printed).toContain("re-key block (source_custody) is malformed");
      expect(inspectCode).toBe(1);
    });
  }

  it("A5 pin scope: a programmatic sourceMasterKey import bypasses the custody gate inspect reports on", async () => {
    // The contract pin in server/src/exit/verifier.ts used to claim inspect
    // mirrors `resolveSourceMasterKey` outright. It does not: that function
    // returns `opts.sourceMasterKey` BEFORE `validateSourceCustody`, so this
    // import succeeds on a bundle inspect calls `unusable`. The pin now scopes
    // itself to the CLI credential paths, and this test is what holds it there
    // instead of prose. If a `--source-master-key` CLI flag is ever added, this
    // divergence becomes reachable by an operator and inspect's verdict becomes
    // wrong; this test is the place that will look wrong first.
    const source = await makeSource("a5-pin-scope-source");
    const bundleDir = await newBundleDir("sanctuary-a5-pinscope-");
    await exportBundle(source, bundleDir, { mint: true });
    await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
      const custody = artifact.source_custody as Record<string, unknown>;
      const wrap = { ...((custody.wraps as Record<string, unknown>[])[0] ?? {}) };
      wrap.payload = null;
      artifact.source_custody = { ...custody, wraps: [wrap] };
    });

    const { chunks, out, err } = captureCli();
    const inspectCode = await runExitCommand({ argv: ["inspect", bundleDir], out, err });
    const printed = chunks.join("");
    expect(inspectCode).toBe(1);
    expect(printed).toContain("credential: unusable");

    // No CLI flag reaches this option; only a programmatic caller can.
    const cliSource = await readFile(
      new URL("../../src/exit/cli.ts", import.meta.url),
      "utf8"
    );
    expect(cliSource).not.toContain("sourceMasterKey");

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
      sourceMasterKey: source.masterKey,
      destinationSignerIdentityId: destination.identityId,
    });
    expect(result.state.status).toBe("rekeyed");
    expect(result.state.imported_keys).toBeGreaterThan(0);
  });

  it("A5 differential: a malformed custody block outranks a usable legacy marker", async () => {
    // Import validates custody BEFORE it looks at anything else, so a damaged
    // block kills the legacy passphrase path with it. A classifier that checked
    // the legacy marker first would print a passphrase command that cannot run.
    const source = await makeSource("a5-custody-outranks-source");
    const { params } = await deriveMasterKey(SOURCE_PASSPHRASE);
    await source.storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params))
    );
    const bundleDir = await newBundleDir("sanctuary-a5-outrank-");
    await exportBundle(source, bundleDir, { mint: true });
    await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
      artifact.source_custody = { format: "nope", wraps: [] };
    });

    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({ argv: ["inspect", bundleDir], out, err });
    const printed = chunks.join("");
    expect(printed).toContain("legacy_kdf_params: valid");
    expect(printed).toContain("credential: unusable");
    expect(code).toBe(1);

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
    ).rejects.toMatchObject({ code: "SOURCE_CUSTODY_MALFORMED" });
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
