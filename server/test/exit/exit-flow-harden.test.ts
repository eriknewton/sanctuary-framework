/**
 * Exit-flow harden findings (2026-06-25).
 *
 * Five defects on the "no lock-in / you control your data" portability pillar:
 *
 *  H1 (HIGH, custody-adjacent): importExitBundle must NOT zero a
 *      caller-supplied `opts.sourceMasterKey` (use-after-zero of the caller's
 *      own buffer), but MUST still zero key material it derived/unwrapped
 *      itself. Provenance precision, not removal.
 *  M1: audit-receipts export must mark truncation honestly when the population
 *      exceeds the export cap (instead of carrying a `total` that overclaims
 *      against `entries.length`).
 *  M3: the `verify` CLI's `manifest:` line must reflect the manifest-specific
 *      result, not the overall verdict (a valid manifest with a failing
 *      downstream artifact must print `manifest: verified`).
 *  L1: `source_key_derivation` (Argon2id salt + cost) must NOT be emitted for
 *      an empty/zero-state bundle (no re-keyable state to leak it for).
 *  M2-slice (warn): re-keyed state is re-stamped (`written_at` + `ver` reset)
 *      at import; surface that in the import warnings so the relative-TTL
 *      renewal and version reset are not silent.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createL4Tools } from "../../src/reputation/tools.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { defaultConfig } from "../../src/config.js";
import { toBase64url } from "../../src/core/encoding.js";
import * as encoding from "../../src/core/encoding.js";
import {
  exportExitBundle,
  importExitBundle,
  ExitBundleImportError,
} from "../../src/exit/index.js";
import { runExitCommand } from "../../src/exit/cli.js";
import type { StorageBackend } from "../../src/storage/interface.js";

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

/** Wrap a backend so the Nth non-reserved-namespace write throws. */
function failOnNthUserWrite(
  inner: StorageBackend,
  failOnCall: number
): StorageBackend {
  let count = 0;
  return {
    async write(namespace, key, data) {
      if (!namespace.startsWith("_")) {
        count++;
        if (count === failOnCall) {
          throw new Error(`injected: storage.write fault on call ${count}`);
        }
      }
      await inner.write(namespace, key, data);
    },
    async read(namespace, key) {
      return inner.read(namespace, key);
    },
    async delete(namespace, key, secureOverwrite) {
      return inner.delete(namespace, key, secureOverwrite);
    },
    async list(namespace, prefix) {
      return inner.list(namespace, prefix);
    },
    async exists(namespace, key) {
      return inner.exists(namespace, key);
    },
    async totalSize() {
      return inner.totalSize();
    },
  };
}

async function exportFromSource(
  source: Awaited<ReturnType<typeof makeHarness>>,
  bundleDir: string,
  namespaces: string[],
  extra: Record<string, unknown> = {}
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
    stateNamespaces: namespaces,
    keySource: "recovery-key",
    ...extra,
  });
}

const tempDirs: string[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  for (const dir of tempDirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

describe("Exit-flow harden H1: caller-supplied sourceMasterKey is never zeroed", () => {
  it("(a) leaves a CALLER-supplied sourceMasterKey untouched on the SUCCESS path", async () => {
    const source = await makeHarness();
    const sourceIdentity = await callTool(source.tools, "identity_create", {
      label: "source-agent",
    });
    const sourceIdentityId = sourceIdentity.identity_id as string;
    await callTool(source.tools, "state_write", {
      namespace: "user-data",
      key: "k1",
      value: "v1",
      identity_id: sourceIdentityId,
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-h1-success-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir, ["user-data"]);

    // The caller's own buffer. A separate, deterministic 32-byte copy of the
    // source master so we can detect zeroing independently of `source.masterKey`
    // staying alive elsewhere.
    const callerKey = Uint8Array.from(source.masterKey);
    const callerKeyBefore = Uint8Array.from(callerKey);
    expect(callerKey.some((b) => b !== 0)).toBe(true);

    const destination = await makeHarness();
    const destIdentity = await callTool(destination.tools, "identity_create", {
      label: "dest-signer",
    });

    const imported = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
      forceRebind: true,
      sourceMasterKey: callerKey,
      destinationSignerIdentityId: destIdentity.identity_id as string,
    });

    expect(imported.state.status).toBe("rekeyed");
    expect(imported.state.imported_keys).toBe(1);
    // The make-or-break assertion: the caller's buffer is byte-for-byte intact.
    expect(callerKey).toEqual(callerKeyBefore);
    expect(callerKey.every((b) => b === 0)).toBe(false);
  });

  it("(a) leaves a CALLER-supplied sourceMasterKey untouched on the FAILURE path", async () => {
    const source = await makeHarness();
    const sourceIdentity = await callTool(source.tools, "identity_create", {
      label: "source-agent",
    });
    const sourceIdentityId = sourceIdentity.identity_id as string;
    await callTool(source.tools, "state_write", {
      namespace: "user-data",
      key: "k1",
      value: "v1",
      identity_id: sourceIdentityId,
    });
    await callTool(source.tools, "state_write", {
      namespace: "user-data",
      key: "k2",
      value: "v2",
      identity_id: sourceIdentityId,
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-h1-failure-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir, ["user-data"]);

    const callerKey = Uint8Array.from(source.masterKey);
    const callerKeyBefore = Uint8Array.from(callerKey);

    // Destination shares the master so re-key can decrypt; inject a write fault
    // so the SECOND user-data write throws and the import fails+cleans up.
    const destInner = new MemoryStorage();
    const destMasterKey = source.masterKey;
    const destAuditLog = new AuditLog(destInner, destMasterKey);
    const setupStateStore = new StateStore(destInner, destMasterKey);
    const { tools: setupTools, identityManager: destIdentityManager } =
      createL1Tools(
        setupStateStore,
        destInner,
        destMasterKey,
        "recovery-key",
        destAuditLog
      );
    await destIdentityManager.load();
    await callTool(setupTools as ToolDef[], "identity_create", {
      label: "dest-default",
    });
    const destStorage = failOnNthUserWrite(destInner, 2);
    const { reputationStore: destReputationStore } = createL4Tools(
      destStorage,
      destMasterKey,
      destIdentityManager,
      destAuditLog
    );

    let caught: ExitBundleImportError | null = null;
    try {
      await importExitBundle({
        bundleDir,
        storage: destStorage,
        masterKey: destMasterKey,
        identityManager: destIdentityManager,
        auditLog: destAuditLog,
        reputationStore: destReputationStore,
        activate: true,
        forceRebind: true,
        sourceMasterKey: callerKey,
      });
    } catch (err) {
      caught = err as ExitBundleImportError;
    }
    expect(caught).toBeInstanceOf(ExitBundleImportError);
    // Even though the import failed and the `finally` ran, the caller's buffer
    // is intact - the use-after-zero footgun is closed on the failure path too.
    expect(callerKey).toEqual(callerKeyBefore);
    expect(callerKey.every((b) => b === 0)).toBe(false);
  });

  it("(b) STILL zeroes an import-DERIVED key (legacy recovery-key path, no caller key)", async () => {
    const source = await makeHarness();
    const sourceIdentity = await callTool(source.tools, "identity_create", {
      label: "source-agent",
    });
    const sourceIdentityId = sourceIdentity.identity_id as string;
    await callTool(source.tools, "state_write", {
      namespace: "user-data",
      key: "k1",
      value: "v1",
      identity_id: sourceIdentityId,
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-h1-derived-"));
    tempDirs.push(bundleDir);
    // No mintStateRekeyKey => legacy bundle (no source_custody): the recovery
    // key IS the master, decoded internally by decodeSourceRecoveryKey.
    await exportFromSource(source, bundleDir, ["user-data"]);

    // The legacy recovery key string that base64url-decodes to the source
    // master. The import path will decode it into a FRESH buffer it owns.
    const recoveryKey = toBase64url(source.masterKey);

    // Capture the import-derived buffer: spy on fromBase64url and grab the
    // result of the single call whose input is exactly our recovery key.
    const realFromBase64url = encoding.fromBase64url;
    let derivedKey: Uint8Array | null = null;
    vi.spyOn(encoding, "fromBase64url").mockImplementation((value: string) => {
      const out = realFromBase64url(value);
      if (value === recoveryKey) {
        derivedKey = out;
      }
      return out;
    });

    const destination = await makeHarness();
    const destIdentity = await callTool(destination.tools, "identity_create", {
      label: "dest-signer",
    });

    // The recovery key decodes to the SOURCE master (decrypts bundle entries);
    // the destination re-encrypts/re-signs under its OWN master + identity.
    const imported = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
      forceRebind: true,
      sourceRecoveryKey: recoveryKey,
      destinationSignerIdentityId: destIdentity.identity_id as string,
    });

    expect(imported.state.status).toBe("rekeyed");
    expect(derivedKey).not.toBeNull();
    // The import-derived key MUST be zeroed in the finally (security preserved).
    expect((derivedKey as unknown as Uint8Array).every((b) => b === 0)).toBe(
      true
    );
  });
});

describe("Exit-flow harden M1: audit-export truncation is marked honestly", () => {
  it("marks truncated + omitted_count and warns when the population exceeds the cap", async () => {
    const source = await makeHarness();
    const sourceIdentity = await callTool(source.tools, "identity_create", {
      label: "source-agent",
    });
    const sourceIdentityId = sourceIdentity.identity_id as string;
    // Generate a handful of audit entries (each state_write appends).
    for (let i = 0; i < 6; i++) {
      await callTool(source.tools, "state_write", {
        namespace: "user-data",
        key: `k${i}`,
        value: `v${i}`,
        identity_id: sourceIdentityId,
      });
    }

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-m1-trunc-"));
    tempDirs.push(bundleDir);
    // Inject a tiny cap so the audit population exceeds it.
    const exported = await exportFromSource(source, bundleDir, ["user-data"], {
      auditReceiptsExportCap: 2,
    });

    const artifact = JSON.parse(
      await readFile(join(bundleDir, "artifacts", "audit_receipts.json"), "utf8")
    ) as {
      total: number;
      truncated?: boolean;
      omitted_count?: number;
      entries: unknown[];
    };

    expect(artifact.entries.length).toBe(2);
    expect(artifact.total).toBeGreaterThan(2);
    expect(artifact.truncated).toBe(true);
    expect(artifact.omitted_count).toBe(artifact.total - 2);
    // The completeness overclaim is closed: total now agrees with the marker.
    expect(artifact.total).toBe(artifact.entries.length + artifact.omitted_count!);

    // The export surfaces the truncation as an operator-facing warning.
    expect(exported.warnings ?? []).toEqual(
      expect.arrayContaining([
        expect.stringContaining("oldest"),
      ])
    );
    expect((exported.warnings ?? []).join("\n")).toContain("export cap");
  });

  it("emits NO truncation marker when the whole population fits under the cap", async () => {
    const source = await makeHarness();
    const sourceIdentity = await callTool(source.tools, "identity_create", {
      label: "source-agent",
    });
    await callTool(source.tools, "state_write", {
      namespace: "user-data",
      key: "k1",
      value: "v1",
      identity_id: sourceIdentity.identity_id as string,
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-m1-clean-"));
    tempDirs.push(bundleDir);
    const exported = await exportFromSource(source, bundleDir, ["user-data"]);

    const artifact = JSON.parse(
      await readFile(join(bundleDir, "artifacts", "audit_receipts.json"), "utf8")
    ) as { truncated?: boolean; omitted_count?: number };
    expect(artifact.truncated).toBeUndefined();
    expect(artifact.omitted_count).toBeUndefined();
    expect(exported.warnings).toBeUndefined();
  });
});

describe("Exit-flow harden L1: empty-bundle KDF leak is closed", () => {
  it("omits source_key_derivation for a zero-state bundle", async () => {
    const source = await makeHarness();
    await callTool(source.tools, "identity_create", { label: "source-agent" });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-l1-empty-"));
    tempDirs.push(bundleDir);
    // No state writes and no namespaces => zero-state encrypted bundle.
    await exportFromSource(source, bundleDir, []);

    const encryptedState = JSON.parse(
      await readFile(
        join(bundleDir, "artifacts", "encrypted_state.json"),
        "utf8"
      )
    ) as { total_keys: number; source_key_derivation?: unknown };
    expect(encryptedState.total_keys).toBe(0);
    expect(encryptedState.source_key_derivation).toBeUndefined();
  });

  it("STILL emits source_key_derivation when the bundle carries state (legacy params present)", async () => {
    const source = await makeHarness();
    const sourceIdentity = await callTool(source.tools, "identity_create", {
      label: "source-agent",
    });
    await callTool(source.tools, "state_write", {
      namespace: "user-data",
      key: "k1",
      value: "v1",
      identity_id: sourceIdentity.identity_id as string,
    });
    // A legacy fortress persists Argon2id params at `_meta/key-params`; the
    // export reads them into `source_key_derivation`. Seed a stub so this path
    // is exercised (the random-master harness has none by default). The L1 gate
    // must NOT suppress them when there is re-keyable state.
    const { deriveMasterKey } = await import(
      "../../src/core/key-derivation.js"
    );
    const { stringToBytes } = await import("../../src/core/encoding.js");
    const { params } = await deriveMasterKey("legacy-fortress-passphrase");
    await source.storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params))
    );

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-l1-nonempty-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir, ["user-data"]);

    const encryptedState = JSON.parse(
      await readFile(
        join(bundleDir, "artifacts", "encrypted_state.json"),
        "utf8"
      )
    ) as { total_keys: number; source_key_derivation?: unknown };
    expect(encryptedState.total_keys).toBeGreaterThan(0);
    expect(encryptedState.source_key_derivation).toBeDefined();
  });
});

describe("Exit-flow harden M2-slice (warn): re-key re-stamp is surfaced", () => {
  it("warns that re-keyed state was re-stamped (relative TTLs renewed, version reset)", async () => {
    const source = await makeHarness();
    const sourceIdentity = await callTool(source.tools, "identity_create", {
      label: "source-agent",
    });
    await callTool(source.tools, "state_write", {
      namespace: "user-data",
      key: "k1",
      value: "v1",
      identity_id: sourceIdentity.identity_id as string,
      metadata: { ttl_seconds: 3600 },
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-m2-warn-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir, ["user-data"]);

    const destination = await makeHarness();
    const destIdentity = await callTool(destination.tools, "identity_create", {
      label: "dest-signer",
    });

    const imported = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
      forceRebind: true,
      sourceMasterKey: source.masterKey,
      destinationSignerIdentityId: destIdentity.identity_id as string,
    });

    expect(imported.state.status).toBe("rekeyed");
    expect(imported.state.imported_keys).toBe(1);
    expect(imported.warnings.join("\n")).toContain("re-stamped at import time");
    expect(imported.warnings.join("\n")).toContain("ttl_seconds are renewed");
  });
});

describe("Exit-flow harden M3: verify CLI manifest label reflects manifest, not overall verdict", () => {
  function captureCli() {
    const chunks: string[] = [];
    const out = {
      write(s: string | Uint8Array): boolean {
        chunks.push(typeof s === "string" ? s : Buffer.from(s).toString());
        return true;
      },
    } as unknown as NodeJS.WritableStream;
    const err = {
      write(): boolean {
        return true;
      },
    } as unknown as NodeJS.WritableStream;
    return { chunks, out, err };
  }

  it("prints `manifest: verified` when the signed manifest is valid but a downstream artifact fails (verdict FAIL)", async () => {
    const source = await makeHarness();
    const sourceIdentity = await callTool(source.tools, "identity_create", {
      label: "source-agent",
    });
    const sourceIdentityId = sourceIdentity.identity_id as string;
    await callTool(source.tools, "state_write", {
      namespace: "user-data",
      key: "k1",
      value: "v1",
      identity_id: sourceIdentityId,
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-m3-fail-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir, ["user-data"]);

    // Tamper a NON-manifest artifact's bytes. The manifest signature stays
    // cryptographically valid (we never touch manifest.json), but the
    // commitments artifact no longer matches its manifest-pinned hash:
    // failure_class = artifact_hash_mismatch, a DOWNSTREAM failure. Before the
    // fix the CLI printed `manifest: failed` here (overall verdict folded in);
    // after the fix it must print `manifest: verified`.
    const commitmentsPath = join(bundleDir, "artifacts", "commitments.json");
    const original = JSON.parse(await readFile(commitmentsPath, "utf8")) as {
      exported_at: string;
    };
    original.exported_at = "1999-01-01T00:00:00.000Z";
    const { writeFile } = await import("node:fs/promises");
    await writeFile(commitmentsPath, JSON.stringify(original));

    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({ argv: ["verify", bundleDir], out, err });
    const printed = chunks.join("");

    expect(printed).toContain("verdict: FAIL");
    // The make-or-break: the manifest line is NOT mislabeled `failed`.
    expect(printed).toContain("manifest: verified");
    expect(printed).not.toContain("manifest: failed");
    expect(code).toBe(1);
  });

  it("prints `manifest: failed` when the manifest signature itself is broken", async () => {
    const source = await makeHarness();
    const sourceIdentity = await callTool(source.tools, "identity_create", {
      label: "source-agent",
    });
    await callTool(source.tools, "state_write", {
      namespace: "user-data",
      key: "k1",
      value: "v1",
      identity_id: sourceIdentity.identity_id as string,
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-m3-manifest-fail-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir, ["user-data"]);

    // Corrupt the manifest signature directly: manifest_signature_invalid,
    // which IS a manifest-integrity failure, so the line must read `failed`.
    const manifestPath = join(bundleDir, "manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
      signature: string;
    };
    // Flip the first base64url char to a different valid char.
    manifest.signature =
      (manifest.signature[0] === "A" ? "B" : "A") + manifest.signature.slice(1);
    const { writeFile } = await import("node:fs/promises");
    await writeFile(manifestPath, JSON.stringify(manifest));

    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({ argv: ["verify", bundleDir], out, err });
    const printed = chunks.join("");

    expect(printed).toContain("verdict: FAIL");
    expect(printed).toContain("manifest: failed");
    expect(code).toBe(1);
  });

  it("prints `manifest: verified` for a fully clean bundle (verdict PASS)", async () => {
    const source = await makeHarness();
    const sourceIdentity = await callTool(source.tools, "identity_create", {
      label: "source-agent",
    });
    await callTool(source.tools, "state_write", {
      namespace: "user-data",
      key: "k1",
      value: "v1",
      identity_id: sourceIdentity.identity_id as string,
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-m3-pass-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir, ["user-data"]);

    const { chunks, out, err } = captureCli();
    const code = await runExitCommand({ argv: ["verify", bundleDir], out, err });
    const printed = chunks.join("");
    expect(printed).toContain("verdict: PASS");
    expect(printed).toContain("manifest: verified");
    expect(code).toBe(0);
  });
});
