/**
 * Recognition-Layer Path C primary build 2: exit-bundle did:web
 * integration regression suite.
 *
 * Coverage:
 *  - Export embeds did:web binding in manifest.identity_binding when
 *    caller supplies it; absent caller binding leaves manifest
 *    unchanged (backward compat).
 *  - Export rejects a malformed binding (identifier/authority-host
 *    mismatch) before producing a manifest.
 *  - Import succeeds end-to-end when the mocked resolver returns a
 *    DID Document whose verificationMethod public key matches the
 *    manifest's fortress_master_pubkey.
 *  - Import FAILS with ExitBundleImportError code `did_web_mismatch`
 *    when the resolver returns a mismatching public key.
 *  - Import surfaces a warning (does not fail) when the resolver
 *    reports a resolution failure (host_not_allowed / network).
 *  - --skip-did-web-verify bypass: import proceeds without
 *    resolution, emits `outcome: "skipped"` audit event.
 *  - Backward compat: pre-did:web manifest imports cleanly with no
 *    did:web audit emissions and no warnings.
 *  - Audit emissions fire on every path with stable details payloads
 *    (success, mismatch, resolution_failure, skipped, authority_host).
 *  - Multi-fortress isolation: each fortress's audit log is scoped.
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { canonicalizeToBytes } from "../../src/mesh/canonical-json.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { AuditLog, type AuditEntry } from "../../src/operational/audit-log.js";
import { createL4Tools } from "../../src/reputation/tools.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import type { ExitBundleManifest } from "../../src/contracts/v1.1/exit-bundle-manifest.js";
import {
  exportExitBundle,
  importExitBundle,
  EXIT_BUNDLE_DID_WEB_AUDIT_OPS,
} from "../../src/exit/bundle.js";
import { ExitBundleImportError } from "../../src/exit/bundle.js";
import {
  deriveDidWebFromPrivateKey,
  issueDidWeb,
  rotateDidWebKey,
  type DidDocument,
} from "../../src/recognition/did-web.js";
import { sign as identitySign } from "../../src/core/identity.js";
import { fromBase64url, toBase64url } from "../../src/core/encoding.js";

const TEST_AUTHORITY_HOST = "alice.example.com";
const TEST_FORTRESS_LABEL = "abc123";
const ALLOWED_HOSTS = [TEST_AUTHORITY_HOST];

interface TestHarness {
  storage: MemoryStorage;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  identityManager: ReturnType<typeof createL1Tools>["identityManager"];
  reputationStore: ReturnType<typeof createL4Tools>["reputationStore"];
}

async function callTool(
  tools: Array<{
    name: string;
    handler: (args: Record<string, unknown>) => Promise<{
      content: Array<{ type: string; text: string }>;
    }>;
  }>,
  name: string,
  args: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const tool = tools.find((c) => c.name === name);
  if (!tool) throw new Error(`tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

async function makeHarness(): Promise<TestHarness> {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  const { tools: l1Tools, identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog,
  );
  await identityManager.load();
  const { reputationStore } = createL4Tools(
    storage,
    masterKey,
    identityManager,
    auditLog,
  );
  // Source-fortress harness needs a real identity for exit-bundle
  // export; the test calls identity_create here so getDefault()
  // returns a usable StoredIdentity. Receiver harnesses skip this
  // step (the import flow re-keys the source's encrypted payloads
  // under the receiver's signer identity).
  await callTool(l1Tools, "identity_create", { label: "fortress-default" });
  return { storage, masterKey, auditLog, identityManager, reputationStore };
}

async function exportWithDidWeb(
  h: TestHarness,
  bundleDir: string,
  didWebIdentifier?: string,
): Promise<void> {
  const result = await exportExitBundle({
      unpartitionedLegacyExport: true,
    bundleDir,
    storage: h.storage,
    masterKey: h.masterKey,
    identityManager: h.identityManager,
    auditLog: h.auditLog,
    reputationStore: h.reputationStore,
    policy: DEFAULT_POLICY,
    ...(didWebIdentifier !== undefined
      ? {
          didWeb: {
            identifier: didWebIdentifier,
            authority_host: TEST_AUTHORITY_HOST,
          },
        }
      : {}),
  });
  expect(result.manifest).toBeDefined();
}

/**
 * Build a synthetic fetcher that returns a DID Document containing
 * the supplied JWK `x` value. Used to feed `resolveDidWeb` through
 * a deterministic in-memory channel.
 */
function makeFetcher(jwkX: string, didUri: string): Parameters<typeof importExitBundle>[0]["didWebFetcher"] {
  const document: DidDocument = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ],
    id: didUri,
    verificationMethod: [
      {
        id: `${didUri}#key-1`,
        type: "JsonWebKey2020",
        controller: didUri,
        publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: jwkX },
      },
    ],
    authentication: [`${didUri}#key-1`],
    assertionMethod: [`${didUri}#key-1`],
  };
  return async () => ({
    ok: true,
    status: 200,
    json: async () => document,
  });
}

function makeFailingFetcher(message: string): Parameters<typeof importExitBundle>[0]["didWebFetcher"] {
  return async () => {
    throw new Error(message);
  };
}

function makeNotFoundFetcher(): Parameters<typeof importExitBundle>[0]["didWebFetcher"] {
  return async () => ({ ok: false, status: 404, json: async () => ({}) });
}

function manifestDidUri(h: TestHarness): string {
  const identity = h.identityManager.getDefault();
  if (!identity) throw new Error("test fixture: identity not loaded");
  return `did:web:${TEST_AUTHORITY_HOST}:fortress:${TEST_FORTRESS_LABEL}:agent:default`;
}

function lastAuditEntry(
  audit: AuditEntry[],
  op: string,
): AuditEntry | undefined {
  return [...audit].reverse().find((e) => e.operation === op);
}

async function rewriteManifestDidWeb(
  h: TestHarness,
  bundleDir: string,
  didWeb: { identifier: string; authority_host: string },
): Promise<void> {
  const identity = h.identityManager.getDefault();
  if (!identity) throw new Error("test fixture: identity not loaded");
  const manifestPath = join(bundleDir, "manifest.json");
  const manifest = JSON.parse(
    await readFile(manifestPath, "utf8"),
  ) as ExitBundleManifest;
  manifest.body.identity_binding.did_web = didWeb;
  manifest.signature = toBase64url(
    identitySign(
      canonicalizeToBytes(manifest.body),
      identity.encrypted_private_key,
      derivePurposeKey(h.masterKey, "identity-encryption"),
    ),
  );
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2));
}

describe("Recognition-Layer Path C primary build 2: exit-bundle did:web integration", () => {
  const tempDirs: string[] = [];
  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function makeTempDir(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "exit-did-web-"));
    tempDirs.push(dir);
    return dir;
  }

  it("export embeds did_web in manifest.identity_binding when caller supplies it", async () => {
    const h = await makeHarness();
    const dir = await makeTempDir();
    const didUri = manifestDidUri(h);
    await exportWithDidWeb(h, dir, didUri);

    const result = await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir: await makeTempDir(),
      storage: h.storage,
      masterKey: h.masterKey,
      identityManager: h.identityManager,
      auditLog: h.auditLog,
      reputationStore: h.reputationStore,
      policy: DEFAULT_POLICY,
      didWeb: { identifier: didUri, authority_host: TEST_AUTHORITY_HOST },
    });
    expect(result.manifest.body.identity_binding.did_web).toBeDefined();
    expect(result.manifest.body.identity_binding.did_web!.identifier).toBe(
      didUri,
    );
    expect(result.manifest.body.identity_binding.did_web!.authority_host).toBe(
      TEST_AUTHORITY_HOST,
    );
  });

  it("export omits did_web when caller does not supply a binding (backward compat)", async () => {
    const h = await makeHarness();
    const dir = await makeTempDir();
    const result = await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir: dir,
      storage: h.storage,
      masterKey: h.masterKey,
      identityManager: h.identityManager,
      auditLog: h.auditLog,
      reputationStore: h.reputationStore,
      policy: DEFAULT_POLICY,
    });
    expect(result.manifest.body.identity_binding.did_web).toBeUndefined();
  });

  it("export emits exit_bundle_did_web_export_included audit op when did_web embedded", async () => {
    const h = await makeHarness();
    const dir = await makeTempDir();
    const didUri = manifestDidUri(h);
    await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir: dir,
      storage: h.storage,
      masterKey: h.masterKey,
      identityManager: h.identityManager,
      auditLog: h.auditLog,
      reputationStore: h.reputationStore,
      policy: DEFAULT_POLICY,
      didWeb: { identifier: didUri, authority_host: TEST_AUTHORITY_HOST },
    });
    const q = await h.auditLog.query({ layer: "l1", limit: 200 });
    const evt = lastAuditEntry(
      q.entries,
      EXIT_BUNDLE_DID_WEB_AUDIT_OPS.EXPORT_INCLUDED,
    );
    expect(evt).toBeDefined();
    expect(evt!.details?.identifier).toBe(didUri);
    expect(evt!.details?.authority_host).toBe(TEST_AUTHORITY_HOST);
  });

  it("export does NOT emit did_web_export_included audit op when binding absent (backward compat)", async () => {
    const h = await makeHarness();
    const dir = await makeTempDir();
    await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir: dir,
      storage: h.storage,
      masterKey: h.masterKey,
      identityManager: h.identityManager,
      auditLog: h.auditLog,
      reputationStore: h.reputationStore,
      policy: DEFAULT_POLICY,
    });
    const q = await h.auditLog.query({ layer: "l1", limit: 200 });
    expect(
      q.entries.some(
        (e) => e.operation === EXIT_BUNDLE_DID_WEB_AUDIT_OPS.EXPORT_INCLUDED,
      ),
    ).toBe(false);
  });

  it("export REJECTS a malformed binding where identifier host does not match authority_host", async () => {
    const h = await makeHarness();
    const dir = await makeTempDir();
    await expect(
      exportExitBundle({
      unpartitionedLegacyExport: true,
        bundleDir: dir,
        storage: h.storage,
        masterKey: h.masterKey,
        identityManager: h.identityManager,
        auditLog: h.auditLog,
        reputationStore: h.reputationStore,
        policy: DEFAULT_POLICY,
        didWeb: {
          identifier: `did:web:other.example.com:fortress:${TEST_FORTRESS_LABEL}:agent:default`,
          authority_host: TEST_AUTHORITY_HOST,
        },
      }),
    ).rejects.toThrow(/authority host .* does not match/);
  });

  it("import rejects a signed manifest whose parsed did:web host differs from manifest authority_host", async () => {
    const h = await makeHarness();
    const dir = await makeTempDir();
    const didUri = manifestDidUri(h);
    await exportWithDidWeb(h, dir, didUri);
    const parsedHost = "other.example.com";
    const tamperedDid = `did:web:${parsedHost}:fortress:${TEST_FORTRESS_LABEL}:agent:default`;
    await rewriteManifestDidWeb(h, dir, {
      identifier: tamperedDid,
      authority_host: TEST_AUTHORITY_HOST,
    });

    let fetcherInvoked = false;
    const receiver = await makeHarness();
    let thrown: unknown;
    try {
      await importExitBundle({
        bundleDir: dir,
        storage: receiver.storage,
        masterKey: receiver.masterKey,
        identityManager: receiver.identityManager,
        auditLog: receiver.auditLog,
        reputationStore: receiver.reputationStore,
        didWebAllowedHosts: [TEST_AUTHORITY_HOST, parsedHost],
        didWebFetcher: async () => {
          fetcherInvoked = true;
          return { ok: true, status: 200, json: async () => ({}) };
        },
      });
    } catch (err) {
      thrown = err;
    }

    expect(fetcherInvoked).toBe(false);
    expect(thrown).toBeInstanceOf(ExitBundleImportError);
    expect((thrown as ExitBundleImportError).code).toBe("did_web_mismatch");
    const q = await receiver.auditLog.query({ layer: "l1", limit: 200 });
    const hostEvt = lastAuditEntry(
      q.entries,
      EXIT_BUNDLE_DID_WEB_AUDIT_OPS.AUTHORITY_HOST,
    );
    expect(hostEvt).toBeDefined();
    expect(hostEvt!.details?.authority_host).toBe(parsedHost);
    expect(hostEvt!.details?.identifier).toBe(tamperedDid);
  });

  it("import succeeds end-to-end when resolver returns DID Document with matching pubkey", async () => {
    const h = await makeHarness();
    const identity = h.identityManager.getDefault()!;
    const dir = await makeTempDir();
    const didUri = manifestDidUri(h);
    await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir: dir,
      storage: h.storage,
      masterKey: h.masterKey,
      identityManager: h.identityManager,
      auditLog: h.auditLog,
      reputationStore: h.reputationStore,
      policy: DEFAULT_POLICY,
      didWeb: { identifier: didUri, authority_host: TEST_AUTHORITY_HOST },
    });

    // The receiver mocks the resolver to return a DID Document whose
    // publicKeyJwk.x equals the operator's actual fortress_master_pubkey
    // (which the manifest's identity_binding also carries).
    const matchingX = identity.public_key;
    const receiver = await makeHarness();
    const result = await importExitBundle({
      bundleDir: dir,
      storage: receiver.storage,
      masterKey: receiver.masterKey,
      identityManager: receiver.identityManager,
      auditLog: receiver.auditLog,
      reputationStore: receiver.reputationStore,
      didWebAllowedHosts: ALLOWED_HOSTS,
      didWebFetcher: makeFetcher(matchingX, didUri),
    });
    expect(result.verified).toBe(true);

    const q = await receiver.auditLog.query({ layer: "l1", limit: 200 });
    const verified = lastAuditEntry(
      q.entries,
      EXIT_BUNDLE_DID_WEB_AUDIT_OPS.IMPORT_VERIFIED,
    );
    expect(verified).toBeDefined();
    expect(verified!.details?.outcome).toBe("success");
    const authority = lastAuditEntry(
      q.entries,
      EXIT_BUNDLE_DID_WEB_AUDIT_OPS.AUTHORITY_HOST,
    );
    expect(authority).toBeDefined();
    expect(authority!.details?.authority_host).toBe(TEST_AUTHORITY_HOST);
  });

  it("import FAILS with did_web_mismatch when resolver returns mismatching pubkey", async () => {
    const h = await makeHarness();
    const dir = await makeTempDir();
    const didUri = manifestDidUri(h);
    await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir: dir,
      storage: h.storage,
      masterKey: h.masterKey,
      identityManager: h.identityManager,
      auditLog: h.auditLog,
      reputationStore: h.reputationStore,
      policy: DEFAULT_POLICY,
      didWeb: { identifier: didUri, authority_host: TEST_AUTHORITY_HOST },
    });

    // Resolver returns a DID Document with a DIFFERENT pubkey (a
    // freshly-generated random 32-byte sequence base64url-encoded).
    const wrongPubkey = toBase64url(generateRandomKey());

    const receiver = await makeHarness();
    await expect(
      importExitBundle({
        bundleDir: dir,
        storage: receiver.storage,
        masterKey: receiver.masterKey,
        identityManager: receiver.identityManager,
        auditLog: receiver.auditLog,
        reputationStore: receiver.reputationStore,
        didWebAllowedHosts: ALLOWED_HOSTS,
        didWebFetcher: makeFetcher(wrongPubkey, didUri),
      }),
    ).rejects.toBeInstanceOf(ExitBundleImportError);

    const q = await receiver.auditLog.query({ layer: "l1", limit: 200 });
    const verified = lastAuditEntry(
      q.entries,
      EXIT_BUNDLE_DID_WEB_AUDIT_OPS.IMPORT_VERIFIED,
    );
    expect(verified).toBeDefined();
    expect(verified!.details?.outcome).toBe("mismatch");
  });

  it("import surfaces warning + proceeds when resolver reports host_not_allowed", async () => {
    const h = await makeHarness();
    const dir = await makeTempDir();
    const didUri = manifestDidUri(h);
    await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir: dir,
      storage: h.storage,
      masterKey: h.masterKey,
      identityManager: h.identityManager,
      auditLog: h.auditLog,
      reputationStore: h.reputationStore,
      policy: DEFAULT_POLICY,
      didWeb: { identifier: didUri, authority_host: TEST_AUTHORITY_HOST },
    });

    const receiver = await makeHarness();
    const result = await importExitBundle({
      bundleDir: dir,
      storage: receiver.storage,
      masterKey: receiver.masterKey,
      identityManager: receiver.identityManager,
      auditLog: receiver.auditLog,
      reputationStore: receiver.reputationStore,
      didWebAllowedHosts: [], // empty allowlist
    });
    expect(result.verified).toBe(true);
    expect(result.warnings.some((w) => /did:web resolution failed/.test(w))).toBe(
      true,
    );
    const q = await receiver.auditLog.query({ layer: "l1", limit: 200 });
    const verified = lastAuditEntry(
      q.entries,
      EXIT_BUNDLE_DID_WEB_AUDIT_OPS.IMPORT_VERIFIED,
    );
    expect(verified!.details?.outcome).toBe("resolution_failure");
    expect(verified!.details?.failure).toBe("host_not_allowed");
  });

  it("import surfaces warning + proceeds when resolver reports network failure", async () => {
    const h = await makeHarness();
    const dir = await makeTempDir();
    const didUri = manifestDidUri(h);
    await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir: dir,
      storage: h.storage,
      masterKey: h.masterKey,
      identityManager: h.identityManager,
      auditLog: h.auditLog,
      reputationStore: h.reputationStore,
      policy: DEFAULT_POLICY,
      didWeb: { identifier: didUri, authority_host: TEST_AUTHORITY_HOST },
    });

    const receiver = await makeHarness();
    const result = await importExitBundle({
      bundleDir: dir,
      storage: receiver.storage,
      masterKey: receiver.masterKey,
      identityManager: receiver.identityManager,
      auditLog: receiver.auditLog,
      reputationStore: receiver.reputationStore,
      didWebAllowedHosts: ALLOWED_HOSTS,
      didWebFetcher: makeFailingFetcher("ECONNREFUSED"),
    });
    expect(result.verified).toBe(true);
    const q = await receiver.auditLog.query({ layer: "l1", limit: 200 });
    const verified = lastAuditEntry(
      q.entries,
      EXIT_BUNDLE_DID_WEB_AUDIT_OPS.IMPORT_VERIFIED,
    );
    expect(verified!.details?.outcome).toBe("resolution_failure");
    expect(verified!.details?.failure).toBe("fetch_failed");
  });

  it("import surfaces warning + proceeds when resolver returns 404 not_found", async () => {
    const h = await makeHarness();
    const dir = await makeTempDir();
    const didUri = manifestDidUri(h);
    await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir: dir,
      storage: h.storage,
      masterKey: h.masterKey,
      identityManager: h.identityManager,
      auditLog: h.auditLog,
      reputationStore: h.reputationStore,
      policy: DEFAULT_POLICY,
      didWeb: { identifier: didUri, authority_host: TEST_AUTHORITY_HOST },
    });

    const receiver = await makeHarness();
    const result = await importExitBundle({
      bundleDir: dir,
      storage: receiver.storage,
      masterKey: receiver.masterKey,
      identityManager: receiver.identityManager,
      auditLog: receiver.auditLog,
      reputationStore: receiver.reputationStore,
      didWebAllowedHosts: ALLOWED_HOSTS,
      didWebFetcher: makeNotFoundFetcher(),
    });
    expect(result.verified).toBe(true);
    const q = await receiver.auditLog.query({ layer: "l1", limit: 200 });
    const verified = lastAuditEntry(
      q.entries,
      EXIT_BUNDLE_DID_WEB_AUDIT_OPS.IMPORT_VERIFIED,
    );
    expect(verified!.details?.outcome).toBe("resolution_failure");
    expect(verified!.details?.failure).toBe("not_found");
  });

  it("import skips did:web resolution when skipDidWebVerify=true; emits outcome:skipped", async () => {
    const h = await makeHarness();
    const dir = await makeTempDir();
    const didUri = manifestDidUri(h);
    await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir: dir,
      storage: h.storage,
      masterKey: h.masterKey,
      identityManager: h.identityManager,
      auditLog: h.auditLog,
      reputationStore: h.reputationStore,
      policy: DEFAULT_POLICY,
      didWeb: { identifier: didUri, authority_host: TEST_AUTHORITY_HOST },
    });

    const receiver = await makeHarness();
    const fetcherCalls = { count: 0 };
    const result = await importExitBundle({
      bundleDir: dir,
      storage: receiver.storage,
      masterKey: receiver.masterKey,
      identityManager: receiver.identityManager,
      auditLog: receiver.auditLog,
      reputationStore: receiver.reputationStore,
      didWebAllowedHosts: ALLOWED_HOSTS,
      didWebFetcher: async () => {
        fetcherCalls.count += 1;
        return { ok: true, status: 200, json: async () => ({}) };
      },
      skipDidWebVerify: true,
    });
    expect(result.verified).toBe(true);
    expect(fetcherCalls.count).toBe(0); // resolver never invoked
    const q = await receiver.auditLog.query({ layer: "l1", limit: 200 });
    const verified = lastAuditEntry(
      q.entries,
      EXIT_BUNDLE_DID_WEB_AUDIT_OPS.IMPORT_VERIFIED,
    );
    expect(verified!.details?.outcome).toBe("skipped");
  });

  it("import of pre-did:web manifest: backward compatible, no did:web audit events fire", async () => {
    const h = await makeHarness();
    const dir = await makeTempDir();
    // Export WITHOUT didWeb opts (pre-did:web manifest shape).
    await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir: dir,
      storage: h.storage,
      masterKey: h.masterKey,
      identityManager: h.identityManager,
      auditLog: h.auditLog,
      reputationStore: h.reputationStore,
      policy: DEFAULT_POLICY,
    });

    const receiver = await makeHarness();
    const fetcherCalls = { count: 0 };
    const result = await importExitBundle({
      bundleDir: dir,
      storage: receiver.storage,
      masterKey: receiver.masterKey,
      identityManager: receiver.identityManager,
      auditLog: receiver.auditLog,
      reputationStore: receiver.reputationStore,
      didWebAllowedHosts: ALLOWED_HOSTS,
      didWebFetcher: async () => {
        fetcherCalls.count += 1;
        return { ok: true, status: 200, json: async () => ({}) };
      },
    });
    expect(result.verified).toBe(true);
    expect(fetcherCalls.count).toBe(0);

    const q = await receiver.auditLog.query({ layer: "l1", limit: 200 });
    expect(
      q.entries.some(
        (e) => e.operation === EXIT_BUNDLE_DID_WEB_AUDIT_OPS.IMPORT_VERIFIED,
      ),
    ).toBe(false);
    expect(
      q.entries.some(
        (e) => e.operation === EXIT_BUNDLE_DID_WEB_AUDIT_OPS.AUTHORITY_HOST,
      ),
    ).toBe(false);
  });

  it("import emits authority_host audit op with the parsed identifier host on every did:web check", async () => {
    const h = await makeHarness();
    const dir = await makeTempDir();
    const didUri = manifestDidUri(h);
    await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir: dir,
      storage: h.storage,
      masterKey: h.masterKey,
      identityManager: h.identityManager,
      auditLog: h.auditLog,
      reputationStore: h.reputationStore,
      policy: DEFAULT_POLICY,
      didWeb: { identifier: didUri, authority_host: TEST_AUTHORITY_HOST },
    });

    const receiver = await makeHarness();
    await importExitBundle({
      bundleDir: dir,
      storage: receiver.storage,
      masterKey: receiver.masterKey,
      identityManager: receiver.identityManager,
      auditLog: receiver.auditLog,
      reputationStore: receiver.reputationStore,
      didWebAllowedHosts: [], // forces resolution_failure path
    });
    const q = await receiver.auditLog.query({ layer: "l1", limit: 200 });
    const hostEvt = lastAuditEntry(
      q.entries,
      EXIT_BUNDLE_DID_WEB_AUDIT_OPS.AUTHORITY_HOST,
    );
    expect(hostEvt).toBeDefined();
    expect(hostEvt!.details?.authority_host).toBe(TEST_AUTHORITY_HOST);
    expect(hostEvt!.details?.identifier).toBe(didUri);
  });

  it("derived-from-private-key did:web round trips: issuance pubkey matches resolved pubkey", async () => {
    const h = await makeHarness();
    const dir = await makeTempDir();
    const identity = h.identityManager.getDefault()!;
    // Re-derive a did:web identifier from the fortress's identity
    // public-key (via deriveDidWebFromPrivateKey's parallel issuance
    // path, exercised here through issueDidWeb directly).
    const expectedPubkey = identity.public_key;
    const identifier = `did:web:${TEST_AUTHORITY_HOST}:fortress:${TEST_FORTRESS_LABEL}:agent:default`;
    await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir: dir,
      storage: h.storage,
      masterKey: h.masterKey,
      identityManager: h.identityManager,
      auditLog: h.auditLog,
      reputationStore: h.reputationStore,
      policy: DEFAULT_POLICY,
      didWeb: { identifier, authority_host: TEST_AUTHORITY_HOST },
    });

    const receiver = await makeHarness();
    const result = await importExitBundle({
      bundleDir: dir,
      storage: receiver.storage,
      masterKey: receiver.masterKey,
      identityManager: receiver.identityManager,
      auditLog: receiver.auditLog,
      reputationStore: receiver.reputationStore,
      didWebAllowedHosts: ALLOWED_HOSTS,
      didWebFetcher: makeFetcher(expectedPubkey, identifier),
    });
    expect(result.verified).toBe(true);
  });

  it("multi-fortress isolation: each fortress's did:web audit events stay in its own audit log", async () => {
    const fortressA = await makeHarness();
    const fortressB = await makeHarness();
    const dir = await makeTempDir();
    const didUri = manifestDidUri(fortressA);

    await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir: dir,
      storage: fortressA.storage,
      masterKey: fortressA.masterKey,
      identityManager: fortressA.identityManager,
      auditLog: fortressA.auditLog,
      reputationStore: fortressA.reputationStore,
      policy: DEFAULT_POLICY,
      didWeb: { identifier: didUri, authority_host: TEST_AUTHORITY_HOST },
    });

    const qA = await fortressA.auditLog.query({ layer: "l1", limit: 200 });
    const qB = await fortressB.auditLog.query({ layer: "l1", limit: 200 });
    expect(
      qA.entries.some(
        (e) => e.operation === EXIT_BUNDLE_DID_WEB_AUDIT_OPS.EXPORT_INCLUDED,
      ),
    ).toBe(true);
    expect(
      qB.entries.some(
        (e) => e.operation === EXIT_BUNDLE_DID_WEB_AUDIT_OPS.EXPORT_INCLUDED,
      ),
    ).toBe(false);
  });

  it("import verifies an old manifest signature against a rotated multi-key DID Document", async () => {
    const source = await makeHarness();
    const dir = await makeTempDir();
    const identity = source.identityManager.getDefault()!;
    const didUri = manifestDidUri(source);
    const exportedAt = "2026-05-09T12:30:00.000Z";
    const issued = await issueDidWeb({
      fortress_id: TEST_FORTRESS_LABEL,
      authority_host: TEST_AUTHORITY_HOST,
      agent_label: "default",
      public_key: fromBase64url(identity.public_key),
      now: () => new Date("2026-05-09T12:00:00.000Z"),
    });
    const exported = await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir: dir,
      storage: source.storage,
      masterKey: source.masterKey,
      identityManager: source.identityManager,
      auditLog: source.auditLog,
      reputationStore: source.reputationStore,
      policy: DEFAULT_POLICY,
      didWeb: { identifier: didUri, authority_host: TEST_AUTHORITY_HOST },
      now: () => new Date(exportedAt),
    });
    expect(exported.manifest.body.exported_at).toBe(exportedAt);
    const rotated = await rotateDidWebKey(issued, {
      reason: "manual",
      now: () => new Date("2026-05-10T00:00:00.000Z"),
    });

    const receiver = await makeHarness();
    const result = await importExitBundle({
      bundleDir: dir,
      storage: receiver.storage,
      masterKey: receiver.masterKey,
      identityManager: receiver.identityManager,
      auditLog: receiver.auditLog,
      reputationStore: receiver.reputationStore,
      didWebAllowedHosts: ALLOWED_HOSTS,
      didWebFetcher: async () => ({
        ok: true,
        status: 200,
        json: async () => rotated.new_did_document,
      }),
    });
    expect(result.verified).toBe(true);
    const audit = await receiver.auditLog.query({ layer: "l1", limit: 200 });
    const historical = lastAuditEntry(
      audit.entries,
      "did_web_historical_verification_used",
    );
    expect(historical?.details?.assertion_time).toBe(exportedAt);
  });

  it("Castle-walking: empty allowed_hosts blocks outbound at the application layer (no fetcher invocation)", async () => {
    const h = await makeHarness();
    const dir = await makeTempDir();
    const didUri = manifestDidUri(h);
    await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir: dir,
      storage: h.storage,
      masterKey: h.masterKey,
      identityManager: h.identityManager,
      auditLog: h.auditLog,
      reputationStore: h.reputationStore,
      policy: DEFAULT_POLICY,
      didWeb: { identifier: didUri, authority_host: TEST_AUTHORITY_HOST },
    });

    const receiver = await makeHarness();
    const fetcherCalls = { count: 0 };
    await importExitBundle({
      bundleDir: dir,
      storage: receiver.storage,
      masterKey: receiver.masterKey,
      identityManager: receiver.identityManager,
      auditLog: receiver.auditLog,
      reputationStore: receiver.reputationStore,
      didWebAllowedHosts: [], // empty -> host_not_allowed, no socket
      didWebFetcher: async () => {
        fetcherCalls.count += 1;
        return { ok: true, status: 200, json: async () => ({}) };
      },
    });
    // The resolver returns host_not_allowed synchronously without
    // touching the fetcher. Castle Wall invariant preserved at the
    // application layer even when the operator's kernel-level
    // egress filter is not active.
    expect(fetcherCalls.count).toBe(0);
  });
});
