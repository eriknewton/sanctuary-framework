import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
import {
  exportExitBundle,
  importExitBundle,
  verifyExitBundle,
  ExitBundleImportError,
} from "../../src/exit/index.js";
import { EXIT_BUNDLE_DID_WEB_AUDIT_OPS } from "../../src/exit/bundle.js";
import { sign as identitySign } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import {
  canonicalize,
  canonicalizeToBytes,
} from "../../src/mesh/canonical-json.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { hash as sha256 } from "../../src/core/hashing.js";
import {
  reputationBundleSigningBytes,
  type ReputationBundle,
} from "../../src/reputation/reputation-store.js";

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

async function exportFromSource(
  source: Awaited<ReturnType<typeof makeHarness>>,
  bundleDir: string,
  stateNamespaces: string[] = []
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
    // Omit rather than forward an empty list: the exporter rejects a
    // supplied-but-empty selection, because that shape is what a flag parser
    // emits when the operator named nothing and it must mean "export all."
    ...(stateNamespaces.length > 0 ? { stateNamespaces } : {}),
    keySource: "recovery-key",
  });
}

describe("Exit bundle hardening (full-sweep #54 + #55)", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("#54: refuses identity overwrite without forceRebind, allows it with forceRebind, records audit", async () => {
    const source = await makeHarness();
    await callTool(source.tools, "identity_create", { label: "source-agent" });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-exit-hardening-54-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir);

    const destination = await makeHarness();
    await callTool(destination.tools, "identity_create", { label: "dest-default" });

    // First import: destination has a different identity, so forceRebind is
    // required (Finding RRR guard fires on mismatched active identity).
    const firstImport = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
      forceRebind: true,
    });
    expect(firstImport.activated).toBe(true);
    expect(firstImport.staged_artifacts).toContain("public_identity");

    await expect(
      importExitBundle({
        bundleDir,
        storage: destination.storage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
      })
    ).rejects.toThrow(ExitBundleImportError);

    let caught: ExitBundleImportError | null = null;
    try {
      await importExitBundle({
        bundleDir,
        storage: destination.storage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
      });
    } catch (err) {
      caught = err as ExitBundleImportError;
    }
    expect(caught).toBeInstanceOf(ExitBundleImportError);
    expect(caught?.code).toBe("IDENTITY_OVERWRITE_REFUSED");

    const dryRun = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: false,
    });
    expect(dryRun.conflicts.public_identity_exists).toBe(true);
    expect(dryRun.activated).toBe(false);

    const forced = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
      forceRebind: true,
    });
    expect(forced.verified).toBe(true);
    expect(forced.activated).toBe(true);
    expect(forced.conflicts.public_identity_exists).toBe(true);
    expect(forced.staged_artifacts).toContain("public_identity");

    await destination.auditLog.flush();
    const audit = await destination.auditLog.query({
      operation_type: "exit_bundle_force_rebind",
      limit: 10,
    });
    expect(audit.total).toBeGreaterThanOrEqual(1);
  });

  it("#55/B2: read-only verifier may relax unverifiable signers, but IMPORT never admits them (no signature-verification bypass)", async () => {
    const source = await makeHarness();
    const primary = await callTool(source.tools, "identity_create", {
      label: "source-default",
    });
    const secondary = await callTool(source.tools, "identity_create", {
      label: "source-secondary",
    });
    const secondaryIdentityId = secondary.identity_id as string;

    await callTool(source.tools, "reputation_record", {
      interaction_id: "bundle-laundering-001",
      counterparty_did: "did:key:counterparty",
      outcome: {
        type: "transaction",
        result: "completed",
        metrics: { score: 100 },
      },
      context: "exit-hardening",
      identity_id: secondaryIdentityId,
    });

    expect(typeof primary.identity_id).toBe("string");

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-exit-hardening-55-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir);

    // The read-only previewer keeps its strict-by-default / opt-in-relax
    // behavior: it produces a VERDICT and never writes to any store.
    const strict = await verifyExitBundle(bundleDir);
    expect(strict.passed).toBe(false);
    // Full-sweep #77 narrowed this from generic "other" to the
    // specific class so importers can branch without parsing warnings.
    expect(strict.failure_class).toBe("reputation_unverifiable_attestations");
    expect(strict.reputation?.unverifiable_attestations).toBe(1);
    expect(strict.warnings.some((w) => /accept-unverifiable-attestations/.test(w))).toBe(
      true
    );

    const relaxed = await verifyExitBundle(bundleDir, {
      acceptUnverifiableAttestations: true,
    });
    expect(relaxed.passed).toBe(true);
    expect(relaxed.reputation?.unverifiable_attestations).toBe(1);

    // Import path, ACTIVATE: rejected, no activation, nothing staged.
    const destination = await makeHarness();
    const importStrict = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
    });
    expect(importStrict.verified).toBe(false);
    expect(importStrict.activated).toBe(false);
    expect(importStrict.staged_artifacts).toEqual([]);
    await expect(
      destination.storage.list("_reputation")
    ).resolves.toHaveLength(0);

    // B2 round-2 finding 1 (dry-run reporting fail-open): the DRY-RUN
    // (activate:false) import path must ALSO verify strictly. The
    // accept-unverifiable relaxation has been removed from the import surface
    // entirely (it no longer type-checks as an ImportExitBundleOptions field),
    // so there is no caller-facing knob that can flip a dry-run verdict.
    //
    // FAIL-BEFORE this round-2 fix: importExitBundle({activate:false}) on a
    // bundle with an unverifiable reputation signer returned verified:true (the
    // strict reputation gate only ran on the activate:true path), and the
    // did:web branch could schedule audit appends before the dry-run return.
    // PASS-AFTER: the dry-run is verified:false with ZERO reputation writes and
    // ZERO audit writes.
    const destinationDry = await makeHarness();
    // Baseline audit-entry count BEFORE the dry-run import: the harness may have
    // written anchor/checkpoint markers at setup, so assert the import ADDS
    // nothing rather than assuming the namespace starts empty.
    await destinationDry.auditLog.flush();
    const auditBefore = (
      await destinationDry.storage.list("_audit")
    ).length;
    const importDryRun = await importExitBundle({
      bundleDir,
      storage: destinationDry.storage,
      masterKey: destinationDry.masterKey,
      identityManager: destinationDry.identityManager,
      auditLog: destinationDry.auditLog,
      reputationStore: destinationDry.reputationStore,
      activate: false,
    });
    expect(importDryRun.verified).toBe(false);
    expect(importDryRun.activated).toBe(false);
    expect(importDryRun.staged_artifacts).toEqual([]);
    // Nothing credited into the reputation store, and no audit entry scheduled.
    await expect(
      destinationDry.storage.list("_reputation")
    ).resolves.toHaveLength(0);
    await destinationDry.auditLog.flush();
    const auditAfter = (
      await destinationDry.storage.list("_audit")
    ).length;
    expect(auditAfter).toBe(auditBefore);
  });

  it("#55/B2 did:web branch: dry-run import of a did:web bundle with an unverifiable reputation signer stays before the did:web block (no fetcher call, zero reputation + zero audit writes)", async () => {
    // The strict reputation-signature gate runs BEFORE the did:web
    // cross-check block. This test proves that ordering on a bundle
    // that carries BOTH a did:web identity binding AND an unverifiable
    // reputation signer. If the gate were (re)moved to AFTER the
    // did:web block, the did:web audit appends and the fetcher would
    // fire before the reputation refusal returned, so this test would
    // fail. It is the did:web-branch counterpart to the #55/B2 dry-run
    // test above, which used a NON-did:web fixture and therefore never
    // exercised the did:web audit path.
    const AUTHORITY_HOST = "b2-didweb.example.com";
    const DID_URI = `did:web:${AUTHORITY_HOST}:fortress:b2rep:agent:default`;

    const source = await makeHarness();
    await callTool(source.tools, "identity_create", {
      label: "b2-didweb-primary",
    });
    // Record reputation under a SECONDARY identity so the signer DID is
    // absent from the bundle's published identity material: the
    // attestation is unverifiable, exactly the #55 laundering shape.
    const secondary = await callTool(source.tools, "identity_create", {
      label: "b2-didweb-secondary",
    });
    await callTool(source.tools, "reputation_record", {
      interaction_id: "b2-didweb-unverifiable-001",
      counterparty_did: "did:key:counterparty",
      outcome: {
        type: "transaction",
        result: "completed",
        metrics: { score: 100 },
      },
      context: "b2-didweb",
      identity_id: secondary.identity_id as string,
    });

    const bundleDir = await mkdtemp(
      join(tmpdir(), "sanctuary-exit-hardening-b2-didweb-")
    );
    tempDirs.push(bundleDir);
    // Export WITH a did:web binding so the manifest carries an
    // identity_binding.did_web the import path would otherwise resolve.
    await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir,
      storage: source.storage,
      masterKey: source.masterKey,
      identityManager: source.identityManager,
      auditLog: source.auditLog,
      reputationStore: source.reputationStore,
      policy: DEFAULT_POLICY,
      config: defaultConfig(),
      // No stateStoragePath is supplied, so discovery finds nothing; the
      // exporter rejects an explicit empty list, so omit it.
      keySource: "recovery-key",
      didWeb: { identifier: DID_URI, authority_host: AUTHORITY_HOST },
    });

    const destination = await makeHarness();
    // Capture the audit-entry count BEFORE the import: the harness may
    // have written setup markers, so assert the import ADDS zero rather
    // than assuming the namespace starts empty.
    await destination.auditLog.flush();
    const auditBefore = (await destination.storage.list("_audit")).length;

    // Configure a did:web fetcher and an allowed host: if control ever
    // reached the did:web block, the fetcher WOULD be invoked. It must
    // not be, because the strict reputation gate returns first.
    let fetcherInvoked = false;
    const result = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: false,
      didWebAllowedHosts: [AUTHORITY_HOST],
      didWebFetcher: async () => {
        fetcherInvoked = true;
        return { ok: true, status: 200, json: async () => ({}) };
      },
    });

    // (1) Refused: not verified, not activated, nothing staged.
    expect(result.verified).toBe(false);
    expect(result.activated).toBe(false);
    expect(result.staged_artifacts).toEqual([]);

    // (2) Zero reputation writes.
    await expect(
      destination.storage.list("_reputation")
    ).resolves.toHaveLength(0);

    // (3) Zero new audit entries: the strict gate returned before any
    // did:web audit append could be scheduled.
    await destination.auditLog.flush();
    const auditAfter = (await destination.storage.list("_audit")).length;
    expect(auditAfter).toBe(auditBefore);

    // (4) The did:web fetcher was never called, and no did:web audit
    // op (AUTHORITY_HOST / IMPORT_VERIFIED) was emitted. This is the
    // load-bearing assertion: it proves control never entered the
    // did:web block. If the strict gate moved to after the did:web
    // block, these would flip.
    expect(fetcherInvoked).toBe(false);
    const q = await destination.auditLog.query({ layer: "l1", limit: 200 });
    expect(
      q.entries.some(
        (e) =>
          e.operation === EXIT_BUNDLE_DID_WEB_AUDIT_OPS.AUTHORITY_HOST ||
          e.operation === EXIT_BUNDLE_DID_WEB_AUDIT_OPS.IMPORT_VERIFIED
      )
    ).toBe(false);
  });

  // Per full-sweep #77: helpers for tampering with internal artifact
  // signatures while keeping the per-file artifact hash + manifest
  // aggregate hash + manifest signature consistent. These tests verify
  // the verifier surfaces the *specific* failure class instead of the
  // generic "other".
  function sha256Hex(bytes: Uint8Array): string {
    return Array.from(sha256(bytes))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function jsonBytes(value: unknown): Uint8Array {
    return stringToBytes(JSON.stringify(value, null, 2) + "\n");
  }

  async function tamperArtifactInternalField(
    bundleDir: string,
    artifactKind: string,
    mutate: (parsed: Record<string, unknown>) => Record<string, unknown>,
    source: Awaited<ReturnType<typeof makeHarness>>
  ): Promise<void> {
    const manifestPath = join(bundleDir, "manifest.json");
    const rawManifest = await readFile(manifestPath, "utf8");
    const manifest = JSON.parse(rawManifest) as {
      body: {
        artifacts: Array<{
          kind: string;
          path: string;
          hash_alg: string;
          hash: string;
          size_bytes: number;
        }>;
        artifacts_aggregate_hash: string;
      };
      signature: string;
    };
    const entry = manifest.body.artifacts.find(
      (artifact) => artifact.kind === artifactKind
    );
    if (!entry) {
      throw new Error(
        `tamperArtifactInternalField: no artifact of kind ${artifactKind}`
      );
    }
    const artifactPath = join(bundleDir, entry.path);
    const parsed = JSON.parse(await readFile(artifactPath, "utf8")) as Record<
      string,
      unknown
    >;
    const tampered = mutate(parsed);
    const newBytes = jsonBytes(tampered);
    await writeFile(artifactPath, newBytes);
    entry.hash = sha256Hex(newBytes);
    entry.size_bytes = newBytes.length;
    manifest.body.artifacts_aggregate_hash = sha256Hex(
      stringToBytes(canonicalize(manifest.body.artifacts))
    );
    const identity = source.identityManager.getDefault();
    if (!identity) throw new Error("no default identity");
    const identityEncryptionKey = derivePurposeKey(
      source.masterKey,
      "identity-encryption"
    );
    const signature = identitySign(
      canonicalizeToBytes(manifest.body),
      identity.encrypted_private_key,
      identityEncryptionKey
    );
    manifest.signature = toBase64url(signature);
    await writeFile(manifestPath, jsonBytes(manifest));
  }

  async function rewriteManifest(
    bundleDir: string,
    signer: Awaited<ReturnType<typeof makeHarness>>,
    mutate: (manifest: {
      body: {
        identity_binding: {
          identity_id: string;
          fortress_id: string;
          fortress_master_pubkey: string;
          did?: string;
        };
      };
      signature: string;
    } & Record<string, unknown>) => void
  ): Promise<void> {
    const manifestPath = join(bundleDir, "manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
      body: {
        identity_binding: {
          identity_id: string;
          fortress_id: string;
          fortress_master_pubkey: string;
          did?: string;
        };
      };
      signature: string;
    } & Record<string, unknown>;
    mutate(manifest);
    const identity = signer.identityManager.getDefault();
    if (!identity) throw new Error("manifest signer identity missing");
    const identityEncryptionKey = derivePurposeKey(
      signer.masterKey,
      "identity-encryption"
    );
    manifest.signature = toBase64url(
      identitySign(
        canonicalizeToBytes(manifest.body),
        identity.encrypted_private_key,
        identityEncryptionKey
      )
    );
    await writeFile(manifestPath, jsonBytes(manifest));
  }

  const ACTIVATION_NAMESPACES = [
    "_exit_public_identities",
    "_exit_policy_sets",
    "_exit_audit_receipts",
    "_exit_commitments",
    "_exit_placeholder_metadata",
    "_exit_imports",
    "_reputation",
    "_audit",
  ] as const;

  async function activationNamespaceSnapshot(
    storage: MemoryStorage
  ): Promise<Record<string, string[]>> {
    const snapshot: Record<string, string[]> = {};
    for (const namespace of ACTIVATION_NAMESPACES) {
      snapshot[namespace] = (await storage.list(namespace)).map(
        (entry) => entry.key
      );
    }
    return snapshot;
  }

  async function expectNoActivationWritesAfterRejectedImport(
    bundleDir: string,
    destination: Awaited<ReturnType<typeof makeHarness>>,
    options: { acceptUnverifiableAttestations?: boolean } = {}
  ): Promise<void> {
    const before = await activationNamespaceSnapshot(destination.storage);
    let result:
      | Awaited<ReturnType<typeof importExitBundle>>
      | undefined;
    let thrown: unknown;
    try {
      result = await importExitBundle({
        bundleDir,
        storage: destination.storage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
        ...options,
      });
    } catch (err) {
      thrown = err;
    }

    if (thrown === undefined) {
      expect(result?.activated).toBe(false);
      expect(result?.staged_artifacts).toEqual([]);
    }
    expect(thrown ?? result).toBeDefined();
    await destination.auditLog.flush();
    await expect(activationNamespaceSnapshot(destination.storage)).resolves.toEqual(
      before
    );
  }

  function signReputationBody(
    source: Awaited<ReturnType<typeof makeHarness>>,
    body: {
      version: "SANCTUARY_REP_V1";
      attestations: ReputationBundle["attestations"];
      exported_at: string;
      exporter_did: string;
      completeness_manifest?: ReputationBundle["completeness_manifest"];
    },
    legacyJson = false
  ): string {
    const identity = source.identityManager.getDefault();
    if (!identity) throw new Error("no default identity");
    const identityEncryptionKey = derivePurposeKey(
      source.masterKey,
      "identity-encryption"
    );
    const bytes = legacyJson
      ? stringToBytes(
          JSON.stringify({
            version: body.version,
            attestations: body.attestations,
            exported_at: body.exported_at,
            exporter_did: body.exporter_did,
          })
        )
      : reputationBundleSigningBytes(body);
    return toBase64url(
      identitySign(bytes, identity.encrypted_private_key, identityEncryptionKey)
    );
  }

  it("#77: verifier surfaces identity_signature_invalid when public_identity signature is tampered", async () => {
    const source = await makeHarness();
    await callTool(source.tools, "identity_create", { label: "tampered-id" });
    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-77-identity-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir);

    // Replace the inner `signature` with a syntactically-valid but
    // cryptographically-wrong base64url string. The artifact-hash
    // check still passes because we recompute the artifact hash;
    // only the signature verification at line ~238 of verifier.ts
    // should fail, surfacing identity_signature_invalid.
    await tamperArtifactInternalField(
      bundleDir,
      "public_identity",
      (parsed) => ({
        ...parsed,
        signature: toBase64url(new Uint8Array(64)),
      }),
      source
    );

    const result = await verifyExitBundle(bundleDir);
    expect(result.passed).toBe(false);
    expect(result.failure_class).toBe("identity_signature_invalid");
    expect(result.identity?.signature_valid).toBe(false);
  });

  it("M-02: verifier rejects a manifest re-bound to a different identity than public_identity", async () => {
    const sourceA = await makeHarness();
    await callTool(sourceA.tools, "identity_create", { label: "source-a" });
    const sourceB = await makeHarness();
    await callTool(sourceB.tools, "identity_create", { label: "source-b" });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-m02-rebound-"));
    tempDirs.push(bundleDir);
    await exportFromSource(sourceA, bundleDir);

    const honest = await verifyExitBundle(bundleDir);
    expect(honest.passed).toBe(true);

    await rewriteManifest(bundleDir, sourceB, (manifest) => {
      const identity = sourceB.identityManager.getDefault();
      if (!identity) throw new Error("source-b identity missing");
      manifest.body.identity_binding = {
        identity_id: identity.identity_id,
        fortress_id: identity.did,
        fortress_master_pubkey: identity.public_key,
        did: identity.did,
      };
    });

    const result = await verifyExitBundle(bundleDir);
    expect(result.passed).toBe(false);
    expect(result.failure_class).toBe("identity_binding_mismatch");
    expect(result.identity?.signature_valid).toBe(true);
    expect(result.warnings.join("\n")).toContain("identity_binding_mismatch");
  });

  it("M-02: verifier rejects each manifest/public_identity binding mismatch independently", async () => {
    const sourceA = await makeHarness();
    await callTool(sourceA.tools, "identity_create", { label: "source-a-fields" });
    const sourceB = await makeHarness();
    await callTool(sourceB.tools, "identity_create", { label: "source-b-fields" });
    const identityA = sourceA.identityManager.getDefault();
    const identityB = sourceB.identityManager.getDefault();
    if (!identityA || !identityB) throw new Error("test identities missing");

    const scenarios = [
      {
        name: "identity_id",
        signer: sourceA,
        mutate: (binding: {
          identity_id: string;
          fortress_id: string;
          fortress_master_pubkey: string;
          did?: string;
        }) => {
          binding.identity_id = `${binding.identity_id}-other`;
        },
        warning: "manifest identity_id does not match",
      },
      {
        name: "fortress_master_pubkey",
        signer: sourceB,
        mutate: (binding: {
          identity_id: string;
          fortress_id: string;
          fortress_master_pubkey: string;
          did?: string;
        }) => {
          binding.identity_id = identityA.identity_id;
          binding.fortress_id = identityA.did;
          binding.fortress_master_pubkey = identityB.public_key;
          binding.did = identityA.did;
        },
        warning: "manifest fortress_master_pubkey does not match",
      },
      {
        name: "did",
        signer: sourceA,
        mutate: (binding: {
          identity_id: string;
          fortress_id: string;
          fortress_master_pubkey: string;
          did?: string;
        }) => {
          binding.did = identityB.did;
        },
        warning: "manifest did does not match",
      },
    ];

    for (const scenario of scenarios) {
      const bundleDir = await mkdtemp(
        join(tmpdir(), `sanctuary-m02-${scenario.name}-`)
      );
      tempDirs.push(bundleDir);
      await exportFromSource(sourceA, bundleDir);
      await rewriteManifest(bundleDir, scenario.signer, (manifest) => {
        scenario.mutate(manifest.body.identity_binding);
      });

      const result = await verifyExitBundle(bundleDir);
      expect(result.passed, scenario.name).toBe(false);
      expect(result.failure_class, scenario.name).toBe(
        "identity_binding_mismatch"
      );
      expect(result.warnings.join("\n"), scenario.name).toContain(
        scenario.warning
      );
    }
  });

  it("M-02: verifier accepts the named legacy path where manifest identity_binding.did is absent", async () => {
    const source = await makeHarness();
    await callTool(source.tools, "identity_create", { label: "legacy-did-absent" });
    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-m02-legacy-did-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir);

    await rewriteManifest(bundleDir, source, (manifest) => {
      delete manifest.body.identity_binding.did;
    });

    const result = await verifyExitBundle(bundleDir);
    expect(result.passed).toBe(true);
    expect(result.identity?.signature_valid).toBe(true);
    expect(result.warnings.join("\n")).toContain(
      "legacy_identity_binding_did_absent"
    );
  });

  it("#77: verifier surfaces reputation_bundle_signature_invalid when reputation bundle signature is tampered", async () => {
    const source = await makeHarness();
    const created = await callTool(source.tools, "identity_create", {
      label: "tampered-rep",
    });
    const identityId = created.identity_id as string;
    await callTool(source.tools, "reputation_record", {
      interaction_id: "rep-tamper-001",
      counterparty_did: "did:key:counterparty",
      outcome: {
        type: "transaction",
        result: "completed",
        metrics: { score: 50 },
      },
      context: "rep-tamper",
      identity_id: identityId,
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-77-rep-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir);

    // Replace bundle_signature with a wrong-but-well-formed base64url
    // value. Per the verifier flow, attestations whose signer DID is
    // present in publicKeysByDid still verify successfully; only the
    // bundle-level signature fails, isolating the
    // reputation_bundle_signature_invalid path.
    await tamperArtifactInternalField(
      bundleDir,
      "reputation_bundle",
      (parsed) => ({
        ...parsed,
        bundle_signature: toBase64url(new Uint8Array(64)),
      }),
      source
    );

    const result = await verifyExitBundle(bundleDir);
    expect(result.passed).toBe(false);
    expect(result.failure_class).toBe("reputation_bundle_signature_invalid");
    expect(result.reputation?.bundle_signature_valid).toBe(false);

    const destination = await makeHarness();
    await expectNoActivationWritesAfterRejectedImport(bundleDir, destination);
  });

  it("exit activation rejects manifestless reputation before staging artifacts", async () => {
    const source = await makeHarness();
    const created = await callTool(source.tools, "identity_create", {
      label: "missing-rep-manifest",
    });
    const identityId = created.identity_id as string;
    await callTool(source.tools, "reputation_record", {
      interaction_id: "missing-manifest-001",
      counterparty_did: "did:key:counterparty",
      outcome: {
        type: "transaction",
        result: "completed",
        metrics: { score: 90 },
      },
      context: "exit-atomicity",
      identity_id: identityId,
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-exit-atomicity-missing-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir);

    await tamperArtifactInternalField(
      bundleDir,
      "reputation_bundle",
      (parsed) => {
        const bundle = parsed as unknown as ReputationBundle;
        const legacy = { ...bundle } as Record<string, unknown>;
        delete legacy.completeness_manifest;
        legacy.bundle_signature = signReputationBody(
          source,
          {
            version: bundle.version,
            attestations: bundle.attestations,
            exported_at: bundle.exported_at,
            exporter_did: bundle.exporter_did,
          },
          true
        );
        return legacy;
      },
      source
    );

    const outerVerification = await verifyExitBundle(bundleDir);
    expect(outerVerification.passed).toBe(true);
    expect(outerVerification.reputation?.completeness).toBe(
      "unverified-completeness-legacy-bundle"
    );
    expect(outerVerification.reputation?.completeness).not.toBe("verified");

    const destination = await makeHarness();
    await expectNoActivationWritesAfterRejectedImport(bundleDir, destination);
  });

  it("exit activation rejects mismatched reputation completeness before staging artifacts", async () => {
    const source = await makeHarness();
    const created = await callTool(source.tools, "identity_create", {
      label: "bad-rep-manifest",
    });
    const identityId = created.identity_id as string;
    await callTool(source.tools, "reputation_record", {
      interaction_id: "bad-manifest-001",
      counterparty_did: "did:key:counterparty",
      outcome: {
        type: "transaction",
        result: "completed",
        metrics: { score: 91 },
      },
      context: "exit-atomicity",
      identity_id: identityId,
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-exit-atomicity-bad-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir);

    await tamperArtifactInternalField(
      bundleDir,
      "reputation_bundle",
      (parsed) => {
        const bundle = parsed as unknown as ReputationBundle;
        const tampered = {
          ...bundle,
          completeness_manifest: {
            ...bundle.completeness_manifest!,
            total_attestation_count: bundle.attestations.length + 1,
          },
        };
        return {
          ...tampered,
          bundle_signature: signReputationBody(source, tampered),
        } as unknown as Record<string, unknown>;
      },
      source
    );

    const outerVerification = await verifyExitBundle(bundleDir);
    expect(outerVerification.passed).toBe(false);
    expect(outerVerification.failure_class).toBe(
      "reputation_completeness_mismatch"
    );
    expect(outerVerification.reputation?.bundle_signature_valid).toBe(true);
    expect(outerVerification.reputation?.completeness).toBe("mismatch");

    const destination = await makeHarness();
    await expectNoActivationWritesAfterRejectedImport(bundleDir, destination);
  });

  it("verify-exit-bundle fails when a signed reputation body is truncated against its completeness manifest", async () => {
    const source = await makeHarness();
    const created = await callTool(source.tools, "identity_create", {
      label: "truncated-rep-manifest",
    });
    const identityId = created.identity_id as string;
    for (const interactionId of ["truncated-001", "truncated-002"]) {
      await callTool(source.tools, "reputation_record", {
        interaction_id: interactionId,
        counterparty_did: "did:key:counterparty",
        outcome: {
          type: "transaction",
          result: "completed",
          metrics: { score: 94 },
        },
        context: "exit-truncation",
        identity_id: identityId,
      });
    }

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-exit-truncated-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir);

    await tamperArtifactInternalField(
      bundleDir,
      "reputation_bundle",
      (parsed) => {
        const bundle = parsed as unknown as ReputationBundle;
        const truncated = {
          ...bundle,
          attestations: bundle.attestations.slice(0, 1),
        };
        return {
          ...truncated,
          bundle_signature: signReputationBody(source, truncated),
        } as unknown as Record<string, unknown>;
      },
      source
    );

    const result = await verifyExitBundle(bundleDir);
    expect(result.passed).toBe(false);
    expect(result.failure_class).toBe("reputation_completeness_mismatch");
    expect(result.reputation?.bundle_signature_valid).toBe(true);
    expect(result.reputation?.attestation_count).toBe(1);
    expect(result.reputation?.completeness).toBe("mismatch");
    expect(result.warnings.join("\n")).toContain(
      "Reputation bundle completeness manifest does not match contents"
    );
  });

  it("exit activation leaves no artifacts for unverifiable reputation without opt-in", async () => {
    const source = await makeHarness();
    await callTool(source.tools, "identity_create", {
      label: "primary-only-in-bundle",
    });
    const secondary = await callTool(source.tools, "identity_create", {
      label: "secondary-reputation-signer",
    });
    await callTool(source.tools, "reputation_record", {
      interaction_id: "unverifiable-atomicity-001",
      counterparty_did: "did:key:counterparty",
      outcome: {
        type: "transaction",
        result: "completed",
        metrics: { score: 92 },
      },
      context: "exit-atomicity",
      identity_id: secondary.identity_id as string,
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-exit-atomicity-unverifiable-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir);

    const outerVerification = await verifyExitBundle(bundleDir);
    expect(outerVerification.passed).toBe(false);
    expect(outerVerification.failure_class).toBe(
      "reputation_unverifiable_attestations"
    );

    const destination = await makeHarness();
    await expectNoActivationWritesAfterRejectedImport(bundleDir, destination);
  });

  it("#55: verifier still passes clean bundles with no unverifiable attestations", async () => {
    const source = await makeHarness();
    const primary = await callTool(source.tools, "identity_create", {
      label: "source-default",
    });
    const primaryIdentityId = primary.identity_id as string;

    await callTool(source.tools, "reputation_record", {
      interaction_id: "clean-bundle-001",
      counterparty_did: "did:key:counterparty",
      outcome: {
        type: "transaction",
        result: "completed",
        metrics: { score: 75 },
      },
      context: "happy-path",
      identity_id: primaryIdentityId,
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-exit-hardening-clean-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir);

    const verified = await verifyExitBundle(bundleDir);
    expect(verified.passed).toBe(true);
    expect(verified.reputation?.completeness).toBe("verified");
    expect(verified.reputation?.unverifiable_attestations).toBe(0);
    expect(verified.reputation?.verified_attestations).toBe(1);
  });

  it("exit activation happy path still stages and imports reputation", async () => {
    const source = await makeHarness();
    const created = await callTool(source.tools, "identity_create", {
      label: "atomicity-happy",
    });
    const identityId = created.identity_id as string;
    await callTool(source.tools, "reputation_record", {
      interaction_id: "atomicity-happy-001",
      counterparty_did: "did:key:counterparty",
      outcome: {
        type: "transaction",
        result: "completed",
        metrics: { score: 93 },
      },
      context: "exit-atomicity",
      identity_id: identityId,
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-exit-atomicity-happy-"));
    tempDirs.push(bundleDir);
    await exportFromSource(source, bundleDir);

    const destination = await makeHarness();
    const imported = await importExitBundle({
      bundleDir,
      storage: destination.storage,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      reputationStore: destination.reputationStore,
      activate: true,
    });

    expect(imported.verified).toBe(true);
    expect(imported.activated).toBe(true);
    expect(imported.reputation.imported_attestations).toBe(1);
    expect([...imported.staged_artifacts].sort()).toEqual([
      "audit_receipts",
      "commitments",
      "placeholder_vault_metadata",
      "policy_set",
      "public_identity",
      "reputation_bundle",
    ]);
  });
});
