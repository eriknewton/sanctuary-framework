/**
 * Exit V2 drill F2 (2026-08-22/23, Erik-ratified option a,
 * `Wiki/decisions/exit-v2-known-signers-carried-in-bundle-2026-08-22.md`):
 * a fortress that imports another fortress's reputation attestations now
 * persists the DID -> public key mapping it verified at import time
 * (`server/src/reputation/known-signers-store.ts`), and its OWN later
 * export carries that mapping forward as a signed `known_signers` artifact
 * (`server/src/exit/verifier.ts` `resolveKnownSigners`, consumed
 * identically by `verifyExitBundle` and `importExitBundle`'s pre-staging
 * gate). Before this change, a re-exported (second-hop) bundle's
 * foreign-signed attestations had no key material to verify against and
 * were reported `reputation_unverifiable_attestations` even though every
 * hop individually verified.
 *
 * This file drives the drill-shaped positive case (A -> B -> C -> D, the
 * shape the drill found broken), the version gate, the store-wide capacity
 * bound, the compromised-key exclusion, and a parameterized set of
 * refusal fixtures: every one asserts a typed hard failure
 * (`known_signers_invalid`) BEFORE any staging write, never a soft
 * warning, and a byte-identical destination storage snapshot before and
 * after the refused attempt (private register EXIT-KS-01).
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageEntryMeta } from "../../src/storage/interface.js";
import { generateRandomKey } from "../../src/core/random.js";
import { fromBase64url, stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { hash } from "../../src/core/hashing.js";
import { sign as identitySign, publicKeyToDid, legacyPublicKeyToDid } from "../../src/core/identity.js";
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
  ExitBundleImportError,
  type ExportExitBundleResult,
} from "../../src/exit/index.js";
import {
  verifyExitBundle,
  knownSignersSigningBytes,
  checkKnownSignersStructure,
  isKnownSignersArtifactSizeAcceptable,
  type KnownSignersEntry,
} from "../../src/exit/verifier.js";
import type { ExitBundleManifest } from "../../src/contracts/v1.1/exit-bundle-manifest.js";
import { EXIT_BUNDLE_MANIFEST_VERSION } from "../../src/contracts/v1.1/constants.js";
import {
  KnownSignersStore,
  MAX_KNOWN_SIGNERS,
} from "../../src/reputation/known-signers-store.js";
import {
  buildReputationCompletenessManifest,
  reputationBundleSigningBytes,
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

type Harness = Awaited<ReturnType<typeof makeHarness>>;

async function createIdentity(harness: Harness, label: string): Promise<string> {
  const created = await callTool(harness.tools, "identity_create", { label });
  return created.identity_id as string;
}

async function recordAttestation(
  harness: Harness,
  identityId: string,
  interactionId: string,
  context: string
): Promise<void> {
  const result = await callTool(harness.tools, "reputation_record", {
    interaction_id: interactionId,
    counterparty_did: `did:key:z6Mk${interactionId}counterparty`,
    outcome: { type: "negotiation", result: "success", metrics: { score: 88 } },
    context,
    identity_id: identityId,
  });
  if (result.error) {
    throw new Error(`seed reputation_record failed: ${JSON.stringify(result)}`);
  }
}

async function exportBundle(
  source: Harness,
  bundleDir: string
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
    keySource: "recovery-key",
  });
}

async function importInto(
  destination: Harness,
  destinationIdentityId: string,
  bundleDir: string
) {
  return importExitBundle({
    bundleDir,
    storage: destination.storage,
    masterKey: destination.masterKey,
    identityManager: destination.identityManager,
    auditLog: destination.auditLog,
    reputationStore: destination.reputationStore,
    activate: true,
    forceRebind: true,
    destinationSignerIdentityId: destinationIdentityId,
  });
}

/**
 * Recompute the manifest's aggregate hash and re-sign it with `signer`'s
 * default identity - the SAME two steps `exportExitBundle` performs, run
 * again here after a test has hand-mutated an artifact on disk. Mirrors
 * the equivalent helper in test/exit/exit-bundle-rotated-roundtrip.test.ts
 * and test/exit/exit-verifier-aggregator.test.ts.
 */
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

async function updateArtifactHashAndSize(
  bundleDir: string,
  kind: "known_signers" | "reputation_bundle",
  artifactBytes: Uint8Array
): Promise<void> {
  const manifestPath = join(bundleDir, "manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as ExitBundleManifest;
  const entry = manifest.body.artifacts.find((a) => a.kind === kind);
  if (!entry) throw new Error(`missing ${kind} artifact entry`);
  entry.hash = Array.from(hash(artifactBytes))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  entry.size_bytes = artifactBytes.length;
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
}

/** Read, mutate, and optionally re-sign the `known_signers` artifact, then fix up the manifest's hash/size entry and re-sign the manifest with `manifestSigner`'s identity. */
async function rewriteKnownSigners(
  bundleDir: string,
  manifestSigner: Harness,
  mutate: (parsed: { version: number; signers: KnownSignersEntry[]; signature: string }) => {
    version: number;
    signers: KnownSignersEntry[];
    signature: string;
  },
  resignWith?: Harness
): Promise<void> {
  const artifactPath = join(bundleDir, "artifacts/known_signers.json");
  const parsed = JSON.parse(await readFile(artifactPath, "utf8")) as {
    version: number;
    signers: KnownSignersEntry[];
    signature: string;
  };
  let mutated = mutate(parsed);
  if (resignWith) {
    const identity = resignWith.identityManager.getDefault();
    if (!identity) throw new Error("missing identity to resign known_signers");
    const signature = identitySign(
      knownSignersSigningBytes({ version: 1, signers: mutated.signers }),
      identity.encrypted_private_key,
      derivePurposeKey(resignWith.masterKey, "identity-encryption")
    );
    mutated = { ...mutated, signature: toBase64url(signature) };
  }
  const artifactBytes = stringToBytes(JSON.stringify(mutated, null, 2) + "\n");
  await writeFile(artifactPath, artifactBytes);
  await updateArtifactHashAndSize(bundleDir, "known_signers", artifactBytes);
  await resignManifest(bundleDir, manifestSigner);
}

/** Remove the known_signers artifact and its manifest entry entirely - simulating a bundle exported before this change. */
async function removeKnownSignersArtifact(
  bundleDir: string,
  manifestSigner: Harness
): Promise<void> {
  await rm(join(bundleDir, "artifacts/known_signers.json"), { force: true });
  const manifestPath = join(bundleDir, "manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as ExitBundleManifest;
  manifest.body.artifacts = manifest.body.artifacts.filter(
    (a) => a.kind !== "known_signers"
  );
  // Independent gate item 5 (2026-08-23): a bundle without the
  // known_signers artifact must declare the ORIGINAL frozen V1 manifest
  // version, not the known-signers one - the per-version exact-artifact-set
  // check (verifier.ts) refuses a known-signers-version manifest whose
  // artifact set does not include known_signers. This is exactly what makes
  // the resulting bundle a faithful stand-in for a genuinely pre-this-change
  // export, not merely "the same bytes with one artifact missing."
  manifest.body.manifest_version = EXIT_BUNDLE_MANIFEST_VERSION;
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
  await resignManifest(bundleDir, manifestSigner);
}

/**
 * Full-content snapshot of a MemoryStorage's every namespace EXCEPT
 * `_audit*` (audit entries carry a real timestamp and always differ across
 * two points in time even across a genuine no-op). MEDIUM-5 (independent
 * gate on #1303, 2026-08-23): every refusal fixture below proves not just
 * `activated: false`/a thrown error, but that the destination's storage is
 * BYTE-IDENTICAL before and after the refused import attempt - zero
 * staging writes, not merely zero *successful* writes.
 */
async function snapshotAll(storage: MemoryStorage): Promise<string> {
  const namespaces = await storage.listNamespaces();
  const rows: string[] = [];
  for (const ns of namespaces) {
    if (ns.startsWith("_audit")) continue;
    const entries: StorageEntryMeta[] = await storage.list(ns);
    for (const entry of entries) {
      const data = await storage.read(ns, entry.key);
      rows.push(`${ns}/${entry.key}:${data ? toBase64url(data) : "null"}`);
    }
  }
  return rows.sort().join("\n");
}

describe("Exit V2 known_signers (drill F2)", () => {
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

  it("a bundle with no known_signers artifact at all verifies and imports exactly as before this change (version gate)", async () => {
    const source = await makeHarness();
    const sourceIdentityId = await createIdentity(source, "vg-source");
    await recordAttestation(source, sourceIdentityId, "vg-ix-1", "vg-ctx");

    const bundleDir = await newBundleDir("sanctuary-known-signers-vg-");
    await exportBundle(source, bundleDir);
    // Every export now emits known_signers.json (even with an empty
    // `signers` list, since this single-hop export has no foreign
    // attestations to carry). Remove it entirely and re-sign, to exercise
    // the ACTUAL pre-change wire shape rather than the equivalent-but-not-
    // identical "empty table present" shape.
    await removeKnownSignersArtifact(bundleDir, source);

    const verified = await verifyExitBundle(bundleDir);
    expect(verified.passed).toBe(true);
    expect(verified.reputation?.verified_attestations).toBe(1);
    expect(verified.reputation?.unverifiable_attestations).toBe(0);
    expect(verified.manifest_summary.artifact_count).toBe(7);

    const destination = await makeHarness();
    const destinationIdentityId = await createIdentity(destination, "vg-destination");
    const imported = await importInto(destination, destinationIdentityId, bundleDir);
    expect(imported.activated).toBe(true);
    expect(imported.reputation.imported_attestations).toBe(1);
    expect(imported.reputation.unverifiable_attestations).toBe(0);
  });

  it("the drill-shaped second hop: A -> B -> C, C verifies A's attestation through B's known_signers table with zero unverifiable attestations", async () => {
    const fortressA = await makeHarness();
    const aIdentityId = await createIdentity(fortressA, "hop-a");
    await recordAttestation(fortressA, aIdentityId, "hop-ix-a1", "hop-ctx");
    await recordAttestation(fortressA, aIdentityId, "hop-ix-a2", "hop-ctx");

    const bundleAB = await newBundleDir("sanctuary-known-signers-ab-");
    await exportBundle(fortressA, bundleAB);
    const verifiedAB = await verifyExitBundle(bundleAB);
    expect(verifiedAB.passed).toBe(true);
    expect(verifiedAB.reputation?.unverifiable_attestations).toBe(0);

    const fortressB = await makeHarness();
    const bIdentityId = await createIdentity(fortressB, "hop-b");
    const importedAB = await importInto(fortressB, bIdentityId, bundleAB);
    expect(importedAB.activated).toBe(true);
    expect(importedAB.reputation.imported_attestations).toBe(2);
    expect(importedAB.reputation.unverifiable_attestations).toBe(0);

    // B gives itself one attestation of its own too, so the second-hop
    // bundle carries a MIX of B's own (directly verifiable via B's own
    // identity artifact) and A's foreign (only resolvable through the
    // known_signers table) attestations.
    await recordAttestation(fortressB, bIdentityId, "hop-ix-b1", "hop-ctx");

    const bundleBC = await newBundleDir("sanctuary-known-signers-bc-");
    const exportedBC = await exportBundle(fortressB, bundleBC);
    const knownSignersRaw = JSON.parse(
      await readFile(join(bundleBC, "artifacts/known_signers.json"), "utf8")
    ) as { version: number; signers: KnownSignersEntry[] };
    expect(knownSignersRaw.signers.map((s) => s.did)).toContain(
      fortressA.identityManager.getDefault()?.did
    );
    // LOW (re-gate on #1303, 2026-08-23): first_seen_import_id is local-only
    // bookkeeping (it embeds A's identity_id + exported_at) and must never
    // reach the wire - checked on the RAW exported JSON, not the typed
    // KnownSignersEntry (whose type no longer declares the field at all, so
    // a typed check alone could not catch a stray runtime property).
    for (const signer of knownSignersRaw.signers) {
      expect(Object.keys(signer).sort()).toEqual(["did", "public_key"]);
    }
    expect(exportedBC.manifest.body.artifacts.map((a) => a.kind)).toContain(
      "known_signers"
    );

    const verifiedBC = await verifyExitBundle(bundleBC);
    expect(verifiedBC.passed).toBe(true);
    expect(verifiedBC.reputation?.attestation_count).toBe(3);
    expect(verifiedBC.reputation?.verified_attestations).toBe(3);
    expect(verifiedBC.reputation?.unverifiable_attestations).toBe(0);

    const fortressC = await makeHarness();
    const cIdentityId = await createIdentity(fortressC, "hop-c");
    const importedBC = await importInto(fortressC, cIdentityId, bundleBC);
    expect(importedBC.activated).toBe(true);
    expect(importedBC.reputation.imported_attestations).toBe(3);
    expect(importedBC.reputation.unverifiable_attestations).toBe(0);
    expect(importedBC.reputation.invalid_attestations).toBe(0);
  });

  it("independent gate item 4 (MEDIUM-4): a signer key retired for a COMPROMISED reason is never persisted into known_signers by default, only under --accept-compromised-rotation-keys", async () => {
    const fortressA = await makeHarness();
    const aIdentityId = await createIdentity(fortressA, "compromise-a");
    // Attestation signed by A's CURRENT key, BEFORE rotation - after
    // rotation this key becomes a COMPROMISED retired candidate on A's own
    // rotation chain, but the attestation's signature (over the ORIGINAL
    // signing key) never changes.
    await recordAttestation(fortressA, aIdentityId, "compromise-ix-a1", "compromise-ctx");
    await callTool(fortressA.tools, "identity_rotate", {
      identity_id: aIdentityId,
      reason: "compromised",
    });

    const bundleAB = await newBundleDir("sanctuary-known-signers-compromise-ab-");
    await exportBundle(fortressA, bundleAB);
    const verifiedAB = await verifyExitBundle(bundleAB);
    // The attestation signature itself verifies fine (the compromised flag
    // gates PERSISTENCE into known_signers, MEDIUM-4's scope, not signature
    // validity - a retired key, compromised or not, is still the key that
    // actually produced this signature).
    expect(verifiedAB.passed).toBe(true);
    expect(verifiedAB.reputation?.unverifiable_attestations).toBe(0);

    // Default (no opt-in): import succeeds (no STATE entry here to trip the
    // separate COMPROMISED_ROTATION_KEY_REFUSED gate - this fortress never
    // wrote any state), but the compromised signer's key is EXCLUDED from
    // what gets persisted into _known_signers.
    const refusedDestination = await makeHarness();
    const refusedDestinationId = await createIdentity(refusedDestination, "compromise-b-default");
    const importedDefault = await importInto(refusedDestination, refusedDestinationId, bundleAB);
    expect(importedDefault.activated).toBe(true);
    expect(importedDefault.reputation.imported_attestations).toBe(1);
    expect((await refusedDestination.storage.list("_known_signers")).length).toBe(0);

    // With the explicit opt-in: the SAME compromised-signer key IS
    // persisted - an operator who has already accepted the compromised-key
    // risk is not silently denied the portability this table exists for.
    const acceptedDestination = await makeHarness();
    const acceptedDestinationId = await createIdentity(acceptedDestination, "compromise-b-accepted");
    const importedAccepted = await importExitBundle({
      bundleDir: bundleAB,
      storage: acceptedDestination.storage,
      masterKey: acceptedDestination.masterKey,
      identityManager: acceptedDestination.identityManager,
      auditLog: acceptedDestination.auditLog,
      reputationStore: acceptedDestination.reputationStore,
      activate: true,
      forceRebind: true,
      destinationSignerIdentityId: acceptedDestinationId,
      acceptCompromisedRotationKeys: true,
    });
    expect(importedAccepted.activated).toBe(true);
    expect(importedAccepted.reputation.imported_attestations).toBe(1);
    expect((await acceptedDestination.storage.list("_known_signers")).length).toBe(1);
  });

  it("MEDIUM (re-gate on #1303, item 1): a known_signers entry using the legacy did:key encoding for its key is accepted at a third hop, not refused as a mismatch", async () => {
    const fortressA = await makeHarness();
    const aIdentityId = await createIdentity(fortressA, "legacy-a");
    await recordAttestation(fortressA, aIdentityId, "legacy-ix-a1", "legacy-ctx");
    const bundleAB = await newBundleDir("sanctuary-known-signers-legacy-ab-");
    await exportBundle(fortressA, bundleAB);
    const aDid = fortressA.identityManager.getDefault()?.did;
    if (!aDid) throw new Error("missing A did");

    const fortressB = await makeHarness();
    const bIdentityId = await createIdentity(fortressB, "legacy-b");
    const importedAB = await importInto(fortressB, bIdentityId, bundleAB);
    expect(importedAB.activated).toBe(true);

    const bundleBC = await newBundleDir("sanctuary-known-signers-legacy-bc-");
    await exportBundle(fortressB, bundleBC);
    const legacyADid = legacyPublicKeyToDid(
      fromBase64url(fortressA.identityManager.getDefault()!.public_key)
    );
    // Fixture: a genuinely legacy-DID fortress A - its attestation's
    // `signer` field (unsigned metadata; the signature covers only
    // `attestation.data`) AND B's table entry for A both use the RETIRED
    // base64url did:key encoding (legacyPublicKeyToDid) instead of the
    // canonical base58btc one, for the SAME key. core/identity.ts still
    // treats this encoding as live, and exit/v2-memory-archive.ts already
    // accepts both forms for the same class of check.
    await rewriteKnownSigners(
      bundleBC,
      fortressB,
      (parsed) => ({
        ...parsed,
        signers: parsed.signers.map((entry) =>
          entry.did === aDid ? { ...entry, did: legacyADid } : entry
        ),
      }),
      fortressB
    );
    const reputationPath = join(bundleBC, "artifacts/reputation_bundle.json");
    const reputationRaw = JSON.parse(
      await readFile(reputationPath, "utf8")
    ) as {
      version: "SANCTUARY_REP_V1";
      attestations: Array<{
        signer: string;
        data: { participant_did: string; [key: string]: unknown };
        signature: string;
        [key: string]: unknown;
      }>;
      exported_at: string;
      exporter_did: string;
      completeness_manifest?: unknown;
    };
    const aIdentity = fortressA.identityManager.getDefault();
    if (!aIdentity) throw new Error("missing A identity");
    const aIdentityEncryptionKey = derivePurposeKey(
      fortressA.masterKey,
      "identity-encryption"
    );
    // `signer` AND `data.participant_did` both move to the legacy form - a
    // genuinely legacy-DID fortress A would have recorded this attestation
    // with both fields already equal (reputation-store.ts record() sets
    // them from the SAME `identity.did`), so both are updated in lockstep
    // here and the attestation's OWN signature (over `data`, by A's real
    // key - the key itself is unchanged, only its DID label) is redone to
    // match, exactly reproducing what A recording under a legacy identity
    // would have produced.
    reputationRaw.attestations = reputationRaw.attestations.map((attestation) => {
      if (attestation.signer !== aDid) return attestation;
      const data = { ...attestation.data, participant_did: legacyADid };
      const signature = toBase64url(
        identitySign(
          stringToBytes(JSON.stringify(data)),
          aIdentity.encrypted_private_key,
          aIdentityEncryptionKey
        )
      );
      return { ...attestation, signer: legacyADid, data, signature };
    });
    // The reputation bundle's OWN completeness manifest and signature cover
    // the attestations array too - both must be recomputed and re-signed by
    // B (the reputation bundle's actual signer), independent of the OUTER
    // exit-bundle manifest's own signature.
    reputationRaw.completeness_manifest = buildReputationCompletenessManifest(
      reputationRaw.exported_at,
      reputationRaw.attestations as never
    );
    const bIdentity2 = fortressB.identityManager.getDefault();
    if (!bIdentity2) throw new Error("missing B identity");
    const reputationSignature = toBase64url(
      identitySign(
        reputationBundleSigningBytes(reputationRaw as never),
        bIdentity2.encrypted_private_key,
        derivePurposeKey(fortressB.masterKey, "identity-encryption")
      )
    );
    const reputationBytes = stringToBytes(
      JSON.stringify(
        { ...reputationRaw, bundle_signature: reputationSignature },
        null,
        2
      ) + "\n"
    );
    await writeFile(reputationPath, reputationBytes);
    await updateArtifactHashAndSize(bundleBC, "reputation_bundle", reputationBytes);
    await resignManifest(bundleBC, fortressB);
    // Sanity: the fixture actually changed the DID's spelling (proving the
    // test exercises the legacy-vs-canonical path, not a no-op rewrite).
    const rewrittenKnownSignersRaw = JSON.parse(
      await readFile(join(bundleBC, "artifacts/known_signers.json"), "utf8")
    ) as { signers: KnownSignersEntry[] };
    expect(rewrittenKnownSignersRaw.signers[0]!.did).not.toBe(aDid);
    expect(rewrittenKnownSignersRaw.signers[0]!.did).toBe(legacyADid);

    const verifiedBC = await verifyExitBundle(bundleBC);
    expect(verifiedBC.passed).toBe(true);
    expect(verifiedBC.reputation?.unverifiable_attestations).toBe(0);

    const fortressC = await makeHarness();
    const cIdentityId = await createIdentity(fortressC, "legacy-c");
    const importedBC = await importInto(fortressC, cIdentityId, bundleBC);
    expect(importedBC.activated).toBe(true);
    expect(importedBC.reputation.imported_attestations).toBe(1);
    expect(importedBC.reputation.unverifiable_attestations).toBe(0);
  });

    it("LOW (re-gate on #1303, item 2): a KnownSignersQuotaError during import rolls the WHOLE activation back (reputation attestations included), surfacing as ACTIVATION_FAILED_AND_CLEANED", async () => {
    const fortressA = await makeHarness();
    const aIdentityId = await createIdentity(fortressA, "quota-a");
    await recordAttestation(fortressA, aIdentityId, "quota-ix-a1", "quota-ctx");
    const bundleAB = await newBundleDir("sanctuary-known-signers-quota-ab-");
    await exportBundle(fortressA, bundleAB);

    const fortressB = await makeHarness();
    const bIdentityId = await createIdentity(fortressB, "quota-b");
    // A cap of 0 means ANY net-new known-signer entry is refused - A's key
    // is always net-new to a fresh B, so this deterministically trips the
    // quota gate on B's very first import.
    const cappedKnownSignersStore = new KnownSignersStore(
      fortressB.storage,
      fortressB.masterKey,
      { maxKnownSigners: 0 }
    );
    const beforeSnapshot = await snapshotAll(fortressB.storage);

    // F3 (Codex re-gate 2 on #1303, 2026-08-23): the known_signers capacity
    // preflight (`wouldExceedCapacity`) now runs BEFORE
    // `ReputationStore.importBundle` even starts (see bundle.ts - the
    // preflight was reordered ahead of the reputation write for exactly
    // this reason, addendum HIGH on #1303). This is a counting assertion,
    // not a snapshot-only one, so it distinguishes that ordering from a
    // "write-then-roll-back" outcome that would look identical in the
    // BEFORE/AFTER snapshot alone: it proves zero `_reputation` writes were
    // ever attempted, not merely that any that happened were undone.
    let reputationWriteCount = 0;
    const originalWrite = fortressB.storage.write.bind(fortressB.storage);
    fortressB.storage.write = async (namespace, key, data) => {
      if (namespace === "_reputation") reputationWriteCount++;
      return originalWrite(namespace, key, data);
    };

    let thrown: unknown;
    try {
      await importExitBundle({
        bundleDir: bundleAB,
        storage: fortressB.storage,
        masterKey: fortressB.masterKey,
        identityManager: fortressB.identityManager,
        auditLog: fortressB.auditLog,
        reputationStore: fortressB.reputationStore,
        knownSignersStore: cappedKnownSignersStore,
        activate: true,
        forceRebind: true,
        destinationSignerIdentityId: bIdentityId,
      });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(ExitBundleImportError);
    expect((thrown as ExitBundleImportError).code).toBe(
      "ACTIVATION_FAILED_AND_CLEANED"
    );

    // The known_signers capacity preflight refuses the WHOLE activation
    // before `_reputation` (or `_known_signers`) is ever written - not a
    // partial write rolled back afterward. Both the counting assertion
    // above (preflight-first) and this byte-identical snapshot (nothing
    // observable changed either way) hold, and together they are stronger
    // than either alone.
    expect(reputationWriteCount).toBe(0);
    const afterSnapshot = await snapshotAll(fortressB.storage);
    expect(afterSnapshot).toBe(beforeSnapshot);
  });

    it("independent gate item 4: a four-hop chain (A -> B -> C -> D) keeps known_signers COUNTS exact - no duplication, no loss, across repeated re-export", async () => {
    const fortressA = await makeHarness();
    const aIdentityId = await createIdentity(fortressA, "chain-a");
    await recordAttestation(fortressA, aIdentityId, "chain-ix-a1", "chain-ctx");
    const aDid = fortressA.identityManager.getDefault()?.did;
    if (!aDid) throw new Error("missing A did");

    const bundleAB = await newBundleDir("sanctuary-known-signers-chain-ab-");
    await exportBundle(fortressA, bundleAB);

    const fortressB = await makeHarness();
    const bIdentityId = await createIdentity(fortressB, "chain-b");
    const importedAB = await importInto(fortressB, bIdentityId, bundleAB);
    expect(importedAB.activated).toBe(true);
    expect((await fortressB.storage.list("_known_signers")).length).toBe(1);

    const bundleBC = await newBundleDir("sanctuary-known-signers-chain-bc-");
    const exportedBC = await exportBundle(fortressB, bundleBC);
    const knownSignersBC = JSON.parse(
      await readFile(join(bundleBC, "artifacts/known_signers.json"), "utf8")
    ) as { signers: KnownSignersEntry[] };
    // Exactly ONE entry (A) - not duplicated, and B's own DID never appears
    // (INVARIANT: the table can never introduce a signer for the exporting
    // fortress's own DID).
    expect(knownSignersBC.signers).toHaveLength(1);
    expect(knownSignersBC.signers[0]!.did).toBe(aDid);
    expect(exportedBC.manifest.body.artifacts.map((a) => a.kind)).toContain(
      "known_signers"
    );

    const fortressC = await makeHarness();
    const cIdentityId = await createIdentity(fortressC, "chain-c");
    const importedBC = await importInto(fortressC, cIdentityId, bundleBC);
    expect(importedBC.activated).toBe(true);
    expect(importedBC.reputation.imported_attestations).toBe(1);
    expect(importedBC.reputation.unverifiable_attestations).toBe(0);
    // C now persists A's key too (learned via B's known_signers table),
    // still exactly one net-new entry - never duplicated across hops.
    expect((await fortressC.storage.list("_known_signers")).length).toBe(1);

    const bundleCD = await newBundleDir("sanctuary-known-signers-chain-cd-");
    const exportedCD = await exportBundle(fortressC, bundleCD);
    const knownSignersCD = JSON.parse(
      await readFile(join(bundleCD, "artifacts/known_signers.json"), "utf8")
    ) as { signers: KnownSignersEntry[] };
    // Still exactly ONE entry after a THIRD hop - the table does not grow
    // with hop count, only with the number of DISTINCT foreign signers ever
    // actually admitted (here, always just A).
    expect(knownSignersCD.signers).toHaveLength(1);
    expect(knownSignersCD.signers[0]!.did).toBe(aDid);

    const verifiedCD = await verifyExitBundle(bundleCD);
    expect(verifiedCD.passed).toBe(true);
    expect(verifiedCD.reputation?.attestation_count).toBe(1);
    expect(verifiedCD.reputation?.verified_attestations).toBe(1);
    expect(verifiedCD.reputation?.unverifiable_attestations).toBe(0);

    const fortressD = await makeHarness();
    const dIdentityId = await createIdentity(fortressD, "chain-d");
    const importedCD = await importInto(fortressD, dIdentityId, bundleCD);
    expect(importedCD.activated).toBe(true);
    expect(importedCD.reputation.imported_attestations).toBe(1);
    expect(importedCD.reputation.unverifiable_attestations).toBe(0);
    expect(importedCD.reputation.invalid_attestations).toBe(0);
    expect((await fortressD.storage.list("_known_signers")).length).toBe(1);
  });

  /**
   * Independent gate on #1303 (2026-08-23), items 5/6: every refusal
   * fixture below is driven through the SAME shape - build a legitimate
   * B->C bundle, corrupt its known_signers table one way, and assert ALL
   * FOUR of: verify reports FAIL with failure_class "known_signers_invalid"
   * (never a soft warning, never a different failure_class); import THROWS
   * a typed ExitBundleImportError with code "KNOWN_SIGNERS_INVALID"; C's
   * storage is BYTE-IDENTICAL before and after the refused import attempt
   * (MEDIUM-5: zero staging writes, not merely zero successful writes);
   * and the pre-corruption bundle (proving the harness itself is sound)
   * verifies and imports cleanly. Each case names the ONE corruption it
   * applies.
   */
  const refusalCases: Array<{
    name: string;
    corrupt: (
      parsed: { version: number; signers: KnownSignersEntry[]; signature: string },
      ctx: { bIdentity: { did: string; public_key: string } }
    ) => { version: number; signers: KnownSignersEntry[]; signature: string };
    resignWith: "b" | "forger";
  }> = [
    {
      name: "a malformed element (undecodable public_key)",
      corrupt: (parsed) => ({
        ...parsed,
        signers: parsed.signers.map((entry) => ({
          ...entry,
          public_key: "not-a-valid-base64url-key",
        })),
      }),
      resignWith: "b",
    },
    {
      name: "a duplicate DID with two conflicting keys",
      corrupt: (parsed, ctx) => ({
        ...parsed,
        signers: [
          ...parsed.signers,
          {
            did: parsed.signers[0]!.did,
            public_key: ctx.bIdentity.public_key,
          },
        ],
      }),
      resignWith: "b",
    },
    {
      name: "a table signed by an identity other than the bundle's own exporter",
      corrupt: (parsed) => parsed,
      resignWith: "forger",
    },
    {
      name: "an entry naming the exporting fortress's own DID (own-DID entry, HIGH item 6: rejected, not merely skipped)",
      corrupt: (parsed, ctx) => ({
        ...parsed,
        signers: [
          ...parsed.signers,
          {
            did: ctx.bIdentity.did,
            public_key: ctx.bIdentity.public_key,
          },
        ],
      }),
      resignWith: "b",
    },
  ];

  for (const refusalCase of refusalCases) {
    it(`refuses closed on ${refusalCase.name}: verify FAILS (known_signers_invalid), import THROWS, zero staging writes`, async () => {
      const fortressA = await makeHarness();
      const aIdentityId = await createIdentity(fortressA, "ref-a");
      await recordAttestation(fortressA, aIdentityId, "ref-ix-a1", "ref-ctx");
      const bundleAB = await newBundleDir("sanctuary-known-signers-ref-ab-");
      await exportBundle(fortressA, bundleAB);
      const fortressB = await makeHarness();
      const bIdentityId = await createIdentity(fortressB, "ref-b");
      const importedAB = await importInto(fortressB, bIdentityId, bundleAB);
      // Sanity: the harness setup itself must succeed before this fixture's
      // OWN corruption is applied, or a later refusal would be meaningless.
      expect(importedAB.activated).toBe(true);
      const bIdentity = fortressB.identityManager.getDefault();
      if (!bIdentity) throw new Error("missing B identity");

      const bundleBC = await newBundleDir("sanctuary-known-signers-ref-bc-");
      await exportBundle(fortressB, bundleBC);

      let resigner = fortressB;
      if (refusalCase.resignWith === "forger") {
        const forger = await makeHarness();
        await createIdentity(forger, "ref-forger");
        resigner = forger;
      }
      await rewriteKnownSigners(
        bundleBC,
        fortressB,
        (parsed) => refusalCase.corrupt(parsed, { bIdentity }),
        resigner
      );

      const verifiedBC = await verifyExitBundle(bundleBC);
      expect(verifiedBC.passed).toBe(false);
      expect(verifiedBC.failure_class).toBe("known_signers_invalid");
      expect(
        verifiedBC.warnings.some((w) => w.includes("known_signers table could not be trusted"))
      ).toBe(true);

      const fortressC = await makeHarness();
      const cIdentityId = await createIdentity(fortressC, "ref-c");
      const cStorage = fortressC.storage;
      const beforeSnapshot = await snapshotAll(cStorage);

      let thrown: unknown;
      try {
        await importInto(fortressC, cIdentityId, bundleBC);
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(ExitBundleImportError);
      expect((thrown as ExitBundleImportError).code).toBe("KNOWN_SIGNERS_INVALID");

      const afterSnapshot = await snapshotAll(cStorage);
      expect(afterSnapshot).toBe(beforeSnapshot);
    });
  }

  it("an entry whose key does not derive its declared DID is refused as a whole-table failure, even when that DID matches a real attestation signer field (private register EXIT-KS-01)", async () => {
    const fortressA = await makeHarness();
    const aIdentityId = await createIdentity(fortressA, "sub-a");
    await recordAttestation(fortressA, aIdentityId, "sub-ix-a1", "sub-ctx");
    const bundleAB = await newBundleDir("sanctuary-known-signers-sub-ab-");
    await exportBundle(fortressA, bundleAB);
    const aDid = fortressA.identityManager.getDefault()?.did;
    if (!aDid) throw new Error("missing A did");

    const fortressB = await makeHarness();
    const bIdentityId = await createIdentity(fortressB, "sub-b");
    await importInto(fortressB, bIdentityId, bundleAB);
    // B's own attestation supplies the fixture signature reused below - the
    // signature covers only `attestation.data`, never the top-level
    // `signer` field.
    await recordAttestation(fortressB, bIdentityId, "sub-ix-b1", "sub-ctx");
    const bIdentity = fortressB.identityManager.getDefault();
    if (!bIdentity) throw new Error("missing B identity");

    const bundleBC = await newBundleDir("sanctuary-known-signers-sub-bc-");
    await exportBundle(fortressB, bundleBC);

    // Fixture: same signature and data, a differently-claimed signer.
    const reputationPath = join(bundleBC, "artifacts/reputation_bundle.json");
    const reputationRaw = JSON.parse(await readFile(reputationPath, "utf8")) as {
      attestations: Array<{ signer: string; data: { participant_did: string } }>;
    };
    let forged = false;
    reputationRaw.attestations = reputationRaw.attestations.map((attestation) => {
      if (attestation.data.participant_did === bIdentity.did && !forged) {
        forged = true;
        return { ...attestation, signer: aDid };
      }
      return attestation;
    });
    expect(forged).toBe(true);
    const reputationBytes = stringToBytes(JSON.stringify(reputationRaw, null, 2) + "\n");
    await writeFile(reputationPath, reputationBytes);
    await updateArtifactHashAndSize(bundleBC, "reputation_bundle", reputationBytes);
    await resignManifest(bundleBC, fortressB);

    // Fixture: known_signers claims A's DID resolves to B's own key.
    await rewriteKnownSigners(
      bundleBC,
      fortressB,
      (parsed) => ({
        ...parsed,
        signers: [
          { did: aDid, public_key: bIdentity.public_key },
          ...parsed.signers.filter((entry) => entry.did !== aDid),
        ],
      }),
      fortressB
    );

    // The fixture entry's public_key does not derive DID `aDid` under
    // publicKeyToDid, so the table is structurally refused before its
    // signature is even checked (checkKnownSignersStructure).
    expect(publicKeyToDid(fromBase64url(bIdentity.public_key))).not.toBe(aDid);

    const verifiedBC = await verifyExitBundle(bundleBC);
    expect(verifiedBC.passed).toBe(false);
    expect(verifiedBC.failure_class).toBe("known_signers_invalid");

    const fortressC = await makeHarness();
    const cIdentityId = await createIdentity(fortressC, "sub-c");
    const cStorage = fortressC.storage;
    const beforeSnapshot = await snapshotAll(cStorage);

    let thrown: unknown;
    try {
      await importInto(fortressC, cIdentityId, bundleBC);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(ExitBundleImportError);
    expect((thrown as ExitBundleImportError).code).toBe("KNOWN_SIGNERS_INVALID");

    const afterSnapshot = await snapshotAll(cStorage);
    expect(afterSnapshot).toBe(beforeSnapshot);
  });

  it("a malformed-length signature (1 byte, still valid base64url) is refused as known_signers_invalid, never an uncaught exception (Codex re-gate 2 on #1303, item 2)", async () => {
    const fortressA = await makeHarness();
    const aIdentityId = await createIdentity(fortressA, "sig-a");
    await recordAttestation(fortressA, aIdentityId, "sig-ix-a1", "sig-ctx");
    const bundleAB = await newBundleDir("sanctuary-known-signers-sig-ab-");
    await exportBundle(fortressA, bundleAB);
    const fortressB = await makeHarness();
    const bIdentityId = await createIdentity(fortressB, "sig-b");
    const importedAB = await importInto(fortressB, bIdentityId, bundleAB);
    expect(importedAB.activated).toBe(true);

    const bundleBC = await newBundleDir("sanctuary-known-signers-sig-bc-");
    await exportBundle(fortressB, bundleBC);
    // Deliberately NOT passing a `resignWith` identity - a real signer
    // would never produce a 1-byte signature, so this fixture writes the
    // malformed bytes directly and leaves them unsigned-over, exercising
    // the raw decode-and-verify path exactly as a corrupted-on-disk or
    // truncated-in-transit artifact would arrive.
    await rewriteKnownSigners(bundleBC, fortressB, (parsed) => ({
      ...parsed,
      signature: toBase64url(new Uint8Array([7])),
    }));

    // Noble's ed25519.verify throws on a malformed-length signature rather
    // than returning false; verify must still report the typed failure
    // class, not propagate an uncaught exception to its caller.
    const verifiedBC = await verifyExitBundle(bundleBC);
    expect(verifiedBC.passed).toBe(false);
    expect(verifiedBC.failure_class).toBe("known_signers_invalid");

    const fortressC = await makeHarness();
    const cIdentityId = await createIdentity(fortressC, "sig-c");
    const cStorage = fortressC.storage;
    const beforeSnapshot = await snapshotAll(cStorage);

    let thrown: unknown;
    try {
      await importInto(fortressC, cIdentityId, bundleBC);
    } catch (err) {
      thrown = err;
    }
    // Same requirement on the import path: a typed ExitBundleImportError,
    // never the raw exception escaping from resolveKnownSigners.
    expect(thrown).toBeInstanceOf(ExitBundleImportError);
    expect((thrown as ExitBundleImportError).code).toBe("KNOWN_SIGNERS_INVALID");

    const afterSnapshot = await snapshotAll(cStorage);
    expect(afterSnapshot).toBe(beforeSnapshot);
  });

  it("MEDIUM (re-gate on #1303): an oversized signers array is refused by COUNT before any element is touched", () => {
    // A Proxy over a length-only array: every index access increments a
    // counter, so this proves checkKnownSignersStructure's count cap fires
    // BEFORE the per-element loop even starts - not merely that it
    // eventually refuses. `length` itself is read freely (Array.isArray
    // and the cap comparison both need it).
    let elementAccesses = 0;
    const oversized = new Proxy(
      new Array(MAX_KNOWN_SIGNERS + 1) as unknown[],
      {
        get(target, prop, receiver) {
          if (typeof prop === "string" && /^\d+$/.test(prop)) {
            elementAccesses++;
          }
          return Reflect.get(target, prop, receiver);
        },
      }
    );
    const result = checkKnownSignersStructure({
      version: 1,
      signers: oversized as unknown as KnownSignersEntry[],
    });
    expect(result).toMatchObject({ ok: false, problem: "signers_too_many" });
    expect(elementAccesses).toBe(0);
  });

  it("MEDIUM (re-gate on #1303): a known_signers artifact whose manifest-declared size exceeds the cap is refused WITHOUT reading the file", () => {
    const manifest = {
      body: {
        artifacts: [
          {
            kind: "known_signers",
            path: "artifacts/known_signers.json",
            hash_alg: "sha256",
            hash: "0".repeat(64),
            size_bytes: MAX_KNOWN_SIGNERS * 300 + 1,
          },
        ],
      },
    } as unknown as ExitBundleManifest;
    expect(isKnownSignersArtifactSizeAcceptable(manifest)).toBe(false);

    const acceptableManifest = {
      body: {
        artifacts: [
          {
            kind: "known_signers",
            path: "artifacts/known_signers.json",
            hash_alg: "sha256",
            hash: "0".repeat(64),
            size_bytes: 4096,
          },
        ],
      },
    } as unknown as ExitBundleManifest;
    expect(isKnownSignersArtifactSizeAcceptable(acceptableManifest)).toBe(true);

    // Absent entirely (an old, pre-this-change bundle) - accepted, matching
    // the version gate.
    const absentManifest = {
      body: { artifacts: [] },
    } as unknown as ExitBundleManifest;
    expect(isKnownSignersArtifactSizeAcceptable(absentManifest)).toBe(true);
  });
});
