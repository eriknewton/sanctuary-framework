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
 * This file drives the drill-shaped positive case (A -> B -> C, the exact
 * shape the drill found broken) plus the version gate and the four refusal
 * fixtures named in the build brief: a bundle with no known_signers
 * artifact at all still verifies exactly as before this change; a
 * malformed table element; a table with two conflicting keys for one DID;
 * and a table signed by an identity other than the bundle's own exporter.
 * All four refusal fixtures resolve to ZERO trusted signers from the table
 * (fail closed), never a partial admission - the affected attestation
 * stays `unverifiable` through the SAME existing accounting a bundle with
 * no known_signers artifact at all would produce.
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
import {
  exportExitBundle,
  importExitBundle,
  type ExportExitBundleResult,
} from "../../src/exit/index.js";
import {
  verifyExitBundle,
  knownSignersSigningBytes,
  type KnownSignersEntry,
} from "../../src/exit/verifier.js";
import type { ExitBundleManifest } from "../../src/contracts/v1.1/exit-bundle-manifest.js";

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
  kind: "known_signers",
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
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
  await resignManifest(bundleDir, manifestSigner);
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

  it("a malformed known_signers element resolves to zero trusted signers; the affected attestation stays unverifiable and the bundle fails closed", async () => {
    const fortressA = await makeHarness();
    const aIdentityId = await createIdentity(fortressA, "mal-a");
    await recordAttestation(fortressA, aIdentityId, "mal-ix-a1", "mal-ctx");
    const bundleAB = await newBundleDir("sanctuary-known-signers-mal-ab-");
    await exportBundle(fortressA, bundleAB);
    const fortressB = await makeHarness();
    const bIdentityId = await createIdentity(fortressB, "mal-b");
    await importInto(fortressB, bIdentityId, bundleAB);

    const bundleBC = await newBundleDir("sanctuary-known-signers-mal-bc-");
    await exportBundle(fortressB, bundleBC);
    await rewriteKnownSigners(
      bundleBC,
      fortressB,
      (parsed) => ({
        ...parsed,
        signers: parsed.signers.map((entry) => ({
          ...entry,
          public_key: "not-a-valid-base64url-key",
        })),
      }),
      fortressB
    );

    const verifiedBC = await verifyExitBundle(bundleBC);
    expect(verifiedBC.passed).toBe(false);
    expect(verifiedBC.failure_class).toBe("reputation_unverifiable_attestations");
    expect(verifiedBC.reputation?.unverifiable_attestations).toBe(1);
    expect(
      verifiedBC.warnings.some((w) => w.includes("known_signers table could not be trusted"))
    ).toBe(true);

    const fortressC = await makeHarness();
    const cIdentityId = await createIdentity(fortressC, "mal-c");
    const importedBC = await importInto(fortressC, cIdentityId, bundleBC);
    expect(importedBC.activated).toBe(false);
    expect(importedBC.reputation.imported_attestations).toBe(0);
  });

  it("a known_signers table with two conflicting keys for one DID resolves to zero trusted signers", async () => {
    const fortressA = await makeHarness();
    const aIdentityId = await createIdentity(fortressA, "dup-a");
    await recordAttestation(fortressA, aIdentityId, "dup-ix-a1", "dup-ctx");
    const bundleAB = await newBundleDir("sanctuary-known-signers-dup-ab-");
    await exportBundle(fortressA, bundleAB);
    const fortressB = await makeHarness();
    const bIdentityId = await createIdentity(fortressB, "dup-b");
    await importInto(fortressB, bIdentityId, bundleAB);

    const bundleBC = await newBundleDir("sanctuary-known-signers-dup-bc-");
    await exportBundle(fortressB, bundleBC);
    // A second, differently-keyed entry for the SAME DID as the existing
    // (legitimate) entry - the conflicting-DID shape rule 11 rules out.
    const bIdentity = fortressB.identityManager.getDefault();
    if (!bIdentity) throw new Error("missing B identity");
    await rewriteKnownSigners(
      bundleBC,
      fortressB,
      (parsed) => ({
        ...parsed,
        signers: [
          ...parsed.signers,
          {
            did: parsed.signers[0]!.did,
            public_key: bIdentity.public_key,
            first_seen_import_id: parsed.signers[0]!.first_seen_import_id,
          },
        ],
      }),
      fortressB
    );

    const verifiedBC = await verifyExitBundle(bundleBC);
    expect(verifiedBC.passed).toBe(false);
    expect(verifiedBC.failure_class).toBe("reputation_unverifiable_attestations");
    expect(verifiedBC.reputation?.unverifiable_attestations).toBe(1);

    const fortressC = await makeHarness();
    const cIdentityId = await createIdentity(fortressC, "dup-c");
    const importedBC = await importInto(fortressC, cIdentityId, bundleBC);
    expect(importedBC.activated).toBe(false);
  });

  it("a known_signers table signed by an identity other than the bundle's own exporter resolves to zero trusted signers", async () => {
    const fortressA = await makeHarness();
    const aIdentityId = await createIdentity(fortressA, "wrong-a");
    await recordAttestation(fortressA, aIdentityId, "wrong-ix-a1", "wrong-ctx");
    const bundleAB = await newBundleDir("sanctuary-known-signers-wrong-ab-");
    await exportBundle(fortressA, bundleAB);
    const fortressB = await makeHarness();
    const bIdentityId = await createIdentity(fortressB, "wrong-b");
    await importInto(fortressB, bIdentityId, bundleAB);

    const bundleBC = await newBundleDir("sanctuary-known-signers-wrong-bc-");
    await exportBundle(fortressB, bundleBC);
    // An unrelated third identity signs the table instead of B (the
    // bundle's actual, manifest-bound exporter).
    const forger = await makeHarness();
    await createIdentity(forger, "wrong-forger");
    await rewriteKnownSigners(
      bundleBC,
      fortressB,
      (parsed) => parsed,
      forger
    );

    const verifiedBC = await verifyExitBundle(bundleBC);
    expect(verifiedBC.passed).toBe(false);
    expect(verifiedBC.failure_class).toBe("reputation_unverifiable_attestations");
    expect(verifiedBC.reputation?.unverifiable_attestations).toBe(1);

    const fortressC = await makeHarness();
    const cIdentityId = await createIdentity(fortressC, "wrong-c");
    const importedBC = await importInto(fortressC, cIdentityId, bundleBC);
    expect(importedBC.activated).toBe(false);
  });
});
