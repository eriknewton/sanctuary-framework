/**
 * LD2-01: the class-level fix, not the fourth one-instance patch.
 *
 * Three prior instances of the SAME shape ("`sanctuary exit verify` reports
 * PASS while `sanctuary exit import` fails closed on the identical bundle")
 * were each closed one at a time, by adding one more named boolean to a
 * hand-written `&&` chain in `verifyExitBundle`'s `passed` computation:
 *
 *   - rotation-chain invalid (#1189)
 *   - reputation-bundle signature unverifiable (#1194)
 *   - encrypted_state entries unreadable (this file's trigger, LD2-01)
 *
 * Each fix closed its own instance and left the SHAPE open: a fourth
 * dimension the verifier learns to classify, and nobody remembers to fold
 * into `passed`, reproduces the exact same bug. `server/src/exit/verifier.ts`
 * now derives `passed` from a `Record` keyed over the entire
 * `ExitBundleFailureClass` union (see the CLASS-LEVEL AGGREGATOR comment
 * there), so omitting a member is a compile error; this file is the
 * differential that HOLDS that structure, by driving every structural
 * damage/invalidity the verifier can classify through both a real
 * `verifyExitBundle` and a real `importExitBundle` and asserting the
 * invariant directly:
 *
 *   if verify reports `passed: true`, import must never fail CLOSED for a
 *   STRUCTURAL reason (it may still refuse for a missing-credential reason
 *   the operator can act on, but never crash, and never a bare "not
 *   verified" with no named cause).
 *
 * Two rows below (malformed `source_custody` / malformed
 * `legacy_kdf_params`, both with a READABLE entries list) are the
 * DELIBERATE exception the CRITICAL SCOPING note in verifier.ts is about:
 * they stay verify-PASS on purpose, and import refuses them with a named,
 * actionable credential error, never a crash. Each such row says so in its
 * own comment; the shared assertion helper below enforces that a PASS bundle
 * can ONLY reach that outcome or full activation, never a silent refusal.
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
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
import {
  buildReputationCompletenessManifest,
  reputationBundleSigningBytes,
  type ReputationBundle,
} from "../../src/reputation/reputation-store.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { defaultConfig } from "../../src/config.js";
import {
  exportExitBundle,
  importExitBundle,
  ExitBundleImportError,
  type ExportExitBundleResult,
  type ImportExitBundleResult,
} from "../../src/exit/index.js";
// `encryptedStateSubVerdictFailed` is module-internal to verifier.ts (not
// re-exported from the package barrel; see the comment in
// src/exit/index.ts), so this file imports it directly, same as several
// sibling exit tests import straight from bundle.ts.
import {
  verifyExitBundle,
  encryptedStateSubVerdictFailed,
} from "../../src/exit/verifier.js";
import type { ExitBundleArtifactEntry } from "../../src/contracts/v1.1/exit-bundle-manifest.js";

const SOURCE_PASSPHRASE = "correct horse battery aggregator";

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

/** A source fortress with one identity, one state entry, one attestation. */
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
 * Rewrite an artifact identified by KIND and re-sign the manifest so the
 * bundle verifies again (hash + aggregate hash + fortress-master signature).
 * Does NOT re-sign the artifact's OWN inner signature (`public_identity`'s
 * `signature` field, `reputation_bundle`'s `bundle_signature`) - callers that
 * want the inner signature to stay valid must set it themselves inside
 * `mutate`; callers that want it to go INVALID (identity_signature_invalid,
 * bundle-sig unverifiable) simply leave it alone or corrupt it directly.
 *
 * FAILURE MODE if done wrong: forgetting the aggregate hash or size field
 * leaves a bundle that fails verification for the WRONG reason (a hash
 * mismatch, not the intended structural defect), and the test would pass
 * while proving nothing about the intended row.
 */
async function tamperArtifactAndResign(
  bundleDir: string,
  source: Harness,
  kind: ExitBundleArtifactEntry["kind"],
  mutate: (artifact: Record<string, unknown>) => Record<string, unknown>
): Promise<void> {
  const manifestPath = join(bundleDir, "manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
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
  const entry = manifest.body.artifacts.find((artifact) => artifact.kind === kind);
  if (!entry) {
    throw new Error(`tamperArtifactAndResign: no artifact of kind ${kind}`);
  }
  const artifactPath = join(bundleDir, entry.path);
  const parsed = JSON.parse(await readFile(artifactPath, "utf8")) as Record<
    string,
    unknown
  >;
  const tampered = mutate(parsed);
  const newBytes = stringToBytes(JSON.stringify(tampered, null, 2) + "\n");
  await writeFile(artifactPath, newBytes);
  entry.hash = sha256Hex(newBytes);
  entry.size_bytes = newBytes.length;
  manifest.body.artifacts_aggregate_hash = sha256Hex(
    stringToBytes(canonicalize(manifest.body.artifacts))
  );
  const identity = source.identityManager.getDefault();
  if (!identity) throw new Error("tamperArtifactAndResign: no default identity");
  manifest.signature = toBase64url(
    identitySign(
      canonicalizeToBytes(manifest.body),
      identity.encrypted_private_key,
      derivePurposeKey(source.masterKey, "identity-encryption")
    )
  );
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
}

/** Same shape as `tamperArtifactAndResign`, for `encrypted_state`. */
async function patchEncryptedStateAndResign(
  bundleDir: string,
  source: Harness,
  mutate: (artifact: Record<string, unknown>) => void
): Promise<void> {
  await tamperArtifactAndResign(bundleDir, source, "encrypted_state", (artifact) => {
    mutate(artifact);
    return artifact;
  });
}

/**
 * Mutate `public_identity`'s `bundle` (e.g. `rotation_history`) and
 * RE-SIGN the artifact's own inner signature over the mutated bundle, so the
 * identity artifact's signature itself stays valid - isolating a rotation-
 * chain defect from an identity-signature defect. Use `tamperArtifactAndResign`
 * directly (leaving the inner signature stale) when the identity SIGNATURE
 * itself is the thing under test.
 */
async function tamperPublicIdentityBundleAndResignInner(
  bundleDir: string,
  source: Harness,
  mutateBundle: (bundle: Record<string, unknown>) => void
): Promise<void> {
  const identity = source.identityManager.getDefault();
  if (!identity) throw new Error("tamperPublicIdentityBundleAndResignInner: no default identity");
  await tamperArtifactAndResign(bundleDir, source, "public_identity", (artifact) => {
    const bundle = { ...(artifact.bundle as Record<string, unknown>) };
    mutateBundle(bundle);
    return {
      ...artifact,
      bundle,
      signature: toBase64url(
        identitySign(
          canonicalizeToBytes(bundle),
          identity.encrypted_private_key,
          derivePurposeKey(source.masterKey, "identity-encryption")
        )
      ),
    };
  });
}

/** Sign a reputation bundle's outer `bundle_signature` over BODY (attestations
 * + completeness_manifest), for callers that mutated the body and need the
 * inner signature to stay internally valid.
 */
function signReputationBody(
  source: Harness,
  body: {
    version: "SANCTUARY_REP_V1";
    attestations: ReputationBundle["attestations"];
    exported_at: string;
    exporter_did: string;
    completeness_manifest?: ReputationBundle["completeness_manifest"];
  }
): string {
  const identity = source.identityManager.getDefault();
  if (!identity) throw new Error("signReputationBody: no default identity");
  return toBase64url(
    identitySign(
      reputationBundleSigningBytes(body),
      identity.encrypted_private_key,
      derivePurposeKey(source.masterKey, "identity-encryption")
    )
  );
}

/**
 * Mutate a `reputation_bundle` artifact's SIGNED BODY (attestations and/or
 * completeness_manifest) and re-sign both the inner `bundle_signature` (over
 * the mutated body) and the outer manifest, so the bundle stays internally
 * consistent except for the defect the caller is deliberately introducing.
 * Use this when the COMPLETENESS or ATTESTATION content is the thing under
 * test, as opposed to `tamperArtifactAndResign` directly (leaves
 * `bundle_signature` stale) when the bundle-level SIGNATURE itself is the
 * thing under test.
 */
async function tamperReputationBundleAndResignInner(
  bundleDir: string,
  source: Harness,
  mutate: (bundle: ReputationBundle) => ReputationBundle
): Promise<void> {
  await tamperArtifactAndResign(bundleDir, source, "reputation_bundle", (artifact) => {
    const mutated = mutate(artifact as unknown as ReputationBundle);
    return {
      ...mutated,
      bundle_signature: signReputationBody(source, mutated),
    } as unknown as Record<string, unknown>;
  });
}

/**
 * Replace an artifact's RAW BYTES (not a parsed-JSON mutation) and re-sign
 * the outer manifest to match. Needed for the null-JSON-root row (MUST-FIX 2
 * RECHECK): a bundle artifact whose content is the JSON literal `null`
 * cannot be produced by `tamperArtifactAndResign`, whose `mutate` callback
 * operates on an already-parsed `Record<string, unknown>` and so cannot
 * express a non-object root.
 */
async function writeArtifactRawBytesAndResign(
  bundleDir: string,
  source: Harness,
  kind: ExitBundleArtifactEntry["kind"],
  rawBytes: Uint8Array
): Promise<void> {
  const manifestPath = join(bundleDir, "manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
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
  const entry = manifest.body.artifacts.find((artifact) => artifact.kind === kind);
  if (!entry) {
    throw new Error(`writeArtifactRawBytesAndResign: no artifact of kind ${kind}`);
  }
  const artifactPath = join(bundleDir, entry.path);
  await writeFile(artifactPath, rawBytes);
  entry.hash = sha256Hex(rawBytes);
  entry.size_bytes = rawBytes.length;
  manifest.body.artifacts_aggregate_hash = sha256Hex(
    stringToBytes(canonicalize(manifest.body.artifacts))
  );
  const identity = source.identityManager.getDefault();
  if (!identity) throw new Error("writeArtifactRawBytesAndResign: no default identity");
  manifest.signature = toBase64url(
    identitySign(
      canonicalizeToBytes(manifest.body),
      identity.encrypted_private_key,
      derivePurposeKey(source.masterKey, "identity-encryption")
    )
  );
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
}

describe("exit verify/import parity aggregator (LD2-01 class fix)", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function newBundleDir(prefix = "sanctuary-exit-aggregator-"): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), prefix));
    tempDirs.push(dir);
    return dir;
  }

  type ExpectedOutcome =
    | { kind: "activates" }
    | { kind: "resolves-not-activated" }
    | {
        kind: "throws";
        code: string;
        // MUST-FIX 3 (fix round, 2026-08-10): every "throws" row DECLARES
        // which invariant it is proving, so the helper below can assert
        // `verified.passed` FROM this declaration directly, rather than
        // trusting that the row's separately-supplied `expectedVerifyPassed`
        // happens to agree with it. A row that mislabels a structural
        // rejection as verify-PASS is exactly the omission class this
        // differential exists to catch, and the previous shape (both values
        // hand-supplied, only implicitly required to agree) could not catch
        // itself being wrong.
        //   - "structural": the bundle is itself damaged/unverifiable, so
        //     import's throw is the SAME "verify PASS while import fails
        //     closed" shape LD2-01 closes; verify MUST have reported
        //     `passed: false` for it.
        //   - "credential-exempt": the two deliberate CRITICAL-SCOPING-note
        //     rows (malformed source_custody / legacy_kdf_params with
        //     READABLE entries) - the bundle is intact and stays
        //     verify-PASS by design, and import refuses only for an
        //     actionable credential reason, never a structural one.
        reason: "structural" | "credential-exempt";
      };

  /**
   * THE DIFFERENTIAL. Drives a real `verifyExitBundle` and a real
   * `importExitBundle` over the SAME bundle and asserts the class invariant
   * in both directions:
   *
   *  - `outcome: "activates"` requires `verifyPassed: true` (an activated
   *    import is never possible over a bundle verify failed).
   *  - `outcome: "throws"` requires import to fail with a NAMED
   *    `ExitBundleImportError`, proven with `toBeInstanceOf` - a bare
   *    TypeError (the LD2-01 crash shape) is NOT an instance of that class
   *    and fails this assertion, which is the whole point: this is what
   *    would have caught the crash before the fix, not just its symptom. It
   *    ALSO requires `verified.passed` to match `outcome.reason` exactly
   *    (see the `ExpectedOutcome` doc above): "import structural-reject <=>
   *    verify passed===false" is bound in BOTH directions here, not left to
   *    a per-row hand-supplied value.
   *  - `outcome: "resolves-not-activated"` requires `verifyPassed: false`:
   *    a PASS bundle may end in full activation or a NAMED credential
   *    refusal, but never a silent, unexplained "not activated" - that
   *    silent shape IS the bug this file exists to catch.
   */
  async function assertVerifyImportInvariant(
    bundleDir: string,
    expectedVerifyPassed: boolean,
    expectedFailureClass: string | undefined,
    runImport: () => Promise<ImportExitBundleResult>,
    outcome: ExpectedOutcome
  ): Promise<void> {
    const verified = await verifyExitBundle(bundleDir);
    expect(verified.passed).toBe(expectedVerifyPassed);
    expect(verified.failure_class).toBe(expectedFailureClass);

    if (outcome.kind === "activates") {
      expect(expectedVerifyPassed).toBe(true);
      const result = await runImport();
      expect(result.activated).toBe(true);
      return;
    }

    if (outcome.kind === "throws") {
      // MUST-FIX 3: mechanical, not merely a matching hand-supplied value -
      // a "structural" throw REQUIRES verify to have failed closed, and a
      // "credential-exempt" throw REQUIRES verify to have stayed PASS.
      expect(verified.passed).toBe(outcome.reason === "credential-exempt");
      let caught: unknown;
      try {
        await runImport();
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(ExitBundleImportError);
      expect((caught as ExitBundleImportError).code).toBe(outcome.code);
      return;
    }

    // outcome.kind === "resolves-not-activated"
    expect(expectedVerifyPassed).toBe(false);
    const result = await runImport();
    expect(result.activated).toBe(false);
  }

  it("control: a healthy bundle verifies PASS and activates cleanly", async () => {
    const source = await makeSource("aggregator-control-source");
    const bundleDir = await newBundleDir();
    const exported = await exportBundle(source, bundleDir, { mint: true });
    const destination = await makeDestination();

    await assertVerifyImportInvariant(
      bundleDir,
      true,
      undefined,
      () =>
        importExitBundle({
          bundleDir,
          storage: destination.storage,
          masterKey: destination.masterKey,
          identityManager: destination.identityManager,
          auditLog: destination.auditLog,
          reputationStore: destination.reputationStore,
          activate: true,
          forceRebind: true,
          sourceRecoveryKey: exported.state_rekey_key,
          destinationSignerIdentityId: destination.identityId,
        }),
      { kind: "activates" }
    );
  });

  it("an unreadable entries list fails verify closed, and import refuses with a NAMED error, never a crash", async () => {
    const source = await makeSource("aggregator-ld201-source");
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir, { mint: true });
    await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
      delete artifact.entries;
    });
    const destination = await makeDestination();

    // sourceMasterKey bypasses every credential-resolution branch
    // (resolveSourceMasterKey's own opts.sourceMasterKey shortcut) - proving
    // the fix holds even for the programmatic caller who already HOLDS the
    // key and would otherwise sail straight past every other check into the
    // bare `entries.length` dereference that used to crash here.
    await assertVerifyImportInvariant(
      bundleDir,
      false,
      "encrypted_state_entries_unreadable",
      () =>
        importExitBundle({
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
        }),
      { kind: "throws", code: "ENCRYPTED_STATE_ENTRIES_UNREADABLE", reason: "structural" }
    );
  });

  it("SCOPING PIN: malformed source_custody with READABLE entries stays verify-PASS; import refuses with the typed credential error", async () => {
    // The exempted case the CRITICAL SCOPING note in verifier.ts is about.
    // `declared_rekey_material === "damaged"` fires here too, but the
    // entries themselves ARE readable, so this bundle is NOT the LD2-01
    // shape - it is a signed, intact bundle whose bundle re-key path
    // specifically cannot run. Import already refused this before LD2-01
    // (SOURCE_CUSTODY_MALFORMED, `validateSourceCustody` in bundle.ts) and
    // must keep doing so; the aggregator must NOT start failing `passed` on
    // it, or a working, previously-PASS bundle regresses to FAIL.
    const source = await makeSource("aggregator-custody-source");
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir, { mint: true });
    await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
      const custody = artifact.source_custody as Record<string, unknown>;
      artifact.source_custody = { ...custody, format: "NOT_A_REAL_FORMAT" };
    });
    const destination = await makeDestination();

    // validateSourceCustody fires unconditionally whenever the block is
    // present, before any credential branch, so no source credential needs
    // to be supplied for the typed refusal to fire.
    await assertVerifyImportInvariant(
      bundleDir,
      true,
      undefined,
      () =>
        importExitBundle({
          bundleDir,
          storage: destination.storage,
          masterKey: destination.masterKey,
          identityManager: destination.identityManager,
          auditLog: destination.auditLog,
          reputationStore: destination.reputationStore,
          activate: true,
          forceRebind: true,
          destinationSignerIdentityId: destination.identityId,
        }),
      { kind: "throws", code: "SOURCE_CUSTODY_MALFORMED", reason: "credential-exempt" }
    );
  });

  it("SCOPING PIN: malformed legacy_kdf_params with READABLE entries stays verify-PASS; import refuses with the typed credential error", async () => {
    // The sibling exempted case: a migrated fortress's legacy
    // `_meta/key-params` marker is malformed, but the entries are readable.
    // Import refuses (SOURCE_KDF_PARAMS_MALFORMED) only once a passphrase is
    // actually offered - the bundle stays verify-PASS either way.
    const source = await makeSource("aggregator-kdf-source");
    const { params } = await deriveMasterKey(SOURCE_PASSPHRASE);
    await source.storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params))
    );
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir, { mint: false });
    await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
      artifact.source_key_derivation = { ...params, l: 64 };
    });
    const destination = await makeDestination();

    await assertVerifyImportInvariant(
      bundleDir,
      true,
      undefined,
      () =>
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
        }),
      { kind: "throws", code: "SOURCE_KDF_PARAMS_MALFORMED", reason: "credential-exempt" }
    );
  });

  it("rotation_chain_invalid (absorbed): verify FAILS closed, import refuses with ROTATION_CHAIN_UNVERIFIABLE", async () => {
    const source = await makeSource("aggregator-rotation-source");
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir);
    // A single hop whose `rotation_event` is not a signed rotation event at
    // all: the chain fails to verify, but the ARTIFACT's own signature (via
    // `tamperPublicIdentityBundleAndResignInner`) stays valid, isolating the
    // defect to the rotation chain rather than the identity signature.
    await tamperPublicIdentityBundleAndResignInner(bundleDir, source, (bundle) => {
      bundle.rotation_history = [
        {
          old_public_key: bundle.publicKey,
          new_public_key: bundle.publicKey,
          rotation_event: toBase64url(stringToBytes("not a signed event")),
          rotated_at: "2026-08-09T00:00:00.000Z",
        },
      ];
    });

    const destination = await makeDestination();
    await assertVerifyImportInvariant(
      bundleDir,
      false,
      "rotation_chain_invalid",
      () =>
        importExitBundle({
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
        }),
      { kind: "throws", code: "ROTATION_CHAIN_UNVERIFIABLE", reason: "structural" }
    );
  });

  it("identity_signature_invalid: verify FAILS closed, import resolves cleanly with activated:false (no throw, no crash)", async () => {
    const source = await makeSource("aggregator-identity-source");
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir);
    await tamperArtifactAndResign(bundleDir, source, "public_identity", (artifact) => ({
      ...artifact,
      signature: toBase64url(new Uint8Array(64)),
    }));

    const destination = await makeDestination();
    await assertVerifyImportInvariant(
      bundleDir,
      false,
      "identity_signature_invalid",
      () =>
        importExitBundle({
          bundleDir,
          storage: destination.storage,
          masterKey: destination.masterKey,
          identityManager: destination.identityManager,
          auditLog: destination.auditLog,
          reputationStore: destination.reputationStore,
          activate: true,
          forceRebind: true,
          destinationSignerIdentityId: destination.identityId,
        }),
      { kind: "resolves-not-activated" }
    );
  });

  it("reputation_bundle_signature_invalid (unverifiable exporter, absorbed): verify FAILS closed, import resolves cleanly", async () => {
    const source = await makeSource("aggregator-repbundle-source");
    await callTool(source.tools, "reputation_record", {
      interaction_id: "aggregator-unverifiable-bundle-001",
      counterparty_did: "did:key:counterparty",
      outcome: { type: "transaction", result: "completed", metrics: { score: 100 } },
      context: "aggregator-test",
      identity_id: source.identityId,
    });
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir);

    // Sanity: honest bundle PASSES with a positively-valid bundle signature.
    const honest = await verifyExitBundle(bundleDir);
    expect(honest.passed).toBe(true);
    expect(honest.reputation?.bundle_signature_valid).toBe(true);

    await tamperArtifactAndResign(bundleDir, source, "reputation_bundle", (artifact) => ({
      ...artifact,
      exporter_did: "did:key:z6MkNotAnIncludedExporterKey0000000000000000",
    }));

    const destination = await makeDestination();
    await assertVerifyImportInvariant(
      bundleDir,
      false,
      "reputation_bundle_signature_invalid",
      () =>
        importExitBundle({
          bundleDir,
          storage: destination.storage,
          masterKey: destination.masterKey,
          identityManager: destination.identityManager,
          auditLog: destination.auditLog,
          reputationStore: destination.reputationStore,
          activate: true,
          forceRebind: true,
          destinationSignerIdentityId: destination.identityId,
        }),
      { kind: "resolves-not-activated" }
    );
  });

  it("reputation_unverifiable_attestations (no opt-in): verify FAILS closed, import resolves cleanly (strict gate, no bypass)", async () => {
    const source = await makeSource("aggregator-unverifiable-att-source");
    const secondary = await callTool(source.tools, "identity_create", {
      label: "aggregator-secondary",
    });
    await callTool(source.tools, "reputation_record", {
      interaction_id: "aggregator-unverifiable-att-001",
      counterparty_did: "did:key:counterparty",
      outcome: { type: "transaction", result: "completed", metrics: { score: 100 } },
      context: "aggregator-test",
      identity_id: secondary.identity_id as string,
    });
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir);

    const destination = await makeDestination();
    await assertVerifyImportInvariant(
      bundleDir,
      false,
      "reputation_unverifiable_attestations",
      () =>
        importExitBundle({
          bundleDir,
          storage: destination.storage,
          masterKey: destination.masterKey,
          identityManager: destination.identityManager,
          auditLog: destination.auditLog,
          reputationStore: destination.reputationStore,
          activate: true,
          forceRebind: true,
          destinationSignerIdentityId: destination.identityId,
        }),
      { kind: "resolves-not-activated" }
    );
  });

  // ---- MUST-FIX 3 (fix round, 2026-08-10): the two rows the gate found ----
  // ---- missing from the differential's enumerated set ----

  it("reputation_completeness_mismatch (missing row): verify FAILS closed, import resolves cleanly (no throw, no crash)", async () => {
    const source = await makeSource("aggregator-completeness-source");
    await callTool(source.tools, "reputation_record", {
      interaction_id: "aggregator-completeness-001",
      counterparty_did: "did:key:counterparty",
      outcome: { type: "transaction", result: "completed", metrics: { score: 100 } },
      context: "aggregator-test",
      identity_id: source.identityId,
    });
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir);

    // Same shape as exit-bundle-hardening.test.ts's "rejects mismatched
    // reputation completeness": bump the signed total_attestation_count so
    // it disagrees with the actual attestations array, and re-sign the
    // bundle over the now-inconsistent body. `bundle_signature_valid` stays
    // true (the signature covers exactly what was signed); the recomputed
    // completeness manifest disagrees with it.
    await tamperReputationBundleAndResignInner(bundleDir, source, (bundle) => ({
      ...bundle,
      completeness_manifest: bundle.completeness_manifest
        ? {
            ...bundle.completeness_manifest,
            total_attestation_count: bundle.attestations.length + 1,
          }
        : bundle.completeness_manifest,
    }));

    const destination = await makeDestination();
    await assertVerifyImportInvariant(
      bundleDir,
      false,
      "reputation_completeness_mismatch",
      () =>
        importExitBundle({
          bundleDir,
          storage: destination.storage,
          masterKey: destination.masterKey,
          identityManager: destination.identityManager,
          auditLog: destination.auditLog,
          reputationStore: destination.reputationStore,
          activate: true,
          forceRebind: true,
          destinationSignerIdentityId: destination.identityId,
        }),
      { kind: "resolves-not-activated" }
    );
  });

  it("reputation_attestation_signature_invalid (missing row): verify FAILS closed, import resolves cleanly (no throw, no crash)", async () => {
    const source = await makeSource("aggregator-attsig-source");
    await callTool(source.tools, "reputation_record", {
      interaction_id: "aggregator-attsig-001",
      counterparty_did: "did:key:counterparty",
      outcome: { type: "transaction", result: "completed", metrics: { score: 100 } },
      context: "aggregator-test",
      identity_id: source.identityId,
    });
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir);

    // The signer (source's own identity) IS present in publicKeysByDid, so
    // this is `invalid_attestations`, not `unverifiable_attestations`:
    // mutate the signed DATA of one attestation without re-signing it, so
    // its own ed25519 signature no longer verifies. The completeness
    // manifest is recomputed from the SAME mutated attestations array, so it
    // still agrees with the (now-tampered) body - isolating the defect to
    // the attestation signature, not completeness (which outranks it in the
    // priority ladder and would otherwise mask this row).
    await tamperReputationBundleAndResignInner(bundleDir, source, (bundle) => {
      const attestations = bundle.attestations.map((attestation, index) =>
        index === 0
          ? {
              ...attestation,
              data: { ...attestation.data, metrics: { score: 0 } },
            }
          : attestation
      );
      return {
        ...bundle,
        attestations,
        completeness_manifest: bundle.completeness_manifest
          ? buildReputationCompletenessManifest(bundle.exported_at, attestations)
          : bundle.completeness_manifest,
      };
    });

    const destination = await makeDestination();
    await assertVerifyImportInvariant(
      bundleDir,
      false,
      "reputation_attestation_signature_invalid",
      () =>
        importExitBundle({
          bundleDir,
          storage: destination.storage,
          masterKey: destination.masterKey,
          identityManager: destination.identityManager,
          auditLog: destination.auditLog,
          reputationStore: destination.reputationStore,
          activate: true,
          forceRebind: true,
          destinationSignerIdentityId: destination.identityId,
        }),
      { kind: "resolves-not-activated" }
    );
  });

  it("encrypted_state artifact whose JSON root is not an object: verify FAILS closed, import throws the NAMED error, never a crash", async () => {
    const source = await makeSource("aggregator-nullroot-source");
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir, { mint: true });

    // The narrower LD2-01 row above deletes `entries` from an otherwise
    // object-shaped artifact. This row goes one level up: the artifact's
    // JSON ROOT itself is not an object at all. The original bundle.ts guard
    // (`encryptedState.json.entries`) dereferenced `.entries` before
    // checking the root's shape, so a null root threw a raw TypeError
    // BEFORE reaching the typed `ENCRYPTED_STATE_ENTRIES_UNREADABLE` throw -
    // this row is what catches that regression.
    await writeArtifactRawBytesAndResign(
      bundleDir,
      source,
      "encrypted_state",
      stringToBytes("null\n")
    );

    const destination = await makeDestination();
    await assertVerifyImportInvariant(
      bundleDir,
      false,
      "encrypted_state_entries_unreadable",
      () =>
        importExitBundle({
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
        }),
      { kind: "throws", code: "ENCRYPTED_STATE_ENTRIES_UNREADABLE", reason: "structural" }
    );
  });

  // ---- EXIT-STRUCT-02: malformed ELEMENT, one level deeper than LD2-01's
  // ---- unreadable CONTAINER. Same failure_class
  // ---- (encrypted_state_entries_unreadable), same named import error
  // ---- (ENCRYPTED_STATE_ENTRIES_UNREADABLE) - a correctly hashed and
  // ---- source-signed artifact whose `entries` array itself is readable but
  // ---- whose contents are not.

  it("EXIT-STRUCT-02: a null entries element fails verify closed, and import refuses with a NAMED error, never a crash", async () => {
    const source = await makeSource("aggregator-struct02-null-source");
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir, { mint: true });
    await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
      // The container stays a readable, non-empty array - only the
      // ELEMENT is damaged. `entry_count` still reads 1, so this is NOT
      // the LD2-01 (`entries` missing/non-array) case.
      artifact.entries = [null];
    });
    const destination = await makeDestination();

    await assertVerifyImportInvariant(
      bundleDir,
      false,
      "encrypted_state_entries_unreadable",
      () =>
        importExitBundle({
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
        }),
      { kind: "throws", code: "ENCRYPTED_STATE_ENTRIES_UNREADABLE", reason: "structural" }
    );
  });

  it("EXIT-STRUCT-02: an entries element missing `namespace` fails verify closed, and import refuses with a NAMED error, never a crash", async () => {
    const source = await makeSource("aggregator-struct02-namespace-source");
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir, { mint: true });
    await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
      const entries = artifact.entries as Array<Record<string, unknown>>;
      // `compromisedRetiredSignatureUse` (bundle.ts) dereferences
      // `item.namespace.startsWith(...)` on every entry before any other
      // check runs - a missing `namespace` throws there first.
      const { namespace: _namespace, ...withoutNamespace } = entries[0]!;
      artifact.entries = [withoutNamespace];
    });
    const destination = await makeDestination();

    await assertVerifyImportInvariant(
      bundleDir,
      false,
      "encrypted_state_entries_unreadable",
      () =>
        importExitBundle({
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
        }),
      { kind: "throws", code: "ENCRYPTED_STATE_ENTRIES_UNREADABLE", reason: "structural" }
    );
  });

  it("EXIT-STRUCT-02: an entries element missing `entry.sig` fails verify closed, and import refuses with a NAMED error, never a crash", async () => {
    const source = await makeSource("aggregator-struct02-entrysig-source");
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir, { mint: true });
    await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
      const entries = artifact.entries as Array<Record<string, unknown>>;
      const original = entries[0]! as { entry: Record<string, unknown> };
      const { sig: _sig, ...entryWithoutSig } = original.entry;
      artifact.entries = [{ ...entries[0], entry: entryWithoutSig }];
    });
    const destination = await makeDestination();

    await assertVerifyImportInvariant(
      bundleDir,
      false,
      "encrypted_state_entries_unreadable",
      () =>
        importExitBundle({
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
        }),
      { kind: "throws", code: "ENCRYPTED_STATE_ENTRIES_UNREADABLE", reason: "structural" }
    );
  });

  it("EXIT-STRUCT-02 fix-round: an entries element missing `entry.metadata` fails verify closed, and import refuses with a NAMED error, never a crash", async () => {
    const source = await makeSource("aggregator-struct02-metadata-source");
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir, { mint: true });
    await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
      const entries = artifact.entries as Array<Record<string, unknown>>;
      // `rekeyState` (bundle.ts write site) reads `entry.metadata.content_type`
      // AFTER decrypt + integrity-hash pass. `metadata` is covered by NEITHER
      // the signature (over payload.ct) NOR the integrity_hash (over plaintext),
      // so this element re-signs cleanly and decrypts, then throws on the
      // metadata deref unless verify fails it closed first.
      const entry = entries[0]!.entry as Record<string, unknown>;
      const { metadata: _metadata, ...entryWithoutMetadata } = entry;
      artifact.entries = [{ ...entries[0]!, entry: entryWithoutMetadata }];
    });
    const destination = await makeDestination();

    await assertVerifyImportInvariant(
      bundleDir,
      false,
      "encrypted_state_entries_unreadable",
      () =>
        importExitBundle({
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
        }),
      { kind: "throws", code: "ENCRYPTED_STATE_ENTRIES_UNREADABLE", reason: "structural" }
    );
  });

  it("EXIT-STRUCT-02 fix-round: an entries element whose `entry.metadata.tags` is a non-array fails verify closed (the `...tags` spread would otherwise throw)", async () => {
    const source = await makeSource("aggregator-struct02-tags-source");
    const bundleDir = await newBundleDir();
    await exportBundle(source, bundleDir, { mint: true });
    await patchEncryptedStateAndResign(bundleDir, source, (artifact) => {
      const entries = artifact.entries as Array<Record<string, unknown>>;
      const entry = entries[0]!.entry as Record<string, unknown>;
      const metadata = { ...(entry.metadata as Record<string, unknown>), tags: "not-an-array" };
      artifact.entries = [{ ...entries[0]!, entry: { ...entry, metadata } }];
    });
    const destination = await makeDestination();

    await assertVerifyImportInvariant(
      bundleDir,
      false,
      "encrypted_state_entries_unreadable",
      () =>
        importExitBundle({
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
        }),
      { kind: "throws", code: "ENCRYPTED_STATE_ENTRIES_UNREADABLE", reason: "structural" }
    );
  });

  // ---- Artifact 1's OTHER mutation-provable half: the fail-closed default ---

  it("EXIT-STRUCT-02: `entries_malformed_elements` fails closed directly at the aggregator function", () => {
    // Unit-level pin, independent of the end-to-end rows above: drives the
    // health value `classifyEncryptedStateStructuralHealth` now returns for a
    // malformed-element artifact straight through `encryptedStateSubVerdictFailed`
    // and asserts it fails closed, the same way the pre-existing
    // "entries_unreadable" case is pinned.
    expect(encryptedStateSubVerdictFailed("entries_malformed_elements")).toBe(true);
  });

  it("fails closed on a structural-health value the switch does not recognize (mutation-provable guard)", () => {
    // No legitimate TS caller can construct this today - the
    // `EncryptedStateStructuralHealth` union is closed to "readable" |
    // "entries_unreadable" | "entries_malformed_elements" - but this cast is
    // exactly the shape a FUTURE fourth health value would take if
    // `classifyEncryptedStateStructuralHealth` grew a new case without a
    // matching one in `encryptedStateSubVerdictFailed`. Reverting that
    // function's default arm from `return true` to `return false` (the
    // fail-open mutation) makes this assertion fail.
    const outOfUnionHealth = "a-future-health-value-nobody-wired-up" as unknown as Parameters<
      typeof encryptedStateSubVerdictFailed
    >[0];
    expect(encryptedStateSubVerdictFailed(outOfUnionHealth)).toBe(true);
  });
});
