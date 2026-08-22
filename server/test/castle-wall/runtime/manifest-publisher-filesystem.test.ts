/**
 * Focused filesystem-path tests for MANIFEST-RULEID-PATH-01 (PR-2 closure).
 *
 * These tests use the real FilesystemManifestStorage (not InMemoryStorage)
 * and disposable temp directories so they prove the PRODUCER PATH on disk.
 *
 * Coverage:
 *  P1 - encoded-v1 filename (rid1_*) appears on disk; legacy name does not
 *  P2 - signed manifest entry `file` field matches the on-disk filename
 *  P3 - distinct maximum-length IDs remain distinct on disk (no collision)
 *  P4 - traversal and overlong identities both fail before any write; sentinel unchanged
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { encrypt } from "../../../src/core/encryption.js";
import { generateRandomKey } from "../../../src/core/random.js";
import {
  localManifestSigner,
  publishSignedManifest,
  type ManifestSigner,
} from "../../../src/castle-wall/runtime/manifest-publisher.js";
import { FilesystemManifestStorage } from "../../../src/cli/castle-wall-observe.js";
import {
  encodeRuleFilename,
  parseRuleId,
  RULE_ID_MAX_LENGTH,
} from "../../../src/castle-wall/allowlist/rule-identity.js";
import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../../src/castle-wall/constants.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";

function makeRule(id: string, host: string): AllowlistRule {
  return {
    id,
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: "2026-08-22T00:00:00Z",
    match: { host: [host], port: [443], protocol: "tcp" },
    scope: {},
    disposition: "allow",
  };
}

function makeSigner(): ManifestSigner {
  const privateSeed = generateRandomKey();
  const encryptionKey = generateRandomKey();
  return localManifestSigner({
    signingKeyId: "test-key-fs",
    encryptedPrivateKey: encrypt(privateSeed, encryptionKey),
    encryptionKey,
  });
}

/**
 * Captures a rejection from a promise, ensuring the result is an Error.
 * Fails if the promise resolves or if the rejection is not an Error instance.
 */
async function captureError(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
    throw new Error("Expected promise to reject, but it resolved");
  } catch (e) {
    if (e instanceof Error) {
      return e;
    }
    throw new Error(`Expected Error, but caught non-Error value: ${typeof e}`);
  }
}

describe("manifest-publisher filesystem: encoded-v1 producer path (PR-2 closure)", () => {
  let egressDir: string;
  let signer: ManifestSigner;

  beforeEach(async () => {
    egressDir = await mkdtemp(join(tmpdir(), "cw-prod-path-"));
    signer = makeSigner();
  });

  afterEach(async () => {
    await rm(egressDir, { recursive: true, force: true });
  });

  // P1: encoded filename appears on disk; legacy name absent
  it("P1: rule file appears on disk with encoded-v1 name (rid1_*), not the legacy <id>.json name", async () => {
    const id = "my-test-rule";
    const parsed = parseRuleId(id);
    if (!parsed.ok) throw new Error(`test setup: invalid id: ${parsed.error}`);
    // encodeRuleFilename is the code-controlled injective relation that the
    // producer must use; this assertion is the fail-before contract.
    const expectedFilename = encodeRuleFilename(parsed.value);

    await publishSignedManifest(
      {
        fortressId: "fortress-p1",
        issuedAt: "2026-08-22T00:00:00Z",
        rules: [makeRule(id, "api.example.com")],
        signer,
      },
      new FilesystemManifestStorage(egressDir),
    );

    // Encoded file must exist on disk
    const encodedStat = await stat(join(egressDir, "rules", expectedFilename));
    expect(encodedStat.isFile()).toBe(true);
    // Legacy file must NOT exist on disk
    const legacyPath = join(egressDir, "rules", `${id}.json`);
    await expect(stat(legacyPath)).rejects.toThrow(/ENOENT/);
  });

  // P2: manifest entry file field matches on-disk filename
  it("P2: signed manifest entry `file` field is the encoded-v1 filename matching what is on disk", async () => {
    const id = "my-test-rule";
    const parsed = parseRuleId(id);
    if (!parsed.ok) throw new Error(`test setup: invalid id: ${parsed.error}`);
    const expectedFilename = encodeRuleFilename(parsed.value);

    const { signed } = await publishSignedManifest(
      {
        fortressId: "fortress-p2",
        issuedAt: "2026-08-22T00:00:00Z",
        rules: [makeRule(id, "api.example.com")],
        signer,
      },
      new FilesystemManifestStorage(egressDir),
    );

    // Manifest entry must name the encoded file
    expect(signed.manifest.rules[0]!.file).toBe(expectedFilename);
    // The file named in the manifest must actually be present in rules/
    const names = await readdir(join(egressDir, "rules"));
    expect(names).toContain(expectedFilename);
    // The manifest entry and the on-disk file are in 1-to-1 correspondence
    expect(names.filter((n) => n !== "manifest.json")).toHaveLength(1);
  });

  // P3: distinct maximum-length IDs remain distinct on disk
  it("P3: distinct maximum-length IDs produce distinct encoded filenames and distinct on-disk files", async () => {
    // Both IDs exactly at the 120-char contract ceiling; explicit assertion so the claim cannot drift.
    const shared = "r".repeat(114);
    const idAlpha = shared + "-alpha"; // 114 + 6 = 120 exactly
    const idBeta  = shared + "-beta0"; // 114 + 6 = 120 exactly
    expect(idAlpha.length).toBe(RULE_ID_MAX_LENGTH);
    expect(idBeta.length).toBe(RULE_ID_MAX_LENGTH);
    const pAlpha = parseRuleId(idAlpha);
    const pBeta  = parseRuleId(idBeta);
    if (!pAlpha.ok) throw new Error(`test setup: ${pAlpha.error}`);
    if (!pBeta.ok)  throw new Error(`test setup: ${pBeta.error}`);
    const encodedAlpha = encodeRuleFilename(pAlpha.value);
    const encodedBeta  = encodeRuleFilename(pBeta.value);
    // Injectivity pre-check: the two encoded names must already differ
    expect(encodedAlpha).not.toBe(encodedBeta);

    const { written_rule_filenames, signed } = await publishSignedManifest(
      {
        fortressId: "fortress-p3",
        issuedAt: "2026-08-22T00:00:00Z",
        rules: [makeRule(idAlpha, "a.example"), makeRule(idBeta, "b.example")],
        signer,
      },
      new FilesystemManifestStorage(egressDir),
    );

    // Both files must appear on disk
    const names = await readdir(join(egressDir, "rules"));
    expect(names).toContain(encodedAlpha);
    expect(names).toContain(encodedBeta);
    // The publisher must report two distinct written filenames
    expect(new Set(written_rule_filenames).size).toBe(2);
    // The signed manifest must reference two distinct files
    expect(new Set(signed.manifest.rules.map((e) => e.file)).size).toBe(2);
  });

  // P4: traversal AND overlong identities fail BEFORE any write (fail-closed ordering)
  it("P4: traversal and overlong identities reject with generic `invalid rule id` before any write; sentinel unchanged", async () => {
    // Pre-create a sentinel at the path the historical raw-filename join (egressDir/rules/<id>.json)
    // would have reached for the traversal id "../outside-sentinel":
    //   join(egressDir, "rules", "../outside-sentinel.json") → egressDir/outside-sentinel.json
    const sentinelPath = join(egressDir, "outside-sentinel.json");
    const sentinelContent = "sentinel-must-not-change";
    await writeFile(sentinelPath, sentinelContent);

    const traversalId = "../outside-sentinel";
    const overlongId = "x".repeat(121); // one char over the 120-char ceiling

    // Both must reject with a bounded generic error that does not echo the raw invalid value.
    const traversalErr = await captureError(
      publishSignedManifest(
        {
          fortressId: "fortress-p4",
          issuedAt: "2026-08-22T00:00:00Z",
          rules: [makeRule(traversalId, "a.example")],
          signer,
        },
        new FilesystemManifestStorage(egressDir),
      ),
    );
    expect(traversalErr.message).toMatch(/invalid rule id/);
    expect(traversalErr.message).not.toContain(traversalId);

    const overlongErr = await captureError(
      publishSignedManifest(
        {
          fortressId: "fortress-p4",
          issuedAt: "2026-08-22T00:00:00Z",
          rules: [makeRule(overlongId, "a.example")],
          signer,
        },
        new FilesystemManifestStorage(egressDir),
      ),
    );
    expect(overlongErr.message).toMatch(/invalid rule id/);
    expect(overlongErr.message).not.toContain(overlongId);

    // No rules/ dir: both errors fired before any writeRule call
    await expect(stat(join(egressDir, "rules"))).rejects.toThrow(/ENOENT/);

    // Sentinel is byte-identical: neither invalid ID touched the filesystem
    const sentinelAfter = await readFile(sentinelPath, "utf8");
    expect(sentinelAfter).toBe(sentinelContent);
  });
});
