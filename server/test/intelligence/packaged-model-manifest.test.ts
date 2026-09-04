/**
 * Packaged signed model-manifest loader: verified text or a typed, audited
 * refusal for every input class, with the build-time byte pin and the shared
 * V2 parser on the path.
 */

import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { INTEL_OPS } from "../../src/intelligence/audit-events.js";
import * as intelligenceBarrel from "../../src/intelligence/index.js";
import {
  PACKAGED_MODEL_MANIFEST_AUDIT_STAGE,
  PACKAGED_MODEL_MANIFEST_REFUSAL_REASONS,
  PACKAGED_MODEL_MANIFEST_V2_ASSET_RELATIVE_PATH,
  PACKAGED_MODEL_MANIFEST_V2_ASSET_SHA256,
  PACKAGED_MODEL_MANIFEST_V2_MAX_BYTES,
  loadPackagedModelManifestV2,
  mapModelManifestV2RefusalToAssetRefusal,
  resolvePackagedModelManifestV2AssetPath,
  type PackagedModelManifestAuditEvent,
} from "../../src/intelligence/packaged-model-manifest.js";
import { MAX_CATALOG_WIRE_JSON_BYTES } from "../../src/intelligence/model-catalog-v3.js";
import {
  Q5E_PUBLIC_KEY,
  q5eBody,
  signQ5eBody,
} from "./q5e-fixtures.js";

const sha256 = (bytes: Uint8Array | string) =>
  createHash("sha256").update(bytes).digest("hex");
const signedText = (manifestVersion = 17) =>
  JSON.stringify(signQ5eBody(q5eBody(undefined, manifestVersion)));
// 86 = unpadded base64url length of a 64-byte signature; all "A" is all-zero.
const ALL_ZERO_SIGNATURE = "A".repeat(86);

describe("packaged model manifest loader", () => {
  let dir: string;
  let audit: ReturnType<typeof vi.fn<(event: PackagedModelManifestAuditEvent) => void>>;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sanctuary-packaged-manifest-"));
    audit = vi.fn<(event: PackagedModelManifestAuditEvent) => void>();
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  async function stage(name: string, content: string | Uint8Array): Promise<string> {
    const path = join(dir, name);
    await writeFile(path, content);
    return path;
  }

  function lastAudit() {
    return audit.mock.calls.at(-1)?.[0];
  }

  /** Lay the asset at the canonical location under a package root. */
  async function stagePackaged(root: string, text: string): Promise<string> {
    const path = join(root, ...PACKAGED_MODEL_MANIFEST_V2_ASSET_RELATIVE_PATH.split("/"));
    await mkdir(join(path, ".."), { recursive: true });
    await writeFile(path, text);
    return path;
  }

  it("accepts a signed envelope at the canonical packaged location and audits success", async () => {
    const text = signedText();
    await stagePackaged(dir, text);
    const result = await loadPackagedModelManifestV2({
      moduleDir: dir,
      publicKey: Q5E_PUBLIC_KEY,
      expectedAssetSha256: sha256(text),
      audit,
    });
    expect(result).toMatchObject({
      ok: true,
      source: "packaged",
      manifestText: text,
      assetSha256: sha256(text),
    });
    expect(result.ok && result.body.manifest_version).toBe(17);
    expect(audit).toHaveBeenCalledTimes(1);
    expect(lastAudit()).toMatchObject({
      operation: INTEL_OPS.LOAD_INTEGRITY,
      outcome: "success",
      details: {
        stage: PACKAGED_MODEL_MANIFEST_AUDIT_STAGE,
        source: "packaged",
        asset_sha256: sha256(text),
        manifest_version: 17,
        model_count: 1,
      },
    });
  });

  it("accepts an operator path with the same verifier and no build pin", async () => {
    const text = signedText(3);
    const path = await stage("operator.json", text);
    const result = await loadPackagedModelManifestV2({
      assetPath: path,
      publicKey: Q5E_PUBLIC_KEY,
      // A pin for some other bytes must not apply to the operator path.
      expectedAssetSha256: "1".repeat(64),
      audit,
    });
    expect(result).toMatchObject({ ok: true, source: "operator-path" });
    expect(lastAudit()?.details).toMatchObject({ source: "operator-path", path });
  });

  it("refuses a tampered body under a matching pin as a signature failure", async () => {
    const tampered = signedText().replace('"manifest_version":17', '"manifest_version":18');
    expect(tampered).not.toBe(signedText());
    await stagePackaged(dir, tampered);
    const result = await loadPackagedModelManifestV2({
      moduleDir: dir,
      publicKey: Q5E_PUBLIC_KEY,
      expectedAssetSha256: sha256(tampered),
      audit,
    });
    expect(result).toMatchObject({
      ok: false,
      reason: "integrity_asset_signature_invalid",
      detail: "bad_signature",
    });
    expect(lastAudit()).toMatchObject({
      outcome: "failure",
      details: { stage: PACKAGED_MODEL_MANIFEST_AUDIT_STAGE, reason: "integrity_asset_signature_invalid" },
    });
  });

  it("refuses a tampered packaged asset against the recorded pin before parsing", async () => {
    const original = signedText();
    const tampered = original.replace('"manifest_version":17', '"manifest_version":18');
    await stagePackaged(dir, tampered);
    const result = await loadPackagedModelManifestV2({
      moduleDir: dir,
      publicKey: Q5E_PUBLIC_KEY,
      expectedAssetSha256: sha256(original),
      audit,
    });
    expect(result).toMatchObject({
      ok: false,
      reason: "integrity_asset_pin_mismatch",
      detail: sha256(tampered),
    });
    expect(lastAudit()?.details).toMatchObject({ reason: "integrity_asset_pin_mismatch" });
  });

  it("refuses a stripped signature, a zero signature, and a foreign key", async () => {
    const envelope = signQ5eBody(q5eBody());
    const stripped = JSON.stringify({ ...envelope, signature: "" });
    const zero = JSON.stringify({ ...envelope, signature: ALL_ZERO_SIGNATURE });
    const foreignKey = ed25519.getPublicKey(new Uint8Array(32).fill(7));
    for (const [text, key, detail] of [
      [stripped, Q5E_PUBLIC_KEY, "absent"],
      [zero, Q5E_PUBLIC_KEY, "zero_signature"],
      [JSON.stringify(envelope), foreignKey, "bad_signature"],
    ] as const) {
      const path = await stage(`sig-${detail}.json`, text);
      await expect(loadPackagedModelManifestV2({
        assetPath: path,
        publicKey: key,
        audit,
      })).resolves.toMatchObject({
        ok: false,
        reason: "integrity_asset_signature_invalid",
        detail,
      });
    }
    expect(audit).toHaveBeenCalledTimes(3);
  });

  it("refuses an oversize asset before decoding it", async () => {
    expect(PACKAGED_MODEL_MANIFEST_V2_MAX_BYTES).toBe(MAX_CATALOG_WIRE_JSON_BYTES);
    const path = await stage(
      "oversize.json",
      Buffer.alloc(PACKAGED_MODEL_MANIFEST_V2_MAX_BYTES + 1, 0x20),
    );
    await expect(loadPackagedModelManifestV2({
      assetPath: path,
      publicKey: Q5E_PUBLIC_KEY,
      audit,
    })).resolves.toMatchObject({
      ok: false,
      reason: "integrity_asset_oversize",
      detail: "byte_cap_exceeded",
    });
    const exact = await stage("exact.json", Buffer.alloc(PACKAGED_MODEL_MANIFEST_V2_MAX_BYTES, 0x20));
    await expect(loadPackagedModelManifestV2({ assetPath: exact, publicKey: Q5E_PUBLIC_KEY }))
      .resolves.toMatchObject({ ok: false, reason: "integrity_asset_unparseable" });
  });

  it("refuses a missing path, a directory, and an exhausted candidate list as absent", async () => {
    await expect(loadPackagedModelManifestV2({
      assetPath: join(dir, "nope.json"),
      publicKey: Q5E_PUBLIC_KEY,
      audit,
    })).resolves.toMatchObject({ ok: false, reason: "integrity_asset_absent", detail: "ENOENT" });
    await expect(loadPackagedModelManifestV2({
      assetPath: dir,
      publicKey: Q5E_PUBLIC_KEY,
    })).resolves.toMatchObject({ ok: false, reason: "integrity_asset_absent" });
    await expect(loadPackagedModelManifestV2({
      moduleDir: dir,
      publicKey: Q5E_PUBLIC_KEY,
    })).resolves.toMatchObject({ ok: false, reason: "integrity_asset_absent", detail: "ENOENT" });
  });

  it("reads only the canonical packaged location; a file planted beside a bundle entry is ignored", async () => {
    // A `dist/`-style root: the bundle entry's own directory. The planted file
    // sits where a sibling-relative lookup would have found it first.
    await mkdir(join(dir, "model-manifest"), { recursive: true });
    await writeFile(join(dir, "model-manifest", "model-manifest.v2.json"), signedText());
    await expect(loadPackagedModelManifestV2({
      moduleDir: dir,
      publicKey: Q5E_PUBLIC_KEY,
      expectedAssetSha256: sha256(signedText()),
      audit,
    })).resolves.toMatchObject({ ok: false, reason: "integrity_asset_absent", detail: "ENOENT" });
    expect(lastAudit()?.details).toMatchObject({ reason: "integrity_asset_absent" });
    // The same planted bytes at the canonical location are read.
    await stagePackaged(dir, signedText());
    await expect(loadPackagedModelManifestV2({
      moduleDir: dir,
      publicKey: Q5E_PUBLIC_KEY,
      expectedAssetSha256: sha256(signedText()),
    })).resolves.toMatchObject({ ok: true, source: "packaged" });
  });

  it("refuses non-JSON, non-UTF-8, empty, and schema-rejected bytes as unparseable", async () => {
    const cases: Array<[string, string | Uint8Array, string]> = [
      ["text.json", "not json", "malformed_json"],
      ["utf8.json", new Uint8Array([0xff, 0xfe, 0x7b]), "invalid_utf8"],
      ["empty.json", "", "empty"],
      ["shape.json", JSON.stringify({ body: {}, signature: "x" }), "missing_key"],
    ];
    for (const [name, content, detail] of cases) {
      const path = await stage(name, content);
      await expect(loadPackagedModelManifestV2({
        assetPath: path,
        publicKey: Q5E_PUBLIC_KEY,
        audit,
      })).resolves.toMatchObject({ ok: false, reason: "integrity_asset_unparseable", detail });
    }
  });

  it("refuses when the pinned key is unavailable, and an audit sink failure changes nothing", async () => {
    const path = await stage("asset.json", signedText());
    const throwingAudit = vi.fn(() => {
      throw new Error("sink down");
    });
    await expect(loadPackagedModelManifestV2({
      assetPath: path,
      publicKey: new Uint8Array(32),
      audit: throwingAudit,
    })).resolves.toMatchObject({
      ok: false,
      reason: "integrity_asset_signature_invalid",
      detail: "zero_pinned_key",
    });
    expect(throwingAudit).toHaveBeenCalledTimes(1);
    await expect(loadPackagedModelManifestV2({
      assetPath: path,
      publicKey: Q5E_PUBLIC_KEY,
      audit: throwingAudit,
    })).resolves.toMatchObject({ ok: true });
  });

  it("maps the shared parser taxonomy onto the closed asset taxonomy", () => {
    expect(mapModelManifestV2RefusalToAssetRefusal("manifest_too_large")).toBe("integrity_asset_oversize");
    for (const reason of [
      "absent",
      "bad_signature_encoding",
      "bad_signature_length",
      "zero_signature",
      "bad_signature",
      "bad_pinned_key_length",
      "zero_pinned_key",
    ] as const) {
      expect(mapModelManifestV2RefusalToAssetRefusal(reason)).toBe("integrity_asset_signature_invalid");
    }
    for (const reason of ["malformed_json", "duplicate_key", "unknown_key", "downgrade", "rollback"] as const) {
      expect(mapModelManifestV2RefusalToAssetRefusal(reason)).toBe("integrity_asset_unparseable");
    }
    expect([...PACKAGED_MODEL_MANIFEST_REFUSAL_REASONS]).toEqual([
      "integrity_asset_absent",
      "integrity_asset_oversize",
      "integrity_asset_unparseable",
      "integrity_asset_signature_invalid",
      "integrity_asset_pin_mismatch",
    ]);
  });

  it("derives one canonical asset path from the module directory for every bundle layout", () => {
    const relative = join(...PACKAGED_MODEL_MANIFEST_V2_ASSET_RELATIVE_PATH.split("/"));
    // dist/cli.js and dist/index.js: module dir is the package dist root.
    expect(resolvePackagedModelManifestV2AssetPath("/pkg/dist")).toBe(join("/pkg/dist", relative));
    // dist/intelligence/index.js and src/intelligence/*.ts: module dir is the intelligence segment.
    expect(resolvePackagedModelManifestV2AssetPath("/pkg/dist/intelligence")).toBe(join("/pkg/dist", relative));
    expect(resolvePackagedModelManifestV2AssetPath("/repo/server/src/intelligence")).toBe(join("/repo/server/src", relative));
    // The production default resolves from this module's real location.
    expect(resolvePackagedModelManifestV2AssetPath().endsWith(relative)).toBe(true);
    expect(intelligenceBarrel.loadPackagedModelManifestV2).toBe(loadPackagedModelManifestV2);
    expect(intelligenceBarrel.PACKAGED_MODEL_MANIFEST_V2_ASSET_SHA256).toBe(PACKAGED_MODEL_MANIFEST_V2_ASSET_SHA256);
  });

  // COMMITTED ASSET STATE. The tree carries a PLACEHOLDER envelope (real body,
  // all-zero signature) until the coordinator signs with the catalog root seed.
  // Flip this constant to "signed" in the same change that lands the signed
  // asset; each branch is a strict expectation for its state.
  const COMMITTED_ASSET_STATE = "signed" as "placeholder" | "signed";

  it("loads the committed asset through the real candidates under the compiled pin", async () => {
    const bytes = await readFile(
      new URL(`../../src/${PACKAGED_MODEL_MANIFEST_V2_ASSET_RELATIVE_PATH}`, import.meta.url),
    );
    expect(sha256(bytes)).toBe(PACKAGED_MODEL_MANIFEST_V2_ASSET_SHA256);
    const result = await loadPackagedModelManifestV2({ audit });
    if (COMMITTED_ASSET_STATE === "placeholder") {
      expect(JSON.parse(bytes.toString("utf8")).signature).toBe(ALL_ZERO_SIGNATURE);
      expect(result).toMatchObject({
        ok: false,
        source: "packaged",
        reason: "integrity_asset_signature_invalid",
        detail: "zero_signature",
      });
    } else {
      expect(result).toMatchObject({ ok: true, source: "packaged", assetSha256: PACKAGED_MODEL_MANIFEST_V2_ASSET_SHA256 });
      expect(result.ok && result.body.manifest_version).toBe(1);
    }
  });
});
