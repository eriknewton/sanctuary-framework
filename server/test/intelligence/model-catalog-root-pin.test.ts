/**
 * The V2 model-manifest trust root is the dedicated model-catalog root key;
 * the historical V1 constant and the catalog v3 epoch-1 bootstrap keyring stay
 * on the release-signing key.
 */

import { describe, expect, it } from "vitest";
import { fromBase64urlStrict } from "../../src/core/encoding.js";
import * as intelligenceBarrel from "../../src/intelligence/index.js";
import { COMPILED_CATALOG_KEYRING } from "../../src/intelligence/model-catalog-v3.js";
import {
  PINNED_MODEL_CATALOG_ROOT_PUBLIC_KEY_B64URL,
  PINNED_MODEL_MANIFEST_SIGNING_PUBLIC_KEY_B64URL,
  loadPinnedModelManifestKey,
} from "../../src/intelligence/model-manifest.js";
import { PINNED_MODEL_MANIFEST_V2_SIGNING_PUBLIC_KEY_B64URL } from "../../src/intelligence/model-manifest-v2.js";
import { PINNED_RELEASE_SIGNING_PUBLIC_KEY_B64URL } from "../../src/release-manifest.js";

// Public half minted 2026-09-03 (owner ruling 2); recorded in the operator's
// off-host key backup as model-catalog-root-public-2026-09-03.txt.
const CATALOG_ROOT_HEX = "fa4a6406022dae5b61362be587fa5f8d66eba5c40f11ed733ddc7a1b0b5cb36c";

describe("model-catalog root pin", () => {
  it("pins the V2 contract to the dedicated catalog root, not the release key", () => {
    expect(PINNED_MODEL_MANIFEST_V2_SIGNING_PUBLIC_KEY_B64URL).toBe(PINNED_MODEL_CATALOG_ROOT_PUBLIC_KEY_B64URL);
    expect(PINNED_MODEL_CATALOG_ROOT_PUBLIC_KEY_B64URL).not.toBe(PINNED_RELEASE_SIGNING_PUBLIC_KEY_B64URL);
    expect(Buffer.from(fromBase64urlStrict(PINNED_MODEL_CATALOG_ROOT_PUBLIC_KEY_B64URL)).toString("hex"))
      .toBe(CATALOG_ROOT_HEX);
  });

  it("resolves the production V2 key from the catalog root and refuses degenerate values", () => {
    const key = loadPinnedModelManifestKey();
    expect(key).not.toBeNull();
    expect(Buffer.from(key!).toString("hex")).toBe(CATALOG_ROOT_HEX);
    expect(key!.length).toBe(32);
    expect(key!.some((byte) => byte !== 0)).toBe(true);
  });

  it("leaves the historical V1 constant and the catalog v3 epoch-1 bootstrap on the release key", () => {
    expect(PINNED_MODEL_MANIFEST_SIGNING_PUBLIC_KEY_B64URL).toBe(PINNED_RELEASE_SIGNING_PUBLIC_KEY_B64URL);
    expect(COMPILED_CATALOG_KEYRING).toHaveLength(1);
    expect(COMPILED_CATALOG_KEYRING[0]!.pubkey).toBe(PINNED_RELEASE_SIGNING_PUBLIC_KEY_B64URL);
  });

  it("exports the catalog root through the intelligence barrel", () => {
    expect(intelligenceBarrel.PINNED_MODEL_CATALOG_ROOT_PUBLIC_KEY_B64URL)
      .toBe(PINNED_MODEL_CATALOG_ROOT_PUBLIC_KEY_B64URL);
    expect(intelligenceBarrel.loadPinnedModelManifestKey).toBe(loadPinnedModelManifestKey);
  });
});
