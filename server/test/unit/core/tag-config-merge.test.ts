// fail-before-exempt: pins tag-era preservation of the optional session binding key through merge and serialization.
/** Tag config merging preserves the operator's binding choice. */
import { expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { defaultConfig } from "../../../src/config.js";
import { deepMerge } from "../../fixtures/tag-config-merge/deep-merge.v1.9.0-rc.4.js";
// sha256 of `git show v1.9.0-rc.4:server/src/config.ts | awk '/^function deepMerge/,/^}/'`; identical at v1.8.6-rc.5; must match the fixture file.
const TAG_DEEP_MERGE_SHA256 = "cde8dc6457140e98c800782a63ecccc054cc1cc58dcc7472b535f55b68793a85";
it("the tag's `mergeFileConfig` keeps the key", async () => {
  const text = await readFile(new URL("../../fixtures/tag-config-merge/deep-merge.v1.9.0-rc.4.ts", import.meta.url), "utf8");
  const body = text.slice(text.indexOf("function deepMerge")).split("\n}\n")[0] + "\n}\n";
  expect(createHash("sha256").update(body).digest("hex")).toBe(TAG_DEEP_MERGE_SHA256);
  const merged = deepMerge(defaultConfig(), { session_binding: { sole_identity: true } });
  expect(JSON.parse(JSON.stringify(merged, null, 2)).session_binding).toEqual({ sole_identity: true });
});
