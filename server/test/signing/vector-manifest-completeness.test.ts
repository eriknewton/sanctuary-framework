// fail-before-exempt: K1c-2b adds the signer status corpus to the Rust corpus manifest, which sits outside the server source that the base comparison restores; the manifest hash and case pins are the regression evidence.
import {expect, it} from "vitest";
import {readFileSync} from "node:fs";
import {createHash} from "node:crypto";

it("pins the exact full corpus set before reading any corpus", () => {
  const root = "../castle-wall-daemon/src/business_profile/";
  const manifest = JSON.parse(readFileSync(root + "vector_manifest.json", "utf8")) as {files: Record<string, {sha256: string; cases: Record<string, number>}>};
  expect(Object.keys(manifest.files).sort()).toEqual(["closure_vectors.json", "generator_vectors.json", "profile_selector_vectors.json", "public_vectors.json", "record_join_vectors.json", "role_vectors.json", "signer_status_vectors.json"]);
  for (const [name, entry] of Object.entries(manifest.files)) {
    const bytes = readFileSync(root + name), value = JSON.parse(bytes.toString("utf8")) as unknown;
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(entry.sha256);
    const groups = Array.isArray(value) ? {$root: value.length} : Object.fromEntries(Object.entries(value as Record<string, unknown>).filter(([, group]) => Array.isArray(group)).map(([name, group]) => [name, (group as unknown[]).length]));
    expect(groups).toEqual(entry.cases);
  }
});
