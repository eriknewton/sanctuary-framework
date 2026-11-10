// fail-before-exempt: the feature boundary is new; predicate removal is mutation evidence.
import {expect, it} from "vitest";
import {readFileSync, readdirSync} from "node:fs";
import {resolve} from "node:path";
import {fileURLToPath} from "node:url";

const root = resolve(fileURLToPath(import.meta.url), "../../../..");
const read = (path: string): string => readFileSync(resolve(root, path), "utf8");

it("excludes the raw seed constructor and all its callers from shipped builds", () => {
  const producer = read("castle-wall-daemon/src/ipc/producer_sig.rs");
  expect(producer).toMatch(/#\[cfg\(feature = "legacy-raw-producer"\)\]\s*pub fn from_signing_key/);
  expect(producer).toMatch(/#\[cfg\(feature = "legacy-raw-producer"\)\]\s*#\[test\]\s*fn replayed_signature_fails_against_different_seq/);
  expect(read("castle-wall-daemon/tests/integration_producer_sig_cross_lang.rs")).toMatch(/^#!\[cfg\(feature = "legacy-raw-producer"\)\]/);
  const manifest = read("castle-wall-daemon/Cargo.toml");
  expect(manifest).toContain("legacy-raw-producer = []");
  expect(manifest).not.toMatch(/^default\s*=.*legacy-raw-producer/m);
  const callers = ["src", "tests"].flatMap(dir => readdirSync(resolve(root, "castle-wall-daemon", dir), {recursive: true})
    .filter((name): name is string => typeof name === "string" && name.endsWith(".rs"))
    .map(name => `${dir}/${name}`))
    .filter(path => read(`castle-wall-daemon/${path}`).includes("ProducerSigner::from_signing_key("));
  expect(callers.sort()).toEqual(["src/ipc/producer_sig.rs", "tests/integration_producer_sig_cross_lang.rs"]);
  for (const name of readdirSync(resolve(root, ".github/workflows"))) {
    for (const line of read(`.github/workflows/${name}`).split("\n")) {
      if (/cargo(?:\s+\+\S+)?\s+build\b/.test(line)) expect(line).not.toContain("legacy-raw-producer");
    }
  }
});
