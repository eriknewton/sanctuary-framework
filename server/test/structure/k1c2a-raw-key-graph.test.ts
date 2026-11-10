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

it("keeps both selection tokens sealed and roots isolated only in test builds", () => {
  const config = read("castle-wall-daemon/src/config.rs");
  for (const token of ["LegacyV1Selection", "BusinessSelection"]) {
    expect(config).toMatch(new RegExp(`pub struct ${token} \\{\\s*_sealed: Sealed`));
    expect(config).not.toMatch(new RegExp(`#\\[derive\\([^\\]]*(?:Clone|Copy|Default)[^\\]]*\\)\\]\\s*pub struct ${token}`));
    const body = config.match(new RegExp(`impl ${token} \\{([\\s\\S]*?)\\n\\}`))?.[1] ?? "";
    expect(body).not.toMatch(/pub fn (?:new|default|from)/);
    const construction = config.slice(config.indexOf("pub fn select_profile("), config.indexOf("mod selection_walk"));
    const whole = [...config.matchAll(new RegExp(`${token} \\{\\s*_sealed: Sealed(?:,|\\s*\\})`, "g"))].length;
    const inside = [...construction.matchAll(new RegExp(`${token} \\{\\s*_sealed: Sealed(?:,|\\s*\\})`, "g"))].length;
    expect(whole).toBe(inside + 1); // The struct definition is the one non-construction occurrence.
  }
  expect(read("castle-wall-daemon/src/ipc/producer_sig.rs")).toMatch(/pub fn load_or_generate\(\s*_selection: &crate::config::LegacyV1Selection,/);
  const roots = config.match(/pub struct SelectorRoots \{([\s\S]*?)\n\}/)![1];
  expect(roots).not.toMatch(/\bpub\b/);
  for (const constructor of ["isolated_under", "expect_owner_at", "deny_lookup", "deny_open"]) {
    const source = config.slice(config.indexOf("impl SelectorRoots"));
    expect(source).toMatch(new RegExp(`#\\[cfg\\(any\\(test, feature = "test-isolation"\\)\\)\\]\\s*pub fn ${constructor}`));
  }
  for (const file of ["main.rs", "daemon.rs"]) expect(read(`castle-wall-daemon/src/${file}`)).not.toContain("business_profile");
  expect(config).toContain('#[cfg(not(target_os = "linux"))]');
  expect(config).toContain("production_roots_trust_only_root_without_seams");
  expect(config).toContain("non_linux_returns_implicit_legacy_without_lookups");
});

it("pins policy literals and excludes alternate root or token constructors", () => {
  const config = read("castle-wall-daemon/src/config.rs");
  for (const [constant, literal, files] of [
    ["BUSINESS_SIGNER_PEER_POLICY", "/etc/sanctuary/business-signer-peer.json", ["sanctuary-business-signer.rs", "sanctuary-business-unlock.rs"]],
    ["BUSINESS_SIGNER_CONTROLLER_POLICY", "/etc/sanctuary/business-signer-controller.json", ["sanctuary-business-signer.rs"]],
  ] as const) {
    expect(config).toMatch(new RegExp(`${constant}: &str =\\s*"${literal}"`));
    for (const file of files) expect(read(`castle-wall-daemon/src/bin/${file}`)).toContain(`"${literal}"`);
  }
  for (const name of readdirSync(resolve(root, "castle-wall-daemon/src"), {recursive: true})) {
    if (typeof name !== "string" || !name.endsWith(".rs") || name === "config.rs") continue;
    const source = read(`castle-wall-daemon/src/${name}`);
    expect(source).not.toMatch(/impl(?:<[^>]*>)?\s+(?:SelectorRoots|LegacyV1Selection|BusinessSelection)\b/);
    expect(source).not.toMatch(/(?:LegacyV1Selection|BusinessSelection)\s*\{\s*_sealed/);
  }
});
