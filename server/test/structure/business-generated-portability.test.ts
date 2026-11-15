// fail-before-exempt: generated native module dependencies and test gates are read outside server/src.
// Portable generated contracts remain available on every host.
// W-JOIN-LIFECYCLE
import {expect, it} from "vitest";
import {readFileSync} from "node:fs";
import {resolve, dirname} from "node:path";
import {fileURLToPath} from "node:url";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../../castle-wall-daemon/src/business_profile");
const read = (name: string) => readFileSync(resolve(root, name), "utf8");
it("ungated generated includes name only portable module paths", () => {
  const modules = [...read("mod.rs").matchAll(/((?:#\[[^\n]+\]\s*)*)pub mod (\w+);/g)];
  const linux = modules.filter(m => m[1].includes('target_os = "linux"')).map(m => m[2]);
  expect(linux).toContain("append_checkpoint");
  const checked: string[] = [];
  for (const mod of modules.filter(m => !linux.includes(m[2]))) {
    for (const inc of read(`${mod[2]}.rs`).matchAll(/include!\("([^"]+)"\)/g)) {
      const source = read(inc[1]);
      if (!source.startsWith("// Generated")) continue;
      checked.push(inc[1]);
      for (const gated of linux) expect(source, `${inc[1]} must be portable`).not.toMatch(new RegExp(`\\b${gated}::`));
    }
  }
  expect(checked).toContain("join_state_contract.rs");
  expect(read("append_checkpoint.rs")).toContain('include!("checkpoint_bounds.rs")');
});
it("Linux bounded fixtures have a matching test module gate", () => {
  expect(read("records.rs")).toMatch(/#\[cfg\(target_os = "linux"\)\]\s*#\[cfg\(test\)\]\s*mod bounded_tests/);
});
