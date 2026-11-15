// fail-before-exempt: invariant-site checks inspect native sources and cross-file contract comments.
// Native file access and protocol state names preserve explicit contracts.
// W-WAL-STORE
import {expect, it} from "vitest";
import {readFileSync} from "node:fs";
import {resolve, dirname} from "node:path";
import {fileURLToPath} from "node:url";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const read = (path: string) => readFileSync(resolve(root, path), "utf8");
it("enumeration opens cannot block on a non-regular entry", () => {
  const s=read("castle-wall-daemon/src/business_profile/business_wal.rs");
  expect(s.slice(s.indexOf("fn open_at"),s.indexOf("fn held_root"))).toContain("libc::O_NONBLOCK");
});
it("created private files receive descriptor permissions", () => {
  const s=read("castle-wall-daemon/src/business_profile/business_wal.rs");
  expect(s).toContain("libc::fchmod");
  expect(s).toContain("set_private_mode(&file)?");
  expect(s.match(/set_private_mode\(&stage\)\?/g)?.length).toBe(2);
});
it("intent states have explicit protocol names", () => {
  const s=read("castle-wall-daemon/src/business_profile/business_wal.rs");
  for(const name of ["BodyFrozen","SignMarked","EnvelopeFrozen","CommitFrozen"]) expect(s).toContain(name);
  expect(s).toContain("r.intent_state()");
});
it("the delivery contract carries its reciprocal native barrier pin", () => {
  expect(read("server/src/signing/business-append-contract.ts")).toContain("business_wal.rs persist_ts_fact");
});
it("freshness names the reporting principal and what the verifier establishes", () => {
  expect(read("castle-wall-daemon/src/business_profile/append_checkpoint.rs")).toContain("W's self-report");
});
