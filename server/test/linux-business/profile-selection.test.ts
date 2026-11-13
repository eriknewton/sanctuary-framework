// fail-before-exempt: the selector and its corpus are new; predicate removal supplies evidence.
import {describe, expect, it} from "vitest";
import * as fs from "node:fs";
import {join, dirname} from "node:path";
import {tmpdir} from "node:os";
import {execFileSync} from "node:child_process";
import {loadCheckedCorpus} from "../fixtures/business-corpus.js";
import * as selection from "../../src/linux-business/profile-selection.js";

type Obj = Record<string, any>;
// Must match profile_selector_vectors.json and linux_business_profile_selection.rs's full refusal set.
const exact = (v: any, names: string[]) => v !== null && typeof v === "object" && !Array.isArray(v)
  && Object.keys(v).length === names.length && names.every(k => Object.hasOwn(v, k));
const relative = (v: any): v is string => typeof v === "string" && v.length > 0 && !v.includes("\0")
  && v.split("/").every(p => p !== "" && p !== "." && p !== "..");
function validate(v: any): boolean {
  if (!exact(v, ["version", "reasons", "inventory", "cases"]) || v.version !== 1) return false;
  if (JSON.stringify(v.reasons) !== JSON.stringify(["Explicit", "NoBusinessEvidence", "SelectorInvalid", "InventoryAmbiguous", "LegacyWithEnrollment", "RawInventoryPresent"]) || !Array.isArray(v.cases)) return false;
  const ids = new Set();
  for (const c of v.cases) {
    if (!exact(c, ["id", "caller", "layout", "owners", "deny", "candidates", "expect"]) || typeof c.id !== "string" || !c.id || ids.has(c.id) || !["owner", "unprivileged"].includes(c.caller)) return false;
    ids.add(c.id);
    if (!Array.isArray(c.layout)) return false;
    const paths = new Set(), regular = new Set(), nonDirectories = new Set();
    for (const n of c.layout) {
      const fields = n?.type === "file" ? ["type", "path", "mode", "content"] : ["dir", "fifo"].includes(n?.type) ? ["type", "path", "mode"] : ["symlink", "hardlink"].includes(n?.type) ? ["type", "path", "mode", "target"] : [];
      if (!fields.length || !exact(n, fields) || !relative(n.path) || paths.has(n.path) || !Number.isInteger(n.mode) || n.mode < 0 || n.mode > 0o7777) return false;
      paths.add(n.path);
      const components = n.path.split("/");
      for (let i = 1; i < components.length; i++) if (nonDirectories.has(components.slice(0, i).join("/"))) return false;
      if (n.type !== "dir") nonDirectories.add(n.path);
      if (n.type === "file") { if (typeof n.content !== "string") return false; regular.add(n.path); }
      if (["symlink", "hardlink"].includes(n.type) && (!relative(n.target) || n.type === "hardlink" && !regular.has(n.target))) return false;
    }
    if (!c.owners || typeof c.owners !== "object" || Array.isArray(c.owners) || Object.entries(c.owners).some(([p, o]) => !relative(p) || !["self", "other"].includes(o as string))) return false;
    if (!exact(c.deny, ["lookup", "open"])) return false;
    for (const a of [c.deny.lookup, c.deny.open, c.candidates]) if (!Array.isArray(a) || !a.every(relative)) return false;
    if (c.candidates.length > selection.MAX_RAW_CANDIDATES || !exact(c.expect, ["kind", "reason"])) return false;
    const valid = c.expect.kind === "Business" ? c.expect.reason === null : c.expect.kind === "LegacyV1" ? ["Explicit", "NoBusinessEvidence"].includes(c.expect.reason)
      : c.expect.kind === "Refused" ? ["SelectorInvalid", "InventoryAmbiguous", "LegacyWithEnrollment", "RawInventoryPresent"].includes(c.expect.reason) : false;
    if (!valid) return false;
  }
  return true;
}
function fixture(root: string, c: Obj): selection.IsolatedSelectorRoots {
  for (const n of c.layout) {
    const path = join(root, n.path);
    fs.mkdirSync(dirname(path), {recursive: true, mode: 0o700});
    switch (n.type) {
      case "file": fs.writeFileSync(path, n.content); break;
      case "dir": fs.mkdirSync(path, {recursive: true}); break;
      case "symlink": fs.symlinkSync(join(root, n.target), path); break;
      case "hardlink": fs.linkSync(join(root, n.target), path); break;
      case "fifo": execFileSync("mkfifo", [path]); break;
      default: throw new Error("validated layout");
    }
    if (n.type !== "symlink") fs.chmodSync(path, n.mode);
  }
  let roots = selection.isolatedSelectorRoots(root);
  for (const [path, owner] of Object.entries(c.owners)) roots = roots.expectOwnerAt(path, process.geteuid!() + (owner === "other" ? 1 : 0));
  for (const path of c.deny.lookup) roots = roots.denyLookup(path);
  for (const path of c.deny.open) roots = roots.denyOpen(path);
  return roots;
}
function snapshot(root: string): unknown[] {
  const rows: unknown[][] = [];
  const visit = (dir: string) => {
    // The entry type comes from the directory read and a file's mode and bytes from one descriptor, so no path is checked and
    // then reopened: a link swapped in between could otherwise be followed out of the fixture.
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
      const path = join(dir, entry.name), label = path.slice(root.length);
      if (entry.isSymbolicLink()) rows.push([label, "link", fs.readlinkSync(path)]);
      else if (entry.isFile()) {
        const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
        try { rows.push([label, fs.fstatSync(fd).mode, fs.readFileSync(fd).toString("hex")]); } finally { fs.closeSync(fd); }
      } else {
        rows.push([label, entry.isDirectory() ? fs.lstatSync(path).mode : "other", null]);
        if (entry.isDirectory()) visit(path);
      }
    }
  };
  visit(root); return rows;
}
function cleanup(root: string): void {
  for (const name of fs.readdirSync(root)) {
    const path = join(root, name);
    if (fs.lstatSync(path).isDirectory()) cleanup(path); else fs.unlinkSync(path);
  }
  fs.rmdirSync(root);
}
const corpus = loadCheckedCorpus("profile_selector_vectors.json") as Obj;
if (!validate(corpus)) throw new Error("HARNESS_FAILURE: malformed selector corpus element");
const actual: unknown[] = [];
// Selection requires the Linux procfs descriptor transport.
describe.skipIf(process.platform !== "linux")("shared selector corpus", () => {
  for (const c of corpus.cases) it(c.id, () => {
    const root = fs.mkdtempSync(join(tmpdir(), "k1-selector-"));
    try {
      const roots = fixture(root, c);
      if (c.id === "selector-two-links") expect(fs.statSync(join(root, selection.BUSINESS_PROFILE_SELECTOR.slice(1))).nlink).toBe(2);
      if (c.id === "maximal-selector") expect(fs.statSync(join(root, selection.BUSINESS_PROFILE_SELECTOR.slice(1))).size).toBe(463);
      const before = snapshot(root);
      const result = selection.selectLinuxProfile(roots, c.candidates.map((p: string) => join(root, p)));
      expect(result).toEqual(c.expect);
      expect(snapshot(root)).toEqual(before);
      actual.push([c.id, result]);
    } finally { cleanup(root); }
  });
  it("executes the complete sorted result set and pins all inventory constants", () => {
    expect(actual.sort()).toEqual(corpus.cases.map((c: Obj) => [c.id, c.expect]).sort());
    const schema = JSON.parse(fs.readFileSync(new URL("../../../castle-wall-daemon/src/business_profile/drain_schema.json", import.meta.url), "utf8"));
    expect(selection.BUSINESS_EVIDENCE).toEqual(schema.inventory.map((e: {path: string}) => e.path));
    expect(selection.BUSINESS_EVIDENCE[0]).toBe(selection.BUSINESS_PROFILE_SELECTOR);
    expect(corpus.inventory).toEqual({evidence: selection.BUSINESS_EVIDENCE.map((path, i) => ({id: String(i + 1), path})),
      raw_roots: [selection.RAW_STATE_ROOT, selection.RAW_RUNTIME_ROOT], raw_relative: {state: selection.RAW_STATE_RELATIVE, runtime: selection.RAW_RUNTIME_RELATIVE}});
  });
});
it("rejects the same malformed element set as Rust before execution", () => {
  const bads = [
    {path: ["caller"], value: "unknown"},
    {path: ["expect", "kind"], value: "unknown"},
    {path: ["expect", "reason"], value: "unknown"},
    {path: ["layout"], value: [{type: "unknown"}]},
    {path: ["owners"], value: {x: "foreign"}},
    {path: ["deny", "lookup"], value: ["../escape"]},
    {path: ["candidates"], value: ["/absolute"]},
    {path: ["layout"], value: [{type: "hardlink", path: "alias", target: "missing", mode: 384}]},
  ];
  for (const bad of bads) {
    const copy = structuredClone(corpus);
    let at = copy.cases[0];
    for (const key of bad.path.slice(0, -1)) at = at[key];
    at[bad.path.at(-1)!] = bad.value;
    expect(validate(copy), JSON.stringify(bad)).toBe(false);
  }
  const duplicate = structuredClone(corpus);
  duplicate.cases.push(duplicate.cases[0]);
  expect(validate(duplicate)).toBe(false);
});
// Descriptor accounting requires Linux procfs.
it.skipIf(process.platform !== "linux")("bounds caller paths and closes every descriptor on refusal", () => {
  const root = fs.mkdtempSync(join(tmpdir(), "k1-selector-"));
  try {
    fs.mkdirSync(join(root, selection.BUSINESS_CUSTODY_ROOT.slice(1)), {recursive: true});
    const roots = selection.isolatedSelectorRoots(root);
    const before = fs.readdirSync("/proc/self/fd").length;
    for (const candidate of ["/outside-selection-anchor", `${root}/x/../key`, `${root}/${"x".repeat(selection.CANDIDATE_MAX_BYTES)}`]) {
      expect(selection.selectLinuxProfile(roots, [candidate])).toEqual({kind: "Refused", reason: "RawInventoryPresent"});
    }
    expect(selection.selectLinuxProfile(roots, ["/x", "/y", "/z"])).toEqual({kind: "Refused", reason: "RawInventoryPresent"});
    expect(fs.readdirSync("/proc/self/fd").length).toBe(before);
  } finally { cleanup(root); }
});

// Non-UTF-8 Linux directory names must reach the byte-preserving procfs probes.
for (const [rawRoot, suffix] of [[selection.RAW_STATE_ROOT, selection.RAW_STATE_RELATIVE], [selection.RAW_RUNTIME_ROOT, selection.RAW_RUNTIME_RELATIVE]]) {
  it.skipIf(process.platform !== "linux")(`finds raw inventory under a non-UTF-8 name in ${rawRoot}`, () => {
    const root = fs.mkdtempSync(join(tmpdir(), "k1-selector-bytes-"));
    const rawBase = join(root, rawRoot);
    const entry = Buffer.concat([Buffer.from(`${rawBase}/`), Buffer.from([0xff])]);
    const directories = [entry];
    let parent = entry;
    const parts = suffix.split("/");
    for (const part of parts.slice(0, -1)) {
      parent = Buffer.concat([parent, Buffer.from(`/${part}`)]);
      directories.push(parent);
    }
    const key = Buffer.concat([parent, Buffer.from(`/${parts.at(-1)!}`)]);
    try {
      fs.mkdirSync(join(root, selection.BUSINESS_CUSTODY_ROOT), {recursive: true});
      fs.mkdirSync(rawBase, {recursive: true});
      for (const dir of directories) fs.mkdirSync(dir);
      fs.writeFileSync(key, "untouched raw inventory");
      expect(selection.selectLinuxProfile(selection.isolatedSelectorRoots(root), [])).toEqual({kind: "Refused", reason: "RawInventoryPresent"});
      expect(fs.readFileSync(key, "utf8")).toBe("untouched raw inventory");
    } finally {
      if (fs.existsSync(key)) fs.unlinkSync(key);
      for (const dir of directories.reverse()) if (fs.existsSync(dir)) fs.rmdirSync(dir);
      cleanup(root);
    }
  });
}
