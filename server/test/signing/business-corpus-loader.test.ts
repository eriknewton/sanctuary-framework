// fail-before-exempt: the common loader is new; predicate removal is mutation evidence.
import {expect, it} from "vitest";
import {createHash} from "node:crypto";
import {mkdtempSync, readFileSync, writeFileSync, unlinkSync, rmdirSync} from "node:fs";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {checkCorpus, loadCheckedCorpus, REQUIRED_CORPORA} from "../fixtures/business-corpus.js";

const root = "../castle-wall-daemon/src/business_profile";
const manifestBytes = readFileSync(join(root, "vector_manifest.json"), "utf8");
const closureBytes = readFileSync(join(root, "closure_vectors.json"), "utf8");
const manifest = () => JSON.parse(manifestBytes) as {files: Record<string, {sha256: string; cases: Record<string, number>}>};
function truncated(): string {
  const closure = JSON.parse(closureBytes) as {recover: Array<{id: string}>};
  closure.recover = closure.recover.filter(row => row.id !== "recover-drain-tail-ahead-accept");
  return JSON.stringify(closure);
}
function repin(bytes: string): ReturnType<typeof manifest> {
  const copy = manifest();
  copy.files["closure_vectors.json"].sha256 = createHash("sha256").update(bytes).digest("hex");
  return copy;
}
it.each(REQUIRED_CORPORA)("returns the complete pinned corpus %s", name => {
  expect(loadCheckedCorpus(name)).toEqual(JSON.parse(readFileSync(join(root, name), "utf8")));
});
it("refuses a truncated custody corpus by digest before case collection", () => {
  expect(() => checkCorpus(manifestBytes, "closure_vectors.json", truncated())).toThrow("digest");
});
it("refuses a truncated recovery group even when its digest is updated", () => {
  const bytes = truncated();
  expect(() => checkCorpus(JSON.stringify(repin(bytes)), "closure_vectors.json", bytes)).toThrow("count recover");
});
it("requires every other corpus before returning a valid requested corpus", () => {
  const copy = manifest();
  delete copy.files["role_vectors.json"];
  expect(() => checkCorpus(JSON.stringify(copy), "closure_vectors.json", closureBytes)).toThrow("required names");
});
it("refuses an unpinned extra manifest entry", () => {
  const copy = manifest();
  copy.files["unexpected.json"] = copy.files["closure_vectors.json"];
  expect(() => checkCorpus(JSON.stringify(copy), "closure_vectors.json", closureBytes)).toThrow("required names");
});
it("pins array roots through the root group", () => {
  const name = "public_vectors.json", bytes = readFileSync(join(root, name), "utf8"), copy = manifest();
  copy.files[name].cases = {cases: (JSON.parse(bytes) as unknown[]).length};
  expect(() => checkCorpus(JSON.stringify(copy), name, bytes)).toThrow("group form");
});
it("refuses the root group convention for object corpora", () => {
  const copy = manifest();
  copy.files["closure_vectors.json"].cases = {$root: 0};
  expect(() => checkCorpus(JSON.stringify(copy), "closure_vectors.json", closureBytes)).toThrow("group form");
});
it.each([-1, 0.5, Number.MAX_SAFE_INTEGER + 1, true, "7"])("refuses malformed manifest count %s", count => {
  const copy = manifest();
  (copy.files["closure_vectors.json"].cases as Record<string, unknown>).recover = count;
  expect(() => checkCorpus(JSON.stringify(copy), "closure_vectors.json", closureBytes)).toThrow("manifest count");
});
it("refuses an omitted object array group", () => {
  const copy = manifest();
  delete copy.files["closure_vectors.json"].cases.recover;
  expect(() => checkCorpus(JSON.stringify(copy), "closure_vectors.json", closureBytes)).toThrow("group form");
});
it("the consumer loader refuses altered bytes before any case is returned", () => {
  const fixture = mkdtempSync(join(tmpdir(), "corpus-"));
  try {
    writeFileSync(join(fixture, "vector_manifest.json"), manifestBytes);
    writeFileSync(join(fixture, "closure_vectors.json"), truncated());
    expect(() => loadCheckedCorpus("closure_vectors.json", {root: fixture})).toThrow("digest");
  } finally {
    unlinkSync(join(fixture, "vector_manifest.json"));
    unlinkSync(join(fixture, "closure_vectors.json"));
    rmdirSync(fixture);
  }
});

it("equivalent integer number spellings match the other runtime", () => {
  const spelling = manifestBytes.replace('"version": 1', '"version": 1.0').replace('"recover": 7', '"recover": 7.0');
  expect(checkCorpus(spelling, "closure_vectors.json", closureBytes)).toEqual(JSON.parse(closureBytes));
});
