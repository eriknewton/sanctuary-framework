import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync, writeFileSync, mkdtempSync, realpathSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
// @ts-expect-error The build script is JavaScript and intentionally has no declaration artifact.
import { validateSource, digest, candidateForTests } from "../../scripts/build-evidence-pack.mjs";
const SOURCE = process.env.SANCTUARY_SOURCE_SHA!;
const archive = Buffer.from("synthetic source archive");
// Must match the source and installed build record schemas in scripts/build-evidence-pack.mjs.
const metadata = { format: "SANCTUARY_RELEASE_SOURCE_V1", source_revision: SOURCE, source_archive_sha256: digest(archive) };
describe("candidate provenance input boundary", () => {
  it("accepts full matching git and archive provenance", () => { expect(validateSource(metadata, archive, SOURCE, SOURCE)).toEqual(metadata); });
  it.each(["short", "uppercase", "head", "env", "archive", "extra", "missing"])("refuses %s provenance", kind => {
    const m = { ...metadata }; if (kind === "short") m.source_revision = SOURCE.slice(0, 8); if (kind === "uppercase") m.source_revision = SOURCE.toUpperCase(); if (kind === "extra") Object.assign(m, { extra: true }); if (kind === "missing") delete (m as Partial<typeof m>).source_archive_sha256;
    expect(() => validateSource(m, kind === "archive" ? Buffer.from("other") : archive, kind === "short" ? m.source_revision : kind === "env" ? "a".repeat(40) : SOURCE, kind === "short" ? m.source_revision : kind === "head" ? "b".repeat(40) : SOURCE)).toThrow("Source provenance refused");
  });
  it("build command refuses an eight-hex input before bundling", () => { const root = mkdtempSync(join(tmpdir(), "provenance-")); const m = join(root, "source.json"), a = join(root, "archive"); writeFileSync(m, JSON.stringify({ ...metadata, source_revision: SOURCE.slice(0, 8) })); writeFileSync(a, archive); const r = spawnSync(process.execPath, ["scripts/build-evidence-pack.mjs", "--source-metadata", m, "--source-archive", a], { encoding: "utf8" }); expect(r.status).toBe(1); expect(r.stderr).toContain("Source provenance refused"); });
});
describe("installed immutable version", () => {
  let c: Awaited<ReturnType<typeof candidateForTests>>;
  beforeAll(async () => { c = await candidateForTests(); }, 120_000);
  it("runtime environment cannot replace the baked revision", () => { const r = spawnSync(process.execPath, [c.command, "--version"], { env: { ...process.env, SANCTUARY_SOURCE_SHA: "e".repeat(40) }, encoding: "utf8" }); expect(r.status).toBe(0); expect(r.stdout).toBe(`verify-evidence-pack 0.1.0 source_revision=${SOURCE}\n`); });
  it("provenance hashes the final bundle and marks fixture builds non-release", () => { const p = JSON.parse(readFileSync(join(dirname(realpathSync(c.command)), "provenance.json"), "utf8")); expect(Object.keys(p).sort()).toEqual(["format", "package_version", "source_revision", "source_archive_sha256", "verifier_sha256"].sort()); expect(p).toMatchObject({ format: "SANCTUARY_VERIFIER_BUILD_V1", package_version: "0.1.0", source_revision: SOURCE, source_archive_sha256: digest(readFileSync(c.archive)), verifier_sha256: digest(readFileSync(c.command)) }); expect(readFileSync(join(c.root, "NON_RELEASE_FIXTURE"), "utf8")).toContain("not release authentication"); });
});
